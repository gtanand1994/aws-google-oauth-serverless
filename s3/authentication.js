// REPLACE <BUCKET_NAME> with S3 bucket where you hosted the frontend and <REGION> with actual AWS REGION.
//function readTextFile(callback) {
//    var rawFile = new XMLHttpRequest();
//    rawFile.overrideMimeType("application/json");
//    rawFile.open("GET", "http://<BUCKET_NAME>.s3.<REGION>.amazonaws.com/users/users.json", true);
//    rawFile.onreadystatechange = function() {
//        if (rawFile.readyState === 4 && rawFile.status == "200") {
//            window.config.users = rawFile.responseText;
//            return callback(rawFile.responseText);
//        }
//    }
//    rawFile.send(null);
//}

function authenticate(googleUser) {
    getIdToken(googleUser)
        .then(AWSSTSSignIn)
        .then(handleSTSResponse)
        .then(signHttpRequest)
        .then(getSigninTokenFromLambda)
        .then(redirectToManagementConsole)
        .catch(handleError);
};

function getIdToken(googleUser) {
    // Useful data for your client-side scripts:
    var profile = googleUser.getBasicProfile();
    // Profile ID can be used in IAM roles for authorization by using accounts.google.com:sub
    console.log("Google ID: " + profile.getId());
    console.log("Google Name: " + profile.getEmail());
    var gname = profile.getEmail();
    // The ID token needed for web identity authentication:
    var idToken = googleUser.getAuthResponse().id_token;
    console.log("Google ID Token: " + idToken);
    var id = [gname, idToken]
    return new Promise(function (resolve) {
        resolve(id);
    });
}

function AWSSTSSignIn(id) {
    console.log(id[0] + ":" + id[1])
    var gname = id[0];
    var idToken = id[1];
//    readTextFile(function(text){
//        window.config.users = JSON.parse(text);
//        console.log(window.config.users);
//    });
    var rawFile = new XMLHttpRequest();
    rawFile.overrideMimeType("application/json");
    rawFile.open("GET", "http://<BUCKET_NAME>.s3.<REGION>.amazonaws.com/users/users.json", false);
    rawFile.onreadystatechange = function() {
        if (rawFile.readyState === 4 && rawFile.status == "200") {
            window.config.users = JSON.parse(rawFile.responseText);
        }
    }
    rawFile.send(null);
    console.log(window.config.users);
    if (window.config.users.hasOwnProperty(gname)) {
        console.log('Role for user ' + gname + ' is :' + window.config.users[gname]);
    }
    else {
        console.log('No Role set for user' + gname); // toString or something else
        window.location.replace("http://<BUCKET_NAME>.s3-website.<REGION>.amazonaws.com/403.html")
        err("User is not authorized");
    }

    var sts = new AWS.STS();
    var params = {
        RoleArn: window.config.users[gname], /* required */
        RoleSessionName: gname, /* required */
        WebIdentityToken: idToken /* required */
    };
    return new Promise(function (resolve, reject) {
        sts.assumeRoleWithWebIdentity(params, function (err, data) {
            if (err) {
                reject(err);
            } else {
                // Returning STS response
                console.log("STS credentials: " + JSON.stringify(data.Credentials));
                resolve(data);
            }
        });
    });
}

function handleSTSResponse(data) {
    // Setting AWS config credentials globally
    AWS.config.credentials = new AWS.Credentials(
        data.Credentials.AccessKeyId,
        data.Credentials.SecretAccessKey,
        data.Credentials.SessionToken);
    AWS.config.region = window.config.region;
    // Sending sign-in parameters to lambda function
    var signInParameters = {
        "sessionId": data.Credentials.AccessKeyId,
        "sessionKey": data.Credentials.SecretAccessKey,
        "sessionToken": data.Credentials.SessionToken
    };
    return new Promise(function (resolve) {
        resolve(signInParameters);
    })
}

function signHttpRequest(signInParameters) {
    var signInUrl = "https://";
    signInUrl += window.config.apiGatewayUrl;
    signInUrl += window.config.apiGatewayPath;
    // Setting AWS Signed header
    var request = new AWS.HttpRequest(window.config.apiGatewayUrl, window.config.region);
    request.method = 'POST';
    request.path = window.config.apiGatewayPath;
    request.endpoint.path = window.config.apiGatewayPath;
    request.endpoint.pathname = window.config.apiGatewayPath;
    request.body = JSON.stringify(signInParameters);
    // Needed for proper signature generation
    request.headers['Host'] = request.endpoint.host;
    request.headers['Access-Control-Allow-Origin'] = '*';
    request.headers['Access-Control-Allow-Credentials'] = "true";
    request.headers['Access-Control-Allow-Methods'] = "*";
    request.headers['Access-Control-Allow-Methods'] = "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent";
    // Signing
//    console.log("break-point-0");
    var signer = new AWS.Signers.V4(request, 'execute-api');
    signer.addAuthorization(AWS.config.credentials, AWS.util.date.getDate());
    return new Promise(function (resolve) {
        resolve(signer.request);
    });
//    console.log("break-point-1");
}

function getSigninTokenFromLambda(request) {
//    console.log("break-point-2");
    return new Promise(function (resolve, reject) {
        AWS.util.defer(function () {
            var data = '';
            var http = AWS.HttpClient.getInstance();
            http.handleRequest(request, {}, function (httpResponse) {
//                console.log("break-point-3");
                httpResponse.on('data', function (chunk) {
                    data += chunk.toString();
                });
//                console.log("break-point-4");
                httpResponse.on('end', function () {
                    console.log("Sign-in token from Lambda: " + data);
                    resolve(data);
                });
            }, reject);
        });
    });
}

function redirectToManagementConsole(data) {
    var signin_token = JSON.parse(data);
    var request_parameters = "?Action=login"
    request_parameters += "&Issuer=Example.org"
    request_parameters += "&Destination=" + encodeURIComponent("https://console.aws.amazon.com/")
    request_parameters += "&SigninToken=" + signin_token.SigninToken;
    var request_url = "https://signin.aws.amazon.com/federation" + request_parameters;
    window.location.replace(request_url);
}

function handleError(error) {
    console.log("Authentication failed: " + error);
}

