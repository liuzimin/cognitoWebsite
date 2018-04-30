// When using loose Javascript files:
var CognitoUserPool = AmazonCognitoIdentity.CognitoUserPool;
var CognitoUser = AmazonCognitoIdentity.CognitoUser;
var AuthenticationDetails = AmazonCognitoIdentity.AuthenticationDetails;

var poolData = {
    UserPoolId : 'us-east-2_57jpQupfc', // Your user pool id here
    ClientId : '7ec9h7hhtchermdsceg3v2p5ar' // Your client id here
};

function signIn() {
    var username = $('#sign_in_username').val();
    var password = $('#sign_in_password').val();
    console.log(username);
    console.log(password);

    var authenticationData = {
        Username : username,
        Password : password,
    };
    var authenticationDetails = new AuthenticationDetails(authenticationData);

    var userPool = new CognitoUserPool(poolData);

    var userData = {
        Username : username,
        Pool : userPool
    };

    var cognitoUser = new CognitoUser(userData);
    cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: function (result) {
            console.log('access token + ' + result.getAccessToken().getJwtToken());
            location.href = "account.html";
            /*
            //POTENTIAL: Region needs to be set if not already set previously elsewhere.
            AWS.config.region = '<region>';

            AWS.config.credentials = new AWS.CognitoIdentityCredentials({
                IdentityPoolId : '...', // your identity pool id here
                Logins : {
                    // Change the key below according to the specific region your user pool is in.
                    'cognito-idp.<region>.amazonaws.com/<YOUR_USER_POOL_ID>' : result.getIdToken().getJwtToken()
                }
            });

            //refreshes credentials using AWS.CognitoIdentity.getCredentialsForIdentity()
            AWS.config.credentials.refresh((error) => {
                if (error) {
                     console.error(error);
                } else {
                     // Instantiate aws sdk service objects now that the credentials have been updated.
                     // example: var s3 = new AWS.S3();
                     console.log('Successfully logged!');
                }
            });*/
        },
        
        onFailure: function(err) {
            alert(err.message || JSON.stringify(err));
        },

    });
}

function register() {
    var username = $('#registration_username').val();
    var password = $('#registration_password').val();
    var email = $('#registration_email').val();
    console.log(username);
    console.log(password);
    console.log(email);

    var userPool = new CognitoUserPool(poolData);

    var attributeList = [];

    var dataEmail = {
        Name : 'email',
        Value : email
    };

    var attributeEmail = new AmazonCognitoIdentity.CognitoUserAttribute(dataEmail);

    attributeList.push(attributeEmail);

    userPool.signUp(username, password, attributeList, null, function(err, result){
        if (err) {
            alert(err.message || JSON.stringify(err));
            return;
        }
        cognitoUser = result.user;
        console.log('user name is ' + cognitoUser.getUsername());
    });
}

function validate() {
    var username = $('#code_username').val();
    var code = $('#code_code').val();
    console.log(username);
    console.log(code);

    var userPool = new CognitoUserPool(poolData);
    var userData = {
        Username : username,
        Pool : userPool
    };

    var cognitoUser = new CognitoUser(userData);
    cognitoUser.confirmRegistration(code, true, function(err, result) {
        if (err) {
            alert(err.message || JSON.stringify(err));
            return;
        }
        console.log('call result: ' + result);
    });
}

function signOut() {
    console.log('sign out');
    var userPool = new CognitoUserPool(poolData);
    var cognitoUser = userPool.getCurrentUser();
    if(cognitoUser !== null) {
        cognitoUser.signOut();
    }
    location.href = "index.html";
}

function resendValidationCode() {
    var username = $('#code_username').val();
    var code = $('#code_code').val();
    console.log(username);
    console.log(code);

    var userPool = new CognitoUserPool(poolData);
    var userData = {
        Username : username,
        Pool : userPool
    };

    var cognitoUser = new CognitoUser(userData);
    cognitoUser.resendConfirmationCode(function(err, result) {
        if (err) {
            alert(err.message || JSON.stringify(err));
            return;
        }
        console.log('call result: ' + result);
    });
}

function setEntry() {

    var userPool = new CognitoUserPool(poolData);
    var cognitoUser = userPool.getCurrentUser();

    if (cognitoUser != null) {
        cognitoUser.getSession(function(err, session) {
            if (err) {
                alert(err.message || JSON.stringify(err));
                return;
            }
            console.log('session validity: ' + session.isValid());
            console.log(cognitoUser);
            $('#account-name-header').html(cognitoUser.username);
            /*
            // NOTE: getSession must be called to authenticate user before calling getUserAttributes
            cognitoUser.getUserAttributes(function(err, attributes) {
                if (err) {
                    // Handle error
                } else {
                    // Do something with attributes
                }
            });

            AWS.config.credentials = new AWS.CognitoIdentityCredentials({
                IdentityPoolId : '...', // your identity pool id here
                Logins : {
                    // Change the key below according to the specific region your user pool is in.
                    'cognito-idp.<region>.amazonaws.com/<YOUR_USER_POOL_ID>' : session.getIdToken().getJwtToken()
                }
            });

            // Instantiate aws sdk service objects now that the credentials have been updated.
            // example: var s3 = new AWS.S3();
            */
        });

        var apiURL = "index.html";
        console.log("here1");

        $.ajax({
            type: "POST",
            url: apiURL,
            data: {},
            success: function(data){
                $('#data_from_api').html(data.data);
                console.log("here");
            }
        });

        console.log("here2");
    }
}