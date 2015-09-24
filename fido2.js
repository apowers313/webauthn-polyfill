var defaultTimeout = 10;
var defaultAuthPort = 61904;

/**
 * Discover
 */
function authDiscover() {
	console.log ("authDiscover");
    var authSocket = io.connect("http://localhost:" + defaultAuthPort + "/fido");
    authSocket.on("connect", function(socket) {
        console.log("connected");
        console.log("Firing message");

        authSocket.emit("discover", {
            command: "discover"
        });
    });
}

/**
 * Get Credentials
 *
 * FIDO 2.0 Web API Specification, Section 4.1.1
 */
function makeCredential(
    account,
    cryptoParameters,
    attestationChallenge,
    timeoutSeconds,
    blacklist,
    extensions) {
    console.log("makeCredential");

    // Select authenticator

    // // Set timeout
    // if (timeoutSeconds !== undefined) {
    //     this.adjustedTimeout = timeoutSeconds;
    // } else {
    // 	this.adjustedTimeout = defaultTimeout;
    // }
    // var makeCredentialTimer = window.setTimeout(function() {
    // 	console.log ("Timer expired");
    // }, this.adjustedTimeout * 1000);

    // Return promise
}

/**
 * getAssertion
 */
function getAssertion(
    assertionChallenge,
    timeoutSeconds,
    whitelist,
    extensions
) {
    console.log("getAssertion");
}

/**
 * Credential Info
 *
 * TODO: Not really used, just a template; turn into a proper object later
 */
var credentialInfo = {
	credential: "credential",
	algorithmIdentifier: "algorithmIdentifier",
	publicKey: [ String, Object, Array, Number ],
	attestation: "attestationStatement"
};

/**
 * Account
 *
 * TODO: Not really used, just a template; turn into a proper object later
 */
var account = {
	rpDisplayName: String,
	displayName: String,
	name: String,
	id: String,
	imageUri: String
};

/**
 * Credential Parameters
 *
 * TODO: Not really used, just a template; turn into a proper object later
 */
var credentailParameters = {
	credentialType: "type",
	algorithmIdentifier: "algorithmIdentifier"
};

/**
 * Credential
 *
 * TODO: Not really used, just a template; turn into a proper object later
 */
var credential = {
	credentialType: "type",
	id: String
};

