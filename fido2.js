var defaultTimeout = 10;
var defaultAuthPort = 61904;
var maxTimeout = 30 * 60; // max timeout for a call is 30 minutes
var minTimeout = 3; // minimum timeout is 3 seconds

window.fido = {
    makeCredential: makeCredential,
    getAssertion: getAssertion
};

var _discoveredAuthenticators = [];
/**
 * Discover
 */
function authDiscover() {
    console.log("authDiscover");
    // TODO: Discovery cache
    // TODO: Fire events when discovered / state changes
    var authSocket = io.connect("http://localhost:" + defaultAuthPort + "/fido");
    authSocket.on("connect", function (socket) {
        console.log("connected");
        // Do the discovery of all the authenticators
        authSocket.emit("discover", {
            command: "discover"
        });
        // If an authenticator responds, remember it for the future
        authSocket.on("discover", function (msg) {
            if (msg.aaid === undefined) {
                // TODO: throw error?
                return;
            }
            // console.log ("Got discovery response:", msg);
            if (_discoveredAuthenticators[msg.aaid] === undefined) {
                _discoveredAuthenticators[msg.aaid] = msg;
                console.log ("Adding authenticator:" + msg.aaid + " List is:", _discoveredAuthenticators);
            }
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
    var callerOrigin = document.origin;
    // argument checking
    // TODO: check types
    if (timeoutSeconds > maxTimeout) {
        timeoutSeconds = maxTimeout;
    }
    if (timeoutSeconds < minTimeout) {
        timeoutSeconds = minTimeout;
    }
    if (blacklist === undefined) {
        blacklist = [];
    }
    if (extensions === undefined) {
        extensions = [];
    }
    // Select authenticator
    authDiscover();

    // Return promise
    return new Promise(function (resolve, reject) {
        var issuedRequests = [];

        // // Set timeout
        // if (timeoutSeconds !== undefined) {
        //     this.adjustedTimeout = timeoutSeconds;
        // } else {
        //  this.adjustedTimeout = defaultTimeout;
        // }
        // var makeCredentialTimer = window.setTimeout(function() {
        //  console.log ("makeCredential timedout");
        //  reject(err);
        // }, this.adjustedTimeout * 1000);

        // resolve();
    });
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
    publicKey: [String, Object, Array, Number],
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