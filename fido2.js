var defaultTimeout = 10;
var defaultAuthPort = 61904;
var maxTimeout = 30 * 60; // max timeout for a call is 30 minutes
var minTimeout = 3; // minimum timeout is 3 seconds

/********************************************************************************
 * IIFE module to keep namespace clean and protect internals...
 *********************************************************************************/
window.fido = (function () {
    // var fidoAPI = Object.create(null);
    var fidoAPI = {};

    /**
     * Get Credentials
     *
     * FIDO 2.0 Web API Specification, Section 4.1.1
     */
    fidoAPI.__proto__.makeCredential = function (
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
    };

    /**
     * getAssertion
     */
    fidoAPI.__proto__.getAssertion = function (
        assertionChallenge,
        timeoutSeconds,
        whitelist,
        extensions
    ) {
        console.log("getAssertion");
    };

    /********************************************************************************
     * Everything below this line is properietary and not part of the FIDO 2.0 specification
     *********************************************************************************/
    /**
     * Credential Info
     *
     * just a template; can use getters and setters if strict type enforcement is desired
     */
    fidoAPI.__proto__.fidoCredentialInfo = {};
    Object.defineProperties(fidoAPI.__proto__.fidoCredentialInfo, {
        credential: {
            enumerable: true,
            configurable: true,
            writable: true
        },
        algorithmIdentifier: {
            enumerable: true,
            configurable: true,
            writable: true
        },
        publicKey: {
            enumerable: true,
            configurable: true,
            writable: true
        },
        attestation: {
            enumerable: true,
            configurable: true,
            writable: true
        },
    });

    /**
     * Account
     *
     * Defined in FIDO 2.0 Web API, Section 4.3
     * just a template; can use getters and setters if strict type enforcement is desired
     */
    fidoAPI.__proto__.fidoAccount = {};
    Object.defineProperties(fidoAPI.__proto__.fidoAccount, {
        rpDisplayName: {
            enumerable: true,
            configurable: true,
            writable: true
        },
        displayName: {
            enumerable: true,
            configurable: true,
            writable: true
        },
        name: {
            enumerable: true,
            configurable: true,
            writable: true
        },
        id: {
            enumerable: true,
            configurable: true,
            writable: true
        },
        imageUri: {
            enumerable: true,
            configurable: true,
            writable: true
        }
    });

    /**
     * Credential Parameters
     *
     * just a template; can use getters and setters if strict type enforcement is desired
     */
    fidoAPI.__proto__.fidoCredentialProperties = {};
    Object.defineProperties(fidoAPI.__proto__.fidoCredentialProperties, {
        credentialType: {
            enumerable: true,
            configurable: true,
            writable: true
        },
        algorithmIdentifier: {
            enumerable: true,
            configurable: true,
            writable: true
        }
    });

    /**
     * Credential
     *
     * defined in the specification
     * just a template; can use getters and setters if strict type enforcement is desired
     */
    fidoAPI.__proto__.fidoCredential = {};
    Object.defineProperties(fidoAPI.__proto__.fidoCredential, {
        credentialType: {
            enumerable: true,
            configurable: true,
            writable: true
        },
        id: {
            enumerable: true,
            configurable: true,
            writable: true
        }
    });

    /********************************************************************************
     * Everything below this line is an extension to the specification to make authenticators easier to work with
     *********************************************************************************/
    /**
     * Authenticator
     *
     * not part of the FIDO 2.0 specification
     * just a template; can use getters and setters if strict type enforcement is desired
     */
    function fidoAuthenticator() {}
    fidoAuthenticator.prototype = {
        constructor: fidoAuthenticator,
        authenticatorDiscover: function () {},
        authenticatorMakeCredential: function () {},
        authenticatorGetAssertion: function () {},
        authenticatorCancel: function () {}
    };

    fidoAPI.__proto__.addAuthenticator = function (auth) {
        console.log("addAuthenticator");
        if (this._authenticatorList === undefined) {
            this._authenticatorList = [];
        }

        if (auth instanceof fidoAuthenticator) {
            console.log("Adding authenticator");
            this._authenticatorList.push(auth);
        } else {
            console.log("Adding authenticator: Authenticator was wrong type, failing");
        }
    };

    // removeAuthenticator
    fidoAPI.__proto__.listAuthenticators = function () {
        // deep copy
        return JSON.parse(JSON.stringify(this._authenticatorList));
    };

    return fidoAPI;
}());