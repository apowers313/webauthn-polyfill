var defaultTimeout = 10;
var defaultAuthPort = 61904;
var maxTimeout = 30 * 60; // max timeout for a call is 30 minutes
var minTimeout = 1; // minimum timeout is 3 seconds
var supportedCryptoTypes = ["FIDO"];

/*********************************************************************************
 * IIFE module to keep namespace clean and protect internals...
 *********************************************************************************/
window.fido = (function () {
    var fidoAPI = function () {};

    function _makeRpId(origin) {
        var parser = document.createElement('a');
        parser.href = origin;
        // console.log("RPID:", parser.hostname);
        return parser.hostname;
    }

    function _normalizeAlgorithm(keyAlgorithm) {
        var subtle = window.crypto.subtle.__proto__;
        var key, i;
        var encrypt = subtle.encrypt;

        console.log("Subtle is", subtle);
        console.log("Encrypt is", encrypt);
        console.log("Encrypt name", encrypt.name);

        // for (key in Object.keys(subtle)) {
        //     console.log ("Subtle key:", key);
        // }
        // for (i = 0; i < encrypt.length; i++) {
        //     console.log ("Encrypt: ", encrypt[i].name);
        // }
    }

    /**
     * Get Credentials
     *
     * FIDO 2.0 Web API Specification, Section 4.1.1
     */
    fidoAPI.prototype.makeCredential = function (
        account,
        cryptoParameters,
        attestationChallenge,
        timeoutSeconds,
        blacklist,
        extensions) {
        var callerOrigin = document.origin;
        // console.log("Origin:", callerOrigin);
        var rpId = _makeRpId(callerOrigin);
        // argument checking
        // TODO: check types
        if (timeoutSeconds === undefined || timeoutSeconds < minTimeout) {
            timeoutSeconds = minTimeout;
        }
        if (timeoutSeconds > maxTimeout) {
            timeoutSeconds = maxTimeout;
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

            var makeCredentialTimer = window.setTimeout(function () {
                console.log("makeCredential timed out");
                // TODO: call cancel on all pending authenticators
                var err = new Error("timedOut");
                reject(err);
            }, timeoutSeconds * 1000);

            var i, current = null;
            // find a crypto type that meets our needs
            for (i = 0; i < cryptoParameters.length; i++) {
                current = cryptoParameters[i];
                if (supportedCryptoTypes.indexOf(current.type) === -1) {
                    continue;
                }

                // WebCrypto Section 18.4, Normalizing Algorithm
                var keyAlgorithm = {
                    alg: current.algorithm,
                    op: "generateKey"
                };
                current = null;
                // TODO: not quite sure how to make this work from userland...
                // _normalizeAlgorithm (keyAlgorithm);
            }
            cryptoParameters = current;

            var _pendingList = [];
            for (i = 0; i < _authenticatorList.length; i++) {
                // Web API 4.1.1 says to call with: callerOrigin, rpId, account, current.type, normalizedAlgorithm, blacklist, attestationChallenge and clientExtensions
                // External Authenticator Protocol 4.1 says to use the args below
                // console.log("Calling authenticatorMakeCredential[" + i + "]");
                _pendingList.push(
                    _authenticatorList[i].authenticatorMakeCredential(
                        rpId,
                        account,
                        // clientDataHash,
                        // cryptoParameters, // selectedCrypto parameters
                        blacklist,
                        extensions
                    )
                );
            }

            // basically Promises.all() that doesn't die on failure
            // TODO: this probably doesn't work if the timer lapses, since it won't .then() anything after the promise that hung
            // use some version of Promises.race() instead
            function resolveAll(promises) {
                var accumulator = [];
                var ready = Promise.resolve(null);

                promises.forEach(function (promise) {
                    ready = ready.then(function () {
                        return promise;
                    }).then(function (value) {
                        accumulator.push(value);
                    }).catch(function (err) {
                        // accumulator.push(err);
                    });
                });

                return ready.then(function () {
                    return accumulator;
                });
            }

            resolveAll(_pendingList)
                .then(function (ret) {
                    // console.log("all promises resolved:", ret);
                    window.clearTimeout (makeCredentialTimer);
                    resolve (ret);
                })
                .catch(function (err) {
                    console.log ("caught error");
                    reject (err);
                });
        });
    };

    /**
     * getAssertion
     */
    fidoAPI.prototype.getAssertion = function (
        assertionChallenge,
        timeoutSeconds,
        whitelist,
        extensions
    ) {
        console.log("getAssertion");
    };

    /*********************************************************************************
     * Everything below this line is properietary and not part of the FIDO 2.0 specification
     *********************************************************************************/
    /**
     * Credential Info
     *
     * just a template; can use getters and setters if strict type enforcement is desired
     */
    fidoAPI.prototype.fidoCredentialInfo = {};
    Object.defineProperties(fidoAPI.prototype.fidoCredentialInfo, {
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
    fidoAPI.prototype.fidoAccount = {};
    Object.defineProperties(fidoAPI.prototype.fidoAccount, {
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
    fidoAPI.prototype.fidoCredentialProperties = {};
    Object.defineProperties(fidoAPI.prototype.fidoCredentialProperties, {
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
    fidoAPI.prototype.fidoCredential = {};
    Object.defineProperties(fidoAPI.prototype.fidoCredential, {
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

    /*********************************************************************************
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
        authenticatorMakeCredential: function () {
            return new Promise(function (resolve, reject) {
                resolve();
            }); // stub
        },
        authenticatorGetAssertion: function () {
            return new Promise(function (resolve, reject) {
                resolve();
            }); // stub
        },
        authenticatorCancel: function () {}
    };
    fidoAPI.prototype.fidoAuthenticator = fidoAuthenticator;
    var _authenticatorList = [];

    fidoAPI.prototype.addAuthenticator = function (auth) {
        // console.log("addAuthenticator");

        if (auth instanceof fidoAuthenticator) {
            // console.log("Adding authenticator");
            _authenticatorList.push(auth);
        } else {
            // console.log("Adding authenticator: Authenticator was wrong type, failing");
        }
    };

    // removeAuthenticator
    fidoAPI.prototype.listAuthenticators = function () {
        // cheap deep copy
        return JSON.parse(JSON.stringify(_authenticatorList));
    };

    fidoAPI.prototype.removeAllAuthenticators = function () {
        _authenticatorList = [];
    };

    /*********************************************************************************
     * Everything below this line is an extension to the specification for managing extensions
     *********************************************************************************/
    // addExtension
    // removeExtension

    // TODO: seal returned object and make all functions non-writeable (for security purposes)
    return new fidoAPI();
}());