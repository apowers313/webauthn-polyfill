// TODO: turn into setOptions call
var defaultTimeout = 10;
var defaultAuthPort = 61904;
var maxTimeout = 30 * 60; // max timeout for a call is 30 minutes
var minTimeout = 1; // minimum timeout is 1 second
var defaultTimeout = 30;
var supportedCryptoTypes = ["FIDO"];


// SECURITY TODO: make sure this meets the requirements for secure context
// for browsers that don't support secure context
if (window.isSecureContext === undefined && location.origin.match(/:\/\/localhost|https:\/\//g)) {
    window.isSecureContext = true;
}

// for safari's version of webCrypto
if (window.crypto && !window.crypto.subtle && window.crypto.webkitSubtle) {
    window.crypto.subtle = window.crypto.webkitSubtle;
}

// IIFE module to keep namespace clean and protect internals...
(function() {
    console.log("Loading WebAuthn polyfill...");
    class ScopedCredential {}

    class WebAuthnAttestation {}

    /**
     * ScopedCredentialInfo
     *
     * The interface object returned by makeCredential
     */
    class ScopedCredentialInfo {
        constructor() {
            Object.defineProperty(this.__proto__, Symbol.toStringTag, {
                get: function() {
                    return "ScopedCredentialInfoPrototype";
                }
            });
            Object.defineProperty(this, Symbol.toStringTag, {
                get: function() {
                    return "ScopedCredentialInfo";
                }
            });
            this.__proto__.credential = new ScopedCredential();
            // this.__proto__.attestation = new WebAuthnAttestation();
            // this.__proto__.publicKey = null;
            Object.defineProperty(this.__proto__, "credential", {
                enumerable: true,
                configurable: true,
                get: function() {
                    throw new TypeError("function () { [native code] }");
                },
            });
            Object.defineProperty(this.__proto__, "attestation", {
                enumerable: true,
                configurable: true,
                get: function() {
                    throw new TypeError("function () { [native code] }");
                },
            });
            Object.defineProperty(this.__proto__, "publicKey", {
                enumerable: true,
                configurable: true,
                get: function() {
                    throw new TypeError("function () { [native code] }");
                },
            });
        }
        init() {
            return window.crypto.subtle.generateKey({
                    // TODO: should be options for crypto, bits, hash, etc.
                    name: "RSASSA-PKCS1-v1_5",
                    modulusLength: 2048, //can be 1024, 2048, or 4096
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: {
                        name: "SHA-256" //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                    },
                },
                false, ["sign", "verify"]
            ).then((foo) => {

                Object.defineProperty(this, "credential", {
                    enumerable: true,
                    configurable: true,
                    value: new ScopedCredential()
                });
                Object.defineProperty(this, "attestation", {
                    enumerable: true,
                    configurable: true,
                    value: new WebAuthnAttestation()
                });
                Object.defineProperty(this, "publicKey", {
                    enumerable: true,
                    configurable: true,
                    value: foo.publicKey
                });

                // this.__proto__.credential = new ScopedCredential();
                // this.__proto__.attestation = new WebAuthnAttestation();
                // this.__proto__.publicKey = foo.publicKey;
            });
        }
    }
    /**
     * WebAuthentication
     *
     * This is the primary class / interface of WebAuthn. The spec can be found here:
     * https://w3c.github.io/webauthn/#api
     */
    class WebAuthentication {
        constructor() {
            // configure this object in a way that makes WebIDL / idlharness happy
            Object.defineProperty(this.__proto__, Symbol.toStringTag, {
                get: function() {
                    return "WebAuthenticationPrototype";
                }
            });
            Object.defineProperty(this, Symbol.toStringTag, {
                get: function() {
                    return "WebAuthentication";
                }
            });
            Object.defineProperty(this.__proto__, "makeCredential", {
                enumerable: true
            });
            Object.defineProperty(this.__proto__, "getAssertion", {
                enumerable: true
            });

            // TODO: rename
            class fidoAuthenticator {
                constructor() {}
                authenticatorDiscover() {}
                authenticatorMakeCredential() {
                    console.log("got authenticatorMakeCredential");
                    return Promise.resolve(null);
                }
                authenticatorGetAssertion() {
                    console.log("got authenticatorGetAssertion");
                    return Promise.resolve(null);
                }
                authenticatorCancel() {}
            }

            this.fidoAuthenticator = fidoAuthenticator;
            this._authenticatorList = [];
        }

        /**
         * Get Credentials
         *
         * WebAuthn Specification, Section 4.1
         */
        makeCredential(
            accountInformation,
            cryptoParameters,
            attestationChallenge,
            ...options) {
            // TODO set options
            // TODO: Select authenticator

            console.log("makeCredential:");
            console.log("- account:", accountInformation);
            console.log("- cryptoParameters:", cryptoParameters);
            var callerOrigin = document.origin;
            console.log("Origin:", callerOrigin);
            var rpId = _makeRpId(callerOrigin);

            // argument checking
            // set defaults
            if (Array.isArray(options)) options = options[0];
            options = options || {};

            console.log("options:", options);
            var timeoutSeconds = options.timeout;
            var blacklist = options.blacklist;
            var extensions = options.extensions;
            if (timeoutSeconds === undefined) {
                timeoutSeconds = defaultTimeout;
            }
            if (timeoutSeconds < minTimeout) {
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

            // check arguments
            if (!accountInformation || typeof accountInformation !== "object") {
                return Promise.reject(new TypeError("makeCredential: expected accountInformation argument to be an object, got " + typeof accountInformation));
            }

            if (typeof accountInformation.rpDisplayName !== "string" ||
                typeof accountInformation.displayName !== "string" ||
                typeof accountInformation.id !== "string" ||
                accountInformation.rpDisplayName.length < 1 ||
                accountInformation.displayName.length < 1 ||
                accountInformation.id.length < 1) {
                console.log("accountInformation", accountInformation);
                return Promise.reject(new TypeError("makeCredential: expected accountInformation properties rpDisplayName, displayName and id to be strings"));
            }

            if (!Array.isArray(cryptoParameters) ||
                cryptoParameters.length < 1) {
                return Promise.reject(new TypeError("makeCredential: expected cryptoParameters argument to be a non-empty array"));
            }

            for (let param of cryptoParameters) {
                if (param.type !== "ScopedCred") {
                    return Promise.reject(new TypeError("makeCredential: expected all cryptoParameters to be of type 'ScopedCred', got " + param.type));
                }
                if (typeof param.algorithm !== "string" ||
                    param.algorithm.length < 1) {
                    return Promise.reject(new TypeError("makeCredential: expected all cryptoParameters to have an algorithm of type 'String', got " + typeof param.algorithm));
                }
            }

            if ((attestationChallenge instanceof ArrayBuffer) === false) {
                return Promise.reject(new TypeError("makeCredential: expected attestationChallenge to be an ArrayBuffer"));
            }

            // TODO: validate attestationChallenge

            var issuedRequests = [];
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
                var x = _normalizeAlgorithm.call(this, keyAlgorithm);
            }
            // should be a valid AlgorithmIdentifier object
            cryptoParameters = current;

            // TODO: process _extensionHookList

            // TODO: make sure window.crypto.subtle exists
            var self = this; // TODO: remove
            // create client data hash
            var clientData;
            return _createClientDataHash(attestationChallenge, callerOrigin)
                .then((cd) => {
                    clientData = cd;
                    var rpIdBuf = str2ab(rpId);
                    return window.crypto.subtle.digest({
                            name: "SHA-256",
                        },
                        rpIdBuf)
                })
                .then((rpIdHash) => {
                    //returns the hash as an ArrayBuffer
                    return _callOnAllAuthenticators.call(self, timeoutSeconds, "authenticatorMakeCredential", [rpIdHash,
                        accountInformation,
                        clientData.hash,
                        "ScopedCred",
                        blacklist,
                        extensions
                    ]);
                })
                .then((scopedCredInfo) => {
                    // if the call passed, mix in the clientData
                    if (typeof scopedCredInfo === "object" &&
                        typeof scopedCredInfo.credential === "object" &&
                        typeof scopedCredInfo.attestation === "object") {
                        scopedCredInfo.clientDataJSON = clientData.jsonBuf;
                        return scopedCredInfo;
                    }
                });
            // .then((ret) => {
            //     console.log("ret");
            //     return ret;
            //     // resolve (ret);
            // })
            // .catch((err) => {
            //     console.error(err);
            //     reject (err);
            // });
        }

        /**
         * getAssertion
         */
        getAssertion(
            assertionChallenge,
            ...options
        ) {
            console.log("getAssertion");
            var callerOrigin = document.origin;
            var rpId = _makeRpId(callerOrigin);

            // TODO set options
            console.log("getAssertion options", options);
            var timeoutSeconds;

            // argument checking
            // TODO: check types
            if (Array.isArray(options)) options = options[0];
            options = options || {};
            var whitelist = options.whitelist || [];
            var extensions = options.extensions || [];
            if (typeof options.timeout === "number") timeoutSeconds = options.timeout;

            if (timeoutSeconds === undefined) {
                timeoutSeconds = defaultTimeout;
            }
            if (timeoutSeconds < minTimeout) {
                timeoutSeconds = minTimeout;
            }
            if (timeoutSeconds > maxTimeout) {
                timeoutSeconds = maxTimeout;
            }

            // TODO: validate assertionChallenge
            console.log("assertionChallenge", assertionChallenge);

            // new promise
            // Return promise
            // return new Promise((resolve, reject) => { // TODO: return inner Promise instead
            // initialize issuedRequests
            var issuedRequests = [];

            var clientData;

            // TODO: make sure window.crypto.subtle exists
            return _createClientDataHash(assertionChallenge, callerOrigin)
                .then((cd) => {
                    clientData = cd;
                    var rpIdBuf = str2ab(rpId);
                    printHex("rpIdBuf", rpIdBuf);
                    return window.crypto.subtle.digest({
                            name: "SHA-256",
                        },
                        rpIdBuf);
                })
                .then((rpIdHash) => { // call authenticatorGetAssertion on all authenticators
                    // clientDataHash = new Uint8Array(hash);
                    // console.log(clientDataHash);

                    // TODO: for each authenticator...
                    // - create whitelist
                    // - call authenticatorGetAssertion
                    // - add entry to issuedRequests
                    // wait for timer or results
                    return _callOnAllAuthenticators.call(this, timeoutSeconds, "authenticatorGetAssertion", [rpIdHash,
                        clientData.hash,
                        whitelist,
                        extensions
                    ]);
                })
                .then((webAuthnAssertion) => {
                    console.log("getAssertion res:", res);
                    if (typeof res !== "object" || !res) {
                        return res;
                    }
                    webAuthnAssertion.clientDataJSON = clientData.jsonBuf;
                    // return Promise.resolve(res);
                    return webAuthnAssertion;
                });
            // .catch((err) => {
            //     return Promise.reject(err);
            // });
            // });
        }

        /*********************************************************************************
         * Everything below this line is an extension to the specification to make authenticators easier to work with
         *********************************************************************************/
        /**
         * Authenticator
         *
         * not part of the FIDO 2.0 specification
         * just a template; can use getters and setters if strict type enforcement is desired
         */
        addAuthenticator(auth) {
            // console.log("addAuthenticator");

            if (auth instanceof this.fidoAuthenticator) {
                console.log("Adding authenticator:", auth.name);
                this._authenticatorList.push(auth);
            } else {
                console.log("Adding authenticator: Authenticator was wrong type, failing:", auth);
            }
        }

        // removeAuthenticator
        listAuthenticators() {
            // cheap deep copy
            return JSON.parse(JSON.stringify(this._authenticatorList));
        }

        removeAllAuthenticators() {
                this._authenticatorList = [];
            }
            /*********************************************************************************
             * Everything below this line is an extension to the specification for managing extensions
             *********************************************************************************/
        addExtension(extensionHook) {
            this._extensionHookList.push(extensionHook);
        }

        removeExtension(extensionHook) {
            var index = this._extensionHookList.indexOf(extensionHook);
            if (index === -1) return;
            this._extensionHookList = this._extensionHookList.splice(index, 1);
        }
    } // END: class WebAuthentication
    var wa = new WebAuthentication();

    /*********************************************************************************
     * Everything below this line is internal support functions
     *********************************************************************************/
    // create clientData hash
    function _createClientDataHash(challenge, callerOrigin) {
        var clientDataJson = JSON.stringify({
            challenge: b64encode(challenge),
            origin: callerOrigin,
            hashAlg: "S256" // TODO: S384, S512, SM3
        });
        var clientDataBuffer = str2ab(clientDataJson);

        return window.crypto.subtle.digest({
                    name: "SHA-256",
                },
                clientDataBuffer
            )
            .then((hash) => {
                return {
                    hash: hash,
                    jsonBuf: clientDataBuffer,
                    json: clientDataJson
                };
            });
    }

    function _makeRpId(origin) {
        var parser = document.createElement("a");
        parser.href = origin;
        console.log("RPID:", parser.hostname);
        return parser.hostname;
    }

    function str2ab(str) {
        var buf = new ArrayBuffer(str.length);
        var bufView = new Uint8Array(buf);
        for (var i = 0, strLen = str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return buf;
    }

    function ab2str(buf) {
        return String.fromCharCode.apply(null, new Uint16Array(buf));
    }

    // borrowed from:
    // https://github.com/niklasvh/base64-arraybuffer/blob/master/lib/base64-arraybuffer.js
    // modified to base64url by Yuriy :)
    /*
     * base64-arraybuffer
     * https://github.com/niklasvh/base64-arraybuffer
     *
     * Copyright (c) 2012 Niklas von Hertzen
     * Licensed under the MIT license.
     */
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    function b64encode(arraybuffer) {
        var bytes = new Uint8Array(arraybuffer),
            i, len = bytes.length,
            base64 = "";

        for (i = 0; i < len; i += 3) {
            base64 += chars[bytes[i] >> 2];
            base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
            base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
            base64 += chars[bytes[i + 2] & 63];
        }

        if ((len % 3) === 2) {
            base64 = base64.substring(0, base64.length - 1) + "=";
        } else if (len % 3 === 1) {
            base64 = base64.substring(0, base64.length - 2) + "==";
        }

        return base64;
    }

    var supportedAlgorithms = {
        "aes-cbc": {
            name: "AES-CBC",
            dict: {
                name: "AES-CBC",
            },
            supports: ["encrypt", "decrypt", "generateKey"],
        },
        "aes-ctr": {
            name: "AES-CTR",
            dict: {
                name: "AES-CTR",
            },
            supports: ["encrypt", "decrypt", "generateKey"],
        },
        "aes-gcm": {
            name: "AES-GCM",
            dict: {
                name: "AES-GCM",
            },
            supports: ["encrypt", "decrypt", "generateKey"],
        },
        "pbkdf2": {
            name: "PBKDF2",
            dict: {
                name: "PBKDF2",
            },
            supports: ["derive_key"],
        },
        "md2": {
            name: "MD2",
            dict: {
                name: "MD2",
            },
            supports: ["digest"],
        },
        "md5": {
            name: "MD5",
            dict: {
                name: "MD5",
            },
            supports: ["digest"],
        },
        "sha-1": {
            name: "SHA-1",
            dict: {
                name: "SHA-1",
            },
            supports: ["digest"],
        },
        "sha-256": {
            name: "SHA-256",
            dict: {
                name: "SHA-256",
            },
            supports: ["digest"],
        },
        "sha-384": {
            name: "SHA-384",
            dict: {
                name: "SHA-384",
            },
            supports: ["digest"],
        },
        "sha-512": {
            name: "SHA-512",
            dict: {
                name: "SHA-512",
            },
            supports: ["digest"],
        },
        "rsassa-pkcs1-v1_5": {
            name: "RSASSA-PKCS1-v1_5",
            dict: {
                name: "RSASSA-PKCS1-v1_5",
            },
            supports: ["sign", "verify", "generateKey"],
        },
        "rsaes-pkcs1-v1_5": {
            name: "RSAES-PKCS1-v1_5",
            dict: {
                name: "RSAES-PKCS1-v1_5",
            },
            supports: ["encrypt", "decrypt", "generateKey"],
        }
    };

    function _normalizeAlgorithm(keyAlgorithm) {
        var res = {};
        if (typeof keyAlgorithm === "string") {
            keyAlgorithm = keyAlgorithm.toLowerCase();
            if (keyAlgorithm in supportedAlgorithms) {
                if ("dict" in supportedAlgorithms[keyAlgorithm]) {
                    res = supportedAlgorithms[keyAlgorithm].dict;
                    res = window.normalizeAlgorithm(res);
                } else {
                    throw new Error("Algorithm didn't have dictionary");
                }
            } else {
                throw new Error("Unknown algorithm");
            }
        } else {
            var key, val, tmp;
            for (key in keyAlgorithm) {
                if (key === "name") {
                    val = keyAlgorithm[key];
                    if (val in supportedAlgorithms) {
                        tmp = supportedAlgorithms[val];
                        tmp = tmp.dict.name;
                    } else {
                        tmp = val;
                    }
                    res[key] = tmp;
                }
                if (key !== "name" && keyAlgorithm[key] in supportedAlgorithms) {
                    res[key] = window.normalizeAlgorithm(keyAlgorithm[key]);
                } else {
                    res[key] = keyAlgorithm[key];
                }
            }
        }
        return res;
    }

    /**
     * Calls a method on all authenticators
     */
    var _callOnAllAuthenticators = function(timeoutSeconds, method, args) {
        return new Promise((resolve, reject) => {
            var pendingTimer = window.setTimeout(function() {
                console.log("makeCredential timed out");
                // TODO: call cancel on all pending authenticators
                var err = new Error("timedOut");
                reject(err);
            }, timeoutSeconds * 1000);

            // attempt to make credentials on each authenticator
            var i, _pendingList = [];
            console.log("me:", this);
            console.log("authnr list:", this._authenticatorList);
            for (i = 0; i < this._authenticatorList.length; i++) {
                // Web API 4.1.1 says to call with: callerOrigin, rpId, account, current.type, normalizedAlgorithm, blacklist, attestationChallenge and clientExtensions
                // External Authenticator Protocol 4.1 says to use the args below
                console.log("Calling authenticatorMakeCredential[" + i + "] with:", args);
                _pendingList.push(
                    this._authenticatorList[i][method].apply(this._authenticatorList[i], args)
                );
            }

            // basically Promises.all() that doesn't die on failure
            // TODO: this probably doesn"t work if the timer lapses, since it won"t .then() anything after the promise that hung
            // use some version of Promises.race() instead
            function resolveAll(promises) {
                var accumulator = [];
                var ready = Promise.resolve(null);

                promises.forEach(function(promise) {
                    ready = ready.then(() => {
                        return promise;
                    }).then((value) => {
                        // TODO: if result is cancel, then cancel all pending requests
                        console.log("Got value:", value);
                        accumulator.push(value);
                    }).catch((err) => {
                        accumulator.push(err);
                    });
                });

                return ready.then(() => {
                    return accumulator;
                });
            }

            resolveAll(_pendingList)
                .then((res) => {
                    console.log("all promises resolved:", res);
                    window.clearTimeout(pendingTimer);

                    // find the succesful result or return error
                    var i;
                    for (i = 0; i < res.length; i++) {
                        if (typeof res[i] !== undefined &&
                            !(res[i] instanceof Error)) {
                            console.log(method, "returning", res[i]);
                            return resolve(res[i]);
                        }
                    }
                    console.log("No successful authenticatons");
                    return resolve(new Error("No successful authenticatons"));
                })
                .catch((err) => {
                    console.log("caught error");
                    return reject(err);
                });
        });
    };

    // All WebAuthn interfaces (as defined in WebIDL) should only be exposed in a Secure Context
    if (window.isSecureContext) {
        // define navigator.authentication without setter to prevent hijacking
        Object.defineProperty(navigator, "authentication", {
            configurable: false,
            writable: false,
            value: wa
        });
        // freeze returned object to make sure functions aren't hijacked
        // Object.freeze(navigator.authentication);

        // configure WebIDL interfaces in a way that makes idlharness happy
        Object.defineProperty(window, "WebAuthentication", {
            configurable: true,
            writable: true,
            enumberable: true,
            value: WebAuthentication
        });
        Object.defineProperty(window, "ScopedCredentialInfo", {
            configurable: true,
            writable: true,
            enumberable: true,
            value: ScopedCredentialInfo
        });
    }
}());


// TODO: remove this debug code
function printHex(msg, buf) {
    // if the buffer was a TypedArray (e.g. Uint8Array), grab its buffer and use that
    if (ArrayBuffer.isView(buf) && buf.buffer instanceof ArrayBuffer) {
        buf = buf.buffer;
    }

    // check the arguments
    if ((typeof msg != "string") ||
        (typeof buf != "object")) {
        console.log("Bad args to printHex");
        return;
    }
    if (!(buf instanceof ArrayBuffer)) {
        console.log("Attempted printHex with non-ArrayBuffer:", buf);
        return;
    }
    // print the buffer as a 16 byte long hex string
    var arr = new Uint8Array(buf);
    var len = buf.byteLength;
    var i, str = "";
    console.log(msg);
    for (i = 0; i < len; i++) {
        var hexch = arr[i].toString(16);
        hexch = (hexch.length == 1) ? ("0" + hexch) : hexch;
        str += hexch.toUpperCase() + " ";
        if (i && !((i + 1) % 16)) {
            console.log(str);
            str = "";
        }
    }
    // print the remaining bytes
    if ((i) % 16) {
        console.log(str);
    }
}