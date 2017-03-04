var assert = chai.assert;
var h = fido2Helpers;

/***********************
 * Helpers
 ************************/
//TODO: Move to another file
var userAccountInformation = {
    rpDisplayName: "PayPal",
    displayName: "John P. Smith",
    name: "johnpsmith@gmail.com",
    id: "1098237235409872",
    imageUri: "https://pics.paypal.com/00/p/aBjjjpqPb.png"
};
var cryptoParams = [{
    type: "ScopedCred",
    algorithm: "RSASSA-PKCS1-v1_5",
}];
var expectedCryptoParams = {
    type: "ScopedCred",
    algorithm: "RSASSA-PKCS1-v1_5",
};
// var challenge = new ArrayBuffer([
//     0x59, 0x32, 0x78, 0x70, 0x62, 0x57, 0x49, 0x67, 0x59, 0x53, 0x42, 0x74, 0x62, 0x33, 0x56, 0x75, 0x64, 0x47, 0x46, 0x70, 0x62, 0x67
//     ]);
var challenge = "Y2xpbWIgYSBtb3VudGFpbg";
var rpId = "localhost";
// var timeoutSeconds = 300; // 5 minutes
var timeoutOpts = {
    timeout: 1
};
var timeoutSeconds = 1;
var blacklist = []; // No blacklist
var whitelist = []; // No whitelist
// var extensions = {
//     "fido.location": true // Include location information in attestation
// };
var extensions = [];
var calculatedClientData = {
    challenge: "Y2xpbWIgYSBtb3VudGFpbg",
    facet: "http://localhost:8000",
    hashAlg: "S256"
};
var expectedClientDataHash = new ArrayBuffer([227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85]);
var validMakeCredential = {
    credential: {
        type: 'ScopedCred',
        id: '8DD7414D-EE43-474C-A05D-FDDB828B663B'
    },
    publicKey: {
        kty: 'RSA',
        alg: 'RS256',
        ext: false,
        n: 'lMR4XoxRiY5kptgHhh1XLKnezHC2EWPIImlHS-iUMSKVH32WWUKfEoY5Al_exPtcVuUfcNGtMoysAN65PZzcMKXaQ-2a8AebKwe8qQGBc4yY0EkP99Sgb80rAf1S7s-JRNVtNTRb4qrXVCMxZHu3ubjsdeybMI-fFKzYg9IV6DPotJyx1OpNSdibSwWKDTc5YzGfoOG3vA-1ae9oFOh5ZolhHnr5UkodFKUaxOOHfPrAB0MVT5Y5Stvo_Z_1qFDOLyOWdhxxzl2at3K9tyQC8kgJCNKYsq7-EFzvA9Q90PC6SxGATQoICKn2vCNMBqVHLlTydBmP7-8MoMxefM277w',
        e: 'AQAB'
    },
    attestation: null
};
// window.navigator.authentication.addAuthenticator (new fidoAuthenticator());

/*
 * Basic tests
 * If these fail, probably something isn't loaded right and certainly everything else is going to fail
 */
describe("API", function() {
    it("window.navigator.authentication exists", function() {
        assert.isDefined(window.navigator.authentication, "window.navigator.authentication should be defined");
    });

    it("makeCredential exists", function() {
        assert.isDefined(window.navigator.authentication.makeCredential, "makeCredential should exist on WebAuthn object");
        assert.isFunction(window.navigator.authentication.makeCredential, "makeCredential should be a function");
    });

    it("getAssertion exists", function() {
        assert.isDefined(window.navigator.authentication.getAssertion, "getAssertion should exist on WebAuthn object");
        assert.isFunction(window.navigator.authentication.getAssertion, "getAssertion should be a function");
    });
});

// describe.only("Testing", function () {

// });

describe("makeCredential", function() {
    afterEach(function() {
        window.navigator.authentication.removeAllAuthenticators();
    });

    it("makeCredential returns promise", function() {
        var webAuthnAPI = window.navigator.authentication;
        var promise = webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, h.challenge);
        console.log("Got promise:", promise);
        // MS Edge doesn't show that a Promise is an object... strange
        // assert.isObject(promise, "makeCredential should return a function");
        // not sure this is fair... what if we are using a Promise polyfill / shim on a non-ES6 browser?
        assert.instanceOf(promise, Promise, "makeCredential should return a promise");
    });


    it("makeCredential is callable", function() {
        var webAuthnAPI = window.navigator.authentication;
        return webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, h.challenge);
    });

    it("makeCredential should call authenticatorMakeCredential", function() {
        var webAuthnAPI = window.navigator.authentication;
        var auth = new webAuthnAPI.fidoAuthenticator();
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth);

        return webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, h.challenge)
            .then(function(ret) {
                sinon.assert.calledOnce(spy);
                // TODO: update this assertion
                sinon.assert.alwaysCalledWithExactly(spy, rpId, userAccountInformation, expectedClientDataHash, expectedCryptoParams, blacklist, extensions);
                assert.deepEqual(ret, null, "Should return null ret");
            });
    });

    it("makeCredential timeout", function() {
        this.timeout(3000);
        this.slow(2100);
        var webAuthnAPI = window.navigator.authentication;
        var auth = new webAuthnAPI.fidoAuthenticator();

        function authenticatorMakeCredential() {
            return new Promise(function(resolve, reject) {
                /* never fulfilled, should time out */
            });
        }
        auth.authenticatorMakeCredential = authenticatorMakeCredential;
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth);

        return webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, h.challenge, h.timeoutOpts)
            .then(function(ret) {
                console.log("Ret:", ret);
                assert(false, "Should not receive successful Promise result");
            })
            .catch(function(err) {
                assert.strictEqual(err.message, "timedOut", "Should receive error with message 'timedOut'");
                sinon.assert.calledOnce(spy);
            });
    });

    it("makeCredential resolved promise shouldn't timeout", function() {
        var webAuthnAPI = window.navigator.authentication;
        var auth = new webAuthnAPI.fidoAuthenticator();

        function authenticatorMakeCredential() {
            return new Promise(function(resolve, reject) {
                console.log ("RESOLVING!!!");
                resolve("beer");
            });
        }
        auth.authenticatorMakeCredential = authenticatorMakeCredential;
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth);

       return webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, h.challenge, h.timeoutOpts)
            .then(function(ret) {
                sinon.assert.calledOnce(spy);
                assert.deepEqual(ret, "beer", "authenticatorMakeCredential should give me 'beer'");
            });
    });

    it("makeCredential should return successful promise", function() {
        var webAuthnAPI = window.navigator.authentication;
        var auth = new webAuthnAPI.fidoAuthenticator();

        function authenticatorMakeCredential() {
            return new Promise(function(resolve, reject) {
                resolve("beer");
            });
        }
        auth.authenticatorMakeCredential = authenticatorMakeCredential;
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth);

        return webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, h.challenge, h.timeoutOpts)
            .then(function(ret) {
                sinon.assert.calledOnce(spy);
                assert.deepEqual(ret, "beer", "authenticatorMakeCredential should give me 'beer'");
            });
    });

    it("makeCredential should return successful promise for two authenticators", function() {
        var webAuthnAPI = window.navigator.authentication;

        // make authenticator 1
        var auth1 = new webAuthnAPI.fidoAuthenticator();

        function amc1() {
            return new Promise(function(resolve, reject) {
                resolve("beer");
            });
        }
        auth1.authenticatorMakeCredential = amc1;
        var spy1 = sinon.spy(auth1, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth1);

        // make authenticator 2
        var auth2 = new webAuthnAPI.fidoAuthenticator();

        function amc2() {
            return new Promise(function(resolve, reject) {
                resolve("whiskey");
            });
        }
        auth2.authenticatorMakeCredential = amc2;
        var spy2 = sinon.spy(auth2, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth2);

        return webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, h.challenge, h.timeoutOpts)
            .then(function(ret) {
                sinon.assert.calledOnce(spy1);
                sinon.assert.calledOnce(spy2);
                assert.deepEqual(ret, "beer", "authenticatorMakeCredential should give me 'beer'");
            });
    });

    it.skip("makeCredential should return successful promise for two authenticators where one times out", function(done) {
        var webAuthnAPI = window.navigator.authentication;

        // make authenticator 1
        var auth1 = new webAuthnAPI.fidoAuthenticator();

        function amc1() {
            return new Promise(function(resolve, reject) {
                resolve("beer");
            });
        }
        auth1.authenticatorMakeCredential = amc1;
        var spy1 = sinon.spy(auth1, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth1);

        // make authenticator 2
        var auth2 = new webAuthnAPI.fidoAuthenticator();

        function amc2() {
            return new Promise(function(resolve, reject) {
                /* never fulfilled, should time out */
            });
        }
        auth2.authenticatorMakeCredential = amc2;
        var spy2 = sinon.spy(auth2, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth2);

        webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
                1, blacklist, extensions)
            .then(function(ret) {
                sinon.assert.calledOnce(spy1);
                sinon.assert.calledOnce(spy2);
                assert.deepEqual(ret, ["beer"], "authenticatorMakeCredential should give me ['beer']");
                done();
            })
            .catch(function(err) {
                console.log("Error:", err);
                assert(false, "Should not reject Promise");
                done();
            });
    });

    it("makeCredential calls authenticatorCancel when timed out");
    it("makeCredential fails without account parameter");
    it("makeCredential fails without cryptoParameters parameter");
    it("makeCredential fails without attestationChallenge parameter");
    it("makeCredential passes without timeoutSeconds parameter");
    it("makeCredential passes without blacklist parameter");
    it("makeCredential passes without extensions parameter");
    it("makeCredential with basic accountInfo");
    it("makeCredential with missing accountInfo");
    it("Crypto Params");
    it("Challenge");
    it("Timeout");
    it("Blacklist");
    it("Extensions");
});

describe("getAssertion Tests", function() {
    afterEach(function() {
        window.navigator.authentication.removeAllAuthenticators();
    });

    it("getAssertion returns promise", function() {
        var webAuthnAPI = window.navigator.authentication;
        var promise = webAuthnAPI.getAssertion(userAccountInformation, cryptoParams, challenge,
            timeoutSeconds, blacklist, extensions);
        console.log("Got promise:", promise);
        // MS Edge doesn't show that a Promise is an object... strange
        // assert.isObject(promise, "getAssertion should return a function");
        // not sure this is fair... what if we are using a Promise polyfill / shim on a non-ES6 browser?
        assert.instanceOf(promise, Promise, "getAssertion should return a promise");
    });


    it("getAssertion is callable", function() {
        var webAuthnAPI = window.navigator.authentication;
        return webAuthnAPI.getAssertion(userAccountInformation, cryptoParams, challenge,
            timeoutSeconds, blacklist, extensions);
    });

    it.skip("getAssertion should call authenticatorGetAssertion", function() {
        var webAuthnAPI = window.navigator.authentication;
        var auth = new webAuthnAPI.fidoAuthenticator();
        var spy = sinon.spy(auth, "authenticatorGetAssertion");
        webAuthnAPI.addAuthenticator(auth);

        return webAuthnAPI.getAssertion(h.challenge, h.timeoutOpts)
            .then(function(ret) {
                sinon.assert.calledOnce(spy);
                // TODO: update this assertion
                // rpId,
                //         callerOrigin,
                //         assertionChallenge,
                //         clientDataHash,
                //         whitelist,
                //         extensions
                sinon.assert.alwaysCalledWithExactly(spy, rpId, challenge, expectedClientDataHash, whitelist, extensions);
                assert.deepEqual(ret, null, "Should return null ret");
            });
    });

    it("Challenge");
    it("Timeout");
    it("Credentials");
});

describe("Decommissioning", function() {
    it("Decommissioning");
});

describe("Proprietary Tests", function() {
    afterEach(function() {
        window.navigator.authentication.removeAllAuthenticators();
    });

    it("addAuthenticator", function() {
        var webAuthnAPI = window.navigator.authentication;

        assert.isDefined(webAuthnAPI.addAuthenticator, "Should have addAuthenticator extension");
        assert.isDefined(webAuthnAPI.listAuthenticators, "Should have listAuthenticators extension");
        assert.isDefined(webAuthnAPI.fidoAuthenticator, "Should have fidoAuthenticator extension");
        assert.isDefined(webAuthnAPI.removeAllAuthenticators, "Should have removeAllAuthenticators extension");
        assert.strictEqual(webAuthnAPI.listAuthenticators().length, 0, "Shouldn't have any authenticators yet");

        webAuthnAPI.addAuthenticator(new webAuthnAPI.fidoAuthenticator());
        assert.strictEqual(webAuthnAPI.listAuthenticators().length, 1, "Should have one authenticator");
    });
    it("Helper objects");
    it("Multiple authenticators");
});

/* JSHINT */
/* globals sinon, afterEach */