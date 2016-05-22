var assert = chai.assert;

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
var challenge = "Y2xpbWIgYSBtb3VudGFpbg";
// var timeoutSeconds = 300; // 5 minutes
var timeoutSeconds = 1;
var blacklist = []; // No blacklist
var extensions = {
    "fido.location": true // Include location information in attestation
};
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
// window.webauthn.addAuthenticator (new fidoAuthenticator());

/*
 * Basic tests
 * If these fail, probably something isn't loaded right and certainly everything else is going to fail
 */
suite("Basic Tests", function() {
    test("window.webauthn exists", function() {
        assert.isDefined(window.webauthn, "window.webauthn should be defined");
    });

    test("makeCredential exists", function() {
        assert.isDefined(window.webauthn.makeCredential, "makeCredential should exist on WebAuthn object");
        assert.isFunction(window.webauthn.makeCredential, "makeCredential should be a function");
    });

    test("getAssertion exists", function() {
        assert.isDefined(window.webauthn.getAssertion, "getAssertion should exist on WebAuthn object");
        assert.isFunction(window.webauthn.getAssertion, "getAssertion should be a function");
    });
});

// suite.only("Testing", function () {

// });

suite("makeCredential Tests", function() {
    teardown(function() {
        window.webauthn.removeAllAuthenticators();
    });

    test("makeCredential returns promise", function() {
        var webAuthnAPI = window.webauthn;
        var promise = webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
            timeoutSeconds, blacklist, extensions);
        console.log("Got promise:", promise);
        // MS Edge doesn't show that a Promise is an object... strange
        // assert.isObject(promise, "makeCredential should return a function");
        // not sure this is fair... what if we are using a Promise polyfill / shim on a non-ES6 browser?
        assert.instanceOf(promise, Promise, "makeCredential should return a promise");
    });


    test("makeCredential is callable", function() {
        var webAuthnAPI = window.webauthn;
        return webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
            timeoutSeconds, blacklist, extensions);
    });

    test("makeCredential should call authenticatorMakeCredential", function(done) {
        var webAuthnAPI = window.webauthn;
        var auth = new webAuthnAPI.fidoAuthenticator();
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth);

        webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
                timeoutSeconds, blacklist, extensions)
            .then(function(ret) {
                sinon.assert.calledOnce(spy);
                // TODO: update this assertion
                sinon.assert.alwaysCalledWithExactly(spy, "localhost", userAccountInformation, expectedClientDataHash, expectedCryptoParams, blacklist, extensions);
                assert.deepEqual(ret, null, "Should return null ret");
                done();
            })
            .catch(function(err) {
                console.log("Error:", err);
                assert(false, "Promise should not be rejected");
                done();
            });
    });

    test("makeCredential timeout", function(done) {
        var webAuthnAPI = window.webauthn;
        var auth = new webAuthnAPI.fidoAuthenticator();

        function authenticatorMakeCredential() {
            return new Promise(function(resolve, reject) {
                /* never fulfilled, should time out */
            });
        }
        auth.authenticatorMakeCredential = authenticatorMakeCredential;
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth);

        webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
                1, blacklist, extensions)
            .then(function(ret) {
                console.log("Ret:", ret);
                assert(false, "Should not receive successful Promise result");
                done();
            })
            .catch(function(err) {
                sinon.assert.calledOnce(spy);
                assert.strictEqual(err.message, "timedOut", "Should receive error with message 'timedOut'");
                done();
            });
    });

    test("makeCredential resolved promise shouldn't timeout", function(done) {
        var webAuthnAPI = window.webauthn;
        var auth = new webAuthnAPI.fidoAuthenticator();

        function authenticatorMakeCredential() {
            return new Promise(function(resolve, reject) {
                resolve("beer");
            });
        }
        auth.authenticatorMakeCredential = authenticatorMakeCredential;
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth);

        webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
                1, blacklist, extensions)
            .then(function(ret) {
                sinon.assert.calledOnce(spy);
                assert.deepEqual(ret, "beer", "authenticatorMakeCredential should give me 'beer'");
                done();
            })
            .catch(function(err) {
                console.log("Error:", err);
                assert(false, "Should not reject Promise");
                done();
            });
    });

    test("makeCredential should return successful promise", function(done) {
        var webAuthnAPI = window.webauthn;
        var auth = new webAuthnAPI.fidoAuthenticator();

        function authenticatorMakeCredential() {
            return new Promise(function(resolve, reject) {
                resolve("beer");
            });
        }
        auth.authenticatorMakeCredential = authenticatorMakeCredential;
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth);

        webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
                1, blacklist, extensions)
            .then(function(ret) {
                sinon.assert.calledOnce(spy);
                assert.deepEqual(ret, "beer", "authenticatorMakeCredential should give me 'beer'");
                done();
            })
            .catch(function(err) {
                console.log("Error:", err);
                assert(false, "Should not reject Promise");
                done();
            });
    });

    test("makeCredential should return successful promise for two authenticators", function(done) {
        var webAuthnAPI = window.webauthn;

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

        webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
                1, blacklist, extensions)
            .then(function(ret) {
                sinon.assert.calledOnce(spy1);
                sinon.assert.calledOnce(spy2);
                assert.deepEqual(ret, "beer", "authenticatorMakeCredential should give me 'beer'");
                done();
            })
            .catch(function(err) {
                console.log("Error:", err);
                assert(false, "Should not reject Promise");
                done();
            });
    });

    test.skip("makeCredential should return successful promise for two authenticators where one times out", function(done) {
        var webAuthnAPI = window.webauthn;

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

    test("makeCredential calls authenticatorCancel when timed out");
    test("makeCredential fails without account parameter");
    test("makeCredential fails without cryptoParameters parameter");
    test("makeCredential fails without attestationChallenge parameter");
    test("makeCredential passes without timeoutSeconds parameter");
    test("makeCredential passes without blacklist parameter");
    test("makeCredential passes without extensions parameter");
    test("makeCredential with basic accountInfo");
    test("makeCredential with missing accountInfo");
    test("Crypto Params");
    test("Challenge");
    test("Timeout");
    test("Blacklist");
    test("Extensions");
});

suite("getAssertion Tests", function() {
    test("Challenge");
    test("Timeout");
    test("Credentials");
});

suite("Decommissioning", function() {
    test("Decommissioning");
});

suite("Proprietary Tests", function() {
    teardown(function() {
        window.webauthn.removeAllAuthenticators();
    });

    test("addAuthenticator", function() {
        var webAuthnAPI = window.webauthn;

        assert.isDefined(webAuthnAPI.addAuthenticator, "Should have addAuthenticator extension");
        assert.isDefined(webAuthnAPI.listAuthenticators, "Should have listAuthenticators extension");
        assert.isDefined(webAuthnAPI.fidoAuthenticator, "Should have fidoAuthenticator extension");
        assert.isDefined(webAuthnAPI.removeAllAuthenticators, "Should have removeAllAuthenticators extension");
        assert.strictEqual(webAuthnAPI.listAuthenticators().length, 0, "Shouldn't have any authenticators yet");

        webAuthnAPI.addAuthenticator(new webAuthnAPI.fidoAuthenticator());
        assert.strictEqual(webAuthnAPI.listAuthenticators().length, 1, "Should have one authenticator");
    });
    test("Helper objects");
    test("Multiple authenticators");
});