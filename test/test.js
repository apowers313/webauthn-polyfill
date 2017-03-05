var assert = chai.assert;
var h = fido2Helpers;

function arrayBufferEquals(b1, b2) {
    if (b1.byteLength !== b2.byteLength) return false;
    b1 = new Uint8Array(b1);
    b2 = new Uint8Array(b2);
    for (let i = 0; i < b1.byteLength; i++) {
        if (b1[i] !== b2[i]) return false;
    }
    return true;
}

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
        var promise = webAuthnAPI.makeCredential(h.userAccountInformation, h.cryptoParams, h.challenge);
        console.log("Got promise:", promise);
        // MS Edge doesn't show that a Promise is an object... strange
        // assert.isObject(promise, "makeCredential should return a function");
        // not sure this is fair... what if we are using a Promise polyfill / shim on a non-ES6 browser?
        assert.instanceOf(promise, Promise, "makeCredential should return a promise");
    });


    it("makeCredential is callable", function() {
        var webAuthnAPI = window.navigator.authentication;
        return webAuthnAPI.makeCredential(h.userAccountInformation, h.cryptoParams, h.challenge);
    });

    it("makeCredential should call authenticatorMakeCredential", function() {
        var webAuthnAPI = window.navigator.authentication;
        var auth = new webAuthnAPI.fidoAuthenticator();
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        webAuthnAPI.addAuthenticator(auth);
        printHex ("h.challenge", h.challenge);

        return webAuthnAPI.makeCredential(h.userAccountInformation, h.cryptoParams, h.challenge)
            .then(function(ret) {
                printHex ("h.clientDataJsonBuf", h.clientDataJsonBuf);
                sinon.assert.calledOnce(spy);
                // TODO: update this assertion
                console.log ("spy args", spy.args);
                assert.deepEqual (spy.args[0][0], h.rpIdHash);
                assert.deepEqual (spy.args[0][1], h.userAccountInformation);
                assert.deepEqual (spy.args[0][2], h.clientDataHash);
                assert.deepEqual (spy.args[0][3], h.expectedCryptoParams);
                sinon.assert.alwaysCalledWithExactly(spy, h.rpIdHash, h.userAccountInformation, h.clientDataHash, "ScopedCred", [], []);
                assert(arrayBufferEquals(h.rpIdHash, spy.args[0][0]), "rpIdHash didn't match");
                printHex ("spy.args[0][2])", spy.args[0][2]);
                assert(arrayBufferEquals(h.clientDataHash, spy.args[0][2]), "clientDataHash didn't match");
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

        return webAuthnAPI.makeCredential(h.userAccountInformation, h.cryptoParams, h.challenge, h.timeoutOpts)
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

       return webAuthnAPI.makeCredential(h.userAccountInformation, h.cryptoParams, h.challenge, h.timeoutOpts)
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

        return webAuthnAPI.makeCredential(h.userAccountInformation, h.cryptoParams, h.challenge, h.timeoutOpts)
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

        return webAuthnAPI.makeCredential(h.userAccountInformation, h.cryptoParams, h.challenge, h.timeoutOpts)
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

        webAuthnAPI.makeCredential(h.userAccountInformation, h.cryptoParams, h.challenge, h.timeoutOpts)
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
        var promise = webAuthnAPI.getAssertion(h.userAccountInformation, h.cryptoParams, h.challenge);
        console.log("Got promise:", promise);
        // MS Edge doesn't show that a Promise is an object... strange
        // assert.isObject(promise, "getAssertion should return a function");
        // not sure this is fair... what if we are using a Promise polyfill / shim on a non-ES6 browser?
        assert.instanceOf(promise, Promise, "getAssertion should return a promise");
    });


    it("getAssertion is callable", function() {
        var webAuthnAPI = window.navigator.authentication;
        return webAuthnAPI.getAssertion(h.userAccountInformation, h.cryptoParams, h.challenge);
    });

    it("getAssertion should call authenticatorGetAssertion", function() {
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
                sinon.assert.alwaysCalledWithExactly(spy, h.rpIdHash, h.clientDataHash, [], []);
                assert.deepEqual(ret, null, "Should return null ret");
                assert(arrayBufferEquals(h.rpIdHash, spy.args[0][0]), "rpIdHash didn't match");
                assert(arrayBufferEquals(h.clientDataHash, spy.args[0][1]), "clientDataHash didn't match");
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