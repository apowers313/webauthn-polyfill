var assert = chai.assert;

/*
 * Test fixtures
 * TODO: Move to another file
 */
var userAccountInformation = {
    rpDisplayName: "PayPal",
    displayName: "John P. Smith",
    name: "johnpsmith@gmail.com",
    id: "1098237235409872",
    imageUri: "https://pics.paypal.com/00/p/aBjjjpqPb.png"
};
// This Relying Party will accept either an ES256 or RS256 credential, but 
// prefers an ES256 credential.
var cryptoParams = [{
    type: "FIDO",
    algorithm: "ES256",
}, {
    type: "FIDO",
    algorithm: "RS256",
}];
var challenge = "Y2xpbWIgYSBtb3VudGFpbg";
// var timeoutSeconds = 300; // 5 minutes
var timeoutSeconds = 1;
var blacklist = []; // No blacklist
var extensions = {
    "fido.location": true // Include location information in attestation
};
// window.fido.addAuthenticator (new fidoAuthenticator());

/*
 * Basic tests
 * If these fail, probably something isn't loaded right and certainly everything else is going to fail
 */
suite("Basic Tests", function () {
    test("window.fido exists", function () {
        assert.isDefined(window.fido, "window.fido should be defined");
    });

    test("makeCredential exists", function () {
        assert.isDefined(window.fido.makeCredential, "makeCredential should exist on FIDO object");
        assert.isFunction(window.fido.makeCredential, "makeCredential should be a function");
    });

    test("getAssertion exists", function () {
        assert.isDefined(window.fido.getAssertion, "makeCredential should exist on FIDO object");
        assert.isFunction(window.fido.getAssertion, "makeCredential should be a function");
    });
});

// suite.only("Testing", function () {

// });

suite("makeCredential Tests", function () {
    teardown(function () {
        window.fido.removeAllAuthenticators();
    });

    test("makeCredential returns promise", function () {
        var fidoAPI = window.fido;
        var promise = fidoAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
            timeoutSeconds, blacklist, extensions);
        assert.isObject(promise, "makeCredential should return a function");
        // not sure this is fair... what if we are using a Promise polyfill / shim on a non-ES6 browser?
        assert.instanceOf(promise, Promise, "makeCredential should return a promise");
    });


    test("makeCredential is callable", function () {
        var fidoAPI = window.fido;
        fidoAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
            timeoutSeconds, blacklist, extensions);
    });

    test("makeCredential should call authenticatorMakeCredential", function (done) {
        var fidoAPI = window.fido;
        var auth = new fidoAPI.fidoAuthenticator();
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        fidoAPI.addAuthenticator(auth);

        fidoAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
            timeoutSeconds, blacklist, extensions)
            .then(function (ret) {
                sinon.assert.calledOnce(spy);
                sinon.assert.alwaysCalledWithExactly(spy, "localhost", userAccountInformation, /* clientDataHash, cryptoParameters,*/ blacklist, extensions);
                assert.deepEqual(ret, [true], "Should return [true] ret");
                done();
            })
            .catch(function (err) {
            	console.log ("Error:", err);
                assert(false, "Promise should not be rejected");
                done();
            });
    });

    test("makeCredential timeout", function (done) {
        var fidoAPI = window.fido;
        var auth = new fidoAPI.fidoAuthenticator();

        function authenticatorMakeCredential() {
            return new Promise(function (resolve, reject) {
                /* never fulfilled, should time out */
            });
        }
        auth.authenticatorMakeCredential = authenticatorMakeCredential;
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        fidoAPI.addAuthenticator(auth);

        fidoAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
            1, blacklist, extensions)
            .then(function (ret) {
            	console.log ("Ret:", ret);
                assert(false, "Should not receive successful Promise result");
                done();
            })
            .catch(function (err) {
                sinon.assert.calledOnce(spy);
                assert.strictEqual(err.message, "timedOut", "Should receive error with message 'timedOut'");
                done();
            });
    });

    test("makeCredential resolved promise shouldn't timeout", function (done) {
        var fidoAPI = window.fido;
        var auth = new fidoAPI.fidoAuthenticator();

        function authenticatorMakeCredential() {
            return new Promise(function (resolve, reject) {
                resolve("beer");
            });
        }
        auth.authenticatorMakeCredential = authenticatorMakeCredential;
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        fidoAPI.addAuthenticator(auth);

        fidoAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
            1, blacklist, extensions)
            .then(function (ret) {
                sinon.assert.calledOnce(spy);
                assert.deepEqual(ret, ["beer"], "authenticatorMakeCredential should give me 'beer'");
                done();
            })
            .catch(function (err) {
            	console.log ("Error:", err);
                assert(false, "Should not reject Promise");
                done();
            });
    });

    test("makeCredential should return successful promise", function (done) {
        var fidoAPI = window.fido;
        var auth = new fidoAPI.fidoAuthenticator();

        function authenticatorMakeCredential() {
            return new Promise(function (resolve, reject) {
                resolve("beer");
            });
        }
        auth.authenticatorMakeCredential = authenticatorMakeCredential;
        var spy = sinon.spy(auth, "authenticatorMakeCredential");
        fidoAPI.addAuthenticator(auth);

        fidoAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
            1, blacklist, extensions)
            .then(function (ret) {
                sinon.assert.calledOnce(spy);
                assert.deepEqual(ret, ["beer"], "authenticatorMakeCredential should give me ['beer']");
                done();
            })
            .catch(function (err) {
            	console.log ("Error:", err);
                assert(false, "Should not reject Promise");
                done();
            });
    });

    test("makeCredential should return successful promise for two authenticators", function (done) {
        var fidoAPI = window.fido;

        // make authenticator 1
        var auth1 = new fidoAPI.fidoAuthenticator();
        function amc1() {
            return new Promise(function (resolve, reject) {
                resolve("beer");
            });
        }
        auth1.authenticatorMakeCredential = amc1;
        var spy1 = sinon.spy(auth1, "authenticatorMakeCredential");
        fidoAPI.addAuthenticator(auth1);

        // make authenticator 2
        var auth2 = new fidoAPI.fidoAuthenticator();
        function amc2() {
            return new Promise(function (resolve, reject) {
                resolve("whiskey");
            });
        }
        auth2.authenticatorMakeCredential = amc2;
        var spy2 = sinon.spy(auth2, "authenticatorMakeCredential");
        fidoAPI.addAuthenticator(auth2);

        fidoAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
            1, blacklist, extensions)
            .then(function (ret) {
                sinon.assert.calledOnce(spy1);
                sinon.assert.calledOnce(spy2);
                assert.deepEqual(ret, ["beer", "whiskey"], "authenticatorMakeCredential should give me ['beer']");
                done();
            })
            .catch(function (err) {
            	console.log ("Error:", err);
                assert(false, "Should not reject Promise");
                done();
            });
    });

    test.skip ("makeCredential should return successful promise for two authenticators where one times out", function (done) {
        var fidoAPI = window.fido;

        // make authenticator 1
        var auth1 = new fidoAPI.fidoAuthenticator();
        function amc1() {
            return new Promise(function (resolve, reject) {
                resolve("beer");
            });
        }
        auth1.authenticatorMakeCredential = amc1;
        var spy1 = sinon.spy(auth1, "authenticatorMakeCredential");
        fidoAPI.addAuthenticator(auth1);

        // make authenticator 2
        var auth2 = new fidoAPI.fidoAuthenticator();
        function amc2() {
            return new Promise(function (resolve, reject) {
                /* never fulfilled, should time out */
            });
        }
        auth2.authenticatorMakeCredential = amc2;
        var spy2 = sinon.spy(auth2, "authenticatorMakeCredential");
        fidoAPI.addAuthenticator(auth2);

        fidoAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
            1, blacklist, extensions)
            .then(function (ret) {
                sinon.assert.calledOnce(spy1);
                sinon.assert.calledOnce(spy2);
                assert.deepEqual(ret, ["beer"], "authenticatorMakeCredential should give me ['beer']");
                done();
            })
            .catch(function (err) {
            	console.log ("Error:", err);
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

suite("getAssertion Tests", function () {
    test("Challenge");
    test("Timeout");
    test("Credentials");
});

suite("Decommissioning", function () {
    test("Decommissioning");
});

suite("Proprietary Tests", function () {
    teardown(function () {
        window.fido.removeAllAuthenticators();
    });

    test("addAuthenticator", function () {
        var fidoAPI = window.fido;

        assert.isDefined(fidoAPI.addAuthenticator, "Should have addAuthenticator extension");
        assert.isDefined(fidoAPI.listAuthenticators, "Should have listAuthenticators extension");
        assert.isDefined(fidoAPI.fidoAuthenticator, "Should have fidoAuthenticator extension");
        assert.isDefined(fidoAPI.removeAllAuthenticators, "Shouldh have removeAllAuthenticators extension");
        assert.strictEqual(fidoAPI.listAuthenticators().length, 0, "Shouldn't have any authenticators yet");

        fidoAPI.addAuthenticator(new fidoAPI.fidoAuthenticator());
        assert.strictEqual(fidoAPI.listAuthenticators().length, 1, "Should have one authenticator");
    });
    test("Helper objects");
    test("Multiple authenticators");
});