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
var timeoutSeconds = 300; // 5 minutes
var blacklist = []; // No blacklist
var extensions = {
    "fido.location": true // Include location information in attestation
};

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

suite("makeCredential Tests", function () {

    test("makeCredential returns promise", function () {
        var fidoAPI = window.fido;
        var ret = fidoAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
            timeoutSeconds, blacklist, extensions);
        assert.isObject(ret, "makeCredential should return a function");
        // not sure this is fair... what if we are using a Promise polyfill / shim on a non-ES6 browser?
        assert.instanceOf(ret, Promise, "makeCredential should return a promise");
    });

    test("makeCredential is callable", function () {
        var fidoAPI = window.fido;
        fidoAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
            timeoutSeconds, blacklist, extensions);
    });
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
    test.skip("Discovery", function () {
    	authDiscover();
    });
    test("Helper objects");
    test("Multiple authenticators");
});