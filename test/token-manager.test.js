/*
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * token-manager.test.js: Unit tests for token-manager
 * module
 */

var _helper = __dirname + '/helper.js';
if (require.cache[_helper])
    delete require.cache[_helper];
var helper = require(_helper);

var tokenManager = require('../lib/auth/token-manager');

var test = helper.test;


///--- Globals

var AES_CONFIG = {
    salt: 'C93A670ACC05C166',
    key: '5163205CA0C7F2752FD3A574E30F64DD',
    iv: '6B11F0F0B786F96812D5A0799D5B217A',
    maxAge: 3600000  // 1 hour
};

var TEST_CALLER = {
    account: {
        uuid: '930896af-bf8c-48d4-885c-6573a94b1853',
        login: 'testuser',
        groups: ['users'],
        approved_for_provisioning: true
    }
};


///--- Tests

test('create token with account only', function (t) {
    var opts = {
        caller: TEST_CALLER,
        context: {},
        fromjob: false
    };

    tokenManager.create(opts, AES_CONFIG,
        function (err, token) {
        t.ifError(err, 'no error creating token');
        t.ok(token, 'token created');
        t.equal(typeof (token), 'string',
            'token is string');
        t.ok(token.length > 0, 'token not empty');
        t.end();
    });
});


test('create and parse token roundtrip', function (t) {
    var opts = {
        caller: TEST_CALLER,
        context: {
            owner: 'testowner',
            method: 'GET'
        },
        fromjob: false
    };

    tokenManager.create(opts, AES_CONFIG,
        function (err, token) {
        t.ifError(err, 'no error creating token');

        tokenManager.parse(token, AES_CONFIG,
            function (err2, obj) {
            t.ifError(err2, 'no error parsing token');
            t.ok(obj, 'parsed object exists');
            t.ok(obj.principal, 'has principal');
            t.ok(obj.conditions, 'has conditions');
            t.ok(obj.ctime, 'has creation time');

            t.equal(obj.principal.account.uuid,
                TEST_CALLER.account.uuid,
                'account uuid matches');
            t.equal(obj.principal.account.login,
                TEST_CALLER.account.login,
                'account login matches');
            t.equal(obj.conditions.owner, 'testowner',
                'condition owner matches');
            t.equal(obj.conditions.method, 'GET',
                'condition method matches');

            t.end();
        });
    });
});


test('create token with user', function (t) {
    var callerWithUser = {
        account: TEST_CALLER.account,
        user: {
            uuid: 'user-uuid-1234'
        }
    };

    var opts = {
        caller: callerWithUser,
        context: {},
        fromjob: false
    };

    tokenManager.create(opts, AES_CONFIG,
        function (err, token) {
        t.ifError(err, 'no error creating token');

        tokenManager.parse(token, AES_CONFIG,
            function (err2, obj) {
            t.ifError(err2, 'no error parsing');
            t.ok(obj.principal.user,
                'has user in principal');
            t.equal(obj.principal.user.uuid,
                'user-uuid-1234',
                'user uuid matches');
            t.end();
        });
    });
});


test('parse invalid token returns error', function (t) {
    var invalidToken = 'not-a-valid-token';

    tokenManager.parse(invalidToken, AES_CONFIG,
        function (err, obj) {
        t.ok(err, 'error parsing invalid token');
        t.equal(err.name, 'InvalidAuthTokenError',
            'correct error type');
        t.notOk(obj, 'no object returned');
        t.end();
    });
});


test('parse expired token returns error', function (t) {
    var opts = {
        caller: TEST_CALLER,
        context: {},
        fromjob: false
    };

    // Create config with very short maxAge
    var shortAgeConfig = {
        salt: AES_CONFIG.salt,
        key: AES_CONFIG.key,
        iv: AES_CONFIG.iv,
        maxAge: 1  // 1ms
    };

    tokenManager.create(opts, shortAgeConfig,
        function (err, token) {
        t.ifError(err, 'no error creating token');

        // Wait 10ms then try to parse
        setTimeout(function () {
            tokenManager.parse(token, shortAgeConfig,
                function (err2, obj) {
                t.ok(err2, 'error parsing expired');
                t.equal(err2.name,
                    'InvalidAuthTokenError',
                    'correct error type');
                t.notOk(obj, 'no object returned');
                t.end();
            });
        }, 10);
    });
});


test('token creation validates input', function (t) {
    t.throws(function () {
        tokenManager.create(null, AES_CONFIG,
            function () {});
    }, 'throws on null opts');

    t.throws(function () {
        tokenManager.create({}, AES_CONFIG,
            function () {});
    }, 'throws on missing caller');

    t.throws(function () {
        tokenManager.create({caller: TEST_CALLER},
            null, function () {});
    }, 'throws on null aes config');

    t.end();
});


test('token parsing validates input', function (t) {
    t.throws(function () {
        tokenManager.parse(null, AES_CONFIG,
            function () {});
    }, 'throws on null token');

    t.throws(function () {
        tokenManager.parse('token', null,
            function () {});
    }, 'throws on null aes config');

    t.throws(function () {
        tokenManager.parse('token', {},
            function () {});
    }, 'throws on incomplete aes config');

    t.end();
});


test('token with fromjob condition', function (t) {
    var opts = {
        caller: TEST_CALLER,
        context: {},
        fromjob: true
    };

    tokenManager.create(opts, AES_CONFIG,
        function (err, token) {
        t.ifError(err, 'no error creating token');

        tokenManager.parse(token, AES_CONFIG,
            function (err2, obj) {
            t.ifError(err2, 'no error parsing');
            t.equal(obj.conditions.fromjob, true,
                'fromjob condition preserved');
            t.end();
        });
    });
});


test('token under 8KB limit', function (t) {
    // Create token with lots of conditions
    var largeContext = {
        owner: 'owner-name-here',
        method: 'GET',
        path: '/very/long/path/name/here',
        activeRoles: ['role1', 'role2', 'role3'],
        activeXAcctRoles: ['xrole1', 'xrole2']
    };

    var opts = {
        caller: TEST_CALLER,
        context: largeContext,
        fromjob: false
    };

    tokenManager.create(opts, AES_CONFIG,
        function (err, token) {
        t.ifError(err, 'no error creating token');
        t.ok(Buffer.byteLength(token) < 8192,
            'token under 8KB HAProxy limit');
        t.end();
    });
});
