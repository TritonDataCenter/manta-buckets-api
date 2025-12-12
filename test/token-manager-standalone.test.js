/*
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * token-manager-standalone.test.js: Standalone unit
 * tests for token-manager module without dependencies
 */

var tokenManager =
    require('../lib/auth/token-manager');


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

exports['create token with account only'] =
function (t) {
    var opts = {
        caller: TEST_CALLER,
        context: {},
        fromjob: false
    };

    tokenManager.create(opts, AES_CONFIG,
        function (err, token) {
        t.ifError(err);
        t.ok(token);
        t.equal(typeof (token), 'string');
        t.ok(token.length > 0);
        t.done();
    });
};


exports['create and parse token roundtrip'] =
function (t) {
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
        t.ifError(err);

        tokenManager.parse(token, AES_CONFIG,
            function (err2, obj) {
            t.ifError(err2);
            t.ok(obj);
            t.ok(obj.principal);
            t.ok(obj.conditions);
            t.ok(obj.ctime);

            t.equal(obj.principal.account.uuid,
                TEST_CALLER.account.uuid);
            t.equal(obj.principal.account.login,
                TEST_CALLER.account.login);
            t.equal(obj.conditions.owner,
                'testowner');
            t.equal(obj.conditions.method, 'GET');

            t.done();
        });
    });
};


exports['create token with user'] = function (t) {
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
        t.ifError(err);

        tokenManager.parse(token, AES_CONFIG,
            function (err2, obj) {
            t.ifError(err2);
            t.ok(obj.principal.user);
            t.equal(obj.principal.user.uuid,
                'user-uuid-1234');
            t.done();
        });
    });
};


exports['parse invalid token returns error'] =
function (t) {
    var invalidToken = 'not-a-valid-token';

    tokenManager.parse(invalidToken, AES_CONFIG,
        function (err, obj) {
        t.ok(err);
        t.equal(err.restCode,
            'InvalidAuthenticationToken');
        t.ok(!obj);
        t.done();
    });
};


exports['parse expired token returns error'] =
function (t) {
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
        t.ifError(err);

        // Wait 10ms then try to parse
        setTimeout(function () {
            tokenManager.parse(token, shortAgeConfig,
                function (err2, obj) {
                t.ok(err2);
                t.equal(err2.restCode,
                    'InvalidAuthenticationToken');
                t.ok(!obj);
                t.done();
            });
        }, 10);
    });
};


exports['token with fromjob condition'] =
function (t) {
    var opts = {
        caller: TEST_CALLER,
        context: {},
        fromjob: true
    };

    tokenManager.create(opts, AES_CONFIG,
        function (err, token) {
        t.ifError(err);

        tokenManager.parse(token, AES_CONFIG,
            function (err2, obj) {
            t.ifError(err2);
            t.equal(obj.conditions.fromjob, true);
            t.done();
        });
    });
};


exports['token under 8KB limit'] = function (t) {
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
        t.ifError(err);
        t.ok(Buffer.byteLength(token) < 8192);
        t.done();
    });
};
