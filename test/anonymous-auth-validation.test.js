/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 * File:     anonymous-auth-validation.test.js
 * Purpose:  Unit tests for account name validation in anonymous access
 */

// var test = require('nodeunit'); // Unused import
var anonymousAuth = require('../lib/anonymous-auth');

// Test exports availability
exports['module exports isValidAccountName'] = function (t) {
    t.ok(typeof (anonymousAuth.isValidAccountName) === 'function',
         'isValidAccountName should be exported');
    t.done();
};

// ============================================================================
// VALID ACCOUNT NAMES (Format Validation)
// ============================================================================

exports['validates basic alphanumeric names'] = function (t) {
    t.ok(anonymousAuth.isValidAccountName('testuser'),
         'testuser should be valid');
    t.ok(anonymousAuth.isValidAccountName('user123'),
         'user123 should be valid');
    t.ok(anonymousAuth.isValidAccountName('123user'),
         '123user should be valid');
    t.ok(anonymousAuth.isValidAccountName('TestUser'),
         'TestUser should be valid (mixed case)');
    t.done();
};

exports['validates names with hyphens'] = function (t) {
    t.ok(anonymousAuth.isValidAccountName('test-user'),
         'test-user should be valid');
    t.ok(anonymousAuth.isValidAccountName('my-test-account'),
         'my-test-account should be valid');
    t.ok(anonymousAuth.isValidAccountName('user-123'),
         'user-123 should be valid');
    t.done();
};

exports['validates names with underscores'] = function (t) {
    t.ok(anonymousAuth.isValidAccountName('test_user'),
         'test_user should be valid');
    t.ok(anonymousAuth.isValidAccountName('my_test_account'),
         'my_test_account should be valid');
    t.ok(anonymousAuth.isValidAccountName('user_123'),
         'user_123 should be valid');
    t.done();
};

exports['validates names with periods'] = function (t) {
    t.ok(anonymousAuth.isValidAccountName('test.user'),
         'test.user should be valid');
    t.ok(anonymousAuth.isValidAccountName('my.test.account'),
         'my.test.account should be valid');
    t.ok(anonymousAuth.isValidAccountName('user.123'),
         'user.123 should be valid');
    t.done();
};

exports['validates mixed format names'] = function (t) {
    t.ok(anonymousAuth.isValidAccountName('test-user_123.prod'),
         'test-user_123.prod should be valid');
    t.ok(anonymousAuth.isValidAccountName('my-account_v2.test'),
         'my-account_v2.test should be valid');
    t.ok(anonymousAuth.isValidAccountName('user.123-test_v1'),
         'user.123-test_v1 should be valid');
    t.done();
};

exports['validates single character names'] = function (t) {
    t.ok(anonymousAuth.isValidAccountName('a'),
         'a should be valid');
    t.ok(anonymousAuth.isValidAccountName('z'),
         'z should be valid');
    t.ok(anonymousAuth.isValidAccountName('9'),
         '9 should be valid');
    t.ok(anonymousAuth.isValidAccountName('A'),
         'A should be valid');
    t.done();
};

exports['validates UUID format names'] = function (t) {
    t.ok(anonymousAuth.isValidAccountName(
        '550e8400-e29b-41d4-a716-446655440000'),
        'UUID v4 should be valid');
    t.ok(anonymousAuth.isValidAccountName(
        '6ba7b810-9dad-11d1-80b4-00c04fd430c8'),
        'UUID v1 should be valid');
    t.ok(anonymousAuth.isValidAccountName(
        'a1b2c3d4-5678-90ab-cdef-1234567890ab'),
        'UUID with lowercase hex should be valid');
    t.ok(anonymousAuth.isValidAccountName(
        'A1B2C3D4-5678-90AB-CDEF-1234567890AB'),
        'UUID with uppercase hex should be valid');
    t.done();
};

exports['validates 64 character limit'] = function (t) {
    var name64 =
        'a123456789012345678901234567890123456789012345678901234567890123';
    t.equal(name64.length, 64, 'test string should be exactly 64 chars');
    t.ok(anonymousAuth.isValidAccountName(name64),
         '64 character name should be valid');
    t.done();
};

// ============================================================================
// INVALID ACCOUNT NAMES (Format Validation)
// ============================================================================

exports['rejects path traversal patterns'] = function (t) {
    t.equal(anonymousAuth.isValidAccountName('../etc/passwd'), false,
            '../etc/passwd should be rejected');
    t.equal(anonymousAuth.isValidAccountName('user/../admin'), false,
            'user/../admin should be rejected');
    t.equal(anonymousAuth.isValidAccountName('..'), false,
            '.. should be rejected');
    t.equal(anonymousAuth.isValidAccountName('../'), false,
            '../ should be rejected');
    t.equal(anonymousAuth.isValidAccountName('user/../../root'), false,
            'user/../../root should be rejected');
    t.done();
};

exports['rejects names with slashes'] = function (t) {
    t.equal(anonymousAuth.isValidAccountName('user/admin'), false,
            'user/admin should be rejected');
    t.equal(anonymousAuth.isValidAccountName('user\\admin'), false,
            'user\\admin should be rejected (backslash)');
    t.equal(anonymousAuth.isValidAccountName('/user'), false,
            '/user should be rejected');
    t.equal(anonymousAuth.isValidAccountName('user/'), false,
            'user/ should be rejected');
    t.done();
};

exports['rejects names that are too long'] = function (t) {
    var name65 =
        'a1234567890123456789012345678901234567890123456789012345678901234';
    t.equal(name65.length, 65, 'test string should be exactly 65 chars');
    t.equal(anonymousAuth.isValidAccountName(name65), false,
            '65 character name should be rejected');
    var name100 = new Array(101).join('a');
    t.equal(anonymousAuth.isValidAccountName(name100), false,
            '100 character name should be rejected');
    t.done();
};

exports['rejects empty or null values'] = function (t) {
    t.equal(anonymousAuth.isValidAccountName(''), false,
            'empty string should be rejected');
    t.equal(anonymousAuth.isValidAccountName(null), false,
            'null should be rejected');
    t.equal(anonymousAuth.isValidAccountName(undefined), false,
            'undefined should be rejected');
    t.done();
};

exports['rejects names with invalid start or end characters'] = function (t) {
    t.equal(anonymousAuth.isValidAccountName('-user'), false,
            '-user should be rejected (starts with hyphen)');
    t.equal(anonymousAuth.isValidAccountName('user-'), false,
            'user- should be rejected (ends with hyphen)');
    t.equal(anonymousAuth.isValidAccountName('.user'), false,
            '.user should be rejected (starts with period)');
    t.equal(anonymousAuth.isValidAccountName('user.'), false,
            'user. should be rejected (ends with period)');
    t.equal(anonymousAuth.isValidAccountName('_user'), false,
            '_user should be rejected (starts with underscore)');
    t.equal(anonymousAuth.isValidAccountName('user_'), false,
            'user_ should be rejected (ends with underscore)');
    t.done();
};

exports['rejects names with special characters'] = function (t) {
    t.equal(anonymousAuth.isValidAccountName('user@host'), false,
            'user@host should be rejected');
    t.equal(anonymousAuth.isValidAccountName('user#123'), false,
            'user#123 should be rejected');
    t.equal(anonymousAuth.isValidAccountName('user$123'), false,
            'user$123 should be rejected');
    t.equal(anonymousAuth.isValidAccountName('user%123'), false,
            'user%123 should be rejected');
    t.equal(anonymousAuth.isValidAccountName('user&admin'), false,
            'user&admin should be rejected');
    t.equal(anonymousAuth.isValidAccountName('user*admin'), false,
            'user*admin should be rejected');
    t.equal(anonymousAuth.isValidAccountName('user!admin'), false,
            'user!admin should be rejected');
    t.done();
};

exports['rejects injection attempt patterns'] = function (t) {
    t.equal(anonymousAuth.isValidAccountName('\'; DROP TABLE--'), false,
            'SQL injection attempt should be rejected');
    t.equal(anonymousAuth.isValidAccountName('<script>alert(1)</script>'),
            false, 'XSS attempt should be rejected');
    t.equal(anonymousAuth.isValidAccountName('$(rm -rf /)'), false,
            'Command injection attempt should be rejected');
    t.equal(anonymousAuth.isValidAccountName('user`whoami`'), false,
            'Command substitution should be rejected');
    t.done();
};

exports['rejects non-string types'] = function (t) {
    t.equal(anonymousAuth.isValidAccountName(123), false,
            'number should be rejected');
    t.equal(anonymousAuth.isValidAccountName(['user']), false,
            'array should be rejected');
    t.equal(anonymousAuth.isValidAccountName({name: 'user'}), false,
            'object should be rejected');
    t.equal(anonymousAuth.isValidAccountName(true), false,
            'boolean should be rejected');
    t.done();
};
