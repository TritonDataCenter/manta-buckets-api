/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
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
    // sdc-ufds LOGIN_RE requires names to start with letter (not digit)
    t.equal(anonymousAuth.isValidAccountName('123user'), false,
         '123user should be rejected (starts with digit)');
    t.ok(anonymousAuth.isValidAccountName('TestUser'),
         'TestUser should be valid (mixed case)');
    t.done();
};

exports['rejects names with hyphens'] = function (t) {
    // sdc-ufds LOGIN_RE does NOT allow hyphens
    t.equal(anonymousAuth.isValidAccountName('test-user'), false,
         'test-user should be rejected (hyphen not allowed)');
    t.equal(anonymousAuth.isValidAccountName('my-test-account'), false,
         'my-test-account should be rejected (hyphen not allowed)');
    t.equal(anonymousAuth.isValidAccountName('user-123'), false,
         'user-123 should be rejected (hyphen not allowed)');
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
    // sdc-ufds LOGIN_RE allows: letters, digits, underscore, period, at-sign
    // (hyphens NOT allowed)
    t.ok(anonymousAuth.isValidAccountName('test_user123.prod'),
         'test_user123.prod should be valid');
    t.ok(anonymousAuth.isValidAccountName('myaccount_v2.test'),
         'myaccount_v2.test should be valid');
    t.ok(anonymousAuth.isValidAccountName('user.123test_v1'),
         'user.123test_v1 should be valid');
    t.ok(anonymousAuth.isValidAccountName('user@example.com'),
         'user@example.com should be valid (at-sign allowed)');
    t.done();
};

exports['rejects single and two character names'] = function (t) {
    // sdc-ufds LOGIN_RE requires minimum 3 characters
    t.equal(anonymousAuth.isValidAccountName('a'), false,
         'a should be rejected (too short)');
    t.equal(anonymousAuth.isValidAccountName('z'), false,
         'z should be rejected (too short)');
    t.equal(anonymousAuth.isValidAccountName('ab'), false,
         'ab should be rejected (too short)');
    t.equal(anonymousAuth.isValidAccountName('99'), false,
         '99 should be rejected (too short)');
    // 3 characters is minimum
    t.ok(anonymousAuth.isValidAccountName('abc'),
         'abc should be valid (3 chars minimum)');
    t.done();
};

exports['validates UUID format names'] = function (t) {
    // sdc-ufds UUID_RE requires lowercase hex digits only
    t.ok(anonymousAuth.isValidAccountName(
        '550e8400-e29b-41d4-a716-446655440000'),
        'UUID v4 should be valid');
    t.ok(anonymousAuth.isValidAccountName(
        '6ba7b810-9dad-11d1-80b4-00c04fd430c8'),
        'UUID v1 should be valid');
    t.ok(anonymousAuth.isValidAccountName(
        'a1b2c3d4-5678-90ab-cdef-1234567890ab'),
        'UUID with lowercase hex should be valid');
    // Uppercase UUIDs are NOT allowed by sdc-ufds UUID_RE
    t.equal(anonymousAuth.isValidAccountName(
        'A1B2C3D4-5678-90AB-CDEF-1234567890AB'), false,
        'UUID with uppercase hex should be rejected');
    t.done();
};

exports['validates 32 character maximum (sdc-ufds limit)'] = function (t) {
    // sdc-ufds LOGIN_RE has 32 character maximum (not 64)
    var name32 = 'a1234567890123456789012345678901';
    t.equal(name32.length, 32, 'test string should be exactly 32 chars');
    t.ok(anonymousAuth.isValidAccountName(name32),
         '32 character name should be valid (maximum)');

    var name33 = 'a12345678901234567890123456789012';
    t.equal(name33.length, 33, 'test string should be exactly 33 chars');
    t.equal(anonymousAuth.isValidAccountName(name33), false,
         '33 character name should be rejected (exceeds maximum)');
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
    // sdc-ufds LOGIN_RE maximum is 32 characters
    var name33 = 'a12345678901234567890123456789012';
    t.equal(name33.length, 33, 'test string should be exactly 33 chars');
    t.equal(anonymousAuth.isValidAccountName(name33), false,
            '33 character name should be rejected (exceeds 32 max)');
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

exports['rejects names with invalid start characters'] = function (t) {
    // sdc-ufds LOGIN_RE requires names to START with letter only
    t.equal(anonymousAuth.isValidAccountName('-user'), false,
            '-user should be rejected (starts with hyphen)');
    t.equal(anonymousAuth.isValidAccountName('.user'), false,
            '.user should be rejected (starts with period)');
    t.equal(anonymousAuth.isValidAccountName('_user'), false,
            '_user should be rejected (starts with underscore)');
    t.equal(anonymousAuth.isValidAccountName('@user'), false,
            '@user should be rejected (starts with at-sign)');

    // Names CAN end with underscore, period, or at-sign
    // (they're in allowed character set)
    t.ok(anonymousAuth.isValidAccountName('user_'),
            'user_ should be valid (ends with underscore)');
    t.ok(anonymousAuth.isValidAccountName('user.'),
            'user. should be valid (ends with period)');
    t.ok(anonymousAuth.isValidAccountName('user@'),
            'user@ should be valid (ends with at-sign)');

    // But NOT with hyphen (not in allowed character set)
    t.equal(anonymousAuth.isValidAccountName('user-'), false,
            'user- should be rejected (hyphen not allowed)');
    t.done();
};

exports['validates at-sign in names'] = function (t) {
    // sdc-ufds LOGIN_RE allows @ for email-style logins
    t.ok(anonymousAuth.isValidAccountName('user@host'),
            'user@host should be valid (at-sign allowed)');
    t.ok(anonymousAuth.isValidAccountName('user@example.com'),
            'user@example.com should be valid');
    t.done();
};

exports['rejects names with disallowed special characters'] = function (t) {
    // Only letters, digits, underscore, period, at-sign are allowed
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
