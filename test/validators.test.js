/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var validators = require('../lib/validators');

///--- Tests

exports['LOGIN_RE pattern is exported'] = function (t) {
    t.ok(validators.LOGIN_RE, 'LOGIN_RE should be exported');
    t.equal(typeof (validators.LOGIN_RE), 'object',
        'LOGIN_RE should be RegExp');
    t.done();
};

exports['UUID_RE pattern is exported'] = function (t) {
    t.ok(validators.UUID_RE, 'UUID_RE should be exported');
    t.equal(typeof (validators.UUID_RE), 'object', 'UUID_RE should be RegExp');
    t.done();
};

///--- isValidLogin() Tests

exports['isValidLogin accepts standard login names'] = function (t) {
    t.ok(validators.isValidLogin('testuser'), 'simple login');
    t.ok(validators.isValidLogin('user123'), 'login with digits');
    t.ok(validators.isValidLogin('user_name'), 'login with underscore');
    t.ok(validators.isValidLogin('user.name'), 'login with period');
    t.ok(validators.isValidLogin('user@example'), 'login with at-sign');
    t.ok(validators.isValidLogin('abc'), 'minimum length login (3 chars)');
    t.ok(validators.isValidLogin('a12345678901234567890123456789bc'),
        'maximum length login (32 chars)');
    t.done();
};

exports['isValidLogin rejects invalid formats'] = function (t) {
    t.equal(validators.isValidLogin('ab'), false, 'too short (2 chars)');
    t.equal(validators.isValidLogin('a123456789012345678901234567890123'),
        false, 'too long (33 chars)');
    t.equal(validators.isValidLogin('123user'), false, 'starts with digit');
    t.equal(validators.isValidLogin('_user'), false, 'starts with underscore');
    t.equal(validators.isValidLogin('.user'), false, 'starts with period');
    t.equal(validators.isValidLogin('@user'), false, 'starts with at-sign');
    t.done();
};

exports['isValidLogin rejects special characters'] = function (t) {
    t.equal(validators.isValidLogin('user-name'), false, 'hyphen not allowed');
    t.equal(validators.isValidLogin('user%test'), false, 'percent not allowed');
    t.equal(validators.isValidLogin('user/test'), false, 'slash not allowed');
    t.equal(validators.isValidLogin('user\\test'), false,
        'backslash not allowed');
    t.equal(validators.isValidLogin('user name'), false, 'space not allowed');
    t.equal(validators.isValidLogin('user$test'), false, 'dollar not allowed');
    t.done();
};

exports['isValidLogin rejects path traversal attempts'] = function (t) {
    t.equal(validators.isValidLogin('../admin'), false,
        'path traversal with dots');
    t.equal(validators.isValidLogin('..\\admin'), false,
        'path traversal backslash');
    t.equal(validators.isValidLogin('/etc/passwd'), false, 'absolute path');
    t.done();
};

exports['isValidLogin rejects invalid types'] = function (t) {
    t.equal(validators.isValidLogin(null), false, 'null');
    t.equal(validators.isValidLogin(undefined), false, 'undefined');
    t.equal(validators.isValidLogin(''), false, 'empty string');
    t.equal(validators.isValidLogin(123), false, 'number');
    t.equal(validators.isValidLogin({}), false, 'object');
    t.equal(validators.isValidLogin([]), false, 'array');
    t.done();
};

///--- isValidUuid() Tests

exports['isValidUuid accepts valid UUIDs'] = function (t) {
    t.ok(validators.isValidUuid('550e8400-e29b-41d4-a716-446655440000'),
        'standard UUID');
    t.ok(validators.isValidUuid('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'),
        'another valid UUID');
    t.ok(validators.isValidUuid('00000000-0000-0000-0000-000000000000'),
        'nil UUID');
    t.ok(validators.isValidUuid('ffffffff-ffff-ffff-ffff-ffffffffffff'),
        'max UUID');
    t.done();
};

exports['isValidUuid rejects invalid UUID formats'] = function (t) {
    t.equal(validators.isValidUuid('not-a-uuid'), false, 'non-UUID string');
    t.equal(validators.isValidUuid('550e8400-e29b-41d4-a716'), false,
        'incomplete UUID');
    t.equal(validators.isValidUuid(
        '550e8400-e29b-41d4-a716-446655440000-extra'),
        false, 'UUID with extra chars');
    t.equal(validators.isValidUuid('550e8400e29b41d4a716446655440000'), false,
        'UUID without hyphens');
    t.done();
};

exports['isValidUuid rejects uppercase UUIDs'] = function (t) {
    t.equal(validators.isValidUuid('550E8400-E29B-41D4-A716-446655440000'),
        false, 'all uppercase');
    t.equal(validators.isValidUuid('550e8400-E29B-41d4-a716-446655440000'),
        false, 'mixed case');
    t.done();
};

exports['isValidUuid rejects invalid types'] = function (t) {
    t.equal(validators.isValidUuid(null), false, 'null');
    t.equal(validators.isValidUuid(undefined), false, 'undefined');
    t.equal(validators.isValidUuid(''), false, 'empty string');
    t.equal(validators.isValidUuid(123), false, 'number');
    t.equal(validators.isValidUuid({}), false, 'object');
    t.equal(validators.isValidUuid([]), false, 'array');
    t.done();
};

///--- isValidAccountIdentifier() Tests

exports['isValidAccountIdentifier accepts valid logins'] = function (t) {
    t.ok(validators.isValidAccountIdentifier('testuser'), 'simple login');
    t.ok(validators.isValidAccountIdentifier('user.name'),
        'login with period');
    t.ok(validators.isValidAccountIdentifier('user_123'),
        'login with underscore and digits');
    t.ok(validators.isValidAccountIdentifier('user@example'),
        'login with at-sign');
    t.done();
};

exports['isValidAccountIdentifier accepts valid UUIDs'] = function (t) {
    t.ok(validators.isValidAccountIdentifier(
        '550e8400-e29b-41d4-a716-446655440000'), 'standard UUID');
    t.ok(validators.isValidAccountIdentifier(
        'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'), 'another UUID');
    t.done();
};

exports['isValidAccountIdentifier rejects invalid formats'] = function (t) {
    t.equal(validators.isValidAccountIdentifier('ab'), false,
        'too short for login');
    t.equal(validators.isValidAccountIdentifier('123user'), false,
        'login starts with digit');
    t.equal(validators.isValidAccountIdentifier('../admin'), false,
        'path traversal');
    t.equal(validators.isValidAccountIdentifier('user-name'), false,
        'hyphen not allowed in login');
    t.equal(validators.isValidAccountIdentifier('not-a-uuid'), false,
        'neither valid login nor UUID');
    t.equal(validators.isValidAccountIdentifier(
        '550E8400-E29B-41D4-A716-446655440000'), false, 'uppercase UUID');
    t.done();
};

exports['isValidAccountIdentifier rejects invalid types'] = function (t) {
    t.equal(validators.isValidAccountIdentifier(null), false, 'null');
    t.equal(validators.isValidAccountIdentifier(undefined), false, 'undefined');
    t.equal(validators.isValidAccountIdentifier(''), false, 'empty string');
    t.equal(validators.isValidAccountIdentifier(123), false, 'number');
    t.done();
};

///--- Security Tests

exports['validators reject common attack vectors'] = function (t) {
    var attacks = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32',
        '/etc/passwd',
        'admin\x00',
        'admin%00',
        '<script>alert(1)</script>',
        'admin\'; DROP TABLE users;--',
        '%2e%2e%2fadmin',
        'admin/../root'
    ];

    attacks.forEach(function (attack) {
        t.equal(validators.isValidLogin(attack), false,
            'LOGIN: reject ' + attack);
        t.equal(validators.isValidAccountIdentifier(attack), false,
            'IDENTIFIER: reject ' + attack);
    });

    t.done();
};
