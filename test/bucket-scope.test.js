/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 * File:     bucket-scope.test.js
 * Purpose:  Unit tests for per-bucket access key scope
 *           enforcement middleware
 */

var bucketScope = require('../lib/auth/bucket-scope');
require('../lib/errors');

// ============================================================================
// matchBucketPattern tests
// ============================================================================

exports['matchBucketPattern: exact match'] = function (t) {
    t.ok(bucketScope.matchBucketPattern('my-bucket', 'my-bucket'),
        'exact match should succeed');
    t.equal(bucketScope.matchBucketPattern('my-bucket', 'other'),
        false, 'different name should fail');
    t.done();
};

exports['matchBucketPattern: wildcard star matches all'] = function (t) {
    t.ok(bucketScope.matchBucketPattern('*', 'anything'),
        '* should match any bucket');
    t.ok(bucketScope.matchBucketPattern('*', ''),
        '* should match empty string');
    t.done();
};

exports['matchBucketPattern: trailing wildcard'] = function (t) {
    t.ok(bucketScope.matchBucketPattern('logs-*', 'logs-2026'),
        'logs-* should match logs-2026');
    t.ok(bucketScope.matchBucketPattern('logs-*', 'logs-'),
        'logs-* should match logs-');
    t.equal(bucketScope.matchBucketPattern('logs-*', 'other'),
        false, 'logs-* should not match other');
    t.equal(bucketScope.matchBucketPattern('logs-*', 'log'),
        false, 'logs-* should not match partial prefix');
    t.done();
};

// ============================================================================
// parseScope tests
// ============================================================================

exports['parseScope: valid scope'] = function (t) {
    var raw = JSON.stringify({
        version: 1,
        permissions: [
            { bucket: 'my-bucket', level: 'read' }
        ]
    });
    var scope = bucketScope.parseScope(raw);
    t.ok(scope !== null, 'valid scope should parse');
    t.equal(scope.version, 1);
    t.equal(scope.permissions.length, 1);
    t.equal(scope.permissions[0].bucket, 'my-bucket');
    t.equal(scope.permissions[0].level, 'read');
    t.done();
};

exports['parseScope: invalid JSON returns null'] = function (t) {
    t.equal(bucketScope.parseScope('{bad json'),
        null, 'invalid JSON should return null');
    t.done();
};

exports['parseScope: wrong version returns null'] = function (t) {
    var raw = JSON.stringify({
        version: 2,
        permissions: []
    });
    t.equal(bucketScope.parseScope(raw),
        null, 'version 2 should return null');
    t.done();
};

exports['parseScope: missing permissions returns null'] = function (t) {
    var raw = JSON.stringify({ version: 1 });
    t.equal(bucketScope.parseScope(raw),
        null, 'missing permissions should return null');
    t.done();
};

// ============================================================================
// scopeGrantsAccess tests
// ============================================================================

exports['scopeGrantsAccess: read level allows read'] = function (t) {
    var perms = [ { bucket: 'b1', level: 'read' } ];
    t.ok(bucketScope.scopeGrantsAccess(
        perms, 'b1', bucketScope.LEVEL_READ),
        'read level should allow read');
    t.done();
};

exports['scopeGrantsAccess: read level denies write'] = function (t) {
    var perms = [ { bucket: 'b1', level: 'read' } ];
    t.equal(bucketScope.scopeGrantsAccess(
        perms, 'b1', bucketScope.LEVEL_READWRITE),
        false, 'read level should deny readwrite');
    t.done();
};

exports['scopeGrantsAccess: readwrite allows read'] = function (t) {
    var perms = [ { bucket: 'b1', level: 'readwrite' } ];
    t.ok(bucketScope.scopeGrantsAccess(
        perms, 'b1', bucketScope.LEVEL_READ),
        'readwrite should allow read');
    t.done();
};

exports['scopeGrantsAccess: readwrite allows readwrite'] = function (t) {
    var perms = [ { bucket: 'b1', level: 'readwrite' } ];
    t.ok(bucketScope.scopeGrantsAccess(
        perms, 'b1', bucketScope.LEVEL_READWRITE),
        'readwrite should allow readwrite');
    t.done();
};

exports['scopeGrantsAccess: readwrite denies full'] = function (t) {
    var perms = [ { bucket: 'b1', level: 'readwrite' } ];
    t.equal(bucketScope.scopeGrantsAccess(
        perms, 'b1', bucketScope.LEVEL_FULL),
        false, 'readwrite should deny full');
    t.done();
};

exports['scopeGrantsAccess: full allows everything'] = function (t) {
    var perms = [ { bucket: 'b1', level: 'full' } ];
    t.ok(bucketScope.scopeGrantsAccess(
        perms, 'b1', bucketScope.LEVEL_READ),
        'full should allow read');
    t.ok(bucketScope.scopeGrantsAccess(
        perms, 'b1', bucketScope.LEVEL_READWRITE),
        'full should allow readwrite');
    t.ok(bucketScope.scopeGrantsAccess(
        perms, 'b1', bucketScope.LEVEL_FULL),
        'full should allow full');
    t.done();
};

exports['scopeGrantsAccess: wrong bucket denied'] = function (t) {
    var perms = [ { bucket: 'b1', level: 'full' } ];
    t.equal(bucketScope.scopeGrantsAccess(
        perms, 'b2', bucketScope.LEVEL_READ),
        false, 'different bucket should be denied');
    t.done();
};

exports['scopeGrantsAccess: wildcard pattern'] = function (t) {
    var perms = [ { bucket: 'logs-*', level: 'readwrite' } ];
    t.ok(bucketScope.scopeGrantsAccess(
        perms, 'logs-jan', bucketScope.LEVEL_READ),
        'wildcard should match and allow read');
    t.ok(bucketScope.scopeGrantsAccess(
        perms, 'logs-feb', bucketScope.LEVEL_READWRITE),
        'wildcard should match and allow readwrite');
    t.equal(bucketScope.scopeGrantsAccess(
        perms, 'data-jan', bucketScope.LEVEL_READ),
        false, 'wildcard should not match non-prefixed');
    t.done();
};

exports['scopeGrantsAccess: multiple permissions'] = function (t) {
    var perms = [
        { bucket: 'readonly-bucket', level: 'read' },
        { bucket: 'rw-bucket', level: 'readwrite' },
        { bucket: 'admin-*', level: 'full' }
    ];
    t.ok(bucketScope.scopeGrantsAccess(
        perms, 'readonly-bucket', bucketScope.LEVEL_READ));
    t.equal(bucketScope.scopeGrantsAccess(
        perms, 'readonly-bucket', bucketScope.LEVEL_READWRITE),
        false);
    t.ok(bucketScope.scopeGrantsAccess(
        perms, 'rw-bucket', bucketScope.LEVEL_READWRITE));
    t.ok(bucketScope.scopeGrantsAccess(
        perms, 'admin-config', bucketScope.LEVEL_FULL));
    t.done();
};

// ============================================================================
// requiredLevel tests
// ============================================================================

exports['requiredLevel: GET on bucket = read'] = function (t) {
    t.equal(bucketScope.requiredLevel('GET', true),
        bucketScope.LEVEL_READ);
    t.done();
};

exports['requiredLevel: HEAD on bucket = read'] = function (t) {
    t.equal(bucketScope.requiredLevel('HEAD', true),
        bucketScope.LEVEL_READ);
    t.done();
};

exports['requiredLevel: PUT on bucket = full'] = function (t) {
    t.equal(bucketScope.requiredLevel('PUT', true),
        bucketScope.LEVEL_FULL);
    t.done();
};

exports['requiredLevel: DELETE on bucket = full'] = function (t) {
    t.equal(bucketScope.requiredLevel('DELETE', true),
        bucketScope.LEVEL_FULL);
    t.done();
};

exports['requiredLevel: GET on object = read'] = function (t) {
    t.equal(bucketScope.requiredLevel('GET', false),
        bucketScope.LEVEL_READ);
    t.done();
};

exports['requiredLevel: PUT on object = readwrite'] = function (t) {
    t.equal(bucketScope.requiredLevel('PUT', false),
        bucketScope.LEVEL_READWRITE);
    t.done();
};

exports['requiredLevel: DELETE on object = readwrite'] = function (t) {
    t.equal(bucketScope.requiredLevel('DELETE', false),
        bucketScope.LEVEL_READWRITE);
    t.done();
};

// ============================================================================
// enforceBucketScope middleware tests
// ============================================================================

/**
 * @brief Create a minimal mock request object
 *
 * @param {Object} opts - Options
 * @param {string} opts.method - HTTP method
 * @param {string} opts.urlPath - Request path
 * @param {string|null} opts.bucketScope - Scope JSON
 * @param {string|null} opts.bucketParam - req.params[0]
 * @return {Object} Mock request
 */
function mockReq(opts) {
    var params = {};
    if (opts.bucketParam) {
        params[0] = opts.bucketParam;
    }
    return {
        method: opts.method || 'GET',
        caller: opts.bucketScope !== undefined ? {
            bucketScope: opts.bucketScope
        } : null,
        auth: { accessKeyId: 'AKIATEST' },
        params: params,
        path: function () { return opts.urlPath || '/'; },
        log: {
            debug: function () {},
            info: function () {},
            warn: function () {},
            error: function () {}
        }
    };
}


exports['enforceBucketScope: no scope = pass through'] =
function (t) {
    var req = mockReq({
        method: 'GET',
        urlPath: '/my-bucket/my-key',
        bucketScope: null,
        bucketParam: 'my-bucket'
    });
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(!err, 'no scope should pass through');
        t.done();
    });
};

exports['enforceBucketScope: no caller = pass through'] =
function (t) {
    var req = mockReq({
        method: 'GET',
        urlPath: '/my-bucket',
        bucketScope: undefined
    });
    req.caller = null;
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(!err, 'no caller should pass through');
        t.done();
    });
};

exports['enforceBucketScope: malformed JSON = deny'] =
function (t) {
    var req = mockReq({
        method: 'GET',
        urlPath: '/my-bucket',
        bucketScope: '{bad',
        bucketParam: 'my-bucket'
    });
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(err, 'malformed scope should deny');
        t.equal(err.restCode, 'AccessDeniedByKeyScope');
        t.equal(err.statusCode, 403);
        t.done();
    });
};

exports['enforceBucketScope: read scope allows GET'] =
function (t) {
    var scope = JSON.stringify({
        version: 1,
        permissions: [
            { bucket: 'my-bucket', level: 'read' }
        ]
    });
    var req = mockReq({
        method: 'GET',
        urlPath: '/my-bucket/my-key',
        bucketScope: scope,
        bucketParam: 'my-bucket'
    });
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(!err, 'read scope should allow GET object');
        t.done();
    });
};

exports['enforceBucketScope: read scope denies PUT'] =
function (t) {
    var scope = JSON.stringify({
        version: 1,
        permissions: [
            { bucket: 'my-bucket', level: 'read' }
        ]
    });
    var req = mockReq({
        method: 'PUT',
        urlPath: '/my-bucket/my-key',
        bucketScope: scope,
        bucketParam: 'my-bucket'
    });
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(err, 'read scope should deny PUT object');
        t.equal(err.restCode, 'AccessDeniedByKeyScope');
        t.done();
    });
};

exports['enforceBucketScope: readwrite scope allows PUT'] =
function (t) {
    var scope = JSON.stringify({
        version: 1,
        permissions: [
            { bucket: 'my-bucket', level: 'readwrite' }
        ]
    });
    var req = mockReq({
        method: 'PUT',
        urlPath: '/my-bucket/my-key',
        bucketScope: scope,
        bucketParam: 'my-bucket'
    });
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(!err, 'readwrite scope should allow PUT object');
        t.done();
    });
};

exports['enforceBucketScope: readwrite scope denies bucket DELETE'] =
function (t) {
    var scope = JSON.stringify({
        version: 1,
        permissions: [
            { bucket: 'my-bucket', level: 'readwrite' }
        ]
    });
    var req = mockReq({
        method: 'DELETE',
        urlPath: '/my-bucket',
        bucketScope: scope,
        bucketParam: 'my-bucket'
    });
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(err, 'readwrite should deny bucket DELETE');
        t.equal(err.restCode, 'AccessDeniedByKeyScope');
        t.done();
    });
};

exports['enforceBucketScope: full scope allows bucket DELETE'] =
function (t) {
    var scope = JSON.stringify({
        version: 1,
        permissions: [
            { bucket: 'my-bucket', level: 'full' }
        ]
    });
    var req = mockReq({
        method: 'DELETE',
        urlPath: '/my-bucket',
        bucketScope: scope,
        bucketParam: 'my-bucket'
    });
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(!err, 'full scope should allow bucket DELETE');
        t.done();
    });
};

exports['enforceBucketScope: unscoped bucket denied'] =
function (t) {
    var scope = JSON.stringify({
        version: 1,
        permissions: [
            { bucket: 'allowed-bucket', level: 'full' }
        ]
    });
    var req = mockReq({
        method: 'GET',
        urlPath: '/other-bucket/key',
        bucketScope: scope,
        bucketParam: 'other-bucket'
    });
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(err, 'unscoped bucket should be denied');
        t.equal(err.restCode, 'AccessDeniedByKeyScope');
        t.done();
    });
};

exports['enforceBucketScope: root path sets scopeContext'] =
function (t) {
    var scope = JSON.stringify({
        version: 1,
        permissions: [
            { bucket: 'b1', level: 'read' },
            { bucket: 'b2', level: 'readwrite' }
        ]
    });
    var req = mockReq({
        method: 'GET',
        urlPath: '/',
        bucketScope: scope
    });
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(!err, 'root path should pass through');
        t.ok(req.scopeContext,
            'should set scopeContext');
        t.ok(req.scopeContext.scope,
            'scopeContext.scope should be set');
        t.equal(req.scopeContext.scope.version, 1);
        t.ok(req.scopeContext.patterns,
            'scopeContext.patterns should be set');
        t.equal(req.scopeContext.patterns.length, 2);
        t.equal(req.scopeContext.patterns[0], 'b1');
        t.equal(req.scopeContext.patterns[1], 'b2');
        t.done();
    });
};

exports['enforceBucketScope: sets scopeContext on allow'] =
function (t) {
    var scope = JSON.stringify({
        version: 1,
        permissions: [
            { bucket: 'my-bucket', level: 'read' }
        ]
    });
    var req = mockReq({
        method: 'GET',
        urlPath: '/my-bucket/my-key',
        bucketScope: scope,
        bucketParam: 'my-bucket'
    });
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(!err, 'should allow');
        t.ok(req.scopeContext,
            'scopeContext should be set');
        t.ok(req.scopeContext.scope,
            'scope should be set');
        t.equal(
            req.scopeContext.patterns.length, 1);
        t.equal(
            req.scopeContext.patterns[0],
            'my-bucket');
        t.done();
    });
};

exports['enforceBucketScope: no scopeContext without scope'] =
function (t) {
    var req = mockReq({
        method: 'GET',
        urlPath: '/my-bucket/my-key',
        bucketScope: null,
        bucketParam: 'my-bucket'
    });
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(!err, 'should pass through');
        t.ok(!req.scopeContext,
            'scopeContext should not be set');
        t.done();
    });
};

exports['enforceBucketScope: wildcard scope pattern'] =
function (t) {
    var scope = JSON.stringify({
        version: 1,
        permissions: [
            { bucket: 'app-*', level: 'readwrite' }
        ]
    });
    var req = mockReq({
        method: 'PUT',
        urlPath: '/app-data/my-key',
        bucketScope: scope,
        bucketParam: 'app-data'
    });
    bucketScope.enforceBucketScope(req, {}, function (err) {
        t.ok(!err,
            'wildcard scope should allow matching bucket');
        t.done();
    });
};

// ============================================================================
// levelName tests
// ============================================================================

exports['levelName: maps read level'] = function (t) {
    t.equal(bucketScope.levelName(bucketScope.LEVEL_READ),
        'read', 'LEVEL_READ should map to "read"');
    t.done();
};

exports['levelName: maps readwrite level'] = function (t) {
    t.equal(bucketScope.levelName(bucketScope.LEVEL_READWRITE),
        'readwrite',
        'LEVEL_READWRITE should map to "readwrite"');
    t.done();
};

exports['levelName: maps full level'] = function (t) {
    t.equal(bucketScope.levelName(bucketScope.LEVEL_FULL),
        'full', 'LEVEL_FULL should map to "full"');
    t.done();
};

exports['levelName: unknown returns unknown'] = function (t) {
    t.equal(bucketScope.levelName(99), 'unknown',
        'unrecognized level should return "unknown"');
    t.equal(bucketScope.levelName(0), 'unknown',
        'zero should return "unknown"');
    t.done();
};

// ============================================================================
// highestGrantedLevel tests
// ============================================================================

exports['highestGrantedLevel: matching bucket'] = function (t) {
    var perms = [
        { bucket: 'b1', level: 'read' },
        { bucket: 'b1', level: 'readwrite' }
    ];
    t.equal(bucketScope.highestGrantedLevel(perms, 'b1'),
        bucketScope.LEVEL_READWRITE,
        'should return highest matching level');
    t.done();
};

exports['highestGrantedLevel: no match returns 0'] =
function (t) {
    var perms = [
        { bucket: 'b1', level: 'full' }
    ];
    t.equal(bucketScope.highestGrantedLevel(perms, 'b2'),
        0, 'non-matching bucket should return 0');
    t.done();
};

exports['highestGrantedLevel: wildcard pattern'] =
function (t) {
    var perms = [
        { bucket: 'logs-*', level: 'read' },
        { bucket: 'logs-*', level: 'full' }
    ];
    t.equal(
        bucketScope.highestGrantedLevel(perms, 'logs-jan'),
        bucketScope.LEVEL_FULL,
        'wildcard should match and return highest');
    t.done();
};

exports['highestGrantedLevel: empty perms returns 0'] =
function (t) {
    t.equal(bucketScope.highestGrantedLevel([], 'b1'),
        0, 'empty permissions should return 0');
    t.done();
};

// ============================================================
// matchBucketPattern: wildcard edge cases
// ============================================================

exports['matchBucketPattern: bare * matches everything'] =
    function (t) {
    t.ok(bucketScope.matchBucketPattern('*', 'a'));
    t.ok(bucketScope.matchBucketPattern(
        '*', 'my-bucket'));
    t.ok(bucketScope.matchBucketPattern(
        '*', 'very-long-bucket-name-123'));
    t.done();
};

exports['matchBucketPattern: trailing wildcard prefix'] =
    function (t) {
    t.ok(bucketScope.matchBucketPattern(
        'app-*', 'app-data'));
    t.ok(bucketScope.matchBucketPattern(
        'app-*', 'app-'));
    t.ok(bucketScope.matchBucketPattern(
        'app-*', 'app-data-2026'));
    t.equal(bucketScope.matchBucketPattern(
        'app-*', 'ap'), false);
    t.equal(bucketScope.matchBucketPattern(
        'app-*', 'application'), false);
    t.done();
};

exports['matchBucketPattern: no partial wildcard match'] =
    function (t) {
    /*
     * These patterns would be rejected by validation,
     * but matchBucketPattern itself should not match
     * them as trailing wildcards.
     */
    t.equal(bucketScope.matchBucketPattern(
        'exact', 'exact'), true);
    t.equal(bucketScope.matchBucketPattern(
        'exact', 'exactlynot'), false);
    t.done();
};

exports['matchBucketPattern: single char bucket names'] =
    function (t) {
    t.ok(bucketScope.matchBucketPattern('a', 'a'));
    t.equal(bucketScope.matchBucketPattern('a', 'b'),
        false);
    t.done();
};
