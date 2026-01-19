/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/**
 * Unit tests for DistributedLockManager.acquireLock helper functions
 * in s3-multipart.js
 *
 * These tests exercise actual production code exported from
 * lib/s3-multipart.js.
 */

var os = require('os');

var helper = require('./s3-test-helper.js');
var s3Multipart = require('../lib/s3-multipart.js');

// Import production functions
var createLockData = s3Multipart.createLockData;
var parseLockState = s3Multipart.parseLockState;
var determineLockAction = s3Multipart.determineLockAction;

/**
 * Create mock self object with req.log for functions that need it
 */
function createMockSelf() {
    return {
        req: {
            log: {
                debug: function () {},
                warn: function () {}
            }
        }
    };
}


// ========== createLockData Tests ==========

helper.test('createLockData creates valid structure', function (t) {
    var mockSelf = createMockSelf();
    var result = createLockData(mockSelf, 'test-upload-123',
        'instance-456', 30000);

    t.equal(result.uploadId, 'test-upload-123', 'should set uploadId');
    t.equal(result.instanceId, 'instance-456', 'should set instanceId');
    t.equal(result.operation, 'complete-multipart', 'should set operation');
    t.equal(result.processId, process.pid, 'should set processId');
    t.equal(result.hostname, os.hostname(), 'should set hostname');
    t.ok(result.acquired, 'should set acquired timestamp');
    t.ok(result.expires, 'should set expires timestamp');
    t.end();
});

helper.test('createLockData sets future expiration', function (t) {
    var mockSelf = createMockSelf();
    var now = new Date();
    var result = createLockData(mockSelf, 'test-upload', 'instance', 5000);
    var expires = new Date(result.expires);

    t.ok(expires > now, 'expiration should be in the future');
    t.end();
});

helper.test('createLockData respects timeout parameter', function (t) {
    var mockSelf = createMockSelf();
    var beforeCreate = Date.now();
    var timeout = 60000; // 60 seconds
    var result = createLockData(mockSelf, 'upload-id', 'instance-id', timeout);
    var afterCreate = Date.now();

    var expires = new Date(result.expires).getTime();

    // Expires should be roughly beforeCreate + timeout to afterCreate + timeout
    t.ok(expires >= beforeCreate + timeout - 100,
        'expires should be at least timeout from start');
    t.ok(expires <= afterCreate + timeout + 100,
        'expires should not exceed timeout from end');
    t.end();
});


// ========== parseLockState Tests ==========

helper.test('parseLockState parses valid JSON', function (t) {
    var mockSelf = createMockSelf();

    var existingLock = {
        value: JSON.stringify({
            uploadId: 'test-upload',
            instanceId: 'instance-123',
            expires: '2025-12-31T00:00:00.000Z'
        })
    };

    var result = parseLockState(mockSelf, existingLock, 'test-upload');

    t.ok(result.success, 'should parse successfully');
    t.equal(result.data.uploadId, 'test-upload', 'should extract uploadId');
    t.equal(result.data.instanceId, 'instance-123',
        'should extract instanceId');
    t.ok(!result.hadParsingError, 'should not have parsing error');
    t.end();
});

helper.test('parseLockState handles missing expires', function (t) {
    var mockSelf = createMockSelf();

    var existingLock = {
        value: JSON.stringify({uploadId: 'test-upload'})
    };

    var result = parseLockState(mockSelf, existingLock, 'test-upload');

    t.ok(result.success, 'should parse successfully');
    t.ok(result.hadParsingError, 'should flag parsing error');
    t.equal(result.expires.getTime(), 0,
        'should use epoch for invalid expires');
    t.end();
});

helper.test('parseLockState uses header fallback', function (t) {
    var mockSelf = createMockSelf();

    var existingLock = {
        value: JSON.stringify({}),
        headers: {
            'x-lock-expires': '2025-12-31T00:00:00.000Z',
            'x-lock-instance': 'header-instance-123'
        }
    };

    var result = parseLockState(mockSelf, existingLock, 'test-upload');

    t.ok(result.success, 'should parse successfully');
    t.equal(result.data.instanceId, 'header-instance-123',
        'should extract instanceId from header');
    t.ok(!result.hadParsingError, 'should not have parsing error');
    t.end();
});

helper.test('parseLockState handles invalid JSON', function (t) {
    var mockSelf = createMockSelf();

    var existingLock = {
        value: 'invalid-json-{}'
    };

    var result = parseLockState(mockSelf, existingLock, 'test-upload');

    t.ok(!result.success, 'should fail to parse');
    t.ok(result.error, 'should include error');
    t.end();
});

helper.test('parseLockState handles empty value', function (t) {
    var mockSelf = createMockSelf();

    var existingLock = {
        value: ''
    };

    var result = parseLockState(mockSelf, existingLock, 'test-upload');

    // Empty string becomes '{}' due to || operator
    t.ok(result.success, 'should parse empty as empty object');
    t.ok(result.hadParsingError,
        'should flag parsing error for missing expires');
    t.end();
});


// ========== determineLockAction Tests ==========

helper.test('determineLockAction returns owned for same instance',
    function (t) {
    var mockSelf = createMockSelf();

    var lockState = {
        data: {
            instanceId: 'instance-123',
            acquired: '2025-12-14T00:00:00.000Z',
            expires: '2025-12-14T01:00:00.000Z'
        },
        expires: new Date('2025-12-14T01:00:00.000Z'),
        hadParsingError: false
    };

    var result = determineLockAction(mockSelf, lockState, 'instance-123',
        'test-upload', 'lock-obj-id');

    t.equal(result.action, 'owned', 'should return owned action');
    t.ok(result.lockInfo, 'should include lockInfo');
    t.equal(result.lockInfo.instanceId, 'instance-123',
        'should include instanceId');
    t.end();
});

helper.test('determineLockAction returns claim-expired for expired lock',
    function (t) {
    var mockSelf = createMockSelf();
    var pastTime = new Date(Date.now() - 60000); // 1 minute ago

    var lockState = {
        data: {
            instanceId: 'other-instance',
            acquired: '2025-12-14T00:00:00.000Z',
            expires: pastTime.toISOString()
        },
        expires: pastTime,
        hadParsingError: false
    };

    var result = determineLockAction(mockSelf, lockState, 'instance-123',
        'test-upload', 'lock-obj-id');

    t.equal(result.action, 'claim-expired',
        'should return claim-expired action');
    t.equal(result.existingObjectId, 'lock-obj-id',
        'should include existing object id');
    t.end();
});

helper.test('determineLockAction returns retry-held for active lock',
    function (t) {
    var mockSelf = createMockSelf();
    var futureTime = new Date(Date.now() + 60000); // 1 minute from now

    var lockState = {
        data: {
            instanceId: 'other-instance',
            acquired: '2025-12-14T00:00:00.000Z',
            expires: futureTime.toISOString()
        },
        expires: futureTime,
        hadParsingError: false
    };

    var result = determineLockAction(mockSelf, lockState, 'instance-123',
        'test-upload', 'lock-obj-id');

    t.equal(result.action, 'retry-held', 'should return retry-held action');
    t.ok(result.timeUntilExpiry > 0,
        'should include positive time until expiry');
    t.end();
});

helper.test('determineLockAction returns retry-parsing-error', function (t) {
    var mockSelf = createMockSelf();

    var lockState = {
        data: {
            instanceId: 'other-instance'
        },
        expires: new Date(0),
        hadParsingError: true
    };

    var result = determineLockAction(mockSelf, lockState, 'instance-123',
        'test-upload', 'lock-obj-id');

    t.equal(result.action, 'retry-parsing-error',
        'should return retry-parsing-error action');
    t.end();
});

helper.test('determineLockAction owned takes priority over parsing error',
    function (t) {
    var mockSelf = createMockSelf();

    // Same instance but with parsing error - should still return owned
    var lockState = {
        data: {
            instanceId: 'instance-123',
            acquired: '2025-12-14T00:00:00.000Z'
        },
        expires: new Date(0),
        hadParsingError: true
    };

    var result = determineLockAction(mockSelf, lockState, 'instance-123',
        'test-upload', 'lock-obj-id');

    t.equal(result.action, 'owned',
        'should return owned even with parsing error for same instance');
    t.end();
});
