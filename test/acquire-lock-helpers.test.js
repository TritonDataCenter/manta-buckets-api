/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/**
 * Unit tests for DistributedLockManager.acquireLock helper functions
 * in s3-multipart.js
 */

var helper = require('./s3-test-helper.js');

// Test: createLockData - should create valid lock data structure
helper.test('createLockData creates valid structure', function (t) {
    function createLockData(self, uploadId, instanceId, lockTimeout) {
        return {
            uploadId: uploadId,
            instanceId: instanceId,
            acquired: new Date().toISOString(),
            expires: new Date(Date.now() + lockTimeout).toISOString(),
            operation: 'complete-multipart',
            processId: process.pid,
            hostname: require('os').hostname()
        };
    }

    var mockSelf = {};
    var result = createLockData(mockSelf, 'test-upload-123',
        'instance-456', 30000);

    t.equal(result.uploadId, 'test-upload-123', 'should set uploadId');
    t.equal(result.instanceId, 'instance-456', 'should set instanceId');
    t.equal(result.operation, 'complete-multipart', 'should set operation');
    t.equal(result.processId, process.pid, 'should set processId');
    t.equal(typeof (result).hostname, 'string', 'should set hostname');
    t.ok(result.acquired, 'should set acquired timestamp');
    t.ok(result.expires, 'should set expires timestamp');
    t.end();
});

// Test: createLockData - should set expiration in future
helper.test('createLockData sets future expiration', function (t) {
    function createLockData(self, uploadId, instanceId, lockTimeout) {
        return {
            uploadId: uploadId,
            instanceId: instanceId,
            acquired: new Date().toISOString(),
            expires: new Date(Date.now() + lockTimeout).toISOString(),
            operation: 'complete-multipart',
            processId: process.pid,
            hostname: require('os').hostname()
        };
    }

    var now = new Date();
    var result = createLockData({}, 'test-upload', 'instance', 5000);
    var expires = new Date(result.expires);

    t.ok(expires > now, 'expiration should be in the future');
    t.end();
});

// Test: parseLockState - should parse valid JSON lock data
helper.test('parseLockState parses valid JSON', function (t) {
    function parseLockState(self, lock, _uploadId) {
        try {
            var existingData = JSON.parse(lock.value || '{}');
            var expiresValue = existingData.expires;

            if (!expiresValue && lock.headers &&
                existingLock.headers['x-lock-expires']) {
                expiresValue = existingLock.headers['x-lock-expires'];
            }

            var expires = new Date(expiresValue);
            var hadParsingError = false;

            if (!expiresValue || isNaN(expires.getTime())) {
                hadParsingError = true;
                expires = new Date(0);
            }

            return {
                success: true,
                data: existingData,
                expires: expires,
                hadParsingError: hadParsingError
            };

        } catch (parseErr) {
            return {
                success: false,
                error: parseErr
            };
        }
    }

    var mockSelf = {
        req: {log: {debug: function () {}, warn: function () {}}}
    };

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

// Test: parseLockState - should handle missing expires in data
helper.test('parseLockState handles missing expires', function (t) {
    function parseLockState(self, lock, _uploadId) {
        try {
            var existingData = JSON.parse(lock.value || '{}');
            var expiresValue = existingData.expires;

            if (!expiresValue && lock.headers &&
                existingLock.headers['x-lock-expires']) {
                expiresValue = existingLock.headers['x-lock-expires'];
            }

            var expires = new Date(expiresValue);
            var hadParsingError = false;

            if (!expiresValue || isNaN(expires.getTime())) {
                hadParsingError = true;
                expires = new Date(0);
            }

            return {
                success: true,
                data: existingData,
                expires: expires,
                hadParsingError: hadParsingError
            };

        } catch (parseErr) {
            return {
                success: false,
                error: parseErr
            };
        }
    }

    var mockSelf = {
        req: {log: {debug: function () {}, warn: function () {}}}
    };

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

// Test: parseLockState - should fallback to headers for expires
helper.test('parseLockState uses header fallback', function (t) {
    function parseLockState(self, lock, _uploadId) {
        try {
            var existingData = JSON.parse(lock.value || '{}');
            var expiresValue = existingData.expires;

            if (!expiresValue && lock.headers &&
                existingLock.headers['x-lock-expires']) {
                expiresValue = existingLock.headers['x-lock-expires'];
                if (!existingData.instanceId &&
                    existingLock.headers['x-lock-instance']) {
                    existingData.instanceId =
                        existingLock.headers['x-lock-instance'];
                }
            }

            var expires = new Date(expiresValue);
            var hadParsingError = false;

            if (!expiresValue || isNaN(expires.getTime())) {
                hadParsingError = true;
                expires = new Date(0);
            }

            return {
                success: true,
                data: existingData,
                expires: expires,
                hadParsingError: hadParsingError
            };

        } catch (parseErr) {
            return {
                success: false,
                error: parseErr
            };
        }
    }

    var mockSelf = {
        req: {log: {debug: function () {}, warn: function () {}}}
    };

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

// Test: parseLockState - should handle invalid JSON
helper.test('parseLockState handles invalid JSON', function (t) {
    function parseLockState(self, lock, _uploadId) {
        try {
            var existingData = JSON.parse(lock.value || '{}');
            var expiresValue = existingData.expires;

            if (!expiresValue && lock.headers &&
                existingLock.headers['x-lock-expires']) {
                expiresValue = existingLock.headers['x-lock-expires'];
            }

            var expires = new Date(expiresValue);
            var hadParsingError = false;

            if (!expiresValue || isNaN(expires.getTime())) {
                hadParsingError = true;
                expires = new Date(0);
            }

            return {
                success: true,
                data: existingData,
                expires: expires,
                hadParsingError: hadParsingError
            };

        } catch (parseErr) {
            return {
                success: false,
                error: parseErr
            };
        }
    }

    var mockSelf = {
        req: {log: {debug: function () {}, warn: function () {}}}
    };

    var existingLock = {
        value: 'invalid-json-{}'
    };

    var result = parseLockState(mockSelf, existingLock, 'test-upload');

    t.ok(!result.success, 'should fail to parse');
    t.ok(result.error, 'should include error');
    t.end();
});

// Test: determineLockAction - should return 'owned' for same instance
helper.test('determineLockAction returns owned for same instance',
    function (t) {
    function determineLockAction(self, state, instanceId, uploadId,
        existingLockId) {
        var existingData = state.data;
        var expires = state.expires;

        if (existingData.instanceId === instanceId) {
            return {
                action: 'owned',
                lockInfo: {
                    lockKey: null,
                    instanceId: instanceId,
                    objectId: existingLockId,
                    acquired: existingData.acquired,
                    expires: existingData.expires
                }
            };
        }

        if (lockState.hadParsingError &&
            existingData.instanceId !== instanceId) {
            return ({action: 'retry-parsing-error'});
        }

        var now = new Date();
        if (now > expires) {
            return {
                action: 'claim-expired',
                existingObjectId: existingLockId
            };
        }

        var timeUntilExpiry = expires.getTime() - now.getTime();
        return {
            action: 'retry-held',
            timeUntilExpiry: timeUntilExpiry
        };
    }

    var mockSelf = {
        req: {log: {debug: function () {}, warn: function () {}}}
    };

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

// Test: determineLockAction - should return 'claim-expired' for expired lock
helper.test('determineLockAction returns claim-expired for expired lock',
    function (t) {
    function determineLockAction(self, state, instanceId, uploadId,
        existingLockId) {
        var existingData = state.data;
        var expires = state.expires;

        if (existingData.instanceId === instanceId) {
            return {
                action: 'owned',
                lockInfo: {
                    lockKey: null,
                    instanceId: instanceId,
                    objectId: existingLockId,
                    acquired: existingData.acquired,
                    expires: existingData.expires
                }
            };
        }

        if (lockState.hadParsingError &&
            existingData.instanceId !== instanceId) {
            return ({action: 'retry-parsing-error'});
        }

        var now = new Date();
        if (now > expires) {
            return {
                action: 'claim-expired',
                existingObjectId: existingLockId
            };
        }

        var timeUntilExpiry = expires.getTime() - now.getTime();
        return {
            action: 'retry-held',
            timeUntilExpiry: timeUntilExpiry
        };
    }

    var mockSelf = {
        req: {log: {debug: function () {}, warn: function () {}}}
    };

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

// Test: determineLockAction - should return 'retry-held' for active lock
helper.test('determineLockAction returns retry-held for active lock',
    function (t) {
    function determineLockAction(self, state, instanceId, uploadId,
        existingLockId) {
        var existingData = state.data;
        var expires = state.expires;

        if (existingData.instanceId === instanceId) {
            return {
                action: 'owned',
                lockInfo: {
                    lockKey: null,
                    instanceId: instanceId,
                    objectId: existingLockId,
                    acquired: existingData.acquired,
                    expires: existingData.expires
                }
            };
        }

        if (lockState.hadParsingError &&
            existingData.instanceId !== instanceId) {
            return ({action: 'retry-parsing-error'});
        }

        var now = new Date();
        if (now > expires) {
            return {
                action: 'claim-expired',
                existingObjectId: existingLockId
            };
        }

        var timeUntilExpiry = expires.getTime() - now.getTime();
        return {
            action: 'retry-held',
            timeUntilExpiry: timeUntilExpiry
        };
    }

    var mockSelf = {
        req: {log: {debug: function () {}, warn: function () {}}}
    };

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

// Test: determineLockAction - should return 'retry-parsing-error'
// for parsing errors
helper.test('determineLockAction returns retry-parsing-error', function (t) {
    function determineLockAction(self, state, instanceId, uploadId,
        existingLockId) {
        var existingData = state.data;
        var expires = state.expires;

        if (existingData.instanceId === instanceId) {
            return {
                action: 'owned',
                lockInfo: {
                    lockKey: null,
                    instanceId: instanceId,
                    objectId: existingLockId,
                    acquired: existingData.acquired,
                    expires: existingData.expires
                }
            };
        }

        if (lockState.hadParsingError &&
            existingData.instanceId !== instanceId) {
            return ({action: 'retry-parsing-error'});
        }

        var now = new Date();
        if (now > expires) {
            return {
                action: 'claim-expired',
                existingObjectId: existingLockId
            };
        }

        var timeUntilExpiry = expires.getTime() - now.getTime();
        return {
            action: 'retry-held',
            timeUntilExpiry: timeUntilExpiry
        };
    }

    var mockSelf = {
        req: {log: {debug: function () {}, warn: function () {}}}
    };

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
