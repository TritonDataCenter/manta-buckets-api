/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/**
 * Unit tests for s3CompleteMultipartUploadHandler helper functions
 * in s3-multipart.js
 */

var helper = require('./s3-test-helper.js');

// Test: extractPartETags - should extract ETag array from parts
helper.test('extractPartETags extracts ETag array', function (t) {
    function extractPartETags(partsFromXML) {
        var partETags = [];
        partsFromXML.forEach(function (xmlPart) {
            partETags.push(xmlPart.etag);
        });
        return partETags;
    }

    var partsFromXML = [
        {partNumber: 1, etag: 'etag-1'},
        {partNumber: 2, etag: 'etag-2'},
        {partNumber: 3, etag: 'etag-3'}
    ];

    var result = extractPartETags(partsFromXML);

    t.equal(result.length, 3, 'should extract 3 ETags');
    t.equal(result[0], 'etag-1', 'should extract first ETag');
    t.equal(result[1], 'etag-2', 'should extract second ETag');
    t.equal(result[2], 'etag-3', 'should extract third ETag');
    t.end();
});

// Test: extractPartETags - should handle empty array
helper.test('extractPartETags handles empty array', function (t) {
    function extractPartETags(partsFromXML) {
        var partETags = [];
        partsFromXML.forEach(function (xmlPart) {
            partETags.push(xmlPart.etag);
        });
        return partETags;
    }

    var result = extractPartETags([]);

    t.equal(result.length, 0, 'should return empty array');
    t.end();
});

// Test: extractPartETags - should handle single part
helper.test('extractPartETags handles single part', function (t) {
    function extractPartETags(partsFromXML) {
        var partETags = [];
        partsFromXML.forEach(function (xmlPart) {
            partETags.push(xmlPart.etag);
        });
        return partETags;
    }

    var partsFromXML = [{partNumber: 1, etag: 'single-etag'}];

    var result = extractPartETags(partsFromXML);

    t.equal(result.length, 1, 'should extract 1 ETag');
    t.equal(result[0], 'single-etag', 'should extract correct ETag');
    t.end();
});

// Test: createCommitBody - should create valid commit body
helper.test('createCommitBody creates valid structure', function (t) {
    function extractPartETags(partsFromXML) {
        var partETags = [];
        partsFromXML.forEach(function (xmlPart) {
            partETags.push(xmlPart.etag);
        });
        return partETags;
    }

    function createCommitBody(partsFromXML, actualTotalSize, owner,
        finalObjectId) {
        var partETags = extractPartETags(partsFromXML);

        return {
            version: 1,
            nbytes: actualTotalSize,
            account: owner,
            objectId: finalObjectId,
            parts: partETags
        };
    }

    var partsFromXML = [
        {partNumber: 1, etag: 'etag-1'},
        {partNumber: 2, etag: 'etag-2'}
    ];

    var result = createCommitBody(partsFromXML, 2048, 'test-owner',
        'final-obj-id');

    t.equal(result.version, 1, 'should set version to 1');
    t.equal(result.nbytes, 2048, 'should set nbytes correctly');
    t.equal(result.account, 'test-owner', 'should set account correctly');
    t.equal(result.objectId, 'final-obj-id', 'should set objectId correctly');
    t.equal(result.parts.length, 2, 'should include all parts');
    t.equal(result.parts[0], 'etag-1', 'should include first ETag');
    t.equal(result.parts[1], 'etag-2', 'should include second ETag');
    t.end();
});

// Test: createCommitBody - should handle zero bytes
helper.test('createCommitBody handles zero bytes', function (t) {
    function extractPartETags(partsFromXML) {
        var partETags = [];
        partsFromXML.forEach(function (xmlPart) {
            partETags.push(xmlPart.etag);
        });
        return partETags;
    }

    function createCommitBody(partsFromXML, actualTotalSize, owner,
        finalObjectId) {
        var partETags = extractPartETags(partsFromXML);

        return {
            version: 1,
            nbytes: actualTotalSize,
            account: owner,
            objectId: finalObjectId,
            parts: partETags
        };
    }

    var result = createCommitBody([], 0, 'test-owner', 'obj-id');

    t.equal(result.nbytes, 0, 'should handle zero bytes');
    t.equal(result.parts.length, 0, 'should handle empty parts');
    t.end();
});

// Test: transformAssemblyError - should transform NotEnoughSpaceError
helper.test('transformAssemblyError handles NotEnoughSpaceError', function (t) {
    function transformAssemblyError(assembleErr) {
        if (assembleErr.name === 'NotEnoughSpaceError') {
            var spaceError = new Error(assembleErr.message ||
                'Insufficient storage space');
            spaceError.statusCode = 507;
            spaceError.restCode = 'InsufficientStorage';
            return spaceError;
        }

        var internalError = new Error(assembleErr.message ||
            'Multipart upload assembly failed');
        internalError.statusCode = 500;
        internalError.restCode = 'InternalError';
        return internalError;
    }

    var originalError = new Error('Out of space');
    originalError.name = 'NotEnoughSpaceError';

    var result = transformAssemblyError(originalError);

    t.equal(result.statusCode, 507, 'should set 507 status code');
    t.equal(result.restCode, 'InsufficientStorage',
        'should set InsufficientStorage restCode');
    t.equal(result.message, 'Out of space', 'should preserve message');
    t.end();
});

// Test: transformAssemblyError - should use default message for space error
helper.test('transformAssemblyError uses default space error message', function (t) {
    function transformAssemblyError(assembleErr) {
        if (assembleErr.name === 'NotEnoughSpaceError') {
            var spaceError = new Error(assembleErr.message ||
                'Insufficient storage space');
            spaceError.statusCode = 507;
            spaceError.restCode = 'InsufficientStorage';
            return spaceError;
        }

        var internalError = new Error(assembleErr.message ||
            'Multipart upload assembly failed');
        internalError.statusCode = 500;
        internalError.restCode = 'InternalError';
        return internalError;
    }

    var originalError = new Error();
    originalError.name = 'NotEnoughSpaceError';
    originalError.message = '';

    var result = transformAssemblyError(originalError);

    t.equal(result.message, 'Insufficient storage space',
        'should use default message');
    t.end();
});

// Test: transformAssemblyError - should transform generic errors
helper.test('transformAssemblyError handles generic errors', function (t) {
    function transformAssemblyError(assembleErr) {
        if (assembleErr.name === 'NotEnoughSpaceError') {
            var spaceError = new Error(assembleErr.message ||
                'Insufficient storage space');
            spaceError.statusCode = 507;
            spaceError.restCode = 'InsufficientStorage';
            return spaceError;
        }

        var internalError = new Error(assembleErr.message ||
            'Multipart upload assembly failed');
        internalError.statusCode = 500;
        internalError.restCode = 'InternalError';
        return internalError;
    }

    var originalError = new Error('Something went wrong');
    originalError.name = 'GenericError';

    var result = transformAssemblyError(originalError);

    t.equal(result.statusCode, 500, 'should set 500 status code');
    t.equal(result.restCode, 'InternalError', 'should set InternalError restCode');
    t.equal(result.message, 'Something went wrong', 'should preserve message');
    t.end();
});

// Test: transformAssemblyError - should use default message for generic error
helper.test('transformAssemblyError uses default generic error message', function (t) {
    function transformAssemblyError(assembleErr) {
        if (assembleErr.name === 'NotEnoughSpaceError') {
            var spaceError = new Error(assembleErr.message ||
                'Insufficient storage space');
            spaceError.statusCode = 507;
            spaceError.restCode = 'InsufficientStorage';
            return spaceError;
        }

        var internalError = new Error(assembleErr.message ||
            'Multipart upload assembly failed');
        internalError.statusCode = 500;
        internalError.restCode = 'InternalError';
        return internalError;
    }

    var originalError = new Error();
    originalError.name = 'GenericError';
    originalError.message = '';

    var result = transformAssemblyError(originalError);

    t.equal(result.message, 'Multipart upload assembly failed',
        'should use default message');
    t.end();
});

// Test: releaseLockSafely - should handle null lockInfo
helper.test('releaseLockSafely handles null lockInfo', function (t) {
    function releaseLockSafely(lockManager, lockInfo, req, uploadId, callback) {
        if (!lockInfo) {
            return callback();
        }

        lockManager.releaseLock(lockInfo, function (releaseErr) {
            if (releaseErr) {
                req.log.warn(releaseErr, 'Failed to release lock');
            } else {
                req.log.debug({
                    uploadId: uploadId,
                    lockKey: lockInfo.lockKey
                }, 'Successfully released distributed lock');
            }
            callback(releaseErr);
        });
    }

    var callbackCalled = false;

    releaseLockSafely(null, null, {}, 'test-upload', function () {
        callbackCalled = true;
    });

    t.ok(callbackCalled, 'should call callback immediately for null lockInfo');
    t.end();
});

// Test: releaseLockSafely - should call releaseLock for valid lockInfo
helper.test('releaseLockSafely calls releaseLock', function (t) {
    function releaseLockSafely(lockManager, lockInfo, req, uploadId, callback) {
        if (!lockInfo) {
            return callback();
        }

        lockManager.releaseLock(lockInfo, function (releaseErr) {
            if (releaseErr) {
                req.log.warn(releaseErr, 'Failed to release lock');
            } else {
                req.log.debug({
                    uploadId: uploadId,
                    lockKey: lockInfo.lockKey
                }, 'Successfully released distributed lock');
            }
            callback(releaseErr);
        });
    }

    var releaseCalled = false;
    var mockLockManager = {
        releaseLock: function (lockInfo, callback) {
            releaseCalled = true;
            callback(null);
        }
    };

    var req = {
        log: {
            warn: function () {},
            debug: function () {}
        }
    };

    releaseLockSafely(mockLockManager, {lockKey: 'test-lock'}, req,
        'test-upload', function () {
            t.ok(releaseCalled, 'should call releaseLock');
            t.end();
        });
});

// Test: releaseLockSafely - should handle release errors
helper.test('releaseLockSafely handles release errors', function (t) {
    function releaseLockSafely(lockManager, lockInfo, req, uploadId, callback) {
        if (!lockInfo) {
            return callback();
        }

        lockManager.releaseLock(lockInfo, function (releaseErr) {
            if (releaseErr) {
                req.log.warn(releaseErr, 'Failed to release lock');
            } else {
                req.log.debug({
                    uploadId: uploadId,
                    lockKey: lockInfo.lockKey
                }, 'Successfully released distributed lock');
            }
            callback(releaseErr);
        });
    }

    var warnCalled = false;
    var mockLockManager = {
        releaseLock: function (lockInfo, callback) {
            callback(new Error('Release failed'));
        }
    };

    var req = {
        log: {
            warn: function () { warnCalled = true; },
            debug: function () {}
        }
    };

    releaseLockSafely(mockLockManager, {lockKey: 'test-lock'}, req,
        'test-upload', function (err) {
            t.ok(warnCalled, 'should log warning on error');
            t.ok(err, 'should pass error to callback');
            t.equal(err.message, 'Release failed', 'should pass correct error');
            t.end();
        });
});

// Test: cleanupAndExit - should release lock before calling callback
helper.test('cleanupAndExit releases lock before exit', function (t) {
    function releaseLockSafely(lockManager, lockInfo, req, uploadId, callback) {
        if (!lockInfo) {
            return callback();
        }

        lockManager.releaseLock(lockInfo, function (releaseErr) {
            callback(releaseErr);
        });
    }

    function cleanupAndExit(error, lockManager, lockInfo, req, uploadId,
        callback) {
        releaseLockSafely(lockManager, lockInfo, req, uploadId, function () {
            callback(error);
        });
    }

    var releaseCalled = false;
    var mockLockManager = {
        releaseLock: function (lockInfo, callback) {
            releaseCalled = true;
            callback(null);
        }
    };

    var testError = new Error('Test error');

    cleanupAndExit(testError, mockLockManager, {lockKey: 'test'}, {},
        'test-upload', function (err) {
            t.ok(releaseCalled, 'should release lock before callback');
            t.equal(err, testError, 'should pass original error to callback');
            t.end();
        });
});
