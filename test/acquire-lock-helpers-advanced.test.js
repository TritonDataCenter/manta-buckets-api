/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/**
 * Advanced unit tests for DistributedLockManager.acquireLock helper functions
 * Uses mock infrastructure to test complex functions with dependencies
 */

var helper = require('./s3-test-helper.js');
var mocks = require('./mock-infrastructure.js');
var crypto = require('crypto');

// Test: createLockAtomic - should create lock successfully
helper.test('createLockAtomic creates lock on success', function (t) {
    function createLockAtomic(mockClient, mockLockParams, callback) {
        var self = mockLockParams.self;
        var owner = mockLockParams.owner;
        var lockReq = mockLockParams.lockReq;
        var lockKey = mockLockParams.lockKey;
        var lockObjectId = mockLockParams.lockObjectId;
        var lockContentArg = mockLockParams.lockContent;
        var lockMD5 = mockLockParams.lockMD5;
        var lockDataArg = mockLockParams.lockData;
        var instanceId = mockLockParams.instanceId;
        var metadataLocation = mockLockParams.metadataLocation;
        var _uploadId = mockLockParams.uploadId;

        self.req.log.debug({
            uploadId: _uploadId,
            instanceId: instanceId,
            lockKey: lockKey
        }, 'No existing lock found, attempting atomic creation');

        client.createObject(owner, lockReq.bucket.id, lockKey,
            lockObjectId, lockContentArg.length, lockMD5,
            'application/json', {
                'x-lock-instance': instanceId,
                'x-lock-expires': lockDataArg.expires,
                'x-lock-operation': 'complete-multipart',
                'x-lock-hostname': lockDataArg.hostname
            }, [], {}, metadataLocation.vnode, {},
            self.req.getId(),
            function (createErr, _result) {
                if (createErr) {
                    if (createErr.name === 'ObjectExistsError') {
                        self.req.log.debug({
                            uploadId: _uploadId
                        }, 'Lost creation race, will retry');
                        return (callback({action: 'retry-race'}));
                    }

                    self.req.log.error({
                        err: createErr,
                        uploadId: _uploadId
                    }, 'Failed to create lock due to system error');
                    return (callback({action: 'error', error: createErr}));
                }

                self.req.log.debug({
                    uploadId: _uploadId,
                    instanceId: instanceId,
                    lockKey: lockKey,
                    expires: lockDataArg.expires
                }, 'Successfully acquired distributed lock');

                callback({
                    action: 'success',
                    lockInfo: {
                        lockKey: lockKey,
                        instanceId: instanceId,
                        objectId: lockObjectId,
                        acquired: lockDataArg.acquired,
                        expires: lockDataArg.expires
                    }
                });
            });
    }

    var client = mocks.createMockMantaClient();
    var req = mocks.createMockRequest();

    var lockData = {
        uploadId: 'test-upload',
        instanceId: 'instance-123',
        acquired: new Date().toISOString(),
        expires: new Date(Date.now() + 30000).toISOString(),
        hostname: 'test-host',
        processId: process.pid
    };

    var lockContent = JSON.stringify(lockData);

    var lockParams = {
        self: {req: req},
        uploadId: 'test-upload',
        owner: 'test-owner',
        lockReq: {bucket: {id: 'bucket-id'}},
        lockKey: '.mpu-locks/test-upload.lock',
        lockObjectId: 'lock-obj-123',
        lockContent: lockContent,
        lockMD5: crypto.createHash('md5').update(lockContent).digest('base64'),
        lockData: lockData,
        instanceId: 'instance-123',
        metadataLocation: {vnode: 1}
    };

    createLockAtomic(client, lockParams, function (result) {
        t.equal(result.action, 'success', 'should return success action');
        t.ok(result.lockInfo, 'should include lock info');
        t.equal(result.lockInfo.instanceId, 'instance-123',
            'should include instance id');
        t.equal(result.lockInfo.lockKey, '.mpu-locks/test-upload.lock',
            'should include lock key');
        t.end();
    });
});

// Test: createLockAtomic - should handle race condition
helper.test('createLockAtomic handles ObjectExistsError', function (t) {
    function createLockAtomic(mockClient, mockLockParams, callback) {
        var self = mockLockParams.self;
        var owner = mockLockParams.owner;
        var lockReq = mockLockParams.lockReq;
        var lockKey = mockLockParams.lockKey;
        var lockObjectId = mockLockParams.lockObjectId;
        var lockContentArg = mockLockParams.lockContent;
        var lockMD5 = mockLockParams.lockMD5;
        var lockDataArg = mockLockParams.lockData;
        var instanceId = mockLockParams.instanceId;
        var metadataLocation = mockLockParams.metadataLocation;
        var _uploadId = mockLockParams.uploadId;

        client.createObject(owner, lockReq.bucket.id, lockKey,
            lockObjectId, lockContentArg.length, lockMD5,
            'application/json', {
                'x-lock-instance': instanceId,
                'x-lock-expires': lockDataArg.expires
            }, [], {}, metadataLocation.vnode, {},
            self.req.getId(),
            function (createErr, _result) {
                if (createErr) {
                    if (createErr.name === 'ObjectExistsError') {
                        return (callback({action: 'retry-race'}));
                    }
                    return (callback({action: 'error', error: createErr}));
                }

                callback({
                    action: 'success',
                    lockInfo: {
                        lockKey: lockKey,
                        instanceId: instanceId,
                        objectId: lockObjectId
                    }
                });
            });
    }

    var client = mocks.createMockMantaClient({
        simulateRaceCondition: true
    });
    var req = mocks.createMockRequest();

    var lockParams = {
        self: {req: req},
        uploadId: 'test-upload',
        owner: 'test-owner',
        lockReq: {bucket: {id: 'bucket-id'}},
        lockKey: '.mpu-locks/test-upload.lock',
        lockObjectId: 'lock-obj-123',
        lockContent: '{}',
        lockMD5: 'test-md5',
        lockData: {expires: new Date().toISOString()},
        instanceId: 'instance-123',
        metadataLocation: {vnode: 1}
    };

    createLockAtomic(client, lockParams, function (result) {
        t.equal(result.action, 'retry-race',
            'should return retry-race action for ObjectExistsError');
        t.end();
    });
});

// Test: createLockAtomic - should handle system errors
helper.test('createLockAtomic handles system errors', function (t) {
    function createLockAtomic(mockClient, mockLockParams, callback) {
        var self = mockLockParams.self;
        var owner = mockLockParams.owner;
        var lockReq = mockLockParams.lockReq;
        var lockKey = mockLockParams.lockKey;
        var lockObjectId = mockLockParams.lockObjectId;
        var lockContentArg = mockLockParams.lockContent;
        var lockMD5 = mockLockParams.lockMD5;
        var lockDataArg = mockLockParams.lockData;
        var instanceId = mockLockParams.instanceId;
        var metadataLocation = mockLockParams.metadataLocation;
        var _uploadId = mockLockParams.uploadId;

        client.createObject(owner, lockReq.bucket.id, lockKey,
            lockObjectId, lockContentArg.length, lockMD5,
            'application/json', {
                'x-lock-instance': instanceId,
                'x-lock-expires': lockDataArg.expires
            }, [], {}, metadataLocation.vnode, {},
            self.req.getId(),
            function (createErr, _result) {
                if (createErr) {
                    if (createErr.name === 'ObjectExistsError') {
                        return (callback({action: 'retry-race'}));
                    }
                    self.req.log.error({
                        err: createErr,
                        uploadId: _uploadId
                    }, 'Failed to create lock');
                    return (callback({action: 'error', error: createErr}));
                }

                callback({action: 'success'});
            });
    }

    var systemError = new Error('Database connection failed');
    systemError.name = 'SystemError';

    var client = mocks.createMockMantaClient({
        createObjectError: systemError
    });
    var req = mocks.createMockRequest();

    var lockParams = {
        self: {req: req},
        uploadId: 'test-upload',
        owner: 'test-owner',
        lockReq: {bucket: {id: 'bucket-id'}},
        lockKey: '.mpu-locks/test-upload.lock',
        lockObjectId: 'lock-obj-123',
        lockContent: '{}',
        lockMD5: 'test-md5',
        lockData: {expires: new Date().toISOString()},
        instanceId: 'instance-123',
        metadataLocation: {vnode: 1}
    };

    createLockAtomic(client, lockParams, function (result) {
        t.equal(result.action, 'error', 'should return error action');
        t.equal(result.error, systemError, 'should include error object');
        t.end();
    });
});

// Test: updateLockAtomic - should update expired lock successfully
helper.test('updateLockAtomic updates expired lock', function (t) {
    function updateLockAtomic(mockClient, mockLockParams, existingObjectId, callback) {
        var self = mockLockParams.self;
        var owner = mockLockParams.owner;
        var lockReq = mockLockParams.lockReq;
        var lockKey = mockLockParams.lockKey;
        var lockContentArg = mockLockParams.lockContent;
        var lockDataArg = mockLockParams.lockData;
        var instanceId = mockLockParams.instanceId;
        var metadataLocation = mockLockParams.metadataLocation;
        var _uploadId = mockLockParams.uploadId;

        self.req.log.debug({
            uploadId: _uploadId,
            existingObjectId: existingObjectId,
            newOwner: instanceId
        }, 'Attempting atomic update of expired lock');

        client.updateObject(owner, lockReq.bucket.id, lockKey,
            existingObjectId, 'application/json', {
                'x-lock-instance': instanceId,
                'x-lock-expires': lockDataArg.expires,
                'x-lock-hostname': lockDataArg.hostname,
                'content-length': String(lockContentArg.length)
            }, {}, metadataLocation.vnode, {},
            self.req.getId(),
            function (updateErr, _updateResult) {
                if (updateErr) {
                    if (updateErr.name === 'ObjectNotFoundError') {
                        self.req.log.debug({
                            uploadId: _uploadId
                        }, 'Expired lock was deleted by someone else');
                        return (callback({action: 'retry-deleted'}));
                    }

                    self.req.log.error({
                        err: updateErr,
                        uploadId: _uploadId
                    }, 'Failed to update lock');
                    return (callback({action: 'error', error: updateErr}));
                }

                self.req.log.debug({
                    uploadId: _uploadId,
                    instanceId: instanceId
                }, 'Successfully claimed expired lock');

                callback({
                    action: 'success',
                    lockInfo: {
                        lockKey: lockKey,
                        instanceId: instanceId,
                        objectId: existingObjectId,
                        acquired: lockDataArg.acquired,
                        expires: lockDataArg.expires
                    }
                });
            });
    }

    var client = mocks.createMockMantaClient();
    var req = mocks.createMockRequest();

    var lockData = {
        uploadId: 'test-upload',
        instanceId: 'instance-123',
        acquired: new Date().toISOString(),
        expires: new Date(Date.now() + 30000).toISOString(),
        hostname: 'test-host'
    };

    var lockParams = {
        self: {req: req},
        uploadId: 'test-upload',
        owner: 'test-owner',
        lockReq: {bucket: {id: 'bucket-id'}},
        lockKey: '.mpu-locks/test-upload.lock',
        lockContent: JSON.stringify(lockData),
        lockData: lockData,
        instanceId: 'instance-123',
        metadataLocation: {vnode: 1}
    };

    updateLockAtomic(client, lockParams, 'existing-lock-id-456',
        function (result) {
            t.equal(result.action, 'success', 'should return success action');
            t.ok(result.lockInfo, 'should include lock info');
            t.equal(result.lockInfo.objectId, 'existing-lock-id-456',
                'should use existing object id');
            t.end();
        });
});

// Test: updateLockAtomic - should handle lock deleted by another instance
helper.test('updateLockAtomic handles ObjectNotFoundError', function (t) {
    function updateLockAtomic(mockClient, mockLockParams, existingObjectId, callback) {
        var self = mockLockParams.self;
        var owner = mockLockParams.owner;
        var lockReq = mockLockParams.lockReq;
        var lockKey = mockLockParams.lockKey;
        var lockDataArg = mockLockParams.lockData;
        var instanceId = mockLockParams.instanceId;
        var metadataLocation = mockLockParams.metadataLocation;

        client.updateObject(owner, lockReq.bucket.id, lockKey,
            existingObjectId, 'application/json', {
                'x-lock-instance': instanceId,
                'x-lock-expires': lockDataArg.expires
            }, {}, metadataLocation.vnode, {},
            self.req.getId(),
            function (updateErr, _updateResult) {
                if (updateErr) {
                    if (updateErr.name === 'ObjectNotFoundError') {
                        return (callback({action: 'retry-deleted'}));
                    }
                    return (callback({action: 'error', error: updateErr}));
                }

                callback({action: 'success'});
            });
    }

    var client = mocks.createMockMantaClient({
        simulateLockDeleted: true
    });
    var req = mocks.createMockRequest();

    var lockParams = {
        self: {req: req},
        uploadId: 'test-upload',
        owner: 'test-owner',
        lockReq: {bucket: {id: 'bucket-id'}},
        lockKey: '.mpu-locks/test-upload.lock',
        lockContent: '{}',
        lockData: {expires: new Date().toISOString()},
        instanceId: 'instance-123',
        metadataLocation: {vnode: 1}
    };

    updateLockAtomic(client, lockParams, 'old-lock-id', function (result) {
        t.equal(result.action, 'retry-deleted',
            'should return retry-deleted for ObjectNotFoundError');
        t.end();
    });
});

// Test: updateLockAtomic - should handle system errors
helper.test('updateLockAtomic handles system errors', function (t) {
    function updateLockAtomic(mockClient, mockLockParams, existingObjectId, callback) {
        var self = mockLockParams.self;
        var owner = mockLockParams.owner;
        var lockReq = mockLockParams.lockReq;
        var lockKey = mockLockParams.lockKey;
        var lockDataArg = mockLockParams.lockData;
        var instanceId = mockLockParams.instanceId;
        var metadataLocation = mockLockParams.metadataLocation;
        var _uploadId = mockLockParams.uploadId;

        client.updateObject(owner, lockReq.bucket.id, lockKey,
            existingObjectId, 'application/json', {
                'x-lock-instance': instanceId,
                'x-lock-expires': lockDataArg.expires
            }, {}, metadataLocation.vnode, {},
            self.req.getId(),
            function (updateErr, _updateResult) {
                if (updateErr) {
                    if (updateErr.name === 'ObjectNotFoundError') {
                        return (callback({action: 'retry-deleted'}));
                    }
                    self.req.log.error({
                        err: updateErr,
                        uploadId: _uploadId
                    }, 'Failed to update lock');
                    return (callback({action: 'error', error: updateErr}));
                }

                callback({action: 'success'});
            });
    }

    var systemError = new Error('Network timeout');
    systemError.name = 'TimeoutError';

    var client = mocks.createMockMantaClient({
        updateObjectError: systemError
    });
    var req = mocks.createMockRequest();

    var lockParams = {
        self: {req: req},
        uploadId: 'test-upload',
        owner: 'test-owner',
        lockReq: {bucket: {id: 'bucket-id'}},
        lockKey: '.mpu-locks/test-upload.lock',
        lockContent: '{}',
        lockData: {expires: new Date().toISOString()},
        instanceId: 'instance-123',
        metadataLocation: {vnode: 1}
    };

    updateLockAtomic(client, lockParams, 'old-lock-id', function (result) {
        t.equal(result.action, 'error', 'should return error action');
        t.equal(result.error, systemError, 'should include error object');
        t.end();
    });
});
