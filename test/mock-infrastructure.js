/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/**
 * Mock infrastructure for unit testing
 * Provides mock implementations of complex dependencies
 */

/**
 * Create a mock logger with all required methods
 */
function createMockLogger() {
    var logs = {
        debug: [],
        info: [],
        warn: [],
        error: [],
        trace: []
    };

    return {
        debug: function(obj, msg) {
            logs.debug.push({obj: obj, msg: msg});
        },
        info: function(obj, msg) {
            logs.info.push({obj: obj, msg: msg});
        },
        warn: function(obj, msg) {
            logs.warn.push({obj: obj, msg: msg});
        },
        error: function(obj, msg) {
            logs.error.push({obj: obj, msg: msg});
        },
        trace: function(obj, msg) {
            logs.trace.push({obj: obj, msg: msg});
        },
        getLogs: function() {
            return logs;
        },
        child: function() {
            return createMockLogger();
        }
    };
}

/**
 * Create a mock request object with S3 request structure
 */
function createMockRequest(options) {
    options = options || {};

    var req = {
        log: options.log || createMockLogger(),
        params: options.params || {},
        headers: options.headers || {},
        s3Request: options.s3Request || {
            bucket: options.bucket || 'test-bucket',
            object: options.object || 'test-object',
            uploadId: options.uploadId,
            partNumber: options.partNumber
        },
        owner: options.owner || {
            account: {
                uuid: options.accountUuid || 'test-account-uuid'
            }
        },
        metadataPlacement: options.metadataPlacement || createMockMetadataPlacement(),
        body: options.body,
        _rawBodyString: options._rawBodyString,
        _rawBodyBuffer: options._rawBodyBuffer,
        potentialAnonymousAccess: options.potentialAnonymousAccess || false,
        isS3Request: options.isS3Request !== undefined ? options.isS3Request : true,
        method: options.method || 'GET',
        _size: options._size,
        metadata: options.metadata || {headers: {}},
        getId: function() {
            return options.requestId || 'test-request-id-123';
        },
        path: function() {
            return options.path || '/test-bucket/test-object';
        },
        header: function(name, defaultValue) {
            var value = req.headers[name.toLowerCase()];
            return value !== undefined ? value : defaultValue;
        },
        isChunked: options.isChunked
    };

    return req;
}

/**
 * Create a mock response object
 */
function createMockResponse(options) {
    options = options || {};

    var headers = {};
    var statusCode = null;
    var body = null;
    var sent = false;

    return {
        setHeader: function(name, value) {
            headers[name] = value;
        },
        header: function(name, value) {
            headers[name] = value;
            return this;
        },
        getHeader: function(name) {
            return headers[name];
        },
        getHeaders: function() {
            return headers;
        },
        send: function(code, data) {
            statusCode = code;
            body = data;
            sent = true;
        },
        _headers: headers,
        _getStatusCode: function() {
            return statusCode;
        },
        _getBody: function() {
            return body;
        },
        _wasSent: function() {
            return sent;
        }
    };
}

/**
 * Create a mock Manta metadata client
 */
function createMockMantaClient(options) {
    options = options || {};

    return {
        createObject: function(owner, bucketId, objectName, objectId, size, md5,
            contentType, headers, sharks, properties, vnode, opts, requestId,
            callback) {
            if (options.createObjectError) {
                return callback(options.createObjectError);
            }

            if (options.simulateRaceCondition) {
                var err = new Error('Object already exists');
                err.name = 'ObjectExistsError';
                return callback(err);
            }

            callback(null, {
                id: objectId,
                owner: owner,
                bucket: bucketId,
                name: objectName,
                created: new Date().toISOString()
            });
        },

        updateObject: function(owner, bucketId, objectName, existingId,
            contentType, headers, properties, vnode, opts, requestId, callback) {
            if (options.updateObjectError) {
                return callback(options.updateObjectError);
            }

            if (options.simulateLockDeleted) {
                var err = new Error('Object not found');
                err.name = 'ObjectNotFoundError';
                return callback(err);
            }

            callback(null, {
                id: existingId,
                owner: owner,
                bucket: bucketId,
                name: objectName,
                updated: new Date().toISOString()
            });
        },

        getObject: function(owner, bucketId, objectName, vnode, opts, requestId,
            callback) {
            if (options.getObjectError) {
                return callback(options.getObjectError);
            }

            if (options.noLockFound) {
                var err = new Error('Object not found');
                err.name = 'ObjectNotFoundError';
                return callback(err);
            }

            callback(null, options.existingLock || {
                id: 'existing-lock-id',
                owner: owner,
                bucket: bucketId,
                name: objectName,
                value: JSON.stringify({
                    uploadId: 'test-upload',
                    instanceId: 'other-instance',
                    acquired: new Date().toISOString(),
                    expires: new Date(Date.now() + 60000).toISOString()
                })
            });
        }
    };
}

/**
 * Create a mock metadata placement manager
 */
function createMockMetadataPlacement(options) {
    options = options || {};

    return {
        getObjectLocation: function(owner, bucketId, hash) {
            return options.location || {
                pnode: 'tcp://127.0.0.1:2020',
                vnode: 123,
                data: 1
            };
        },
        getBucketsMdapiClient: function(location) {
            return options.client || createMockMantaClient(options.clientOptions);
        }
    };
}

/**
 * Create a mock bucket object
 */
function createMockBucket(options) {
    options = options || {};

    return {
        id: options.id || 'test-bucket-id-123',
        name: options.name || 'test-bucket',
        owner: options.owner || 'test-owner-uuid',
        created: options.created || new Date().toISOString()
    };
}

/**
 * Create mock bucketHelpers module
 */
function createMockBucketHelpers(options) {
    options = options || {};

    return {
        getBucketIfExists: function(req, opts, callback) {
            if (options.getBucketError) {
                return callback(options.getBucketError);
            }

            req.bucket = options.bucket || createMockBucket();
            callback(null);
        },

        loadRequest: function(req, opts, callback) {
            if (options.loadRequestError) {
                return callback(options.loadRequestError);
            }

            callback(null);
        },

        Bucket: function(req) {
            this.id = 'test-bucket-id';
            this.name = req.params.bucket_name || 'test-bucket';
        }
    };
}

/**
 * Create a mock upload record
 */
function createMockUploadRecord(options) {
    options = options || {};

    return {
        uploadId: options.uploadId || 'test-upload-id',
        bucket: options.bucket || 'test-bucket',
        objectKey: options.objectKey || 'test-object',
        owner: options.owner || 'test-owner-uuid',
        initiated: options.initiated || new Date().toISOString(),
        durabilityLevel: options.durabilityLevel,
        preAllocatedSharks: options.preAllocatedSharks || [
            {manta_storage_id: 'shark-1'},
            {manta_storage_id: 'shark-2'}
        ],
        parts: options.parts || []
    };
}

/**
 * Create a mock bucket module with handler methods
 */
function createMockBucketsModule(options) {
    options = options || {};

    return {
        getBucketObjectHandler: function() {
            return options.handlers || [
                function(req, res, next) { next(); }
            ];
        }
    };
}

/**
 * Create a mock callback function that captures calls
 */
function createMockCallback() {
    var calls = [];

    var callback = function(err, result) {
        calls.push({
            err: err,
            result: result,
            timestamp: Date.now()
        });
    };

    callback.getCalls = function() {
        return calls;
    };

    callback.getLastCall = function() {
        return calls.length > 0 ? calls[calls.length - 1] : null;
    };

    callback.wasCalled = function() {
        return calls.length > 0;
    };

    callback.wasCalledWith = function(expectedErr, expectedResult) {
        var lastCall = callback.getLastCall();
        if (!lastCall) return false;

        if (expectedErr !== undefined && lastCall.err !== expectedErr) {
            return false;
        }

        if (expectedResult !== undefined && lastCall.result !== expectedResult) {
            return false;
        }

        return true;
    };

    return callback;
}

/**
 * Create a spy function that tracks calls
 */
function createSpy(implementation) {
    var calls = [];

    var spy = function() {
        var args = Array.prototype.slice.call(arguments);
        calls.push({
            args: args,
            timestamp: Date.now()
        });

        if (implementation) {
            return implementation.apply(this, arguments);
        }
    };

    spy.getCalls = function() {
        return calls;
    };

    spy.getCallCount = function() {
        return calls.length;
    };

    spy.wasCalled = function() {
        return calls.length > 0;
    };

    spy.wasCalledWith = function() {
        var expectedArgs = Array.prototype.slice.call(arguments);
        return calls.some(function(call) {
            if (call.args.length !== expectedArgs.length) return false;
            for (var i = 0; i < expectedArgs.length; i++) {
                if (call.args[i] !== expectedArgs[i]) return false;
            }
            return true;
        });
    };

    spy.reset = function() {
        calls = [];
    };

    return spy;
}

module.exports = {
    createMockLogger: createMockLogger,
    createMockRequest: createMockRequest,
    createMockResponse: createMockResponse,
    createMockMantaClient: createMockMantaClient,
    createMockMetadataPlacement: createMockMetadataPlacement,
    createMockBucket: createMockBucket,
    createMockBucketHelpers: createMockBucketHelpers,
    createMockUploadRecord: createMockUploadRecord,
    createMockBucketsModule: createMockBucketsModule,
    createMockCallback: createMockCallback,
    createSpy: createSpy
};
