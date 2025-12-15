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
        debug: function (obj, msg) {
            logs.debug.push({obj: obj, msg: msg});
        },
        info: function (obj, msg) {
            logs.info.push({obj: obj, msg: msg});
        },
        warn: function (obj, msg) {
            logs.warn.push({obj: obj, msg: msg});
        },
        error: function (obj, msg) {
            logs.error.push({obj: obj, msg: msg});
        },
        trace: function (obj, msg) {
            logs.trace.push({obj: obj, msg: msg});
        },
        getLogs: function () {
            return (logs);
        },
        child: function () {
            return (createMockLogger());
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
        metadataPlacement: options.metadataPlacement ||
            createMockMetadataPlacement(),
        body: options.body,
        _rawBodyString: options._rawBodyString,
        _rawBodyBuffer: options._rawBodyBuffer,
        potentialAnonymousAccess: options.potentialAnonymousAccess || false,
        isS3Request: options.isS3Request !== undefined ?
            options.isS3Request : true,
        method: options.method || 'GET',
        _size: options._size,
        metadata: options.metadata || {headers: {}},
        getId: function () {
            return (options.requestId || 'test-request-id-123');
        },
        path: function () {
            return (options.path || '/test-bucket/test-object');
        },
        header: function (name, defaultValue) {
            var value = req.headers[name.toLowerCase()];
            return (value !== undefined ? value : defaultValue);
        },
        isChunked: options.isChunked
    };

    return (req);
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
        setHeader: function (name, value) {
            headers[name] = value;
        },
        header: function (name, value) {
            headers[name] = value;
            return (this);
        },
        getHeader: function (name) {
            return (headers[name]);
        },
        getHeaders: function () {
            return (headers);
        },
        send: function (code, data) {
            statusCode = code;
            body = data;
            sent = true;
        },
        _headers: headers,
        _getStatusCode: function () {
            return (statusCode);
        },
        _getBody: function () {
            return (body);
        },
        _wasSent: function () {
            return (sent);
        }
    };
}

/**
 * Create a mock Manta metadata client
 */
function createMockMantaClient(options) {
    options = options || {};

    return {
        createObject: function (owner, bucketId, objectName, objectId,
            size, md5, contentType, headers, sharks, properties, vnode,
            opts, requestId, callback) {
            if (options.createObjectError) {
                return (callback(options.createObjectError));
            }

            if (options.simulateRaceCondition) {
                var err = new Error('Object already exists');
                err.name = 'ObjectExistsError';
                return (callback(err));
            }

            callback(null, {
                id: objectId,
                owner: owner,
                bucket: bucketId,
                name: objectName,
                created: new Date().toISOString()
            });
        },

        updateObject: function (owner, bucketId, objectName,
            existingId, contentType, headers, properties, vnode, opts,
            requestId, callback) {
            if (options.updateObjectError) {
                return (callback(options.updateObjectError));
            }

            if (options.simulateLockDeleted) {
                var err = new Error('Object not found');
                err.name = 'ObjectNotFoundError';
                return (callback(err));
            }

            callback(null, {
                id: existingId,
                owner: owner,
                bucket: bucketId,
                name: objectName,
                updated: new Date().toISOString()
            });
        },

        getObject: function (owner, bucketId, objectName, vnode, opts,
            requestId, callback) {
            if (options.getObjectError) {
                return (callback(options.getObjectError));
            }

            if (options.noLockFound) {
                var err = new Error('Object not found');
                err.name = 'ObjectNotFoundError';
                return (callback(err));
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
        getObjectLocation: function (owner, bucketId, hash) {
            return options.location || {
                pnode: 'tcp://127.0.0.1:2020',
                vnode: 123,
                data: 1
            };
        },
        getBucketsMdapiClient: function (location) {
            return (options.client ||
                createMockMantaClient(options.clientOptions));
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
        getBucketIfExists: function (req, opts, callback) {
            if (options.getBucketError) {
                return (callback(options.getBucketError));
            }

            req.bucket = options.bucket || createMockBucket();
            callback(null);
        },

        loadRequest: function (req, opts, callback) {
            if (options.loadRequestError) {
                return (callback(options.loadRequestError));
            }

            callback(null);
        },

        Bucket: function (req) {
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
        getBucketObjectHandler: function () {
            return options.handlers || [
                function (req, res, next) { next(); }
            ];
        }
    };
}

/**
 * Create a mock callback function that captures calls
 */
function createMockCallback() {
    var calls = [];

    var callback = function (err, result) {
        calls.push({
            err: err,
            result: result,
            timestamp: Date.now()
        });
    };

    callback.getCalls = function () {
        return (calls);
    };

    callback.getLastCall = function () {
        return (calls.length > 0 ? calls[calls.length - 1] : null);
    };

    callback.wasCalled = function () {
        return (calls.length > 0);
    };

    callback.wasCalledWith = function (expectedErr, expectedResult) {
        var lastCall = callback.getLastCall();
if (!lastCall) {
            return (false);
        }

        if (expectedErr !== undefined && lastCall.err !== expectedErr) {
            return (false);
        }

        if (expectedResult !== undefined &&
            lastCall.result !== expectedResult) {
            return (false);
        }

        return (true);
    };

    return (callback);
}

/**
 * Create a spy function that tracks calls
 */
function createSpy(implementation) {
    var calls = [];

    var spy = function () {
        var args = Array.prototype.slice.call(arguments);
        calls.push({
            args: args,
            timestamp: Date.now()
        });

        if (implementation) {
            return (implementation.apply(this, arguments));
        }
    };

    spy.getCalls = function () {
        return (calls);
    };

    spy.getCallCount = function () {
        return (calls.length);
    };

    spy.wasCalled = function () {
        return (calls.length > 0);
    };

    spy.wasCalledWith = function () {
        var expectedArgs = Array.prototype.slice.call(arguments);
        return calls.some(function (call) {
if (call.args.length !== expectedArgs.length) {
                return (false);
            }
            for (var i = 0; i < expectedArgs.length; i++) {
if (call.args[i] !== expectedArgs[i]) {
                    return (false);
                }
            }
            return (true);
        });
    };

    spy.reset = function () {
        calls = [];
    };

    return (spy);
}

/*
 * E2E Testing Components - Streaming & Multipart Support
 * ============================================================================
 */

var crypto = require('crypto');
var stream = require('stream');
var util = require('util');

/**
 * Create a mock shark node with streaming support
 * Simulates a Manta storage node that can store/retrieve object data
 */
function createMockSharkNode(sharkId, options) {
    options = options || {};

    var storage = {}; // objectId -> Buffer

    return {
        id: sharkId,

        /**
         * Store object data from stream
         * Computes MD5 during streaming
         */
        putObject: function (objectId, dataStream, callback) {
            var chunks = [];
            var hash = crypto.createHash('md5');
            var bytesWritten = 0;

            dataStream.on('data', function (chunk) {
                chunks.push(chunk);
                hash.update(chunk);
                bytesWritten += chunk.length;
            });

            dataStream.on('end', function () {
                var data = Buffer.concat(chunks);
                var md5 = hash.digest('base64');

                storage[objectId] = data;

                callback(null, {
                    id: objectId,
                    size: bytesWritten,
                    md5: md5,
                    shark: sharkId
                });
            });

            dataStream.on('error', function (err) {
                callback(err);
            });
        },

        /**
         * Retrieve object data as stream
         */
        getObject: function (objectId, callback) {
            var data = storage[objectId];

            if (!data) {
                var err = new Error('Object not found on shark ' + sharkId);
                err.name = 'ObjectNotFoundError';
                return (callback(err));
            }

            // Create readable stream from buffer
            var bufferStream = new stream.PassThrough();
            bufferStream.end(data);

            callback(null, bufferStream, {
                size: data.length,
                shark: sharkId
            });
        },

        /**
         * Get object metadata without streaming data
         */
        getObjectMetadata: function (objectId) {
            var data = storage[objectId];
if (!data) {
                return (null);
            }

            return {
                size: data.length,
                shark: sharkId,
                exists: true
            };
        },

        /**
         * Delete object
         */
        deleteObject: function (objectId, callback) {
            delete storage[objectId];
            callback(null);
        },

        /**
         * Get storage stats
         */
        getStats: function () {
            var totalSize = 0;
            var objectCount = 0;

            Object.keys(storage).forEach(function (key) {
                totalSize += storage[key].length;
                objectCount++;
            });

            return {
                objectCount: objectCount,
                totalBytes: totalSize,
                shark: sharkId
            };
        }
    };
}

/**
 * Create a mock shark cluster
 * Coordinates streaming to multiple shark replicas
 */
function createMockSharkCluster(sharks, options) {
    options = options || {};

    var nodes = {};

    // Create shark nodes
    sharks.forEach(function (shark) {
        var sharkId = shark.manta_storage_id;
        nodes[sharkId] = createMockSharkNode(sharkId, options);
    });

    return {
        /**
         * Stream object to multiple shark replicas
         */
        streamToSharks: function (objectId, dataStream, sharkIds, callback) {
            var results = [];
            var errors = [];
            var completed = 0;

            // For simplicity, buffer the stream and replay to each shark
            var chunks = [];
            var hash = crypto.createHash('md5');

            dataStream.on('data', function (chunk) {
                chunks.push(chunk);
                hash.update(chunk);
            });

            dataStream.on('end', function () {
                var data = Buffer.concat(chunks);
                var md5 = hash.digest('base64');

                // Stream to each shark
                sharkIds.forEach(function (sharkId) {
                    var shark = nodes[sharkId];
                    if (!shark) {
                        errors.push(new Error('Shark not found: ' + sharkId));
                        completed++;
                        return;
                    }

                    // Create new stream for this shark
                    var sharkStream = new stream.PassThrough();
                    sharkStream.end(data);

                    shark.putObject(objectId, sharkStream,
                        function (err, result) {
                        if (err) {
                            errors.push(err);
                        } else {
                            results.push(result);
                        }

                        completed++;

                        // All sharks completed
                        if (completed === sharkIds.length) {
                            if (errors.length > 0 && results.length === 0) {
                                return (callback(errors[0]));
                            }

                            // Return first successful result
                            callback(null, {
                                id: objectId,
                                size: data.length,
                                md5: md5,
                                replicas: results.length,
                                sharks: sharkIds
                            });
                        }
                    });
                });
            });

            dataStream.on('error', function (err) {
                callback(err);
            });
        },

        /**
         * Retrieve object from first available shark
         */
        streamFromSharks: function (objectId, sharkIds, callback) {
            var attemptIndex = 0;

            function tryNextShark() {
                if (attemptIndex >= sharkIds.length) {
                    var err = new Error('Object not found on any shark');
                    err.name = 'ObjectNotFoundError';
                    return (callback(err));
                }

                var sharkId = sharkIds[attemptIndex++];
                var shark = nodes[sharkId];

                if (!shark) {
                    return (tryNextShark());
                }

                shark.getObject(objectId, function (err, dataStream, metadata) {
                    if (err) {
                        // Try next shark
                        return (tryNextShark());
                    }

                    callback(null, dataStream, metadata);
                });
            }

            tryNextShark();
        },

        /**
         * Get shark node by ID
         */
        getShark: function (sharkId) {
            return (nodes[sharkId]);
        },

        /**
         * Get all sharks
         */
        getAllSharks: function () {
            return (nodes);
        }
    };
}

/**
 * Create enhanced mock storinfo client with shark selection
 */
function createMockStorinfoClient(options) {
    options = options || {};

    var mockSharks = options.sharks || [
        {
            manta_storage_id: 'mock-shark-1',
            datacenter: 'us-west-1',
            zone: 'zone-1',
            availableMB: 100000,
            percentUtilized: 0.3,
            status: 'online'
        },
        {
            manta_storage_id: 'mock-shark-2',
            datacenter: 'us-west-1',
            zone: 'zone-2',
            availableMB: 80000,
            percentUtilized: 0.4,
            status: 'online'
        },
        {
            manta_storage_id: 'mock-shark-3',
            datacenter: 'us-east-1',
            zone: 'zone-1',
            availableMB: 90000,
            percentUtilized: 0.35,
            status: 'online'
        }
    ];

    // Create shark cluster
    var sharkCluster = createMockSharkCluster(mockSharks, options);

    return {
        choose: function (opts, callback) {
            if (options.simulateNoSharks) {
                var err = new Error('No sharks available');
                err.name = 'NoSharksAvailableError';
                return (callback(err));
            }

            var numCopies = opts.replicas || 2;
            var selected = mockSharks.slice(0, numCopies);

            callback(null, selected);
        },

        getSharkCluster: function () {
            return (sharkCluster);
        },

        getSharks: function () {
            return (mockSharks);
        }
    };
}

/**
 * Create enhanced mock metadata client with full CRUD support
 */
function createMockMetadataClientE2E(options) {
    options = options || {};

    // In-memory storage
    var buckets = {}; // bucketId -> bucket metadata
    var objects = {}; // bucketId:objectName -> object metadata

    return {
        /**
         * Create object metadata
         */
        createObject: function (owner, bucketId, objectName, objectId, size,
            md5, contentType, headers, sharks, props, vnode, opts, requestId,
            callback) {

            var key = bucketId + ':' + objectName;

            // Check conditional headers
            if (opts && opts['if-none-match'] === '*' && objects[key]) {
                var err = new Error('Object already exists');
                err.name = 'ObjectExistsError';
                err.statusCode = 412;
                return (callback(err));
            }

            if (opts && opts['if-match']) {
                var existing = objects[key];
                if (!existing || existing.id !== opts['if-match']) {
                    var err = new Error('Precondition failed');
                    err.name = 'PreconditionFailedError';
                    err.statusCode = 412;
                    return (callback(err));
                }
            }

            // Store metadata
            var now = new Date().toISOString();
            objects[key] = {
                id: objectId,
                owner: owner,
                bucket: bucketId,
                name: objectName,
                content_md5: md5,
                content_length: size,
                content_type: contentType || 'application/octet-stream',
                sharks: sharks,
                headers: headers || {},
                properties: props || {},
                created: now,
                modified: now,
                type: 'bucketobject'
            };

            callback(null, objects[key]);
        },

        /**
         * Get object metadata
         */
        getObject: function (owner, bucketId, objectName, vnode, opts,
            requestId, callback) {

            var key = bucketId + ':' + objectName;
            var obj = objects[key];

            if (!obj) {
                var err = new Error('Object not found');
                err.name = 'ObjectNotFoundError';
                err.statusCode = 404;
                return (callback(err));
            }

            // Handle conditional headers
            if (opts && opts['if-match'] && opts['if-match'] !== obj.id) {
                var err = new Error('Precondition failed');
                err.statusCode = 412;
                return (callback(err));
            }

            if (opts && opts['if-none-match'] &&
                opts['if-none-match'] === obj.id) {
                var err = new Error('Not modified');
                err.statusCode = 304;
                return (callback(err));
            }

            callback(null, obj);
        },

        /**
         * Update object metadata
         */
        updateObject: function (owner, bucketId, objectName, objectId,
            contentType, headers, props, vnode, opts, requestId, callback) {

            var key = bucketId + ':' + objectName;
            var obj = objects[key];

            if (!obj) {
                var err = new Error('Object not found');
                err.name = 'ObjectNotFoundError';
                return (callback(err));
            }

            // Update fields
            obj.modified = new Date().toISOString();
            if (contentType) obj.content_type = contentType;
            if (headers) obj.headers = headers;
            if (props) obj.properties = props;

            callback(null, obj);
        },

        /**
         * Delete object metadata
         */
        deleteObject: function (owner, bucketId, objectName, objectId, vnode,
            opts, requestId, callback) {

            var key = bucketId + ':' + objectName;

            if (!objects[key]) {
                var err = new Error('Object not found');
                err.name = 'ObjectNotFoundError';
                return (callback(err));
            }

            delete objects[key];
            callback(null);
        },

        /**
         * List objects (for cleanup/testing)
         */
        listObjects: function (bucketId) {
            var results = [];
            Object.keys(objects).forEach(function (key) {
                if (key.startsWith(bucketId + ':')) {
                    results.push(objects[key]);
                }
            });
            return (results);
        },

        /**
         * Create bucket
         */
        createBucket: function (bucketId, bucketName, owner, callback) {
            buckets[bucketId] = {
                id: bucketId,
                name: bucketName,
                owner: owner,
                created: new Date().toISOString()
            };
            callback(null, buckets[bucketId]);
        },

        /**
         * Get bucket
         */
        getBucket: function (bucketId, callback) {
            var bucket = buckets[bucketId];
            if (!bucket) {
                var err = new Error('Bucket not found');
                err.name = 'BucketNotFoundError';
                return (callback(err));
            }
            callback(null, bucket);
        }
    };
}

/**
 * Create mock multipart upload manager
 */
function createMockMultipartManager(metadataClient, sharkCluster, options) {
    options = options || {};

    var uploads = {}; // uploadId -> upload record
    var parts = {};   // uploadId:partNumber -> part metadata

    function generateUploadId() {
        var timestamp = Date.now();
        var random = Math.random().toString(36).substr(2, 9);
        return ('upload-' + timestamp + '-' + random);
    }

    return {
        /**
         * Initiate multipart upload
         */
        initiateUpload: function (bucketId, objectKey, metadata, callback) {
            var uploadId = generateUploadId();
            var sharks = metadata.sharks || [];

            uploads[uploadId] = {
                uploadId: uploadId,
                bucket: bucketId,
                objectKey: objectKey,
                owner: metadata.owner,
                initiated: new Date().toISOString(),
                durabilityLevel: metadata.durabilityLevel || 2,
                preAllocatedSharks: sharks,
                contentType: metadata.contentType || 'application/octet-stream'
            };

            callback(null, uploadId, uploads[uploadId]);
        },

        /**
         * Upload part
         */
        uploadPart: function (uploadId, partNumber, dataStream, callback) {
            var upload = uploads[uploadId];
            if (!upload) {
                var err = new Error('Upload not found');
                err.name = 'NoSuchUploadError';
                return (callback(err));
            }

            var partKey = uploadId + ':' + partNumber;
            var partObjectId = 'part-' + uploadId + '-' + partNumber;

            // Stream to sharks
            var sharkIds = upload.preAllocatedSharks.map(function (s) {
                return (s.manta_storage_id);
            });

            sharkCluster.streamToSharks(partObjectId, dataStream, sharkIds,
                function (err, result) {
if (err) {
                        return (callback(err));
                    }

                    parts[partKey] = {
                        partNumber: partNumber,
                        uploadId: uploadId,
                        etag: result.id,
                        size: result.size,
                        md5: result.md5
                    };

                    callback(null, {
                        etag: result.id,
                        partNumber: partNumber
                    });
                });
        },

        /**
         * Complete multipart upload
         */
        completeUpload: function (uploadId, partsFromXML, callback) {
            var upload = uploads[uploadId];
            if (!upload) {
                var err = new Error('Upload not found');
                err.name = 'NoSuchUploadError';
                return (callback(err));
            }

            // Validate all parts exist
            var allParts = [];
            var totalSize = 0;

            for (var i = 0; i < partsFromXML.length; i++) {
                var xmlPart = partsFromXML[i];
                var partKey = uploadId + ':' + xmlPart.partNumber;
                var part = parts[partKey];

                if (!part) {
                    var err = new Error('Invalid part: ' + xmlPart.partNumber);
                    err.name = 'InvalidPartError';
                    return (callback(err));
                }

                if (part.etag !== xmlPart.etag) {
                    var err = new Error('Part ETag mismatch');
                    err.name = 'InvalidPartError';
                    return (callback(err));
                }

                allParts.push(part);
                totalSize += part.size;
            }

            // Create final object ID
            var finalObjectId = 'object-' + uploadId;

            // Store final object metadata
            var sharkIds = upload.preAllocatedSharks.map(function (s) {
                return (s.manta_storage_id);
            });

            metadataClient.createObject(
                upload.owner,
                upload.bucket,
                upload.objectKey,
                finalObjectId,
                totalSize,
                null, // MD5 computed during assembly
                upload.contentType,
                {},
                sharkIds,
                {},
                null,
                {},
                'complete-mpu',
                function (err, metadata) {
if (err) {
                        return (callback(err));
                    }

                    // Cleanup
                    delete uploads[uploadId];
                    partsFromXML.forEach(function (p) {
                        delete parts[uploadId + ':' + p.partNumber];
                    });

                    callback(null, {
                        objectId: finalObjectId,
                        size: totalSize,
                        etag: finalObjectId
                    });
                });
        },

        /**
         * Abort multipart upload
         */
        abortUpload: function (uploadId, callback) {
            var upload = uploads[uploadId];
            if (!upload) {
                var err = new Error('Upload not found');
                err.name = 'NoSuchUploadError';
                return (callback(err));
            }

            // Cleanup all parts
            Object.keys(parts).forEach(function (key) {
                if (key.startsWith(uploadId + ':')) {
                    delete parts[key];
                }
            });

            delete uploads[uploadId];
            callback(null);
        },

        /**
         * Get upload record
         */
        getUpload: function (uploadId) {
            return (uploads[uploadId]);
        },

        /**
         * List parts
         */
        listParts: function (uploadId) {
            var uploadParts = [];
            Object.keys(parts).forEach(function (key) {
                if (key.startsWith(uploadId + ':')) {
                    uploadParts.push(parts[key]);
                }
            });
            return (uploadParts);
        }
    };
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
    createSpy: createSpy,
    // E2E Components
    createMockSharkNode: createMockSharkNode,
    createMockSharkCluster: createMockSharkCluster,
    createMockStorinfoClient: createMockStorinfoClient,
    createMockMetadataClientE2E: createMockMetadataClientE2E,
    createMockMultipartManager: createMockMultipartManager
};
