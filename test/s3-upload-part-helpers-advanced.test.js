/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/**
 * Advanced unit tests for s3UploadPartHandler helper functions
 * Uses mock infrastructure to test complex functions
 */

var helper = require('./s3-test-helper.js');
var mocks = require('./mock-infrastructure.js');

// Test: configureBasicPartRequest - should set up part request correctly
helper.test('configureBasicPartRequest sets up part request', function (t) {
    function configureBasicPartRequest(partReqArg, reqArg, bucketName, partKey,
        partId) {
        partReqArg.params = {
            bucket_name: bucketName,
            object_name: partKey
        };
        partReqArg.objectId = partId;

        // Copy headers manually for Node.js v0.10.48 compatibility
        partReqArg.headers = {};
        var sourceHeaders = reqArg.headers || {};
        Object.keys(sourceHeaders).forEach(function (k) {
            partReqArg.headers[k] = sourceHeaders[k];
        });
        partReqArg.header = function (name, defaultValue) {
            return (partReqArg.headers[name.toLowerCase()] || defaultValue);
        };

        partReqArg.isS3Request = true;
        partReqArg.method = 'PUT';

        return (partReqArg);
    }

    var req = mocks.createMockRequest({
        headers: {
            'content-type': 'application/octet-stream',
            'content-length': '1024'
        }
    });

    var partReq = Object.create(req);

    configureBasicPartRequest(partReq, req, 'test-bucket',
        '.mpu-parts/upload-123/1', 'part-id-123');

    t.equal(partReq.params.bucket_name, 'test-bucket',
        'should set bucket_name');
    t.equal(partReq.params.object_name, '.mpu-parts/upload-123/1',
        'should set object_name');
    t.equal(partReq.objectId, 'part-id-123', 'should set objectId');
    t.ok(partReq.isS3Request, 'should mark as S3 request');
    t.equal(partReq.method, 'PUT', 'should set method to PUT');
    t.equal(typeof (partReq.header), 'function',
        'should provide header function');
    t.equal(partReq.headers['content-type'], 'application/octet-stream',
        'should copy headers');
    t.end();
});

// Test: configureBasicPartRequest - header function should work
helper.test('configureBasicPartRequest header function works', function (t) {
    function configureBasicPartRequest(partReqArg, reqArg, bucketName, partKey,
        partId) {
        partReqArg.params = {
            bucket_name: bucketName,
            object_name: partKey
        };
        partReqArg.objectId = partId;

        // Copy headers manually for Node.js v0.10.48 compatibility
        partReqArg.headers = {};
        var sourceHeaders = reqArg.headers || {};
        Object.keys(sourceHeaders).forEach(function (k) {
            partReqArg.headers[k] = sourceHeaders[k];
        });
        partReqArg.header = function (name, defaultValue) {
            return (partReqArg.headers[name.toLowerCase()] || defaultValue);
        };

        partReqArg.isS3Request = true;
        partReqArg.method = 'PUT';

        return (partReqArg);
    }

    var req = mocks.createMockRequest({
        headers: {'content-length': '2048'}
    });

    var partReq = Object.create(req);
    configureBasicPartRequest(partReq, req, 'bucket', 'key', 'id');

    t.equal(partReq.header('content-length'), '2048',
        'should return header value');
    t.equal(partReq.header('missing-header', 'default'), 'default',
        'should return default for missing header');
    t.end();
});

// Test: configurePreAllocatedSharks - should configure sharks from
// upload record
helper.test('configurePreAllocatedSharks sets sharks from record',
    function (t) {
    function configurePreAllocatedSharks(partReqArg, reqArg, uploadRecordArg, partNumber,
        uploadId) {
        if (uploadRecordArg.preAllocatedSharks &&
            Array.isArray(uploadRecordArg.preAllocatedSharks) &&
            uploadRecordArg.preAllocatedSharks.length > 0) {

            reqArg.log.debug({
                uploadId: uploadId,
                partNumber: partNumber,
                sharkCount: uploadRecordArg.preAllocatedSharks.length,
                sharks: uploadRecordArg.preAllocatedSharks.map(function (s) {
                    return (s.manta_storage_id);
                })
            }, 'Using pre-allocated sharks from upload record');

            partReqArg.preAllocatedSharks = uploadRecordArg.preAllocatedSharks;
        } else {
            reqArg.log.error({
                uploadId: uploadId,
                partNumber: partNumber
            }, 'No pre-allocated sharks found in upload record');
        }
    }

    var req = mocks.createMockRequest();
    var partReq = {};
    var uploadRecord = mocks.createMockUploadRecord({
        preAllocatedSharks: [
            {manta_storage_id: 'shark-1'},
            {manta_storage_id: 'shark-2'},
            {manta_storage_id: 'shark-3'}
        ]
    });

    configurePreAllocatedSharks(partReq, req, uploadRecord, 1, 'upload-123');

    t.ok(partReq.preAllocatedSharks, 'should set preAllocatedSharks');
    t.equal(partReq.preAllocatedSharks.length, 3, 'should set all 3 sharks');
    t.equal(partReq.preAllocatedSharks[0].manta_storage_id, 'shark-1',
        'should preserve shark data');
    t.end();
});

// Test: configurePreAllocatedSharks - should log error for missing sharks
helper.test('configurePreAllocatedSharks logs error for missing sharks',
    function (t) {
    function configurePreAllocatedSharks(partReqArg, reqArg, uploadRecordArg, partNumber,
        uploadId) {
        if (uploadRecordArg.preAllocatedSharks &&
            Array.isArray(uploadRecordArg.preAllocatedSharks) &&
            uploadRecordArg.preAllocatedSharks.length > 0) {

            reqArg.log.debug({
                uploadId: uploadId,
                partNumber: partNumber,
                sharkCount: uploadRecordArg.preAllocatedSharks.length
            }, 'Using pre-allocated sharks from upload record');

            partReqArg.preAllocatedSharks = uploadRecordArg.preAllocatedSharks;
        } else {
            reqArg.log.error({
                uploadId: uploadId,
                partNumber: partNumber
            }, 'No pre-allocated sharks found in upload record');
        }
    }

    var req = mocks.createMockRequest();
    var partReq = {};
    var uploadRecord = {uploadId: 'upload-123'};

    configurePreAllocatedSharks(partReq, req, uploadRecord, 1, 'upload-123');

    var logs = req.log.getLogs();
    t.equal(logs.error.length, 1, 'should log error');
    t.ok(!partReq.preAllocatedSharks, 'should not set sharks');
    t.end();
});

// Test: createETagCapturingResponse - should capture ETag from header()
helper.test('createETagCapturingResponse captures ETag from header',
    function (t) {
    function createETagCapturingResponse(resArg, _req, _partNumber, _uploadId) {
        var partETag = null;
        var customRes = Object.create(resArg);

        customRes.send = function (statusCode, _body) {
            req.log.debug({
                statusCode: statusCode,
                capturedETag: partETag
            }, 'Captured part upload result');
        };

        customRes.header = function (name, value) {
            if (name.toLowerCase() === 'etag') {
                partETag = value;
                req.log.debug({
                    etag: value,
                    headerName: name
                }, 'Captured ETag from part upload (header)');
            }
            return (resArg.header(name, value));
        };

        customRes.setHeader = function (name, value) {
            if (name.toLowerCase() === 'etag') {
                partETag = value;
                req.log.debug({
                    etag: value,
                    headerName: name
                }, 'Captured ETag from part upload (setHeader)');
            }
            return (resArg.setHeader(name, value));
        };

        return {
            response: customRes,
            getETag: function () {
                return (partETag);
            }
        };
    }

    var req = mocks.createMockRequest();
    var res = mocks.createMockResponse();

    var etagCapture = createETagCapturingResponse(res, req, 1, 'upload-123');

    etagCapture.response.header('ETag', 'test-etag-456');

    t.equal(etagCapture.getETag(), 'test-etag-456',
        'should capture ETag from header()');
    t.end();
});

// Test: createETagCapturingResponse - should capture ETag from setHeader()
helper.test('createETagCapturingResponse captures ETag from setHeader',
    function (t) {
    function createETagCapturingResponse(resArg, _req, _partNumber, _uploadId) {
        var partETag = null;
        var customRes = Object.create(resArg);

        customRes.send = function (statusCode, _body) {
            req.log.debug({
                statusCode: statusCode,
                capturedETag: partETag
            }, 'Captured part upload result');
        };

        customRes.header = function (name, value) {
            if (name.toLowerCase() === 'etag') {
                partETag = value;
            }
            return (resArg.header(name, value));
        };

        customRes.setHeader = function (name, value) {
            if (name.toLowerCase() === 'etag') {
                partETag = value;
            }
            return (resArg.setHeader(name, value));
        };

        return {
            response: customRes,
            getETag: function () {
                return (partETag);
            }
        };
    }

    var req = mocks.createMockRequest();
    var res = mocks.createMockResponse();

    var etagCapture = createETagCapturingResponse(res, req, 1, 'upload-123');

    etagCapture.response.setHeader('etag', 'test-etag-789');

    t.equal(etagCapture.getETag(), 'test-etag-789',
        'should capture ETag from setHeader()');
    t.end();
});

// Test: createETagCapturingResponse - should handle case-insensitive ETag
helper.test('createETagCapturingResponse handles case-insensitive ETag',
    function (t) {
    function createETagCapturingResponse(resArg, _req, _partNumber, _uploadId) {
        var partETag = null;
        var customRes = Object.create(resArg);

        customRes.send = function (_statusCode, _body) {
            // Don't actually send
        };

        customRes.header = function (name, value) {
            if (name.toLowerCase() === 'etag') {
                partETag = value;
            }
            return (resArg.header(name, value));
        };

        customRes.setHeader = function (name, value) {
            if (name.toLowerCase() === 'etag') {
                partETag = value;
            }
            return (resArg.setHeader(name, value));
        };

        return {
            response: customRes,
            getETag: function () {
                return (partETag);
            }
        };
    }

    var req = mocks.createMockRequest();
    var res = mocks.createMockResponse();

    var etagCapture = createETagCapturingResponse(res, req, 1, 'upload-123');

    etagCapture.response.header('ETAG', 'uppercase-etag');
    t.equal(etagCapture.getETag(), 'uppercase-etag',
        'should capture uppercase ETAG');

    etagCapture.response.setHeader('ETag', 'mixedcase-etag');
    t.equal(etagCapture.getETag(), 'mixedcase-etag',
        'should capture mixed case ETag');

    t.end();
});

// Test: createETagCapturingResponse - should return null for missing ETag
helper.test('createETagCapturingResponse returns null without ETag',
    function (t) {
    function createETagCapturingResponse(resArg, _req, _partNumber, _uploadId) {
        var partETag = null;
        var customRes = Object.create(resArg);

        customRes.send = function (_statusCode, _body) {};
        customRes.header = function (name, value) {
            if (name.toLowerCase() === 'etag') {
                partETag = value;
            }
            return (resArg.header(name, value));
        };
        customRes.setHeader = function (name, value) {
            if (name.toLowerCase() === 'etag') {
                partETag = value;
            }
            return (resArg.setHeader(name, value));
        };

        return {
            response: customRes,
            getETag: function () {
                return (partETag);
            }
        };
    }

    var req = mocks.createMockRequest();
    var res = mocks.createMockResponse();

    var etagCapture = createETagCapturingResponse(res, req, 1, 'upload-123');

    etagCapture.response.header('Content-Type', 'text/plain');

    t.equal(etagCapture.getETag(), null,
        'should return null when no ETag set');
    t.end();
});
