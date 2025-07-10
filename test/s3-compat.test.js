/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var helper = require('./helper.js');
var s3Compat = require('../lib/s3-compat');
var restify = require('restify');
var bunyan = require('bunyan');

// Mock request helper
function createMockRequest(method, path, query, headers) {
    return {
        method: method,
        path: function () { return path; },
        query: query || {},
        headers: headers || {},
        log: helper.createLogger('test')
    };
}

// Mock response helper
function createMockResponse() {
    var headers = {};
    var response = {
        headers: headers,
        setHeader: function (key, value) {
            headers[key] = value;
        },
        getHeader: function (key) {
            return (headers[key]);
        }
    };
    return (response);
}

///--- S3 Request Parsing Tests

helper.test('S3 request parsing - list buckets', function (t) {
    var req = createMockRequest('GET', '/');
    var s3Request = s3Compat.parseS3Request(req);

    t.equal(s3Request.isS3Request, true, 'should detect S3 request');
    t.equal(s3Request.operation,
    'ListBuckets', 'should detect list buckets operation');
    t.equal(s3Request.bucket, null, 'should have no bucket');
    t.equal(s3Request.object, null, 'should have no object');
    t.end();
});

helper.test('S3 request parsing - create bucket', function (t) {
    var req = createMockRequest('PUT', '/my-bucket');
    var s3Request = s3Compat.parseS3Request(req);

    t.equal(s3Request.isS3Request, true, 'should detect S3 request');
    t.equal(s3Request.operation,
    'CreateBucket', 'should detect create bucket operation');
    t.equal(s3Request.bucket, 'my-bucket', 'should extract bucket name');
    t.equal(s3Request.object, null, 'should have no object');
    t.end();
});

helper.test('S3 request parsing - list bucket objects', function (t) {
    var req = createMockRequest('GET', '/my-bucket');
    var s3Request = s3Compat.parseS3Request(req);

    t.equal(s3Request.isS3Request, true, 'should detect S3 request');
    t.equal(s3Request.operation,
    'ListBucketObjects', 'should detect list objects operation');
    t.equal(s3Request.bucket, 'my-bucket', 'should extract bucket name');
    t.equal(s3Request.object, null, 'should have no object');
    t.end();
});

helper.test('S3 request parsing - create object', function (t) {
    var req = createMockRequest('PUT', '/my-bucket/my-object.txt');
    var s3Request = s3Compat.parseS3Request(req);

    t.equal(s3Request.isS3Request, true, 'should detect S3 request');
    t.equal(s3Request.operation, 'CreateBucketObject',
    'should detect create object operation');
    t.equal(s3Request.bucket, 'my-bucket', 'should extract bucket name');
    t.equal(s3Request.object, 'my-object.txt', 'should extract object name');
    t.end();
});

helper.test('S3 request parsing - nested object path', function (t) {
    var req = createMockRequest('GET', '/my-bucket/folder/subfolder/file.txt');
    var s3Request = s3Compat.parseS3Request(req);

    t.equal(s3Request.isS3Request, true, 'should detect S3 request');
    t.equal(s3Request.operation, 'GetBucketObject',
    'should detect get object operation');
    t.equal(s3Request.bucket, 'my-bucket', 'should extract bucket name');
    t.equal(s3Request.object, 'folder/subfolder/file.txt',
    'should preserve nested path');
    t.end();
});

helper.test('S3 request parsing - Manta path (should not be detected)',
function (t) {
    var req = createMockRequest('GET', '/admin/buckets/my-bucket');
    var s3Request = s3Compat.parseS3Request(req);

    t.equal(s3Request.isS3Request, false, 'should not detect Manta path as S3');
    t.end();
});

///--- Path Conversion Tests

helper.test('S3 to Manta path conversion - list buckets', function (t) {
    var s3Request = {
        isS3Request: true,
        operation: 'ListBuckets'
    };
    var mantaPath = s3Compat.convertS3ToMantaPath(s3Request, 'testuser');

    t.equal(mantaPath, '/testuser/buckets',
    'should convert to Manta buckets path');
    t.end();
});

helper.test('S3 to Manta path conversion - create bucket', function (t) {
    var s3Request = {
        isS3Request: true,
        operation: 'CreateBucket',
        bucket: 'my-bucket'
    };
    var mantaPath = s3Compat.convertS3ToMantaPath(s3Request, 'testuser');

    t.equal(mantaPath, '/testuser/buckets/my-bucket',
    'should convert to Manta bucket path');
    t.end();
});

helper.test('S3 to Manta path conversion - list objects', function (t) {
    var s3Request = {
        isS3Request: true,
        operation: 'ListBucketObjects',
        bucket: 'my-bucket'
    };
    var mantaPath = s3Compat.convertS3ToMantaPath(s3Request, 'testuser');

    t.equal(mantaPath, '/testuser/buckets/my-bucket/objects',
    'should convert to Manta objects path');
    t.end();
});

helper.test('S3 to Manta path conversion - create object', function (t) {
    var s3Request = {
        isS3Request: true,
        operation: 'CreateBucketObject',
        bucket: 'my-bucket',
        object: 'my-object.txt'
    };
    var mantaPath = s3Compat.convertS3ToMantaPath(s3Request, 'testuser');

    t.equal(mantaPath, '/testuser/buckets/my-bucket/objects/my-object.txt',
    'should convert to Manta object path');
    t.end();
});

///--- Response Conversion Tests

helper.test('Bucket list response conversion', function (t) {
    var mantaResponse = [
        { name: 'bucket1', created: '2025-01-01T00:00:00.000Z' },
        { name: 'bucket2', created: '2025-01-02T00:00:00.000Z' }
    ];

    var s3Response = s3Compat.convertMantaToS3Response(mantaResponse,
    'ListBuckets', {});

    t.ok(s3Response.indexOf('<?xml version="1.0"') === 0,
    'should start with XML declaration');
    t.ok(s3Response.indexOf('<ListAllMyBucketsResult') > 0,
    'should contain ListAllMyBucketsResult');
    t.ok(s3Response.indexOf('<Name>bucket1</Name>') > 0,
    'should contain bucket1');
    t.ok(s3Response.indexOf('<Name>bucket2</Name>') > 0,
    'should contain bucket2');
    t.end();
});

helper.test('Object list response conversion', function (t) {
    var mantaResponse = [
        { name: 'object1.txt', mtime: '2025-01-01T00:00:00.000Z',
        etag: 'abc123', size: 1024 },
        { name: 'object2.txt', mtime: '2025-01-02T00:00:00.000Z',
        etag: 'def456', size: 2048 }
    ];

    var s3Response = s3Compat.convertMantaToS3Response(mantaResponse,
    'ListBucketObjects', { bucket: 'test-bucket' });

    t.ok(s3Response.indexOf('<?xml version="1.0"') === 0,
    'should start with XML declaration');
    t.ok(s3Response.indexOf('<ListBucketResult') > 0,
    'should contain ListBucketResult');
    t.ok(s3Response.indexOf('<Name>test-bucket</Name>') > 0,
    'should contain bucket name');
    t.ok(s3Response.indexOf('<Key>object1.txt</Key>') > 0,
    'should contain object1');
    t.ok(s3Response.indexOf('<Key>object2.txt</Key>') > 0,
    'should contain object2');
    t.ok(s3Response.indexOf('<Size>1024</Size>') > 0,
    'should contain object1 size');
    t.ok(s3Response.indexOf('<Size>2048</Size>') > 0,
    'should contain object2 size');
    t.end();
});

///--- Error Conversion Tests

helper.test('Error response conversion', function (t) {
    var error = new Error('Bucket not found');
    error.restCode = 'NoSuchBucket';

    var s3Request = {
        bucket: 'missing-bucket'
    };

    var s3ErrorResponse = s3Compat.convertErrorToS3(error, s3Request);

    t.ok(s3ErrorResponse.indexOf('<?xml version="1.0"') === 0,
    'should start with XML declaration');
    t.ok(s3ErrorResponse.indexOf('<Error>') > 0,
    'should contain Error element');
    t.ok(s3ErrorResponse.indexOf('<Code>NoSuchBucket</Code>') > 0,
    'should contain error code');
    t.ok(s3ErrorResponse.indexOf('<BucketName>missing-bucket</BucketName>') > 0,
    'should contain bucket name');
    t.ok(s3ErrorResponse.indexOf('<RequestId>') > 0,
    'should contain request ID');
    t.end();
});

///--- Middleware Tests

helper.test('S3 request detector middleware', function (t) {
    var req = createMockRequest('GET', '/my-bucket');
    var res = createMockResponse();
    var nextCalled = false;

    function next() {
        nextCalled = true;
    }

    s3Compat.s3RequestDetector(req, res, next);

    t.ok(nextCalled, 'should call next');
    t.ok(req.s3Request, 'should add s3Request to req');
    t.equal(req.s3Request.isS3Request, true, 'should detect S3 request');
    t.equal(req.isS3Request, true, 'should mark request as S3');
    t.ok(res.s3Request, 'should add s3Request to res');
    t.end();
});

helper.test('S3 header translator middleware', function (t) {
    var req = createMockRequest('PUT', '/my-bucket/my-object', {}, {
        'x-amz-meta-custom': 'value1',
        'x-amz-meta-another': 'value2',
        'content-type': 'text/plain'
    });
    req.isS3Request = true;

    var res = createMockResponse();
    var nextCalled = false;

    function next() {
        nextCalled = true;
    }

    s3Compat.s3HeaderTranslator(req, res, next);

    t.ok(nextCalled, 'should call next');
    t.equal(req.headers['m-custom'], 'value1',
    'should convert x-amz-meta-custom to m-custom');
    t.equal(req.headers['m-another'], 'value2',
    'should convert x-amz-meta-another to m-another');
    t.equal(req.headers['content-type'], 'text/plain',
    'should preserve non-metadata headers');
    t.notOk(req.headers['x-amz-meta-custom'],
    'should remove original S3 header');
    t.notOk(req.headers['x-amz-meta-another'],
    'should remove original S3 header');
    t.end();
});

helper.test('S3 header translator - non-S3 request passthrough', function (t) {
    var req = createMockRequest('GET', '/admin/buckets', {}, {
        'x-amz-meta-custom': 'value1'
    });
    req.isS3Request = false;

    var res = createMockResponse();
    var nextCalled = false;

    function next() {
        nextCalled = true;
    }

    s3Compat.s3HeaderTranslator(req, res, next);

    t.ok(nextCalled, 'should call next');
    t.equal(req.headers['x-amz-meta-custom'], 'value1',
    'should preserve headers for non-S3 requests');
    t.notOk(req.headers['m-custom'],
    'should not convert headers for non-S3 requests');
    t.end();
});
