/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

var helper = require('./s3-test-helper.js');
var s3Compat = require('../lib/s3-compat');
// var restify = require('restify'); // Unused import

///--- Enhanced Mock Helpers

// Create mock MultiError for testing unwrapping
function createMockMultiError(errors) {
    var multiError = new Error('Multiple errors occurred');
    multiError.name = 'MultiError';
    multiError.errors = errors;
    multiError._errors = errors; // Also test alternative property
    return (multiError);
}

// Create mock S3 request with more options
function createEnhancedMockRequest(options) {
    options = options || {};
    return {
        method: options.method || 'GET',
        path: function () { return (options.path || '/'); },
        query: options.query || {},
        headers: options.headers || {},
        log: helper.createLogger('test'),
        getId: function () {
            return (options.requestId || 'test-req-' + Date.now());
        },
        s3Request: options.s3Request || null,
        isS3Request: options.isS3Request || false
    };
}

// Create mock response with more functionality
function createEnhancedMockResponse() {
    var headers = {};
    var response = {
        headers: headers,
        statusCode: 200,
        setHeader: function (key, value) {
            headers[key.toLowerCase()] = value;
        },
        getHeader: function (key) {
            return (headers[key.toLowerCase()]);
        },
        writeHead: function (statusCode, reasonPhrase) {
            this.statusCode = statusCode;
            this.reasonPhrase = reasonPhrase;
        },
        end: function (data) {
            this._data = data;
            this._ended = true;
        }
    };
    return (response);
}

///--- Enhanced S3 Compatibility Tests

helper.test('MultiError unwrapping in error conversion', function (t) {
    // Test the specific fix we implemented for MultiError handling
    var innerError = new Error('Part too small');
    innerError.restCode = 'EntityTooSmall';
    innerError.statusCode = 400;

    var multiError = createMockMultiError([innerError]);

    var s3Request = {
        bucket: 'test-bucket',
        object: 'test-object',
        uploadId: 'test-upload-123',
        partNumber: 1
    };

    var s3ErrorXML = s3Compat.convertErrorToS3(multiError, s3Request);

    t.ok(s3ErrorXML, 'should generate S3 error XML');
    t.ok(s3ErrorXML.indexOf('<?xml version="1.0"') === 0,
         'should start with XML declaration');
    t.ok(s3ErrorXML.indexOf('<Error>') > 0, 'should contain Error element');
    t.ok(s3ErrorXML.indexOf('<Code>EntityTooSmall</Code>') > 0,
         'should contain unwrapped error code');
    t.ok(s3ErrorXML.indexOf('<Message>Part too small</Message>') > 0,
         'should contain error message');
    t.ok(s3ErrorXML.indexOf('<BucketName>test-bucket</BucketName>') > 0,
         'should contain bucket name');

    t.end();
});

helper.test('S3 error conversion with various error types', function (t) {
    var testCases = [
        {
            name: 'NoSuchBucket error',
            error: {
                message: 'Bucket not found',
                restCode: 'NoSuchBucket',
                statusCode: 404
            },
            s3Request: { bucket: 'missing-bucket' },
            expectedCode: 'NoSuchBucket'
        },
        {
            name: 'NoSuchKey error',
            error: {
                message: 'Object not found',
                restCode: 'NoSuchKey',
                statusCode: 404
            },
            s3Request: { bucket: 'test-bucket', object: 'missing-object' },
            expectedCode: 'NoSuchKey'
        },
        {
            name: 'InvalidPartOrderError',
            error: {
                message: 'Part order invalid',
                restCode: 'InvalidPartOrderError',
                statusCode: 400
            },
            s3Request: {
                bucket: 'test-bucket',
                object: 'test-object',
                uploadId: 'test-123'
            },
            expectedCode: 'InvalidPartOrderError'
        },
        {
            name: 'EntityTooSmall error',
            error: {
                message: 'Part size too small',
                restCode: 'EntityTooSmall',
                statusCode: 400
            },
            s3Request: {
                bucket: 'test-bucket',
                object: 'test-object',
                partNumber: 1
            },
            expectedCode: 'EntityTooSmall'
        }
    ];

    testCases.forEach(function (testCase) {
        var s3ErrorXML = s3Compat.convertErrorToS3(testCase.error,
                                                   testCase.s3Request);

        t.ok(s3ErrorXML, testCase.name + ' should generate XML');
        t.ok(s3ErrorXML.indexOf('<Code>' + testCase.expectedCode +
                                '</Code>') > 0,
             testCase.name + ' should contain correct error code');
        t.ok(s3ErrorXML.indexOf('<Message>' + testCase.error.message +
                                '</Message>') > 0,
             testCase.name + ' should contain error message');
    });

    t.end();
});

helper.test('Empty response operations handling', function (t) {
    // Test operations that should return empty responses
    // (like AbortMultipartUpload)
    var emptyResponseOperations = [
        'AbortMultipartUpload',
        'DeleteObject',
        'DeleteBucket'
    ];

    emptyResponseOperations.forEach(function (operation) {
        // Test that these operations don't try to convert empty arrays to XML
        var emptyData = [];
        var s3Request = { operation: operation };

        // This should not throw an error about invalid XML
        try {
            var result = s3Compat.convertMantaToS3Response(emptyData,
                                                           operation,
                                                           s3Request);
            // For empty response operations, we expect either empty string
            // or simple XML
            t.ok(typeof (result) === 'string',
                 operation + ' should return string response');
        } catch (err) {
            t.fail(operation + ' should not throw error: ' + err.message);
        }
    });

    t.end();
});

helper.test('S3 header translation with edge cases', function (t) {
    var testHeaders = {
        // Standard S3 metadata headers
        'x-amz-meta-user-id': 'user123',
        'x-amz-meta-document-type': 'pdf',
        'x-amz-meta-version': '1.0',

        // Headers with special characters
        'x-amz-meta-file-name': 'my file.pdf',
        'x-amz-meta-description': 'A test file with special chars: !@#$%',

        // Mixed case headers
        'X-Amz-Meta-UPPER': 'UPPERCASE',
        'x-Amz-Meta-Mixed': 'MixedCase',

        // Non-metadata headers (should be preserved)
        'content-type': 'application/pdf',
        'content-length': '1024',
        'authorization': 'AWS test:signature',

        // AWS-specific headers
        'x-amz-date': '20250101T000000Z',
        'x-amz-content-sha256': 'abc123'
    };

    var req = createEnhancedMockRequest({
        headers: testHeaders,
        isS3Request: true
    });
    var res = createEnhancedMockResponse();
    var nextCalled = false;

    function next() { nextCalled = true; }

    s3Compat.s3HeaderTranslator(req, res, next);

    t.ok(nextCalled, 'should call next');

    // Check metadata header translation
    t.equal(req.headers['m-user-id'], 'user123',
            'should translate x-amz-meta-user-id');
    t.equal(req.headers['m-document-type'], 'pdf',
            'should translate x-amz-meta-document-type');
    t.equal(req.headers['m-version'], '1.0',
            'should translate x-amz-meta-version');
    t.equal(req.headers['m-file-name'], 'my file.pdf',
            'should preserve special characters');
    t.equal(req.headers['m-description'],
            'A test file with special chars: !@#$%',
            'should preserve special characters in description');

    // Check case normalization
    t.equal(req.headers['m-upper'], 'UPPERCASE',
            'should handle uppercase headers');
    t.equal(req.headers['m-mixed'], 'MixedCase',
            'should handle mixed case headers');

    // Check non-metadata headers are preserved
    t.equal(req.headers['content-type'], 'application/pdf',
            'should preserve content-type');
    t.equal(req.headers['content-length'], '1024',
            'should preserve content-length');
    t.equal(req.headers['authorization'], 'AWS test:signature',
            'should preserve authorization');
    t.equal(req.headers['x-amz-date'], '20250101T000000Z',
            'should preserve x-amz-date');
    t.equal(req.headers['x-amz-content-sha256'], 'abc123',
            'should preserve x-amz-content-sha256');

    // Check original metadata headers are removed
    t.notOk(req.headers['x-amz-meta-user-id'],
            'should remove original x-amz-meta-user-id');
    t.notOk(req.headers['x-amz-meta-document-type'],
            'should remove original x-amz-meta-document-type');
    t.notOk(req.headers['X-Amz-Meta-UPPER'],
            'should remove original X-Amz-Meta-UPPER');

    t.end();
});

helper.test('Complex S3 request parsing scenarios', function (t) {
    var testCases = [
        {
            name: 'Multipart upload initiation',
            method: 'POST',
            path: '/my-bucket/large-file.bin',
            query: { uploads: '' },
            expected: {
                isS3Request: true,
                operation: 'InitiateMultipartUpload',
                bucket: 'my-bucket',
                object: 'large-file.bin'
            }
        },
        {
            name: 'Upload part',
            method: 'PUT',
            path: '/my-bucket/large-file.bin',
            query: { uploadId: 'upload123', partNumber: '1' },
            expected: {
                isS3Request: true,
                operation: 'UploadPart',
                bucket: 'my-bucket',
                object: 'large-file.bin',
                uploadId: 'upload123',
                partNumber: '1'
            }
        },
        {
            name: 'Complete multipart upload',
            method: 'POST',
            path: '/my-bucket/large-file.bin',
            query: { uploadId: 'upload123' },
            expected: {
                isS3Request: true,
                operation: 'CompleteMultipartUpload',
                bucket: 'my-bucket',
                object: 'large-file.bin',
                uploadId: 'upload123'
            }
        },
        {
            name: 'List parts',
            method: 'GET',
            path: '/my-bucket/large-file.bin',
            query: { uploadId: 'upload123' },
            expected: {
                isS3Request: true,
                operation: 'ListParts',
                bucket: 'my-bucket',
                object: 'large-file.bin',
                uploadId: 'upload123'
            }
        },
        {
            name: 'Nested object path',
            method: 'PUT',
            path: '/my-bucket/folder/subfolder/deep/file.txt',
            query: {},
            expected: {
                isS3Request: true,
                operation: 'CreateBucketObject',
                bucket: 'my-bucket',
                object: 'folder/subfolder/deep/file.txt'
            }
        },
        {
            name: 'Object with query parameters',
            method: 'GET',
            path: '/my-bucket/file.txt',
            query: {
                'response-content-type': 'text/plain',
                'response-content-disposition': 'attachment'
            },
            expected: {
                isS3Request: true,
                operation: 'GetBucketObject',
                bucket: 'my-bucket',
                object: 'file.txt'
            }
        }
    ];

    testCases.forEach(function (testCase) {
        var req = createEnhancedMockRequest({
            method: testCase.method,
            path: testCase.path,
            query: testCase.query
        });

        var s3Request = s3Compat.parseS3Request(req);

        t.equal(s3Request.isS3Request, testCase.expected.isS3Request,
               testCase.name + ' - should detect S3 request correctly');
        t.equal(s3Request.operation, testCase.expected.operation,
               testCase.name + ' - should detect operation correctly');
        t.equal(s3Request.bucket, testCase.expected.bucket,
               testCase.name + ' - should extract bucket correctly');
        t.equal(s3Request.object, testCase.expected.object,
               testCase.name + ' - should extract object correctly');

        if (testCase.expected.uploadId) {
            t.equal(s3Request.uploadId, testCase.expected.uploadId,
                   testCase.name + ' - should extract uploadId correctly');
        }
        if (testCase.expected.partNumber) {
            t.equal(s3Request.partNumber, testCase.expected.partNumber,
                   testCase.name + ' - should extract partNumber correctly');
        }
    });

    t.end();
});

helper.test('S3 response XML generation edge cases', function (t) {
    // Test ListBuckets with empty bucket list
    var emptyBuckets = [];
    var listBucketsXML = s3Compat.convertMantaToS3Response(emptyBuckets,
                                                           'ListBuckets',
                                                           {});
    t.ok(listBucketsXML.indexOf('<Buckets></Buckets>') > 0,
         'should handle empty bucket list');

    // Test ListBucketObjects with empty object list
    var emptyObjects = [];
    var listObjectsXML = s3Compat.convertMantaToS3Response(emptyObjects,
                                                           'ListBucketObjects',
                                                           {
        bucket: 'empty-bucket'
    });
    t.ok(listObjectsXML.indexOf('<Name>empty-bucket</Name>') > 0,
         'should include bucket name');
    t.ok(listObjectsXML.indexOf('<Contents>') < 0,
         'should not include empty Contents elements');

    // Test InitiateMultipartUpload response
    var uploadData = { uploadId: 'test-upload-123' };
    var initiateXML = s3Compat.convertMantaToS3Response(uploadData,
                   'InitiateMultipartUpload', {
        bucket: 'test-bucket',
        object: 'test-object.bin'
    });
    t.ok(initiateXML.indexOf('<UploadId>test-upload-123</UploadId>') > 0,
         'should include upload ID');
    t.ok(initiateXML.indexOf('<Bucket>test-bucket</Bucket>') > 0,
         'should include bucket name');
    t.ok(initiateXML.indexOf('<Key>test-object.bin</Key>') > 0,
         'should include object key');

    // Test ListParts response
    var partsData = {
        parts: [
            {
                partNumber: 1,
                etag: 'etag1',
                size: 5242880,
                lastModified: '2025-01-01T00:00:00.000Z'
            },
            {
                partNumber: 2,
                etag: 'etag2',
                size: 5242880,
                lastModified: '2025-01-01T00:01:00.000Z'
            }
        ],
        uploadId: 'test-upload-456'
    };
    var listPartsXML = s3Compat.convertMantaToS3Response(partsData,
                                                         'ListParts',
                                                         {
        bucket: 'test-bucket',
        object: 'test-object.bin'
    });
    t.ok(listPartsXML.indexOf('<PartNumber>1</PartNumber>') > 0,
         'should include part 1');
    t.ok(listPartsXML.indexOf('<PartNumber>2</PartNumber>') > 0,
         'should include part 2');
    t.ok(listPartsXML.indexOf('<ETag>etag1</ETag>') > 0,
         'should include part 1 ETag');
    t.ok(listPartsXML.indexOf('<Size>5242880</Size>') > 0,
         'should include part sizes');

    t.end();
});

helper.test('Path conversion with special characters', function (t) {
    var testCases = [
        {
            name: 'URL encoded characters',
            s3Request: {
                bucket: 'my-bucket',
                object: 'file%20with%20spaces.txt'
            },
            user: 'testuser',
            expected:
                '/testuser/buckets/my-bucket/objects/file%20with%20spaces.txt'
        },
        {
            name: 'Unicode characters',
            s3Request: { bucket: 'my-bucket', object: 'файл.txt' },
            user: 'testuser',
            expected: '/testuser/buckets/my-bucket/objects/файл.txt'
        },
        {
            name: 'Special punctuation',
            s3Request: {
                bucket: 'my-bucket',
                object: 'file-name_v1.2.3.tar.gz'
            },
            user: 'testuser',
            expected:
                '/testuser/buckets/my-bucket/objects/file-name_v1.2.3.tar.gz'
        },
        {
            name: 'Path with slashes',
            s3Request: {
                bucket: 'my-bucket',
                object: 'folder/subfolder/file.txt'
            },
            user: 'testuser',
            expected:
                '/testuser/buckets/my-bucket/objects/folder/subfolder/file.txt'
        }
    ];

    testCases.forEach(function (testCase) {
        testCase.s3Request.isS3Request = true;
        testCase.s3Request.operation = 'GetBucketObject';

        var mantaPath = s3Compat.convertS3ToMantaPath(testCase.s3Request,
                                                      testCase.user);
        t.equal(mantaPath, testCase.expected,
                testCase.name + ' - should convert path correctly');
    });

    t.end();
});
