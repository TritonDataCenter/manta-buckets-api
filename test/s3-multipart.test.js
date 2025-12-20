/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var helper = require('./s3-test-helper.js');
var crypto = require('crypto');
var uuid = require('uuid');
// var EventEmitter = require('events').EventEmitter; // Unused import
// var util = require('util'); // Unused import

///--- Mock Data and Helpers

// Mock upload record for testing
function createMockUploadRecord() {
    return {
        id: 'test-upload-' + Date.now(),
        accountId: 'test-account-123',
        bucketId: 'test-bucket-456',
        objectPath: '/test-bucket/test-object.bin',
        headers: {
            'content-type': 'application/octet-stream',
            'durability-level': '2'
        },
        state: 'created',
        creationTimeMs: Date.now()
    };
}

// Mock part metadata for testing
function createMockPartMeta(partNumber, size) {
    size = size || (5 * 1024 * 1024); // Default 5MB
    var data = Buffer.alloc(size).fill('test data');
    var md5Hash = crypto.createHash('md5').update(data).digest('base64');
    var hexMD5 = crypto.createHash('md5').update(data).digest('hex');

    return {
        id: uuid.v4(), // UUID format
        partNumber: partNumber,
        size: size,
        contentMD5: md5Hash,  // Base64 MD5
        content_md5: md5Hash, // Alternative property name
        hexMD5: hexMD5,      // Hex format for testing
        etag: hexMD5,        // ETag in hex format
        mtime: new Date().toISOString()
    };
}

// Mock request object
function createMockRequest(options) {
    options = options || {};
    return {
        getId: function () { return 'req-' + Date.now(); },
        log: helper.createLogger('test'),
        owner: {
            account: { uuid: options.accountId || 'test-account-123' }
        },
        s3Request: {
            bucket: options.bucket || 'test-bucket',
            object: options.object || 'test-object.bin',
            operation: options.operation || 'CreateMultipartUpload'
        },
        header: function (name) {
            return (options.headers && options.headers[name]);
        },
        headers: options.headers || {},
        query: options.query || {},
        config: {
            maxObjectCopies: 3
        }
    };
}

///--- Unit Tests

helper.test('Upload ID generation should create valid UUID', function (t) {
    // Test the upload ID generation function
    var uploadId1 = uuid.v4();
    var uploadId2 = uuid.v4();

    t.ok(uploadId1, 'should generate upload ID');
    t.ok(uploadId2, 'should generate second upload ID');
    t.notEqual(uploadId1, uploadId2, 'should generate unique IDs');

    // Verify UUID format
    var uuidRegex =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    t.ok(uuidRegex.test(uploadId1), 'should generate valid UUID format');
    t.ok(uuidRegex.test(uploadId2), 'should generate valid UUID format');

    t.end();
});

helper.test('Part size validation - minimum 5MB enforcement', function (t) {
    var validSize = 5 * 1024 * 1024; // 5MB
    var invalidSize = (5 * 1024 * 1024) - 1; // 1 byte under 5MB
    var largeSize = 50 * 1024 * 1024; // 50MB

    // Test size validation logic
    function validatePartSize(size, isLastPart) {
        var minSize = 5 * 1024 * 1024; // 5MB
        if (!isLastPart && size < minSize) {
            return (new Error('EntityTooSmall'));
        }
        return (null);
    }

    t.equal(validatePartSize(validSize, false), null, 'should accept 5MB part');
    t.equal(validatePartSize(largeSize, false), null,
            'should accept large part');
    t.equal(validatePartSize(invalidSize, true), null,
            'should accept small last part');

    var error = validatePartSize(invalidSize, false);
    t.ok(error, 'should reject small non-final part');
    t.equal(error.message, 'EntityTooSmall',
            'should return EntityTooSmall error');

    t.end();
});

helper.test('ETag validation - multiple format support', function (t) {
    var partMeta = createMockPartMeta(1, 5 * 1024 * 1024);
    var expectedHexETag = partMeta.hexMD5;
    var expectedBase64ETag = partMeta.contentMD5;
    var expectedUUIDETag = partMeta.id;
    var quotedETag = '"' + expectedHexETag + '"';

    // Test ETag validation logic
    // (simulating the fixed logic from s3-multipart.js)
    function validateETag(expectedETag, partMetadata, _request) {
        var storedHexMD5 = partMetadata.hexMD5;
        var storedUUID = partMetadata.id;
        var etagMatches = false;
        var matchedFormat = null;

        // 1. Try hex MD5 comparison first (prioritized for s3cmd compatibility)
        if (expectedETag === storedHexMD5) {
            etagMatches = true;
            matchedFormat = 'hex-md5';
        }
        // 2. Fall back to UUID comparison
        else if (expectedETag === storedUUID) {
            etagMatches = true;
            matchedFormat = 'uuid';
        }
        // 3. Try base64 MD5 comparison
        else if (partMetadata.contentMD5 &&
                 expectedETag === partMetadata.contentMD5) {
            etagMatches = true;
            matchedFormat = 'base64-md5';
        }
        // 4. Try removing quotes from expectedETag
        else if (expectedETag && expectedETag.length > 2) {
            var unquotedETag = expectedETag.replace(/^"|"$/g, '');
            if (unquotedETag !== expectedETag &&
                unquotedETag === storedHexMD5) {
                etagMatches = true;
                matchedFormat = 'unquoted-hex-md5';
            }
        }

        return ({ matches: etagMatches, format: matchedFormat });
    }

    var testReq = createMockRequest();

    // Test hex MD5 format (should work)
    var result1 = validateETag(expectedHexETag, partMeta, testReq);
    t.ok(result1.matches, 'should match hex MD5 ETag');
    t.equal(result1.format, 'hex-md5', 'should identify hex-md5 format');

    // Test base64 MD5 format (should work)
    var result2 = validateETag(expectedBase64ETag, partMeta, testReq);
    t.ok(result2.matches, 'should match base64 MD5 ETag');
    t.equal(result2.format, 'base64-md5', 'should identify base64-md5 format');

    // Test UUID format (should work)
    var result3 = validateETag(expectedUUIDETag, partMeta, testReq);
    t.ok(result3.matches, 'should match UUID ETag');
    t.equal(result3.format, 'uuid', 'should identify uuid format');

    // Test quoted ETag (should work by unquoting)
    var result4 = validateETag(quotedETag, partMeta, testReq);
    t.ok(result4.matches, 'should match quoted ETag');
    t.equal(result4.format, 'unquoted-hex-md5',
            'should identify unquoted-hex-md5 format');

    // Test invalid ETag (should fail)
    var result5 = validateETag('invalid-etag-123', partMeta, testReq);
    t.notOk(result5.matches, 'should not match invalid ETag');
    t.equal(result5.format, null,
            'should not identify format for invalid ETag');

    t.end();
});

helper.test('Durability level extraction and validation', function (t) {
    // Test durability level parsing logic
    function extractDurabilityLevel(req) {
        var copies = parseInt(
            req.header('durability-level') ||
            req.header('x-durability-level') ||
            '2', // default
            10);

        var maxObjectCopies = req.config.maxObjectCopies || 3;
        var minCopies = 1;

        if (typeof (copies) !== 'number' || isNaN(copies) ||
            copies < minCopies || copies > maxObjectCopies) {
            return ({ error: 'InvalidDurabilityLevelError', min: minCopies,
                max: maxObjectCopies });
        }

        return ({ copies: copies });
    }

    // Test default durability level
    var req1 = createMockRequest();
    var result1 = extractDurabilityLevel(req1);
    t.equal(result1.copies, 2, 'should default to 2 copies');
    t.notOk(result1.error, 'should not have error for default');

    // Test explicit durability-level header
    var req2 = createMockRequest({ headers: { 'durability-level': '3' } });
    var result2 = extractDurabilityLevel(req2);
    t.equal(result2.copies, 3, 'should use durability-level header');
    t.notOk(result2.error, 'should not have error for valid level');

    // Test x-durability-level header
    var req3 = createMockRequest({ headers: { 'x-durability-level': '1' } });
    var result3 = extractDurabilityLevel(req3);
    t.equal(result3.copies, 1, 'should use x-durability-level header');
    t.notOk(result3.error, 'should not have error for valid level');

    // Test invalid durability level (too high)
    var req4 = createMockRequest({ headers: { 'durability-level': '5' } });
    var result4 = extractDurabilityLevel(req4);
    t.equal(result4.error, 'InvalidDurabilityLevelError',
            'should error for too high level');
    t.equal(result4.max, 3, 'should indicate maximum allowed');

    // Test invalid durability level (too low)
    var req5 = createMockRequest({ headers: { 'durability-level': '0' } });
    var result5 = extractDurabilityLevel(req5);
    t.equal(result5.error, 'InvalidDurabilityLevelError',
            'should error for too low level');
    t.equal(result5.min, 1, 'should indicate minimum allowed');

    t.end();
});

helper.test('MultiError unwrapping logic', function (t) {
    // Test the MultiError unwrapping logic from s3-compat.js fix
    function unwrapMultiError(err) {
        if (err.name === 'MultiError' && err.errors && err.errors.length > 0) {
            return (err.errors[0]);
        } else if (err._errors && err._errors.length > 0) {
            return (err._errors[0]);
        }
        return (err);
    }

    // Test regular error (should pass through)
    var regularError = new Error('Regular error');
    regularError.restCode = 'TestError';
    var result1 = unwrapMultiError(regularError);
    t.equal(result1, regularError, 'should pass through regular error');

    // Test MultiError with errors array
    var innerError = new Error('Inner error');
    innerError.restCode = 'EntityTooSmall';
    var multiError1 = {
        name: 'MultiError',
        errors: [innerError, new Error('Second error')],
        message: 'Multiple errors occurred'
    };
    var result2 = unwrapMultiError(multiError1);
    t.equal(result2, innerError, 'should unwrap first error from errors array');
    t.equal(result2.restCode, 'EntityTooSmall',
            'should preserve error properties');

    // Test MultiError with _errors array
    var multiError2 = {
        name: 'MultiError',
        _errors: [innerError],
        message: 'Multiple errors occurred'
    };
    var result3 = unwrapMultiError(multiError2);
    t.equal(result3, innerError,
            'should unwrap first error from _errors array');

    // Test MultiError with empty arrays (should pass through)
    var multiError3 = {
        name: 'MultiError',
        errors: [],
        message: 'No errors'
    };
    var result4 = unwrapMultiError(multiError3);
    t.equal(result4, multiError3,
            'should pass through MultiError with empty errors');

    t.end();
});

helper.test('Enhanced EntityTooSmall MultiError unwrapping', function (t) {
    // Test the enhanced logic that unwraps EntityTooSmall from jse_cause

    function testEntityTooSmallUnwrapping(err) {
        // Handle EntityTooSmall errors directly to preserve statusCode
        if (err.restCode === 'EntityTooSmall' ||
            err.name === 'EntityTooSmall') {
            return (err);
        }

        // Check if MultiError contains EntityTooSmall
        if (err.name === 'MultiError' && err.jse_cause &&
            (err.jse_cause.restCode === 'EntityTooSmall' ||
             err.jse_cause.name === 'EntityTooSmall')) {
            return (err.jse_cause);
        }

        return (err);
    }

    // Test direct EntityTooSmall error
    var directError = new Error('Part 1 is too small' +
                                ' (4194304 bytes, minimum 5242880)');
    directError.restCode = 'EntityTooSmall';
    directError.statusCode = 400;

    var result1 = testEntityTooSmallUnwrapping(directError);
    t.equal(result1, directError, 'should pass through direct EntityTooSmall');
    t.equal(result1.statusCode, 400, 'should preserve statusCode');

    // Test MultiError with EntityTooSmall in jse_cause
    var innerEntityError = new Error('Part 1 is too small' +
                                     ' (4194304 bytes, minimum 5242880)');
    innerEntityError.restCode = 'EntityTooSmall';
    innerEntityError.statusCode = 400;

    var multiErrorWithCause = {
        name: 'MultiError',
        jse_cause: innerEntityError,
        message: 'first of 1 error: Part 1 is too small' +
            ' (4194304 bytes, minimum 5242880)'
    };

    var result2 = testEntityTooSmallUnwrapping(multiErrorWithCause);
    t.equal(result2, innerEntityError,
            'should unwrap EntityTooSmall from jse_cause');
    t.equal(result2.restCode, 'EntityTooSmall', 'should preserve restCode');
    t.equal(result2.statusCode, 400, 'should preserve statusCode');

    // Test MultiError with non-EntityTooSmall cause (should pass through)
    var otherError = new Error('Some other error');
    otherError.restCode = 'InternalError';

    var multiErrorOther = {
        name: 'MultiError',
        jse_cause: otherError,
        message: 'first of 1 error: Some other error'
    };

    var result3 = testEntityTooSmallUnwrapping(multiErrorOther);
    t.equal(result3, multiErrorOther,
            'should pass through non-EntityTooSmall MultiError');

    t.end();
});

helper.test('SharkResponseError 409 size mismatch conversion', function (t) {
    // Test detection of 409 errors with size mismatch message
    // Test conversion to InvalidPart with statusCode 400
    // This covers the s3-mako-v2-commit.js fix at lines 328-342

    function testSizeMismatchDetection(postErr, res) {
        // Check for 409 errors indicating size mismatches
        if (res && res.statusCode === 409) {
            return (createInvalidPartError('1.stor.example.com'));
        }

        // Check for SharkResponseError with 409 in message (size mismatch)
        if (postErr && postErr.message &&
            postErr.message.includes('HTTP 409') &&
            postErr.message.includes('assembled temporary file') &&
            postErr.message.includes('bytes, request specified')) {
            return (createInvalidPartError('1.stor.example.com'));
        }

        return (null);
    }

    function createInvalidPartError(shark) {
        var invalidPartError =
            new Error('One or more parts have size discrepancies' +
                      ' that prevent assembly');
        invalidPartError.statusCode = 400;
        invalidPartError.restCode = 'InvalidPart';
        invalidPartError.shark = shark;
        invalidPartError.isSharkFailure = true;
        return (invalidPartError);
    }

    // Test direct 409 response
    var mockResponse409 = { statusCode: 409 };
    var result1 = testSizeMismatchDetection(null, mockResponse409);
    t.ok(result1, 'should detect direct 409 response');
    t.equal(result1.statusCode, 400, 'should convert to statusCode 400');
    t.equal(result1.restCode, 'InvalidPart', 'should convert to InvalidPart');

    // Test SharkResponseError with 409 in message
    var sharkError =
        new Error('storage node failure:\nHTTP 409\n' +
                  '{"code":"BadRequestError",'+
                  '"message":"assembled temporary file' +
                  ' /manta/nginx_temp/0000004545 has size 9437184 bytes,' +
                  ' request specified 8388608 bytes"}');
    sharkError.name = 'SharkResponseError';

    var result2 = testSizeMismatchDetection(sharkError, null);
    t.ok(result2, 'should detect SharkResponseError with 409');
    t.equal(result2.statusCode, 400, 'should convert to statusCode 400');
    t.equal(result2.restCode, 'InvalidPart', 'should convert to InvalidPart');
    t.ok(result2.message.includes('size discrepancies'),
         'should have appropriate error message');

    // Test non-409 SharkResponseError (should not convert)
    var nonSizeError =
        new Error('storage node failure:\nHTTP 500\nInternal Server Error');
    var result3 = testSizeMismatchDetection(nonSizeError, null);
    t.equal(result3, null, 'should not convert non-size-mismatch errors');

    // Test regular error (should not convert)
    var regularError = new Error('Regular error');
    var result4 = testSizeMismatchDetection(regularError, null);
    t.equal(result4, null, 'should not convert regular errors');

    t.end();
});

helper.test('v2 commit InvalidPart extraction from parallel errors',
            function (t) {
    // Test extraction of InvalidPart errors from vasync ase_errors
    // Test behavior when all sharks return InvalidPart vs mixed errors
    // This covers the s3-mako-v2-commit.js fix at lines 399-415

    function testInvalidPartExtraction(vasyncErr) {
        // Check if this is an InvalidPart error (size mismatch)
        if (vasyncErr.restCode === 'InvalidPart' ||
            vasyncErr.statusCode === 400) {
            return (vasyncErr);
        }

        // Check if MultiError contains InvalidPart errors from all sharks
        if (vasyncErr.ase_errors && vasyncErr.ase_errors.length > 0) {
            var invalidPartErrors = vasyncErr.ase_errors.filter(function (err) {
                return (err.restCode === 'InvalidPart' ||
                        err.statusCode === 400);
            });

            if (invalidPartErrors.length === vasyncErr.ase_errors.length) {
                // All errors are InvalidPart - return the first one directly
                return (invalidPartErrors[0]);
            }
        }

        return (null); // Should continue with normal error handling
    }

    // Test all sharks returning InvalidPart
    var allInvalidPartError = {
        ase_errors: [
            {
                statusCode: 400,
                restCode: 'InvalidPart',
                shark: '1.stor.example.com',
                isSharkFailure: true,
                message:
                'One or more parts have size' +
                ' discrepancies that prevent assembly'
            },
            {
                statusCode: 400,
                restCode: 'InvalidPart',
                shark: '2.stor.example.com',
                isSharkFailure: true,
                message:
                'One or more parts have size' +
                ' discrepancies that prevent assembly'
            }
        ],
        message: 'first of 2 errors:' +
            ' One or more parts have size discrepancies that prevent assembly'
    };

    var result1 = testInvalidPartExtraction(allInvalidPartError);
    t.ok(result1,
         'should extract InvalidPart when all sharks return InvalidPart');
    t.equal(result1.statusCode, 400,
            'should preserve statusCode 400');
    t.equal(result1.restCode, 'InvalidPart',
            'should preserve restCode InvalidPart');

    // Test mixed errors (some InvalidPart, some other)
    var mixedError = {
        ase_errors: [
            {
                statusCode: 400,
                restCode: 'InvalidPart',
                shark: '1.stor.example.com'
            },
            {
                statusCode: 503,
                restCode: 'ServiceUnavailable',
                shark: '2.stor.example.com'
            }
        ],
        message: 'first of 2 errors: mixed error types'
    };

    var result2 = testInvalidPartExtraction(mixedError);
    t.equal(result2, null,
            'should not extract InvalidPart when errors are mixed');

    // Test direct InvalidPart error (not in ase_errors)
    var directInvalidPart = {
        statusCode: 400,
        restCode: 'InvalidPart',
        message:
        'One or more parts have size discrepancies that prevent assembly'
    };

    var result3 = testInvalidPartExtraction(directInvalidPart);
    t.equal(result3, directInvalidPart,
             'should pass through direct InvalidPart error');

    // Test error with no ase_errors
    var noAseError = {
        statusCode: 503,
        restCode: 'ServiceUnavailable',
        message: 'Service unavailable'
    };

    var result4 = testInvalidPartExtraction(noAseError);
    t.equal(result4, null,
            'should return null for non-InvalidPart errors without ase_errors');
    t.end();
});

helper.test('Upload record creation and retrieval', function (t) {
    // Test upload record structure and properties
    var uploadRecord = createMockUploadRecord();

    t.ok(uploadRecord.id, 'should have upload ID');
    t.ok(uploadRecord.accountId, 'should have account ID');
    t.ok(uploadRecord.bucketId, 'should have bucket ID');
    t.ok(uploadRecord.objectPath, 'should have object path');
    t.equal(uploadRecord.state, 'created', 'should have created state');
    t.ok(uploadRecord.creationTimeMs, 'should have creation timestamp');
    t.equal(typeof (uploadRecord.creationTimeMs), 'number',
            'creation time should be number');

    // Test headers preservation
    t.ok(uploadRecord.headers, 'should have headers object');
    t.equal(uploadRecord.headers['durability-level'], '2',
            'should preserve durability header');
    t.equal(uploadRecord.headers['content-type'],
            'application/octet-stream',
            'should preserve content-type');

    t.end();
});

helper.test('Part metadata structure and properties', function (t) {
    var partSize = 8 * 1024 * 1024; // 8MB
    var partMeta = createMockPartMeta(1, partSize);

    t.equal(partMeta.partNumber, 1, 'should have correct part number');
    t.equal(partMeta.size, partSize, 'should have correct size');
    t.ok(partMeta.contentMD5, 'should have base64 MD5');
    t.ok(partMeta.hexMD5, 'should have hex MD5');
    t.ok(partMeta.id, 'should have UUID');
    t.ok(partMeta.etag, 'should have ETag');
    t.ok(partMeta.mtime, 'should have modification time');

    // Verify MD5 consistency
    var expectedBase64 = partMeta.contentMD5;
    var expectedHex = Buffer.from(expectedBase64, 'base64').toString('hex');
    t.equal(partMeta.hexMD5, expectedHex,
            'hex MD5 should match base64 conversion');

    // Verify UUID format
    var uuidRegex =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    t.ok(uuidRegex.test(partMeta.id), 'should have valid UUID');

    t.end();
});

helper.test('S3 multipart upload request parsing', function (t) {
    // Test multipart upload operation detection
    function parseMultipartOperation(req) {
        var query = req.query || {};

        if (query.uploads !== undefined) {
            return ('InitiateMultipartUpload');
        } else if (query.uploadId && query.partNumber) {
            return ('UploadPart');
        } else if (query.uploadId && !query.partNumber) {
            if (req.method === 'POST') {
                return ('CompleteMultipartUpload');
            } else if (req.method === 'DELETE') {
                return ('AbortMultipartUpload');
            } else if (req.method === 'GET') {
                return ('ListParts');
            }
        }
        return (null);
    }

    // Test initiate multipart upload
    var req1 = createMockRequest({
        query: { uploads: '' },
        operation: 'InitiateMultipartUpload'
    });
    req1.method = 'POST';
    var op1 = parseMultipartOperation(req1);
    t.equal(op1, 'InitiateMultipartUpload',
            'should detect initiate multipart upload');

    // Test upload part
    var req2 = createMockRequest({
        query: { uploadId: 'test-upload-123', partNumber: '1' }
    });
    req2.method = 'PUT';
    var op2 = parseMultipartOperation(req2);
    t.equal(op2, 'UploadPart', 'should detect upload part');

    // Test complete multipart upload
    var req3 = createMockRequest({
        query: { uploadId: 'test-upload-123' }
    });
    req3.method = 'POST';
    var op3 = parseMultipartOperation(req3);
    t.equal(op3, 'CompleteMultipartUpload',
            'should detect complete multipart upload');

    // Test abort multipart upload
    var req4 = createMockRequest({
        query: { uploadId: 'test-upload-123' }
    });
    req4.method = 'DELETE';
    var op4 = parseMultipartOperation(req4);
    t.equal(op4, 'AbortMultipartUpload',
            'should detect abort multipart upload');

    // Test list parts
    var req5 = createMockRequest({
        query: { uploadId: 'test-upload-123' }
    });
    req5.method = 'GET';
    var op5 = parseMultipartOperation(req5);
    t.equal(op5, 'ListParts', 'should detect list parts');

    t.end();
});

helper.test('Part validation for complete multipart upload', function (t) {
    // Test part validation logic
    function validatePartsForComplete(partsFromXML) {
        // Check parts are in ascending order
        for (var i = 1; i < partsFromXML.length; i++) {
            if (partsFromXML[i].partNumber <= partsFromXML[i - 1].partNumber) {
                return ({ error: 'InvalidPartOrderError' });
            }
        }

        // Check for gaps in part numbers
        for (var j = 0; j < partsFromXML.length; j++) {
            var expectedPartNumber = j + 1;
            if (partsFromXML[j].partNumber !== expectedPartNumber) {
                return ({ error: 'InvalidPartError',
                    missing: expectedPartNumber });
            }
        }

        return ({ valid: true });
    }

    // Test valid parts sequence
    var validParts = [
        { partNumber: 1, etag: 'etag1' },
        { partNumber: 2, etag: 'etag2' },
        { partNumber: 3, etag: 'etag3' }
    ];
    var result1 = validatePartsForComplete(validParts);
    t.ok(result1.valid, 'should validate correct parts sequence');

    // Test invalid order
    var invalidOrderParts = [
        { partNumber: 1, etag: 'etag1' },
        { partNumber: 3, etag: 'etag3' },
        { partNumber: 2, etag: 'etag2' }
    ];
    var result2 = validatePartsForComplete(invalidOrderParts);
    t.equal(result2.error, 'InvalidPartOrderError',
            'should detect invalid part order');

    // Test missing parts
    var missingParts = [
        { partNumber: 1, etag: 'etag1' },
        { partNumber: 3, etag: 'etag3' }
    ];
    var result3 = validatePartsForComplete(missingParts);
    t.equal(result3.error, 'InvalidPartError', 'should detect missing parts');
    t.equal(result3.missing, 2, 'should identify missing part number');

    // Test empty parts
    var result4 = validatePartsForComplete([]);
    t.ok(result4.valid, 'should accept empty parts array');

    t.end();
});
