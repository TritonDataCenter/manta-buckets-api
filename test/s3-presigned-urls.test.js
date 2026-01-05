/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

///--- S3 Presigned URL Utility Tests

exports['S3 presigned URL parameter detection'] = function (t) {
    // Test basic parameter detection logic
    var s3PresignedParams = {
        'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
        'X-Amz-Credential': 'AKIATEST12345/20250926/us-east-1/s3/aws4_request',
        'X-Amz-Date': '20250926T120000Z',
        'X-Amz-Expires': '3600',
        'X-Amz-SignedHeaders': 'host',
        'X-Amz-Signature': 'abcdef123456789'
    };

    // Test detection function
    function isS3PresignedURL(query) {
        return query['X-Amz-Algorithm'] &&
               query['X-Amz-Signature'] &&
               query['X-Amz-Credential'];
    }

    t.ok(isS3PresignedURL(s3PresignedParams), 'should detect S3 presigned URL');
    t.ok(!isS3PresignedURL({}), 'should not detect empty query');
    t.ok(!isS3PresignedURL({someParam: 'value'}),
         'should not detect regular query');

    t.done();
};

exports['S3 credential parsing'] = function (t) {
    // Test credential string parsing
    var credential = 'AKIATEST12345/20250926/us-east-1/s3/aws4_request';
    var parts = credential.split('/');

    t.equal(parts[0], 'AKIATEST12345', 'should extract access key');
    t.equal(parts[1], '20250926', 'should extract date');
    t.equal(parts[2], 'us-east-1', 'should extract region');
    t.equal(parts[3], 's3', 'should extract service');
    t.equal(parts[4], 'aws4_request', 'should extract request type');

    t.done();
};

exports['S3 date format validation'] = function (t) {
    // Test ISO8601 date format: YYYYMMDDTHHMMSSZ
    var validDate = '20250926T120000Z';
    var invalidDate = '2025-09-26 12:00:00';

    function isValidS3Date(dateStr) {
        return (/^\d{8}T\d{6}Z$/.test(dateStr));
    }

    t.ok(isValidS3Date(validDate), 'should validate correct S3 date format');
    t.ok(!isValidS3Date(invalidDate), 'should reject invalid date format');
    t.ok(!isValidS3Date(''), 'should reject empty date');

    t.done();
};

exports['S3 presigned URL MPU operation detection'] = function (t) {
    // Test multipart upload part detection in presigned URLs
    var baseQuery = {
        'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
        'X-Amz-Credential': 'AKIATEST12345/20250926/us-east-1/s3/aws4_request',
        'X-Amz-Date': '20250926T120000Z',
        'X-Amz-Expires': '3600',
        'X-Amz-SignedHeaders': 'host',
        'X-Amz-Signature': 'abcdef123456789'
    };

    // Regular PUT operation
    var regularQuery = Object.assign({}, baseQuery);

    // MPU part upload query
    var mpuQuery = Object.assign({}, baseQuery, {
        'uploadId': 'upload-123',
        'partNumber': '1'
    });

    function detectS3Operation(query, method) {
        if (query.uploadId && query.partNumber && method === 'PUT') {
            return ('UploadPart');
        } else if (method === 'PUT') {
            return ('CreateBucketObject');
        } else if (method === 'GET') {
            return ('GetBucketObject');
        }
        return ('Unknown');
    }

    t.equal(detectS3Operation(regularQuery, 'PUT'), 'CreateBucketObject',
            'should detect regular PUT operation');
    t.equal(detectS3Operation(mpuQuery, 'PUT'), 'UploadPart',
            'should detect MPU part upload operation');
    t.equal(detectS3Operation(mpuQuery, 'GET'), 'GetBucketObject',
            'should not detect MPU operation for GET method');

    t.done();
};

exports['S3 presigned URL MPU parameter validation'] = function (t) {
    // Test MPU parameter validation
    function validateMPUParams(uploadId, partNumber) {
        if (!uploadId || typeof (uploadId) !== 'string') {
            return (false);
        }

        var partNum = parseInt(partNumber, 10);
        if (isNaN(partNum) || partNum < 1 || partNum > 10000) {
            return (false);
        }

        return (true);
    }

    t.ok(validateMPUParams('upload-123', '1'),
         'should validate valid MPU params');
    t.ok(validateMPUParams('upload-456', '5000'),
         'should validate mid-range part number');
    t.ok(validateMPUParams('upload-789', '10000'),
         'should validate max part number');

    t.ok(!validateMPUParams('', '1'), 'should reject empty uploadId');
    t.ok(!validateMPUParams('upload-123', '0'), 'should reject part number 0');
    t.ok(!validateMPUParams('upload-123', '10001'),
         'should reject part number > 10000');
    t.ok(!validateMPUParams('upload-123', 'abc'),
         'should reject non-numeric part number');
    t.ok(!validateMPUParams(null, '1'), 'should reject null uploadId');

    t.done();
};
