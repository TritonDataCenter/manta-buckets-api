/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/**
 * Unit tests for aws-chunked-encoding.js module
 * Tests the AWS SigV4 streaming (chunked transfer encoding) helpers
 */

var helper = require('./s3-test-helper.js');
var awsChunked = require('../lib/aws-chunked-encoding.js');

// Test: isAwsChunked - should return true for aws-chunked encoding
helper.test('isAwsChunked returns true for aws-chunked', function (t) {
    var headers = {
        'content-encoding': 'aws-chunked'
    };

    var result = awsChunked.isAwsChunked(headers);

    t.ok(result, 'should return true for aws-chunked encoding');
    t.end();
});

// Test: isAwsChunked - should return false for other encodings
helper.test('isAwsChunked returns false for gzip encoding', function (t) {
    var headers = {
        'content-encoding': 'gzip'
    };

    var result = awsChunked.isAwsChunked(headers);

    t.ok(!result, 'should return false for gzip encoding');
    t.end();
});

// Test: isAwsChunked - should return false when no encoding header
helper.test('isAwsChunked returns false when no encoding header', function (t) {
    var headers = {};

    var result = awsChunked.isAwsChunked(headers);

    t.ok(!result, 'should return false when no encoding header');
    t.end();
});

// Test: getDecodedSize - should return decoded size from header
helper.test('getDecodedSize returns size from header', function (t) {
    var headers = {
        'x-amz-decoded-content-length': '1024'
    };

    var result = awsChunked.getDecodedSize(headers);

    t.equal(result, 1024, 'should return parsed integer size');
    t.end();
});

// Test: getDecodedSize - should return null when header missing
helper.test('getDecodedSize returns null when header missing', function (t) {
    var headers = {};

    var result = awsChunked.getDecodedSize(headers);

    t.equal(result, null, 'should return null when header missing');
    t.end();
});

// Test: getDecodedSize - should return null for invalid number
helper.test('getDecodedSize returns null for invalid number', function (t) {
    var headers = {
        'x-amz-decoded-content-length': 'invalid'
    };

    var result = awsChunked.getDecodedSize(headers);

    t.equal(result, null, 'should return null for invalid number');
    t.end();
});

// Test: getDecodedSize - should handle zero size
helper.test('getDecodedSize handles zero size', function (t) {
    var headers = {
        'x-amz-decoded-content-length': '0'
    };

    var result = awsChunked.getDecodedSize(headers);

    t.equal(result, 0, 'should return 0 for zero size');
    t.end();
});

// Test: configureAwsChunkedEncoding - should set decoded size for aws-chunked
helper.test('configureAwsChunkedEncoding sets decoded size', function (t) {
    var req = {
        log: {
            debug: function () {}
        }
    };

    var partReq = {
        headers: {
            'content-encoding': 'aws-chunked',
            'x-amz-decoded-content-length': '2048',
            'content-length': '2100'
        }
    };

    awsChunked.configureAwsChunkedEncoding(req, partReq, 1, 'test-upload');

    t.equal(partReq._size, 2048, 'should set _size to decoded size');
    t.equal(partReq._awsChunkedExpectedSize, 2048,
        'should set expected size');
    t.ok(partReq._awsChunkedMPU, 'should mark as aws-chunked MPU');
    t.end();
});

// Test: configureAwsChunkedEncoding - should not modify non-chunked requests
helper.test('configureAwsChunkedEncoding skips non-chunked', function (t) {
    var req = {
        log: {
            debug: function () {}
        }
    };

    var partReq = {
        headers: {
            'content-length': '1024'
        }
    };

    awsChunked.configureAwsChunkedEncoding(req, partReq, 1, 'test-upload');

    t.ok(!partReq._size, 'should not set _size');
    t.ok(!partReq._awsChunkedExpectedSize, 'should not set expected size');
    t.ok(!partReq._awsChunkedMPU, 'should not mark as aws-chunked MPU');
    t.end();
});

// Test: configureAwsChunkedEncoding - should handle missing decoded size
helper.test('configureAwsChunkedEncoding handles missing decoded size',
    function (t) {
        var req = {
            log: {
                debug: function () {}
            }
        };

        var partReq = {
            headers: {
                'content-encoding': 'aws-chunked',
                'content-length': '2100'
            }
        };

        awsChunked.configureAwsChunkedEncoding(req, partReq, 1, 'test-upload');

        t.ok(!partReq._size, 'should not set _size without decoded size');
        t.ok(partReq._awsChunkedMPU, 'should still mark as aws-chunked MPU');
        t.end();
    });

// Test: configureAwsChunkedEncoding - should handle invalid decoded size
helper.test('configureAwsChunkedEncoding handles invalid decoded size',
    function (t) {
        var req = {
            log: {
                debug: function () {}
            }
        };

        var partReq = {
            headers: {
                'content-encoding': 'aws-chunked',
                'x-amz-decoded-content-length': 'invalid',
                'content-length': '2100'
            }
        };

        awsChunked.configureAwsChunkedEncoding(req, partReq, 1, 'test-upload');

        t.ok(!partReq._size, 'should not set _size for invalid decoded size');
        t.ok(partReq._awsChunkedMPU, 'should still mark as aws-chunked MPU');
        t.end();
    });

// Test: configureAwsChunkedEncoding - should preserve content-length
helper.test('configureAwsChunkedEncoding preserves content-length',
    function (t) {
    var req = {
        log: {
            debug: function () {}
        }
    };

    var partReq = {
        headers: {
            'content-encoding': 'aws-chunked',
            'x-amz-decoded-content-length': '2048',
            'content-length': '2100'
        }
    };

    awsChunked.configureAwsChunkedEncoding(req, partReq, 1, 'test-upload');

    t.equal(partReq.headers['content-length'], '2100',
        'should preserve encoded content-length');
    t.end();
});
