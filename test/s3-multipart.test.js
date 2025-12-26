/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/**
 * Real unit tests for S3 multipart upload helper functions
 * Tests the actual implementation from lib/s3-multipart.js
 */

var helper = require('./s3-test-helper.js');
var s3Multipart = require('../lib/s3-multipart');

///--- validatePartNumber Tests

helper.test('validatePartNumber - accepts valid part numbers', function (t) {
    t.ok(s3Multipart.validatePartNumber(1),
         'should accept part 1 (minimum)');
    t.ok(s3Multipart.validatePartNumber(100),
         'should accept part 100');
    t.ok(s3Multipart.validatePartNumber(5000),
         'should accept part 5000 (middle)');
    t.ok(s3Multipart.validatePartNumber(10000),
         'should accept part 10000 (maximum)');
    t.end();
});

helper.test('validatePartNumber - rejects invalid part numbers', function (t) {
    t.notOk(s3Multipart.validatePartNumber(0),
            'should reject part 0');
    t.notOk(s3Multipart.validatePartNumber(-1),
            'should reject negative part numbers');
    t.notOk(s3Multipart.validatePartNumber(10001),
            'should reject part 10001 (over maximum)');
    t.notOk(s3Multipart.validatePartNumber(99999),
            'should reject very large part numbers');
    t.end();
});

helper.test('validatePartNumber - handles edge cases', function (t) {
    t.notOk(s3Multipart.validatePartNumber(null),
            'should reject null');
    t.notOk(s3Multipart.validatePartNumber(undefined),
            'should reject undefined');
    t.notOk(s3Multipart.validatePartNumber('1'),
            'should reject string "1"');
    t.notOk(s3Multipart.validatePartNumber(1.5),
            'should reject decimal 1.5');
    t.end();
});

///--- generatePartKey Tests

helper.test('generatePartKey - generates correct format', function (t) {
    var uploadId = 'test-upload-abc123';
    var partNumber = 5;

    var partKey = s3Multipart.generatePartKey(uploadId, partNumber);

    t.ok(partKey, 'should generate a key');
    t.equal(typeof (partKey), 'string', 'should be a string');
    t.equal(partKey, '.mpu-parts/test-upload-abc123/5',
            'should match expected format');
    t.end();
});

helper.test('generatePartKey - handles different inputs', function (t) {
    var key1 = s3Multipart.generatePartKey('upload-1', 1);
    var key2 = s3Multipart.generatePartKey('upload-2', 1);
    var key3 = s3Multipart.generatePartKey('upload-1', 2);

    t.notEqual(key1, key2, 'different upload IDs produce different keys');
    t.notEqual(key1, key3, 'different part numbers produce different keys');

    t.ok(key1.indexOf('upload-1') !== -1,
         'key should contain upload ID');
    t.ok(key1.indexOf('/1') !== -1,
         'key should contain part number');
    t.end();
});

helper.test('generatePartKey - handles large part numbers', function (t) {
    var partKey = s3Multipart.generatePartKey('upload-xyz', 10000);

    t.equal(partKey, '.mpu-parts/upload-xyz/10000',
            'should handle maximum part number');
    t.end();
});

///--- extractPartETags Tests

helper.test('extractPartETags - extracts ETags from parts array',
           function (t) {
    var partsFromXML = [
        {partNumber: 1, etag: 'etag-abc123'},
        {partNumber: 2, etag: 'etag-def456'},
        {partNumber: 3, etag: 'etag-ghi789'}
    ];

    var etags = s3Multipart.extractPartETags(partsFromXML);

    t.ok(Array.isArray(etags), 'should return an array');
    t.equal(etags.length, 3, 'should extract all 3 ETags');
    t.equal(etags[0], 'etag-abc123', 'should match first ETag');
    t.equal(etags[1], 'etag-def456', 'should match second ETag');
    t.equal(etags[2], 'etag-ghi789', 'should match third ETag');
    t.end();
});

helper.test('extractPartETags - handles empty array', function (t) {
    var etags = s3Multipart.extractPartETags([]);

    t.ok(Array.isArray(etags), 'should return an array');
    t.equal(etags.length, 0, 'should be empty for empty input');
    t.end();
});

helper.test('extractPartETags - handles single part', function (t) {
    var partsFromXML = [
        {partNumber: 1, etag: 'single-etag'}
    ];

    var etags = s3Multipart.extractPartETags(partsFromXML);

    t.equal(etags.length, 1, 'should extract single ETag');
    t.equal(etags[0], 'single-etag', 'should match the ETag');
    t.end();
});

///--- validatePartOrder Tests

helper.test('validatePartOrder - accepts correctly ordered parts',
           function (t) {
    var orderedParts = [
        {partNumber: 1},
        {partNumber: 2},
        {partNumber: 3},
        {partNumber: 5},
        {partNumber: 10}
    ];

    var result = s3Multipart.validatePartOrder(orderedParts);

    t.equal(result, null, 'should return null for valid order');
    t.end();
});

helper.test('validatePartOrder - rejects out of order parts', function (t) {
    var unorderedParts = [
        {partNumber: 1},
        {partNumber: 3},
        {partNumber: 2}
    ];

    var result = s3Multipart.validatePartOrder(unorderedParts);

    t.ok(result, 'should return error for wrong order');
    t.ok(result instanceof Error, 'should be an Error');
    t.ok(result.name.indexOf('InvalidPartOrder') !== -1,
         'should be InvalidPartOrder error');
    t.end();
});

helper.test('validatePartOrder - rejects duplicate part numbers', function (t) {
    var duplicateParts = [
        {partNumber: 1},
        {partNumber: 2},
        {partNumber: 2}
    ];

    var result = s3Multipart.validatePartOrder(duplicateParts);

    t.ok(result, 'should return error for duplicates');
    t.ok(result instanceof Error, 'should be an Error');
    t.end();
});

helper.test('validatePartOrder - accepts single part', function (t) {
    var singlePart = [ { partNumber: 1 } ];

    var result = s3Multipart.validatePartOrder(singlePart);

    t.equal(result, null, 'should accept single part');
    t.end();
});

///--- validateNoGaps Tests

helper.test('validateNoGaps - accepts sequential parts starting from 1',
           function (t) {
    var sequentialParts = [
        {partNumber: 1},
        {partNumber: 2},
        {partNumber: 3},
        {partNumber: 4}
    ];

    var result = s3Multipart.validateNoGaps(sequentialParts);

    t.equal(result, null, 'should return null for sequential parts');
    t.end();
});

helper.test('validateNoGaps - rejects gaps in part numbers', function (t) {
    var partsWithGap = [
        {partNumber: 1},
        {partNumber: 2},
        {partNumber: 4}
    ];

    var result = s3Multipart.validateNoGaps(partsWithGap);

    t.ok(result, 'should return error for gap');
    t.ok(result instanceof Error, 'should be an Error');
    t.ok(result.message.indexOf('expected 3') !== -1,
         'error should mention expected part 3');
    t.ok(result.message.indexOf('got 4') !== -1,
         'error should mention got part 4');
    t.end();
});

helper.test('validateNoGaps - rejects if not starting from 1', function (t) {
    var partsNotStartingFrom1 = [
        {partNumber: 2},
        {partNumber: 3}
    ];

    var result = s3Multipart.validateNoGaps(partsNotStartingFrom1);

    t.ok(result, 'should return error when not starting from 1');
    t.ok(result.message.indexOf('expected 1') !== -1,
         'should expect part 1');
    t.ok(result.message.indexOf('got 2') !== -1,
         'should mention got part 2');
    t.end();
});

helper.test('validateNoGaps - accepts single part 1', function (t) {
    var singlePart = [ { partNumber: 1 } ];

    var result = s3Multipart.validateNoGaps(singlePart);

    t.equal(result, null, 'should accept single part 1');
    t.end();
});

///--- resolveETag Tests

helper.test('resolveETag - prefers captured ETag', function (t) {
    var capturedETag = 'captured-etag-123';
    var result = {id: 'result-id-456'};

    var etag = s3Multipart.resolveETag(capturedETag, result);

    t.equal(etag, 'captured-etag-123',
            'should return captured ETag when available');
    t.end();
});

helper.test('resolveETag - falls back to result.id', function (t) {
    var result = {id: 'result-id-789'};

    var etag = s3Multipart.resolveETag(null, result);

    t.equal(etag, 'result-id-789',
            'should return result.id when no captured ETag');
    t.end();
});

helper.test('resolveETag - returns unknown when no ETag available',
           function (t) {
    var etag1 = s3Multipart.resolveETag(null, null);
    var etag2 = s3Multipart.resolveETag(null, {});
    var etag3 = s3Multipart.resolveETag(undefined, undefined);

    t.equal(etag1, 'unknown', 'should return "unknown" for null inputs');
    t.equal(etag2, 'unknown', 'should return "unknown" for empty result');
    t.equal(etag3, 'unknown',
            'should return "unknown" for undefined inputs');
    t.end();
});

helper.test('resolveETag - priority order is correct', function (t) {
    var capturedETag = 'captured';
    var result = {id: 'result-id'};

    var etag = s3Multipart.resolveETag(capturedETag, result);

    t.equal(etag, 'captured',
            'captured ETag should have highest priority');
    t.end();
});

///--- Integration Tests

helper.test('Part validation workflow - valid sequential upload',
           function (t) {
    var parts = [
        {partNumber: 1, etag: 'etag-1'},
        {partNumber: 2, etag: 'etag-2'},
        {partNumber: 3, etag: 'etag-3'}
    ];

    // Validate all parts are within range
    var allValid = parts.every(function (p) {
        return (s3Multipart.validatePartNumber(p.partNumber));
    });
    t.ok(allValid, 'all part numbers should be valid');

    // Validate order
    var orderError = s3Multipart.validatePartOrder(parts);
    t.equal(orderError, null, 'parts should be in correct order');

    // Validate no gaps
    var gapError = s3Multipart.validateNoGaps(parts);
    t.equal(gapError, null, 'parts should have no gaps');

    // Extract ETags
    var etags = s3Multipart.extractPartETags(parts);
    t.equal(etags.length, 3, 'should extract all ETags');

    // Generate keys
    var uploadId = 'test-upload';
    var keys = parts.map(function (p) {
        return (s3Multipart.generatePartKey(uploadId, p.partNumber));
    });
    t.equal(keys.length, 3, 'should generate all keys');
    t.ok(keys[0].indexOf('/1') !== -1, 'key should contain part number');

    t.end();
});

helper.test('Part validation workflow - detects multiple errors',
           function (t) {
    var invalidParts = [
        {partNumber: 2, etag: 'etag-2'},
        {partNumber: 4, etag: 'etag-4'},
        {partNumber: 3, etag: 'etag-3'}
    ];

    // Not starting from 1
    var gapError = s3Multipart.validateNoGaps(invalidParts);
    t.ok(gapError, 'should detect parts not starting from 1');

    // Out of order
    var orderError = s3Multipart.validatePartOrder(invalidParts);
    t.ok(orderError, 'should detect out of order parts');

    t.end();
});
