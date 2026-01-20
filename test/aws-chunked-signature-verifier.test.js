/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Unit tests for AWS chunked signature verification
 *
 * Tests the cryptographic functions used to verify AWS SigV4 streaming
 * signatures for aws-chunked encoded uploads.
 */

var helper = require('./s3-test-helper.js');
var verifier = require('../lib/aws-chunked-signature-verifier');

/*
 * Test vectors based on AWS SigV4 Streaming specification
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
 */

helper.test('deriveSigningKey - produces correct signing key', function (t) {
    // Test case from AWS documentation
    var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20130524';
    var region = 'us-east-1';
    var service = 's3';

    var signingKey = verifier.deriveSigningKey(secretKey, dateStamp,
        region, service);

    t.ok(signingKey, 'signing key should be generated');
    t.ok(Buffer.isBuffer(signingKey), 'signing key should be a Buffer');
    t.equal(signingKey.length, 32,
        'signing key should be 32 bytes (SHA256)');

    t.end();
});

helper.test('deriveSigningKey - different dates produce different keys',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var region = 'us-east-1';
        var service = 's3';

        var key1 = verifier.deriveSigningKey(secretKey, '20130524',
            region, service);
        var key2 = verifier.deriveSigningKey(secretKey, '20130525',
            region, service);

        t.notEqual(key1.toString('hex'), key2.toString('hex'),
            'different dates should produce different keys');

        t.end();
    });

helper.test('deriveSigningKey - different regions produce different keys',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var service = 's3';

        var key1 = verifier.deriveSigningKey(secretKey, dateStamp,
            'us-east-1', service);
        var key2 = verifier.deriveSigningKey(secretKey, dateStamp,
            'us-west-2', service);

        t.notEqual(key1.toString('hex'), key2.toString('hex'),
            'different regions should produce different keys');

        t.end();
    });

helper.test('calculateChunkSignature - produces valid signature format',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var previousSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';
        var chunkData = new Buffer(Array(65537).join('a'));

        var signature = verifier.calculateChunkSignature(
            signingKey,
            previousSignature,
            timestamp,
            credentialScope,
            chunkData);

        t.ok(signature, 'signature should be generated');
        t.equal(typeof (signature), 'string',
            'signature should be a string');
        t.equal(signature.length, 64,
            'signature should be 64 hex characters (SHA256)');
        t.ok(/^[a-f0-9]{64}$/.test(signature),
            'signature should be lowercase hex');

        t.end();
    });

helper.test(
    'calculateChunkSignature - different data produces different signatures',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var previousSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';

        var sig1 = verifier.calculateChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            new Buffer('data1'));

        var sig2 = verifier.calculateChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            new Buffer('data2'));

        t.notEqual(sig1, sig2,
            'different chunk data should produce different signatures');

        t.end();
    });

helper.test(
    'calculateChunkSignature - signature chain works correctly',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var seedSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';

        // Calculate signature for first chunk
        var chunk1Data = new Buffer('first chunk data');
        var chunk1Sig = verifier.calculateChunkSignature(
            signingKey, seedSignature, timestamp, credentialScope,
            chunk1Data);

        // Calculate signature for second chunk using first
        // chunk's signature
        var chunk2Data = new Buffer('second chunk data');
        var chunk2Sig = verifier.calculateChunkSignature(
            signingKey, chunk1Sig, timestamp, credentialScope,
            chunk2Data);

        t.ok(chunk1Sig, 'first chunk signature generated');
        t.ok(chunk2Sig, 'second chunk signature generated');
        t.notEqual(chunk1Sig, chunk2Sig,
            'chunk signatures should be different');
        t.notEqual(chunk1Sig, seedSignature,
            'chunk signature should differ from seed');

        t.end();
    });

helper.test('verifyChunkSignature - accepts valid signature',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var previousSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';
        var chunkData = new Buffer('test data');

        // Calculate the expected signature
        var expectedSignature = verifier.calculateChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            chunkData);

        // Verify it
        var isValid = verifier.verifyChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            chunkData, expectedSignature);

        t.ok(isValid, 'valid signature should be accepted');

        t.end();
    });

helper.test('verifyChunkSignature - rejects invalid signature',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var previousSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';
        var chunkData = new Buffer('test data');

        var invalidSignature =
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

        var isValid = verifier.verifyChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            chunkData, invalidSignature);

        t.notOk(isValid, 'invalid signature should be rejected');

        t.end();
    });

helper.test('verifyChunkSignature - rejects tampered data',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var previousSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';
        var originalData = new Buffer('original data');

        // Calculate signature for original data
        var signature = verifier.calculateChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            originalData);

        // Try to verify with tampered data
        var tamperedData = new Buffer('tampered data');
        var isValid = verifier.verifyChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            tamperedData, signature);

        t.notOk(isValid,
            'signature verification should fail for tampered data');

        t.end();
    });

helper.test(
    'verifyChunkSignature - rejects wrong previous signature',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var correctPrevSig =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var wrongPrevSig =
            'bd80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';
        var chunkData = new Buffer('test data');

        // Calculate signature with correct previous signature
        var signature = verifier.calculateChunkSignature(
            signingKey, correctPrevSig, timestamp, credentialScope,
            chunkData);

        // Try to verify with wrong previous signature
        var isValid = verifier.verifyChunkSignature(
            signingKey, wrongPrevSig, timestamp, credentialScope,
            chunkData, signature);

        t.notOk(isValid,
            'verification should fail with wrong previous signature');

        t.end();
    });

/*
 * Edge case tests
 */

helper.test('Edge case: empty chunk data (end-of-stream marker)',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var previousSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';
        var emptyChunk = new Buffer(0);

        // Calculate signature for empty chunk
        var signature = verifier.calculateChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            emptyChunk);

        t.ok(signature, 'should generate signature for empty chunk');
        t.equal(signature.length, 64,
            'empty chunk signature should be 64 hex chars');

        // Verify it
        var isValid = verifier.verifyChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            emptyChunk, signature);

        t.ok(isValid, 'empty chunk signature should verify correctly');

        t.end();
    });

helper.test('Edge case: very large chunk data (1MB)',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var previousSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';

        // Create 1MB chunk
        var largeChunk = new Buffer(1024 * 1024);
        for (var i = 0; i < largeChunk.length; i++) {
            largeChunk[i] = i % 256;
        }

        var signature = verifier.calculateChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            largeChunk);

        var isValid = verifier.verifyChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            largeChunk, signature);

        t.ok(isValid, 'large chunk (1MB) should verify correctly');

        t.end();
    });

helper.test('Edge case: binary data with null bytes',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var previousSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';

        // Binary data with null bytes
        var binaryChunk = new Buffer([
            0x00, 0xFF, 0x00, 0xAB, 0xCD, 0xEF, 0x00
        ]);

        var signature = verifier.calculateChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            binaryChunk);

        var isValid = verifier.verifyChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            binaryChunk, signature);

        t.ok(isValid,
            'binary data with null bytes should verify correctly');

        t.end();
    });

helper.test('Edge case: single byte tampering detection',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var previousSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';

        var originalData = new Buffer(
            'The quick brown fox jumps over the lazy dog');

        var signature = verifier.calculateChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            originalData);

        // Tamper with a single byte
        var tamperedData = new Buffer(originalData);
        tamperedData[10] = tamperedData[10] + 1;

        var isValid = verifier.verifyChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            tamperedData, signature);

        t.notOk(isValid, 'single byte change should break signature');

        t.end();
    });

helper.test('Edge case: signature case sensitivity',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var previousSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';
        var chunkData = new Buffer('test data');

        var signature = verifier.calculateChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            chunkData);

        // Signatures should be lowercase
        t.ok(/^[a-f0-9]{64}$/.test(signature),
            'signature should be lowercase hex');

        // Try uppercase version
        var uppercaseSignature = signature.toUpperCase();

        var isValid = verifier.verifyChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            chunkData, uppercaseSignature);

        t.notOk(isValid, 'uppercase signature should be rejected');

        t.end();
    });

helper.test('Edge case: malformed signature - wrong length',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var previousSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';
        var chunkData = new Buffer('test data');

        // Too short
        var shortSignature = 'deadbeef';
        var isValid1 = verifier.verifyChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            chunkData, shortSignature);
        t.notOk(isValid1, 'short signature should be rejected');

        // Too long
        var longSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648' +
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';

        var isValid2 = verifier.verifyChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            chunkData, longSignature);
        t.notOk(isValid2, 'long signature should be rejected');

        t.end();
    });

helper.test(
    'Edge case: malformed signature - invalid hex characters',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var previousSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';
        var chunkData = new Buffer('test data');

        // Non-hex characters (invalid but same length)
        var invalidSignature =
            'ZZZZZZZZA21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';

        var isValid = verifier.verifyChunkSignature(
            signingKey, previousSignature, timestamp, credentialScope,
            chunkData, invalidSignature);

        t.notOk(isValid,
            'signature with invalid hex should be rejected');

        t.end();
    });

helper.test(
    'Edge case: different service names produce different keys',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';

        var s3Key = verifier.deriveSigningKey(secretKey, dateStamp,
            region, 's3');
        var ec2Key = verifier.deriveSigningKey(secretKey, dateStamp,
            region, 'ec2');

        t.notEqual(s3Key.toString('hex'), ec2Key.toString('hex'),
            'different services should produce different keys');

        t.end();
    });

helper.test('Edge case: signature chain break detection',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var seedSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';

        // Calculate correct chain
        var chunk1Data = new Buffer('chunk 1');
        var chunk1Sig = verifier.calculateChunkSignature(
            signingKey, seedSignature, timestamp, credentialScope,
            chunk1Data);

        var chunk2Data = new Buffer('chunk 2');
        var chunk2Sig = verifier.calculateChunkSignature(
            signingKey, chunk1Sig, timestamp, credentialScope,
            chunk2Data);

        // Try to verify chunk 2 with wrong previous signature
        // (using seed instead of chunk1Sig)
        var isValid = verifier.verifyChunkSignature(
            signingKey, seedSignature, timestamp, credentialScope,
            chunk2Data, chunk2Sig);

        t.notOk(isValid,
            'chunk 2 verification should fail with wrong previous ' +
            'signature in chain');

        t.end();
    });

helper.test(
    'Edge case: identical chunks produce different signatures in chain',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var seedSignature =
            'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';

        // Send same data in two consecutive chunks
        var identicalData = new Buffer('identical chunk data');

        var chunk1Sig = verifier.calculateChunkSignature(
            signingKey, seedSignature, timestamp, credentialScope,
            identicalData);

        var chunk2Sig = verifier.calculateChunkSignature(
            signingKey, chunk1Sig, timestamp, credentialScope,
            identicalData);

        t.notEqual(chunk1Sig, chunk2Sig,
            'identical data in consecutive chunks should produce ' +
            'different signatures');

        t.end();
    });

helper.test('Edge case: empty previous signature string',
    function (t) {
        var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        var dateStamp = '20130524';
        var region = 'us-east-1';
        var service = 's3';

        var signingKey = verifier.deriveSigningKey(secretKey,
            dateStamp, region, service);

        var timestamp = '20130524T000000Z';
        var credentialScope = '20130524/us-east-1/s3/aws4_request';
        var chunkData = new Buffer('test data');

        // Empty string as previous signature
        // (invalid but shouldn't crash)
        var signature = verifier.calculateChunkSignature(
            signingKey, '', timestamp, credentialScope, chunkData);

        t.ok(signature,
            'should generate signature even with empty previous signature');
        t.equal(signature.length, 64,
            'signature should still be 64 hex chars');

        t.end();
    });
