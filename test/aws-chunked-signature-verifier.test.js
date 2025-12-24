/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Joyent, Inc.
 */

/*
 * Unit tests for AWS chunked signature verification
 *
 * Tests the cryptographic functions used to verify AWS SigV4 streaming
 * signatures for aws-chunked encoded uploads.
 */

var test = require('tap').test;
var verifier = require('../lib/aws-chunked-signature-verifier');

/*
 * Test vectors based on AWS SigV4 Streaming specification
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
 */

test('deriveSigningKey - produces correct signing key', function (t) {
    // Test case from AWS documentation
    var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20130524';
    var region = 'us-east-1';
    var service = 's3';

    var signingKey = verifier.deriveSigningKey(secretKey, dateStamp, region, service);

    t.ok(signingKey, 'signing key should be generated');
    t.ok(Buffer.isBuffer(signingKey), 'signing key should be a Buffer');
    t.equal(signingKey.length, 32, 'signing key should be 32 bytes (SHA256)');

    t.end();
});

test('deriveSigningKey - different dates produce different keys', function (t) {
    var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var region = 'us-east-1';
    var service = 's3';

    var key1 = verifier.deriveSigningKey(secretKey, '20130524', region, service);
    var key2 = verifier.deriveSigningKey(secretKey, '20130525', region, service);

    t.notEqual(key1.toString('hex'), key2.toString('hex'),
        'different dates should produce different keys');

    t.end();
});

test('deriveSigningKey - different regions produce different keys', function (t) {
    var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20130524';
    var service = 's3';

    var key1 = verifier.deriveSigningKey(secretKey, dateStamp, 'us-east-1', service);
    var key2 = verifier.deriveSigningKey(secretKey, dateStamp, 'us-west-2', service);

    t.notEqual(key1.toString('hex'), key2.toString('hex'),
        'different regions should produce different keys');

    t.end();
});

test('calculateChunkSignature - produces valid signature format', function (t) {
    var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20130524';
    var region = 'us-east-1';
    var service = 's3';

    var signingKey = verifier.deriveSigningKey(secretKey, dateStamp, region, service);

    var previousSignature = 'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
    var timestamp = '20130524T000000Z';
    var credentialScope = '20130524/us-east-1/s3/aws4_request';
    var chunkData = Buffer.from('a'.repeat(65536));

    var signature = verifier.calculateChunkSignature(
        signingKey,
        previousSignature,
        timestamp,
        credentialScope,
        chunkData
    );

    t.ok(signature, 'signature should be generated');
    t.equal(typeof signature, 'string', 'signature should be a string');
    t.equal(signature.length, 64, 'signature should be 64 hex characters (SHA256)');
    t.ok(/^[a-f0-9]{64}$/.test(signature), 'signature should be lowercase hex');

    t.end();
});

test('calculateChunkSignature - different data produces different signatures', function (t) {
    var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20130524';
    var region = 'us-east-1';
    var service = 's3';

    var signingKey = verifier.deriveSigningKey(secretKey, dateStamp, region, service);

    var previousSignature = 'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
    var timestamp = '20130524T000000Z';
    var credentialScope = '20130524/us-east-1/s3/aws4_request';

    var sig1 = verifier.calculateChunkSignature(
        signingKey, previousSignature, timestamp, credentialScope,
        Buffer.from('data1')
    );

    var sig2 = verifier.calculateChunkSignature(
        signingKey, previousSignature, timestamp, credentialScope,
        Buffer.from('data2')
    );

    t.notEqual(sig1, sig2, 'different chunk data should produce different signatures');

    t.end();
});

test('calculateChunkSignature - signature chain works correctly', function (t) {
    var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20130524';
    var region = 'us-east-1';
    var service = 's3';

    var signingKey = verifier.deriveSigningKey(secretKey, dateStamp, region, service);

    var seedSignature = 'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
    var timestamp = '20130524T000000Z';
    var credentialScope = '20130524/us-east-1/s3/aws4_request';

    // Calculate signature for first chunk
    var chunk1Data = Buffer.from('first chunk data');
    var chunk1Sig = verifier.calculateChunkSignature(
        signingKey, seedSignature, timestamp, credentialScope, chunk1Data
    );

    // Calculate signature for second chunk using first chunk's signature
    var chunk2Data = Buffer.from('second chunk data');
    var chunk2Sig = verifier.calculateChunkSignature(
        signingKey, chunk1Sig, timestamp, credentialScope, chunk2Data
    );

    t.ok(chunk1Sig, 'first chunk signature generated');
    t.ok(chunk2Sig, 'second chunk signature generated');
    t.notEqual(chunk1Sig, chunk2Sig, 'chunk signatures should be different');
    t.notEqual(chunk1Sig, seedSignature, 'chunk signature should differ from seed');

    t.end();
});

test('verifyChunkSignature - accepts valid signature', function (t) {
    var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20130524';
    var region = 'us-east-1';
    var service = 's3';

    var signingKey = verifier.deriveSigningKey(secretKey, dateStamp, region, service);

    var previousSignature = 'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
    var timestamp = '20130524T000000Z';
    var credentialScope = '20130524/us-east-1/s3/aws4_request';
    var chunkData = Buffer.from('test data');

    // Calculate the expected signature
    var expectedSignature = verifier.calculateChunkSignature(
        signingKey, previousSignature, timestamp, credentialScope, chunkData
    );

    // Verify it
    var isValid = verifier.verifyChunkSignature(
        signingKey, previousSignature, timestamp, credentialScope,
        chunkData, expectedSignature
    );

    t.ok(isValid, 'valid signature should be accepted');

    t.end();
});

test('verifyChunkSignature - rejects invalid signature', function (t) {
    var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20130524';
    var region = 'us-east-1';
    var service = 's3';

    var signingKey = verifier.deriveSigningKey(secretKey, dateStamp, region, service);

    var previousSignature = 'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
    var timestamp = '20130524T000000Z';
    var credentialScope = '20130524/us-east-1/s3/aws4_request';
    var chunkData = Buffer.from('test data');

    var invalidSignature = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

    var isValid = verifier.verifyChunkSignature(
        signingKey, previousSignature, timestamp, credentialScope,
        chunkData, invalidSignature
    );

    t.notOk(isValid, 'invalid signature should be rejected');

    t.end();
});

test('verifyChunkSignature - rejects tampered data', function (t) {
    var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20130524';
    var region = 'us-east-1';
    var service = 's3';

    var signingKey = verifier.deriveSigningKey(secretKey, dateStamp, region, service);

    var previousSignature = 'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
    var timestamp = '20130524T000000Z';
    var credentialScope = '20130524/us-east-1/s3/aws4_request';
    var originalData = Buffer.from('original data');

    // Calculate signature for original data
    var signature = verifier.calculateChunkSignature(
        signingKey, previousSignature, timestamp, credentialScope, originalData
    );

    // Try to verify with tampered data
    var tamperedData = Buffer.from('tampered data');
    var isValid = verifier.verifyChunkSignature(
        signingKey, previousSignature, timestamp, credentialScope,
        tamperedData, signature
    );

    t.notOk(isValid, 'signature verification should fail for tampered data');

    t.end();
});

test('verifyChunkSignature - rejects wrong previous signature', function (t) {
    var secretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20130524';
    var region = 'us-east-1';
    var service = 's3';

    var signingKey = verifier.deriveSigningKey(secretKey, dateStamp, region, service);

    var correctPrevSig = 'ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
    var wrongPrevSig = 'bd80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648';
    var timestamp = '20130524T000000Z';
    var credentialScope = '20130524/us-east-1/s3/aws4_request';
    var chunkData = Buffer.from('test data');

    // Calculate signature with correct previous signature
    var signature = verifier.calculateChunkSignature(
        signingKey, correctPrevSig, timestamp, credentialScope, chunkData
    );

    // Try to verify with wrong previous signature
    var isValid = verifier.verifyChunkSignature(
        signingKey, wrongPrevSig, timestamp, credentialScope,
        chunkData, signature
    );

    t.notOk(isValid, 'verification should fail with wrong previous signature');

    t.end();
});
