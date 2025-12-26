/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * Real AWS Chunked Decoder Signature Verification Tests
 *
 * These tests use the actual AwsChunkedDecoder implementation to test
 * signature verification functionality. This ensures that signature
 * verification errors are properly thrown and can be caught in unit tests.
 */

var helper = require('./s3-test-helper.js');

// Import real decoder for signature verification tests
var AwsChunkedDecoder = require('../lib/aws-chunked-decoder');
var errors = require('../lib/errors');
var verifier = require('../lib/aws-chunked-signature-verifier');

// Compatibility helper for Buffer.equals (not available in Node.js v0.10.48)
function bufferEquals(buf1, buf2) {
    if (buf1.length !== buf2.length) {
        return (false);
    }
    for (var i = 0; i < buf1.length; i++) {
        if (buf1[i] !== buf2[i]) {
            return (false);
        }
    }
    return (true);
}

// Helper to create AWS chunked data with signatures
function
createSignedChunkedData(dataChunks, signingKey, timestamp, credentialScope,
    seedSignature)
{
    var chunks = [];
    var previousSignature = seedSignature;

    dataChunks.forEach(function (data) {
        var chunkSize = data.length.toString(16);
        var signature = verifier.calculateChunkSignature(
            signingKey,
            previousSignature,
            timestamp,
            credentialScope,
            data);

        chunks.push(new Buffer(
            chunkSize + ';chunk-signature=' + signature + '\r\n',
            'ascii'));
        chunks.push(data);
        chunks.push(new Buffer('\r\n', 'ascii'));

        previousSignature = signature;
    });

    // Final chunk
    chunks.push(new Buffer('0;chunk-signature=' +
        verifier.calculateChunkSignature(
            signingKey,
            previousSignature,
            timestamp,
            credentialScope,
            new Buffer(0)) + '\r\n\r\n', 'ascii'));

    return (Buffer.concat(chunks));
}

///--- Real Decoder Signature Verification Tests

helper.test('Real decoder - signature verification with valid signatures',
           function (t) {
    // Setup verification context
    var secretKey = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20250124';
    var region = 'us-east-1';
    var service = 's3';
    var timestamp = '20250124T123456Z';
    var credentialScope = dateStamp + '/' + region + '/' +
        service + '/aws4_request';
    var seedSignature = 'a' + Array(64).join('b');

    var signingKey = verifier.deriveSigningKey(
        secretKey,
        dateStamp,
        region,
        service);

    var testData1 = new Buffer('First chunk data', 'utf8');
    var testData2 = new Buffer('Second chunk data', 'utf8');
    var expectedData = Buffer.concat([testData1, testData2]);

    var signedChunkedData = createSignedChunkedData(
        [testData1, testData2],
        signingKey,
        timestamp,
        credentialScope,
        seedSignature);

    var decoder = new AwsChunkedDecoder({
        log: {
            debug: function () {},
            error: function () {}
        },
        seedSignature: seedSignature,
        signingKey: signingKey,
        timestamp: timestamp,
        credentialScope: credentialScope,
        validateSignatures: true});

    var outputChunks = [];

    decoder.on('data', function (chunk) {
        outputChunks.push(chunk);
    });

    decoder.on('end', function () {
        var reconstructed = Buffer.concat(outputChunks);
        t.ok(bufferEquals(reconstructed, expectedData),
             'should decode data with valid signatures');
        t.end();
    });

    decoder.on('error', function (err) {
        t.fail('should not error with valid signatures: ' + err.message);
        t.end();
    });

    decoder.write(signedChunkedData);
    decoder.end();
});

helper.test('Real decoder - signature verification fails with invalid ' +
           'signature', function (t) {
    // Setup verification context
    var secretKey = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20250124';
    var region = 'us-east-1';
    var service = 's3';
    var timestamp = '20250124T123456Z';
    var credentialScope = dateStamp + '/' + region + '/' +
        service + '/aws4_request';
    var seedSignature = 'a' + Array(64).join('b');

    var signingKey = verifier.deriveSigningKey(
        secretKey,
        dateStamp,
        region,
        service);

    var testData = new Buffer('Test chunk data', 'utf8');

    // Create data with intentionally WRONG signature
    var invalidSignature = 'deadbeef' + Array(57).join('0');
    var chunkSize = testData.length.toString(16);
    var maliciousChunkedData = Buffer.concat([
        new Buffer(chunkSize + ';chunk-signature=' +
            invalidSignature + '\r\n', 'ascii'),
        testData,
        new Buffer('\r\n0\r\n\r\n', 'ascii')
    ]);

    var decoder = new AwsChunkedDecoder({
        log: {
            debug: function () {},
            error: function () {}
        },
        seedSignature: seedSignature,
        signingKey: signingKey,
        timestamp: timestamp,
        credentialScope: credentialScope,
        validateSignatures: true});

    var errorReceived = false;

    decoder.on('data', function () {
        t.fail('should not emit data with invalid signature');
    });

    decoder.on('error', function (err) {
        errorReceived = true;
        t.ok(err instanceof errors.InvalidChunkSignatureError,
             'should throw InvalidChunkSignatureError');
        t.ok(err.message.indexOf('chunk signature') !== -1,
             'error message should mention chunk signature');
        t.end();
    });

    decoder.on('end', function () {
        if (!errorReceived) {
            t.fail('should have received error for invalid signature');
            t.end();
        }
    });

    decoder.write(maliciousChunkedData);
    decoder.end();
});

helper.test('Real decoder - signature verification detects tampered data',
           function (t) {
    // Setup verification context
    var secretKey = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20250124';
    var region = 'us-east-1';
    var service = 's3';
    var timestamp = '20250124T123456Z';
    var credentialScope = dateStamp + '/' + region + '/' +
        service + '/aws4_request';
    var seedSignature = 'a' + Array(64).join('b');

    var signingKey = verifier.deriveSigningKey(
        secretKey,
        dateStamp,
        region,
        service);

    var originalData = new Buffer('Original chunk data', 'utf8');
    var tamperedData = new Buffer('Tampered chunk data', 'utf8');

    // Calculate signature for original data
    var validSignature = verifier.calculateChunkSignature(
        signingKey,
        seedSignature,
        timestamp,
        credentialScope,
        originalData);

    // Create chunked data with valid signature but TAMPERED data
    var chunkSize = tamperedData.length.toString(16);
    var maliciousChunkedData = Buffer.concat([
        new Buffer(chunkSize + ';chunk-signature=' +
            validSignature + '\r\n', 'ascii'),
        tamperedData,  // Data doesn't match signature!
        new Buffer('\r\n0\r\n\r\n', 'ascii')
    ]);

    var decoder = new AwsChunkedDecoder({
        log: {
            debug: function () {},
            error: function () {}
        },
        seedSignature: seedSignature,
        signingKey: signingKey,
        timestamp: timestamp,
        credentialScope: credentialScope,
        validateSignatures: true});

    var errorReceived = false;

    decoder.on('data', function () {
        t.fail('should not emit tampered data');
    });

    decoder.on('error', function (err) {
        errorReceived = true;
        t.ok(err instanceof errors.InvalidChunkSignatureError,
             'should throw InvalidChunkSignatureError for tampered data');
        t.end();
    });

    decoder.on('end', function () {
        if (!errorReceived) {
            t.fail('should have detected tampered data');
            t.end();
        }
    });

    decoder.write(maliciousChunkedData);
    decoder.end();
});

helper.test('Real decoder - signature chain break detection', function (t) {
    // Setup verification context
    var secretKey = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20250124';
    var region = 'us-east-1';
    var service = 's3';
    var timestamp = '20250124T123456Z';
    var credentialScope = dateStamp + '/' + region + '/' +
        service + '/aws4_request';
    var seedSignature = 'a' + Array(64).join('b');

    var signingKey = verifier.deriveSigningKey(
        secretKey,
        dateStamp,
        region,
        service);

    var chunk1 = new Buffer('First chunk', 'utf8');
    var chunk2 = new Buffer('Second chunk', 'utf8');

    // Calculate signatures correctly for first chunk
    var sig1 = verifier.calculateChunkSignature(
        signingKey,
        seedSignature,
        timestamp,
        credentialScope,
        chunk1);

    // BREAK THE CHAIN: Calculate second signature with WRONG previous
    // signature
    var wrongPrevious = 'f' + Array(64).join('0');
    var sig2 = verifier.calculateChunkSignature(
        signingKey,
        wrongPrevious,  // Should be sig1, not wrongPrevious!
        timestamp,
        credentialScope,
        chunk2);

    // Create chunked data with broken signature chain
    var brokenChainData = Buffer.concat([
        new Buffer(chunk1.length.toString(16) + ';chunk-signature=' +
            sig1 + '\r\n', 'ascii'),
        chunk1,
        new Buffer('\r\n', 'ascii'),
        new Buffer(chunk2.length.toString(16) + ';chunk-signature=' +
            sig2 + '\r\n', 'ascii'),
        chunk2,
        new Buffer('\r\n0\r\n\r\n', 'ascii')
    ]);

    var decoder = new AwsChunkedDecoder({
        log: {
            debug: function () {},
            error: function () {}
        },
        seedSignature: seedSignature,
        signingKey: signingKey,
        timestamp: timestamp,
        credentialScope: credentialScope,
        validateSignatures: true});

    var errorReceived = false;
    var firstChunkReceived = false;

    decoder.on('data', function () {
        if (!firstChunkReceived) {
            firstChunkReceived = true;
        } else {
            t.fail('should not emit second chunk with broken chain');
        }
    });

    decoder.on('error', function (err) {
        errorReceived = true;
        t.ok(err instanceof errors.InvalidChunkSignatureError,
             'should throw InvalidChunkSignatureError for broken chain');
        t.ok(firstChunkReceived,
             'first chunk should have been processed before chain break');
        t.end();
    });

    decoder.on('end', function () {
        if (!errorReceived) {
            t.fail('should have detected broken signature chain');
            t.end();
        }
    });

    decoder.write(brokenChainData);
    decoder.end();
});

helper.test('Real decoder - validation disabled allows any signature',
           function (t) {
    // When validateSignatures is false, decoder should accept invalid sigs
    var testData = new Buffer('Test data', 'utf8');
    var chunkSize = testData.length.toString(16);
    var invalidSignature = 'invalid' + Array(58).join('0');

    var chunkedDataWithBadSig = Buffer.concat([
        new Buffer(chunkSize + ';chunk-signature=' +
            invalidSignature + '\r\n', 'ascii'),
        testData,
        new Buffer('\r\n0\r\n\r\n', 'ascii')
    ]);

    var decoder = new AwsChunkedDecoder({
        log: {
            debug: function () {},
            error: function () {}
        },
        validateSignatures: false});  // Disabled!

    var outputChunks = [];

    decoder.on('data', function (chunk) {
        outputChunks.push(chunk);
    });

    decoder.on('end', function () {
        var reconstructed = Buffer.concat(outputChunks);
        t.ok(bufferEquals(reconstructed, testData),
             'should accept data when validation is disabled');
        t.end();
    });

    decoder.on('error', function (err) {
        t.fail('should not error when validation disabled: ' + err.message);
        t.end();
    });

    decoder.write(chunkedDataWithBadSig);
    decoder.end();
});
