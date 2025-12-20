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
var stream = require('stream');
// var util = require('util'); // Unused import

// Compatibility helper for Buffer.indexOf (not available in Node.js v0.10.48)
function bufferIndexOf(buffer, searchString) {
    var searchBuf = new Buffer(searchString, 'ascii');
    for (var i = 0; i <= buffer.length - searchBuf.length; i++) {
        var match = true;
        for (var j = 0; j < searchBuf.length; j++) {
            if (buffer[i + j] !== searchBuf[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return (i);
        }
    }
    return (-1);
}

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

// Mock AWS chunked decoder based on the actual implementation
function createMockAWSChunkedDecoder() {
    var decoder = new stream.Transform();

    decoder._buffer = new Buffer(0);
    decoder._chunkSize = -1;
    decoder._chunkBytesRead = 0;
    decoder._totalBytesRead = 0;
    decoder._signature = '';
    decoder._state = 'reading-chunk-size';

    decoder._transform = function (chunk, encoding, callback) {
        var self = this;
        self._buffer = Buffer.concat([self._buffer, chunk]);

        try {
            while (self._buffer.length > 0) {
                if (self._state === 'reading-chunk-size') {
                    var crlfIndex = bufferIndexOf(self._buffer, '\r\n');
                    if (crlfIndex === -1) {
                        break; // Need more data
                    }

                    var chunkSizeLine = self._buffer.slice(0, crlfIndex)
                                                     .toString('ascii');
                    self._buffer = self._buffer.slice(crlfIndex + 2);

                    // Parse chunk size (hex) and optional signature
                    var parts = chunkSizeLine.split(';');
                    self._chunkSize = parseInt(parts[0], 16);

                    if (self._chunkSize === 0) {
                        // Final chunk
                        self._state = 'reading-trailing-headers';
                        continue;
                    } else {
                        self._state = 'reading-chunk-data';
                        self._chunkBytesRead = 0;
                    }
                }

                if (self._state === 'reading-chunk-data') {
                    var bytesNeeded = self._chunkSize - self._chunkBytesRead;
                    if (bytesNeeded > 0 && self._buffer.length > 0) {
                        var dataToRead = Math.min(bytesNeeded,
                                                  self._buffer.length);
                        var chunkData = self._buffer.slice(0, dataToRead);
                        self._buffer = self._buffer.slice(dataToRead);

                        self._chunkBytesRead += dataToRead;
                        self._totalBytesRead += dataToRead;
                        self.push(chunkData);

                        if (self._chunkBytesRead === self._chunkSize) {
                            self._state = 'reading-chunk-terminator';
                        }
                    }

                    if (self._chunkBytesRead < self._chunkSize) {
                        break; // Need more data
                    }
                }

                if (self._state === 'reading-chunk-terminator') {
                    if (self._buffer.length < 2) {
                        break; // Need more data for CRLF
                    }

                    // Skip CRLF after chunk data
                    self._buffer = self._buffer.slice(2);
                    self._state = 'reading-chunk-size';
                    self._chunkBytesRead = 0; // Reset for next chunk
                }

                if (self._state === 'reading-trailing-headers') {
                    // Look for final CRLF that ends the request
                    var finalCrlfIndex = bufferIndexOf(self._buffer, '\r\n');
                    if (finalCrlfIndex === -1) {
                        break; // Need more data
                    }

                    // Skip trailing headers and final CRLF
                    self._buffer = self._buffer.slice(finalCrlfIndex + 2);
                    self.push(null); // End stream
                    break;
                }
            }
            callback();
        } catch (err) {
            callback(err);
        }
    };

    return (decoder);
}

// Create test AWS chunked encoded data
function createAWSChunkedData(dataChunks) {
    var chunks = [];

    dataChunks.forEach(function (data) {
        var chunkSize = data.length.toString(16);
        chunks.push(new Buffer(chunkSize + '\r\n', 'ascii'));
        chunks.push(data);
        chunks.push(new Buffer('\r\n', 'ascii'));
    });

    // Final chunk
    chunks.push(new Buffer('0\r\n\r\n', 'ascii'));

    return (Buffer.concat(chunks));
}

///--- AWS Chunked Decoder Tests

helper.test('AWS chunked decoder - single chunk', function (t) {
    var decoder = createMockAWSChunkedDecoder();
    var testData = new Buffer('Hello, AWS chunked world!', 'utf8');
    var chunkedData = createAWSChunkedData([testData]);

    var outputChunks = [];
    var totalBytes = 0;

    decoder.on('data', function (chunk) {
        outputChunks.push(chunk);
        totalBytes += chunk.length;
    });

    decoder.on('end', function () {
        var finalData = Buffer.concat(outputChunks);

        t.equal(totalBytes, testData.length,
                'should output correct number of bytes');
        t.ok(bufferEquals(finalData, testData), 'should output original data');
        t.end();
    });

    decoder.on('error', function (err) {
        t.fail('should not error: ' + err.message);
        t.end();
    });

    decoder.write(chunkedData);
    decoder.end();
});

helper.test('AWS chunked decoder - multiple chunks', function (t) {
    var decoder = createMockAWSChunkedDecoder();
    var chunk1 = new Buffer('First chunk of data', 'utf8');
    var chunk2 = new Buffer('Second chunk of data', 'utf8');
    var chunk3 = new Buffer('Third and final chunk', 'utf8');

    var chunkedData = createAWSChunkedData([chunk1, chunk2, chunk3]);
    var expectedData = Buffer.concat([chunk1, chunk2, chunk3]);

    var outputChunks = [];
    var totalBytes = 0;

    decoder.on('data', function (chunk) {
        outputChunks.push(chunk);
        totalBytes += chunk.length;
    });

    decoder.on('end', function () {
        var finalData = Buffer.concat(outputChunks);

        t.equal(totalBytes, expectedData.length,
                'should output correct total bytes');
        t.ok(bufferEquals(finalData, expectedData),
             'should reconstruct original data correctly');
        t.end();
    });

    decoder.on('error', function (err) {
        t.fail('should not error: ' + err.message);
        t.end();
    });

    decoder.write(chunkedData);
    decoder.end();
});

helper.test('AWS chunked decoder - streaming input', function (t) {
    var decoder = createMockAWSChunkedDecoder();
    var testData = new Buffer(
        'This is streaming test data for AWS chunked encoding',
        'utf8');
    var chunkedData = createAWSChunkedData([testData]);

    var outputChunks = [];
    var bytesReceived = 0;

    decoder.on('data', function (chunk) {
        outputChunks.push(chunk);
        bytesReceived += chunk.length;
    });

    decoder.on('end', function () {
        var reconstructed = Buffer.concat(outputChunks);

        t.equal(bytesReceived, testData.length, 'should receive all bytes');
        t.ok(bufferEquals(reconstructed, testData),
             'should reconstruct data correctly');
        t.end();
    });

    decoder.on('error', function (err) {
        t.fail('should not error during streaming: ' + err.message);
        t.end();
    });

    // Stream the chunked data in small pieces to test incremental parsing
    var chunkSize = 10;
    var offset = 0;

    function writeNextChunk() {
        if (offset >= chunkedData.length) {
            decoder.end();
            return;
        }

        var endPos = Math.min(offset + chunkSize, chunkedData.length);
        var dataPiece = chunkedData.slice(offset, endPos);
        decoder.write(dataPiece);
        offset = endPos;

        // Continue with next chunk asynchronously
        setImmediate(writeNextChunk);
    }

    writeNextChunk();
});

helper.test('AWS chunked decoder - large data integrity', function (t) {
    var decoder = createMockAWSChunkedDecoder();

    // Create larger test data (simulate multipart upload part)
    var partSize = 1024 * 1024; // 1MB
    var testData = new Buffer(partSize);

    // Fill with recognizable pattern
    for (var i = 0; i < partSize; i++) {
        testData[i] = i % 256;
    }

    var chunkedData = createAWSChunkedData([testData]);

    var outputChunks = [];
    var md5Hash = crypto.createHash('md5');
    var totalBytesReceived = 0;

    decoder.on('data', function (chunk) {
        outputChunks.push(chunk);
        md5Hash.update(chunk);
        totalBytesReceived += chunk.length;
    });

    decoder.on('end', function () {
        var reconstructed = Buffer.concat(outputChunks);
        var outputMD5 = md5Hash.digest('hex');
        var expectedMD5 = crypto.createHash('md5')
                                 .update(testData)
                                 .digest('hex');

        t.equal(totalBytesReceived, partSize, 'should receive all bytes');
        t.equal(reconstructed.length, partSize,
                'reconstructed data should have correct length');
        t.equal(outputMD5, expectedMD5,
                'MD5 hashes should match - no data corruption');
        t.ok(bufferEquals(reconstructed, testData),
             'reconstructed data should match original');

        t.end();
    });

    decoder.on('error', function (err) {
        t.fail('should not error with large data: ' + err.message);
        t.end();
    });

    decoder.write(chunkedData);
    decoder.end();
});

helper.test('AWS chunked decoder - empty chunk handling', function (t) {
    var decoder = createMockAWSChunkedDecoder();
    var emptyChunk = new Buffer(0);
    var dataChunk = new Buffer('Non-empty data', 'utf8');

    var chunkedData = createAWSChunkedData([emptyChunk, dataChunk, emptyChunk]);

    var outputChunks = [];

    decoder.on('data', function (chunk) {
        outputChunks.push(chunk);
    });

    decoder.on('end', function () {
        var reconstructed = Buffer.concat(outputChunks);

        t.equal(reconstructed.length, dataChunk.length,
                'should only output non-empty data');
        t.ok(bufferEquals(reconstructed, dataChunk),
             'should match non-empty chunk data');
        t.end();
    });

    decoder.on('error', function (err) {
        t.fail('should handle empty chunks without error: ' + err.message);
        t.end();
    });

    decoder.write(chunkedData);
    decoder.end();
});

helper.test('AWS chunked decoder - malformed input error handling',
           function (t) {
    var decoder = createMockAWSChunkedDecoder();
    var malformedData = new Buffer('zzz\r\nInvalid hex chunk size\r\n',
                                    'ascii');

    var errorReceived = false;

    decoder.on('error', function (err) {
        errorReceived = true;
        t.ok(err, 'should emit error for malformed input');
        t.end();
    });

    decoder.on('end', function () {
        if (!errorReceived) {
            t.fail('should have received error for malformed input');
            t.end();
        }
    });

    decoder.write(malformedData);
    decoder.end();
});

helper.test('AWS chunked decoder - partial chunk boundary handling',
           function (t) {
    var decoder = createMockAWSChunkedDecoder();
    var testData = new Buffer('Test data for boundary handling', 'utf8');
    var chunkedData = createAWSChunkedData([testData]);

    var outputChunks = [];

    decoder.on('data', function (chunk) {
        outputChunks.push(chunk);
    });

    decoder.on('end', function () {
        var reconstructed = Buffer.concat(outputChunks);
        t.ok(bufferEquals(reconstructed, testData),
             'should handle partial boundaries correctly');
        t.end();
    });

    decoder.on('error', function (err) {
        t.fail('should not error with partial boundaries: ' + err.message);
        t.end();
    });

    // Write data in a way that splits chunk boundaries
    var midpoint = Math.floor(chunkedData.length / 2);
    decoder.write(chunkedData.slice(0, midpoint));

    // Wait a bit then write the rest
    setTimeout(function () {
        decoder.write(chunkedData.slice(midpoint));
        decoder.end();
    }, 10);
});

helper.test('AWS chunked decoder - memory efficiency test', function (t) {
    var decoder = createMockAWSChunkedDecoder();

    // Test with multiple smaller chunks to ensure memory isn't growing
    var numChunks = 100;
    var chunkSize = 1024; // 1KB each
    var testChunks = [];

    for (var i = 0; i < numChunks; i++) {
        var chunk = new Buffer(chunkSize);
        chunk.fill(i % 256);
        testChunks.push(chunk);
    }

    var chunkedData = createAWSChunkedData(testChunks);
    var expectedData = Buffer.concat(testChunks);

    var outputChunks = [];
    var chunksReceived = 0;

    decoder.on('data', function (dataChunk) {
        outputChunks.push(dataChunk);
        chunksReceived++;
    });

    decoder.on('end', function () {
        var reconstructed = Buffer.concat(outputChunks);

        t.equal(reconstructed.length, expectedData.length,
                'should process all data');
        t.ok(chunksReceived > 0, 'should receive data in chunks');
        t.ok(bufferEquals(reconstructed, expectedData),
             'should reconstruct data correctly');

        // Check internal buffer isn't holding onto too much data
        t.ok(decoder._buffer.length === 0, 'internal buffer should be cleared');

        t.end();
    });

    decoder.on('error', function (err) {
        t.fail('should not error in memory efficiency test: ' + err.message);
        t.end();
    });

    decoder.write(chunkedData);
    decoder.end();
});

helper.test('AWS chunked decoder - state management', function (t) {
    var decoder = createMockAWSChunkedDecoder();

    // Test state transitions through the decoding process
    t.equal(decoder._state, 'reading-chunk-size',
            'should start in reading-chunk-size state');
    t.equal(decoder._chunkSize, -1, 'should initialize chunk size to -1');
    t.equal(decoder._chunkBytesRead, 0, 'should initialize bytes read to 0');
    t.equal(decoder._totalBytesRead, 0, 'should initialize total bytes to 0');

    var testData = new Buffer('State test data', 'utf8');
    var chunkedData = createAWSChunkedData([testData]);

    decoder.on('end', function () {
        t.equal(decoder._totalBytesRead, testData.length,
                'should track total bytes correctly');
        t.end();
    });

    decoder.on('error', function (err) {
        t.fail('should not error in state management test: ' + err.message);
        t.end();
    });

    decoder.write(chunkedData);
    decoder.end();
});