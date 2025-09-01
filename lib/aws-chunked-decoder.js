/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var stream = require('stream');
var util = require('util');
var crypto = require('crypto');


/*
 * AWS S3 uses a different encoding scheme called Sigv4 Streaming, when
 * Content-Encoding: aws-chunked is set on the headers.
 *
 * This is used for Multipart uploads by AWS cli and AWS SDK libraries probably
 * already use this to deal with large files.
 * The reason is that if are sending several GiBs over the wire, the whole body
 * the s3 clietn does not signs the  whole body as usual, instead the s3 client
 * signs every chunk sent.
 *
 *
 * The implementation for this consists in a state machine with the following
 * states:
 *
 * 1. State 'chunk-size' :
 *    Extracts the size of the chunk, and percolates the data size in bytes
 *    to the 'chunk-data' state, if the chunk-size is 0 it means is the
 *    final chunk and transitions  to TrailersHeaders.
 *
 * 2. State 'chunk-data' :
 *    Reads the payload data from the chunk using the data size passed in state
 *    1, and reads until all data is consumed or a new chunk is reached. It
 *    transitions to chunk-size.
 *
 * 3. State 'TrailerHeaders':
 *    Transitioning to this state means that this is the final chunk, there is
 *    no more data to process, and we just extract the headers that come in
 *    this chunk to provide to the mpu clients checksum data, the headers here
 *    should be x-amz-checksum-sha256 and x-amz-meta-custom.
 *
 * Chunk Format:
 *
 *   - Data Chunk
 *
 *       +---------------------------+
 *       | Chunk Size (hex)          |  "5"
 *       +---------------------------+
 *       | Separator                 |  ";"
 *       +---------------------------+
 *       | Chunk Extension           |  "chunk-signature=d2a5c4b0...34aa"
 *       +---------------------------+
 *       | CRLF                      |  "\r\n"
 *       +---------------------------+
 *       | Chunk Data (bytes)        |  01 02 03
 *       +---------------------------+
 *       | CRLF                      |  "\r\n"
 *       +---------------------------+
 *
 *  - Final Chunk
 *
 *      +---------------------------+
 *       | Chunk Size (hex)          |  "0"
 *       +---------------------------+
 *       | Chunk Extension           |  "chunk-signature=<final-sig>"
 *       +---------------------------+
 *       | CRLF                      |  "\r\n"
 *       +---------------------------+
 *       | Trailer Headers (optional)|  (empty in AWS)
 *       +---------------------------+
 *       | CRLF                      |  "\r\n"
 *       +---------------------------+
 *
 * State Machine flow:
 *
 *                      (Start)
 *                         |
 *                         v
 *                 +-------------------+
 *                 |   Chunk-Size      |
 *                 | [;chunk-signature]|
 *                 +-------------------+
 *                          |
 *                          v
 *                 +-------------------+
 *                 |   CRLF (end line) |
 *                 +-------------------+
 *                          |
 *                          v
 *                 +-------------------+
 *                 |   Chunk-Data      |  <-- payload bytes (N bytes)
 *                 +-------------------+
 *                          |
 *                          v
 *                 +-------------------+
 *                 |   CRLF (end data) |
 *                 +-------------------+
 *                          |
 *        +-----------------+----------------+
 *        |                                  |
 *        | (if size > 0)                    | (if size = 0)
 *        v                                  v
 *  (loop back to Chunk-Size)        +-------------------+
 *                                   | TrailerHeaders    |
 *                                   +-------------------+
 *                                            |
 *                                            v
 *                                   +-------------------+
 *                                   |   Final CRLF      |
 *                                   +-------------------+
 *                                            |
 *                                            v
 *                                         [END]
 *  References:
 *  - https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
 *  - RFC 9112 https://datatracker.ietf.org/doc/html/rfc9112
 */

/*
 * AWS Chunked Encoding Decoder
 *
 * AWS S3 uses a special chunked encoding format when Content-Encoding is
 * 'aws-chunked':
 *
 * Format:
 * [chunk-size in hex];chunk-signature=[signature]\r\n
 * [chunk-data]\r\n
 * [chunk-size in hex];chunk-signature=[signature]\r\n
 * [chunk-data]\r\n
 * 0;chunk-signature=[final-signature]\r\n
 * [optional trailing headers]\r\n
 * \r\n
 *
 * This decoder strips the AWS chunk metadata and extracts only the actual data.
 */
function AwsChunkedDecoder(options) {
    if (!(this instanceof AwsChunkedDecoder)) {
        return (new AwsChunkedDecoder(options));
    }
    stream.Transform.call(this, options);
    this._buffer = Buffer.alloc(0);
    this._state = 'chunk-size';
    // chunk-size, chunk-data, trailing-headers, complete
    this._chunkSize = 0;
    this._chunkBytesRead = 0;
    this._totalBytesDecoded = 0;
    this._log = options && options.log;
}

util.inherits(AwsChunkedDecoder, stream.Transform);

AwsChunkedDecoder.prototype._transform = function (chunk, encoding, callback) {
    // Don't process data if we're already complete
    if (this._state === 'complete') {
        callback();
        return;
    }

    this._buffer = Buffer.concat([this._buffer, chunk]);

    try {
        this._processBuffer();
        callback();
    } catch (err) {
        if (this._log) {
            this._log.error({
                error: err.message,
                state: this._state,
                bufferLength: this._buffer.length
            }, 'AWS chunked decoder error');
        }
        callback(err);
    }
};

AwsChunkedDecoder.prototype._processBuffer = function () {
    while (this._buffer.length > 0 && this._state !== 'complete') {
        switch (this._state) {
            case 'chunk-size':
                if (!this._readChunkSize()) {
                    return; // Need more data
                }
                break;

            case 'chunk-data':
                if (!this._readChunkData()) {
                    return; // Need more data
                }
                break;

            case 'trailing-headers':
                if (!this._readTrailingHeaders()) {
                    return; // Need more data
                }
                break;

            default:
                if (this._log) {
                    this._log.error({
                        unexpectedState: this._state,
                        bufferLength: this._buffer.length
                    }, 'AWS chunked decoder: unexpected state');
                }
                throw new Error('AWS chunked decoder: unexpected state: '
                + this._state);
        }
    }
};

AwsChunkedDecoder.prototype._readChunkSize = function () {
    // Look for \r\n to find end of chunk size line
    var crlfIndex = this._buffer.indexOf('\r\n');
    if (crlfIndex === -1) {
        return (false); // Need more data
    }

    /*
     * State: chunk-size
     *
     * This step/phase decodes the chunk size from the input chunk,
     * so the chunk-data step knows how many bytes to read from the actual
     * data.
     *
     * An input chunk looks like the following:
     *
     *  1a4;chunk-signature=a-valid-signature-here\r\n
     *   <actual data>\r\n
     *
     *  1. Read the first line of chunk where the size (in hex)
     *    of the data chunk is.
     */
    var chunkSizeLine = this._buffer.slice(0, crlfIndex).toString('utf8');
    this._buffer = this._buffer.slice(crlfIndex + 2);

    /*
     * 2. Parse chunk size line from 1.:
     *  1a4;chunk-signature=a-valid-signature-here\r\n
     *
     * The size of the chunk data is on the first element before the semicolon.
     * In this example, the chunk data size is : 0x1a4, this is the actual
     * data that we want to extract from the chunk.
     */
    var semicolonIndex = chunkSizeLine.indexOf(';');
    var chunkSizeHex = semicolonIndex !== -1 ?
        chunkSizeLine.slice(0, semicolonIndex) :
        chunkSizeLine;

    this._chunkSize = parseInt(chunkSizeHex, 16);
    this._chunkBytesRead = 0;

    /*
     * 3. If the chunk size is not 0, it means we have more chunks to process,
     *    a chunk of size 0 signals that is the last chunk, so we move the state
     *    machine to the state 'chunk-data'
     */

    if (this._chunkSize === 0) {
        // Final chunk - move to trailing headers
        this._state = 'trailing-headers';
    } else {
        this._state = 'chunk-data';
    }

    if (this._log) {
        this._log.debug({
            chunkSizeLine: chunkSizeLine,
            chunkSize: this._chunkSize,
            state: this._state
        }, 'AWS chunked decoder: parsed chunk size');
    }

    return (true);
};


/*
 * This is state 2 ('chunk-data') from the AWS chunk decoder state machine,
 * in the previous step we extracted the chunk data size, so we know
 * now in this step how many bytes to read to extract the data we need.
 */

AwsChunkedDecoder.prototype._readChunkData = function () {
    var bytesNeeded = this._chunkSize - this._chunkBytesRead;
    var bytesAvailable = this._buffer.length;
    var chunkData;

    if (bytesAvailable < bytesNeeded + 2) { // +2 for trailing \r\n
        // Don't have complete chunk yet
        if (bytesAvailable >= bytesNeeded && bytesNeeded > 0) {
            // We have the data but not the trailing \r\n
            chunkData = this._buffer.slice(0, bytesNeeded);
            // send the data
            this.push(chunkData);
            this._chunkBytesRead += bytesNeeded;
            this._totalBytesDecoded += bytesNeeded;
            this._buffer = this._buffer.slice(bytesNeeded);

            /*
             * Check if we now have the \r\n (0x0D 0x0A), this means
             * we need to read another chunk as this one ended, so
             * we need to transition to state 'chunk-size' to read the
             * size of the next chunk.
             */
            if (this._buffer.length >= 2 &&
                this._buffer[0] === 0x0D && this._buffer[1] === 0x0A) {
                this._buffer = this._buffer.slice(2);
                this._state = 'chunk-size';
                this._chunkBytesRead = 0; // Reset for next chunk
                return (true);
            }
            // Return here to prevent double processing
            return (false);
        }
        return (false); // Need more data
    }

    // We have the complete chunk data + \r\n
    if (bytesNeeded > 0) {
        chunkData = this._buffer.slice(0, bytesNeeded);
        this.push(chunkData);
        this._chunkBytesRead += bytesNeeded;
        this._totalBytesDecoded += bytesNeeded;
    }

    // Skip the chunk data and trailing \r\n
    this._buffer = this._buffer.slice(bytesNeeded + 2);
    this._state = 'chunk-size';
    this._chunkBytesRead = 0; // Reset for next chunk

    if (this._log) {
        this._log.debug({
            chunkDataLength: chunkData.length,
            totalDecoded: this._totalBytesDecoded
        }, 'AWS chunked decoder: extracted chunk data');
    }

    return (true);
};

/*
 * State 3 (trailerHeaders) :
 * This state signals that this is the final chunk, so we need to stop reading,
 * and mark it as as complete.
 * We transition to this state if chunksize is zero.
 */
AwsChunkedDecoder.prototype._readTrailingHeaders = function () {
    // Look for final \r\n\r\n sequence
    var endIndex = this._buffer.indexOf('\r\n\r\n');
    if (endIndex === -1) {
        return (false); // Need more data
    }

    // Parse trailing headers before consuming them
    var trailingHeadersStr = this._buffer.slice(0, endIndex).toString('utf8');
    var trailerHeaders = {};

    if (trailingHeadersStr.length > 0) {
        var headerLines = trailingHeadersStr.split('\r\n');
        headerLines.forEach(function (line) {
            var colonIndex = line.indexOf(':');
            if (colonIndex !== -1) {
                var headerName = line.slice(0, colonIndex).trim().toLowerCase();
                var headerValue = line.slice(colonIndex + 1).trim();
                trailerHeaders[headerName] = headerValue;
            }
        });

        if (this._log) {
            this._log.debug({
                trailerHeaders: trailerHeaders
            }, 'AWS chunked decoder: parsed trailer headers');
        }

        // Emit trailer headers for multipart upload handling
        this.emit('trailerHeaders', trailerHeaders);
    }

    // Skip trailing headers and final \r\n\r\n
    this._buffer = this._buffer.slice(endIndex + 4);
    this._state = 'complete';

    if (this._log) {
        this._log.debug({
            totalBytesDecoded: this._totalBytesDecoded,
            hadTrailers: Object.keys(trailerHeaders).length > 0
        }, 'AWS chunked decoder: completed decoding');
    }

    // Signal end of stream
    this.push(null);

    return (true);
};

AwsChunkedDecoder.prototype._flush = function (callback) {
    if (this._state !== 'complete') {
        if (this._log) {
            this._log.warn({
                state: this._state,
                bufferLength: this._buffer.length,
                totalDecoded: this._totalBytesDecoded
            }, 'AWS chunked decoder: incomplete decode on flush');
        }
    }

    callback();
};

module.exports = AwsChunkedDecoder;
