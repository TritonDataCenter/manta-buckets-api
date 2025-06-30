/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 MNX Cloud, Inc.
 */

var stream = require('stream');
var util = require('util');
var crypto = require('crypto');

/**
 * AWS Chunked Encoding Decoder
 * 
 * AWS S3 uses a special chunked encoding format when Content-Encoding is 'aws-chunked':
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
        return new AwsChunkedDecoder(options);
    }
    
    stream.Transform.call(this, options);
    
    this._buffer = Buffer.alloc(0);
    this._state = 'chunk-size'; // chunk-size, chunk-data, trailing-headers, complete
    this._chunkSize = 0;
    this._chunkBytesRead = 0;
    this._totalBytesDecoded = 0;
    this._log = options && options.log;
}

util.inherits(AwsChunkedDecoder, stream.Transform);

AwsChunkedDecoder.prototype._transform = function(chunk, encoding, callback) {
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

AwsChunkedDecoder.prototype._processBuffer = function() {
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
                throw new Error('AWS chunked decoder: unexpected state: ' + this._state);
        }
    }
};

AwsChunkedDecoder.prototype._readChunkSize = function() {
    // Look for \r\n to find end of chunk size line
    var crlfIndex = this._buffer.indexOf('\r\n');
    if (crlfIndex === -1) {
        return false; // Need more data
    }
    
    var chunkSizeLine = this._buffer.slice(0, crlfIndex).toString('utf8');
    this._buffer = this._buffer.slice(crlfIndex + 2);
    
    // Parse chunk size line: "1a4;chunk-signature=abcd1234"
    var semicolonIndex = chunkSizeLine.indexOf(';');
    var chunkSizeHex = semicolonIndex !== -1 ? 
        chunkSizeLine.slice(0, semicolonIndex) : 
        chunkSizeLine;
    
    this._chunkSize = parseInt(chunkSizeHex, 16);
    this._chunkBytesRead = 0;
    
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
    
    return true;
};

AwsChunkedDecoder.prototype._readChunkData = function() {
    var bytesNeeded = this._chunkSize - this._chunkBytesRead;
    var bytesAvailable = this._buffer.length;
    
    if (bytesAvailable < bytesNeeded + 2) { // +2 for trailing \r\n
        // Don't have complete chunk yet
        if (bytesAvailable >= bytesNeeded) {
            // We have the data but not the trailing \r\n
            var chunkData = this._buffer.slice(0, bytesNeeded);
            this.push(chunkData);
            this._chunkBytesRead += bytesNeeded;
            this._totalBytesDecoded += bytesNeeded;
            this._buffer = this._buffer.slice(bytesNeeded);
            
            // Check if we now have the \r\n
            if (this._buffer.length >= 2 && 
                this._buffer[0] === 0x0D && this._buffer[1] === 0x0A) {
                this._buffer = this._buffer.slice(2);
                this._state = 'chunk-size';
                return true;
            }
        }
        return false; // Need more data
    }
    
    // We have the complete chunk data + \r\n
    chunkData = this._buffer.slice(0, bytesNeeded);
    this.push(chunkData);
    this._chunkBytesRead += bytesNeeded;
    this._totalBytesDecoded += bytesNeeded;
    
    // Skip the chunk data and trailing \r\n
    this._buffer = this._buffer.slice(bytesNeeded + 2);
    this._state = 'chunk-size';
    
    if (this._log) {
        this._log.debug({
            chunkDataLength: chunkData.length,
            totalDecoded: this._totalBytesDecoded
        }, 'AWS chunked decoder: extracted chunk data');
    }
    
    return true;
};

AwsChunkedDecoder.prototype._readTrailingHeaders = function() {
    // Look for final \r\n\r\n sequence
    var endIndex = this._buffer.indexOf('\r\n\r\n');
    if (endIndex === -1) {
        return false; // Need more data
    }
    
    // Skip trailing headers and final \r\n\r\n
    this._buffer = this._buffer.slice(endIndex + 4);
    this._state = 'complete';
    
    if (this._log) {
        this._log.debug({
            totalBytesDecoded: this._totalBytesDecoded
        }, 'AWS chunked decoder: completed decoding');
    }
    
    return true;
};

AwsChunkedDecoder.prototype._flush = function(callback) {
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
