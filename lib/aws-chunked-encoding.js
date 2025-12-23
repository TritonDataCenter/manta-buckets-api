/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * AWS Chunked Encoding Handler for S3 Multipart Uploads
 *
 * For aws-chunked MPU, ensure metadata records use the decoded size
 * per S3 spec: Content-Length is encoded size,
 * x-amz-decoded-content-length is the actual payload size.
 *
 * Reference: AWS S3 API Documentation - Chunked Upload Encoding
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
 *
 * Why? Because we stored the encoded size in metadata, but sent decoded
 * size data to disk, causing a size mismatch when Mako validates the
 * assembled multipart object.
 */

var assert = require('assert-plus');
var constants = require('./constants');

/**
 * Check if request uses AWS chunked encoding
 */
function isAwsChunked(headers) {
    assert.object(headers, 'headers');
    return (headers['content-encoding'] === 'aws-chunked');
}

/**
 * Get decoded content length from AWS chunked headers
 */
function getDecodedSize(headers) {
    assert.object(headers, 'headers');

    if (!headers[constants.S3_HEADERS.DECODED_CONTENT_LENGTH]) {
        return (null);
    }

    var decodedSize = parseInt(
        headers[constants.S3_HEADERS.DECODED_CONTENT_LENGTH], 10);

    return (isNaN(decodedSize) ? null : decodedSize);
}

/**
 * Configure part request for AWS chunked encoding
 *
 * CRITICAL: Set _size to decoded size so metadata stores correct size.
 * Content-Length remains encoded size per S3 spec.
 *
 * Not doing this will cause Mako to fail on V2 commit with error:
 * "there is a discrepancy in one of the parts"
 *
 * Why? Because we stored the encoded size in metadata, but sent
 * decoded size data to disk, causing a size mismatch.
 */
function configureAwsChunkedEncoding(req, partReq, partNumber, uploadId) {
    assert.object(req, 'req');
    assert.object(partReq, 'partReq');
    assert.number(partNumber, 'partNumber');
    assert.string(uploadId, 'uploadId');

    if (!isAwsChunked(partReq.headers)) {
        req.log.debug({
            partNumber: partNumber,
            uploadId: uploadId,
            contentLength: partReq.headers['content-length'],
            contentEncoding: partReq.headers['content-encoding'],
            note: 'Using undefined size - will record actual bytes written'
        }, 'S3_MPU: Letting actual stream size determine part metadata size');
        return;
    }

    // AWS chunked encoding detected
    req.log.debug({
        uploadId: uploadId,
        partNumber: partNumber,
        contentEncoding: partReq.headers['content-encoding'],
        transferEncoding: partReq.headers['transfer-encoding'],
        decodedLength: partReq.headers[constants.
                                       S3_HEADERS.DECODED_CONTENT_LENGTH]
    }, 'S3_MPU: AWS chunked encoding detected in part upload');

    // Get decoded size
    var decodedSize = getDecodedSize(partReq.headers);

    if (decodedSize !== null) {
        // Set decoded size for metadata storage
        partReq._size = decodedSize;
        partReq._awsChunkedExpectedSize = decodedSize;

        req.log.debug({
            encodedContentLength: partReq.headers['content-length'],
            decodedContentLength: decodedSize,
            usingDecodedSize: decodedSize,
            note: 'AWS chunked: metadata will use decoded size'
        }, 'S3_MPU: Set decoded size for AWS chunked part metadata');
    }

    // Mark for special handling in common.js
    partReq._awsChunkedMPU = true;

    req.log.debug({
        contentEncoding: partReq.headers['content-encoding'],
        decodedLength: partReq.headers[constants.
                                       S3_HEADERS.DECODED_CONTENT_LENGTH],
        awsChunkedMPU: partReq._awsChunkedMPU,
        isS3Request: partReq.isS3Request,
        partNumber: partNumber
    }, 'S3_MPU: Set AWS chunked MPU flags for common.js processing');
}

module.exports = {
    isAwsChunked: isAwsChunked,
    getDecodedSize: getDecodedSize,
    configureAwsChunkedEncoding: configureAwsChunkedEncoding
};
