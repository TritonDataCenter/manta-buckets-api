/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
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
 * Check if request uses AWS chunked encoding.
 *
 * What the spec describes
 * -----------------------
 * The streaming-payload variant of SigV4 uses several headers
 * together: `Content-Encoding: aws-chunked`,
 * `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD`,
 * `x-amz-decoded-content-length`, and chunked Transfer-Encoding.
 * The spec describes all of these as part of the protocol; it
 * does not describe any of them as optional.
 * Reference:
 *   https://docs.aws.amazon.com/AmazonS3/latest/API/
 *   sigv4-streaming.html
 *
 * `x-amz-content-sha256` is part of the SigV4 canonical request that
 * the client signs. The signature math reads its value as input to the
 * HMAC chain, so a missing or wrong value produces a signature that
 * does not verify. A client that completed auth at all therefore must
 * have set this header to one of the documented sentinel strings.
 * - `Content-Encoding: aws-chunked` is typically not in the request's
 * `SignedHeaders` list. The signature is computed and verified
 * successfully whether the client sets it or not. The server therefore
 * has no way to detect, via signature verification, that a client
 * omitted it.
 * Detection strategy
 * ------------------
 * Match on either signal. The sha256 sentinel covers clients that
 * omit `Content-Encoding`; the Content-Encoding check keeps clients
 * that do follow the full spec working without relying on a
 * particular sentinel value.
 */
function isAwsChunked(headers) {
    assert.object(headers, 'headers');
    if (headers['content-encoding'] === 'aws-chunked') {
        return (true);
    }
    var sha = headers['x-amz-content-sha256'];
    return (sha === 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD');
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
