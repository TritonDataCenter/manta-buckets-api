/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Joyent, Inc.
 */

/*
 * AWS SigV4 Chunked Signature Verification
 *
 * This module provides cryptographic utilities for verifying AWS SigV4 streaming
 * signatures (aws-chunked encoding). Each chunk in an aws-chunked upload has a
 * signature that forms a chain - each chunk's signature depends on the previous
 * chunk's signature (or the seed signature from the Authorization header for the
 * first chunk).
 *
 * References:
 * - AWS SigV4 Streaming: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
 * - Signature Calculation: https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
 */

var crypto = require('crypto');

/*
 * Derive the AWS SigV4 signing key from the secret access key.
 *
 * The signing key is derived through a series of HMAC-SHA256 operations:
 *   kDate = HMAC-SHA256("AWS4" + secretKey, dateStamp)
 *   kRegion = HMAC-SHA256(kDate, region)
 *   kService = HMAC-SHA256(kRegion, service)
 *   kSigning = HMAC-SHA256(kService, "aws4_request")
 *
 * @param {String} secretKey - The secret access key (e.g., from IAM credentials)
 * @param {String} dateStamp - Date in YYYYMMDD format (e.g., "20250124")
 * @param {String} region - AWS region (e.g., "us-east-1")
 * @param {String} service - AWS service name (e.g., "s3")
 * @return {Buffer} The derived signing key
 */
function deriveSigningKey(secretKey, dateStamp, region, service) {
    var kDate = crypto.createHmac('sha256', 'AWS4' + secretKey)
                      .update(dateStamp)
                      .digest();

    var kRegion = crypto.createHmac('sha256', kDate)
                        .update(region)
                        .digest();

    var kService = crypto.createHmac('sha256', kRegion)
                         .update(service)
                         .digest();

    var kSigning = crypto.createHmac('sha256', kService)
                         .update('aws4_request')
                         .digest();

    return kSigning;
}

/*
 * Calculate the signature for a chunk of data.
 *
 * The string-to-sign for a chunk has the format:
 *   AWS4-HMAC-SHA256-PAYLOAD
 *   <timestamp>
 *   <credential-scope>
 *   <previous-signature>
 *   <hash-of-empty-string>
 *   <hash-of-chunk-data>
 *
 * @param {Buffer} signingKey - The derived signing key from deriveSigningKey()
 * @param {String} previousSignature - The previous chunk's signature (or seed signature)
 * @param {String} timestamp - ISO 8601 timestamp (e.g., "20250124T123456Z")
 * @param {String} credentialScope - Scope string (e.g., "20250124/us-east-1/s3/aws4_request")
 * @param {Buffer} chunkData - The chunk data to sign
 * @return {String} The calculated signature as a hex string
 */
function calculateChunkSignature(signingKey, previousSignature, timestamp,
                                  credentialScope, chunkData) {
    // Hash of empty string (always the same)
    var emptyHash = crypto.createHash('sha256').update('').digest('hex');

    // Hash of the chunk data
    var chunkHash = crypto.createHash('sha256').update(chunkData).digest('hex');

    // Build the string-to-sign
    var stringToSign =
        'AWS4-HMAC-SHA256-PAYLOAD\n' +
        timestamp + '\n' +
        credentialScope + '\n' +
        previousSignature + '\n' +
        emptyHash + '\n' +
        chunkHash;

    // Calculate the signature
    var signature = crypto.createHmac('sha256', signingKey)
                          .update(stringToSign, 'utf8')
                          .digest('hex');

    return signature;
}

/*
 * Verify that a chunk's signature matches the expected signature.
 *
 * This calculates what the signature should be and compares it with the
 * provided signature from the chunk header.
 *
 * @param {Buffer} signingKey - The derived signing key
 * @param {String} previousSignature - The previous chunk's signature (or seed signature)
 * @param {String} timestamp - ISO 8601 timestamp
 * @param {String} credentialScope - Scope string
 * @param {Buffer} chunkData - The chunk data
 * @param {String} expectedSignature - The signature from the chunk header
 * @return {Boolean} true if the signature is valid, false otherwise
 */
function verifyChunkSignature(signingKey, previousSignature, timestamp,
                               credentialScope, chunkData, expectedSignature) {
    var calculated = calculateChunkSignature(
        signingKey,
        previousSignature,
        timestamp,
        credentialScope,
        chunkData
    );

    // Constant-time comparison to prevent timing attacks
    return crypto.timingSafeEqual(
        Buffer.from(calculated, 'hex'),
        Buffer.from(expectedSignature, 'hex')
    );
}

module.exports = {
    deriveSigningKey: deriveSigningKey,
    calculateChunkSignature: calculateChunkSignature,
    verifyChunkSignature: verifyChunkSignature
};
