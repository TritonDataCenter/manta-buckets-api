/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 * File:     s3-multipart-v2.js
 * Purpose:  Extends s3-multipart.js with /mpu/v2/commit endpoint support
 */

var assert = require('assert-plus');
var sharkClient = require('./shark_client');

/**
 * Attempt to use native Mako /mpu/v2/commit endpoint for assembly
 * Falls back to streaming assembly if v2 commit fails
 *
 * @param {Object} req - Request object
 * @param {Object} uploadRecord - Upload metadata
 * @param {Array} partPaths - Array of part path objects
 * @param {Object} commitBody - Commit request body
 * @param {Function} callback - Callback function
 */
function tryMakoV2Commit(req, uploadRecord, partPaths, commitBody, callback) {
    var s3MultipartModule = require('./s3-multipart');

    // Check if native v2 commit is enabled
    if (!req.config.multipartUpload ||
        !req.config.multipartUpload.useNativeV2Commit) {
        req.log.debug('S3_MPU: Native v2 commit disabled,' +
                      ' using streaming assembly');
        return s3MultipartModule.customAssembleMultipartUpload(
            req, uploadRecord, partPaths, commitBody, callback);
    }

    req.log.debug({
        uploadId: uploadRecord.uploadId,
        partCount: partPaths.length
    }, 'S3_MPU: Attempting native Mako v2 commit');

    // Build v2 commit request format
    var owner = req.owner.account.uuid;
    var v2CommitBody = {
        version: 2,
        nbytes: commitBody.nbytes,
        owner: owner,
        bucketId: uploadRecord.bucketId,
        objectId: commitBody.objectId,
        objectHash: calculateObjectNameHash(getObjectName(req, uploadRecord)),
        uploadId: uploadRecord.uploadId,
        parts: partPaths.map(function (partPath, index) {
            // Format ETag properly - should be quoted hex string
            var etag = partPath.partETag || partPath.etag || partPath.objectId;
            if (etag && !etag.startsWith('"')) {
                etag = '"' + etag + '"';
            }

            return {
                partNumber: index + 1,
                path: '/manta' + partPath.sharkPath,
                etag: etag || '""',
                size: partPath.size
            };
        })
    };

    // Try v2 commit on available sharks
    var targetSharks = getTargetSharks(req, uploadRecord, partPaths);

    // Debug: Log part shark information for troubleshooting
    req.log.warn({
        uploadId: uploadRecord.uploadId,
        targetSharkCount: targetSharks.length,
        targetSharks: targetSharks.map(function (s) {
            return (s.manta_storage_id); }),
        partDetails: partPaths.slice(0, 3).map(function (p) {
        // Only log first 3 parts
            return {
                partNumber: p.partNumber,
                sharkPath: p.sharkPath,
                sharks: p.sharks ? p.sharks.map(function (s) {
                    return (s.manta_storage_id); }) : 'none',
                size: p.size
            };
        }),
        allPartsHaveSameSharks: partPaths.every(function (p) {
            if (!p.sharks || !partPaths[0].sharks) {
                return (false);
            }
            return p.sharks.length === partPaths[0].sharks.length &&
                   p.sharks.every(function (shark, idx) {
                       return shark.manta_storage_id ===
                           partPaths[0].sharks[idx].manta_storage_id;
                   });
        })
    }, 'S3_MPU: DEBUGGING shark allocation consistency for v2 commit');

    tryV2CommitOnSharks(req, targetSharks, v2CommitBody, owner,
                        function (v2Err, result) {
        if (v2Err) {
            req.log.warn({
                error: v2Err.message,
                uploadId: uploadRecord.uploadId
            }, 'S3_MPU: Native v2 commit failed, falling back to streaming');

            // Fall back to existing streaming assembly
            return s3MultipartModule.customAssembleMultipartUpload(
                req, uploadRecord, partPaths, commitBody, callback);
        }

        req.log.info({
            uploadId: uploadRecord.uploadId,
            resultETag: result.etag
        }, 'S3_MPU:' +
           ' v2 commit physical assembly completed, now creating metadata');

        // After successful v2 commit, create the final object metadata
        /* JSSTYLED */
        var cleanMd5 = result.etag ? result.etag.replace(/"/g, '') : '';

        req.log.debug({
            originalETag: result.etag,
            cleanedMd5: cleanMd5,
            etagLength: result.etag ? result.etag.length : 0,
            cleanMd5Length: cleanMd5.length
        }, 'S3_MPU: Processing ETag for final object metadata');

        var assemblyData = {
            totalBytes: commitBody.nbytes,
            md5: cleanMd5,
            sharks: targetSharks
        };

        // Use the already required s3MultipartModule
        s3MultipartModule.createFinalObjectMetadata(req,
            uploadRecord, commitBody, assemblyData, targetSharks,
            function (metadataErr, metadataResult) {
            if (metadataErr) {
                req.log.error({
                    error: metadataErr,
                    uploadId: uploadRecord.uploadId,
                    objectId: commitBody.objectId
                }, 'S3_MPU: Failed' +
                    ' to create final object metadata after successful' +
                    ' v2 commit');
                return (callback(metadataErr));
            }

            req.log.info({
                uploadId: uploadRecord.uploadId,
                finalObjectId: commitBody.objectId,
                objectSize: commitBody.nbytes,
                resultETag: result.etag
            }, 'S3_MPU: Successfully' +
               ' completed v2 commit with metadata registration');
            callback(null, result);
        });
    });
}

/**
 * Try v2 commit on multiple sharks with failover
 */
function tryV2CommitOnSharks(req, sharks, commitBody, owner, callback) {
    var sharkIndex = 0;

    function tryNextShark() {
        if (sharkIndex >= sharks.length) {
            return (callback(new Error('No sharks available for v2 commit')));
        }

        var shark = sharks[sharkIndex];
        sharkIndex++;

        var client = sharkClient.getClient({
            connectTimeout: (req.sharkConfig &&
                             req.sharkConfig.connectTimeout) || 10000,
            log: req.log,
            retry: (req.sharkConfig && req.sharkConfig.retry) || {},
            shark: shark,
            agent: req.sharkAgent
        });

        var opts = {
            objectId: commitBody.objectId,
            owner: owner,
            requestId: req.getId(),
            path: '/mpu/v2/commit',
            headers: {
                'content-type': 'application/json'
            }
        };

        // Log the v2 commit request details for debugging
        req.log.debug({
            shark: shark.manta_storage_id,
            uploadId: commitBody.uploadId,
            requestPath: opts.path,
            commitBodyKeys: Object.keys(commitBody),
            partCount: commitBody.parts ? commitBody.parts.length : 0,
            nbytes: commitBody.nbytes
        }, 'S3_MPU: Sending v2 commit request to shark');

        client.post(opts, commitBody, function (postErr, postReq, res) {
            // Log what we actually received for debugging
            req.log.debug({
                shark: shark.manta_storage_id,
                hasPostErr: !!postErr,
                hasRes: !!res,
                statusCode: res ? res.statusCode : 'no-response',
                expectedStatus: 204
            }, 'S3_MPU: v2 commit response received');

            // If we have a response, try to read any body content
            if (res && res.statusCode === 204) {
                // Even successful responses might have body content with
                // details
                var responseBody = '';
                if (res.readable) {
                    res.on('data', function (chunk) {
                        responseBody += chunk.toString();
                    });
                    res.on('end', function () {
                        req.log.warn({
                            shark: shark.manta_storage_id,
                            statusCode: 204,
                            responseBodyLength: responseBody.length,
                            responseBody: responseBody || 'empty',
                            headers: res.headers
                        }, 'S3_MPU: v2 commit 204 response body captured');

                        processResponse();
                    });
                    return;
                }
            }

            processResponse();

            function processResponse() {
                    if (postErr || !res || res.statusCode !== 204) {
                        // Extract comprehensive error info from nginx response
                        var errorInfo = {
                            shark: shark.manta_storage_id,
                            statusCode: res ? res.statusCode : 'no-response',
                            headers: res ? res.headers : null,
                            uploadId: commitBody.uploadId,
                            partCount: commitBody.parts ?
                                commitBody.parts.length : 0,
                            hasPostErr: !!postErr,
                            hasResponse: !!res
                        };

                        if (postErr) {
                            errorInfo.errorName = postErr.name;
                            errorInfo.errorMessage = postErr.message;
                            errorInfo.errorCode = postErr.code;

                            // For SharkResponseError, extract the full
                            // nginx error details
                            if (postErr.name === 'SharkResponseError' &&
                                postErr.message) {
                                // Try to extract JSON error from response body
                                var jsonMatch =
                                    /* JSSTYLED */
                                    postErr.message.match(/\{.*\}/);
                                if (jsonMatch) {
                                    try {
                                        var errorObj = JSON.parse(jsonMatch[0]);
                                        errorInfo.nginxError = errorObj;
                                    } catch (e) {
                                        // If JSON parse fails,
                                        // use regex approach
                                        var nginxErrorMatch = postErr.
                                         message.match
                                       (/'code':'([^']+)','message':'([^']+)'/);
                                        if (nginxErrorMatch) {
                                            errorInfo.nginxCode =
                                                nginxErrorMatch[1];
                                            errorInfo.nginxMessage =
                                                nginxErrorMatch[2];
                                        }
                                    }
                                }
                                // Also log the raw error message for debugging
                                errorInfo.rawErrorMessage = postErr.message;
                            }
                        } else if (res && res.statusCode !== 204) {
                            // No postErr but wrong status code -
                            errorInfo.responseStatus = res.statusCode;
                            errorInfo.responseMessage = res.statusMessage ||
                                'Unknown';

                            // Try to read response body if available
                            if (res.body) {
                                errorInfo.responseBody = res.body;
                            }

                            // Check for common HTTP error meanings
                            if (res.statusCode === 404) {
                                errorInfo.likelyIssue =
                                'v2 commit endpoint not found ';
                            } else if (res.statusCode === 500) {
                                errorInfo.likelyIssue =
                                'Internal server error in nginx ' +
                                'v2 commit processing';
                            } else if (res.statusCode === 400) {
                                errorInfo.likelyIssue =
                                    'Bad request - possibly malformed v2' +
                                    ' commit body or missing parts';
                            }
                        }

                        // Add request details for debugging
                        errorInfo.requestPath = opts.path;
                        errorInfo.requestHeaders = opts.headers;

                        req.log.warn(errorInfo, 'S3_MPU: v2 commit failed' +
                                     ' on shark, trying next');
                        return (tryNextShark());
                    }

                    // Success - extract ETag from nginx response
                    var etag = res.headers.etag ||
                               res.headers.md5 ||
                               res.headers['x-joyent-computed-content-md5'];

                    // Ensure ETag is properly quoted
                    if (etag && !etag.startsWith('"')) {
                        etag = '"' + etag + '"';
                    }

                    // Log complete successful response details
                    req.log.info({
                        shark: shark.manta_storage_id,
                        statusCode: res.statusCode,
                        extractedETag: etag,
                        etagHeader: res.headers.etag,
                        md5Header: res.headers.md5,
                        joyentMd5Header: res.headers
                        ['x-joyent-computed-content-md5'],
                        uploadId: commitBody.uploadId,
                        v2CommitSuccess: true
                    }, 'S3_MPU: v2 commit SUCCESS' +
                       ' - extracted ETag from nginx response');

                    callback(null, {
                        etag: etag,
                        shark: shark.manta_storage_id
                    });
                }
        });
    }

    tryNextShark();
}

/**
 * Get object name from request or upload record
 */
function getObjectName(req, uploadRecord) {
    // Try uploadRecord.key first
    if (uploadRecord.key && typeof (uploadRecord.key) === 'string') {
        return (uploadRecord.key);
    }

    // Fallback: extract from request params
    if (req.params && req.params.object_name) {
        return (req.params.object_name);
    }

    // Fallback: extract from URL path
    if (req.url) {
        // For URLs like /public/my2gbv2?uploadId=xyz, extract 'my2gbv2'
        var pathMatch = req.url.match(/\/[^\/]+\/([^?]+)/);
        if (pathMatch && pathMatch[1]) {
            return (decodeURIComponent(pathMatch[1]));
        }
    }

    throw new Error('Unable to determine object name' +
                    ' from request or upload record');
}

/**
 * Calculate object name hash for v2 storage path
 */
function calculateObjectNameHash(objectName) {
    var crypto = require('crypto');
    if (!objectName || typeof (objectName) !== 'string') {
        throw new Error('objectName must be a non-empty string');
    }
    return (crypto.createHash('md5').update(objectName).digest('hex'));
}

/**
 * Get target sharks for final object placement
 */
function getTargetSharks(req, uploadRecord, partPaths) {
    // With durability-level replication, all parts go to the same set of sharks
    // So we just need the sharks from any one part -
    // they all have the same allocation
    if (partPaths.length === 0) {
        req.log.warn('S3_MPU: No parts available for shark selection');
        return ([]);
    }

    var firstPart = partPaths[0];
    if (!firstPart.sharks || !Array.isArray(firstPart.sharks)) {
        req.log.warn('S3_MPU: First part has no shark information');
        return ([]);
    }

    var targetSharks = firstPart.sharks.slice(); // Copy the array

    req.log.debug({
        totalParts: partPaths.length,
        sharkCount: targetSharks.length,
        sharks: targetSharks.map(function (s) { return s.manta_storage_id; }),
        durabilityLevel: targetSharks.length
    }, 'S3_MPU: Using sharks from first part (all parts have same allocation)');

    return (targetSharks);
}

module.exports = {
    tryMakoV2Commit: tryMakoV2Commit
};
