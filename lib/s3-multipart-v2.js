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

    req.log.info({
        uploadId: uploadRecord.uploadId,
        originalNbytes: commitBody.nbytes,
        partCount: partPaths.length,
        samplePartSizes: partPaths.slice(0, 3).map(function (p) {
            return ({ partNumber: p.partNumber, size: p.size });
        })
    }, 'S3_MPU: V2_COMMIT_DEBUG - Building v2 commit with size data');

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
 * Try v2 commit on ALL target sharks in parallel for proper replication
 */
function tryV2CommitOnSharks(req, sharks, commitBody, owner, callback) {
    var vasync = require('vasync');

    req.log.info({
        sharkCount: sharks.length,
        sharks: sharks.map(function (s) { return s.manta_storage_id; }),
        uploadId: commitBody.uploadId
    }, 'S3_MPU: Starting parallel v2 commit on all target sharks');

    // Call v2 commit on ALL sharks in parallel to ensure proper replication
    vasync.forEachParallel({
        func: function (shark, next) {
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

            req.log.debug({
                shark: shark.manta_storage_id,
                uploadId: commitBody.uploadId,
                partCount: commitBody.parts ? commitBody.parts.length : 0
            }, 'S3_MPU: Sending v2 commit request to shark');

            client.post(opts, commitBody, function (postErr, postReq, res) {
                if (postErr || !res || res.statusCode !== 204) {
                    var errorInfo = {
                        shark: shark.manta_storage_id,
                        statusCode: res ? res.statusCode : 'no-response',
                        uploadId: commitBody.uploadId,
                        hasPostErr: !!postErr,
                        hasResponse: !!res
                    };

                    if (postErr) {
                        errorInfo.errorName = postErr.name;
                        errorInfo.errorMessage = postErr.message;
                        errorInfo.errorCode = postErr.code;
                    }

                    req.log.warn(errorInfo,
                        'S3_MPU: v2 commit failed on shark' +
                        ' - this will affect replication');

                    // Don't fail the entire operation for individual shark
                    // failures
                    // but log them for monitoring
                    return (next());
                }

                // Success - extract ETag from nginx response
                var etag = res.headers.etag ||
                           res.headers.md5 ||
                           res.headers['x-joyent-computed-content-md5'];

                if (etag && !etag.startsWith('"')) {
                    etag = '"' + etag + '"';
                }

                req.log.info({
                    shark: shark.manta_storage_id,
                    statusCode: res.statusCode,
                    extractedETag: etag,
                    uploadId: commitBody.uploadId
                }, 'S3_MPU: v2 commit SUCCESS on shark');

                next(null, {
                    etag: etag,
                    shark: shark.manta_storage_id
                });
            });
        },
        inputs: sharks
    }, function (vasyncErr, results) {
        if (vasyncErr) {
            req.log.error({
                error: vasyncErr,
                uploadId: commitBody.uploadId
            }, 'S3_MPU: Critical error during parallel v2 commit');
            return (callback(vasyncErr));
        }

        // Check how many sharks succeeded
        var successes = results.successes || [];
        var failures = (results.operations || []).filter(function (op) {
            return (op.err);
        });

        req.log.info({
            uploadId: commitBody.uploadId,
            totalSharks: sharks.length,
            successCount: successes.length,
            failureCount: failures.length,
            successfulSharks: successes.map(function (s) {
                return (s.shark);
            })
        }, 'S3_MPU: Parallel v2 commit completed');

        if (successes.length === 0) {
            return (callback(new Error('v2 commit failed on all sharks')));
        }

        // Return the first successful result
        // (they should all have the same ETag)
        callback(null, successes[0]);
    });
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
