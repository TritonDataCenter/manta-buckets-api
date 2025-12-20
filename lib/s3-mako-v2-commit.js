/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * File:     s3-mako-v2-commit.js
 * Purpose:  Extends s3-multipart.js with /mpu/v2/commit endpoint support
 *
 * This method relies in mako endpoint /mpu/v2/commit endpoint to be available.
 * Assembling all the parts using mako, simplifies the code and the responsabil-
 * ity is delegated to mako to generate the final object, also performance is a
 * lot better than using buckets-mdapi for doing the same work.
 *
 * For Mako v2/commit endpoint to be used, we need to enable it on
 * the configuration file (check etc/config.json), prefixDirLen is the 2 bytes
 * from the object id used for directory organization when storing objects
 * assembled in Mako. This is actually not used in the configuration as
 * this is already hardcoded in Mako nginx mpu module.
 *
 *  "enableMPU": true,
 *   "multipartUpload": {
 *       "prefixDirLen": 1,
 *       "useNativeV2Commit": true
 *   },
 *
 */

var assert = require('assert-plus');
var s3Compat = require('./s3-compat');
var sharkClient = require('./shark_client');

/**
 * Attempt to use native Mako /mpu/v2/commit endpoint for assembly.
 *
 * @param {Object} req - Request object
 * @param {Object} uploadRecord - Upload metadata
 * @param {Array} partPaths - Array of part path objects
 * @param {Object} commitBody - Commit request body
 * @param {Function} callback - Callback function
 */
function tryMakoV2Commit(req, uploadRecord, partPaths, commitBody, callback) {

    // Check if native v2 mpu commit is enabled
    if (!req.config.multipartUpload ||
        !req.config.multipartUpload.useNativeV2Commit) {
        req.log.error({
            uploadId: uploadRecord.uploadId
        }, 'S3_MPU: Native v2 commit is disabled ' +
           'but required for multipart uploads');

        var error = new Error('Multipart upload v2' +
                              ' commit is required but disabled');
        error.statusCode = 503;
        error.restCode = 'ServiceUnavailable';
        return (callback(error));
    }

    req.log.debug({
        uploadId: uploadRecord.uploadId,
        partCount: partPaths.length
    }, 'S3_MPU: Using native Mako v2 commit');

    /*
     * Proceed directly with v2 commit (storinfo already validated space
     * during initiation)
     */
    proceedWithV2Commit(req, uploadRecord, partPaths, commitBody, callback);
}

/**
 * Execute v2 commit using mako nginx mpu module
 */
function proceedWithV2Commit(req, uploadRecord, partPaths,
                             commitBody, callback) {
    var s3MultipartModule = require('./s3-multipart');

    // Build v2 commit request format
    var owner = req.owner.account.uuid;

    // Recalculate total size from actual part sizes (important for
    // resume scenarios)
    var discoveredTotalSize = partPaths.reduce(function (sum, partPath) {
        return (sum + (partPath.size || 0));
    }, 0);

    var sizeDifference = Math.abs(discoveredTotalSize - commitBody.nbytes);
    var significantDifference = sizeDifference > 0;

    // Only use discovered size if there's a difference
    // (safer for normal uploads)
    var actualSize = significantDifference ?
        discoveredTotalSize : commitBody.nbytes;

    req.log.debug({
        uploadId: uploadRecord.uploadId,
        originalNbytes: commitBody.nbytes,
        discoveredTotalSize: discoveredTotalSize,
        actualSize: actualSize,
        sizeDifference: sizeDifference,
        usedDiscoveredSize: significantDifference,
        partCount: partPaths.length,
        allPartSizes: partPaths.map(function (p, idx) {
            return ({
                index: idx,
                partNumber: p.partNumber,
                size: p.size,
                hasSize: typeof (p.size) !== 'undefined',
                contentLength: p.content_length,
                sharkPath: p.sharkPath ?
                    p.sharkPath.substring(p.sharkPath.lastIndexOf('/')) : 'none'
            });
        })
    }, 'S3_MPU: V2_COMMIT_DEBUG - Detailed size analysis for v2 commit');

    var v2CommitBody = {
        version: 2,
        nbytes: actualSize,
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

            var fullPath = '/manta' + partPath.sharkPath;
            req.log.debug({
                index: index,
                partNumber: index + 1,
                originalSharkPath: partPath.sharkPath,
                constructedPath: fullPath,
                partETag: etag,
                partSize: partPath.size
            }, 'S3_MPU_V2_DEBUG: Part path construction for v2 commit');

            return {
                partNumber: index + 1,
                path: fullPath,
                etag: etag || '""',
                size: partPath.size
            };
        })
    };

    // Get target sharks for final object placement
    var targetSharks = getTargetSharks(req, uploadRecord, partPaths);
    if (!targetSharks) {
        var formattedError =
            new Error('Preallocated storage nodes not available for MPU' +
                      ' UploadId: ' + uploadRecord.uploadId);
        formattedError.statusCode = 503;
        formattedError.restCode = 'ServiceUnavailable';

        req.log.error({uploadRecord: uploadRecord},
                      'S3_MPU_V2 Could not find' +
                      'Preallocated sharks from UploadRecord');
        return (callback(formattedError));
    }

    // Execute v2 commit
    req.log.debug({
        uploadId: uploadRecord.uploadId,
        objectId: commitBody.objectId
    }, 'S3_MPU: Attempting v2 commit');

    tryV2CommitOnSharks(req, targetSharks, v2CommitBody, owner,
                        function onV2CommitComplete(v2Err, result) {
            if (v2Err) {
                req.log.error({
                    error: v2Err.message,
                    uploadId: uploadRecord.uploadId
                }, 'S3_MPU: Native v2 commit failed - no fallback available');

                return (callback(v2Err));
            }

            req.log.debug({
                uploadId: uploadRecord.uploadId,
                resultETag: result.etag
            }, 'S3_MPU: v2 commit physical assembly completed' +
                ', now creating metadata');

            // After successful v2 commit, create the final object metadata
            // JSSTYLED
            var cleanMd5 = result.etag ? result.etag.replace(/"/g, '') : '';

            var assemblyData = {
                totalBytes: actualSize,
                md5: cleanMd5,
                sharks: targetSharks
            };

            s3MultipartModule.createFinalObjectMetadata(req,
                uploadRecord, commitBody, assemblyData, targetSharks,
                function onFinalMetadataCreated(metadataErr, metadataResult) {
                if (metadataErr) {
                    req.log.error({
                        error: metadataErr,
                        uploadId: uploadRecord.uploadId,
                        objectId: commitBody.objectId
                    }, 'S3_MPU: Failed to create final' +
                       ' object metadata after successful v2 commit');
                    return (callback(metadataErr));
                }

                req.log.debug({
                    uploadId: uploadRecord.uploadId,
                    finalObjectId: commitBody.objectId,
                    objectSize: actualSize,
                    resultETag: result.etag
                }, 'S3_MPU: Successfully completed v2' +
                   ' commit with metadata registration');
                callback(null, result);
            });

        });
}

/**
 * Try v2 commit on ALL target sharks in parallel for proper replication
 */
function tryV2CommitOnSharks(req, sharks, commitBody, owner, callback) {
    var vasync = require('vasync');

    req.log.debug({
        sharkCount: sharks.length,
        sharks: sharks.map(function (s) { return s.manta_storage_id; }),
        uploadId: commitBody.uploadId
    }, 'S3_MPU: Starting parallel v2 commit on all target sharks');

    // Call v2 commit on ALL sharks in parallel to ensure proper replication
    vasync.forEachParallel({
        func: function commitOnEachShark(shark, next) {
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

            client.post(opts, commitBody,
                        function onSharkCommitResponse(postErr, postReq, res) {
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

                    // Check for 409 errors indicating size mismatches
                    if (res && res.statusCode === 409) {
                        req.log.error(errorInfo,
                            'S3_MPU: v2 commit failed with 409' +
                            ' - likely size mismatch, ' +
                            'converting to InvalidPart');

                        var invalidPartError =
                           new Error('One or more parts have size' +
                                     ' discrepancies that prevent assembly');
                        invalidPartError.statusCode = 400;
                        invalidPartError.restCode = 'InvalidPart';
                        invalidPartError.shark = shark.manta_storage_id;
                        invalidPartError.isSharkFailure = true;
                        return (next(invalidPartError));
                    }

                    // Check for SharkResponseError with 409 in
                    // message (size mismatch)
                    if (postErr && postErr.message &&
                        postErr.message.includes('HTTP 409') &&
                        postErr.message.includes('assembled temporary file') &&
                        postErr.message.includes('bytes, request specified')) {
                        req.log.error(errorInfo,
                            'S3_MPU: v2 commit failed with SharkResponseError'+
                            ' 409 - size mismatch, converting to InvalidPart');

                        var sharkInvalidPartError =
                            new Error('One or more parts have size' +
                                      ' discrepancies that prevent assembly');
                        sharkInvalidPartError.statusCode = 400;
                        sharkInvalidPartError.restCode = 'InvalidPart';
                        sharkInvalidPartError.shark = shark.manta_storage_id;
                        sharkInvalidPartError.isSharkFailure = true;
                        return (next(sharkInvalidPartError));
                    }

                    req.log.error(errorInfo,
                        'S3_MPU: v2 commit failed on shark' +
                        ' - this will affect replication');

                    // Don't fail the entire operation for individual shark
                    // failures, but pass the error to vasync for
                    // proper counting
                    var sharkError = new Error('v2 commit failed on shark ' +
                                             shark.manta_storage_id);
                    sharkError.shark = shark.manta_storage_id;
                    sharkError.isSharkFailure = true;
                    return (next(sharkError));
                }

                // Success - extract ETag from nginx response
                // The etag is critical as metadata creation
                // will fail if it does not have it, we will have
                // the physical file on this but no the metadata
                // to reach or know where it is.
                var etag = res.headers.etag ||
                           res.headers.md5 ||
                           res.headers['x-joyent-computed-content-md5'];

                if (etag && !etag.startsWith('"')) {
                    etag = '"' + etag + '"';
                }

                req.log.debug({
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
    }, function onParallelCommitsComplete(vasyncErr, results) {
        if (vasyncErr) {
            req.log.error({
                error: vasyncErr,
                uploadId: commitBody.uploadId
            }, 'S3_MPU: Critical error during parallel v2 commit');

            // Check if this is an InvalidPart error (size mismatch)
            if (vasyncErr.restCode === 'InvalidPart' ||
                vasyncErr.statusCode === 400) {
                // Pass through InvalidPart errors directly
                return (callback(vasyncErr));
            }

            // Check if MultiError contains InvalidPart errors from all sharks
            if (vasyncErr.ase_errors && vasyncErr.ase_errors.length > 0) {
                var invalidPartErrors = vasyncErr.ase_errors.filter(
                    function (err) {
                    return err.restCode === 'InvalidPart' ||
                        err.statusCode === 400;
                });

                if (invalidPartErrors.length === vasyncErr.ase_errors.length) {
                    // All errors are InvalidPart -
                    // return the first one directly
                    req.log.debug({
                        uploadId: commitBody.uploadId,
                        invalidPartCount: invalidPartErrors.length,
                        totalErrors: vasyncErr.ase_errors.length
                    }, 'S3_MPU: All v2 commit' +
                       ' errors are InvalidPart,' +
                       ' returning first InvalidPart error');

                    return (callback(invalidPartErrors[0]));
                }
            }

            // Ensure error goes through S3 XML formatting
            var formattedError = new Error('v2 commit failed: ' +
                                           vasyncErr.message);
            formattedError.statusCode = 503;
            formattedError.restCode = 'ServiceUnavailable';
            return (callback(formattedError));
        }

        // Check how many sharks succeeded
        var successes = results.successes || [];
        var operations = results.operations || [];
        var failures = operations.filter(function (op) {
            return (op.err);
        });

        // Extract successful shark IDs from operations that succeeded
        var successfulSharks = operations.filter(function (op) {
            return (!op.err && op.result);
        }).map(function (op) {
            return ((op.result && op.result.shark) ? op.result.shark :
                    'unknown');
        });

        req.log.debug({
            uploadId: commitBody.uploadId,
            totalSharks: sharks.length,
            successCount: successes.length,
            failureCount: failures.length,
            successfulSharks: successfulSharks
        }, 'S3_MPU: Parallel v2 commit completed');

        if (successes.length === 0) {
            return (callback(new Error('v2 commit failed on all sharks')));
        }

        // Return the first successful result from operations
        // (they should all have the same ETag)
        var firstSuccess = operations.find(function (op) {
            return (!op.err && op.result);
        });

        if (firstSuccess && firstSuccess.result) {
            callback(null, firstSuccess.result);
        } else {
            // Fallback if no proper result found
            callback(null, successes[0] || {etag: '', shark: 'unknown'});
        }
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
    if (!objectName || typeof (objectName) !== 'string') {
        throw new Error('objectName must be a non-empty string');
    }
    return (s3Compat.createMD5Hash(objectName));
}

/**
 * Get target sharks for final object placement
 */
function getTargetSharks(req, uploadRecord, partPaths) {
    // Use pre-allocated sharks from upload record (cached from initiation)
    assert.object(uploadRecord.preAllocatedSharks, 'preAllocatedSharks');

    req.log.debug({
        uploadRecord: uploadRecord,
        uploadRecordKeys: uploadRecord ? Object.keys(uploadRecord) :
            'null-or-undefined',
        hasPreAllocatedSharks: !!(uploadRecord &&
                                  uploadRecord.preAllocatedSharks),
        preAllocatedSharksLength: uploadRecord &&
            uploadRecord.preAllocatedSharks ?
            uploadRecord.preAllocatedSharks.length : 'no-sharks'
    }, 'S3 DEBUG MPU UPLOAD RECORD');

    if (uploadRecord.preAllocatedSharks &&
        Array.isArray(uploadRecord.preAllocatedSharks) &&
        uploadRecord.preAllocatedSharks.length > 0) {
        req.log.debug({
            uploadId: uploadRecord.uploadId,
            totalParts: partPaths.length,
            sharkCount: uploadRecord.preAllocatedSharks.length,
            sharks: uploadRecord.preAllocatedSharks.map(function (s) {
                return (s.manta_storage_id);
            }),
            durabilityLevel: uploadRecord.preAllocatedSharks.length
        }, 'S3_MPU: Using pre-allocated sharks from upload record');

        return (uploadRecord.preAllocatedSharks.slice()); // Copy the array
    }
    req.log.error(uploadRecord,
       'S3 MPU uploadRecord should have preserved sharks');
}


module.exports = {
    tryMakoV2Commit: tryMakoV2Commit
};
