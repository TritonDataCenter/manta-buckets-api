/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 * File:     s3-multipart-v2.js
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

    // SPACE CHECK: Validate shark space before v2 commit attempt
    validateSharkSpaceForV2Commit(req, partPaths, commitBody.nbytes, function (spaceErr) {
        if (spaceErr) {
            req.log.warn({
                error: spaceErr.message,
                sizeMB: Math.ceil(commitBody.nbytes / 1048576),
                uploadId: uploadRecord.uploadId
            }, 'S3_MPU: Insufficient space for v2 commit, falling back to streaming');
            
            // Fall back to streaming assembly on space error
            return s3MultipartModule.customAssembleMultipartUpload(
                req, uploadRecord, partPaths, commitBody, callback);
        }

        req.log.info({
            sizeMB: Math.ceil(commitBody.nbytes / 1048576),
            uploadId: uploadRecord.uploadId
        }, 'S3_MPU: Space validation passed, proceeding with v2 commit');

        // Continue with v2 commit logic
        proceedWithV2Commit(req, uploadRecord, partPaths, commitBody, callback);
    });
}

/**
 * Proceed with v2 commit after space validation passes
 */
function proceedWithV2Commit(req, uploadRecord, partPaths, commitBody, callback) {
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
            
            // Ensure error goes through S3 XML formatting
            var formattedError = new Error('v2 commit failed: ' + vasyncErr.message);
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
            return !op.err && op.result;
        }).map(function (op) {
            return (op.result && op.result.shark) ? op.result.shark : 'unknown';
        });

        req.log.info({
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
            return !op.err && op.result;
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

/**
 * Validate space on pre-allocated sharks before v2 commit
 * This prevents hanging commits when sharks don't have sufficient space
 */
function validateSharkSpaceForV2Commit(req, partPaths, finalSizeBytes, callback) {
    var finalSizeMB = Math.ceil(finalSizeBytes / 1048576);
    
    if (partPaths.length === 0) {
        return callback(new Error('No parts available for space validation'));
    }

    // Get shark information from first part (all parts use same sharks)
    var samplePart = partPaths[0];
    if (!samplePart.sharks || !Array.isArray(samplePart.sharks)) {
        req.log.warn({
            uploadId: req.s3Request ? req.s3Request.uploadId : 'unknown',
            finalSizeMB: finalSizeMB
        }, 'S3_MPU_V2: No shark information available, proceeding without space validation');
        return callback(); // Proceed without validation if no shark info
    }

    // Check available space using storinfo
    var isOperator = req.caller && req.caller.account && req.caller.account.isOperator;
    var sharkMap = isOperator ? 
        (req.storinfo && req.storinfo.operatorDcSharkMap) : 
        (req.storinfo && req.storinfo.dcSharkMap);

    if (!sharkMap) {
        req.log.warn({
            uploadId: req.s3Request ? req.s3Request.uploadId : 'unknown',
            finalSizeMB: finalSizeMB
        }, 'S3_MPU_V2: No shark map available, proceeding without space validation');
        return callback(); // Proceed without validation if no shark map
    }

    req.log.debug({
        uploadId: req.s3Request ? req.s3Request.uploadId : 'unknown',
        finalSizeMB: finalSizeMB,
        sharkCount: samplePart.sharks.length,
        sharks: samplePart.sharks.map(function (s) { return s.manta_storage_id; })
    }, 'S3_MPU_V2: Validating space on pre-allocated sharks');

    // Build map of shark ID to current space info
    var currentSharkSpaces = {};
    Object.keys(sharkMap).forEach(function (datacenter) {
        var dcSharks = sharkMap[datacenter];
        if (Array.isArray(dcSharks)) {
            dcSharks.forEach(function (shark) {
                currentSharkSpaces[shark.manta_storage_id] = shark.availableMB || 0;
            });
        }
    });

    // Check each pre-allocated shark's current available space
    var insufficientSharks = [];
    var totalSharks = samplePart.sharks.length;
    
    samplePart.sharks.forEach(function (shark) {
        var sharkId = shark.manta_storage_id;
        var availableMB = currentSharkSpaces[sharkId] || 0;
        
        if (availableMB < finalSizeMB) {
            insufficientSharks.push({
                shark: sharkId,
                availableMB: availableMB,
                requiredMB: finalSizeMB,
                deficitMB: finalSizeMB - availableMB
            });
        }
    });

    if (insufficientSharks.length > 0) {
        req.log.warn({
            uploadId: req.s3Request ? req.s3Request.uploadId : 'unknown',
            finalSizeMB: finalSizeMB,
            totalSharks: totalSharks,
            insufficientSharks: insufficientSharks.length,
            insufficientSharkDetails: insufficientSharks
        }, 'S3_MPU_V2: Pre-allocated sharks have insufficient space for v2 commit');

        // Create NotEnoughSpaceError for consistency with storinfo.choose()
        try {
            var storinfoErrors = require('storinfo/lib/errors');
            var StorinfoNotEnoughSpaceError = storinfoErrors.NotEnoughSpaceError;
            var cause = insufficientSharks.length + ' out of ' + totalSharks + 
                       ' pre-allocated sharks have insufficient space for final object';
            var error = new StorinfoNotEnoughSpaceError(finalSizeMB, cause);
            return callback(error);
        } catch (requireErr) {
            // Fallback if storinfo errors not available
            req.log.warn(requireErr, 'S3_MPU_V2: Could not require storinfo errors, using generic error');
            var genericError = new Error('Insufficient space for v2 commit: ' + cause);
            genericError.name = 'NotEnoughSpaceError';
            genericError.statusCode = 507;
            genericError.restCode = 'InsufficientStorage';
            return callback(genericError);
        }
    }

    req.log.info({
        uploadId: req.s3Request ? req.s3Request.uploadId : 'unknown',
        finalSizeMB: finalSizeMB,
        validatedSharks: totalSharks,
        sharkSpaces: samplePart.sharks.map(function (s) {
            return {
                shark: s.manta_storage_id,
                availableMB: currentSharkSpaces[s.manta_storage_id] || 'unknown'
            };
        })
    }, 'S3_MPU_V2: All pre-allocated sharks have sufficient space for v2 commit');

    callback(); // Success - proceed with v2 commit
}

module.exports = {
    tryMakoV2Commit: tryMakoV2Commit
};
