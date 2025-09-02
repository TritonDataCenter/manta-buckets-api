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
    // Check if native v2 commit is enabled
    if (!req.config.multipartUpload || !req.config.multipartUpload.useNativeV2Commit) {
        req.log.debug('S3_MPU: Native v2 commit disabled, using streaming assembly');
        var s3Multipart = require('./s3-multipart');
        return s3Multipart.customAssembleMultipartUpload(
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
    req.log.debug({
        uploadId: uploadRecord.uploadId,
        targetSharkCount: targetSharks.length,
        targetSharks: targetSharks.map(function (s) { return s.manta_storage_id; }),
        partDetails: partPaths.map(function (p) {
            return {
                partNumber: p.partNumber,
                sharks: p.sharks ? p.sharks.map(function (s) { return s.manta_storage_id; }) : 'none'
            };
        })
    }, 'S3_MPU: Debugging shark allocation for v2 commit');
    
    tryV2CommitOnSharks(req, targetSharks, v2CommitBody, owner, function (v2Err, result) {
        if (v2Err) {
            req.log.warn({
                error: v2Err.message,
                uploadId: uploadRecord.uploadId
            }, 'S3_MPU: Native v2 commit failed, falling back to streaming');
            
            // Fall back to existing streaming assembly
            var s3Multipart = require('./s3-multipart');
            return s3Multipart.customAssembleMultipartUpload(
                req, uploadRecord, partPaths, commitBody, callback);
        }

        req.log.info({
            uploadId: uploadRecord.uploadId,
            resultETag: result.etag
        }, 'S3_MPU: Successfully completed via native Mako v2 commit');

        callback(null, result);
    });
}

/**
 * Try v2 commit on multiple sharks with failover
 */
function tryV2CommitOnSharks(req, sharks, commitBody, owner, callback) {
    var sharkIndex = 0;
    
    function tryNextShark() {
        if (sharkIndex >= sharks.length) {
            return callback(new Error('No sharks available for v2 commit'));
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

        client.post(opts, commitBody, function (postErr, res) {
            if (postErr || res.statusCode !== 204) {
                // Extract comprehensive error info from nginx response
                var errorInfo = {
                    shark: shark.manta_storage_id,
                    statusCode: res ? res.statusCode : 'no-response',
                    headers: res ? res.headers : null,
                    uploadId: commitBody.uploadId,
                    partCount: commitBody.parts ? commitBody.parts.length : 0
                };
                
                if (postErr) {
                    errorInfo.errorName = postErr.name;
                    errorInfo.errorMessage = postErr.message;
                    errorInfo.errorCode = postErr.code;
                    
                    // For SharkResponseError, extract the full nginx error details
                    if (postErr.name === 'SharkResponseError' && postErr.message) {
                        // Try to extract JSON error from response body
                        var jsonMatch = postErr.message.match(/\{.*\}/);
                        if (jsonMatch) {
                            try {
                                var errorObj = JSON.parse(jsonMatch[0]);
                                errorInfo.nginxError = errorObj;
                            } catch (e) {
                                // If JSON parse fails, use regex approach
                                var nginxErrorMatch = postErr.message.match(/"code":"([^"]+)","message":"([^"]+)"/);
                                if (nginxErrorMatch) {
                                    errorInfo.nginxCode = nginxErrorMatch[1];
                                    errorInfo.nginxMessage = nginxErrorMatch[2];
                                }
                            }
                        }
                        
                        // Also log the raw error message for debugging
                        errorInfo.rawErrorMessage = postErr.message;
                    }
                }
                
                // Add request details for debugging
                errorInfo.requestPath = opts.path;
                errorInfo.requestHeaders = opts.headers;
                
                req.log.warn(errorInfo, 'S3_MPU: v2 commit failed on shark, trying next');
                return tryNextShark();
            }

            // Success - extract ETag from response headers
            var etag = res.headers.etag || '"' + res.headers.md5 + '"';
            callback(null, {
                etag: etag,
                shark: shark.manta_storage_id
            });
        });
    }

    tryNextShark();
}

/**
 * Get object name from request or upload record
 */
function getObjectName(req, uploadRecord) {
    // Try uploadRecord.key first
    if (uploadRecord.key && typeof uploadRecord.key === 'string') {
        return uploadRecord.key;
    }
    
    // Fallback: extract from request params
    if (req.params && req.params.object_name) {
        return req.params.object_name;
    }
    
    // Fallback: extract from URL path
    if (req.url) {
        // For URLs like /public/my2gbv2?uploadId=xyz, extract 'my2gbv2'
        var pathMatch = req.url.match(/\/[^\/]+\/([^?]+)/);
        if (pathMatch && pathMatch[1]) {
            return decodeURIComponent(pathMatch[1]);
        }
    }
    
    throw new Error('Unable to determine object name from request or upload record');
}

/**
 * Calculate object name hash for v2 storage path
 */
function calculateObjectNameHash(objectName) {
    var crypto = require('crypto');
    if (!objectName || typeof objectName !== 'string') {
        throw new Error('objectName must be a non-empty string');
    }
    return crypto.createHash('md5').update(objectName).digest('hex');
}

/**
 * Get target sharks for final object placement
 */
function getTargetSharks(req, uploadRecord, partPaths) {
    // With durability-level replication, all parts go to the same set of sharks
    // So we just need the sharks from any one part - they all have the same allocation
    if (partPaths.length === 0) {
        req.log.warn('S3_MPU: No parts available for shark selection');
        return [];
    }
    
    var firstPart = partPaths[0];
    if (!firstPart.sharks || !Array.isArray(firstPart.sharks)) {
        req.log.warn('S3_MPU: First part has no shark information');
        return [];
    }
    
    var targetSharks = firstPart.sharks.slice(); // Copy the array
    
    req.log.debug({
        totalParts: partPaths.length,
        sharkCount: targetSharks.length,
        sharks: targetSharks.map(function (s) { return s.manta_storage_id; }),
        durabilityLevel: targetSharks.length
    }, 'S3_MPU: Using sharks from first part (all parts have same allocation)');
    
    return targetSharks;
}

module.exports = {
    tryMakoV2Commit: tryMakoV2Commit
};