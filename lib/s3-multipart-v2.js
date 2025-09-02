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
            return {
                partNumber: index + 1,
                path: partPath.sharkPath,
                etag: partPath.etag || '""',
                size: partPath.size
            };
        })
    };

    // Try v2 commit on available sharks
    var targetSharks = getTargetSharks(req, uploadRecord, partPaths);
    
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

        client.post(opts, commitBody, function (postErr, res) {
            if (postErr || res.statusCode !== 204) {
                req.log.warn({
                    error: postErr,
                    statusCode: res ? res.statusCode : undefined,
                    shark: shark.manta_storage_id
                }, 'S3_MPU: v2 commit failed on shark, trying next');
                
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
    var sharkMap = {};
    var targetSharks = [];
    var partsWithSharks = 0;
    
    // Collect all sharks from all parts
    partPaths.forEach(function (partPath) {
        if (partPath.sharks && Array.isArray(partPath.sharks)) {
            partsWithSharks++;
            partPath.sharks.forEach(function (shark) {
                if (shark.manta_storage_id && !sharkMap[shark.manta_storage_id]) {
                    sharkMap[shark.manta_storage_id] = shark;
                    targetSharks.push(shark);
                }
            });
        }
    });
    
    req.log.debug({
        totalParts: partPaths.length,
        partsWithSharks: partsWithSharks,
        sharkCount: targetSharks.length,
        firstPartHasSharks: partPaths[0] && partPaths[0].sharks ? 'yes' : 'no'
    }, 'S3_MPU: getTargetSharks analysis');
    
    return targetSharks;
}

module.exports = {
    tryMakoV2Commit: tryMakoV2Commit
};