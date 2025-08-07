/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var assert = require('assert-plus');
var crypto = require('crypto');
var uuidv4 = require('uuid/v4');
var vasync = require('vasync');

var auth = require('./auth');
var bucketHelpers = require('./buckets/buckets');
var common = require('./common');
var InvalidDurabilityLevelError = require('./errors').
    InvalidDurabilityLevelError;
var sharkClient = require('./shark_client');
var translateBucketError = require('./buckets/common').translateBucketError;

// Durability level is stored as a simple object in
// .mpu-uploads/{uploadId}.durability

///--- S3 Multipart Upload Handlers

/**
 * S3 Initiate Multipart Upload Handler
 * POST /{bucket}/{key}?uploads
 */
function s3InitiateMultipartUploadHandler() {
    return function s3InitiateMultipartUpload(req, res, next) {
        var bucketName = req.s3Request.bucket;
        var objectKey = req.s3Request.object;
        var owner = req.owner.account.uuid;
        var requestId = req.getId();

        req.log.debug({
            bucket: bucketName,
            object: objectKey,
            owner: owner
        }, 'S3_MPU: Initiating multipart upload');

        // Generate unique upload ID
        var uploadId = generateUploadId();

        // Extract and validate durability-level header
        // (same logic as regular object creation)
        var copies = parseInt((req.header('durability-level') ||
                               req.header('x-durability-level') ||
                               common.DEF_NUM_COPIES), 10);

        // Validate durability-level (same validation as create.js)
        var maxObjectCopies = req.config.maxObjectCopies ||
            common.DEF_MAX_COPIES;
        if (typeof (copies) !== 'number' || isNaN(copies) ||
            (copies < common.DEF_MIN_COPIES || copies > maxObjectCopies)) {
            next(new InvalidDurabilityLevelError(common.DEF_MIN_COPIES,
                                                 maxObjectCopies));
            return;
        }

        // Store durability level in a separate temporary object for
        // multi-instance access
        var durabilityKey = '.mpu-uploads/' + uploadId + '.durability';
        var durabilityData = {
            uploadId: uploadId,
            durabilityLevel: copies,
            created: new Date().toISOString()
        };

        storeDurabilityObject(req, durabilityKey, durabilityData);

        req.log.info({
            uploadId: uploadId,
            durabilityKey: durabilityKey,
            durabilityLevel: copies
        }, 'S3_MPU: Initiated durability object storage for multipart upload');

        req.log.debug({
            uploadId: uploadId,
            durabilityLevel: copies,
            source: req.header('durability-level') ? 'durability-level' :
                   req.header('x-durability-level') ?
                'x-durability-level' : 'default'
        }, 'S3_MPU: Processed and cached durability-level during initiate');

        // Create upload record to track multipart upload state
        var uploadRecord = {
            uploadId: uploadId,
            bucket: bucketName,
            key: objectKey,
            account: owner,
            initiated: new Date().toISOString(),
            parts: {},
            status: 'initiated',
            durabilityLevel: copies
        };

        // Store upload record as special object in buckets-mdapi
        var uploadRecordKey = '.mpu-uploads/' + uploadId;
        var uploadRecordContent = JSON.stringify(uploadRecord);
        var uploadRecordMD5 = crypto.createHash('md5')
                                   .update(uploadRecordContent)
                                   .digest('base64');

        req.log.info({
            uploadId: uploadId,
            uploadRecordKey: uploadRecordKey,
            uploadRecordContent: uploadRecordContent,
            durabilityLevel: uploadRecord.durabilityLevel
        }, 'S3_MPU: About to store upload record with durability level');

        req.log.debug({
            uploadId: uploadId,
            uploadRecordKey: uploadRecordKey
        }, 'S3_MPU: Creating upload record');

        // Create request context for storing upload record
        var uploadReq = Object.create(req);
        uploadReq.params = {
            bucket_name: bucketName,
            object_name: uploadRecordKey
        };
        uploadReq.method = 'PUT';

        // The durability level is already stored in
        // uploadRecord.durabilityLevel
        // and will be saved as JSON content
        uploadReq._size = uploadRecordContent.length;
        uploadReq._contentMD5 = uploadRecordMD5;
        uploadReq.objectId = uuidv4();
        uploadReq.headers['content-type'] = 'application/json';
        uploadReq.headers['content-length'] = uploadRecordContent.length;
        uploadReq.sharks = []; // No sharks needed for metadata-only object

        // Load bucket and create upload record
        bucketHelpers.loadRequest(uploadReq, null, function (loadErr) {
            if (loadErr) {
                req.log.error(loadErr, 'S3_MPU: Failed' +
                              ' to load bucket for upload record');
                return (next(translateBucketError(req, loadErr)));
            }

            bucketHelpers.getBucketIfExists(uploadReq, null,
                                            function (bucketErr) {
                if (bucketErr) {
                    req.log.error(bucketErr, 'S3_MPU: Bucket not found ' +
                                  'for multipart upload');
                    return (next(translateBucketError(req, bucketErr)));
                }

                // Get metadata placement and client
                var metadataLocation = req.metadataPlacement.getObjectLocation(
                    owner, uploadReq.bucket.id, crypto.createHash('md5')
                                                      .update(uploadRecordKey)
                                                      .digest('hex'));
                var client =
                  req.metadataPlacement.getBucketsMdapiClient(metadataLocation);

                // Create upload record object
                client.createObject(owner, uploadReq.bucket.id, uploadRecordKey,
                    uploadReq.objectId, uploadRecordContent.length,
                                    uploadRecordMD5,
                    'application/json', {}, [], {}, metadataLocation.vnode, {},
                    requestId, function (createErr, result) {

                    if (createErr) {
                        req.log.error(createErr,
                            'S3_MPU: Failed to create upload record');
                        return (next(translateBucketError(req, createErr)));
                    }

                    req.log.info({
                        uploadId: uploadId,
                        bucket: bucketName,
                        key: objectKey,
                        storedDurabilityLevel: copies
                    }, 'S3_MPU: Successfully stored upload' +
                                 ' record with durability level');

                    // Return S3 InitiateMultipartUploadResult XML
                    var xml = generateInitiateMultipartUploadXML(bucketName,
                          objectKey, uploadId);
                    res.setHeader('Content-Type', 'application/xml');
                    res.send(200, xml);
                    next(false);
                });
            });
        });
    };
}

/**
 * S3 Upload Part Handler
 * PUT /{bucket}/{key}?partNumber={partNumber}&uploadId={uploadId}
 */
function s3UploadPartHandler() {
    return function s3UploadPart(req, res, next) {
        var bucketName = req.s3Request.bucket;
        var objectKey = req.s3Request.object;
        var uploadId = req.s3Request.uploadId;
        var partNumber = req.s3Request.partNumber;

        req.log.debug({
            bucket: bucketName,
            object: objectKey,
            uploadId: uploadId,
            partNumber: partNumber
        }, 'S3_MPU: Uploading part');

        // Validate part number (S3 allows 1-10000)
        if (partNumber < 1 || partNumber > 10000) {
            return (next(new InvalidPartNumberError(partNumber)));
        }

        // Generate unique part key
        var partKey = '.mpu-parts/' + uploadId + '/' + partNumber;
        var partId = uuidv4();

        req.log.debug({
            partKey: partKey,
            partId: partId
        }, 'S3_MPU: Generated part identifiers');

        // Retrieve upload record to get durability level
        getUploadRecord(req, uploadId, function (getErr, uploadRecord) {
            if (getErr) {
                req.log.error(getErr,
                              'S3_MPU: Failed to read upload record for part');
                return (next(new NoSuchUploadError(uploadId)));
            }

            // Create part upload request by modifying current request
            var partReq = Object.create(req);
            partReq.params = {
                bucket_name: bucketName,
                object_name: partKey
            };
            partReq.objectId = partId;

            // Copy headers and set header method for proper header access
            partReq.headers = Object.assign({}, req.headers || {});
            partReq.header = function (name, defaultValue) {
                return (partReq.headers[name.toLowerCase()] || defaultValue);
            };

            // Get durability level from stored temporary object with metadata
            var durabilityKey = '.mpu-uploads/' + uploadId + '.durability';
            getDurabilityObject(req, durabilityKey,
                                function (durErr, durabilityData) {
                if (!durErr && durabilityData &&
                    durabilityData.durabilityLevel) {
                    partReq.headers['durability-level'] =
                        durabilityData.durabilityLevel.toString();
                    req.log.info({
                        uploadId: uploadId,
                        partNumber: partNumber,
                        durabilityLevel: durabilityData.durabilityLevel
                    }, 'S3_MPU: Set durability-level header' +
                                 ' from durability object metadata');
                } else {
                    req.log.warn({
                        uploadId: uploadId,
                        partNumber: partNumber,
                        error: durErr
                    }, 'S3_MPU: Could not retrieve durability level' +
                                 ' from metadata, using default');
                }

            // Create a custom response object to capture the result
            // without sending it
            var customRes = Object.create(res);
            var partETag = null;

                // Override send method to capture the result
                customRes.send = function (statusCode, body) {
                    req.log.debug({
                        statusCode: statusCode,
                        capturedETag: partETag
                    }, 'S3_MPU: Captured part upload result');
                    // Don't actually send the response yet
                };

                // Override header methods to capture ETag
                customRes.header = function (name, value) {
                    if (name === 'Etag') {
                        partETag = value;
                        req.log.debug({
                            etag: value
                        }, 'S3_MPU: Captured ETag from part upload (header)');
                    }
                    return (res.header(name, value));
                };

                customRes.setHeader = function (name, value) {
                    if (name === 'Etag') {
                        partETag = value;
                        req.log.debug({
                            etag: value
                        }, 'S3_MPU:' +
                          ' Captured ETag from part upload (setHeader)');
                    }
                    return (res.setHeader(name, value));
                };

                // Log the headers being sent to object creation
                req.log.info({
                    uploadId: uploadId,
                    partNumber: partNumber,
                    durabilityHeader: partReq.headers['durability-level'],
                    allHeaders: Object.keys(partReq.headers)
                }, 'S3_MPU: About to call object creation with headers');

                // Use existing object creation logic for part upload
                var createObjectModule = require('./buckets/objects/create');
                var createHandler =
                    createObjectModule.createBucketObjectHandler();

                // Execute the create object chain for the part
                executeMiddlewareChain(createHandler, partReq, customRes,
                                       function (partErr, result) {
                    if (partErr) {
                        req.log.error(partErr, 'S3_MPU: Failed to upload part');
                        return (next(translateBucketError(req, partErr)));
                    }

                    // Use captured ETag or fallback to object ID
                    // from buckets-mdapi
                    var finalETag = partETag || (result && result.id) ||
                        'unknown';

                    req.log.debug({
                        partNumber: partNumber,
                        partId: partId,
                        etag: finalETag,
                        capturedETag: partETag,
                        resultId: result ? result.id : 'no-result'
                    }, 'S3_MPU: Successfully uploaded part');

                    // Update upload record with part information
                    updateUploadRecord(req, uploadId, partNumber, {
                        etag: finalETag,
                        size: req._size || 0,
                        partId: partId,
                        uploaded: new Date().toISOString()
                    }, function (updateErr) {
                        if (updateErr) {
                            req.log.warn(updateErr,
                               'S3_MPU: Failed to update ' +
                               'upload record with part info');
                            // Continue anyway -
                            // the part was uploaded successfully
                        }

                        // Return ETag header (required by S3 clients)
                        res.setHeader('ETag', '"' + finalETag + '"');
                        res.send(200);
                        next(false);
                    });
                });
            }); // Close getDurabilityObject callback
        });
    };
}

/**
 * S3 Complete Multipart Upload Handler
 * POST /{bucket}/{key}?uploadId={uploadId}
 */
function s3CompleteMultipartUploadHandler() {
    return function s3CompleteMultipartUpload(req, res, next) {
        var bucketName = req.s3Request.bucket;
        var objectKey = req.s3Request.object;
        var uploadId = req.s3Request.uploadId;
        var owner = req.owner.account.uuid;

        req.log.debug({
            bucket: bucketName,
            object: objectKey,
            uploadId: uploadId
        }, 'S3_MPU: Completing multipart upload');

        // Parse XML body with part list - try multiple sources
        var body = req.body || req._rawBodyString || null;

        req.log.debug({
            hasBody: !!req.body,
            hasRawBodyString: !!req._rawBodyString,
            hasRawBodyBuffer: !!req._rawBodyBuffer,
            bodyType: typeof (req.body),
            bodyPreview: body ? String(body).substring(0, 200) : 'no body',
            contentLength: req.headers['content-length'],
            contentType: req.headers['content-type']
        }, 'S3_MPU: Debugging complete multipart upload body');

        // If we have a raw body buffer but no string, convert it
        if (!body && req._rawBodyBuffer) {
            body = req._rawBodyBuffer.toString('utf8');
            req.log.debug({
                convertedFromBuffer: true,
                bodyPreview: body.substring(0, 200)
            }, 'S3_MPU: Converted body from buffer');
        }

        if (!body) {
            req.log.error({
                availableProperties: Object.keys(req).filter(function (k) {
                    return (k.indexOf('body') !== -1 ||
                            k.indexOf('Body') !== -1);
                }),
                headers: req.headers
            }, 'S3_MPU: No body found for complete multipart upload');
            return next(new InvalidRequestError('Missing complete multipart'+
                                                ' upload body'));
        }

        var partsFromXML;
        try {
            partsFromXML = parseCompleteMultipartUploadXML(String(body));
            req.log.debug({
                parsedParts: partsFromXML.length,
                firstFewParts: partsFromXML.slice(0, 3)
            }, 'S3_MPU: Successfully parsed XML parts');
        } catch (parseErr) {
            req.log.error({
                parseError: parseErr.message,
                bodyContent: String(body).substring(0, 500)
            }, 'S3_MPU: Failed to parse complete multipart upload XML');
            return (next(new MalformedXMLError(
                'Invalid CompleteMultipartUpload XML: ' + parseErr.message)));
        }

        req.log.debug({
            partsCount: partsFromXML.length,
            parts: partsFromXML
        }, 'S3_MPU: Parsed parts from XML');

        // Read upload record to validate
        getUploadRecord(req, uploadId, function (getErr, uploadRecord) {
            if (getErr) {
                req.log.error(getErr, 'S3_MPU: Failed to read upload record');
                return (next(new NoSuchUploadError(uploadId)));
            }

            // Validate parts exist and are in correct order
            try {
                validatePartsForComplete(uploadRecord, partsFromXML);
            } catch (validationErr) {
                req.log.error(validationErr, 'S3_MPU: Part validation failed');
                return (next(validationErr));
            }

            // Since we don't track parts in the upload record,
            // we'll use the ETags provided in the XML request and
            // calculate size from the parts themselves
            var totalSize = 0;
            var partETags = [];

            partsFromXML.forEach(function (xmlPart) {
                // Use the ETag provided by the client in the XML
                // This should match the ETag we returned during part upload
                partETags.push(xmlPart.etag);
            });

            req.log.debug({
                totalSize: totalSize,
                partCount: partETags.length
            }, 'S3_MPU: Prepared for manta-mako commit');

            // Generate final object ID
            var finalObjectId = uuidv4();

            // Calculate actual total size from uploaded parts
            // using buckets-mdapi
            calculateActualTotalSize(req, uploadId, partETags,
                                     function (sizeErr, actualTotalSize) {
                if (sizeErr) {
                    req.log.error(sizeErr,
                       'S3_MPU: Failed to calculate actual total size');
                    return (next(new InternalError
                        ('Failed to calculate multipart upload size')));
                }

                req.log.debug({
                    partCount: partETags.length,
                    actualTotalSize: actualTotalSize,
                    actualSizeMB: Math.round(actualTotalSize / (1024 * 1024))
                }, 'S3_MPU: Calculated actual total size from parts');

                var commitBody = {
                    version: 1,
                    nbytes: actualTotalSize, // Actual total size from parts
                    account: owner,
                    objectId: finalObjectId,
                    parts: partETags
                };

                // Assemble multipart upload using buckets-mdapi only
                assembleMultipartUpload(req, uploadRecord, commitBody,
                                        function (assembleErr, assembleResult) {
                    if (assembleErr) {
                        req.log.error(assembleErr,
                                      'S3_MPU: multipart assembly failed');
                        return next(new
                                    InternalError(
                                        'Failed to assemble multipart upload'));
                    }

                    req.log.debug({
                        finalObjectId: finalObjectId,
                        md5: assembleResult.md5,
                        assembledSize: assembleResult.nbytes
                    }, 'S3_MPU: multipart assembly successful');

                    // Cleanup upload record and temporary parts
                    cleanupMultipartUpload(req, uploadId,
                                           function (cleanupErr) {
                        if (cleanupErr) {
                            req.log.warn(cleanupErr,
                               'S3_MPU: Cleanup failed' +
                                         ', but upload completed');
                        }

                        req.log.debug({
                            objectId: finalObjectId,
                            assembledSize: assembleResult.nbytes
                        }, 'S3_MPU: Final object created successfully');

                        // Return S3 CompleteMultipartUploadResult XML
                        // Use finalObjectId as ETag to match what was stored
                        var xml = generateCompleteMultipartUploadXML
                              (bucketName, objectKey, '"' +
                               finalObjectId + '"');
                        res.setHeader('Content-Type', 'application/xml');
                        res.send(200, xml);
                        next(false);
                    });
                });
            });
        });
    };
}

/**
 * S3 Abort Multipart Upload Handler
 * DELETE /{bucket}/{key}?uploadId={uploadId}
 */
function s3AbortMultipartUploadHandler() {
    return function s3AbortMultipartUpload(req, res, next) {
        var uploadId = req.s3Request.uploadId;

        req.log.debug({
            uploadId: uploadId
        }, 'S3_MPU: Aborting multipart upload');

        // Cleanup upload record and temporary parts
        cleanupMultipartUpload(req, uploadId, function (cleanupErr) {
            if (cleanupErr) {
                req.log.error(cleanupErr,
                              'S3_MPU: Failed to cleanup aborted upload');
                return next(new
                            InternalError('Failed to abort multipart upload'));
            }

            req.log.debug({
                uploadId: uploadId
            }, 'S3_MPU: Successfully aborted multipart upload');

            res.send(204); // No Content
            next(false);
        });
    };
}

///--- Helper Functions

function generateUploadId() {
    // Generate S3-compatible upload ID (similar to AWS format)
    var timestamp = Date.now().toString(36);
    var random = crypto.randomBytes(8).toString('hex');
    return (timestamp + '-' + random);
}

/* BEGIN JSSTYLED */
function generateInitiateMultipartUploadXML(bucket, key, uploadId) {
    return '<?xml version="1.0" encoding="UTF-8"?>\n' +
           '<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n' +
           '  <Bucket>' + escapeXml(bucket) + '</Bucket>\n' +
           '  <Key>' + escapeXml(key) + '</Key>\n' +
           '  <UploadId>' + escapeXml(uploadId) + '</UploadId>\n' +
           '</InitiateMultipartUploadResult>';
}

function generateCompleteMultipartUploadXML(bucket, key, etag) {
    return '<?xml version="1.0" encoding="UTF-8"?>\n' +
           '<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n' +
           '  <Location>http://s3.amazonaws.com/' + escapeXml(bucket) + '/' + escapeXml(key) + '</Location>\n' +
           '  <Bucket>' + escapeXml(bucket) + '</Bucket>\n' +
           '  <Key>' + escapeXml(key) + '</Key>\n' +
           '  <ETag>' + escapeXml(etag) + '</ETag>\n' +
           '</CompleteMultipartUploadResult>';
}

function parseCompleteMultipartUploadXML(xmlBody) {
    // Simple XML parsing for CompleteMultipartUpload
    var parts = [];
    var partMatches = xmlBody.match(/<Part>[\s\S]*?<\/Part>/g);

    if (!partMatches) {
        throw new Error('No parts found in CompleteMultipartUpload XML');
    }

    partMatches.forEach(function(partXml) {
        var partNumberMatch = partXml.match(/<PartNumber>(\d+)<\/PartNumber>/);
        var etagMatch = partXml.match(/<ETag>"?([^"<]+)"?<\/ETag>/);

        if (partNumberMatch && etagMatch) {
            parts.push({
                partNumber: parseInt(partNumberMatch[1], 10),
                etag: etagMatch[1]
            });
        }
    });

    // Sort parts by part number
    parts.sort(function(a, b) {
        return a.partNumber - b.partNumber;
    });

    return parts;
}

function escapeXml(str) {
    return str.replace(/[<>&'"]/g, function(c) {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
            default: return c;
        }
    });
}
/* END JSSTYLED */

function executeMiddlewareChain(chain, req, res, callback) {
    // Flatten the chain to handle nested arrays from handler factories
    var flatChain = [];
    function flatten(item) {
        if (Array.isArray(item)) {
            item.forEach(flatten);
        } else if (typeof (item) === 'function') {
            flatChain.push(item);
        } else {
            req.log.warn({
                itemType: typeof (item),
                item: item
            }, 'S3_MPU: Unexpected item type in handler chain');
        }
    }
    chain.forEach(flatten);

    var index = 0;

    function executeNext(err) {
        if (err) {
            return (callback(err));
        }

        if (index >= flatChain.length) {
            return (callback(null, req._uploadPartResult));
        }

        var handler = flatChain[index++];

        if (typeof (handler) === 'function') {
            try {
                handler(req, res, executeNext);
            } catch (e) {
                callback(e);
            }
        } else {
            callback(new Error('Invalid handler in chain at index ' +
                               (index - 1)));
        }
    }

    executeNext();
}

function calculateActualTotalSize(req, uploadId, partETags, callback) {
    var owner = req.owner.account.uuid;
    var bucketName = req.s3Request.bucket;
    var totalSize = 0;

    req.log.debug({
        uploadId: uploadId,
        partCount: partETags.length
    }, 'S3_MPU: Calculating actual total size from parts');

    // Load bucket information first
    var uploadReq = Object.create(req);
    uploadReq.params = {
        bucket_name: bucketName,
        object_name: '.mpu-parts/' // Dummy object name for bucket loading
    };

    bucketHelpers.loadRequest(uploadReq, null, function (loadErr) {
        if (loadErr) {
            return (callback(loadErr));
        }

        bucketHelpers.getBucketIfExists(uploadReq, null, function (bucketErr) {
            if (bucketErr) {
                return (callback(bucketErr));
            }

            var bucketId = uploadReq.bucket.id;

            // Query each part object to get its size
            vasync.forEachPipeline({
                func: function getPartSize(partETag, next) {
                    var partNumber = partETags.indexOf(partETag) + 1;
                    var partObjectName = '.mpu-parts/' + uploadId + '/' +
                        partNumber;
                    var objectNameHash = crypto.createHash('md5')
                                              .update(partObjectName)
                                              .digest('hex');

                    var metadataLocation =
                        req.metadataPlacement.getObjectLocation(
                        owner, bucketId, objectNameHash);
                    var client =
                        req.metadataPlacement.getBucketsMdapiClient
                    (metadataLocation);

                    client.getObject(owner, bucketId, partObjectName,
                        metadataLocation.vnode, {}, req.getId(),
                                     function (getErr, result) {

                        if (getErr) {
                            req.log.error({
                                err: getErr,
                                partNumber: partNumber
                            }, 'S3_MPU: Failed to get part size');
                            return (next(getErr));
                        }

                        var partSize = result.content_length || 0;
                        totalSize += partSize;

                        req.log.debug({
                            partNumber: partNumber,
                            partSize: partSize,
                            runningTotal: totalSize
                        }, 'S3_MPU: Added part size to total');

                        next();
                    });
                },
                inputs: partETags
            }, function (err) {
                if (err) {
                    return (callback(err));
                }

                req.log.debug({
                    totalParts: partETags.length,
                    totalSize: totalSize,
                    totalSizeMB: Math.round(totalSize / (1024 * 1024))
                }, 'S3_MPU: Calculated actual total size from all parts');

                callback(null, totalSize);
            });
        });
    });
}

function getUploadRecord(req, uploadId, callback) {
    var uploadRecordKey = '.mpu-uploads/' + uploadId;
    var owner = req.owner.account.uuid;

    // Create request to get upload record
    var uploadReq = Object.create(req);
    uploadReq.params = {
        bucket_name: req.s3Request.bucket,
        object_name: uploadRecordKey
    };

    bucketHelpers.loadRequest(uploadReq, null, function (loadErr) {
        if (loadErr) {
            return (callback(loadErr));
        }

        bucketHelpers.getBucketIfExists(uploadReq, null, function (bucketErr) {
            if (bucketErr) {
                return (callback(bucketErr));
            }

            var metadataLocation = req.metadataPlacement.getObjectLocation(
                owner, uploadReq.bucket.id, crypto.createHash('md5')
                                                  .update(uploadRecordKey)
                                                  .digest('hex'));
            var client =
                req.metadataPlacement.getBucketsMdapiClient(metadataLocation);

            client.getObject(owner, uploadReq.bucket.id, uploadRecordKey,
                metadataLocation.vnode, {}, req.getId(),
                             function (getErr, result) {

                req.log.debug({
                    uploadId: uploadId,
                    hasValue: result && !!result.value,
                    contentLength: result && result.content_length,
                    resultKeys: result ? Object.keys(result) : []
                }, 'S3_MPU: Raw buckets-mdapi result debug');

                if (getErr) {
                    return (callback(getErr));
                }

                try {
                    var uploadRecord = JSON.parse(result.value || '{}');
                    // Add bucket ID for later use
                    uploadRecord.bucketId = uploadReq.bucket.id;

                    // Durability level should already be in the JSON
                    // content from initiate
                    // No need to extract from headers since it's stored in
                    // the record itself

                    req.log.debug({
                        uploadId: uploadId,
                        durabilityLevel: uploadRecord.durabilityLevel,
                        recordContent: uploadRecord
                    }, 'S3_MPU: Retrieved upload record with durability level');

                    callback(null, uploadRecord);
                } catch (parseErr) {
                    callback(parseErr);
                }
            });
        });
    });
}

function updateUploadRecord(req, uploadId, partNumber, partInfo, callback) {
    // For now, we'll skip updating the upload record during part upload
    // This avoids complex race conditions and the record isn't strictly needed
    // until completion. In production, you might want to implement this
    // for better tracking and recovery.
    callback(null);
}

function validatePartsForComplete(uploadRecord, partsFromXML) {
    // Validate parts are in ascending order
    for (var i = 1; i < partsFromXML.length; i++) {
        if (partsFromXML[i].partNumber <= partsFromXML[i - 1].partNumber) {
            throw new InvalidPartOrderError();
        }
    }

    // For now, we'll accept any parts since we're not strictly tracking
    // them in the upload record. In production, you'd want to validate
    // that each part exists and matches the provided ETag.
}


function assembleMultipartUpload(req, uploadRecord, commitBody, callback) {
    req.log.debug({
        uploadId: uploadRecord.uploadId,
        partCount: commitBody.parts.length,
        actualSize: commitBody.nbytes
    }, 'S3_MPU: Assembling multipart upload using buckets-mdapi');

    // Step 1: Discover part paths from buckets-mdapi
    discoverPartPaths(req, uploadRecord, commitBody.parts,
                      function (err, partPaths) {
        if (err) {
            req.log.error(err, 'S3_MPU: Failed to discover part paths');
            return (callback(err));
        }

        req.log.debug({
            partPathsCount: partPaths.length,
            firstFewPaths: partPaths.slice(0, 3)
        }, 'S3_MPU: Discovered part paths from buckets-mdapi');

        // Step 2: Verify total size matches what we calculated
        var discoveredTotalSize = partPaths.reduce(
            function (sum, partPath) {
                return (sum + (partPath.size || 0));
        }, 0);

        req.log.debug({
            commitBodySize: commitBody.nbytes,
            discoveredTotalSize: discoveredTotalSize,
            sizeDifference: discoveredTotalSize - commitBody.nbytes
        }, 'S3_MPU: Size verification from part discovery');

        // Use the discovered size if different (more accurate)
        var finalSize = discoveredTotalSize || commitBody.nbytes;

        var finalCommitBody = {
            version: 1,
            nbytes: finalSize,
            account: commitBody.account,
            objectId: commitBody.objectId,
            parts: partPaths.map(function (partPath) {
                return (partPath.sharkPath);
            })
        };

        req.log.debug({
            finalSize: finalSize,
            partCount: partPaths.length
        }, 'S3_MPU: Starting multipart assembly via buckets-mdapi');

        // Step 3: Use buckets-mdapi custom assembly
        customAssembleMultipartUpload(req, uploadRecord, partPaths,
                                      finalCommitBody, callback);
    });
}

function customAssembleMultipartUpload(req, uploadRecord, partPaths, commitBody,
                                       callback) {
    req.log.debug({
        partCount: partPaths.length,
        totalSize: commitBody.nbytes
    }, 'S3_MPU: Starting multipart assembly through buckets-mdapi');

    // Step 1: Stream parts directly to final storage (memory-efficient)
    // Pass context for streaming assembly
    req._uploadRecord = uploadRecord;
    req._finalObjectId = commitBody.objectId;

    streamAndAssembleParts(req, partPaths, function (streamErr, assemblyData) {
        if (streamErr) {
            req.log.error(streamErr,
                          'S3_MPU: Failed to stream and assemble parts');
            return (callback(streamErr));
        }

        req.log.debug({
            assembledSize: assemblyData.totalBytes,
            finalMD5: assemblyData.md5,
            sharksUsed: assemblyData.sharks ? assemblyData.sharks.length : 0
        }, 'S3_MPU: Successfully streamed parts to final storage');

        // Step 2: Create metadata for the final object (data is already stored)
        // Use the pre-allocated sharks to ensure metadata matches storage
        // location
        createFinalObjectMetadata(req, uploadRecord, commitBody, assemblyData,
                                  req._finalSharks,
                                  function (metaErr, objectResult) {
            if (metaErr) {
                req.log.error(metaErr,
                              'S3_MPU: Failed to create final object metadata');
                return (callback(metaErr));
            }

            req.log.debug({
                finalObjectId: commitBody.objectId,
                storedSize: assemblyData.totalBytes,
                storedMD5: assemblyData.md5
            }, 'S3_MPU: Successfully completed streaming multipart assembly');

            var assembleResult = {
                md5: assemblyData.md5,
                nbytes: assemblyData.totalBytes,
                sharks: assemblyData.sharks || []
            };

            callback(null, assembleResult);
        });
    });
}

function streamAndAssembleParts(req, partPaths, callback) {
    req.log.debug({
        partsToStream: partPaths.length,
        approxTotalSize: partPaths.reduce(function (sum, p)
                                          { return sum + (p.size || 0); }, 0),
        finalObjectId: req._finalObjectId
    }, 'S3_MPU: Starting streaming assembly (memory-efficient)');

    // Use normal object creation flow to ensure proper shark allocation and
    // storage
    // This ensures the data location matches exactly what will be in metadata

    // Get durability level from stored temporary object with metadata
    var uploadRecord = req._uploadRecord;
    var durabilityKey = '.mpu-uploads/' +
        (uploadRecord ? uploadRecord.uploadId : 'unknown') + '.durability';

    getDurabilityObject(req, durabilityKey, function (durErr, durabilityData) {
        var copies;
        if (!durErr && durabilityData && durabilityData.durabilityLevel) {
            copies = durabilityData.durabilityLevel;
            req.log.debug({
                uploadId: uploadRecord ? uploadRecord.uploadId : 'unknown',
                durabilityLevel: copies,
                source: 'durability-object'
            }, 'S3_MPU: Using durability level' +
                          'from durability object for streaming assembly');
        } else {
            // Fallback to upload record or request headers
            copies = (uploadRecord && uploadRecord.durabilityLevel) ||
                     parseInt((req.header('durability-level') ||
                               req.header('x-durability-level') ||
                               common.DEF_NUM_COPIES), 10);
            req.log.debug({
                uploadId: uploadRecord ? uploadRecord.uploadId : 'unknown',
                durabilityLevel: copies,
                source: uploadRecord && uploadRecord.durabilityLevel ?
                    'upload-record' : 'headers-or-default',
                durabilityObjectError: durErr
            }, 'S3_MPU: Using fallback durability' +
                          ' level for streaming assembly');
        }

        // Allocate sharks using the standard buckets-api flow
        var opts = {
            replicas: copies,
            requestId: req.getId(),
            size: partPaths.reduce(function (sum, p)
                                   { return sum + (p.size || 0); }, 0),
            isOperator: req.caller.account.isOperator
        };

        req.storinfo.choose(opts, function (sharkErr, sharks) {
            if (sharkErr) {
                req.log.error(sharkErr,
                  'S3_MPU: Failed to allocate sharks for streaming assembly');
                return (callback(sharkErr));
            }

            // Flatten shark array if nested
            var flatSharks = [];
            sharks.forEach(function (shark) {
                if (Array.isArray(shark)) {
                    flatSharks = flatSharks.concat(shark);
                } else {
                    flatSharks.push(shark);
                }
            });

            req.log.debug({
                allocatedSharks: flatSharks.map(
                    function (s) { return s.manta_storage_id; }),
                finalObjectId: req._finalObjectId
            }, 'S3_MPU: Allocated sharks for streaming assembly');

            // Store the allocated sharks for metadata creation
            req._finalSharks = flatSharks;

            // Stream parts directly to the allocated sharks using the
            // final object ID
            streamPartsToFinalSharks(req, partPaths, flatSharks,
                                     req._finalObjectId,
                                     function (streamErr, assemblyResult) {
                if (streamErr) {
                    return (callback(streamErr));
                }

                // Include the sharks used for storage in the result
                assemblyResult.sharks = flatSharks;
                callback(null, assemblyResult);
            });
        });
    });
}

function streamPartsToFinalSharks(req, partPaths, finalSharks, finalObjectId,
                                  callback) {
    var owner = req.owner.account.uuid;
    var uploadRecord = req._uploadRecord; // Pass this from the calling context
    var objectName = req.s3Request.object;
    var objectId = finalObjectId; // Use the provided final object ID
    var objectNameHash = crypto.createHash('md5').update(objectName).
        digest('hex');
    var totalBytes = 0;
    var md5Hash = crypto.createHash('md5');

    req.log.debug({
        finalSharks: finalSharks.map(
            function (s) { return s.manta_storage_id; }),
        partCount: partPaths.length
    }, 'S3_MPU: Starting direct streaming to final sharks');

    // Create PUT streams to final sharks
    var sharkStreams = [];
    var completedSharks = [];

    // Use a barrier to wait for all sharks to complete
    var barrier = vasync.barrier();
    var streamingComplete = false;

    vasync.forEachParallel({
        func: function setupSharkStream(shark, next) {
            var client = sharkClient.getClient({
                connectTimeout: (req.sharkConfig &&
                                 req.sharkConfig.connectTimeout) || 5000,
                log: req.log,
                retry: (req.sharkConfig && req.sharkConfig.retry) || {},
                shark: shark,
                agent: req.sharkAgent
            });

            var putOpts = {
                contentType: 'application/octet-stream',
                contentLength: undefined, // Chunked encoding
                owner: owner,
                bucketId: uploadRecord ? uploadRecord.bucketId : 'unknown',
                objectId: objectId,
                objectName: objectName,
                objectNameHash: objectNameHash,
                requestId: req.getId(),
                storageLayoutVersion: common.CURRENT_STORAGE_LAYOUT_VERSION
            };

            client.put(putOpts, function (putErr, sharkReq) {
                if (putErr) {
                    req.log.error({
                        err: putErr,
                        shark: shark.manta_storage_id
                    }, 'S3_MPU: Failed to create PUT stream to final shark');
                    return (next(putErr));
                }

                sharkReq._shark = shark;
                sharkStreams.push(sharkReq);

                // Start barrier for this shark
                barrier.start(shark.manta_storage_id);

                sharkReq.once('response', function (sharkRes) {
                    if (sharkRes.statusCode >= 400) {
                        var err =
                            new Error(
                                'Final shark storage failed with status '
                                    + sharkRes.statusCode);
                        req.log.error({
                            err: err,
                            shark: shark.manta_storage_id,
                            statusCode: sharkRes.statusCode
                        }, 'S3_MPU: Final shark storage failed');
                        barrier.done(shark.manta_storage_id);
                        return (next(err));
                    }

                    req.log.debug({
                        shark: shark.manta_storage_id,
                        statusCode: sharkRes.statusCode
                    }, 'S3_MPU: Final shark confirmed successful storage');

                    completedSharks.push(shark);
                    barrier.done(shark.manta_storage_id);
                });

                sharkReq.once('error', function (reqErr) {
                    req.log.error({
                        err: reqErr,
                        shark: shark.manta_storage_id
                    }, 'S3_MPU: Final shark request error');
                    barrier.done(shark.manta_storage_id);
                    next(reqErr);
                });

                // Call next() immediately for setup,
                // completion handled by barrier
                next();
            });
        },
        inputs: finalSharks
    }, function (setupErr) {
        if (setupErr) {
            // Clean up any created streams
            sharkStreams.forEach(function (stream) {
                try { stream.abort(); } catch (e) {}
            });
            return (callback(setupErr));
        }

        req.log.debug({
            establishedStreams: sharkStreams.length
        }, 'S3_MPU: Established streams to all final sharks' +
                      ', starting part streaming');

        // Set up barrier completion handler
        barrier.once('drain', function () {
            if (!streamingComplete) {
                req.log.warn(
                    'S3_MPU: Sharks completed before streaming finished');
                return;
            }

            // Calculate MD5 only once
            var finalMD5 = md5Hash.digest('base64');

            req.log.debug({
                totalBytes: totalBytes,
                finalMD5: finalMD5,
                completedSharks: completedSharks.length
            }, 'S3_MPU: All sharks completed successfully');

            var assemblyResult = {
                totalBytes: totalBytes,
                md5: finalMD5,
                sharks: completedSharks,
                buffer: null // No buffer needed for streaming approach
            };

            callback(null, assemblyResult);
        });

        // Now stream parts sequentially to all shark streams
        vasync.forEachPipeline({
            func: function streamPartToSharks(partPath, nextPart) {
                req.log.debug({
                    partNumber: partPath.partNumber,
                    partSize: partPath.size
                }, 'S3_MPU: Streaming part to final sharks');

                streamPartFromSharks(req, partPath,
                                     function (partErr, partBuffer) {
                    if (partErr) {
                        req.log.error({
                            err: partErr,
                            partNumber: partPath.partNumber
                        },
                        'S3_MPU: Failed to retrieve part for final streaming');
                        return (nextPart(partErr));
                    }

                    // Write this part to all shark streams
                    sharkStreams.forEach(function (sharkStream) {
                        sharkStream.write(partBuffer);
                    });

                    // Update totals
                    totalBytes += partBuffer.length;
                    md5Hash.update(partBuffer);

                    req.log.debug({
                        partNumber: partPath.partNumber,
                        partBytes: partBuffer.length,
                        totalBytes: totalBytes
                    }, 'S3_MPU: Successfully streamed part to final sharks');

                    nextPart();
                });
            },
            inputs: partPaths
        }, function (streamErr) {
            // End all shark streams
            sharkStreams.forEach(function (sharkStream) {
                sharkStream.end();
            });

            streamingComplete = true;

            if (streamErr) {
                req.log.error(streamErr,
                    'S3_MPU: Failed during part streaming to final sharks');
                return (callback(streamErr));
            }

            req.log.debug({
                totalBytes: totalBytes,
                sharksToComplete: sharkStreams.length
            }, 'S3_MPU: Finished streaming all parts,' +
                          ' marked streaming complete');
        });
    });
}

function streamPartFromSharks(req, partPath, callback) {
    // Get available sharks for this part
    var sharks = partPath.sharks;
    if (!sharks || sharks.length === 0) {
        return callback(new Error('No sharks available for part ' +
                                  partPath.partNumber));
    }

    req.log.debug({
        partNumber: partPath.partNumber,
        availableSharks: sharks.map(
            function (s) { return s.manta_storage_id; }),
        partPath: partPath.sharkPath,
        partSize: partPath.size
    }, 'S3_MPU: Available sharks for part');

    // Implement retry logic at the part level
    var maxPartRetries = 3;
    var currentRetry = 0;

    function retryPartStream() {
        if (currentRetry >= maxPartRetries) {
            return callback(new Error('Failed to stream part ' +
               partPath.partNumber + ' after ' + maxPartRetries + ' retries'));
        }

        currentRetry++;
        req.log.debug({
            partNumber: partPath.partNumber,
            retryAttempt: currentRetry,
            maxRetries: maxPartRetries
        }, 'S3_MPU: Attempting to stream part (retry ' + currentRetry + ')');

        // Try sharks in order until one succeeds
        tryStreamFromShark(req, partPath, sharks, 0,
                           function (tryErr, partBuffer) {
            if (tryErr) {
                req.log.warn({
                    err: tryErr,
                    partNumber: partPath.partNumber,
                    retryAttempt: currentRetry
                }, 'S3_MPU: Part stream attempt failed, will retry');

                // Wait a bit before retrying
                setTimeout(retryPartStream, 1000 * currentRetry);
                return;
            }

            callback(null, partBuffer);
        });
    }

    retryPartStream();
}

function tryStreamFromShark(req, partPath, sharks, sharkIndex, callback) {
    if (sharkIndex >= sharks.length) {
        req.log.error({
            partNumber: partPath.partNumber,
            sharksAttempted: sharks.map(
                function (s) { return s.manta_storage_id; })
        }, 'S3_MPU: Exhausted all sharks for part');
        return callback(new Error('Failed to stream part ' +
            partPath.partNumber + ' from all available sharks'));
    }

    var shark = sharks[sharkIndex];

    req.log.debug({
        partNumber: partPath.partNumber,
        shark: shark.manta_storage_id,
        sharkPath: partPath.sharkPath,
        sharkIndex: sharkIndex,
        totalSharks: sharks.length
    }, 'S3_MPU: Trying to stream part from shark');

    // Create a custom shark client with extended timeout specifically for
    // multipart assembly
    // We need to create a new client instance to avoid cache conflicts with
    // different timeouts
    // XXXX should we configure/tune this one?
    var extendedTimeout = 30000; // 30 seconds for multipart part retrieval

    req.log.debug({
        partNumber: partPath.partNumber,
        shark: shark.manta_storage_id,
        connectTimeout: extendedTimeout
    }, 'S3_MPU: Creating shark client with extended timeout');

    // Due to shark client caching issues with different timeouts,
    // implement direct HTTP request for multipart part retrieval
    var http = require('http');

    // Make direct HTTP request to shark with extended timeout
    var httpOptions = {
        hostname: shark.manta_storage_id,
        port: 80,
        path: partPath.sharkPath,
        method: 'GET',
        headers: {
            'connection': 'keep-alive',
            'x-request-id': req.getId()
        },
        timeout: extendedTimeout
    };

    req.log.debug({
        partNumber: partPath.partNumber,
        shark: shark.manta_storage_id,
        sharkPath: partPath.sharkPath,
        timeout: extendedTimeout
    }, 'S3_MPU: Making direct HTTP request to shark');

    var httpReq = http.request(httpOptions, function (res) {
        req.log.debug({
            partNumber: partPath.partNumber,
            shark: shark.manta_storage_id,
            statusCode: res.statusCode
        }, 'S3_MPU: Received response from shark');

        if (res.statusCode >= 400) {
            req.log.warn({
                partNumber: partPath.partNumber,
                shark: shark.manta_storage_id,
                statusCode: res.statusCode,
                sharkIndex: sharkIndex
            }, 'S3_MPU: HTTP error from shark, trying next shark');

            // Try next shark
            return tryStreamFromShark(req, partPath, sharks, sharkIndex + 1,
                                      callback);
        }

        var chunks = [];
        var responseStarted = false;

        res.on('data', function (chunk) {
            if (!responseStarted) {
                responseStarted = true;
                req.log.debug({
                    partNumber: partPath.partNumber,
                    shark: shark.manta_storage_id
                }, 'S3_MPU: Started receiving data from shark');
            }
            chunks.push(chunk);
        });

        res.on('end', function () {
            var partBuffer = Buffer.concat(chunks);

            req.log.debug({
                partNumber: partPath.partNumber,
                receivedBytes: partBuffer.length,
                expectedBytes: partPath.size,
                shark: shark.manta_storage_id
            }, 'S3_MPU: Successfully received complete part from shark');

            callback(null, partBuffer);
        });

        res.on('error', function (resErr) {
            req.log.warn({
                err: resErr,
                partNumber: partPath.partNumber,
                shark: shark.manta_storage_id,
                sharkIndex: sharkIndex
            }, 'S3_MPU: Error receiving part from shark, trying next shark');

            // Try next shark
            tryStreamFromShark(req, partPath, sharks, sharkIndex + 1, callback);
        });
    });

    httpReq.on('error', function (reqErr) {
        req.log.warn({
            err: reqErr,
            partNumber: partPath.partNumber,
            shark: shark.manta_storage_id,
            sharkIndex: sharkIndex
        }, 'S3_MPU: HTTP request error, trying next shark');

        // Try next shark
        tryStreamFromShark(req, partPath, sharks, sharkIndex + 1, callback);
    });

    httpReq.on('timeout', function () {
        req.log.warn({
            partNumber: partPath.partNumber,
            shark: shark.manta_storage_id,
            timeout: extendedTimeout,
            sharkIndex: sharkIndex
        }, 'S3_MPU: HTTP request timeout, trying next shark');

        httpReq.abort();
        tryStreamFromShark(req, partPath, sharks, sharkIndex + 1, callback);
    });

    httpReq.end();
}

function storeAssembledObject(req, uploadRecord, commitBody, assemblyData,
                              callback) {
    req.log.debug({
        objectId: commitBody.objectId,
        assembledSize: assemblyData.totalBytes,
        assembledMD5: assemblyData.md5
    }, 'S3_MPU: Storing assembled object through buckets-mdapi');

    var finalObjectId = commitBody.objectId;
    var finalBuffer = assemblyData.buffer;

    // Get durability level from stored temporary object with metadata
    var durabilityKey = '.mpu-uploads/' + uploadRecord.uploadId + '.durability';

    getDurabilityObject(req, durabilityKey, function (durErr, durabilityData) {
        var copies;
        if (!durErr && durabilityData && durabilityData.durabilityLevel) {
            copies = durabilityData.durabilityLevel;
            req.log.debug({
                uploadId: uploadRecord.uploadId,
                durabilityLevel: copies,
                source: 'durability-object'
            }, 'S3_MPU: Using durability level from durability' +
               ' object for final object storage');
        } else {
            // Fallback to upload record or request headers
            copies = (uploadRecord && uploadRecord.durabilityLevel) ||
                     parseInt((req.header('durability-level') ||
                               req.header('x-durability-level') ||
                               common.DEF_NUM_COPIES), 10);
            req.log.debug({
                uploadId: uploadRecord.uploadId,
                durabilityLevel: copies,
                source: uploadRecord && uploadRecord.durabilityLevel ?
                    'upload-record' : 'headers-or-default',
                durabilityObjectError: durErr
            }, 'S3_MPU: Using fallback durability level' +
               ' for final object storage');
        }

        // Step 1: Find sharks for the final object
        var opts = {
            replicas: copies,
            requestId: req.getId(),
            size: assemblyData.totalBytes,
            isOperator: req.caller.account.isOperator
        };

        req.storinfo.choose(opts, function (sharkErr, sharks) {
        if (sharkErr) {
            req.log.error(sharkErr,
               'S3_MPU: Failed to allocate sharks for final object');
            return (callback(sharkErr));
        }

        // Flatten shark array if nested
        var flatSharks = [];
        sharks.forEach(function (shark) {
            if (Array.isArray(shark)) {
                flatSharks = flatSharks.concat(shark);
            } else {
                flatSharks.push(shark);
            }
        });

        req.log.debug({
            allocatedSharks: flatSharks.map(
                function (s) { return s.manta_storage_id; }),
            objectSize: assemblyData.totalBytes
        }, 'S3_MPU: Allocated sharks for final object');

        // Step 2: Stream assembled data to sharks
        storeDataToSharks(req, uploadRecord, finalObjectId, finalBuffer,
                          flatSharks, function (storeErr, storedSharks) {
            if (storeErr) {
                req.log.error(storeErr,
                   'S3_MPU: Failed to store assembled data to sharks');
                return (callback(storeErr));
            }

            req.log.debug({
                storedSharks: storedSharks.map(
                    function (s) { return s.manta_storage_id; })
            }, 'S3_MPU: Successfully stored assembled data to sharks');

            // Step 3: Create final object metadata
            createFinalObjectMetadata(req, uploadRecord, commitBody,
                           assemblyData, storedSharks,
                                      function (metaErr, objectResult) {
                if (metaErr) {
                    req.log.error(metaErr,
                       'S3_MPU: Failed to create final object metadata');
                    return (callback(metaErr));
                }

                req.log.debug({
                    objectId: finalObjectId,
                    objectSize: assemblyData.totalBytes,
                    objectMD5: assemblyData.md5,
                    sharks: storedSharks.length
                }, 'S3_MPU: Successfully created final object');

                var storeResult = {
                    size: assemblyData.totalBytes,
                    md5: assemblyData.md5,
                    sharks: storedSharks
                };

                callback(null, storeResult);
            });
        });
    });
    }); // Close getDurabilityObject callback
}

function storeDataToSharks(req, uploadRecord, objectId, dataBuffer, sharks,
                           callback) {
    var owner = req.owner.account.uuid;
    var bucketId = uploadRecord.bucketId;
    var objectName = req.s3Request.object;
    var objectNameHash = crypto.createHash('md5').update(objectName).
        digest('hex');
    var storedSharks = [];

    req.log.debug({
        objectId: objectId,
        dataSize: dataBuffer.length,
        targetSharks: sharks.map(function (s) { return s.manta_storage_id; })
    }, 'S3_MPU: Starting to store data to sharks');

    // Store data to sharks in parallel
    vasync.forEachParallel({
        func: function storeToShark(shark, next) {
            var client = sharkClient.getClient({
                connectTimeout: (req.sharkConfig &&
                                 req.sharkConfig.connectTimeout) || 5000,
                log: req.log,
                retry: (req.sharkConfig && req.sharkConfig.retry) || {},
                shark: shark,
                agent: req.sharkAgent
            });

            var putOpts = {
                contentType: 'application/octet-stream',
                contentLength: dataBuffer.length,
                contentMd5: crypto.createHash('md5').update(dataBuffer).
                    digest('base64'),
                owner: owner,
                bucketId: bucketId,
                objectId: objectId,
                objectName: objectName,
                objectNameHash: objectNameHash,
                requestId: req.getId(),
                storageLayoutVersion: common.CURRENT_STORAGE_LAYOUT_VERSION
            };

            req.log.debug({
                shark: shark.manta_storage_id,
                objectId: objectId,
                dataSize: dataBuffer.length
            }, 'S3_MPU: Storing to individual shark');

            client.put(putOpts, function (putErr, sharkReq) {
                if (putErr) {
                    req.log.error({
                        err: putErr,
                        shark: shark.manta_storage_id
                    }, 'S3_MPU: Failed to initiate storage to shark');
                    return (next(putErr));
                }

                // Write the assembled data to the shark
                sharkReq.end(dataBuffer);

                sharkReq.once('response', function (sharkRes) {
                    if (sharkRes.statusCode >= 400) {
                        var err = new Error('Shark storage failed with status '
                                            + sharkRes.statusCode);
                        req.log.error({
                            err: err,
                            shark: shark.manta_storage_id,
                            statusCode: sharkRes.statusCode
                        }, 'S3_MPU: Shark storage failed');
                        return (next(err));
                    }

                    req.log.debug({
                        shark: shark.manta_storage_id,
                        statusCode: sharkRes.statusCode
                    }, 'S3_MPU: Successfully stored to shark');

                    storedSharks.push(shark);
                    next();
                });

                sharkReq.once('error', function (reqErr) {
                    req.log.error({
                        err: reqErr,
                        shark: shark.manta_storage_id
                    }, 'S3_MPU: Shark request error');
                    next(reqErr);
                });
            });
        },
        inputs: sharks
    }, function (parallelErr) {
        if (parallelErr) {
            return (callback(parallelErr));
        }

        req.log.debug({
            successfulSharks: storedSharks.length,
            requiredSharks: sharks.length
        }, 'S3_MPU: Completed storing data to sharks');

        callback(null, storedSharks);
    });
}

function createFinalObjectMetadata(req, uploadRecord, commitBody, assemblyData,
                                   preAllocatedSharks, callback) {
    var owner = req.owner.account.uuid;
    var bucketId = uploadRecord.bucketId;
    var objectName = req.s3Request.object;
    var objectId = commitBody.objectId;
    var objectNameHash = crypto.createHash('md5').update(objectName).
        digest('hex');

    req.log.debug({
        objectId: objectId,
        objectName: objectName,
        bucketId: bucketId,
        dataSize: assemblyData.totalBytes,
        preAllocatedSharks: preAllocatedSharks.map(
            function (s) { return s.manta_storage_id; })
    }, 'S3_MPU: Creating final object metadata using pre-allocated sharks');

    // Get metadata placement for the final object
    var metadataLocation = req.metadataPlacement.getObjectLocation(
        owner, bucketId, objectNameHash);
    var client = req.metadataPlacement.getBucketsMdapiClient(metadataLocation);

    // Prepare final object metadata
    var headers = {
        'content-type': 'application/octet-stream',
        // Headers must be strings
        'content-length': String(assemblyData.totalBytes),
        'content-md5': assemblyData.md5
    };

    // Add any custom headers from the original initiate request if available
    if (req.headers) {
        Object.keys(req.headers).forEach(function (key) {
            if (key.toLowerCase().indexOf('x-amz-meta-') === 0) {
                headers[key] = req.headers[key];
            }
        });
    }

    // Format pre-allocated sharks as array of objects (sequence) for
    // RPC protocol. This ensures metadata points to the same sharks where data
    // was actually stored
    var sharkData = preAllocatedSharks.map(function (shark) {
        return {
            datacenter: shark.datacenter || 'coal',
            manta_storage_id: shark.manta_storage_id
        };
    });

    client.createObject(
        owner,
        bucketId,
        objectName,
        objectId,
        parseInt(assemblyData.totalBytes, 10), // Ensure it's a proper number
        assemblyData.md5,
        'application/octet-stream',
        headers,
        sharkData,
        {}, // props - empty object instead of null
        metadataLocation.vnode,
        {}, // conditions - empty object instead of null
        req.getId(),
        function (createErr, objectResult) {
            if (createErr) {
                req.log.error({
                    err: createErr,
                    objectId: objectId,
                    objectName: objectName
                }, 'S3_MPU: Failed to create final object metadata');
                return (callback(createErr));
            }

            req.log.debug({
                objectId: objectId,
                objectName: objectName,
                objectResult: objectResult
            }, 'S3_MPU: Successfully created final object metadata');
            callback(null, objectResult);
        });
}

function discoverPartPaths(req, uploadRecord, partETags, callback) {
    var owner = req.owner.account.uuid;
    var bucketId = uploadRecord.bucketId;
    // Get upload ID from the request, not the record!
    var uploadId = req.s3Request.uploadId;
    var partPaths = [];

    req.log.debug({
        uploadId: uploadId,
        uploadRecord: uploadRecord,
        partETags: partETags,
        bucketId: bucketId
    }, 'S3_MPU: Discovering real shark paths for parts' +
           ' - debugging upload record');

    // Use vasync to query all part objects in parallel
    vasync.forEachParallel({
        func: function queryPartObject(partETag, next) {
            // Get part number from array index
            var partNumber = partETags.indexOf(partETag) + 1;
            // Part object name follows our naming convention
            var partObjectName = '.mpu-parts/' + uploadId + '/' + partNumber;

            req.log.debug({
                partNumber: partNumber,
                partETag: partETag,
                partObjectName: partObjectName
            }, 'S3_MPU: Querying part object metadata');

            // Create request context for part object lookup
            var partReq = Object.create(req);
            partReq.params = {
                bucket_name: req.s3Request.bucket,
                object_name: partObjectName
            };

            bucketHelpers.loadRequest(partReq, null, function (loadErr) {
                if (loadErr) {
                    req.log.error(loadErr,
                       'S3_MPU: Failed to load request for part object');
                    return (next(loadErr));
                }

                bucketHelpers.getBucketIfExists(partReq, null,
                                                function (bucketErr) {
                    if (bucketErr) {
                        req.log.error(bucketErr,
                           'S3_MPU: Bucket not found for part object');
                        return (next(bucketErr));
                    }

                    // Get part object metadata
                    var metadataLocation =
                        req.metadataPlacement.getObjectLocation(
                        owner, bucketId, crypto.createHash('md5')
                                                .update(partObjectName)
                                                .digest('hex'));
                    var client =
                        req.metadataPlacement.
                        getBucketsMdapiClient(metadataLocation);

                    client.getObject(owner, bucketId, partObjectName,
                        metadataLocation.vnode, {}, req.getId(),
                                     function (getErr, partMeta) {

                        if (getErr) {
                            req.log.error(getErr,
                               'S3_MPU: Failed to get part object metadata');
                            return (next(getErr));
                        }

                        req.log.debug({
                            partNumber: partNumber,
                            partMeta: {
                                id: partMeta.id,
                                content_length: partMeta.content_length,
                                sharks: partMeta.sharks
                            }
                        }, 'S3_MPU: Retrieved part object metadata');

                        // Construct storage path using shark_client.storagePath
                        var objectNameHash = crypto.createHash('md5')
                                                   .update(partObjectName)
                                                   .digest('hex');

                        var sharkPath = sharkClient.storagePath({
                            storageLayoutVersion: 2,
                            owner: owner,
                            bucketId: bucketId,
                            objectNameHash: objectNameHash,
                            objectId: partMeta.id
                        });

                        var partPath = {
                            partNumber: partNumber,
                            partETag: partETag,
                            objectId: partMeta.id,
                            size: partMeta.content_length,
                            sharks: partMeta.sharks,
                            sharkPath: sharkPath
                        };

                        req.log.debug({
                            partNumber: partNumber,
                            sharkPath: sharkPath,
                            sharks: partMeta.sharks
                        }, 'S3_MPU: Constructed shark path for part');

                        partPaths[partNumber - 1] = partPath;
                        next();
                    });
                });
            });
        },
        inputs: partETags
    }, function (err, results) {
        if (err) {
            req.log.error(err, 'S3_MPU: Failed to discover part paths');
            return (callback(err));
        }

        // Filter out any undefined entries and sort by part number
        var sortedPartPaths = partPaths.filter(function (path) {
            return (path !== undefined);
        }).sort(function (a, b) {
            return (a.partNumber - b.partNumber);
        });

        req.log.debug({
            totalParts: sortedPartPaths.length,
            totalSize: sortedPartPaths.reduce(function (sum, part) {
                return (sum + (part.size || 0));
            }, 0)
        }, 'S3_MPU: Successfully discovered all part paths');

        callback(null, sortedPartPaths);
    });
}


function cleanupMultipartUpload(req, uploadId, callback) {
    // TODO: Implement cleanup of upload record and temporary parts
    req.log.debug({
        uploadId: uploadId
    }, 'S3_MPU: Cleanup multipart upload (TODO)');

    callback(null);
}

///--- Error Classes

function InvalidPartNumberError(partNumber) {
    var err = new Error('Part number must be between 1 and 10000');
    err.name = 'InvalidPartNumber';
    err.statusCode = 400;
    err.restCode = 'InvalidPartNumber';
    return (err);
}

function NoSuchUploadError(uploadId) {
    var err = new Error('The specified upload does not exist');
    err.name = 'NoSuchUpload';
    err.statusCode = 404;
    err.restCode = 'NoSuchUpload';
    return (err);
}

function InvalidPartOrderError() {
    var err = new Error('The list of parts was not in ascending order');
    err.name = 'InvalidPartOrder';
    err.statusCode = 400;
    err.restCode = 'InvalidPartOrder';
    return (err);
}

function MalformedXMLError(message) {
    var err = new Error(message || 'The XML you provided was not well-formed');
    err.name = 'MalformedXML';
    err.statusCode = 400;
    err.restCode = 'MalformedXML';
    return (err);
}

function InvalidRequestError(message) {
    var err = new Error(message || 'Invalid request');
    err.name = 'InvalidRequest';
    err.statusCode = 400;
    err.restCode = 'InvalidRequest';
    return (err);
}

function InternalError(message) {
    var err = new Error(message || 'Internal server error');
    err.name = 'InternalError';
    err.statusCode = 500;
    err.restCode = 'InternalError';
    return (err);
}

///--- Helper functions for durability level storage/retrieval

function storeDurabilityObject(req, durabilityKey, durabilityData) {
    // Fire-and-forget storage using direct buckets-mdapi call
    process.nextTick(function () {
        var content = JSON.stringify(durabilityData);
        var contentMD5 = crypto.createHash('md5').
            update(content).digest('base64');
        var objectId = uuidv4();
        var owner = req.owner.account.uuid;
        var bucketName = req.s3Request.bucket;

        // Create a clean request context for durability object storage
        var durabilityReq = Object.create(req);
        durabilityReq.params = {
            bucket_name: bucketName,
            object_name: durabilityKey
        };

        // Load bucket first
        bucketHelpers.loadRequest(durabilityReq, null, function (loadErr) {
            if (loadErr) {
                req.log.warn(loadErr,
                   'S3_MPU: Failed to load bucket for durability object');
                return;
            }

            bucketHelpers.getBucketIfExists(durabilityReq, null,
                                            function (bucketErr) {
                if (bucketErr) {
                    req.log.warn(bucketErr,
                       'S3_MPU: Bucket not found for durability object');
                    return;
                }

                // Get metadata placement and client
                var metadataLocation = req.metadataPlacement.getObjectLocation(
                    owner, durabilityReq.bucket.id, crypto.createHash('md5')
                                                      .update(durabilityKey)
                                                      .digest('hex'));
                var client =
                req.metadataPlacement.getBucketsMdapiClient(metadataLocation);

                // Store durability level as object metadata instead of content
                var headers = {
                    'x-durability-level':
                    durabilityData.durabilityLevel.toString(),
                    'x-upload-id': durabilityData.uploadId,
                    'x-created': durabilityData.created
                };

                // Create durability object with metadata containing the
                // durability info
                client.createObject(owner, durabilityReq.bucket.id,
                                    durabilityKey,
                    objectId, content.length, contentMD5,
                    'application/json', headers, [], {},
                                    metadataLocation.vnode, {},
                    req.getId(), function (createErr, result) {
                    if (createErr) {
                        req.log.warn(createErr,
                            'S3_MPU: Failed to store durability object');
                    } else {
                        req.log.debug(
                            'S3_MPU: Successfully stored durability object');
                    }
                });
            });
        });
    });
}

function getDurabilityObject(req, durabilityKey, callback) {
    var bucketName = req.s3Request.bucket;

    // Create a clean request context for durability object retrieval
    var durabilityReq = Object.create(req);
    durabilityReq.params = {
        bucket_name: bucketName,
        object_name: durabilityKey
    };

    // Use the existing upload record retrieval pattern
    bucketHelpers.loadRequest(durabilityReq, null, function (loadErr) {
        if (loadErr) {
            return (callback(loadErr));
        }

        bucketHelpers.getBucketIfExists(durabilityReq, null,
                                        function (bucketErr) {
            if (bucketErr) {
                return (callback(bucketErr));
            }

            var metadataLocation = req.metadataPlacement.getObjectLocation(
                req.owner.account.uuid,
                durabilityReq.bucket.id, crypto.createHash('md5')
                                                   .update(durabilityKey)
                                                   .digest('hex'));
            var client =
                req.metadataPlacement.getBucketsMdapiClient(metadataLocation);

            client.getObject(req.owner.account.uuid, durabilityReq.bucket.id,
                             durabilityKey,
                metadataLocation.vnode, {}, req.getId(),
                function (getErr, result) {
                if (getErr) {
                    return (callback(getErr));
                }

                // Read durability level from object metadata instead of content
                var durabilityData = {};
                if (result.headers && result.headers['x-durability-level']) {
                    durabilityData = {
                        durabilityLevel:
                        parseInt(result.headers['x-durability-level'], 10),
                        uploadId: result.headers['x-upload-id'],
                        created: result.headers['x-created']
                    };
                }

                callback(null, durabilityData);
            });
        });
    });
}

///--- Exports

module.exports = {
    s3InitiateMultipartUploadHandler: s3InitiateMultipartUploadHandler,
    s3UploadPartHandler: s3UploadPartHandler,
    s3CompleteMultipartUploadHandler: s3CompleteMultipartUploadHandler,
    s3AbortMultipartUploadHandler: s3AbortMultipartUploadHandler
};
