/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 * File:     s3-multipart.js
 * Purpose:  Implements multipart uploads required by S3 clients.
 *
 * Description:
 *  S3 multipart upload is a protocol for uploading large objects by breaking
 *  them into smaller parts that can be uploaded  independently, then assembled
 *  into a single object. This is essential for:
 *  - Large file uploads (the meaning of large varies between S3 clients,
 *  s3cmd considers > 15MiB as large files.
 *  - Resumable uploads (failed parts can be retried)
 *  - Parallel upload performance
 *
 * Notes:
 *  Manta unlike AWS does not have the concept of storage classes, we just deal
 *  with replica sets (durability-level, by default 2), clients could specify
 *  the durability level by sending a header with the same name, the problem
 *  with this in multipart is that this header is only sent on the start of
 *  the multipart upload. To address this, a object is created with the current
 *  upload data, which includes the durability level as part of the object meta-
 *  data, so that each upload part could know how many copies should the final
 *  object have, when assembling.
 *
 *  Assembling parts:
 *  Mako /mpu/v2/commit is used for assembling parts in the background, in case
 *  that the mako endpoint fails, then we will try using the old method using
 *  buckets-mdapi to directly to create the final object ensuring the
 *  correct sequence of parts when assembling it.
 *
 *
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
var storinfoErrors = require('storinfo/lib/errors');
var StorinfoNotEnoughSpaceError = storinfoErrors.NotEnoughSpaceError;
var bucketsCommon = require('./buckets/common');
var translateBucketError = bucketsCommon.translateBucketError;

/*
 * Durability level is stored as a simple object in
 * .mpu-uploads/{uploadId}.durability.
 * The reason behind this, is that only in initiateMultipartUpload the
 * durability header is present and in the rest of parts is missing,
 * so we need to preserve this. This will allow environments where storage
 * nodes are failing to specify a value that will work in those environments.
 */

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
        // By default Manta has 2 copies per object.
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

        // Validate that we have sufficient space for multipart upload
        // This prevents clients from uploading all parts only to fail at commit
        var estimatedMaxSizeMB = Math.max(
            (req.storinfo.defaultMaxStreamingSizeMB || 5120), // 5GB default
            // Minimum 100MB buffer for safety
            100);

        // Perform space validation using same logic as storinfo.choose()
        var spaceValidationOpts = {
            replicas: copies,
            size: estimatedMaxSizeMB,
            isOperator: req.caller.account.isOperator
        };

        req.storinfo.choose(spaceValidationOpts, function (spaceErr, sharks) {
            if (spaceErr && spaceErr.name === 'NotEnoughSpaceError') {
                req.log.warn({
                    uploadId: uploadId,
                    estimatedSizeMB: estimatedMaxSizeMB,
                    durabilityLevel: copies,
                    error: spaceErr.message
                }, 'S3_MPU:' +
                   ' Insufficient space for multipart upload at initiate');

                // Return the same error as storinfo to maintain consistency
                next(spaceErr);
                return;
            }

            if (spaceErr) {
                req.log.warn({
                    error: spaceErr,
                    uploadId: uploadId
                }, 'S3_MPU: Error during space validation, proceeding anyway');
            } else {
                req.log.info({
                    uploadId: uploadId,
                    estimatedSizeMB: estimatedMaxSizeMB,
                    availableSharks: sharks ? sharks[0].length : 'unknown'
                }, 'S3_MPU: Space validation passed for multipart upload');
            }

            // Continue with durability object storage
            createDurabilityAndUploadRecord();
        });

        function createDurabilityAndUploadRecord() {
            // Store durability level for later shark allocation during first
            // part upload
            var durabilityKey = '.mpu-uploads/' + uploadId + '.durability';
            var durabilityData = {
            uploadId: uploadId,
            durabilityLevel: copies,
            sharks: null, // Will be populated during first part upload
            created: new Date().toISOString()
            };

            storeDurabilityObject(req, durabilityKey, durabilityData,
                                  function (durErr) {
                if (durErr) {
                    req.log.warn(durErr,
                     'S3_MPU:'+
                     ' Failed to store durability object during initiation');
                    // Continue anyway, will fall back to upload
                    // record or headers
                }

                req.log.info({
                    uploadId: uploadId,
                    durabilityKey: durabilityKey,
                    durabilityLevel: copies
                }, 'S3_MPU: Initiated durability' +
                   ' object storage for multipart upload');

                req.log.debug({
                    uploadId: uploadId,
                    durabilityLevel: copies,
                    source: req.header('durability-level') ?
                        'durability-level' :
                           req.header('x-durability-level') ?
                        'x-durability-level' : 'default'
                }, 'S3_MPU:' +
                   ' Processed and cached durability-level during initiate');

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
                uploadRecord.preAllocatedSharks = null; // populated during
                                                        // first part upload
                var uploadRecordContent = JSON.stringify(uploadRecord);
                var uploadRecordMD5 = crypto.createHash('md5')
                                           .update(uploadRecordContent)
                                           .digest('base64');

                req.log.info({
                    uploadId: uploadId,
                    uploadRecordKey: uploadRecordKey,
                    uploadRecordContent: uploadRecordContent,
                    durabilityLevel: uploadRecord.durabilityLevel
                }, 'S3_MPU:' +
                   ' About to store upload record with durability level');

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
        uploadReq.headers['content-length'] =
                                      String(uploadRecordContent.length);
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
        }); // Close storeDurabilityObject callback
        } // Close createDurabilityAndUploadRecord function
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

        req.log.info({
            bucket: bucketName,
            object: objectKey,
            uploadId: uploadId,
            partNumber: partNumber,
            handler: 's3UploadPartHandler'
        }, 'S3_MPU: ENTRY - Part upload handler called');

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

            // CRITICAL: Mark as S3 request for AWS chunked handling
            partReq.isS3Request = true;

            // Copy essential request properties for proper stream handling
            partReq.method = 'PUT';
            partReq._size = req._size;
            partReq.isChunked = function () {
                return req.isChunked ? req.isChunked() :
                       (partReq.headers['transfer-encoding'] === 'chunked');
            };

            // Handle AWS chunked encoding for multipart uploads
            if (partReq.headers['content-encoding'] === 'aws-chunked') {
                req.log.debug({
                    uploadId: uploadId,
                    partNumber: partNumber,
                    contentEncoding: partReq.headers['content-encoding'],
                    transferEncoding: partReq.headers['transfer-encoding'],
                    decodedLength:
                    partReq.headers['x-amz-decoded-content-length']
                }, 'S3_MPU: AWS chunked encoding detected in part upload');

                // Mark for special handling in common.js
                partReq._awsChunkedMPU = true;

                // For MPU, let the actual encoded size be stored in metadata
                // instead of overriding with decoded size for AWS Chunked mpu
                //
                req.log.debug({
                    uploadId: uploadId,
                    partNumber: partNumber,
                    decodedLength:
                    partReq.headers['x-amz-decoded-content-length'],
                    willUseActualSize: true
                }, 'S3_MPU: AWS chunked part - will store actual encoded size');
            }

            // Get upload record to check for pre-allocated sharks
            req.log.debug({
                uploadId: uploadId,
                partNumber: partNumber
            }, 'S3_MPU: Attempting to get upload record for shark check');

            getUploadRecord(req, uploadId,
                            function (recErr, sharkUploadRecord) {
                req.log.debug({
                    uploadId: uploadId,
                    partNumber: partNumber,
                    hasError: !!recErr,
                    hasUploadRecord: !!sharkUploadRecord,
                    uploadRecordKeys: sharkUploadRecord ?
                        Object.keys(sharkUploadRecord) : []
                }, 'S3_MPU: Upload record retrieval result');

                if (recErr || !sharkUploadRecord) {
                    req.log.warn({
                        uploadId: uploadId,
                        partNumber: partNumber,
                        error: recErr
                    }, 'S3_MPU:' +
                       ' Could not retrieve upload record' +
                       ', using default allocation');
                    proceedWithPartUpload();
                    return;
                }

                // Get durability level from stored durability object
                // (preferred)
                var durabilityKey = '.mpu-uploads/' + uploadId + '.durability';
                getDurabilityObject(req, durabilityKey,
                                    function (durErr, durabilityData) {
                    var durabilityLevel;

                    if (!durErr && durabilityData &&
                        durabilityData.durabilityLevel !== undefined) {
                        durabilityLevel = durabilityData.durabilityLevel;
                        req.log.info({
                            uploadId: uploadId,
                            partNumber: partNumber,
                            durabilityLevel: durabilityLevel,
                            source: 'durability-object'
                        }, 'S3_MPU: Using durability level' +
                           ' from durability object for part upload');
                    } else {
                        // Fallback to upload record
                        durabilityLevel = (sharkUploadRecord.durabilityLevel
                                           !== undefined) ?
                            sharkUploadRecord.durabilityLevel :
                            common.DEF_NUM_COPIES;
                        req.log.info({
                            uploadId: uploadId,
                            partNumber: partNumber,
                            durabilityLevel: durabilityLevel,
                            source: sharkUploadRecord.durabilityLevel !==
                                undefined ? 'upload-record' : 'default',
                            durabilityObjectError: durErr
                        }, 'S3_MPU: Using fallback durability ' +
                           'level for part upload');
                    }

                    // Set durability level header for part creation
                    partReq.headers['durability-level'] =
                                            durabilityLevel.toString();

                    // Use deterministic shark selection for MPU consistency
                    req.log.debug({
                        uploadId: uploadId,
                        partNumber: partNumber,
                        durabilityLevel: durabilityLevel
                    }, 'S3_MPU: Using deterministic shark selection for MPU');

                    // Get ALL available sharks for deterministic selection
                    var storinfo = req.storinfo;
                    var isOperator = req.caller.account.isOperator;

                    // Access internal dcSharkMap directly (same source as
                    // storinfo.choose)
                    var sharkMap = isOperator ?
                    storinfo.operatorDcSharkMap : storinfo.dcSharkMap;

                if (!sharkMap) {
                    req.log.warn({
                        uploadId: uploadId,
                        partNumber: partNumber
                    }, 'S3_MPU: No shark map' +
                       ' available, using default allocation');
                    proceedWithPartUpload();
                    return;
                }

                // Extract ALL sharks from all datacenters in the shark map
                var allSharks = [];
                Object.keys(sharkMap).forEach(function (datacenter) {
                    var dcSharks = sharkMap[datacenter];
                    if (Array.isArray(dcSharks)) {
                        allSharks = allSharks.concat(dcSharks);
                    }
                });

                if (allSharks.length === 0) {
                    req.log.warn({
                        uploadId: uploadId,
                        partNumber: partNumber,
                        datacenters: Object.keys(sharkMap)
                    }, 'S3_MPU: No sharks found in shark map' +
                       ', using default allocation');
                    proceedWithPartUpload();
                    return;
                }

                // Space-aware deterministic shark selection algorithm
                // Maintains determinism while filtering out sharks with
                // insufficient space

                // Step 1: Filter out sharks with critically low space
                // Use a conservative threshold to exclude only truly
                // problematic sharks
                // XXX 1GB minimum - configurable threshold
                // we should not get in this situation.
                var minimumSpaceMB = 1024;

                var viableSharks = allSharks.filter(function (shark) {
                    var hasMinSpace = shark.availableMB &&
                                     shark.availableMB >= minimumSpaceMB;

                    if (!hasMinSpace) {
                        req.log.debug({
                            shark: shark.manta_storage_id,
                            availableMB: shark.availableMB,
                            minimumMB: minimumSpaceMB
                        }, 'S3_MPU: Excluding shark with critically low space');
                    }

                    return (hasMinSpace);
                });

                // Step 2: Fallback to all sharks if filtering is too aggressive
                if (viableSharks.length < durabilityLevel) {
                    req.log.warn({
                        uploadId: uploadId,
                        partNumber: partNumber,
                        viableSharks: viableSharks.length,
                        requiredSharks: durabilityLevel,
                        minimumSpaceMB: minimumSpaceMB
                    }, 'S3_MPU: Too few sharks with minimum space,' +
                       ' using all available sharks');

                    viableSharks = allSharks;
                }

                // Step 3: Deterministic selection within viable sharks
                // Sort by name for consistent results,
                // regardless of space changes
                var sortedSharks = viableSharks.slice().sort(function (a, b) {
                    return (a.manta_storage_id.
                            localeCompare(b.manta_storage_id));
                });

                // Step 4: Select first N sharks
                // (deterministic but space-filtered)
                var selectedSharks = sortedSharks.slice(0, durabilityLevel);

                req.log.info({
                    uploadId: uploadId,
                    partNumber: partNumber,
                    totalSharkCount: allSharks.length,
                    viableSharkCount: viableSharks.length,
                    selectedSharkCount: selectedSharks.length,
                    selectedSharks: selectedSharks.map(function (s) {
                        return {
                            shark: s.manta_storage_id,
                            availableMB: s.availableMB || 'unknown'
                        };
                    }),
                    minimumSpaceMB: minimumSpaceMB,
                    algorithm: 'space-filtered-deterministic',
                    method: 'dcSharkMap',
                    datacenters: Object.keys(sharkMap)
                }, 'S3_MPU: Selected deterministic sharks' +
                   ' with space filtering' +
                   ' from internal shark map');

                    // Use deterministically selected sharks
                    partReq.preAllocatedSharks = selectedSharks;
                    proceedWithPartUpload();
                }); // Close getDurabilityObject callback
            }); // Close getUploadRecord callback

            function proceedWithPartUpload() {

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
                        req.log.error({
                            err: partErr,
                            uploadId: uploadId,
                            partNumber: partNumber,
                            wasAwsChunked: !!partReq._awsChunkedMPU
                        }, 'S3_MPU: Failed to upload part');
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
                } // Close proceedWithPartUpload function
        }); // Close main part upload handler
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

        req.log.info({
            bucket: bucketName,
            object: objectKey,
            uploadId: uploadId,
            functionEntry: true
        }, 'S3_MPU: ENTRY - Starting complete multipart upload function');

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
            validatePartsForComplete(uploadRecord, partsFromXML, req,
                                     function (validationErr) {
                if (validationErr) {
                    req.log.error(validationErr,
                                  'S3_MPU: Part validation failed');
                    req.log.warn({
                        errorName: validationErr.name,
                        errorRestCode: validationErr.restCode,
                        isMultiError: validationErr.name === 'MultiError',
                        nextWillBeCalled: true
                    }, 'S3_MPU_DEBUG:' +
                       ' About to call next() with validation error');
                    return (next(validationErr));
                }

                // Continue with existing completion logic
                continueWithCompletion();
            });

            // Helper function to safely release lock and call callback
            function safeCleanupAndExit(error, lockInfo, callback) {
                if (lockInfo) {
                    var lockManager = new DistributedLockManager(req);
                    lockManager.releaseLock(lockInfo, function (releaseErr) {
                        if (releaseErr) {
                            req.log.warn(releaseErr,
                                'S3_MPU: Failed to release' +
                                ' lock during error cleanup');
                        } else {
                            req.log.debug({
                                uploadId: uploadId,
                                lockKey: lockInfo.lockKey
                            }, 'S3_MPU: Successfully released' +
                               ' lock during error cleanup');
                        }
                        // Always continue with the original callback
                        // regardless of release result
                        callback(error);
                    });
                } else {
                    // No lock to release, proceed directly
                    callback(error);
                }
            }

            function continueWithCompletion() {

            // Use distributed locking to prevent concurrent completion
            var lockManager = new DistributedLockManager(req);
            var completionLockInfo = null;

            req.log.debug({
                uploadId: uploadId
            }, 'S3_MPU: Acquiring distributed lock for completion');

            lockManager.acquireLock(uploadId, function (lockErr, lockInfo) {
                if (lockErr) {
                    req.log.error(lockErr, 'S3_MPU: Failed to acquire lock');
                    return (next(lockErr));
                }

                // Store lockInfo for use throughout the completion process
                completionLockInfo = lockInfo;

                req.log.info({
                    uploadId: uploadId,
                    lockKey: completionLockInfo.lockKey,
                    instanceId: completionLockInfo.instanceId
                }, 'S3_MPU: Successfully acquired distributed lock');

                function proceedWithCompletion() {

                req.log.info({
                    uploadId: uploadId,
                    step: 'post-lock-acquisition',
                    partsFromXMLCount: partsFromXML ?
                        partsFromXML.length : 0
                }, 'S3_MPU: CHECKPOINT 1' +
                   ' - Starting assembly after lock acquired');

                // Since we don't track parts in the upload record,
                // we'll use the ETags provided in the XML request and
                // calculate size from the parts themselves
                var totalSize = 0;
                var partETags = [];

                req.log.info({
                    uploadId: uploadId,
                    step: 'parts-initialization'
                }, 'S3_MPU: CHECKPOINT 2 - Initialized parts processing');

                partsFromXML.forEach(function (xmlPart) {
                    // Use the ETag provided by the client in the XML
                    // This should match the ETag we returned during part upload
                    partETags.push(xmlPart.etag);
                });

                req.log.debug({
                    totalSize: totalSize,
                    partCount: partETags.length
                }, 'S3_MPU: Prepared for manta-mako commit');

                req.log.info({
                    uploadId: uploadId,
                    step: 'before-size-calculation',
                    partCount: partETags.length
                }, 'S3_MPU: CHECKPOINT 3 - About to calculate total size');

                // Generate final object ID
                var finalObjectId = uuidv4();

                // Calculate actual total size from uploaded parts
                // using buckets-mdapi
                calculateActualTotalSize(req, uploadId, partETags,
                                     function (sizeErr, actualTotalSize) {
                req.log.info({
                    uploadId: uploadId,
                    step: 'size-calculation-callback',
                    sizeErr: sizeErr ? sizeErr.message : null,
                    actualTotalSize: actualTotalSize
                }, 'S3_MPU: CHECKPOINT 4 - Size calculation callback entered');
                if (sizeErr) {
                    req.log.error(sizeErr,
                       'S3_MPU: Failed to calculate actual total size');

                    return safeCleanupAndExit(
                        new InternalError('Failed to calculate multipart' +
                            ' upload size'),
                        completionLockInfo,
                        next);
                }

                req.log.debug({
                    partCount: partETags.length,
                    actualTotalSize: actualTotalSize,
                    actualSizeMB: Math.round(actualTotalSize / (1024 * 1024))
                }, 'S3_MPU: Calculated actual total size from parts');

                req.log.info({
                    uploadId: uploadId,
                    step: 'after-size-calculation',
                    actualTotalSize: actualTotalSize,
                    finalObjectId: finalObjectId
                }, 'S3_MPU: CHECKPOINT 5 - Starting multipart assembly commit');

                req.log.info({
                    uploadId: uploadId,
                    step: 'creating-commit-body',
                    owner: owner,
                    finalObjectId: finalObjectId,
                    partETagsLength: partETags.length,
                    actualTotalSize: actualTotalSize
                }, 'S3_MPU: CHECKPOINT 5.1 - About to create commitBody');

                var commitBody = {
                    version: 1,
                    nbytes: actualTotalSize, // Actual total size from parts
                    account: owner,
                    objectId: finalObjectId,
                    parts: partETags
                };

                req.log.info({
                    uploadId: uploadId,
                    step: 'commit-body-created',
                    commitBody: commitBody
                }, 'S3_MPU: CHECKPOINT 5.2 - commitBody created successfully');

                req.log.info({
                    uploadId: uploadId,
                    step: 'before-assembly-call',
                    commitBodyParts: partETags.length,
                    commitBodySize: commitBody.nbytes
                }, 'S3_MPU: CHECKPOINT 6' +
                             ' - About to call assembleMultipartUpload');

                // Return success immediately to prevent client timeout,
                // waiting to the assembly to complete.
                // All parts are validated, so assembly should succeed
                // (or fail gracefully in background)

                // Generate successful response XML immediately
                var xml = generateCompleteMultipartUploadXML(
                    bucketName, objectKey, '"' + finalObjectId + '"');

                req.log.info({
                    uploadId: uploadId,
                    objectKey: objectKey,
                    totalParts: commitBody.parts.length,
                    approxSize: commitBody.nbytes,
                    responseStrategy: 'wait-for-v2-commit'
                }, 'S3_MPU:' +
                   ' Waiting for v2 commit completion before responding');

                // Wait for assembly completion before responding to client
                // This ensures client gets accurate success/failure status
                assembleMultipartUpload(req, uploadRecord, commitBody,
                                        function (assembleErr, assembleResult) {
                    if (assembleErr) {
                        req.log.error({
                            err: assembleErr,
                            uploadId: uploadId,
                            synchronousAssembly: true
                        }, 'S3_MPU:' +
                            ' Assembly failed - returning error to client');

                        // Return appropriate error to client based
                        // on failure type - use next() to trigger
                        // S3 XML conversion
                        var errorToReturn;
                        if (assembleErr.name === 'NotEnoughSpaceError') {
                            // Storage space error -
                            // return 507 Insufficient Storage
                            var spaceError = new Error(assembleErr.message ||
                                'Insufficient storage space');
                            spaceError.statusCode = 507;
                            spaceError.restCode = 'InsufficientStorage';
                            errorToReturn = spaceError;
                        } else {
                            // Other assembly errors - return
                            // 500 Internal Server Error with original error
                            var internalError = new Error(assembleErr.message ||
                                'Multipart upload assembly failed');
                            internalError.statusCode = 500;
                            internalError.restCode = 'InternalError';
                            errorToReturn = internalError;
                        }

                        return safeCleanupAndExit(
                            errorToReturn,
                            completionLockInfo,
                            next);
                    }

                    req.log.info({
                        finalObjectId: finalObjectId,
                        md5: assembleResult.md5,
                        assembledSize: assembleResult.nbytes,
                        uploadId: uploadId,
                        synchronousAssembly: true
                    }, 'S3_MPU: Assembly completed successfully' +
                       ' - returning success to client');

                    // Return success response to client with actual results
                    res.setHeader('Content-Type', 'application/xml');
                    res.send(200, xml);
                    next(false);

                    // Release lock after successful completion
                    if (completionLockInfo) {
                        lockManager.releaseLock(completionLockInfo,
                                                function (releaseErr) {
                            if (releaseErr) {
                                req.log.warn(releaseErr,
                                    'S3_MPU: Failed to release lock' +
                                    ' after completion');
                            } else {
                                req.log.debug({
                                    uploadId: uploadId,
                                    lockKey: completionLockInfo.lockKey
                                }, 'S3_MPU: Successfully' +
                                   ' released distributed lock');
                            }
                        });
                    }

                    // Cleanup upload record and temporary parts in background
                    cleanupMultipartUpload(req, uploadId,
                                           function (cleanupErr) {
                        if (cleanupErr) {
                            req.log.warn({
                                err: cleanupErr,
                                uploadId: uploadId,
                                backgroundCleanup: true
                            }, 'S3_MPU: Background cleanup failed' +
                               ' - upload record may remain');
                        } else {
                            req.log.debug({
                                uploadId: uploadId,
                                backgroundCleanup: true
                            }, 'S3_MPU:' +
                               ' Background cleanup completed successfully');
                        }
                    });
                }); // Close assembleMultipartUpload callback
            }); // Close calculateActualTotalSize function call
                } // Close proceedWithCompletion function

                // Call the completion function with error handling
                try {
                    proceedWithCompletion();
                } catch (unexpectedErr) {
                    req.log.error({
                        error: unexpectedErr.message,
                        stack: unexpectedErr.stack,
                        uploadId: uploadId
                    }, 'S3_MPU: Unexpected error during completion');

                    return safeCleanupAndExit(
                        new InternalError('Unexpected error during multipart' +
                                          ' upload completion'),
                        lockInfo, // Use lockInfo from acquireLock callback
                        next);
                }
            }); // Close acquireLock callback
    } // Close s3CompleteMultipartUpload function
        }); // Close s3CompleteMultipartUploadHandler function
    }; }
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

///--- Distributed Locking Implementation for Production Multipart Uploads

/*
 * Distributed Lock Manager using buckets-mdapi for coordination
 *
 * HOW IT WORKS:
 * 1. Uses buckets-mdapi objects as distributed locks with atomic operations
 * 2. Each lock is a unique object with instance ID and expiration timestamp
 * 3. Compare-and-swap semantics prevent race conditions
 * 4. Lease-based expiration prevents deadlocks from crashed instances
 * 5. Lock renewal keeps long-running operations from timing out
 *
 * PRODUCTION BENEFITS:
 * - Prevents concurrent multipart completion (data corruption)
 * - Handles instance crashes gracefully (lease expiration)
 * - Scales across multiple manta-buckets-api instances
 * - Provides observability through comprehensive logging
 */
function DistributedLockManager(req) {
    this.req = req;
    this.lockTimeout = 90000; // 90 seconds - sufficient for assembly + buffer
    // 500ms between acquisition attempts for faster response
    this.retryInterval = 500;
    this.maxRetries = 150; // Maximum 30 seconds wait time (60 * 500ms)
}

/*
 * Acquire distributed lock for multipart upload completion
 *
 * ALGORITHM:
 * 1. Generate unique instance ID (request-id + timestamp)
 * 2. Try to create lock object atomically using buckets-mdapi
 * 3. If object exists, check if it's expired or owned by us
 * 4. If expired, attempt compare-and-swap update
 * 5. If owned by others and not expired, retry with backoff
 * 6. Continue until lock acquired or max retries exceeded
 *
 * ATOMICITY GUARANTEE:
 * buckets-mdapi's createObject provides atomic compare-and-swap:
 * - Returns ObjectExistsError if lock already exists
 * - Only one instance can successfully create the lock object
 * - Race conditions are handled by retry logic
 */
DistributedLockManager.prototype.acquireLock = function (uploadId, options,
                                                        callback) {
    if (typeof (options) === 'function') {
        callback = options;
        options = {};
    }

    var self = this;
    var lockKey = '.mpu-locks/' + uploadId + '.lock'; // Unique lock object name
    // Unique instance identifier
    var instanceId = self.req.getId() + '-' + Date.now();
    var lockTimeout = options.timeout || self.lockTimeout;
    var maxRetries = options.maxRetries || self.maxRetries;
    var currentRetry = 0;

    self.req.log.debug({
        uploadId: uploadId,
        lockKey: lockKey,
        instanceId: instanceId,
        lockTimeout: lockTimeout
    }, 'S3_MPU_LOCK: Attempting to acquire distributed lock');

    function attemptLock() {
        // RETRY LIMIT: Prevent infinite waiting
        if (currentRetry >= maxRetries) {
            var timeoutErr = new Error('Failed to acquire lock after ' +
                                       maxRetries + ' retries');
            timeoutErr.name = 'LockTimeout';
            timeoutErr.statusCode = 409; // Conflict - resource locked
            timeoutErr.restCode = 'LockTimeout';
            return (callback(timeoutErr));
        }

        currentRetry++;

        // LOCK DATA STRUCTURE: Contains all necessary coordination info
        var lockData = {
            uploadId: uploadId,
            instanceId: instanceId, // Who owns this lock
            acquired: new Date().toISOString(), // When was it acquired
            // Lease expiration
            expires: new Date(Date.now() + lockTimeout).toISOString(),
            operation: 'complete-multipart', // What operation is protected
            processId: process.pid, // Additional debugging info
            hostname: require('os').hostname()
        };

        var lockContent = JSON.stringify(lockData);
        var lockMD5 = crypto.createHash('md5').update(lockContent).
            digest('base64');
        var lockObjectId = uuidv4();

        // BUCKETS-MDAPI SETUP: Use same infrastructure as multipart data
        var lockReq = Object.create(self.req);
        lockReq.params = {
            // Store locks in same bucket
            bucket_name: self.req.s3Request.bucket,
            object_name: lockKey
        };

        bucketHelpers.loadRequest(lockReq, null, function (loadErr) {
            if (loadErr) {
                return (callback(loadErr));
            }

            bucketHelpers.getBucketIfExists(lockReq, null, function
                                            (bucketErr) {
                if (bucketErr) {
                    return (callback(bucketErr));
                }

                var owner = self.req.owner.account.uuid;
                var metadataLocation = self.req.metadataPlacement.
                    getObjectLocation(
                    owner, lockReq.bucket.id, crypto.createHash('md5')
                                                   .update(lockKey)
                                                   .digest('hex'));
                var client = self.req.metadataPlacement.
                    getBucketsMdapiClient(metadataLocation);

                // STEP 1: Check if lock already exists (non-atomic read)
                client.getObject(owner, lockReq.bucket.id, lockKey,
                               metadataLocation.vnode, {}, self.req.getId(),
                               function (getErr, existingLock) {

                    if (!getErr && existingLock) {
                        // LOCK EXISTS - Need to check ownership and expiration
                        try {
                            var existingData = JSON.parse(existingLock.value ||
                                                          '{}');
                            var expiresValue = existingData.expires;

                            // Fallback: If expires not in JSON content,
                            // check headers
                            if (!expiresValue && existingLock.headers &&
                                existingLock.headers['x-lock-expires']) {
                                expiresValue =
                                    existingLock.headers['x-lock-expires'];
                                // Also populate instanceId from headers
                                // if missing
                                if (!existingData.instanceId &&
                                    existingLock.headers['x-lock-instance']) {
                                    existingData.instanceId =
                                        existingLock.headers['x-lock-instance'];
                                }
                                self.req.log.debug({
                                    uploadId: uploadId,
                                    source: 'headers'
                                }, 'S3_MPU_LOCK:'+
                                   ' Using lock expiration from headers');
                            }

                            var expires = new Date(expiresValue);
                            var now = new Date();

                            // Validate the parsed date to prevent race
                            // conditions
                            var hadParsingError = false;
                            if (!expiresValue || isNaN(expires.getTime())) {
                                self.req.log.warn({
                                    uploadId: uploadId,
                                    invalidExpires: expiresValue,
                                    existingData: existingData,
                                    lockHeaders: existingLock.headers
                                }, 'S3_MPU_LOCK:'+
                                   ' Invalid expiration in existing lock');
                                hadParsingError = true;
                                // Set to epoch, making it expired
                                expires = new Date(0);
                            }

                            // CRITICAL: If we had parsing errors and another
                            // instance owns the lock, be conservative and wait
                            // rather than immediately claiming
                            if (hadParsingError &&
                                existingData.instanceId !== instanceId) {
                                self.req.log.warn({
                                    uploadId: uploadId,
                                    currentOwner: existingData.instanceId,
                                    retryCount: currentRetry
                                }, 'S3_MPU_LOCK: Cannot parse expiration' +
                                   ' for lock owned by another instance' +
                                   ', will retry');
                                setTimeout(attemptLock, self.retryInterval);
                                return;
                            }

                            self.req.log.debug({
                                uploadId: uploadId,
                                existingOwner: existingData.instanceId,
                                ourInstance: instanceId,
                                expires: expires.toISOString(),
                                now: now.toISOString(),
                                expired: now > expires,
                                hostname: existingData.hostname,
                                processId: existingData.processId
                            }, 'S3_MPU_LOCK: Found existing lock' +
                                ', analyzing ownership and expiration');

                            // CASE 1: We already own this lock
                            // (idempotent operation)
                            if (existingData.instanceId === instanceId) {
                                self.req.log.info({
                                    uploadId: uploadId,
                                    instanceId: instanceId
                                }, 'S3_MPU_LOCK: Lock already owned by' +
                                   ' this instance (idempotent)');

                                return callback(null, {
                                    lockKey: lockKey,
                                    instanceId: instanceId,
                                    objectId: existingLock.id,
                                    acquired: existingData.acquired,
                                    expires: existingData.expires
                                });
                            }

                            // CASE 2: Lock expired - attempt to claim it
                            if (now > expires) {
                                self.req.log.debug({
                                    uploadId: uploadId,
                                    expiredOwner: existingData.instanceId,
                                    expiredHostname: existingData.hostname,
                                    expiredAt: expires.toISOString(),
                                    newOwner: instanceId
                                }, 'S3_MPU_LOCK: Attempting' +
                                   ' to claim expired lock');

                                // ATOMIC UPDATE: Compare-and-swap using
                                // object ID
                                attemptLockUpdate(existingLock.id);
                                return;
                            }

                            // CASE 3: Lock valid and owned by someone else -
                            // wait and retry
                            var timeUntilExpiry = expires.getTime() -
                                now.getTime();
                            self.req.log.debug({
                                uploadId: uploadId,
                                currentOwner: existingData.instanceId,
                                ownerHostname: existingData.hostname,
                                timeUntilExpiry: timeUntilExpiry,
                                retryCount: currentRetry
                            }, 'S3_MPU_LOCK: Lock held by another instance' +
                                ', waiting for expiry or release');

                            setTimeout(attemptLock, self.retryInterval);
                            return;

                        } catch (parseErr) {
                            // CORRUPTED LOCK DATA: Treat as if no lock exists
                            self.req.log.warn({
                                err: parseErr,
                                uploadId: uploadId,
                                lockContent: existingLock.value
                            }, 'S3_MPU_LOCK: Failed to parse existing' +
                                ' lock data, will retry');

                            setTimeout(attemptLock, self.retryInterval);
                            return;
                        }
                    }

                    // STEP 2: No existing lock - try to create one atomically
                    self.req.log.debug({
                        uploadId: uploadId,
                        instanceId: instanceId,
                        lockKey: lockKey
                    }, 'S3_MPU_LOCK: No existing lock found' +
                       ', attempting atomic creation');

                    // ATOMIC CREATION: createObject will fail if
                    // lock already exists
                    client.createObject(owner, lockReq.bucket.id, lockKey,
                                      lockObjectId, lockContent.length,
                                        lockMD5,
                                      'application/json', {
                                          'x-lock-instance': instanceId,
                                          'x-lock-expires': lockData.expires,
                                          'x-lock-operation':
                                          'complete-multipart',
                                          'x-lock-hostname': lockData.hostname
                                      }, [], {}, metadataLocation.vnode, {},
                                      self.req.getId(),
                                        function (createErr, result) {
                        if (createErr) {
                            // RACE CONDITION: Someone else created
                            // lock between our check and create
                            if (createErr.name === 'ObjectExistsError') {
                                self.req.log.debug({
                                    uploadId: uploadId,
                                    retryCount: currentRetry
                                }, 'S3_MPU_LOCK:' +
                                   ' Lost creation race, will retry');

                                setTimeout(attemptLock, self.retryInterval);
                                return;
                            }

                            // SYSTEM ERROR: buckets-mdapi failure
                            self.req.log.error({
                                err: createErr,
                                uploadId: uploadId
                            }, 'S3_MPU_LOCK:' +
                               ' Failed to create lock due to system error');
                            return (callback(createErr));
                        }

                        // SUCCESS: Lock acquired atomically
                        self.req.log.info({
                            uploadId: uploadId,
                            instanceId: instanceId,
                            lockKey: lockKey,
                            expires: lockData.expires,
                            hostname: lockData.hostname,
                            processId: lockData.processId
                        }, 'S3_MPU_LOCK:' +
                           ' Successfully acquired distributed lock');

                        callback(null, {
                            lockKey: lockKey,
                            instanceId: instanceId,
                            objectId: lockObjectId,
                            acquired: lockData.acquired,
                            expires: lockData.expires
                        });
                    });
                });

                /**
                 * ATOMIC UPDATE FUNCTION: Try to claim expired lock
                 * Uses object ID for compare-and-swap semantics
                 */
                function attemptLockUpdate(existingObjectId) {
                    self.req.log.debug({
                        uploadId: uploadId,
                        existingObjectId: existingObjectId,
                        newOwner: instanceId
                    }, 'S3_MPU_LOCK: Attempting atomic update of expired lock');

                    // ATOMIC UPDATE: updateObject will fail if object was
                    // deleted/changed
                    client.updateObject(owner, lockReq.bucket.id, lockKey,
                                      existingObjectId, 'application/json',
                                      {
                                          'x-lock-instance': instanceId,
                                          'x-lock-expires': lockData.expires,
                                          'x-lock-hostname': lockData.hostname,
                                          'content-length':
                                          String(lockContent.length)
                                      }, {}, metadataLocation.vnode, {},
                                      self.req.getId(),
                                        function (updateErr, updateResult) {

                        if (updateErr) {
                            // CONCURRENT MODIFICATION: Someone
                            // else claimed or deleted lock
                            if (updateErr.name === 'ObjectNotFoundError') {
                                self.req.log.debug({
                                    uploadId: uploadId
                                }, 'S3_MPU_LOCK: Expired lock was' +
                                   ' deleted by someone else, retrying');
                                setTimeout(attemptLock, self.retryInterval);
                                return;
                            }

                            self.req.log.warn({
                                err: updateErr,
                                uploadId: uploadId
                            }, 'S3_MPU_LOCK: ' +
                                'Failed to update expired lock, will retry');

                            setTimeout(attemptLock, self.retryInterval);
                            return;
                        }

                        // SUCCESS: Claimed expired lock
                        self.req.log.info({
                            uploadId: uploadId,
                            instanceId: instanceId,
                            previousOwner: 'expired',
                            hostname: lockData.hostname
                        }, 'S3_MPU_LOCK: Successfully claimed expired lock');

                        callback(null, {
                            lockKey: lockKey,
                            instanceId: instanceId,
                            objectId: existingObjectId,
                            acquired: lockData.acquired,
                            expires: lockData.expires
                        });
                    });
                }
            });
        });
    }

    // START ACQUISITION PROCESS
    attemptLock();
};

/**
 * Release distributed lock
 *
 * SAFETY GUARANTEES:
 * 1. Verify ownership before release (prevent accidental release)
 * 2. Handle concurrent release attempts gracefully
 * 3. Log all release activities for debugging
 */
DistributedLockManager.prototype.releaseLock = function (lockInfo, callback) {
    var self = this;
    var lockKey = lockInfo.lockKey;
    var instanceId = lockInfo.instanceId;

    self.req.log.debug({
        lockKey: lockKey,
        instanceId: instanceId
    }, 'S3_MPU_LOCK: Releasing distributed lock');

    var lockReq = Object.create(self.req);
    lockReq.params = {
        bucket_name: self.req.s3Request.bucket,
        object_name: lockKey
    };

    bucketHelpers.loadRequest(lockReq, null, function (loadErr) {
        if (loadErr) {
            return (callback(loadErr));
        }

        bucketHelpers.getBucketIfExists(lockReq, null, function (bucketErr) {
            if (bucketErr) {
                return (callback(bucketErr));
            }

            var owner = self.req.owner.account.uuid;
            var metadataLocation = self.req.metadataPlacement.getObjectLocation(
                owner, lockReq.bucket.id, crypto.createHash('md5')
                                               .update(lockKey)
                                               .digest('hex'));
            var client = self.req.metadataPlacement.
                getBucketsMdapiClient(metadataLocation);

            // OWNERSHIP VERIFICATION: Ensure we still own the lock
            client.getObject(owner, lockReq.bucket.id, lockKey,
                           metadataLocation.vnode, {}, self.req.getId(),
                           function (getErr, currentLock) {

                if (getErr) {
                    if (getErr.name === 'ObjectNotFoundError') {
                        // ALREADY RELEASED: Lock doesn't exist
                        // (idempotent operation)
                        self.req.log.debug({
                            lockKey: lockKey,
                            instanceId: instanceId
                        }, 'S3_MPU_LOCK: Lock already released (idempotent)');
                        return (callback(null));
                    }
                    return (callback(getErr));
                }

                // VERIFY OWNERSHIP:
                // Prevent accidental release by wrong instance
                // Check header first (primary source), fallback to JSON value
                var actualInstanceId = currentLock.headers['x-lock-instance'];
                if (!actualInstanceId) {
                    try {
                        var lockData = JSON.parse(currentLock.value || '{}');
                        actualInstanceId = lockData.instanceId;
                    } catch (parseErr) {
                        self.req.log.warn({
                            err: parseErr,
                            lockKey: lockKey
                        }, 'S3_MPU_LOCK: Failed to parse lock data');
                    }
                }

                if (actualInstanceId !== instanceId) {
                    self.req.log.warn({
                        lockKey: lockKey,
                        expectedOwner: instanceId,
                        actualOwner: actualInstanceId,
                        actualHostname: currentLock.headers['x-lock-hostname']
                    }, 'S3_MPU_LOCK: Attempted to release ' +
                       'lock owned by different instance');

                    var ownershipErr =
                        new Error('Lock not owned by this instance');
                    ownershipErr.name = 'LockOwnershipError';
                    return (callback(ownershipErr));
                }

                // ATOMIC DELETION: Remove the lock object
                client.deleteObject(owner, lockReq.bucket.id, lockKey,
                                  metadataLocation.vnode, {}, self.req.getId(),
                                  function (deleteErr) {

                    if (deleteErr && deleteErr.name !== 'ObjectNotFoundError') {
                        self.req.log.error({
                            err: deleteErr,
                            lockKey: lockKey
                        }, 'S3_MPU_LOCK: Failed to delete lock object');
                        return (callback(deleteErr));
                    }

                    self.req.log.info({
                        lockKey: lockKey,
                        instanceId: instanceId
                    }, 'S3_MPU_LOCK: Successfully released distributed lock');

                    callback(null);
                });
            });
        });
    });
};

/**
 * Auto-renew lock periodically to prevent expiration during long operations
 *
 * LEASE RENEWAL STRATEGY:
 * - Renew at 1/3 of lease time (e.g., every 100s for 300s lease)
 * - Maximum renewals prevent runaway processes
 * - Failures are logged but don't stop the process
 * - Used for multipart assembly that may take several minutes
 */
DistributedLockManager.prototype.renewLock = function (lockInfo, callback) {
    var self = this;
    // Conservative renewal timing
    var renewalInterval = Math.floor(self.lockTimeout / 3);
    // Prevent infinite renewal (50 minutes max for 5min lease)
    var maxRenewals = 10;
    var renewalCount = 0;

    self.req.log.debug({
        lockKey: lockInfo.lockKey,
        renewalInterval: renewalInterval,
        maxRenewals: maxRenewals
    }, 'S3_MPU_LOCK: Starting lock renewal process');

    function scheduleRenewal() {
        // RENEWAL LIMIT: Prevent runaway lock renewals
        if (renewalCount >= maxRenewals) {
            self.req.log.warn({
                lockKey: lockInfo.lockKey,
                renewalCount: renewalCount,
                maxRenewals: maxRenewals
            }, 'S3_MPU_LOCK: Maximum lock renewals reached, stopping renewal');
            return;
        }

        setTimeout(function () {
            renewalCount++;

            var newExpiry = new Date(Date.now() +
                                     self.lockTimeout).toISOString();
            var lockReq = Object.create(self.req);
            lockReq.params = {
                bucket_name: self.req.s3Request.bucket,
                object_name: lockInfo.lockKey
            };

            self.req.log.debug({
                lockKey: lockInfo.lockKey,
                renewalAttempt: renewalCount,
                newExpiry: newExpiry
            }, 'S3_MPU_LOCK: Attempting lock renewal');

            // RENEWAL PROCESS: Update expiration timestamp
            bucketHelpers.loadRequest(lockReq, null, function (loadErr) {
                if (loadErr) {
                    self.req.log.warn(loadErr,
                        'S3_MPU_LOCK: Failed to renew lock - load error');
                    scheduleRenewal(); // Try again next interval
                    return;
                }

                bucketHelpers.getBucketIfExists(lockReq, null,
                                                function (bucketErr) {
                    if (bucketErr) {
                        self.req.log.warn(bucketErr,
                        'S3_MPU_LOCK: Failed to renew lock - bucket error');
                        scheduleRenewal(); // Try again next interval
                        return;
                    }

                    var owner = self.req.owner.account.uuid;
                    var metadataLocation = self.req.
                        metadataPlacement.getObjectLocation(
                        owner, lockReq.bucket.id, crypto.createHash('md5')
                                                       .update(lockInfo.lockKey)
                                                       .digest('hex'));
                    var client = self.req.metadataPlacement.
                        getBucketsMdapiClient(metadataLocation);

                    // ATOMIC RENEWAL: Update lock expiration
                    client.updateObject(owner, lockReq.bucket.id,
                                        lockInfo.lockKey,
                                      lockInfo.objectId, 'application/json',
                                      {
                                          'x-lock-expires': newExpiry,
                                          'x-lock-renewal-count':
                                          renewalCount.toString()
                                      }, {}, metadataLocation.vnode, {},
                                      self.req.getId(), function (updateErr) {

                        if (updateErr) {
                            self.req.log.warn({
                                err: updateErr,
                                lockKey: lockInfo.lockKey,
                                renewalAttempt: renewalCount
                            }, 'S3_MPU_LOCK: Failed to renew lock expiration');
                            scheduleRenewal(); // Try again next interval
                            return;
                        }

                        // SUCCESS: Lock renewed
                        lockInfo.expires = newExpiry;
                        self.req.log.debug({
                            lockKey: lockInfo.lockKey,
                            newExpiry: newExpiry,
                            renewalCount: renewalCount
                        }, 'S3_MPU_LOCK: Successfully renewed lock');

                        scheduleRenewal(); // Schedule next renewal
                    });
                });
            });
        }, renewalInterval);
    }

    // START RENEWAL CYCLE
    scheduleRenewal();
    callback(null);
};

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
    if (str === null || str === undefined) {
        return '';
    }
    return str.toString().replace(/[<>&'"]/g, function(c) {
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
            // Use parallel processing for better performance with many parts
            vasync.forEachParallel({
                concurrency: 10, // Limit concurrent requests
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

                    // Add timeout to prevent hanging
                    var timeoutId = setTimeout(function () {
                        req.log.warn({
                            partNumber: partNumber,
                            partObjectName: partObjectName
                        }, 'S3_MPU: getObject timeout' +
                           ' for part size calculation');
                        next(new Error('Timeout getting part size for part ' +
                                       partNumber));
                    }, 30000); // 30 second timeout

                    client.getObject(owner, bucketId, partObjectName,
                        metadataLocation.vnode, {}, req.getId(),
                                     function (getErr, result) {
                        clearTimeout(timeoutId);

                        if (getErr) {
                            req.log.error({
                                err: getErr,
                                partNumber: partNumber
                            }, 'S3_MPU: Failed to get part size');
                            return (next(getErr));
                        }

                        var partSize = result.content_length || 0;
                        totalSize += partSize;

                        req.log.info({
                            partNumber: partNumber,
                            partSize: partSize,
                            runningTotal: totalSize,
                            partObjectName: partObjectName,
                            hasResult: !!result,
                            resultKeys: result ? Object.keys(result) : []
                        }, 'S3_MPU: SIZE_CALC_DEBUG' +
                           ' - Added part size to total');

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
                    // Add bucket ID and uploadId for later use
                    uploadRecord.bucketId = uploadReq.bucket.id;
                    uploadRecord.uploadId = uploadId;

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

function updateUploadRecordContent(req, uploadRecordKey, content, callback) {
    var owner = req.owner.account.uuid;
    var bucketName = req.s3Request.bucket;

    // Create request context for upload record update
    var uploadReq = Object.create(req);
    uploadReq.params = {
        bucket_name: bucketName,
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

            var contentMD5 = crypto.createHash('md5').
                update(content).digest('base64');
            var metadataLocation = req.metadataPlacement.getObjectLocation(
                owner, uploadReq.bucket.id, crypto.createHash('md5')
                                               .update(uploadRecordKey)
                                               .digest('hex'));
            var client = req.metadataPlacement.
                getBucketsMdapiClient(metadataLocation);

            // For simplicity, let's delete and recreate the object with
            // new content
            // First get the existing object ID
            client.getObject(owner, uploadReq.bucket.id, uploadRecordKey,
                            metadataLocation.vnode, {}, req.getId(),
                            function (getErr, existingResult) {
                if (getErr) {
                    return (callback(getErr));
                }

                // Delete the existing object
                client.deleteObject(owner, uploadReq.bucket.id, uploadRecordKey,
                                   metadataLocation.vnode, {}, req.getId(),
                                   function (deleteErr) {
                    if (deleteErr) {
                        req.log.warn(deleteErr,
                        'S3_MPU: Failed to delete existing upload record');
                        // Continue anyway, might be a race condition
                    }

                    // Create new object with updated content
                    var objectId = uuidv4();
                    client.createObject(owner,
                                        uploadReq.bucket.id, uploadRecordKey,
                                       objectId, content.length, contentMD5,
                                       'application/json', {}, [], {},
                                       metadataLocation.vnode, {},
                                       req.getId(),
                                        function (createErr, result) {
                                            if (createErr) {
                                                return (callback(createErr));
                                            }
                                            callback(null);
                                        });
                                   });
                            });
        });
    });
}

function updateUploadRecord(req, uploadId, partNumber, partInfo, callback) {
    var uploadRecordKey = '.mpu-uploads/' + uploadId;
    var owner = req.owner.account.uuid;

    // Create request context for upload record update
    var uploadReq = Object.create(req);
    uploadReq.params = {
        bucket_name: req.s3Request.bucket,
        object_name: uploadRecordKey
    };

    bucketHelpers.loadRequest(uploadReq, null, function (loadErr) {
        if (loadErr) {
            req.log.warn(loadErr,
                         'S3_MPU: Failed to load bucket for record update');
            return (callback(loadErr));
        }

        bucketHelpers.getBucketIfExists(uploadReq, null,
                                        function (bucketErr) {
            if (bucketErr) {
                req.log.warn(bucketErr,
                   'S3_MPU: Bucket not found for record update');
                return (callback(bucketErr));
            }

            // Get existing upload record
            getUploadRecord(req, uploadId, function (getErr, uploadRecord) {
                if (getErr) {
                    req.log.warn(getErr,
                       'S3_MPU: Failed to get upload record for update');
                    return (callback(getErr));
                }

                // Update parts tracking
                uploadRecord.parts = uploadRecord.parts || {};
                uploadRecord.parts[partNumber] = {
                    etag: partInfo.etag,
                    size: partInfo.size,
                    uploaded: partInfo.uploaded
                };
                uploadRecord.lastModified = new Date().toISOString();

                // Store updated record
                var updatedContent = JSON.stringify(uploadRecord);
                var metadataLocation = req.metadataPlacement.getObjectLocation(
                    owner, uploadReq.bucket.id, crypto.createHash('md5')
                                                       .update(uploadRecordKey)
                                                       .digest('hex'));
                var client = req.metadataPlacement.
                    getBucketsMdapiClient(metadataLocation);

                client.updateObject(owner, uploadReq.bucket.id, uploadRecordKey,
                    uploadRecord.objectId || uuidv4(), 'application/json',
                    {'content-length': String(updatedContent.length)}, {},
                    metadataLocation.vnode, {}, req.getId(),
                    function (updateErr, result) {
                        if (updateErr) {
                            req.log.warn(updateErr,
                                'S3_MPU: Failed to update upload record');
                            // Don't fail the part upload if record update fails
                            return (callback(null));
                        }

                        req.log.debug({
                            uploadId: uploadId,
                            partNumber: partNumber
                        }, 'S3_MPU: Successfully' +
                           ' updated upload record with part info');

                        callback(null);
                    });
            });
        });
    });
}

function validatePartsForComplete(uploadRecord, partsFromXML, req, callback) {
    var owner = req.owner.account.uuid;
    var bucketId = uploadRecord.bucketId;
    var uploadId = uploadRecord.uploadId;

    req.log.debug({
        uploadId: uploadId,
        partsFromXML: partsFromXML.length,
        partsToValidate: partsFromXML.map(function (p) {
            return ({ num: p.partNumber, etag: p.etag });
        })
    }, 'S3_MPU: Starting comprehensive part validation');

    // Step 1: Validate parts are in ascending order (existing check)
    for (var i = 1; i < partsFromXML.length; i++) {
        if (partsFromXML[i].partNumber <= partsFromXML[i - 1].partNumber) {
            var orderError = new InvalidPartOrderError();
            return (callback(orderError));
        }
    }

    // Step 2: Validate part number range and no gaps
    var expectedPartNumber = 1;
    for (var j = 0; j < partsFromXML.length; j++) {
        if (partsFromXML[j].partNumber !== expectedPartNumber) {
            var gapError =
                new InvalidPartError('Missing or out of order part: expected ' +
                expectedPartNumber + ', got ' + partsFromXML[j].partNumber);
            return (callback(gapError));
        }
        expectedPartNumber++;
    }

    // Step 3: PERFORMANCE OPTIMIZATION - Batched part validation
    // Process parts in batches to prevent overwhelming buckets-mdapi
    var VALIDATION_BATCH_SIZE = 15; // Process 15 parts per batch
    var BATCH_CONCURRENCY = 3; // 3 parallel batches maximum

    var validatedCount = 0;
    // Report every 10%
    var progressInterval = Math.ceil(partsFromXML.length / 10);
    var validationStartTime = Date.now();

    // Create validation batches
    var validationBatches = [];
    for (i = 0; i < partsFromXML.length; i += VALIDATION_BATCH_SIZE) {
        validationBatches.push(partsFromXML.slice(i, i +
                                                  VALIDATION_BATCH_SIZE));
    }

    req.log.info({
        totalParts: partsFromXML.length,
        batchCount: validationBatches.length,
        batchSize: VALIDATION_BATCH_SIZE,
        batchConcurrency: BATCH_CONCURRENCY,
        strategy: 'batched-validation'
    }, 'S3_MPU: Starting batched part validation for improved performance');

    // Process batches with controlled concurrency
    vasync.forEachParallel({
        func: function validateBatch(batch, nextBatch) {
            var batchNumber = validationBatches.indexOf(batch) + 1;

            req.log.debug({
                batchNumber: batchNumber,
                batchSize: batch.length,
                partsInBatch: batch.map(function (p) { return p.partNumber; })
            }, 'S3_MPU: Processing validation batch');

            // Validate all parts in this batch in parallel
            vasync.forEachParallel({
                func: function validatePart(xmlPart, next) {
            var partNumber = xmlPart.partNumber;
            var expectedETag = xmlPart.etag;
            var partObjectName = '.mpu-parts/' + uploadId + '/' + partNumber;

            req.log.debug({
                partNumber: partNumber,
                expectedETag: expectedETag,
                partObjectName: partObjectName
            }, 'S3_MPU: Validating individual part');

            // Get part object metadata to verify existence and ETag
            var metadataLocation = req.metadataPlacement.getObjectLocation(
                owner, bucketId, crypto.createHash('md5')
                                       .update(partObjectName)
                                       .digest('hex'));
            var client = req.metadataPlacement.
                getBucketsMdapiClient(metadataLocation);

            client.getObject(owner, bucketId, partObjectName,
                           metadataLocation.vnode, {}, req.getId(),
                           function (getErr, partMeta) {
                if (getErr) {
                    req.log.error({
                        err: getErr,
                        partNumber: partNumber,
                        uploadId: uploadId
                    }, 'S3_MPU: Part validation failed - part not found');

                    return next(new InvalidPartError('Part ' + partNumber +
                                       ' does not exist in storage'));
                }

                // Validate ETag matches
                // s3cmd can send either hex MD5 (from resume/ListParts)
                // or UUIDs (from original upload)
                // We need to check both formats
                var storedUUID = partMeta.id || partMeta.etag;
                var storedHexMD5 = null;
                var md5Field = partMeta.contentMD5 || partMeta.content_md5;

                if (md5Field && md5Field !== partMeta.id) {
                    try {
                        storedHexMD5 = Buffer.from(md5Field,
                                                   'base64').toString('hex');
                    } catch (convErr) {
                        req.log.debug({
                            partNumber: partNumber,
                            conversionError: convErr.message
                        }, 'S3_MPU: Failed to convert MD5 for comparison');
                    }
                }

                var etagMatches = false;
                var matchedFormat = 'none';

                // Try hex MD5 comparison first (from resume scenarios)
                if (storedHexMD5 && expectedETag === storedHexMD5) {
                    etagMatches = true;
                    matchedFormat = 'hex-md5';
                }
                // Fall back to UUID comparison (from original upload ETags)
                else if (expectedETag === storedUUID) {
                    etagMatches = true;
                    matchedFormat = 'uuid';
                }

                req.log.debug({
                    partNumber: partNumber,
                    expectedETag: expectedETag,
                    storedUUID: storedUUID,
                    storedHexMD5: storedHexMD5,
                    etagMatches: etagMatches,
                    matchedFormat: matchedFormat
                }, 'S3_MPU: Complete MPU ETag validation - dual format check');

                if (!etagMatches) {
                    req.log.error({
                        partNumber: partNumber,
                        expectedETag: expectedETag,
                        storedUUID: storedUUID,
                        storedHexMD5: storedHexMD5,
                        uploadId: uploadId
                    }, 'S3_MPU: Part validation failed - ETag mismatch');

                    return next(new InvalidPartError('Part ' + partNumber +
                                  ' ETag mismatch: expected ' + expectedETag +
                                  ', got ' + storedUUID + ' (UUID) or ' +
                                  (storedHexMD5 || 'none') + ' (hex MD5)'));
                }

                // Validate part has valid sharks/storage
                if (!partMeta.sharks || partMeta.sharks.length === 0) {
                    req.log.error({
                        partNumber: partNumber,
                        uploadId: uploadId
                    }, 'S3_MPU: Part validation failed - no sharks assigned');

                    return next(new InvalidPartError('Part ' + partNumber +
                               ' has no storage sharks assigned'));
                }

                // Validate minimum part size (except last part)
                var minPartSize = 5 * 1024 * 1024; // 5MB minimum
                var isLastPart = (partNumber === partsFromXML.length);
                if (!isLastPart && partMeta.content_length < minPartSize) {
                    req.log.error({
                        partNumber: partNumber,
                        partSize: partMeta.content_length,
                        minSize: minPartSize,
                        uploadId: uploadId
                    }, 'S3_MPU: Part validation failed - part too small');

                    return next(new EntityTooSmallError('Part ' + partNumber +
                              ' is too small (' + partMeta.content_length +
                              ' bytes, minimum ' + minPartSize + ')'));
                }

                    // Update progress tracking
                    validatedCount++;

                    // Report progress every 10% for large uploads
                    if (partsFromXML.length > 100 && validatedCount %
                        progressInterval === 0) {
                        var progressPct = Math.round((validatedCount /
                             partsFromXML.length) * 100);
                        req.log.info({
                            validatedParts: validatedCount,
                            totalParts: partsFromXML.length,
                            progressPercent: progressPct,
                            batchesCompleted: Math.ceil(validatedCount /
                                VALIDATION_BATCH_SIZE),
                            totalBatches: validationBatches.length,
                            uploadId: uploadId
                        }, 'S3_MPU: Batched validation progress');
                    }

                    req.log.debug({
                        partNumber: partNumber,
                        partSize: partMeta.content_length,
                        sharks: partMeta.sharks.length,
                        etag: matchedFormat === 'hex-md5' ?
                            storedHexMD5 : storedUUID,
                        matchedFormat: matchedFormat,
                        batchNumber: batchNumber
                    }, 'S3_MPU: Part validation passed in batch');

                    next();
                });
                },
                inputs: batch
            }, function (batchErr) {
                if (batchErr) {
                    req.log.error({
                        err: batchErr,
                        batchNumber: batchNumber,
                        batchSize: batch.length
                    }, 'S3_MPU: Batch validation failed');
                    return (nextBatch(batchErr));
                }

                req.log.debug({
                    batchNumber: batchNumber,
                    batchSize: batch.length,
                    validatedSoFar: validatedCount
                }, 'S3_MPU: Validation batch completed successfully');

                nextBatch();
            });
        },
        inputs: validationBatches,
        concurrency: BATCH_CONCURRENCY
    }, function (err) {
        if (err) {
            req.log.error({
                err: err,
                uploadId: uploadId,
                totalParts: partsFromXML.length,
                strategy: 'batched-validation'
            }, 'S3_MPU: Batched part validation failed');
            return (callback(err));
        }

        var validationDuration = Date.now() - validationStartTime;
        var partsPerSecond = Math.round((partsFromXML.length /
                                         validationDuration) * 1000);
        var batchesPerSecond = Math.round((validationBatches.length /
                                           validationDuration) * 1000);

        req.log.info({
            uploadId: uploadId,
            validatedParts: partsFromXML.length,
            totalBatches: validationBatches.length,
            batchSize: VALIDATION_BATCH_SIZE,
            batchConcurrency: BATCH_CONCURRENCY,
            validationDurationMs: validationDuration,
            validationDurationSec: Math.round(validationDuration / 1000),
            partsPerSecond: partsPerSecond,
            batchesPerSecond: batchesPerSecond,
            strategy: 'batched-validation'
        }, 'S3_MPU: All parts validated successfully with batched approach');

        callback(null);
    });
}

// Removed updateUploadRecordStatus - now using simple metadata status objects


function assembleMultipartUpload(req, uploadRecord, commitBody, callback) {
    req.log.debug({
        uploadId: uploadRecord.uploadId,
        partCount: commitBody.parts.length,
        actualSize: commitBody.nbytes
    }, 'S3_MPU: Starting multipart assembly' +
        ' - will discover paths then try v2 commit');

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
        }, 'S3_MPU: Part paths discovered, proceeding to v2 commit attempt');

        // Step 3: Validate shark space before v2 commit
        validateSharkSpaceForCommit(req, partPaths, finalSize,
                                    function (spaceErr) {
            if (spaceErr) {
                req.log.warn({
                    error: spaceErr.message,
                    finalSizeMB: Math.ceil(finalSize / 1048576),
                    uploadId: uploadRecord.uploadId
                }, 'S3_MPU: Insufficient space for v2 commit, failing upload');

                return (callback(spaceErr));
            }

            req.log.info({
                finalSizeMB: Math.ceil(finalSize / 1048576),
                uploadId: uploadRecord.uploadId
            }, 'S3_MPU: Space validation passed, proceeding with v2 commit');

            // Step 4: Try native v2 commit first, fall back to streaming
            var v2Multipart = require('./s3-multipart-v2');
            v2Multipart.tryMakoV2Commit(req, uploadRecord, partPaths,
                                        finalCommitBody, callback);
        });
    });
}

/**
 * Validate that pre-allocated sharks have sufficient space for final object
 * Returns NotEnoughSpaceError if insufficient space is detected
 */
function validateSharkSpaceForCommit(req, partPaths, finalSizeBytes, callback) {
    // Convert to MB for comparison
    var finalSizeMB = Math.ceil(finalSizeBytes / 1048576);

    if (partPaths.length === 0) {
        return (callback(new Error('No parts available for space validation')));
    }

    // Get shark information from the first part (all parts use same sharks)
    var samplePart = partPaths[0];
    if (!samplePart.sharks || !Array.isArray(samplePart.sharks)) {
        req.log.warn({
            uploadId: req.s3Request.uploadId,
            finalSizeMB: finalSizeMB
        }, 'S3_MPU: No shark information available, skipping space validation');
        return (callback()); // Skip validation if no shark info
    }

    // Get current space information from storinfo
    var isOperator = req.caller.account.isOperator;
    var sharkMap = isOperator ?
        req.storinfo.operatorDcSharkMap : req.storinfo.dcSharkMap;

    if (!sharkMap) {
        req.log.warn({
            uploadId: req.s3Request.uploadId,
            finalSizeMB: finalSizeMB
        }, 'S3_MPU: No shark map available, skipping space validation');
        return (callback()); // Skip validation if no shark map
    }

    req.log.debug({
        uploadId: req.s3Request.uploadId,
        finalSizeMB: finalSizeMB,
        sharkCount: samplePart.sharks.length,
        sharks: samplePart.sharks.map(
            function (s) { return s.manta_storage_id; })
    }, 'S3_MPU: Validating space on pre-allocated sharks');

    // Build map of shark ID to current space info
    var currentSharkSpaces = {};
    Object.keys(sharkMap).forEach(function (datacenter) {
        var dcSharks = sharkMap[datacenter];
        if (Array.isArray(dcSharks)) {
            dcSharks.forEach(function (shark) {
                currentSharkSpaces[shark.manta_storage_id] =
                    shark.availableMB || 0;
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
            uploadId: req.s3Request.uploadId,
            finalSizeMB: finalSizeMB,
            totalSharks: totalSharks,
            insufficientSharks: insufficientSharks.length,
            insufficientSharkDetails: insufficientSharks
        }, 'S3_MPU:' +
            ' Pre-allocated sharks have insufficient space for final object');

        // Create same error as storinfo.choose() for consistency
        var cause = insufficientSharks.length + ' out of ' + totalSharks +
            ' pre-allocated sharks have insufficient space for final object';
        var error = new StorinfoNotEnoughSpaceError(finalSizeMB, cause);
        return (callback(error));
    }

    req.log.info({
        uploadId: req.s3Request.uploadId,
        finalSizeMB: finalSizeMB,
        validatedSharks: totalSharks,
        sharkSpaces: samplePart.sharks.map(function (s) {
            return {
                shark: s.manta_storage_id,
                availableMB: currentSharkSpaces[s.manta_storage_id] || 'unknown'
            };
        })
    }, 'S3_MPU: All pre-allocated sharks' +
       ' have sufficient space for final object');

    callback(); // Success
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
    var approxTotalSize = partPaths.reduce(function (sum, p) {
        return (sum + (p.size || 0));
    }, 0);

    // Calculate dynamic timeout based on file size (1 minute per GB +
    // 5 min base)
    var estimatedAssemblyTimeMs = Math.max(300000, // 5 min minimum
        (approxTotalSize / (1024 * 1024 * 1024)) * 60000 + 300000); // 1 min/GB
                                                                 // + 5 min base

    req.log.debug({
        partsToStream: partPaths.length,
        approxTotalSize: approxTotalSize,
        approxTotalSizeGB: (approxTotalSize / (1024 * 1024 * 1024)).toFixed(2),
        estimatedAssemblyTimeMs: estimatedAssemblyTimeMs,
        estimatedAssemblyTimeMin: (estimatedAssemblyTimeMs / 60000).toFixed(1),
        finalObjectId: req._finalObjectId
    }, 'S3_MPU: Starting streaming assembly with dynamic timeout');

    // Use normal object creation flow to ensure proper shark allocation and
    // storage
    // This ensures the data location matches exactly what will be in metadata

    // Get durability level from stored temporary object with metadata
    var uploadRecord = req._uploadRecord;
    var durabilityKey = '.mpu-uploads/' +
        (uploadRecord ? uploadRecord.uploadId : 'unknown') + '.durability';

    getDurabilityObject(req, durabilityKey, function (durErr, durabilityData) {
        var copies;
        if (!durErr && durabilityData &&
            durabilityData.durabilityLevel !== undefined) {
            copies = durabilityData.durabilityLevel;
            req.log.debug({
                uploadId: uploadRecord ? uploadRecord.uploadId : 'unknown',
                durabilityLevel: copies,
                source: 'durability-object'
            }, 'S3_MPU: Using durability level' +
                          'from durability object for streaming assembly');
        } else {
            // Fallback to upload record or request headers
            if (uploadRecord && uploadRecord.durabilityLevel !== undefined) {
                copies = uploadRecord.durabilityLevel;
            } else {
                copies = parseInt((req.header('durability-level') ||
                                   req.header('x-durability-level') ||
                                   common.DEF_NUM_COPIES), 10);
            }
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
            req.log.debug({
                sharkData: shark,
                sharkId: shark ? shark.manta_storage_id : 'undefined',
                sharkKeys: Object.keys(shark || {})
            }, 'S3_MPU: Creating shark client for assembly');

            var client = sharkClient.getClient({
                connectTimeout: (req.sharkConfig &&
                                 req.sharkConfig.connectTimeout) || 10000,
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

            // Calculate the expected storage path for debugging
            var expectedStoragePath = require('./shark_client').storagePath({
                storageLayoutVersion: common.CURRENT_STORAGE_LAYOUT_VERSION,
                owner: owner,
                bucketId: uploadRecord ? uploadRecord.bucketId : 'unknown',
                objectNameHash: objectNameHash,
                objectId: objectId
            });

            req.log.info({
                shark: shark.manta_storage_id,
                putOpts: putOpts,
                expectedStoragePath: expectedStoragePath
            }, 'S3_MPU: Setting up final shark storage with calculated path');

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
                            statusCode: sharkRes.statusCode,
                            objectId: objectId,
                            objectName: objectName
                        }, 'S3_MPU: Final shark storage failed');
                        barrier.done(shark.manta_storage_id);
                        return (next(err));
                    }

                    req.log.info({
                        shark: shark.manta_storage_id,
                        statusCode: sharkRes.statusCode,
                        objectId: objectId,
                        objectName: objectName,
                        storageLayoutVersion:
                        common.CURRENT_STORAGE_LAYOUT_VERSION
                    }, 'S3_MPU: Final shark confirmed successful storage' +
                       ' - object should be downloadable');

                    completedSharks.push(shark);
                    barrier.done(shark.manta_storage_id);
                });

                sharkReq.once('error', function (reqErr) {
                    req.log.error({
                        err: reqErr,
                        shark: shark.manta_storage_id
                    }, 'S3_MPU: Final shark request error');
                    barrier.done(shark.manta_storage_id, reqErr);
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
                req.log.error({
                    uploadId: req._uploadRecord ?
                        req._uploadRecord.uploadId : 'unknown',
                    objectName: objectName,
                    completedSharks: completedSharks.length,
                    expectedSharks: finalSharks.length
                }, 'S3_MPU: CRITICAL ERROR ' +
                    '- Sharks completed before streaming finished');
                return callback(new Error(
                    'Multipart assembly failed - streaming incomplete'));
            }

            // Validate that ALL sharks completed successfully
            if (completedSharks.length !== finalSharks.length) {
                req.log.error({
                    uploadId: req._uploadRecord ? req._uploadRecord.uploadId :
                        'unknown',
                    objectName: objectName,
                    completedSharks: completedSharks.length,
                    expectedSharks: finalSharks.length,
                    failedSharks: finalSharks.length - completedSharks.length
                }, 'S3_MPU: CRITICAL ERROR' +
                   ' - Not all sharks completed successfully');
                return callback(new Error(
                    'Multipart assembly failed - incomplete shark storage'));
            }

            // Calculate MD5 only once
            var finalMD5 = md5Hash.digest('base64');

            req.log.info({
                totalBytes: totalBytes,
                finalMD5: finalMD5,
                completedSharks: completedSharks.length,
                uploadId: req._uploadRecord ? req._uploadRecord.uploadId :
                    'unknown',
                objectName: objectName
            }, 'S3_MPU:' +
               ' All sharks completed successfully - assembly validated');

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
        if (!durErr && durabilityData &&
            durabilityData.durabilityLevel !== undefined) {
            copies = durabilityData.durabilityLevel;
            req.log.debug({
                uploadId: uploadRecord.uploadId,
                durabilityLevel: copies,
                source: 'durability-object'
            }, 'S3_MPU: Using durability level from durability' +
               ' object for final object storage');
        } else {
            // Fallback to upload record or request headers
            if (uploadRecord && uploadRecord.durabilityLevel !== undefined) {
                copies = uploadRecord.durabilityLevel;
            } else {
                copies = parseInt((req.header('durability-level') ||
                                   req.header('x-durability-level') ||
                                   common.DEF_NUM_COPIES), 10);
            }
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
                                 req.sharkConfig.connectTimeout) || 10000,
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

            req.log.info({
                objectId: objectId,
                objectName: objectName,
                bucketId: bucketId,
                vnode: metadataLocation.vnode,
                objectResultCreated: objectResult.created,
                objectResultModified: objectResult.modified
            }, 'S3_MPU: LISTING DEBUG' +
              ' - Object created with metadata, should be visible in listings');
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
    // Mark upload as completed and clean up upload record
    req.log.debug({
        uploadId: uploadId
    }, 'S3_MPU: Starting cleanup of multipart upload');

    // Status object will be cleaned up along with other objects below

    // Clean up upload record
    var uploadRecordKey = '.mpu-uploads/' + uploadId;
    var owner = req.owner.account.uuid;

    var uploadReq = Object.create(req);
    uploadReq.params = {
        bucket_name: req.s3Request.bucket,
        object_name: uploadRecordKey
    };

    bucketHelpers.loadRequest(uploadReq, null, function (loadErr) {
        if (loadErr) {
            req.log.warn(loadErr,
               'S3_MPU: Failed to load bucket for cleanup');
            return (callback(null)); // Don't fail the overall operation
        }

        bucketHelpers.getBucketIfExists(uploadReq, null,
                                        function (bucketErr) {
                if (bucketErr) {
                    req.log.warn(bucketErr,
                       'S3_MPU: Bucket not found during cleanup');
                    return (callback(null));
                }

                var metadataLocation = req.metadataPlacement.getObjectLocation(
                    owner, uploadReq.bucket.id, crypto.createHash('md5')
                                                       .update(uploadRecordKey)
                                                       .digest('hex'));
                var client =
                    req.metadataPlacement.getBucketsMdapiClient
                                                (metadataLocation);

                // Delete upload record
                client.deleteObject(owner, uploadReq.bucket.id, uploadRecordKey,
                    metadataLocation.vnode, {}, req.getId(),
                    function (delErr, result) {
                    if (delErr) {
                        req.log.warn(delErr,
                           'S3_MPU: Failed to delete upload record');
                    } else {
                        req.log.debug({
                            uploadId: uploadId
                        }, 'S3_MPU: Successfully deleted upload record');
                    }

                    // Also try to clean up durability object
                    var durabilityKey = '.mpu-uploads/' + uploadId +
                        '.durability';
                    client.deleteObject(owner, uploadReq.bucket.id,
                                        durabilityKey,
                        metadataLocation.vnode, {}, req.getId(),
                        function (durDelErr, durResult) {
                        if (durDelErr) {
                            if (durDelErr.name === 'ObjectNotFound') {
                                req.log.debug({
                                    uploadId: uploadId
                                }, 'S3_MPU: Durability object not found' +
                                              ' (normal if not created)');
                            } else {
                                req.log.warn(durDelErr, 'S3_MPU: Failed' +
                                             ' to cleanup durability object');
                            }
                        } else {
                            req.log.debug({
                                uploadId: uploadId
                            }, 'S3_MPU: Successfully' +
                                          ' cleaned up durability object');
                        }

                        req.log.debug({
                            uploadId: uploadId
                        }, 'S3_MPU: Multipart upload cleanup completed');

                        callback(null);
                    });
                });
        });
    });
}

/**
 * List parts for a multipart upload (for resume functionality)
 * GET /{bucket}/{key}?uploadId={uploadId}
 */
function listPartsHandler() {
    return function listParts(req, res, next) {
        var uploadId = req.s3Request.uploadId;
        var bucketName = req.s3Request.bucket;
        var objectKey = req.s3Request.object;

        req.log.debug({
            uploadId: uploadId,
            bucket: bucketName,
            key: objectKey
        }, 'S3_MPU: Listing parts for upload');

        // Validate upload exists
        getUploadRecord(req, uploadId, function (getErr, uploadRecord) {
            if (getErr) {
                req.log.error(getErr,
                   'S3_MPU: Failed to get upload record for ListParts');
                return (next(new NoSuchUploadError(uploadId)));
            }

            // List all parts for this upload
            listUploadedParts(req, uploadId, uploadRecord,
                              function (listErr, parts) {
                if (listErr) {
                    req.log.error(listErr,
                       'S3_MPU: Failed to list uploaded parts');
                    return (next(listErr));
                }

                req.log.debug({
                    uploadId: uploadId,
                    partCount: parts.length,
                    parts: parts.map(function (p) {
                        return {
                            partNumber: p.partNumber,
                            size: p.size,
                            etag: p.etag
                        };
                    })
                }, 'S3_MPU: Successfully listed parts');

                // Build S3 XML response
                var xml = buildListPartsXML(uploadRecord, parts, bucketName,
                                            objectKey);

                res.header('Content-Type', 'application/xml');
                res.send(xml);
                next(false); // Stop processing
            });
        });
    };
}

/**
 * List uploaded parts by scanning .mpu-parts/{uploadId}/ directory
 * Supports pagination to handle up to 10,000 parts (S3 spec)
 */
function listUploadedParts(req, uploadId, uploadRecord, callback) {
    var bucketId = uploadRecord.bucketId;
    var partsPrefix = '.mpu-parts/' + uploadId + '/';
    var foundParts = [];
    var marker = null;
    var pageLimit = 1024; // buckets-mdapi limit per page

    req.log.debug({
        uploadId: uploadId,
        bucketId: bucketId,
        partsPrefix: partsPrefix
    }, 'S3_MPU: Starting paginated parts listing');

    // Pagination function to list all parts
    function listNextPage() {
        var listReq = Object.create(req);
        listReq.query = {
            prefix: partsPrefix,
            limit: pageLimit,
            marker: marker
        };

        var mreq = bucketsCommon.listObjects(listReq, bucketId);
        var pageEntries = [];
        var hasMoreResults = false;

        mreq.once('error', function (listErr) {
            req.log.warn(listErr,
               'S3_MPU: Failed to list parts directory page');
            return (callback(null, foundParts)); // Return what we have so far
        });

        mreq.on('entry', function (entry) {
            if (!entry || !entry.name || !entry.name.startsWith(partsPrefix)) {
                return;
            }

            pageEntries.push(entry);

            // Extract part number from name: .mpu-parts/{uploadId}/{partNumber}
            var partName = entry.name.substring(partsPrefix.length);
            var partNumber = parseInt(partName, 10);

            if (isNaN(partNumber) || partNumber < 1 || partNumber > 10000) {
                req.log.warn({
                    entryName: entry.name,
                    extractedPartName: partName,
                    partNumber: partNumber
                }, 'S3_MPU: Invalid part number in parts listing');
                return;
            }

            var etag = entry.contentMD5 || entry.id || '';

            // Convert base64 MD5 to hex format (s3cmd expects hex)
            if (entry.contentMD5 && entry.contentMD5 !== entry.id) {
                try {
                    // contentMD5 is base64, convert to hex for S3 compatibility
                    var hexMD5 = Buffer.from(entry.contentMD5,
                                             'base64').toString('hex');
                    etag = hexMD5;
                    req.log.debug({
                        partNumber: partNumber,
                        base64MD5: entry.contentMD5,
                        hexMD5: hexMD5
                    }, 'S3_MPU: Converted base64 MD5 to hex for ETag');
                } catch (convErr) {
                    req.log.warn({
                        partNumber: partNumber,
                        contentMD5: entry.contentMD5,
                        conversionError: convErr.message
                    }, 'S3_MPU: Failed to convert MD5 format, using original');
                    // Keep original etag on conversion failure
                }
            }

            req.log.debug({
                partNumber: partNumber,
                entryName: entry.name,
                contentMD5: entry.contentMD5,
                objectId: entry.id,
                selectedETag: etag
            }, 'S3_MPU: Processing part for ListParts response');

            foundParts.push({
                partNumber: partNumber,
                size: entry.size || 0,
                etag: etag,  // Use MD5 hash as ETag, fallback to object ID
                lastModified: entry.mtime || new Date()
            });
        });

        mreq.on('message', function (msg) {
            if (msg && msg.finished === false) {
                // More results available - not finished
                hasMoreResults = true;
            }
        });

        mreq.once('end', function () {
            req.log.debug({
                uploadId: uploadId,
                pageEntries: pageEntries.length,
                totalFoundParts: foundParts.length,
                hasMoreResults: hasMoreResults,
                lastEntryName: pageEntries.length > 0 ?
                    pageEntries[pageEntries.length - 1].name : 'none'
            }, 'S3_MPU: Completed parts listing page');

            // If we got a full page and there might be more results,
            // continue pagination
            if (pageEntries.length === pageLimit && hasMoreResults) {
                // Set marker to the last entry name for next page
                marker = pageEntries[pageEntries.length - 1].name;
                req.log.debug({
                    uploadId: uploadId,
                    nextMarker: marker,
                    totalFoundSoFar: foundParts.length
                }, 'S3_MPU: Continuing to next page');
                setImmediate(listNextPage);
            } else {
                // No more pages - sort and return results
                foundParts.sort(function (a, b) {
                    return (a.partNumber - b.partNumber);
                });

                req.log.debug({
                    uploadId: uploadId,
                    totalParts: foundParts.length,
                    partNumbers: foundParts.map(
                        function (p) { return p.partNumber; })
                }, 'S3_MPU: Completed all parts listing');

                callback(null, foundParts);
            }
        });
    }

    // Start pagination
    listNextPage();
}

/**
 * Build S3-compatible ListParts XML response
 */

/* BEGIN JSSTYLED */
function buildListPartsXML(uploadRecord, parts, bucketName, objectKey) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n';
    xml += '  <Bucket>' + escapeXml(bucketName) + '</Bucket>\n';
    xml += '  <Key>' + escapeXml(objectKey) + '</Key>\n';
    xml += '  <UploadId>' + escapeXml(uploadRecord.uploadId) + '</UploadId>\n';
    xml += '  <Initiator>\n';
    xml += '    <ID>' + escapeXml(uploadRecord.account || 'unknown') + '</ID>\n';
    xml += '    <DisplayName>' + escapeXml(uploadRecord.account || 'unknown') + '</DisplayName>\n';
    xml += '  </Initiator>\n';
    xml += '  <Owner>\n';
    xml += '    <ID>' + escapeXml(uploadRecord.account || 'unknown') + '</ID>\n';
    xml += '    <DisplayName>' + escapeXml(uploadRecord.account || 'unknown') + '</DisplayName>\n';
    xml += '  </Owner>\n';
    xml += '  <StorageClass>STANDARD</StorageClass>\n';
    xml += '  <PartNumberMarker>0</PartNumberMarker>\n';
    xml += '  <NextPartNumberMarker>' + (parts.length > 0 ? parts[parts.length - 1].partNumber : '0') + '</NextPartNumberMarker>\n';
    xml += '  <MaxParts>10000</MaxParts>\n';
    xml += '  <IsTruncated>false</IsTruncated>\n';

    parts.forEach(function (part) {
        xml += '  <Part>\n';
        xml += '    <PartNumber>' + part.partNumber + '</PartNumber>\n';
        xml += '    <LastModified>' + part.lastModified.toISOString() + '</LastModified>\n';
        // S3 ETags are already quoted MD5 hashes, don't add extra quotes
        var etag = part.etag;
        if (etag && !etag.startsWith('"')) {
            etag = '"' + etag + '"';
        }
        xml += '    <ETag>' + escapeXml(etag) + '</ETag>\n';
        xml += '    <Size>' + part.size + '</Size>\n';
        xml += '  </Part>\n';
    });

    xml += '</ListPartsResult>\n';
    return xml;
}
/* END JSSTYLED */
/**
 * Handle resume upload requests (PUT without partNumber)
 */
function resumeUploadHandler() {
    return function resumeUpload(req, res, next) {
        var uploadId = req.s3Request.uploadId;

        req.log.debug({
            uploadId: uploadId
        }, 'S3_MPU: Resume upload request received');

        // Validate upload exists
        getUploadRecord(req, uploadId, function (getErr, uploadRecord) {
            if (getErr) {
                req.log.error(getErr,
                   'S3_MPU: Upload record not found for resume');
                return (next(new NoSuchUploadError(uploadId)));
            }

            // Return success - client should use ListParts to determine state
            res.header('x-amz-upload-id', uploadId);
            res.send(200,
               'Upload exists - use ListParts to determine resume state');
            next(false);
        });
    };
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

function InvalidPartError(message) {
    var err = new Error(message || 'Invalid part in multipart upload');
    err.name = 'InvalidPart';
    err.statusCode = 400;
    err.restCode = 'InvalidPart';
    return (err);
}

function EntityTooSmallError(message) {
    var err = new Error(message || 'Part is too small');
    err.name = 'EntityTooSmall';
    err.statusCode = 400;
    err.restCode = 'EntityTooSmall';
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

function storeDurabilityObject(req, durabilityKey, durabilityData, callback) {
    // Synchronous storage using direct buckets-mdapi call
    callback = callback || function () {}; // Default no-op callback

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
            return (callback(loadErr));
        }

        bucketHelpers.getBucketIfExists(durabilityReq, null,
                                        function (bucketErr) {
            if (bucketErr) {
                req.log.warn(bucketErr,
                   'S3_MPU: Bucket not found for durability object');
                return (callback(bucketErr));
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
                ((durabilityData.durabilityLevel !== undefined) ?
                 durabilityData.durabilityLevel :
                 common.DEF_NUM_COPIES).toString(),
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
                    return (callback(createErr));
                } else {
                    req.log.debug(
                        'S3_MPU: Successfully stored durability object');
                    return (callback(null));
                }
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

                // Read durability level and status from object metadata
                var durabilityData = {};
                if (result.headers && result.headers['x-durability-level']) {
                    durabilityData = {
                        durabilityLevel:
                        parseInt(result.headers['x-durability-level'], 10),
                        uploadId: result.headers['x-upload-id'],
                        created: result.headers['x-created']
                    };
                }

                // Also check for status information if it exists in content
                if (result.value) {
                    req.log.debug({
                        durabilityKey: durabilityKey,
                        hasContent: !!result.value,
                        contentLength: result.value ? result.value.length : 0
                    }, 'S3_MPU: Found content in durability object,' +
                                  ' checking for status');

                    try {
                        var contentData = JSON.parse(result.value);
                        req.log.debug({
                            durabilityKey: durabilityKey,
                            contentData: contentData,
                            hasStatus: !!contentData.status
                        }, 'S3_MPU: Parsed durability object content');

                        if (contentData.status) {
                            durabilityData.status = contentData.status;
                            durabilityData.instanceId = contentData.instanceId;
                            durabilityData.completingTimestamp =
                                contentData.completingTimestamp;

                            req.log.debug({
                                durabilityKey: durabilityKey,
                                status: contentData.status,
                                instanceId: contentData.instanceId
                            }, 'S3_MPU: Extracted status' +
                                          ' from durability object content');
                        }

                        // Extract sharks from content if present
                        if (contentData.sharks &&
                            Array.isArray(contentData.sharks)) {
                            durabilityData.sharks = contentData.sharks;

                            req.log.info({
                                durabilityKey: durabilityKey,
                                sharkCount: contentData.sharks.length,
                                sharks: contentData.sharks.map(function (s) {
                                    return (s ? s.manta_storage_id : 'null');
                                }),
                                rawSharkData: contentData.sharks
                            }, 'S3_MPU: Extracted pre-allocated sharks' +
                               ' from durability object');
                        }
                    } catch (parseErr) {
                        req.log.warn({
                            durabilityKey: durabilityKey,
                            parseError: parseErr.message,
                            content: result.value
                        }, 'S3_MPU: Failed to parse durability object content');
                    }
                } else {
                    req.log.debug({
                        durabilityKey: durabilityKey
                    }, 'S3_MPU: No content found in durability object');
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
    s3AbortMultipartUploadHandler: s3AbortMultipartUploadHandler,
    customAssembleMultipartUpload: customAssembleMultipartUpload,
    createFinalObjectMetadata: createFinalObjectMetadata,
    validateSharkSpaceForCommit: validateSharkSpaceForCommit,
    listPartsHandler: listPartsHandler,
    resumeUploadHandler: resumeUploadHandler
};
