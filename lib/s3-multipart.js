/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * File:     s3-multipart.js
 * Purpose:  Implements multipart uploads required by S3 clients.
 *
 * Description:
 *  S3 multipart upload is a mechanism for uploading large objects by breaking
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
 *  object have, when assembling. this is more a workaround for broken environ-
 *  ments where storage nodes cannot comply with the durability level requested.
 *
 *  Assembling parts:
 *  Mako /mpu/v2/commit is used for assembling parts in the background, the
 *  catch here is that all the parts that are part of a final object must reside
 *  in the storage node where the /mpu/v2/commit is requested, so on a mpu
 *  request arrives we choose an array of nodes based on the durability level,
 *  so all parts reside on the array of nodes so the final part is replicated
 *  with the right durability level as we call mpu/v2/commit in each storage
 *  node selected when a complete multipart upload request comes.
 */


var assert = require('assert-plus');
var crypto = require('crypto');
var uuidv4 = require('uuid/v4');
var vasync = require('vasync');

var auth = require('./auth');
var bucketHelpers = require('./buckets/buckets');
var common = require('./common');
var constants = require('./constants');
var InvalidDurabilityLevelError = require('./errors').
    InvalidDurabilityLevelError;
var SharksExhaustedError = require('./errors').
    SharksExhaustedError;
var sharkClient = require('./shark_client');
var storinfoErrors = require('storinfo/lib/errors');
var StorinfoNotEnoughSpaceError = storinfoErrors.NotEnoughSpaceError;
var bucketsCommon = require('./buckets/common');
var translateBucketError = bucketsCommon.translateBucketError;
var s3Compat = require('./s3-compat');

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
            (req.storinfo.defaultMaxStreamingSizeMB ||
                constants.SIZE_LIMITS.DEFAULT_MAX_STREAMING_MB),
            // Minimum 100MB buffer for safety
            100);

        // Perform space validation using same logic as storinfo.choose()
        var spaceValidationOpts = {
            replicas: copies,
            size: estimatedMaxSizeMB,
            isOperator: req.caller.account.isOperator
        };
        // Generate unique upload ID
        var uploadId = generateUploadId();

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
                req.log.debug({
                    uploadId: uploadId,
                    estimatedSizeMB: estimatedMaxSizeMB,
                    availableSharks: sharks ? sharks[0].length : 'unknown'
                }, 'S3_MPU: Space validation passed for multipart upload');
            }

            // Continue with durability object storage
            req.log.debug({
                uploadId: uploadId,
                hasValidatedSharks: !!sharks,
                sharksLength: sharks ? sharks.length : 0,
                sharksFirstReplicaLength: sharks &&
                    sharks[0] ? sharks[0].length : 0
            }, 'S3_MPU: DEBUG -' +
               ' Passing sharks to createDurabilityAndUploadRecord');

            createDurabilityAndUploadRecord(sharks);
        });
        /*
         * Here is where we store the durability level and sharks on a
         * mpu upload,
         * the durability header only comes on the first part part of the
         * request. The rest only have the part data, but the initial headers
         * are lost, so we store the information in the metadata of this dummy
         * object.
         */
        function createDurabilityAndUploadRecord(validatedSharks) {
            // Create upload record to track multipart upload state
            assert.object(validatedSharks, 'validatedSharks');
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

              // Cache sharks from storinfo call, we need the sharks to
              // store all the parts of a mpu in the same group of sharks.
                if (validatedSharks && validatedSharks[0]) {
                    uploadRecord.preAllocatedSharks =
                        validatedSharks[0].map(function (shark) {
                        return {
                            datacenter: shark.datacenter || 'unknown',
                            manta_storage_id: shark.manta_storage_id,
                            zone: shark.zone,
                            availableMB: shark.availableMB,
                            percentUtilized: shark.percentUtilized,
                            last_heartbeat: shark.last_heartbeat,
                            status: shark.status
                        };
                    });
                } else {
                    uploadRecord.preAllocatedSharks = null;
                }

               var uploadRecordContent = JSON.stringify(uploadRecord);
               var uploadRecordMD5 = crypto.createHash('md5')
                                           .update(uploadRecordContent)
                                           .digest('base64');

               req.log.debug({
                    uploadId: uploadId,
                    uploadRecordKey: uploadRecordKey,
                    uploadRecordContent: uploadRecordContent,
                    durabilityLevel: uploadRecord.durabilityLevel,
                    preAllocatedSharks: uploadRecord.preAllocatedSharks
                }, 'S3_MPU: About to store upload record' +
                   ' with durability level and sharks');

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
        uploadReq.headers['content-type'] = constants.CONTENT_TYPES.JSON;
        uploadReq.headers['content-length'] =
            String(uploadRecordContent.length);
        // No sharks needed - storing data in headers only
        uploadReq.sharks = [];
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
                // Create upload record object with headers containing the
                // durability level and sharks.
                var uploadHeaders = {
                    'x-upload-record': uploadRecordContent,
                    'x-durability-level': copies.toString(),
                    'x-upload-id': uploadId,
                    'x-preallocated-sharks':
                    JSON.stringify(uploadRecord.preAllocatedSharks || [])
                };
                // Use empty content - all data stored in headers
                // if we saved as content then we need a shark to get
                // the data and is just faster/simpler to just retrieve the
                // metadata.
                client.createObject(owner, uploadReq.bucket.id, uploadRecordKey,
                    uploadReq.objectId, 0, '',
                    constants.CONTENT_TYPES.JSON, uploadHeaders, [], {},
                                    metadataLocation.vnode, {},
                    requestId, function (createErr, result) {

                    if (createErr) {
                        req.log.error(createErr,
                            'S3_MPU: Failed to create upload record');
                        return (next(translateBucketError(req, createErr)));
                    }

                    req.log.debug({
                        uploadId: uploadId,
                        bucket: bucketName,
                        key: objectKey,
                        storedDurabilityLevel: copies,
                        sharks: uploadRecord.preAllocatedSharks
                    }, 'S3_MPU: Successfully stored upload' +
                                 ' record with durability level and sharks');
                    // Return S3 InitiateMultipartUploadResult XML
                    var xml = generateInitiateMultipartUploadXML(bucketName,
                          objectKey, uploadId);
                    res.setHeader('Content-Type',
                                  constants.CONTENT_TYPES.XML);
                    res.send(constants.HTTP_STATUS.OK, xml);
                    next(false);
                });
            });
        });
        } // End createUploadRecord function
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

        // Retrieve upload record to get durability level and sharks
        getUploadRecord(req, uploadId, function (getErr, sharkUploadRecord) {
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

            // Mark as S3 request for AWS chunked handling
            partReq.isS3Request = true;

            // Copy essential request properties for proper stream handling
            partReq.method = 'PUT';

            // Get durability level from upload record
            var durabilityLevel = sharkUploadRecord.durabilityLevel ||
                                parseInt(req.header('durability-level') ||
                                        req.header('x-durability-level') ||
                                        common.DEF_NUM_COPIES, 10);

            req.log.debug({
                uploadId: uploadId,
                durabilityLevel: durabilityLevel,
                source: sharkUploadRecord.durabilityLevel !== undefined ?
                    'upload-record' : 'default'
            }, 'S3_MPU: Using durability level for part upload');

            // Set durability level header for part creation
            partReq.headers['durability-level'] = durabilityLevel.toString();

            // Check if we have pre-allocated sharks from upload record
            if (sharkUploadRecord.preAllocatedSharks &&
                Array.isArray(sharkUploadRecord.preAllocatedSharks) &&
                sharkUploadRecord.preAllocatedSharks.length > 0) {

                req.log.debug({
                    uploadId: uploadId,
                    partNumber: partNumber,
                    sharkCount: sharkUploadRecord.preAllocatedSharks.length,
                    sharks: sharkUploadRecord.preAllocatedSharks.map(
                        function (s) {
                            return (s.manta_storage_id);
                    })
                }, 'S3_MPU: Using pre-allocated sharks from upload record');

                // Use the cached sharks from initiation
                partReq.preAllocatedSharks =
                    sharkUploadRecord.preAllocatedSharks;
            } else {
                req.log.error({
                    uploadId: uploadId,
                    partNumber: partNumber
                }, 'S3_MPU: No pre-allocated sharks found in upload record');
            }

           /*
            * For aws-chunked MPU, ensure metadata records use the decoded size
            * per S3 spec: Content-Length is encoded size,
            * x-amz-decoded-content-length is the actual payload size.
            * Quoting directly from the documentation:
            * Note:
            *
            *  When transferring data in a series of chunks, you must do one of
            *  the following:
            *
            *  - Explicitly specify the total content length (object length in
            *      bytes plus metadata in each chunk) using the Content-Length
            *      HTTP header. To do this, you must pre-compute the total
            *      length of the payload, including the metadata that you send
            *      in each chunk, before starting your request.
            *
            *  - Specify the Transfer-Encoding HTTP header. If you include the
            *      Transfer-Encoding header and specify any value other than
            *      identity, you must omit the Content-Length header.
            *
            * For all requests, you must include the
            * x-amz-decoded-content-length header, specifying the size of the
            * object in bytes.
            *
            * So in a nutshell if we see aws-chunked for content encoding
            * we must use the x-amz-decoded-content-lenght as size when
            * we are storing the object metadata, not doing so:
            * WILL CAUSE MAKO TO FAIL ON V2 COMMIT
            * the error will be a 409 with the error message : 'there is a disc-
            * repancy in one of the parts'
            * Why?
            * Because we stored in the metadata the encoded size, we send
            * data to disk of size decoded size, so the object sent to Mako
            * that is a list of parts + metadata it will show more data that
            * Mako actually knows about.
            */
            if (partReq.headers['content-encoding'] === 'aws-chunked' &&
                partReq.headers[constants.S3_HEADERS.DECODED_CONTENT_LENGTH]) {
                var decodedSize = parseInt(
                    partReq.headers[constants.
                                    S3_HEADERS.DECODED_CONTENT_LENGTH], 10);
                if (!isNaN(decodedSize)) {
                    // CRITICAL: Set _size to decoded size so metadata stores
                    // correct size Content-Length remains encoded size per
                    // S3 spec
                    partReq._size = decodedSize;
                    partReq._awsChunkedExpectedSize = decodedSize;

                    req.log.debug({
                        encodedContentLength: partReq.headers['content-length'],
                        decodedContentLength: decodedSize,
                        usingDecodedSize: decodedSize,
                        note: 'AWS chunked: metadata will use decoded size'
                    }, 'S3_MPU: Set decoded' +
                       ' size for AWS chunked part metadata');
                }
            }
            // Only let stream size determine metadata for non-AWS chunked parts
            if (partReq.headers['content-encoding'] !== 'aws-chunked') {
                req.log.debug({
                    partNumber: partNumber,
                    uploadId: uploadId,
                    contentLength: partReq.headers['content-length'],
                    contentEncoding: partReq.headers['content-encoding'],
                    note: 'Using undefined size - will record' +
                        ' actual bytes written'
                }, 'S3_MPU: Letting actual stream size' +
                   ' determine part metadata size');
            } else {
                req.log.debug({
                    partNumber: partNumber,
                    uploadId: uploadId,
                    contentLength: partReq.headers['content-length'],
                    contentEncoding: partReq.headers['content-encoding'],
                    partReqSize: partReq._size,
                    note: 'Using fixed Content-Length for AWS chunked part'
                }, 'S3_MPU: Using predetermined size for AWS chunked part');
            }
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
                    partReq.headers[constants.S3_HEADERS.DECODED_CONTENT_LENGTH]
                }, 'S3_MPU: AWS chunked encoding detected in part upload');

                // Mark for special handling in common.js
                partReq._awsChunkedMPU = true;

                req.log.debug({
                    contentEncoding: partReq.headers['content-encoding'],
                    decodedLength:
                    partReq.headers[constants.
                        S3_HEADERS.DECODED_CONTENT_LENGTH],
                    awsChunkedMPU: partReq._awsChunkedMPU,
                    isS3Request: partReq.isS3Request,
                    partNumber: partNumber
                }, 'S3_MPU: Set AWS chunked MPU' +
                   ' flags for common.js processing');

                // For AWS chunked MPU, we must store the DECODED size
                // in metadata to match what's actually on disk,
                // not the encoded size
                req.log.debug({
                    uploadId: uploadId,
                    partNumber: partNumber,
                    decodedLength:
                    partReq.headers[constants.
                        S3_HEADERS.DECODED_CONTENT_LENGTH],
                    willUseDecodedSize: true,
                    partReqSize: partReq._size
                }, 'S3_MPU:' +
                   ' AWS chunked part - will store decoded size');
            }

            // Proceed with part upload using cached sharks
            proceedWithPartUpload();

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
                    if (name.toLowerCase() === 'etag') {
                        partETag = value;
                        req.log.debug({
                            etag: value,
                            headerName: name
                        }, 'S3_MPU: Captured ETag from part upload (header)');
                    }
                    return (res.header(name, value));
                };

                customRes.setHeader = function (name, value) {
                    if (name.toLowerCase() === 'etag') {
                        partETag = value;
                        req.log.debug({
                            etag: value,
                            headerName: name
                        }, 'S3_MPU:' +
                          ' Captured ETag from part upload (setHeader)');
                    }
                    return (res.setHeader(name, value));
                };

                // Log the headers being sent to object creation
                req.log.debug({
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
                        resultId: result ? result.id : 'no-result',
                        resultKeys: result ? Object.keys(result) : [],
                        hasResult: !!result,
                        resultContentMD5: result ?
                            result.contentMD5 : 'no-result',
                        resultContent_md5: result ?
                            result.content_md5 : 'no-result',
                        conversionUsed: partETag ? 'captured' :
                           (result && result.content_md5 ?
                            'content_md5' : 'id')
                    }, 'S3_MPU:' +
                       ' Successfully uploaded part with ETag resolution');

                    req.log.debug({
                        uploadId: uploadId,
                        partNumber: partNumber,
                        etag: finalETag,
                        size: req._size || 0,
                        partKey: partKey
                    }, 'S3_MPU: Part upload completed as independent object');

                    // Return ETag header (required by S3 clients)
                    res.setHeader('ETag', '"' + finalETag + '"');

                    // Add CORS headers for MPU response
                    // Create mock metadata to avoid undefined error
                    req.metadata = req.metadata || { headers: {} };

                    // Ensure req.bucket is available for CORS processing
                    // Use the bucket object from partReq which was loaded by
                    // getBucketIfExists
                    if (!req.bucket && partReq.bucket) {
                        req.bucket = partReq.bucket;
                        req.log.debug({
                            bucketName: req.bucket.name,
                            bucketId: req.bucket.id
                        }, 'S3_MPU: Using bucket object ' +
                           'from partReq for CORS processing');
                    }

                    // Add CORS headers from bucket CORS configuration
                    function applyCorsAndSend() {
                        common.tryBucketLevelCors(req, res, req.headers.origin,
                                                  function () {
                            req.log.debug({
                                responseHeaders: res._headers ||
                                    res.getHeaders()
                            }, 'S3_MPU: tryBucketLevelCors' +
                               'completed for UploadPart');
                            res.send(constants.HTTP_STATUS.OK);
                            next(false);
                        });
                    }

                    // Ensure bucket object is loaded for CORS processing
                    if (!req.bucket && req.s3Request && req.s3Request.bucket) {
                        var corsReq = Object.create(req);
                        corsReq.params = { bucket_name: req.s3Request.bucket };
                        // Create Bucket object first
                        // (required by getBucketIfExists)
                        corsReq.bucket = new bucketHelpers.Bucket(corsReq);
                        bucketHelpers.getBucketIfExists(corsReq, null,
                                                        function (bucketErr) {
                            if (bucketErr) {
                                req.log.warn(bucketErr,
                                    'S3_MPU: Failed to load bucket for CORS');
                            } else {
                                req.bucket = corsReq.bucket;
                                req.log.debug({
                                    bucketName: req.bucket.name,
                                    bucketId: req.bucket.id
                                }, 'S3_MPU: Successfully' +
                                   ' loaded bucket for CORS');
                            }
                            applyCorsAndSend();
                        });
                    } else {
                        applyCorsAndSend();
                    }
                }); // Close executeMiddlewareChain callback
            } // Close proceedWithPartUpload function
        }); // Close getUploadRecord callback
    };  // Close returned function
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
            uploadId: uploadId,
            functionEntry: true
        }, 'S3_MPU: ENTRY - Starting complete multipart upload function');

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
                req.log.debug(getErr, 'S3_MPU: Failed to read upload record');
                return (next(new NoSuchUploadError(uploadId)));
            }

            // Validate parts exist and are in correct order
            validatePartsForComplete(uploadRecord, partsFromXML, req,
                                     function (validationErr) {
                if (validationErr) {
                    req.log.debug(validationErr,
                                  'S3_MPU: Part validation failed');
                    req.log.debug({
                        errorName: validationErr.name,
                        errorRestCode: validationErr.restCode,
                        isMultiError: validationErr.name === 'MultiError',
                        nextWillBeCalled: true
                    }, 'S3_MPU_DEBUG:' +
                       ' About to call next() with validation error');
                    // No lock acquired yet, just return validation error
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

                req.log.debug({
                    uploadId: uploadId,
                    lockKey: completionLockInfo.lockKey,
                    instanceId: completionLockInfo.instanceId
                }, 'S3_MPU: Successfully acquired distributed lock');

                function proceedWithCompletion() {

                req.log.debug({
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

                req.log.debug({
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

                req.log.debug({
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
                req.log.debug({
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
                    actualSizeMB: Math.round(actualTotalSize /
                        constants.FILE_SIZES.MB)
                }, 'S3_MPU: Calculated actual total size from parts');

                req.log.debug({
                    uploadId: uploadId,
                    step: 'after-size-calculation',
                    actualTotalSize: actualTotalSize,
                    finalObjectId: finalObjectId
                }, 'S3_MPU: CHECKPOINT 5 - Starting multipart assembly commit');

                req.log.debug({
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

                req.log.debug({
                    uploadId: uploadId,
                    step: 'commit-body-created',
                    commitBody: commitBody
                }, 'S3_MPU: CHECKPOINT 5.2 - commitBody created successfully');

                req.log.debug({
                    uploadId: uploadId,
                    step: 'before-assembly-call',
                    commitBodyParts: partETags.length,
                    commitBodySize: commitBody.nbytes
                }, 'S3_MPU: CHECKPOINT 6' +
                             ' - About to call assembleMultipartUpload');

               // Generate successful response XML immediately
                var xml = generateCompleteMultipartUploadXML(
                    bucketName, objectKey, '"' + finalObjectId + '"');

                req.log.debug({
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
                            internalError.statusCode =
                                constants.HTTP_STATUS.INTERNAL_SERVER_ERROR;
                            internalError.restCode = 'InternalError';
                            errorToReturn = internalError;
                        }

                        return safeCleanupAndExit(
                            errorToReturn,
                            completionLockInfo,
                            next);
                    }

                    req.log.debug({
                        finalObjectId: finalObjectId,
                        md5: assembleResult.md5,
                        assembledSize: assembleResult.nbytes,
                        uploadId: uploadId,
                        synchronousAssembly: true
                    }, 'S3_MPU: Assembly completed successfully' +
                       ' - returning success to client');

                    // Return success response to client with actual results
                    res.setHeader('Content-Type',
                                  constants.CONTENT_TYPES.XML);

                    // Add CORS headers for complete multipart upload
                    // Ensure req.metadata exists for CORS processing
                    if (!req.metadata) {
                        req.metadata = { headers: {} };
                    }

                    // Add CORS headers from bucket CORS configuration
                    function applyCorsAndSend() {
                        common.tryBucketLevelCors(req, res, req.headers.origin,
                                                  function () {
                            req.log.debug({
                                responseHeaders: res._headers ||
                                    res.getHeaders()
                            }, 'S3_MPU: tryBucketLevelCors' +
                               ' completed for CompleteMultipartUpload');
                            res.send(constants.HTTP_STATUS.OK, xml);
                            next(false);
                        });
                    }

                    // Ensure bucket object is loaded for CORS processing
                    if (!req.bucket && req.s3Request && req.s3Request.bucket) {
                        req.log.debug('S3_MPU: Loading bucket' +
                                      ' for CORS processing');
                        var corsReq = Object.create(req);
                        corsReq.params = { bucket_name: req.s3Request.bucket };
                        // Create Bucket object first
                        corsReq.bucket = new bucketHelpers.Bucket(corsReq);
                        bucketHelpers.getBucketIfExists(corsReq, null,
                                                        function (bucketErr) {
                            if (bucketErr) {
                                req.log.warn(bucketErr,
                                   'S3_MPU: Failed to load bucket for CORS');
                            } else {
                                req.bucket = corsReq.bucket;
                                req.log.debug({
                                    bucketName: req.bucket.name,
                                    bucketId: req.bucket.id
                                }, 'S3_MPU: Successfully' +
                                   ' loaded bucket for CORS');
                            }
                            applyCorsAndSend();
                        });
                    } else {
                        applyCorsAndSend();
                    }

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


/*
 * Distributed Locking Implementation for Multipart Uploads using buckets-mdapi
 * for coordination
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
                                self.req.log.debug({
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
                        self.req.log.debug({
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
                        self.req.log.debug({
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

                    self.req.log.debug({
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
           '  <Bucket>' + s3Compat.escapeXml(bucket) + '</Bucket>\n' +
           '  <Key>' + s3Compat.escapeXml(key) + '</Key>\n' +
           '  <UploadId>' + s3Compat.escapeXml(uploadId) + '</UploadId>\n' +
           '</InitiateMultipartUploadResult>';
}

function generateCompleteMultipartUploadXML(bucket, key, etag) {
    return '<?xml version="1.0" encoding="UTF-8"?>\n' +
           '<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n' +
           '  <Location>http://s3.amazonaws.com/' + s3Compat.escapeXml(bucket) + '/' + s3Compat.escapeXml(key) + '</Location>\n' +
           '  <Bucket>' + s3Compat.escapeXml(bucket) + '</Bucket>\n' +
           '  <Key>' + s3Compat.escapeXml(key) + '</Key>\n' +
           '  <ETag>' + s3Compat.escapeXml(etag) + '</ETag>\n' +
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

                        req.log.debug({
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
                    totalSizeMB: Math.round(totalSize /
                        constants.FILE_SIZES.MB)
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
                    resultKeys: result ? Object.keys(result) : [],
                    rawValueContent: result && result.value ? result.value :
                        'NO-VALUE',
                    getError: getErr ? getErr.message : 'no-error'
                }, 'S3_MPU: Raw buckets-mdapi result debug');

                if (getErr) {
                    return (callback(getErr));
                }

                try {
                    req.log.debug({
                        uploadId: uploadId,
                        rawValue: result.value,
                        valueLength: result.value ? result.value.length : 0,
                        hasHeaders: !!(result.headers),
                        headerUploadRecord: result.headers ?
                            result.headers['x-upload-record'] : 'no-header'
                    }, 'S3_MPU: Raw JSON before parsing');

                    // Try content first, then reconstruct from headers
                    var uploadRecord;
                    var dataSource = 'empty';

                    if (result.headers && result.headers['x-upload-record']) {
                            uploadRecord = JSON.parse(result.
                                               headers['x-upload-record']);
                            dataSource = 'header-json';
                    } else if (result.headers &&
                               result.headers['x-durability-level']) {
                        // Reconstruct from individual headers
                                   uploadRecord = {
                                       durabilityLevel: parseInt(
                                           result.headers['x-durability-level'],
                                           10),
                                       uploadId: result.headers['x-upload-id'],
                                       preAllocatedSharks: result.headers[
                                           'x-preallocated-sharks'] ?
                                           JSON.parse(result.headers[
                                               'x-preallocated-sharks']) : []
                                   };
                                   dataSource = 'header-fields';
                    } else {
                        uploadRecord = {};
                        dataSource = 'empty';
                    }

                    req.log.debug({
                        uploadId: uploadId,
                        parsedRecord: uploadRecord,
                        parsedKeys: Object.keys(uploadRecord),
                        hasPreAllocatedSharks:
                            !!uploadRecord.preAllocatedSharks,
                        dataSource: dataSource
                    }, 'S3_MPU: Parsed upload record debug');

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

function validatePartsForComplete(uploadRecord, partsFromXML, req, callback) {
    var owner = req.owner.account.uuid;
    var uploadId = uploadRecord.uploadId;

    req.log.debug({
        uploadId: uploadId,
        inputPartsCount: partsFromXML.length
    }, 'S3_MPU: Validating parts using actual part objects');

    // Step 1: Validate parts are in ascending order
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
            var gapError = new
            InvalidPartError('Missing or out of order part: expected ' +
                expectedPartNumber + ', got ' + partsFromXML[j].partNumber);
            return (callback(gapError));
        }
        expectedPartNumber++;
    }

    // Create requests for all ACTUAL part objects (not metadata records)
    var partValidations = partsFromXML.map(function (part) {
        return {
            partNumber: part.partNumber,
            expectedETag: part.etag,
            partKey: '.mpu-parts/' + uploadId + '/' + part.partNumber
        };
    });

    // Validate all parts in parallel
    vasync.forEachParallel({
        func: function validatePart(validation, next) {
            var partReq = Object.create(req);
            partReq.params = {
                bucket_name: req.s3Request.bucket,
                object_name: validation.partKey
            };

            bucketHelpers.loadRequest(partReq, null, function (loadErr) {
                if (loadErr) {
                    return (next(loadErr));
                }

                bucketHelpers.
                    getBucketIfExists(partReq, null, function (bucketErr) {
                    if (bucketErr) {
                        return (next(bucketErr));
                    }

                    var metadataLocation = req.metadataPlacement.
                        getObjectLocation(owner, partReq.bucket.id,
                           crypto.createHash('md5')
                           .update(validation.partKey)
                           .digest('hex'));

                    var client = req.metadataPlacement.
                        getBucketsMdapiClient(metadataLocation);

                    client.getObject(owner, partReq.bucket.id,
                                     validation.partKey, metadataLocation.vnode,
                                     {}, req.getId(),
                        function (getErr, partRecord) {
                            if (getErr) {
                                if (getErr.name === 'ObjectNotFoundError' ||
                                    getErr.statusCode === 404) {
                                    var notFoundError = new InvalidPartError(
                                        'Part number ' + validation.partNumber +
                                        ' was not uploaded');
                                    return (next(notFoundError));
                                }
                                return (next(getErr));
                            }

                            req.log.debug({
                                partKey: validation.partKey,
                                partRecordKeys: Object.keys(partRecord),
                                partRecordId: partRecord.id,
                                partRecordContentMd5: partRecord.content_md5,
                                partRecordContentLength:
                                partRecord.content_length
                            }, 'S3_MPU: Processing actual part object');

                            // For actual part objects,
                            // try both MD5 and UUID ETags
                            // Why? S3 Clients like awscli use MD5 hex hash
                            // S3cmd expect UUID
                            var md5ETag = null;
                            var uuidETag = partRecord.id;

                            if (partRecord.content_md5) {
                                try {
                                    md5ETag = Buffer.
                                        from(partRecord.content_md5, 'base64').
                                        toString('hex');
                                } catch (convErr) {
                                    req.log.warn(convErr,
                                       'S3_MPU: Failed to convert' +
                                       ' content_md5 to hex');
                                }
                            }

                            req.log.debug({
                                partNumber: validation.partNumber,
                                expectedETag: validation.expectedETag,
                                md5ETag: md5ETag,
                                uuidETag: uuidETag,
                                hasContentMd5: !!partRecord.content_md5
                            }, 'S3_MPU:' +
                               ' ETag comparison against actual part object');

                            // Validate ETag matches either MD5 or UUID
                            var etagMatches = false;
                            var usedETag = null;

                            if (md5ETag &&
                                validation.expectedETag === md5ETag) {
                                etagMatches = true;
                                usedETag = md5ETag;
                            } else if (validation.expectedETag === uuidETag) {
                                etagMatches = true;
                                usedETag = uuidETag;
                                req.log.debug({
                                    partNumber: validation.partNumber,
                                    clientSentUUID: true,
                                    expectedETag: validation.expectedETag
                                }, 'S3_MPU:' +
                                   ' Client sent UUID ETag');
                            }

                            if (!etagMatches) {
                                var etagError = new InvalidPartError(
                                    'Part number ' + validation.partNumber +
                                    ' has invalid ETag. Expected: ' +
                                    validation.expectedETag + ', Got: ' +
                                        (md5ETag || uuidETag));
                                return (next(etagError));
                            }

                            // Validate minimum part size (except last part)
                            // per AWS specs
                            var minPartSize =
                                constants.SIZE_LIMITS.MIN_PART_SIZE;
                            var isLastPart = (validation.partNumber ===
                                              partsFromXML.length);
                            if (!isLastPart &&
                                partRecord.content_length < minPartSize) {
                                var sizeError = new
                                EntityTooSmallError('Part ' +
                                    validation.partNumber +
                                    ' is too small (' +
                                    partRecord.content_length +
                                    ' bytes, minimum ' + minPartSize + ')');
                                return (next(sizeError));
                            }

                            req.log.debug({
                                partNumber: validation.partNumber,
                                etag: usedETag,
                                size: partRecord.content_length,
                                usedMd5: usedETag === md5ETag
                            }, 'S3_MPU: Part validation successful' +
                               ' against actual part object');

                            next(null, {
                                partNumber: validation.partNumber,
                                etag: usedETag,
                                size: partRecord.content_length,
                                uploaded: partRecord.created
                            });
                        });
                });
            });
        },
        inputs: partValidations
    }, function (validationErr, results) {
        if (validationErr) {
            req.log.debug(validationErr,
                'S3_MPU: Part validation failed');
            return (callback(validationErr));
        }

        var validatedParts = results.successes || [];

        req.log.debug({
            uploadId: uploadId,
            validatedPartsCount: validatedParts.length,
            totalSize: validatedParts.reduce(function (sum, p) {
                return (sum + (p.size || 0));
            }, 0)
        }, 'S3_MPU: All parts validated successfully' +
           ' against actual part objects');

        callback(null, validatedParts);
    });
}

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
        }, 'S3_MPU: Part paths discovered, proceeding directly to v2 commit');

        // Step 3: Try Mako v2 commit
        var v2Multipart = require('./s3-mako-v2-commit');
        v2Multipart.tryMakoV2Commit(req, uploadRecord, partPaths,
                                    finalCommitBody, callback);
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
        uploadId: uploadRecord.uploadId,
        finalObjectId: objectId,
        objectName: objectName,
        objectNameHash: objectNameHash,
        totalBytes: assemblyData.totalBytes,
        md5: assemblyData.md5,
        sharksCount: preAllocatedSharks ? preAllocatedSharks.length : 0
    }, 'S3_MPU: Creating final object metadata after successful assembly');

    // Create metadata request similar to regular object creation
    var metadataReq = Object.create(req);
    metadataReq.params = {
        bucket_name: uploadRecord.bucket,
        object_name: objectName
    };

    bucketHelpers.loadRequest(metadataReq, null, function (loadErr) {
        if (loadErr) {
            req.log.error(loadErr,
                'S3_MPU: Failed to load request for final object metadata');
            return (callback(loadErr));
        }

        bucketHelpers.getBucketIfExists(metadataReq, null,
                                        function (bucketErr) {
            if (bucketErr) {
                req.log.error(bucketErr,
                    'S3_MPU: Failed to load bucket for final object metadata');
                return (callback(bucketErr));
            }

            /*
             * Get metadata placement and client using the same pattern as
             * other functions
             */
            var metadataLocation = req.metadataPlacement.getObjectLocation(
                owner, metadataReq.bucket.id, crypto.createHash('md5')
                                                  .update(objectName)
                                                  .digest('hex'));
            var client = req.metadataPlacement.
                getBucketsMdapiClient(metadataLocation);

            // Build headers for the final object
            var headers = {
                'content-type': 'application/octet-stream',
                'content-md5': assemblyData.md5
            };

            // Add any custom headers from the original initiate request if
            // available
            if (req.headers) {
                Object.keys(req.headers).forEach(function (key) {
                    if (key.toLowerCase().indexOf(
                        constants.S3_HEADERS.META_PREFIX) === 0) {
                        headers[key] = req.headers[key];
                }});
            }

            // Format pre-allocated sharks as array of objects (sequence) for
            // RPC protocol. This ensures metadata points to the same sharks
            // where data was actually stored
            var sharkData = preAllocatedSharks.map(function (shark) {
                return {
                    datacenter: shark.datacenter || 'unknown',
                    manta_storage_id: shark.manta_storage_id
                };
            });

            client.createObject(
            owner,
            bucketId,
            objectName,
            objectId,
            parseInt(assemblyData.totalBytes, 10),
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

                req.log.debug({
                    objectId: objectId,
                    objectName: objectName,
                    bucketId: bucketId,
                    vnode: metadataLocation.vnode,
                    objectResultCreated: objectResult.created,
                    objectResultModified: objectResult.modified
                }, 'S3_MPU: LISTING DEBUG' +
                ' Object created with metadata, should be visible in listings');
                callback(null, objectResult);
            });
        });
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

                        var partSize = partMeta.content_length || 0;

                        var partPath = {
                            partNumber: partNumber,
                            partETag: partETag,
                            objectId: partMeta.id,
                            size: partSize,
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

    cleanupUploadRecordAndDurability();

    function cleanupUploadRecordAndDurability() {
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
                return (callback(null));
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
                                    req.log.warn(durDelErr,
                                       'S3_MPU: Failed' +
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
    } // End cleanupUploadRecordAndDurability
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

                // Ensure req.metadata exists for CORS processing
                if (!req.metadata) {
                    req.metadata = { headers: {} };
                }

                res.header('Content-Type', constants.CONTENT_TYPES.XML);

                // Add CORS headers from bucket CORS configuration
                function applyCorsAndSend() {
                    common.tryBucketLevelCors(req, res, req.headers.origin,
                                              function () {
                        req.log.debug({
                            responseHeaders: res._headers || res.getHeaders()
                        },
                        'S3_MPU: tryBucketLevelCors completed for ListParts');
                        res.send(xml);
                        next(false); // Stop processing
                    });
                }

                // Ensure bucket object is loaded for CORS processing
                if (!req.bucket && req.s3Request && req.s3Request.bucket) {
                    req.log.debug('S3_MPU: Loading bucket for CORS processing');
                    var corsReq = Object.create(req);
                    corsReq.params = { bucket_name: req.s3Request.bucket };
                    // Create Bucket object first
                    corsReq.bucket = new bucketHelpers.Bucket(corsReq);
                    bucketHelpers.getBucketIfExists(corsReq, null,
                                                    function (bucketErr) {
                        if (bucketErr) {
                            req.log.warn(bucketErr,
                                'S3_MPU: Failed to load bucket for CORS');
                        } else {
                            req.bucket = corsReq.bucket;
                            req.log.debug({
                                bucketName: req.bucket.name,
                                bucketId: req.bucket.id
                            }, 'S3_MPU: Successfully loaded bucket for CORS');
                        }
                        applyCorsAndSend();
                    });
                } else {
                    applyCorsAndSend();
                }
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
    var pageLimit = constants.SIZE_LIMITS.MAX_PAGE_LIMIT;

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

            // IMPORTANT: For s3cmd resume to work correctly,
            // we need to prioritize MD5 format over UUID format in
            // list-parts responses. s3cmd uses these ETags for resume
            // detection and expects consistent MD5 format.
            var etag = entry.contentMD5 || entry.id || '';

            req.log.debug({
                partNumber: partNumber,
                objectId: entry.id,
                contentMD5: entry.contentMD5,
                selectedETag: etag,
                etagFormat: entry.contentMD5 ? 'content-md5' : 'uuid'
            }, 'S3_MPU: Selected ETag format for s3cmd resume compatibility');

            // Legacy fallback: If we somehow don't have an ID but have
            // contentMD5, convert base64 MD5 to hex format (for older parts)
            if (!entry.id && entry.contentMD5) {
                try {
                    // contentMD5 is base64, convert to hex for S3 compatibility
                    var hexMD5 = Buffer.from(entry.contentMD5,
                                             'base64').toString('hex');
                    etag = hexMD5;
                    req.log.debug({
                        partNumber: partNumber,
                        base64MD5: entry.contentMD5,
                        hexMD5: hexMD5
                    }, 'S3_MPU: Legacy fallback' +
                       ' - converted base64 MD5 to hex for ETag');
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
    xml += '  <Bucket>' + s3Compat.escapeXml(bucketName) + '</Bucket>\n';
    xml += '  <Key>' + s3Compat.escapeXml(objectKey) + '</Key>\n';
    xml += '  <UploadId>' + s3Compat.escapeXml(uploadRecord.uploadId) + '</UploadId>\n';
    xml += '  <Initiator>\n';
    xml += '    <ID>' + s3Compat.escapeXml(uploadRecord.account || 'unknown') + '</ID>\n';
    xml += '    <DisplayName>' + s3Compat.escapeXml(uploadRecord.account || 'unknown') + '</DisplayName>\n';
    xml += '  </Initiator>\n';
    xml += '  <Owner>\n';
    xml += '    <ID>' + s3Compat.escapeXml(uploadRecord.account || 'unknown') + '</ID>\n';
    xml += '    <DisplayName>' + s3Compat.escapeXml(uploadRecord.account || 'unknown') + '</DisplayName>\n';
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
        xml += '    <ETag>' + s3Compat.escapeXml(etag) + '</ETag>\n';
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
            res.header(constants.S3_HEADERS.UPLOAD_ID, uploadId);
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

///--- Exports

module.exports = {
    s3InitiateMultipartUploadHandler: s3InitiateMultipartUploadHandler,
    s3UploadPartHandler: s3UploadPartHandler,
    s3CompleteMultipartUploadHandler: s3CompleteMultipartUploadHandler,
    s3AbortMultipartUploadHandler: s3AbortMultipartUploadHandler,
    createFinalObjectMetadata: createFinalObjectMetadata,
    listPartsHandler: listPartsHandler,
    resumeUploadHandler: resumeUploadHandler
};
