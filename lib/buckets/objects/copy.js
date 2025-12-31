/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var auth = require('../../auth');
var buckets = require('../buckets');
var bunyan = require('bunyan');
var anonymousAuth = require('../../anonymous-auth');
var constants = require('../../constants');
var crypto = require('crypto');
var sharkClient = require('../../shark_client');
var uuidv4 = require('uuid/v4');
var vasync = require('vasync');


/*
 * Server side copy means the client specifies a source object
 * in a bucket and that object is replicated (copied ) to the destination
 * bucket, the intention is to reduce uploads as the data is already there.
 * This is triggered by a specify HTTP header named x-amz-copy-source which
 * means this PUT request just wants to copy the existing data and
 * Objects copied using this functionality are NOT DELETED FROM THE SOURCE
 * PATH.
 * If the value of x-amz-copy-source is REPLACE we need to replace
 * the metadata on the destination object using the metadata headers from this
 * request.
 *
 * From the developer's perspective this file has all the operations that
 * are the bread and butter for object storage:
 *
 * - Create/Copy metadata for/from object.
 * - Stream object data to disk (sharks/mako)
 *
 * These are the transcendental operations which are the building blocks for
 * every other operation.
 *
 * - https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html
 *
 */

/**
 * Server-side copy implementation for S3 copy operations
 * This function handles copying objects within Manta storage
 * without requiring client-side download/upload.
 */
function copyObject(req, res, next) {
    var log = req.log;
    var copySource = req.headers['x-amz-copy-source'];

    if (!copySource) {
        var missingHeaderError = new Error('Missing x-amz-copy-source header');
        missingHeaderError.statusCode = 400;
        missingHeaderError.restCode = 'InvalidRequest';
        next(missingHeaderError);
        return;
    }

    log.debug({
        copySource: copySource,
        destBucket: req.params.bucket_name,
        destObject: req.params.object_name,
        requestPath: req.path(),
        requestUrl: req.url
    }, 'copyObject: starting server-side copy');

    // Parse copy source: /source-bucket/source-object
    // Note: object name can contain slashes, so only split on first slash
    var decodedCopySource = decodeURIComponent(copySource);
    var sourcePathWithoutLeadingSlash = decodedCopySource.replace(/^\//, '');
    var firstSlashIndex = sourcePathWithoutLeadingSlash.indexOf('/');

    log.debug({
        originalCopySource: copySource,
        decodedCopySource: decodedCopySource,
        sourcePathWithoutLeadingSlash: sourcePathWithoutLeadingSlash,
        firstSlashIndex: firstSlashIndex
    }, 'copyObject: copy source parsing details');

    if (firstSlashIndex === -1 || firstSlashIndex === 0) {
        var parseError = new Error('Invalid copy source format: ' + copySource);
        parseError.statusCode = 400;
        parseError.restCode = 'InvalidRequest';
        next(parseError);
        return;
    }

    var sourceBucketName = sourcePathWithoutLeadingSlash.
        substring(0, firstSlashIndex);
    var sourceObjectName = sourcePathWithoutLeadingSlash.
        substring(firstSlashIndex + 1);

    log.debug({
        sourceBucket: sourceBucketName,
        sourceObject: sourceObjectName,
        destBucket: req.params.bucket_name,
        destObject: req.params.object_name
    }, 'copyObject: parsed source and destination');

    // Step 1: Get source bucket information
    var sourceReq = {
        params: {
            account: req.params.account,
            bucket_name: sourceBucketName,
            object_name: sourceObjectName
        },
        caller: req.caller,
        owner: req.owner, // Copy owner from original request
        log: req.log,
        metadataPlacement: req.metadataPlacement,
        getId: function () { return req.getId(); },
        method: 'GET', // For source object access
        authContext: {
            conditions: {}
        },
        headers: req.headers || {}
    };

    // Load source bucket and object metadata
    buckets.loadRequest(sourceReq, null,
        function onSourceRequestLoaded(loadErr) {
        if (loadErr) {
            log.debug(loadErr, 'copyObject: failed to load source object');
            // Convert to S3-compatible error
            var sourceError = new Error('Source object not found');
            sourceError.statusCode = 404;
            sourceError.restCode = 'NoSuchKey';
            next(sourceError);
            return;
        }

        buckets.getBucketIfExists(sourceReq, null,
                                   function onSourceBucketLoaded(bucketErr) {
            if (bucketErr) {
                log.debug(bucketErr, 'copyObject: source bucket not found');
                var bucketError = new Error('Source bucket not found');
                bucketError.statusCode = 404;
                bucketError.restCode = 'NoSuchBucket';
                next(bucketError);
                return;
            }

            // Step 2: Get source object metadata
            getSourceObjectMetadata(sourceReq,
                function onSourceMetadataLoaded(metadataErr, sourceMetadata) {
                if (metadataErr) {
                    log.debug(metadataErr,
                              'copyObject: failed to get source metadata');
                    next(metadataErr);
                    return;
                }

                log.debug({
                    sourceMetadata: {
                        contentLength: sourceMetadata.content_length,
                        contentType: sourceMetadata.content_type,
                        contentMD5: sourceMetadata.content_md5,
                        sharks: sourceMetadata.sharks ?
                            sourceMetadata.sharks.length : 0
                    }
                }, 'copyObject: retrieved source metadata');


                // Capping server side copying to 5GiB per AWS docs
                var MinSize = 5368709120;
                if (sourceMetadata.content_length > MinSize) {
                    var sizeError = new Error('The specified copy source is' +
                        ' larger than the maximum allowable size for a copy' +
                        ' source: 5368709120');
                    sizeError.statusCode = 400;
                    sizeError.restCode = 'InvalidRequest';
                    log.debug(sourceMetadata, 'S3 SSC exceed limits');
                    next(sizeError);
                    return;
                }
                // Step 3: Perform the actual copy
                performServerSideCopy(req, res, sourceReq, sourceMetadata,
                                      function onCopyComplete(copyErr, result) {
                    if (copyErr) {
                        log.debug(copyErr, 'copyObject: copy operation failed');
                        next(copyErr);
                        return;
                    }

                    log.debug({
                        result: result
                    }, 'copyObject: copy completed successfully');

                    // Step 4: Send S3-compatible copy response
                    sendCopyResponse(res, result);
                    next();
                });
            });
        });
    });
}

/**
 * Get metadata for the source object
 */
function getSourceObjectMetadata(sourceReq, callback) {
    var log = sourceReq.log;

    // Use the actual source object name from the parsed copy source
    var sourceObjectName = sourceReq.params.object_name;
    var sourceObjectNameHash = crypto.createHash('md5')
                                     .update(sourceObjectName)
                                     .digest('hex');

    var metadataLocation = sourceReq.metadataPlacement.getObjectLocation(
        sourceReq.caller.account.uuid,
        sourceReq.bucket.id,
        sourceObjectNameHash);

    var client =
        sourceReq.metadataPlacement.getBucketsMdapiClient(metadataLocation);
    var conditions = {}; // No conditional headers for copy operations

    log.debug({
        owner: sourceReq.caller.account.uuid,
        bucketId: sourceReq.bucket.id,
        objectName: sourceObjectName,
        objectNameHash: sourceObjectNameHash,
        vnode: metadataLocation.vnode
    }, 'getSourceObjectMetadata: requesting object metadata');

    client.getObject(
        sourceReq.caller.account.uuid,
        sourceReq.bucket.id,
        sourceObjectName,
        metadataLocation.vnode,
        conditions,
        sourceReq.getId(),
        function onObjectMetadataRetrieved(err, obj) {
            if (err) {
                log.debug(err, 'getSourceObjectMetadata: failed to get object');
                var notFoundError = new Error('Source object not found');
                notFoundError.statusCode = 404;
                notFoundError.restCode = 'NoSuchKey';
                callback(notFoundError);
                return;
            }

            log.debug({
                objectId: obj.id,
                contentLength: obj.content_length,
                sharks: obj.sharks ? obj.sharks.length : 0
            }, 'getSourceObjectMetadata: retrieved object metadata');

            callback(null, obj);
        });
}

/**
 * Perform the actual server-side copy operation
 * Allocates destination sharks and streams data directly
 */
function performServerSideCopy(req, res, sourceReq, sourceMetadata, callback) {
    var log = req.log;
    var owner = req.owner.account.uuid;
    var bucket = req.bucket;
    var bucketObject = req.bucketObject;

    // Generate new object ID for the copy
    var objectId = uuidv4();

    log.debug({
        sourceObjectId: sourceMetadata.id,
        newObjectId: objectId,
        sourceSize: sourceMetadata.content_length,
        sourceSharks: sourceMetadata.sharks ? sourceMetadata.sharks.length : 0,
        sourceBucket: sourceReq.bucket.name,
        sourceObject: sourceReq.params.object_name,
        destBucket: bucket.name,
        destObject: bucketObject.name,
        copyStartTime: Date.now()
    }, 'performServerSideCopy: starting server-side copy');

    var copyStartTime = Date.now();

    // Step 1: Choose destination sharks for the copy
    var copies = sourceMetadata.sharks ? sourceMetadata.sharks.length :
        constants.COPY_LIMITS.DEFAULT_COPIES;
    var size = Math.ceil(sourceMetadata.content_length /
        constants.FILE_SIZES.MB);

    log.debug({
        requestedCopies: copies,
        sizeInMB: size,
        owner: owner,
        bucketId: bucket.id
    }, 'performServerSideCopy: allocating destination sharks');

    req.storinfo.choose({
        requestType: 'put',
        replicas: copies,
        size: size,
        log: log
    }, function onDestinationSharksChosen(chooseErr, sharks) {
        if (chooseErr) {
            log.error(chooseErr,
               'performServerSideCopy: failed to choose destination sharks');
            callback(chooseErr);
            return;
        }

        var flatSharks = [];
        sharks.forEach(function (shark) {
            if (Array.isArray(shark)) {
                flatSharks = flatSharks.concat(shark);
            } else {
                flatSharks.push(shark);
            }
        });
        sharks = flatSharks;

        if (!sharks || sharks.length === 0) {
            var noSharksError = new Error('No destination sharks allocated');
            noSharksError.statusCode = 507;
            noSharksError.restCode = 'InternalError';
            callback(noSharksError);
            return;
        }

        var sharkAllocationTime = Date.now();
        log.debug({
            destinationSharks: sharks.length,
            sharkIds: sharks.map(function (s) { return s.manta_storage_id; }),
            sharkAllocationDuration: sharkAllocationTime - copyStartTime
        }, 'performServerSideCopy: destination sharks allocated');

        // Step 2: Stream data from source to destination sharks
        // Write to ALL allocated sharks to match metadata
        var streamStartTime = Date.now();
        streamSourceToDestination(req, sourceReq, sourceMetadata, sharks,
            objectId, function onStreamComplete(streamErr, streamResult) {
            if (streamErr) {
                log.error(streamErr, 'performServerSideCopy: streaming failed');
                callback(streamErr);
                return;
            }

            var streamEndTime = Date.now();
            log.debug({
                streamedBytes: streamResult.totalBytes,
                md5: streamResult.md5,
                streamDuration: streamEndTime - streamStartTime,
                totalCopyDuration: streamEndTime - copyStartTime
            }, 'performServerSideCopy: streaming completed, creating metadata');

            // Step 3: Create destination object metadata
            var metadataStartTime = Date.now();
            log.debug({
                metadataStartTime: metadataStartTime,
                streamToMetadataGap: metadataStartTime - streamEndTime
            }, 'performServerSideCopy: starting metadata creation');

            // Pass all allocated sharks to metadata, even though we only wrote
            // to the first one
            createDestinationMetadata(req, sourceMetadata, sharks, objectId,
                streamResult, function onMetadataCreated(metadataErr, result) {
                var metadataEndTime = Date.now();
                if (metadataErr) {
                    log.error({
                        error: metadataErr,
                        metadataDuration: metadataEndTime - metadataStartTime
                    }, 'performServerSideCopy: metadata creation failed');
                    callback(metadataErr);
                    return;
                }

                log.debug({
                    metadataDuration: metadataEndTime - metadataStartTime,
                    totalCopyDuration: metadataEndTime - copyStartTime,
                    result: result
                }, 'performServerSideCopy: operation completed successfully');

                callback(null, result);
            });
        });
    });
}

/**
 * Stream data from source sharks to destination sharks
 */
function streamSourceToDestination(req, sourceReq, sourceMetadata,
                                   destinationSharks, objectId, callback) {
    var log = req.log;
    var owner = req.owner.account.uuid;
    var bucket = req.bucket;
    var bucketObject = req.bucketObject;

    // Use different source shark for each copy to avoid contention
    // Rotate through available source sharks based on current time
    var sourceSharkIndex = Date.now() % sourceMetadata.sharks.length;
    var sourceShark = sourceMetadata.sharks[sourceSharkIndex];

    log.debug({
        availableSourceSharks: sourceMetadata.sharks.length,
        selectedSourceSharkIndex: sourceSharkIndex,
        selectedSourceShark: sourceShark.manta_storage_id,
        allSourceSharks: sourceMetadata.sharks.map(function (s) {
            return (s.manta_storage_id); }),
        sourceShark: sourceShark.manta_storage_id,
        objectId: sourceMetadata.id,
        contentLength: sourceMetadata.content_length

    }, 'streamSourceToDestination: selected source shark to avoid contention');

    // Create source stream from shark
    var sourceClient = sharkClient.getClient({
        connectTimeout: req.sharkConfig.connectTimeout,
        log: log,
        shark: sourceShark,
        agent: req.sharkAgent
    });

    var sourceOpts = {
        objectId: sourceMetadata.id,
        owner: owner,
        requestId: req.getId(),
        path: sharkClient.storagePath({
            storageLayoutVersion: 2,
            owner: owner,
            bucketId: sourceReq.bucket.id,  // Use source bucket id
            objectNameHash: crypto.createHash('md5')
                                  .update(sourceReq.params.object_name)
                                  .digest('hex'),
            objectId: sourceMetadata.id
        })
    };

    sourceClient.get(sourceOpts,
                      function onSourceStreamCreated(getErr, sourceClientReq,
                                                     sourceRes) {
        if (getErr || !sourceRes || sourceRes.statusCode !== 200) {
            log.error({
                error: getErr,
                statusCode: sourceRes ? sourceRes.statusCode : 'no-response'
            }, 'streamSourceToDestination: failed to create source stream');

            var sourceError = new Error('Unable to read source object data');
            sourceError.statusCode = 404;
            sourceError.restCode = 'NoSuchKey';
            callback(sourceError);
            return;
        }

        log.debug('streamSourceToDestination:'  +
                  ' source stream created successfully');

        // Setup destination shark streams
        log.debug({
            bucketId: bucket.id,
            bucketName: bucket.name,
            objectName: bucketObject.name,
            objectNameHash: bucketObject.name_hash,
            owner: owner
        }, 'streamSourceToDestination: destination shark options debug');

        var destSharkOpts = {
            contentType: sourceMetadata.content_type ||
                'application/octet-stream',
            contentLength: sourceMetadata.content_length,
            contentMd5: sourceMetadata.content_md5,
            owner: owner,
            bucketId: bucket.id,
            objectId: objectId,
            objectName: bucketObject.name,
            objectNameHash: bucketObject.name_hash,
            requestId: req.getId(),
            storageLayoutVersion: 2,
            agent: req.sharkAgent,
            log: log,
            sharkConfig: req.sharkConfig
        };

        // Stream to destination sharks in parallel
        var sourceSharkInfo = {
            shark: sourceShark,
            opts: sourceOpts
        };
        streamToDestinationSharks(sourceSharkInfo, destinationSharks,
                                  destSharkOpts, callback);
    });
}

/**
 * Stream source data to multiple destination sharks in parallel.
 * Creates separate source streams for each destination
 */
function streamToDestinationSharks(sourceSharkInfo, destinationSharks,
                                   opts, callback) {
    var log = opts.log || bunyan.createLogger({name: 'copy'});

    var md5Hash = crypto.createHash('md5');
    var totalBytes = 0;
    var completedSharks = [];

    log.debug({
        destinationCount: destinationSharks.length,
        contentLength: opts.contentLength,
        sourceShark: sourceSharkInfo.shark.manta_storage_id
    }, 'streamToDestinationSharks: starting parallel streaming');

    // Create destination streams for each shark
    vasync.forEachParallel({
        func: function streamToShark(shark, next) {
            log.debug({
                destinationShark: shark.manta_storage_id,
                sourceShark: sourceSharkInfo.shark.manta_storage_id,
                contentLength: opts.contentLength,
                requestId: opts.requestId,
                copyAttemptTime: Date.now()
            }, 'streamToDestinationSharks: starting stream' +
                   ' for destination shark');

            // Create separate source stream for this destination shark
            var sourceClientStartTime = Date.now();
            var sourceClient = sharkClient.getClient({
                connectTimeout: opts.sharkConfig.connectTimeout,
                log: log,
                shark: sourceSharkInfo.shark,
                agent: opts.agent
            });

            log.debug({
                destinationShark: shark.manta_storage_id,
                sourceShark: sourceSharkInfo.shark.manta_storage_id,
                sourceClientCreationTime: Date.now() - sourceClientStartTime
            }, 'streamToDestinationSharks: source client created');

            log.debug({
                destinationShark: shark.manta_storage_id,
                sourceShark: sourceSharkInfo.shark.manta_storage_id,
                sourcePath: sourceSharkInfo.opts.path,
                sourceObjectId: sourceSharkInfo.opts.objectId,
                copyAttemptNumber: Date.now()
            }, 'streamToDestinationSharks: creating source GET request');

            // Add jitter to give breathing space to metadata/shark clients
            // Sometimes there are delays when doing
            var jitter = Math.random() * 100; // 0-100ms random delay
            var maxRetries = 2;
            var retryCount = 0;

            function attemptSourceRead() {
                sourceClient.get(sourceSharkInfo.opts,
                    function onSharkSourceStreamReady(getErr, sourceClientReq,
                        sourceRes) {
                    if (getErr || !sourceRes || sourceRes.statusCode !== 200) {
                        retryCount++;
                        if (retryCount <= maxRetries) {
                            log.warn({
                                error: getErr,
                                statusCode: sourceRes ? sourceRes.statusCode :
                                    'no-response',
                                destinationShark: shark.manta_storage_id,
                                sourceShark:
                                sourceSharkInfo.shark.manta_storage_id,
                                retryCount: retryCount,
                                maxRetries: maxRetries
                            }, 'streamToDestinationSharks:' +
                               ' source stream failed, retrying');

                            // Retry with exponential backoff
                            setTimeout(attemptSourceRead, retryCount * 1000);
                            return;
                        }

                        log.error({
                            error: getErr,
                            statusCode: sourceRes ? sourceRes.statusCode :
                                'no-response',
                            destinationShark: shark.manta_storage_id,
                            sourceShark: sourceSharkInfo.shark.manta_storage_id,
                            finalRetryCount: retryCount
                        }, 'streamToDestinationSharks:' +
                           ' failed to create source stream after retries');
                        next(new Error('Unable to read source object data for' +
                                ' destination shark after ' + maxRetries +
                                ' retries'));
                        return;
                    }

                log.debug({
                    destinationShark: shark.manta_storage_id,
                    sourceShark: sourceSharkInfo.shark.manta_storage_id,
                    sourceStatusCode: sourceRes.statusCode
                }, 'streamToDestinationSharks:' +
                   ' source GET request successful,' +
                   ' creating destination client');

                // Create destination client and stream
                var destClient = sharkClient.getClient({
                    connectTimeout: opts.sharkConfig.connectTimeout,
                    log: log,
                    shark: shark,
                    agent: opts.agent
                });

                var putOpts = {
                    bucketId: opts.bucketId,
                    objectId: opts.objectId,
                    objectName: opts.objectName,
                    objectNameHash: opts.objectNameHash,
                    owner: opts.owner,
                    requestId: opts.requestId,
                    storageLayoutVersion: opts.storageLayoutVersion,
                    contentType: opts.contentType,
                    contentLength: opts.contentLength,
                    contentMd5: opts.contentMd5
                };

                var destinationPath = sharkClient.storagePath({
                    storageLayoutVersion: putOpts.storageLayoutVersion,
                    owner: putOpts.owner,
                    bucketId: putOpts.bucketId,
                    objectNameHash: putOpts.objectNameHash,
                    objectId: putOpts.objectId
                });

                log.debug({
                    destinationShark: shark.manta_storage_id,
                    putPath: destinationPath,
                    contentLength: putOpts.contentLength,
                    objectId: putOpts.objectId,
                    objectNameHash: putOpts.objectNameHash,
                    bucketId: putOpts.bucketId
                },
                'streamToDestinationSharks: creating destination PUT request');

                destClient.put(putOpts,
                    function onDestinationStreamCreated(putErr, putReq) {
                    if (putErr) {
                        log.error({
                            error: putErr,
                            shark: shark.manta_storage_id
                        }, 'streamToDestinationSharks: failed to ' +
                           'create destination stream');
                        next(putErr);
                        return;
                    }

                    log.debug({
                        destinationShark: shark.manta_storage_id,
                        sourceShark: sourceSharkInfo.shark.manta_storage_id
                    }, 'streamToDestinationSharks: destination PUT' +
                       ' request created, starting data streaming');

                    var sharkBytes = 0;
                    var sharkMd5 = crypto.createHash('md5');

                    // Track data for this shark
                    sourceRes.on('data', function (chunk) {
                        sharkBytes += chunk.length;
                        sharkMd5.update(chunk);
                    });

                    // Wait for shark response
                    putReq.on('response', function (sharkRes) {
                        log.debug({
                            shark: shark.manta_storage_id,
                            statusCode: sharkRes.statusCode,
                            sharkBytes: sharkBytes,
                            sourceShark: sourceSharkInfo.shark.manta_storage_id
                        },
                        'streamToDestinationSharks: shark response received');

                        if (sharkRes.statusCode !== 200 &&
                            sharkRes.statusCode !== 201) {
                            var sharkError =
                                new Error('Shark PUT failed with status ' +
                                          sharkRes.statusCode);
                            log.error({
                                error: sharkError,
                                shark: shark.manta_storage_id,
                                statusCode: sharkRes.statusCode,
                                sourceShark:
                                sourceSharkInfo.shark.manta_storage_id
                            }, 'streamToDestinationSharks: shark PUT failed');
                            next(sharkError);
                            return;
                        }

                        completedSharks.push(shark.manta_storage_id);
                        totalBytes = sharkBytes; // All must have same size
                        md5Hash = sharkMd5; // All should have same MD5

                        log.debug({
                            shark: shark.manta_storage_id,
                            sharkBytes: sharkBytes,
                            completedSharks: completedSharks.length,
                            expectedSharks: destinationSharks.length,
                            sourceShark: sourceSharkInfo.shark.manta_storage_id
                        }, 'streamToDestinationSharks:' +
                           ' shark stream completed successfully');
                        next();
                    });

                    putReq.on('error', function (streamErr) {
                        log.error({
                            error: streamErr,
                            shark: shark.manta_storage_id,
                            sourceShark: sourceSharkInfo.shark.manta_storage_id
                        }, 'streamToDestinationSharks:' +
                           ' destination stream error');
                        next(streamErr);
                    });

                    sourceRes.on('error', function (sourceErr) {
                        log.error({
                            error: sourceErr,
                            shark: shark.manta_storage_id,
                            sourceShark: sourceSharkInfo.shark.manta_storage_id
                        }, 'streamToDestinationSharks: source stream error');
                        // Cleanup streams on error
                        sourceRes.destroy();
                        putReq.destroy();
                        next(sourceErr);
                    });

                    // Ensure cleanup when source stream ends
                    sourceRes.on('end', function () {
                        log.debug({
                            destinationShark: shark.manta_storage_id,
                            sourceShark: sourceSharkInfo.shark.manta_storage_id
                        }, 'streamToDestinationSharks: source stream ended');
                    });

                    log.debug({
                        destinationShark: shark.manta_storage_id,
                        sourceShark: sourceSharkInfo.shark.manta_storage_id,
                        startedStreaming: true
                    }, 'streamToDestinationSharks: starting pipe' +
                       ' from source to destination');

                    // Start streaming from this source to this destination
                    sourceRes.pipe(putReq);
                });
                }); // End sourceClient.get callback
            } // End attemptSourceRead function
            setTimeout(attemptSourceRead, jitter); // Start with jitter delay
        },
        inputs: destinationSharks
    }, function (parallelErr, results) {
        log.debug({
            parallelErr: parallelErr ? parallelErr.message : null,
            resultCount: results ? results.successes.length : 0,
            completedSharks: completedSharks.length,
            expectedSharks: destinationSharks.length
        }, 'streamToDestinationSharks: vasync.forEachParallel completed');

        if (parallelErr) {
            log.error(parallelErr,
                'streamToDestinationSharks: parallel streaming failed');
            callback(parallelErr);
            return;
        }

        var finalMd5 = md5Hash.digest('hex');

        log.debug({
            totalBytes: totalBytes,
            md5: finalMd5,
            completedSharks: completedSharks.length,
            expectedSharks: destinationSharks.length
        }, 'streamToDestinationSharks: all sharks completed successfully' +
           ' - calling callback');

        callback(null, {
            totalBytes: totalBytes,
            md5: finalMd5,
            completedSharks: completedSharks
        });
    });
}

/**
 * Create destination object metadata after successful data copy
 */
function createDestinationMetadata(req, sourceMetadata, destinationSharks,
                                   objectId, streamResult, callback) {
    var log = req.log;
    var owner = req.owner.account.uuid;
    var bucket = req.bucket;
    var bucketObject = req.bucketObject;
    var requestId = req.getId();

    // Prepare headers for copy (handle metadata directive)
    var copyHeaders = {};
    if (sourceMetadata.headers) {
        Object.keys(sourceMetadata.headers).forEach(function (key) {
            copyHeaders[key] = sourceMetadata.headers[key];
        });
    }

    // Override with copy-specific headers if metadata-directive is REPLACE
    if (req.headers['x-amz-metadata-directive'] === 'REPLACE') {
        copyHeaders = {};
        Object.keys(req.headers).forEach(function (key) {
            var lowerKey = key.toLowerCase();
            // Handle both S3 format (x-amz-meta-*) and
            // Manta's internal format (m-*)
            if (lowerKey.startsWith('x-amz-meta-') ||
                lowerKey.startsWith('m-') ||
                lowerKey === 'content-type') {

                // Convert x-amz-meta-* to internal m-* format for consistency
                if (lowerKey.startsWith('x-amz-meta-')) {
                    // Remove 'x-amz-meta-'
                    var mantaKey = 'm-' + lowerKey.substring(11);
                    copyHeaders[mantaKey] = req.headers[key];
                } else {
                    copyHeaders[key] = req.headers[key];
                }
            }
        });
    }

    // First we get the metadata where the object is located in order
    // to create a MdapiClient to interact with it.
    var metadataLocation = req.metadataPlacement.getObjectLocation(
        owner, bucket.id, bucketObject.name_hash);
    var client = req.metadataPlacement.getBucketsMdapiClient(metadataLocation);

    log.debug({
        objectId: objectId,
        destinationSharks: destinationSharks.length,
        contentLength: sourceMetadata.content_length,
        contentMd5: sourceMetadata.content_md5
    }, 'createDestinationMetadata: creating object metadata');

    // Create new object metadata with copied data location
    var createObjectStartTime = Date.now();
    log.debug({
        owner: owner,
        bucketId: bucket.id,
        objectName: bucketObject.name,
        objectId: objectId,
        contentLength: sourceMetadata.content_length,
        contentMd5: sourceMetadata.content_md5,
        destinationSharks: destinationSharks.length,
        metadataLocation: metadataLocation.vnode,
        createObjectStartTime: createObjectStartTime
    }, 'createDestinationMetadata: calling client.createObject');

    // Create the new object metadata using the source object.
    client.createObject(
        owner,
        bucket.id,
        bucketObject.name,
        objectId,
        sourceMetadata.content_length,
        sourceMetadata.content_md5,
        sourceMetadata.content_type || 'application/octet-stream',
        copyHeaders,
        destinationSharks,  // New shark locations with copied data
        {},  // properties
        metadataLocation.vnode,
        {},  // conditions
        requestId,
        function (createErr, result) {
            if (createErr) {
                log.error(createErr,
                   'createDestinationMetadata: failed to create metadata');
                callback(createErr);
                return;
            }

            var createObjectEndTime = Date.now();
            log.debug({
                sourceObjectId: sourceMetadata.id,
                newObjectId: objectId,
                bucket: bucket.name,
                object: bucketObject.name,
                copiedBytes: streamResult.totalBytes,
                resultEtag: result.id,
                resultModified: result.modified,
                createObjectDuration: createObjectEndTime -
                    createObjectStartTime
            }, 'createDestinationMetadata:' +
               ' copy operation completed successfully');

            callback(null, {
                etag: result.id,
                lastModified: result.modified
            });
        });
}

/**
 * Send S3-compatible copy response
 */
function sendCopyResponse(res, result) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<CopyObjectResult>\n';
    xml += '  <LastModified>' + result.lastModified + '</LastModified>\n';
    xml += '  <ETag>"' + result.etag + '"</ETag>\n';
    xml += '</CopyObjectResult>\n';

    res.setHeader('Content-Type', 'application/xml');
    res.send(200, xml);
}

module.exports = {
    copyObjectHandler: function copyObjectHandler() {
        var chain = [
            buckets.loadRequest,
            buckets.getBucketIfExists,
            anonymousAuth.validateAnonymousAccess,
            auth.authorizationHandler(),
            copyObject
        ];
        return (chain);
    }
};
