/*
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * s3-routing.js: S3 request routing handler.
 *
 * Provides request routing logic for S3 operations including:
 * - Bucket operations (ListBuckets, CreateBucket, DeleteBucket, etc.)
 * - Object operations (GetObject, PutObject, DeleteObject, etc.)
 * - Multipart upload operations (InitiateMultipartUpload, UploadPart, etc.)
 * - CORS configuration operations
 *
 * Routes requests based on HTTP method, path structure, and
 * s3Request.operation.
 */

var common = require('../common');
var bucketHelpers = require('../buckets/buckets');


///--- Functions

/**
 * Handler for S3 ListMultipartUploads operation.
 * Currently returns an empty list as multipart uploads are
 * handled in-memory during the session.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Restify next callback
 */
function s3ListMultipartUploadsHandler(req, res, next) {
    req.log.debug({
        bucket: req.params.bucket
    }, 'S3_DEBUG: s3ListMultipartUploads - returning empty response');

    // Return empty multipart uploads list as XML
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
              '<ListMultipartUploadsResult' +
              ' xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n' +
              '  <Bucket>' + req.params.bucket + '</Bucket>\n' +
              '  <KeyMarker></KeyMarker>\n' +
              '  <UploadIdMarker></UploadIdMarker>\n' +
              '  <NextKeyMarker></NextKeyMarker>\n' +
              '  <NextUploadIdMarker></NextUploadIdMarker>\n' +
              '  <MaxUploads>1000</MaxUploads>\n' +
              '  <IsTruncated>false</IsTruncated>\n' +
              '</ListMultipartUploadsResult>';

    res.setHeader('Content-Type', 'application/xml');

    // Add CORS headers from bucket CORS configuration
    function applyCorsAndSend() {
        common.tryBucketLevelCors(req, res, req.headers.origin, function () {
            req.log.debug({
                responseHeaders: res._headers || res.getHeaders()
            }, 'S3_DEBUG: tryBucketLevelCors completed' +
               ' for ListMultipartUploads');
            res.send(200, xml);
            next(false);
        });
    }

    // Ensure bucket object is loaded for CORS processing
    if (!req.bucket && req.params && req.params.bucket) {
        req.log.debug('S3_DEBUG: Loading bucket for CORS processing');
        var corsReq = Object.create(req);
        corsReq.params = { bucket_name: req.params.bucket };
        // Create Bucket object first (required by getBucketIfExists)
        corsReq.bucket = new bucketHelpers.Bucket(corsReq);
        bucketHelpers.getBucketIfExists(corsReq, null, function (bucketErr) {
            if (bucketErr) {
                req.log.warn(bucketErr,
                             'S3_DEBUG: Failed to load bucket for CORS');
            } else {
                req.bucket = corsReq.bucket;
                req.log.debug({
                    bucketName: req.bucket.name,
                    bucketId: req.bucket.id
                }, 'S3_DEBUG: Successfully loaded bucket for CORS');
            }
            applyCorsAndSend();
        });
    } else {
        applyCorsAndSend();
    }
}


/**
 * Handle S3 requests by routing to appropriate S3 handlers based on path
 * and method. This function is called only for SigV4 authenticated requests.
 *
 * Routes based on path structure:
 * - GET /                     -> ListBuckets
 * - PUT /bucket              -> CreateBucket
 * - GET /bucket              -> ListBucketObjects (V1 or V2)
 * - DELETE /bucket           -> DeleteBucket
 * - PUT /bucket/object       -> CreateBucketObject
 * - GET /bucket/object       -> GetBucketObject
 * - DELETE /bucket/object    -> DeleteBucketObject
 * - Multipart operations     -> Based on s3Request.operation
 *
 * @param {Object} s3Routes - S3 route handlers module
 * @return {Function} Restify route handler
 */
function createS3RequestHandler(s3Routes) {
    return function handleS3Request(req, res, next) {
        var method = req.method.toLowerCase();
        var requestPath = req.path();
        var pathParts = requestPath.split('/').filter(function (part) {
            return (part.length > 0); });

        req.log.debug({
            method: method,
            path: requestPath,
            pathParts: pathParts,
            hasAuth: !!req.authorization,
            hasCaller: !!req.caller
        }, 'S3_DEBUG: handleS3Request - routing S3 request');

        try {
            /*
             *  S3 List Buckets for account: GET /
             *  as pathParts.length === 0
             *  the user is requesting a list for the
             *  root path not specifying a particular bucket,
             *  so in a nutshell the user just wants list
             *  the buckets available in the account.
             *
             *  For example:
             *  $ s3cmd ls s3://
             *
             *  Falls in this case.
             *
             */
            if (method === 'get' && pathParts.length === 0) {
                    req.log.debug('S3_DEBUG: Routing to s3ListBucketsHandler');
                    return (s3Routes.s3ListBucketsHandler()(req, res, next));

            }

            /*
             * S3 Bucket Operations: /:bucket
             * as pathParts.lenght at least has one element, it means the user
             * is requesting an operation using /<bucketname>/,
             * as the parameter.
             *
             * The HTTP verb and req.s3RequestOperation serves as keys to decide
             * which is the actual operation that the user is requesting.
             *
             *
             *  +------------+-------------------+-----------------------------+
             *  |HTTP VERB   |S3Request          |Handler                      |
             *  +------------+-------------------+-----------------------------+
             *  |PUT         |NONE               |s3CreateBucketHandler        |
             *  +------------+-------------------+-----------------------------+
             *  |GET         |ListBucketObjectsV2| s3ListBucketObjectsV2Handler|
             *  +------------+-------------------+-----------------------------+
             *  |GET         |ListBucketObjects  | s3ListBucketObjectsHandler  |
             *  +------------+-------------------+-----------------------------+
             *  |HEAD        |NONE               | s3HeadBucketHandler         |
             *  +------------+-------------------+-----------------------------+
             *  |POST        |DeleteBucketObjects| s3DeleteBucketObjectsHandler|
             *  +------------+-------------------+-----------------------------+
             *  |DELETE      |NONE               | s3DeleteBucketHandler       |
             *  +------------+-------------------+-----------------------------+
             *
             */
            if (pathParts.length === 1) {
                var pathBucketName = pathParts[0];
                req.params = req.params || {};
                req.params.bucket = pathBucketName;
                req.params[0] = pathBucketName; // For regex routes compat

                req.log.debug({
                    operation: 'bucket-' + method,
                    bucket: pathBucketName
                }, 'S3_DEBUG: Routing to bucket operation handler');

                switch (method) {
                    case 'put':
                        // Check for CORS configuration operation
                        if (req.s3Request && req.s3Request.operation ===
                            'PutBucketCors') {
                            req.log.debug('S3_DEBUG_ROUTING:' +
                                          ' ROUTING TO s3PutBucketCorsHandler');
                            return (s3Routes.s3PutBucketCorsHandler()
                                    (req, res, next));
                        } else {
                            return (s3Routes.s3CreateBucketHandler()
                                    (req, res, next));
                        }
                    case 'get':
                        // DEBUG: Log routing decision
                        req.log.debug('S3_DEBUG_ROUTING:' +
                                      ' handleS3Request GET case'+
                        ' - making routing decision');
                        req.log.debug('S3_DEBUG_ROUTING: req.s3Request exists:',
                        !!req.s3Request);
                        req.log.debug('S3_DEBUG_ROUTING: ' +
                                      'req.s3Request.operation:',
                        req.s3Request ? req.s3Request.operation : 'undefined');
                        req.log.debug('S3_DEBUG_ROUTING: operation ==='+
                        ' ListBucketObjectsV2:',
                        req.s3Request && req.s3Request.operation ===
                        'ListBucketObjectsV2');

                        // Check for CORS configuration operation
                        if (req.s3Request && req.s3Request.operation ===
                            'GetBucketCors') {
                            req.log.debug('S3_DEBUG_ROUTING:' +
                                          ' ROUTING TO s3GetBucketCorsHandler');
                            return (s3Routes.s3GetBucketCorsHandler()
                                    (req, res, next));
                        } else if (req.s3Request && req.s3Request.operation ===
                            'ListMultipartUploads') {
                            req.log.debug('S3_DEBUG_ROUTING:' +
                                ' ROUTING TO s3ListMultipartUploadsHandler');
                            return (s3ListMultipartUploadsHandler(req, res,
                                                                  next));
                        } else if (req.s3Request && req.s3Request.operation ===
                        'ListBucketObjectsV2') {
                            req.log.debug('S3_DEBUG_ROUTING:  '+
                            'ROUTING TO s3ListBucketObjectsV2Handler');
                            return (s3Routes.s3ListBucketObjectsV2Handler()(req,
                            res, next));
                        } else {
                            req.log.debug('S3_DEBUG_ROUTING:  '+
                            'ROUTING TO s3ListBucketObjectsHandler (V1)');
                            return (s3Routes.s3ListBucketObjectsHandler()(req,
                            res, next));
                        }
                    case 'head':
                        return (s3Routes.s3HeadBucketHandler()(req, res, next));
                    case 'delete':
                        // Check for CORS configuration operation
                        if (req.s3Request && req.s3Request.operation ===
                            'DeleteBucketCors') {
                            req.log.debug('S3_DEBUG_ROUTING:' +
                                          ' ROUTING TO ' +
                                          's3DeleteBucketCorsHandler');
                            return (s3Routes.s3DeleteBucketCorsHandler()
                                    (req, res, next));
                        } else {
                            return (s3Routes.s3DeleteBucketHandler()
                                    (req, res, next));
                        }
                    case 'post':
                        // Check if this is a bulk delete operation
                        if (req.s3Request && req.s3Request.operation
                            === 'DeleteBucketObjects') {
                            req.log.debug('S3_DEBUG_ROUTING:' +
                               'ROUTING TO s3DeleteBucketObjectsHandler');
                            return (s3Routes.s3DeleteBucketObjectsHandler()
                                    (req, res, next));
                        } else {
                            req.log.warn('S3_WARN: Unsupported POST' +
                                         ' operation for bucket');
                            res.send(405, {
                                code: 'MethodNotAllowed',
                                message: 'The specified method is not allowed' +
                                    ' against this resource.'
                            });
                            return (next(false));
                        }
                    default:
                        req.log.warn({
                            method: method,
                            path: path
                        },
                        'S3_DEBUG: unsupported HTTP method' +
                                     ' for bucket operation');
                        res.send(405, {
                            code: 'MethodNotAllowed',
                            message: 'The specified'+
                            ' method is not allowed against this resource.'
                        });
                        next(false);
                        break;
                }
            }

            /*
             * S3 Bucket Operations: /:bucket/path/to/object
             * as pathParts.lenght has more than one element, it means the user
             * is requesting an operation on an object existing or new using
             * it's path or future path as parameter for example:
             *
             * - /bucketname/path/to/object
             * - /mybucket/myfiles/somefile.txt
             * - /mybucket/file.txt
             *
             * In the special case of multipart uploads that only the S3Request
             * is used to determinate that we need to process a MPU request.
             *
             * a MPU request has the following steps:
             *
             * Steps                            |S1| S2 |  S3   | S4 |
             * -------------------------------------------------------
             * s3InitiateMultipartUploadHandler |==|
             * s3UploadPartHandler                  |===|
             * s3CompleteMultipartUploadHandler          |======|
             * s3AbortMultipartUploadHandler                    |====|
             *
             * User could call s3CompleteMultipartUpload to generate the final
             * file, or just Abort the MPU request.
             *
             * As before the HTTP verb and req.s3RequestOperation serves as
             * keys to decide which is the actual operation that the user is
             * requesting.
             *
             *  +------------+-------------------+-----------------------------+
             *  |HTTP VERB   |S3Request          |Handler                      |
             *  +------------+-------------------+-----------------------------+
             *  |HEAD        |NONE               | s3HeadBucketObjectHandler   |
             *  +------------+-------------------+-----------------------------+
             *  |POST || PUT |NONE               | s3CreateBucketObjectsHandler|
             *  +------------+-------------------+-----------------------------+
             *  |DELETE      |NONE               | s3DeleteBucketObjectHandler |
             *  +------------+-------------------+-----------------------------+
             *  |GET         |NONE               | s3GetBucketObjectHandler    |
             *  +------------+-------------------+-----------------------------+
             *
             */

            if (pathParts.length >= 2) {
                var objectBucketName = pathParts[0];
                var objectPath = pathParts.slice(1).join('/');
                req.params = req.params || {};
                req.params.bucket = objectBucketName;
                req.params['*'] = objectPath;
                req.params[0] = objectBucketName; // For regex routes compat
                req.params[1] = objectPath; // For regex routes compat

                req.log.debug({
                    operation: 'object-' + method,
                    bucket: objectBucketName,
                    object: objectPath
                }, 'S3_DEBUG: Routing to object operation handler');

                // Check for multipart upload operations first
                if (req.s3Request && req.s3Request.operation ===
                    'InitiateMultipartUpload') {
                    req.log.debug('S3_DEBUG_ROUTING:' +
                               ' ROUTING TO s3InitiateMultipartUploadHandler');
                    return s3Routes.s3InitiateMultipartUploadHandler()
                    (req, res, next);
                } else if (req.s3Request &&
                           req.s3Request.operation === 'UploadPart') {
                    req.log.debug('S3_DEBUG_ROUTING:' +
                                  '  ROUTING TO s3UploadPartHandler');
                    return (s3Routes.s3UploadPartHandler()(req, res, next));
                } else if (req.s3Request && req.s3Request.operation
                           === 'CompleteMultipartUpload') {
                    req.log.debug('S3_DEBUG_ROUTING:' +
                          ' ROUTING TO s3CompleteMultipartUploadHandler');
                    return (s3Routes.s3CompleteMultipartUploadHandler()
                            (req, res, next));
                } else if (req.s3Request && req.s3Request.operation ===
                           'AbortMultipartUpload') {
                    req.log.debug('S3_DEBUG_ROUTING:' +
                                 ' ROUTING TO s3AbortMultipartUploadHandler');
                    return (s3Routes.s3AbortMultipartUploadHandler()
                            (req, res, next));
                } else if (req.s3Request && req.s3Request.operation ===
                           'ListParts') {
                    req.log.debug('S3_DEBUG_ROUTING:' +
                                 ' ROUTING TO s3ListPartsHandler');
                    return (s3Routes.s3ListPartsHandler()
                            (req, res, next));
                } else if (req.s3Request && req.s3Request.operation ===
                           'ResumeUpload') {
                    req.log.debug('S3_DEBUG_ROUTING:' +
                                 ' ROUTING TO s3ResumeUploadHandler');
                    return (s3Routes.s3ResumeUploadHandler()
                            (req, res, next));
                }

                switch (method) {
                    case 'post': // Fallthrough
                    case 'put':
                        return s3Routes.s3CreateBucketObjectHandler()(req, res,
                        next);
                    case 'get':
                        return s3Routes.s3GetBucketObjectHandler()(req, res,
                        next);
                    case 'head':
                        return s3Routes.s3HeadBucketObjectHandler()(req, res,
                        next);
                    case 'delete':
                        return s3Routes.s3DeleteBucketObjectHandler()(req, res,
                        next);
                    default:
                        req.log.warn({
                            method: method,
                            path: requestPath
                        },
                        'S3_WARN: unsupported HTTP ' +
                                     'method for object operation');
                        res.send(405, {
                            code: 'MethodNotAllowed',
                            message: 'The specified method'+
                            ' is not allowed against this resource.'
                        });
                    return (next(false));
                }
            }

            // If we get here, no S3 route matched
            req.log.warn({
                method: method,
                path: path
            }, 'S3_DEBUG: no S3 route matched for SigV4 request');

            res.send(404, {
                code: 'NoSuchKey',
                message: 'The specified key does not exist.'
            });
            next(false);

        } catch (err) {
            req.log.error(err, 'S3_DEBUG: error routing S3 request');
            next(err);
        }
    };
}


///--- Exports

module.exports = {
    createS3RequestHandler: createS3RequestHandler
};
