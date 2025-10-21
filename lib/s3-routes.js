/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 * File:     s3-routes.js
 * Purpose:  Converts S3 operations into their equivalent Manta
 *     bucket operations.
 *
 *
 * Description:
 *   Functions here have the responsibility to perform the following operations:
 *   - Handle S3 specific routing for example: ACL operations, MPU, etc...
 *   - Manages path conversion between S3 resources and Manta buckets resources.
 *   - Orchestrates middleware execution for bulk delete operations.
 *   - Convert headers from AWS to Manta required headers, and back.
 *
 * Notes:
 *   The functions here act as a bridge between S3 clients and Manta objects, at
 *   the end, S3 clients think they are talking with an S3 implementation but
 *   we are just translating their request to something that Manta could make
 *   sense.
 */

var assert = require('assert-plus');
var buckets = require('./buckets');
var bucketHelpers = require('./buckets/buckets');

// Import S3 compatibility functions
var s3Compat = require('./s3-compat');

// Import S3 multipart upload handlers
var s3Multipart = require('./s3-multipart');

// Import anonymous auth for SYSTEM_ROLES constant
var anonymousAuth = require('./anonymous-auth');

///--- Helper Functions

/**
 * Execute a middleware chain from buckets module
 * Flattens nested arrays that may be returned by handler factories
 */
function executeMiddlewareChain(chain, req, res, next) {
    // Flatten the chain to handle nested arrays from handler factories
    var flatChain = [];
    function flatten(item) {
        if (Array.isArray(item)) {
            item.forEach(flatten);
        } else if ((typeof (item)) === 'function') {
            flatChain.push(item);
        } else {
            req.log.warn({
                itemType: (typeof (item)),
                item: item
            }, 'S3_DEBUG: executeMiddlewareChain -'+
            ' unexpected item type in chain');
        }
    }
    chain.forEach(flatten);
    var currentIndex = 0;
    req.log.debug({
        originalChainLength: chain.length,
        flatChainLength: flatChain.length,
        chainHandlers: flatChain.map(function (h) {
            return (h.name || 'anonymous');
        })
    }, 'S3_DEBUG: executeMiddlewareChain - starting execution');
    function runNext(err) {
        if (err) {
            // Handle false as a signal to stop middleware chain execution
            if (err === false) {
                req.log.debug('S3_DEBUG: Middleware chain stopped by handler');
                next();
                return;
            }

            // Log user errors at info/debug level,
            // system errors at error level
            var isUserError = (err.statusCode >= 400 &&
            err.statusCode < 500) ||
                (err.name && (err.name.includes('NotFound') ||
                err.name.includes('Exists') ||
                err.name.includes('BadRequest')));
            if (isUserError) {
                req.log.debug({
                    errorName: err.name,
                    errorCode: err.restCode || err.code,
                    statusCode: err.statusCode,
                    message: err.message
                }, 'S3_DEBUG: User error in middleware chain');
            } else {
                req.log.debug(err,
                'S3_DEBUG: System error in middleware chain');
            }
            next(err);
            return;
        }
        if (currentIndex >= flatChain.length) {
            req.log.debug('S3_DEBUG: executeMiddlewareChain -' +
            'completed all handlers, calling completion callback');
            next();
            return;
        }
        var currentHandler = flatChain[currentIndex];
        req.log.debug({
            handlerIndex: currentIndex,
            handlerName: currentHandler.name || 'anonymous'
        }, 'S3_DEBUG: executeMiddlewareChain - executing handler');

        currentIndex++;
        currentHandler(req, res, runNext);
    }

    runNext();
}

///--- S3 Handler Functions

/**
 * S3 List Buckets Handler
 * Converts S3 ListBuckets request to Manta format
 */
function s3ListBucketsHandler() {
    return function s3ListBuckets(req, res, next) {
        req.log.debug({
            caller: req.caller ? {
                login: req.caller.account ?
                req.caller.account.login : 'no-account',
                uuid: req.caller.account ?
                req.caller.account.uuid : 'no-uuid'
            } : 'no-caller'
        }, 'S3_DEBUG: s3ListBuckets - processing S3 list buckets request');

        // Ensure we have authentication context
        if (!req.caller || !req.caller.account) {
            req.log.error('S3_DEBUG: s3ListBuckets -'+
            ' Authentication required, no caller or account');
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Set up Manta-style parameters
        req.params.account = req.caller.account.login;
        req.log.debug({
            account: req.params.account
        }, 'S3_DEBUG: s3ListBuckets - calling Manta listBucketsHandler');

        // Intercept the response to collect bucket data for S3 XML formatting
        var originalWrite = res.write;
        var originalEnd = res.end;
        var bucketData = [];

        res.write = function (chunk) {
            if (chunk) {
                try {
                    var bucketEntry = JSON.parse(chunk.toString().trim());
                    bucketData.push(bucketEntry);
                    req.log.debug({
                        bucketName: bucketEntry.name,
                        bucketEntry: bucketEntry
                    }, 'S3_DEBUG: collected bucket entry');
                } catch (e) {
                    req.log.warn({
                        chunk: chunk.toString(),
                        error: e.message
                    }, 'S3_DEBUG: failed to parse bucket entry');
                }
            }
        };

        res.end = function () {
            // Check if response was already sent (e.g., error response)
            if (res.headersSent || res._headerSent) {
                req.log.debug('S3_DEBUG: s3ListBuckets - ' +
                    'headers already sent, skipping response');
                // Restore original functions before returning
                res.write = originalWrite;
                res.end = originalEnd;
                return;
            }

            req.log.debug({
                bucketCount: bucketData.length,
                buckets: bucketData.map(function (b) { return b.name; }),
                bucketData: bucketData
            }, 'S3_DEBUG: s3ListBuckets -'+
            ' collected all buckets, sending S3 response with status 200');

            // Restore original functions BEFORE sending to avoid recursion
            res.write = originalWrite;
            res.end = originalEnd;

            // Send collected data via res.send() so S3 formatter
            // can convert to XML
            // For empty bucket list, this will generate proper XML with
            // empty <Buckets/>
            res.send(200, bucketData);
        };

        // Call the original Manta buckets list handler
        var mantaHandlerChain = buckets.listBucketsHandler();
        executeMiddlewareChain(mantaHandlerChain, req, res, function (error) {
            // If error occurs, restore original functions immediately
            // so error handler can send response properly
            if (error) {
                res.write = originalWrite;
                res.end = originalEnd;
                next(error);
            } else {
                next(false); // Stop route processing
            }
        });
    };
}

/**
 * S3 Create Bucket Handler
 */
function s3CreateBucketHandler() {
    return function s3CreateBucket(req, res, next) {
        // Debug: Always log query parameters
        req.log.debug({
            bucket: req.params.bucket,
            query: req.query,
            url: req.url,
            path: req.path(),
            hasAclQuery: req.query && req.query.acl !== undefined,
            headers: {
                'x-amz-acl': req.headers['x-amz-acl'],
                'role-tag': req.headers['role-tag']
            }
        }, 'S3_DEBUG: s3CreateBucket - checking for ACL operation');

        // Check if this is an ACL operation
        if (req.query && req.query.acl !== undefined) {
            req.log.debug({
                bucket: req.params.bucket,
                query: req.query
            }, 'S3_DEBUG: PUT ACL operation detected in s3CreateBucket');
            // Call ACL handler directly and return immediately
            s3SetBucketACLHandler()(req, res, next);
            return; // Ensure we don't continue with normal processing
        }

        req.log.debug({
            bucket: req.params.bucket
        }, 's3CreateBucket: processing S3 create bucket request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = req.params.bucket;

        // Call the original Manta bucket creation handler
        var mantaHandlerChain = buckets.createBucketHandler();
        executeMiddlewareChain(mantaHandlerChain, req, res, function (error) {
            // Always terminate the route chain for S3 requests to
            // prevent double execution
            if (error) {
                next(error);
            } else {
                next(false); // Stop route processing
            }
        });
    };
}

/**
 * S3 List Bucket Objects Handler
 */
function s3ListBucketObjectsHandler() {
    return function s3ListBucketObjects(req, res, next) {
        // Debug: Always log query parameters
        req.log.debug({
            bucket: req.params.bucket,
            query: req.query,
            url: req.url,
            path: req.path(),
            rawUrl: req.url,
            queryString: req.url ? req.url.split('?')[1] : 'none',
            hasAclQuery: req.query && req.query.acl !== undefined,
            queryKeys: req.query ? Object.keys(req.query) : 'no-query'
        }, 'S3_DEBUG: s3ListBucketObjects - checking for ACL operation');

        // Check if this is an ACL operation
        if (req.query && req.query.acl !== undefined) {
            req.log.debug({
                bucket: req.params.bucket,
                query: req.query
            }, 'S3_DEBUG: GET ACL operation detected in s3ListBucketObjects');
            // Call ACL handler directly and return immediately
            s3GetBucketACLHandler()(req, res, next);
            return; // Ensure we don't continue with normal processing
        }

        req.log.debug({
            bucket: req.params.bucket
        }, 's3ListBucketObjects: processing S3 list objects request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = req.params.bucket;

        // Convert S3 query parameters to Manta format
        if (req.query['max-keys'] !== undefined) {
            req.query.limit = req.query['max-keys'];
        }

        // Call the original Manta list objects handler
        var mantaHandlerChain = buckets.listBucketObjectsHandler();
        executeMiddlewareChain(mantaHandlerChain, req, res, function (error) {
            // Always terminate the route chain for S3 requests to
            // prevent double execution
            if (error) {
                next(error);
            } else {
                next(false); // Stop route processing
            }
        });
    };
}

/**
 * S3 List Bucket Objects V2 Handler (for list-type=2 requests)
 */
function s3ListBucketObjectsV2Handler() {
    return function s3ListBucketObjectsV2(req, res, next) {
        req.log.debug('S3_DEBUG_V2_HANDLER:  '+
        's3ListBucketObjectsV2Handler CALLED - V2 handler is running');
        req.log.debug('S3_DEBUG_V2_HANDLER:'+
        ' req.s3Request.operation should be ListBucketObjectsV2:',
        req.s3Request ? req.s3Request.operation : 'undefined');

        req.log.debug({
            bucket: req.params.bucket,
            queryParams: req.query
        }, 's3ListBucketObjectsV2: processing S3 list objects v2 request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = req.params.bucket;

        // Convert S3 query parameters to Manta format
        if (req.query['max-keys'] !== undefined) {
            req.query.limit = req.query['max-keys'];
        }

        // Map ListObjectsV2 continuation-token to internal marker
        // Why, ListObjects uses marker so it matches and works,
        // but ListObjectsV2 instead of marker it uses the name
        // 'contination-token' so it breaks with manta, hence
        // the need of mapping this param.
        if (req.query['continuation-token'] !== undefined) {
            req.query.marker = req.query['continuation-token'];
        }

        // Mark this as a V2 request for the S3 formatter
        req.s3Request = req.s3Request || {};
        req.s3Request.operation = 'ListBucketObjectsV2';

        // Call the original Manta list objects handler
        var mantaHandlerChain = buckets.listBucketObjectsHandler();
        executeMiddlewareChain(mantaHandlerChain, req, res, function (error) {
            // Always terminate the route chain for S3 requests
            // to prevent double execution
            if (error) {
                next(error);
            } else {
                next(false); // Stop route processing
            }
        });
    };
}

/**
 * S3 Head Bucket Handler
 */
function s3HeadBucketHandler() {
    return function s3HeadBucket(req, res, next) {
        req.log.debug({
            bucket: req.params.bucket
        }, 's3HeadBucket: processing S3 head bucket request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = req.params.bucket;

        // Call the original Manta head bucket handler
        var mantaHandlerChain = buckets.headBucketHandler();
        executeMiddlewareChain(mantaHandlerChain, req, res, function (error) {
            // Always terminate the route chain for S3 requests
            // to prevent double execution
            if (error) {
                next(error);
            } else {
                next(false); // Stop route processing
            }
        });
    };
}

/**
 * S3 Delete Bucket Handler
 */
function s3DeleteBucketHandler() {
    return function s3DeleteBucket(req, res, next) {
        req.log.debug({
            bucket: req.params.bucket
        }, 's3DeleteBucket: processing S3 delete bucket request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = req.params.bucket;

        // Call the original Manta delete bucket handler
        var mantaHandlerChain = buckets.deleteBucketHandler();
        executeMiddlewareChain(mantaHandlerChain, req, res, function (error) {
            // Always terminate the route chain for S3 requests
            // to prevent double execution
            if (error) {
                next(error);
            } else {
                next(false); // Stop route processing
            }
        });
    };
}

/**
 * S3 Create Object Handler
 */
function s3CreateBucketObjectHandler() {
    return function s3CreateBucketObject(req, res, next) {
        // With regex routes, captured groups are in req.params array
        var bucketName = req.params[0] || req.params.bucket;
        var objectPath = req.params[1] || req.params['*'] || '';

        // Handle S3 directory creation semantics
        // AWS S3 creates zero-byte objects with trailing slash for directories
        // This makes s3 clients recognize them as DIROBJ instead of 0-byte
        // files. This makes clients like cyberduck recognize these files
        // as 'directories'.
        var isDirectoryCreation =
            req.headers['content-type'] === 'application/x-directory';
        if (isDirectoryCreation && !objectPath.endsWith('/')) {
            objectPath = objectPath + '/';
            req.log.debug({
                originalPath: req.params[1] || req.params['*'] || '',
                modifiedPath: objectPath,
                contentType: req.headers['content-type']
            }, 'S3_DEBUG: Modified object path for directory creation ' +
               '- adding trailing slash');
        }

        // Check if this is an ACL operation
        req.log.debug({
            hasQuery: !!req.query,
            query: req.query,
            hasAcl: req.query && req.query.acl !== undefined,
            aclValue: req.query ? req.query.acl : 'no-query'
        }, 'S3_DEBUG: Checking for ACL operation');

        // Check if this is a restore operation
        if (req.query && req.query.restore !== undefined) {
            req.log.debug({
                bucket: bucketName,
                object: objectPath,
                query: req.query
            }, 'S3_DEBUG: PUT Object restore operation detected ' +
               '- not supported');
            var restoreError = new NotImplementedError('Restore operations '+
                                                       'are not supported');
            res.send(501, restoreError);
            return;
        }

        // Check if this is an S3 server-side copy operation
        var copySource = req.headers['x-amz-copy-source'];
        if (copySource) {
            req.log.debug({
                bucket: bucketName,
                object: objectPath,
                copySource: copySource
            }, 'S3_DEBUG: PUT Object copy operation detected');
            s3CopyObjectHandler()(req, res, next);
            return;
        }

        if (req.query && req.query.acl !== undefined) {
            req.log.debug({
                bucket: bucketName,
                object: objectPath,
                query: req.query
            }, 'S3_DEBUG: PUT Object ACL operation detected');
            s3SetObjectACLHandler()(req, res, next);
            return;
        }

        // Check if this is a tagging operation
        if (req.query && req.query.tagging !== undefined) {
            req.log.debug({
                bucket: bucketName,
                object: objectPath,
                query: req.query
            }, 'S3_DEBUG: PUT Object tagging operation detected');
            s3PutObjectTaggingHandler()(req, res, next);
            return;
        }

        req.log.debug({
            bucket: bucketName,
            object: objectPath,
            originalParams: req.params,
            path: req.path(),
            method: req.method
        }, 'S3_DEBUG: s3CreateBucketObject'+
        ' - processing S3 create object request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Mark this as an S3 request for role translation
        req.isS3Request = true;

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = bucketName;
        req.params.object_name = objectPath;

        req.log.debug({
            convertedParams: {
                account: req.params.account,
                bucket_name: req.params.bucket_name,
                object_name: req.params.object_name
            },
            expectedMantaPath: '/' + req.params.account + '/buckets/' +
            bucketName + '/objects/' + objectPath
        }, 'S3_DEBUG: s3CreateBucketObject - converted to Manta format');

        // For binary uploads, ensure request is in binary mode and prevent
        // aws-chunked corruption
        if (req.headers['content-type']) {
            req.log.debug('S3_DEBUG: Setting binary mode for S3'+
            ' object upload and disabling aws-chunked decoding');

            // CRITICAL: Mark for aws-chunked handling after auth
            // (can't remove header before auth)
            if (req.headers['content-encoding'] === 'aws-chunked') {
                req.log.debug('S3_DEBUG:'+
                ' Marking aws-chunked for special binary handling');
                req._awsChunkedBinary = true;
            }

            // Ensure the request stream is in binary mode
            if (req.setEncoding) {
                req.setEncoding(null);
            }
            if (req._readableState) {
                req._readableState.encoding = null;
                req._readableState.decoder = null;
            }

            // Mark as binary for downstream handlers
            req._binaryUpload = true;
        }

        // Apply S3 role translation middleware before calling Manta handler
        s3Compat.s3RoleTranslator(req, res, function (translationErr) {
            if (translationErr) {
                next(translationErr);
                return;
            }

            // Call the original Manta create object handler
            var mantaHandlerChain = buckets.createBucketObjectHandler();
            executeMiddlewareChain(mantaHandlerChain, req, res,
                                   function (error) {
                // Always terminate the route chain for S3 requests to
                // prevent double execution
                if (error) {
                    next(error);
                } else {
                    next(false); // Stop route processing
                }
            });
        });
    };
}

/**
 * S3 Get Object Handler
 */
function s3GetBucketObjectHandler() {
    return function s3GetBucketObject(req, res, next) {
        // With regex routes, captured groups are in req.params array
        var bucketName = req.params[0] || req.params.bucket;
        var objectPath = req.params[1] || req.params['*'] || '';

        // Check if this is a restore operation
        if (req.query && req.query.restore !== undefined) {
            req.log.debug({
                bucket: bucketName,
                object: objectPath,
                query: req.query
            }, 'S3_DEBUG: GET Object restore operation detected' +
               ' - not supported');
            var restoreError =
                new NotImplementedError('Restore operations are not supported');
            res.send(501, restoreError);
            return;
        }

        // Check if this is an ACL operation
        if (req.query && req.query.acl !== undefined) {
            req.log.debug({
                bucket: bucketName,
                object: objectPath,
                query: req.query
            }, 'S3_DEBUG: GET Object ACL operation detected');
            s3GetObjectACLHandler()(req, res, next);
            return;
        }

        // Check if this is a tagging operation
        if (req.query && req.query.tagging !== undefined) {
            req.log.debug({
                bucket: bucketName,
                object: objectPath,
                query: req.query
            }, 'S3_DEBUG: GET Object tagging operation detected');
            s3GetObjectTaggingHandler()(req, res, next);
            return;
        }

        req.log.debug({
            bucket: bucketName,
            object: objectPath
        }, 's3GetBucketObject: processing S3 get object request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Mark this as an S3 request for response formatting
        req.isS3Request = true;

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = bucketName;
        req.params.object_name = objectPath;

        // Intercept res.set() to convert Manta metadata headers to S3 format
        var originalSet = res.set;
        res.set = function (key, value) {
            if (typeof (key) === 'string') {
                var lowerKey = key.toLowerCase();
                if (lowerKey.startsWith('m-')) {
                    var s3MetaKey = 'x-amz-meta-' + lowerKey.substring(2);
                    req.log.debug({
                        originalKey: key,
                        convertedKey: s3MetaKey,
                        value: value
                    }, 'S3_DEBUG: Converting GET metadata header to S3 format');
                    return (originalSet.call(this, s3MetaKey, value));
                }
            }
            return (originalSet.call(this, key, value));
        };

        // Call the original Manta get object handler chain
        var mantaHandlerChain = buckets.getBucketObjectHandler();
        executeMiddlewareChain(mantaHandlerChain, req, res, function (error) {
            // Always terminate the route chain for S3 requests to
            // prevent double execution
            if (error) {
                next(error);
            } else {
                next(false); // Stop route processing
            }
        });
    };
}

/**
 * S3 Head Object Handler
 */
function s3HeadBucketObjectHandler() {
    return function s3HeadBucketObject(req, res, next) {
        // With regex routes, captured groups are in req.params array
        var bucketName = req.params[0] || req.params.bucket;
        var objectPath = req.params[1] || req.params['*'] || '';

        req.log.debug({
            bucket: bucketName,
            object: objectPath
        }, 's3HeadBucketObject: processing S3 head object request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Mark this as an S3 request for response formatting
        req.isS3Request = true;

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = bucketName;
        req.params.object_name = objectPath;

        // Intercept res.set() to convert Manta metadata headers to S3 format
        var originalSet = res.set;
        res.set = function (key, value) {
            if (typeof (key) === 'string') {
                var lowerKey = key.toLowerCase();
                if (lowerKey.startsWith('m-')) {
                    var s3MetaKey = 'x-amz-meta-' + lowerKey.substring(2);
                    req.log.debug({
                        originalKey: key,
                        convertedKey: s3MetaKey,
                        value: value
                    }, 'S3_DEBUG: Converting HEAD '+
                       'metadata header to S3 format');
                    return (originalSet.call(this, s3MetaKey, value));
                }
            }
            return (originalSet.call(this, key, value));
        };

        // Call the original Manta head object handler
        var mantaHandlerChain = buckets.headBucketObjectHandler();
        executeMiddlewareChain(mantaHandlerChain, req, res, function (error) {
            // Always terminate the route chain for S3 requests to
            // prevent double execution
            if (error) {
                next(error);
            } else {
                next(false); // Stop route processing
            }
        });
    };
}

/**
 * S3 Delete Object Handler
 */
function s3DeleteBucketObjectHandler() {
    return function s3DeleteBucketObject(req, res, next) {
        // With regex routes, captured groups are in req.params array
        var bucketName = req.params[0] || req.params.bucket;
        var objectPath = req.params[1] || req.params['*'] || '';

        // Check if this is a tagging operation
        if (req.query && req.query.tagging !== undefined) {
            req.log.debug({
                bucket: bucketName,
                object: objectPath,
                query: req.query
            }, 'S3_DEBUG: DELETE Object tagging operation detected');
            s3DeleteObjectTaggingHandler()(req, res, next);
            return;
        }

        req.log.debug({
            bucket: bucketName,
            object: objectPath
        }, 's3DeleteBucketObject: processing S3 delete object request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = bucketName;
        req.params.object_name = objectPath;

        // Call the original Manta delete object handler
        var mantaHandlerChain = buckets.deleteBucketObjectHandler();
        executeMiddlewareChain(mantaHandlerChain, req, res, function (error) {
            // Always terminate the route chain for S3 requests to
            // prevent double execution
            if (error) {
                next(error);
            } else {
                next(false); // Stop route processing
            }
        });
    };
}

/**
 * S3 bulk delete handler for POST /bucket?delete requests
 */

/* BEGIN JSSTYLED */
function s3DeleteBucketObjectsHandler() {
    return function s3DeleteBucketObjects(req, res, next) {
        req.log.debug({
            bucket: req.s3Request ? req.s3Request.bucket : 'unknown',
            operation: req.s3Request ? req.s3Request.operation : 'unknown'
        }, 'S3_DEBUG: s3DeleteBucketObjects - bulk delete operation');

        // Validate S3 request format
        if (!req.s3Request || !req.s3Request.bucket) {
            var InvalidBucketName = require('./errors').InvalidBucketNameError;
            return (next(new InvalidBucketName('missing bucket name')));
        }

        var bucketName = req.s3Request.bucket;

        // Parse the XML body to get the list of objects to delete
        // Use preserved raw body if available (needed for SigV4 verification)
        var body = req.body || req._rawBodyString || (req._rawBodyBuffer ? req._rawBodyBuffer.toString('utf8') : null);
        if (!body) {
            return (next(new InvalidParameterError('body',
               'missing delete request body')));
        }

        req.log.debug({
            bodyType: typeof body,
            bodyLength: body ? body.length : 0,
            bodyPreview: body ? body.substring(0, 200) : 'no body'
        }, 'S3_DEBUG: s3DeleteBucketObjects - parsing request body');

        // Simple XML parsing to extract object keys
        // Look for <Key>...</Key> patterns in the XML
        var keyMatches = body.match(/<Key>([^<]+)<\/Key>/g);

        if (!keyMatches || keyMatches.length === 0) {
            req.log.error('S3_DEBUG: No objects found in delete request XML');
            return next(new InvalidParameterError('body',
               'No objects specified for deletion'));
        }

        // Extract object keys from matches - keep them as-is from XML
        var objectKeys = keyMatches.map(function(match) {
            var key = match.replace(/<\/?Key>/g, '');

            req.log.debug({
                extractedKey: key,
                isEncoded: key.includes('%')
            }, 'S3_DEBUG: Extracted object key from XML');

            // Don't decode - use the key exactly as it appears in the XML
            // The client should send the key in the same format it was stored
            return key;
        });

        var deleted = [];
        var errors = [];
        var completed = 0;

        req.log.debug({
            objectCount: objectKeys.length,
            objects: objectKeys
        }, 'S3_DEBUG: Processing bulk delete request');

        if (objectKeys.length === 0) {
            return sendDeleteResult();
        }

        // Delete each object using the proper Manta APIs
        objectKeys.forEach(function(objectKey) {
            // Create closure to capture the current objectKey value
            (function(currentObjectKey) {
                req.log.debug({
                    objectKey: currentObjectKey
                }, 'S3_DEBUG: Deleting individual object');

                // Create a new request context for this object deletion
                var deleteReq = Object.create(req);
                deleteReq.params = {
                    bucket_name: bucketName,
                    object_name: currentObjectKey
                };
                deleteReq.method = 'DELETE';
                // Use object key exactly as provided in XML for URL
                deleteReq.url = '/' + bucketName + '/' + currentObjectKey;
                deleteReq.conditions = {};

                req.log.debug({
                    objectKey: currentObjectKey,
                    deleteUrl: deleteReq.url,
                    isEncoded: currentObjectKey.includes('%')
                }, 'S3_DEBUG: Creating delete request using' +
                              ' original object key');

                // Load the bucket and object metadata first
                bucketHelpers.loadRequest(deleteReq, null, function(loadErr) {
                    if (loadErr) {
                        req.log.debug({
                            error: loadErr.message,
                            objectKey: currentObjectKey
                        }, 'S3_DEBUG: Failed to load object metadata');

                        errors.push({
                            Key: currentObjectKey,
                            Code: loadErr.restCode || 'NoSuchKey',
                            Message: loadErr.message || 'Object not found'
                        });

                        completed++;
                        if (completed === objectKeys.length) {
                            sendDeleteResult();
                        }
                        return;
                    }

                    bucketHelpers.getBucketIfExists(deleteReq, null,
                                                    function(bucketErr) {
                        if (bucketErr) {
                            req.log.debug({
                                error: bucketErr.message,
                                objectKey: currentObjectKey
                            }, 'S3_DEBUG: Failed to find bucket');

                            errors.push({
                                Key: currentObjectKey,
                                Code: bucketErr.restCode || 'NoSuchBucket',
                                Message: bucketErr.message || 'Bucket not found'
                            });

                            completed++;
                            if (completed === objectKeys.length) {
                                sendDeleteResult();
                            }
                            return;
                        }

                        // Now perform the actual deletion
                        var deleteObjectModule =
                            require('./buckets/objects/delete');
                        var deleteHandler =
                            deleteObjectModule.deleteBucketObjectHandler();

                        // Execute the delete chain: the delete function is at
                        // index 4
                        // [loadRequest, getBucketIfExists,
                        // authorizationHandler, deleteObject, successHandler]
                        var deleteObjectFunc = deleteHandler[3];

                        deleteObjectFunc(deleteReq, null,
                                         function (delErr, result) {
                            if (delErr && delErr.restCode === 'ObjectNotFound') {
                                // First try with URL-decoded version
                                // in case XML key was encoded
                                var decodedKey;
                                try {
                                    decodedKey =
                                        decodeURIComponent(currentObjectKey);
                                } catch (decodeErr) {
                                    // Use original if decode fails
                                    decodedKey = currentObjectKey;
                                }

                                if (decodedKey !== currentObjectKey) {
                                    req.log.debug({
                                        originalKey: currentObjectKey,
                                        decodedKey: decodedKey,
                                        error: delErr.message
                                    }, 'S3_DEBUG: Object not found with' +
                                  ' original key, trying URL-decoded version');

                                    // Create new request with decoded key
                                    var decodedDeleteReq = Object.create(req);
                                    decodedDeleteReq.params = {
                                        bucket_name: bucketName,
                                        object_name: decodedKey
                                    };
                                    decodedDeleteReq.method = 'DELETE';
                                    decodedDeleteReq.url = '/' + bucketName +
                                        '/' + decodedKey;
                                    decodedDeleteReq.conditions = {};

                                    // Try loading with decoded key
                                    bucketHelpers.loadRequest
                                    (decodedDeleteReq, null,
                                     function(decLoadErr) {
                                        if (decLoadErr) {
                                            // Fall through to encoded attempts
                                            tryEncodedVersions();
                                            return;
                                        }

                                        bucketHelpers.getBucketIfExists
                                         (decodedDeleteReq, null,
                                          function(decBucketErr) {
                                            if (decBucketErr) {
                                                // Fall through to encoded attempts
                                                tryEncodedVersions();
                                                return;
                                            }

                                            deleteObjectFunc
                                              (decodedDeleteReq, null,
                                               function(decDelErr, decResult) {
                                                completed++;

                                                if (decDelErr) {
                                                    req.log.debug({
                                                     error: decDelErr.message,
                                                     objectKey: currentObjectKey,
                                                     decodedKey: decodedKey
                                                    }, 'S3_DEBUG: Failed to' +
                                                      ' delete object even with' +
                                                      ' decoded key, trying' +
                                                      ' encoded versions');

                                                    // Fall through to encoded
                                                    // attempts by not returning
                                                    // here
                                                    // Reset completed counter
                                                    // and try encoded versions
                                                    completed--;
                                                    tryEncodedVersions();
                                                } else {
                                                  req.log.debug({
                                                    objectKey: currentObjectKey,
                                                    decodedKey: decodedKey
                                                   }, 'S3_DEBUG: Successfully' +
                                                      ' deleted object' +
                                                      ' using URL-decoded key');

                                                    deleted.push({
                                                        Key: currentObjectKey
                                                    });

                                                    if (completed ===
                                                        objectKeys.length) {
                                                        sendDeleteResult();
                                                    }
                                                }
                                            });
                                        });
                                    });
                                } else {
                                    // No decoding needed, try encoded versions
                                    tryEncodedVersions();
                                }

                                function tryEncodedVersions() {
                                    // Try with URL-encoded version if object not found
                                    req.log.debug({
                                        originalKey: currentObjectKey,
                                        error: delErr.message
                                    }, 'S3_DEBUG: Object not found,' +
                                                  ' trying encoded versions');

                                    var encodedKey =
                                        encodeURIComponent(currentObjectKey)
                                        .replace(/%2F/g, '/')
                                        .replace(/%28/g, '(')
                                        .replace(/%29/g, ')');
                                    if (encodedKey !== currentObjectKey) {
                                        // Create new request with encoded key
                                        var encodedDeleteReq =
                                            Object.create(req);
                                        encodedDeleteReq.params = {
                                            bucket_name: bucketName,
                                            object_name: encodedKey
                                        };
                                        encodedDeleteReq.method = 'DELETE';
                                        encodedDeleteReq.url = '/' +
                                            bucketName + '/' + encodedKey;
                                        encodedDeleteReq.conditions = {};

                                        req.log.debug({
                                            originalKey: currentObjectKey,
                                            encodedKey: encodedKey
                                        }, 'S3_DEBUG: Retrying delete' +
                                                  ' with encoded object key');

                                        // Try loading with encoded key
                                        bucketHelpers.loadRequest
                                        (encodedDeleteReq, null,
                                         function(encLoadErr) {
                                        if (encLoadErr) {
                                            completed++;
                                            errors.push({
                                                Key: currentObjectKey,
                                                Code: delErr.restCode ||
                                                    'NoSuchKey',
                                                Message: delErr.message ||
                                                    'Object not found'
                                            });
                                            if (completed ===
                                                objectKeys.length) {
                                                sendDeleteResult();
                                            }
                                            return;
                                        }

                                        bucketHelpers.getBucketIfExists
                                             (encodedDeleteReq, null,
                                              function(encBucketErr) {
                                            if (encBucketErr) {
                                                completed++;
                                                errors.push({
                                                    Key: currentObjectKey,
                                                    Code: delErr.restCode ||
                                                        'NoSuchKey',
                                                    Message: delErr.message ||
                                                        'Object not found'
                                                });
                                                if (completed ===
                                                    objectKeys.length) {
                                                    sendDeleteResult();
                                                }
                                                return;
                                            }

                                            deleteObjectFunc
                                                  (encodedDeleteReq,
                                                   null,
                                                   function
                                                   (encDelErr, encResult) {
                                                if (encDelErr &&
                                                    encDelErr.restCode ===
                                                    'ObjectNotFound') {
                                                    // Try with parentheses
                                                    // encoded
                                                    // (some clients encode
                                                    // parentheses differently)
                                                    var parenEncodedKey =
                                                        currentObjectKey
                                                        .replace(/\(/g, '%28')
                                                        .replace(/\)/g, '%29');

                                                    if (parenEncodedKey !==
                                                        currentObjectKey &&
                                                        parenEncodedKey !==
                                                        encodedKey) {
                                                        req.log.debug({
                                                         originalKey:
                                                            currentObjectKey,
                                                         encodedKey: encodedKey,
                                                         parenEncodedKey:
                                                            parenEncodedKey
                                                        }, 'S3_DEBUG: Trying' +
                                                          ' parentheses-encoded'+
                                                                      ' key');

                                                        var parenEncodedDeleteReq = Object.create(req);
                                                        parenEncodedDeleteReq.params = {
                                                            bucket_name: bucketName,
                                                            object_name: parenEncodedKey
                                                        };
                                                        parenEncodedDeleteReq.method = 'DELETE';
                                                        parenEncodedDeleteReq.url = '/' + bucketName + '/' + parenEncodedKey;
                                                        parenEncodedDeleteReq.conditions = {};

                                                        bucketHelpers.loadRequest(parenEncodedDeleteReq, null, function(parenLoadErr) {
                                                            if (!parenLoadErr) {
                                                                bucketHelpers.getBucketIfExists(parenEncodedDeleteReq, null, function(parenBucketErr) {
                                                                    if (!parenBucketErr) {
                                                                        deleteObjectFunc(parenEncodedDeleteReq, null, function(parenDelErr, parenResult) {
                                                                            completed++;

                                                                            if (parenDelErr) {
                                                                                req.log.debug({
                                                                                    error: parenDelErr.message,
                                                                                    objectKey: currentObjectKey,
                                                                                    triedKeys: [currentObjectKey, encodedKey, parenEncodedKey]
                                                                                }, 'S3_DEBUG: Failed to delete object with parentheses encoding');

                                                                                // Try with both spaces and parentheses encoded (most comprehensive pattern)
                                                                                var fullyEncodedKey = currentObjectKey
                                                                                    .replace(/ /g, '%20')
                                                                                    .replace(/\(/g, '%28')
                                                                                    .replace(/\)/g, '%29');

                                                                                if (fullyEncodedKey !== currentObjectKey &&
                                                                                    fullyEncodedKey !== encodedKey &&
                                                                                    fullyEncodedKey !== parenEncodedKey) {

                                                                                    req.log.debug({
                                                                                        originalKey: currentObjectKey,
                                                                                        fullyEncodedKey: fullyEncodedKey
                                                                                    }, 'S3_DEBUG: Trying fully encoded key (spaces + parentheses)');

                                                                                    var fullyEncodedDeleteReq = Object.create(req);
                                                                                    fullyEncodedDeleteReq.params = {
                                                                                        bucket_name: bucketName,
                                                                                        object_name: fullyEncodedKey
                                                                                    };
                                                                                    fullyEncodedDeleteReq.method = 'DELETE';
                                                                                    fullyEncodedDeleteReq.url = '/' + bucketName + '/' + fullyEncodedKey;
                                                                                    fullyEncodedDeleteReq.conditions = {};

                                                                                    bucketHelpers.loadRequest(fullyEncodedDeleteReq, null, function(fullLoadErr) {
                                                                                        if (!fullLoadErr) {
                                                                                            bucketHelpers.getBucketIfExists(fullyEncodedDeleteReq, null, function(fullBucketErr) {
                                                                                                if (!fullBucketErr) {
                                                                                                    deleteObjectFunc(fullyEncodedDeleteReq, null, function(fullDelErr, fullResult) {
                                                                                                        completed++;

                                                                                                        if (fullDelErr) {
                                                                                                            req.log.debug({
                                                                                                                error: fullDelErr.message,
                                                                                                                objectKey: currentObjectKey,
                                                                                                                triedKeys: [currentObjectKey, encodedKey, parenEncodedKey, fullyEncodedKey]
                                                                                                            }, 'S3_DEBUG: Failed to delete object with fully encoded key');

                                                                                                            errors.push({
                                                                                                                Key: currentObjectKey,
                                                                                                                Code: 'NoSuchKey',
                                                                                                                Message: 'Object not found (tried multiple encodings)'
                                                                                                            });
                                                                                                        } else {
                                                                                                            req.log.debug({
                                                                                                                objectKey: currentObjectKey,
                                                                                                                fullyEncodedKey: fullyEncodedKey
                                                                                                            }, 'S3_DEBUG: Successfully deleted object using fully encoded key');

                                                                                                            deleted.push({
                                                                                                                Key: currentObjectKey
                                                                                                            });
                                                                                                        }

                                                                                                        if (completed === objectKeys.length) {
                                                                                                            sendDeleteResult();
                                                                                                        }
                                                                                                    });
                                                                                                    return;
                                                                                                }
                                                                                            });
                                                                                            return;
                                                                                        }

                                                                                        // All encoding attempts failed
                                                                                        completed++;
                                                                                        errors.push({
                                                                                            Key: currentObjectKey,
                                                                                            Code: 'NoSuchKey',
                                                                                            Message: 'Object not found (tried multiple encodings)'
                                                                                        });

                                                                                        if (completed === objectKeys.length) {
                                                                                            sendDeleteResult();
                                                                                        }
                                                                                    });
                                                                                } else {
                                                                                    // Fully encoded key is same as one we already tried
                                                                                    completed++;
                                                                                    errors.push({
                                                                                        Key: currentObjectKey,
                                                                                        Code: 'NoSuchKey',
                                                                                        Message: 'Object not found (tried multiple encodings)'
                                                                                    });

                                                                                    if (completed === objectKeys.length) {
                                                                                        sendDeleteResult();
                                                                                    }
                                                                                }
                                                                            } else {
                                                                                req.log.debug({
                                                                                    objectKey: currentObjectKey,
                                                                                    parenEncodedKey: parenEncodedKey
                                                                                }, 'S3_DEBUG: Successfully deleted object using parentheses-encoded key');

                                                                                deleted.push({
                                                                                    Key: currentObjectKey
                                                                                });
                                                                            }

                                                                            if (completed === objectKeys.length) {
                                                                                sendDeleteResult();
                                                                            }
                                                                        });
                                                                        return;
                                                                    }
                                                                });
                                                                return;
                                                            }

                                                            // Try with double-encoded version as final fallback
                                                            var doubleEncodedKey = encodeURIComponent(encodedKey).replace(/%2F/g, '/');
                                                            if (doubleEncodedKey !== encodedKey) {
                                                                req.log.debug({
                                                                    originalKey: currentObjectKey,
                                                                    encodedKey: encodedKey,
                                                                    doubleEncodedKey: doubleEncodedKey
                                                                }, 'S3_DEBUG: Trying double-encoded key as last resort');

                                                                var doubleEncodedDeleteReq = Object.create(req);
                                                                doubleEncodedDeleteReq.params = {
                                                                    bucket_name: bucketName,
                                                                    object_name: doubleEncodedKey
                                                                };
                                                                doubleEncodedDeleteReq.method = 'DELETE';
                                                                doubleEncodedDeleteReq.url = '/' + bucketName + '/' + doubleEncodedKey;
                                                                doubleEncodedDeleteReq.conditions = {};

                                                                bucketHelpers.loadRequest(doubleEncodedDeleteReq, null, function(dblLoadErr) {
                                                                    if (!dblLoadErr) {
                                                                        bucketHelpers.getBucketIfExists(doubleEncodedDeleteReq, null, function(dblBucketErr) {
                                                                            if (!dblBucketErr) {
                                                                                deleteObjectFunc(doubleEncodedDeleteReq, null, function(dblDelErr, dblResult) {
                                                                                    completed++;

                                                                                    if (dblDelErr) {
                                                                                        req.log.debug({
                                                                                            error: dblDelErr.message,
                                                                                            objectKey: currentObjectKey,
                                                                                            triedKeys: [currentObjectKey, encodedKey, doubleEncodedKey]
                                                                                        }, 'S3_DEBUG: Failed to delete object with all encoding attempts');

                                                                                        errors.push({
                                                                                            Key: currentObjectKey,
                                                                                            Code: 'NoSuchKey',
                                                                                            Message: 'Object not found (tried multiple encodings)'
                                                                                        });
                                                                                    } else {
                                                                                        req.log.debug({
                                                                                            objectKey: currentObjectKey,
                                                                                            doubleEncodedKey: doubleEncodedKey
                                                                                        }, 'S3_DEBUG: Successfully deleted object using double-encoded key');

                                                                                        deleted.push({
                                                                                            Key: currentObjectKey
                                                                                        });
                                                                                    }

                                                                                    if (completed === objectKeys.length) {
                                                                                        sendDeleteResult();
                                                                                    }
                                                                                });
                                                                                return;
                                                                            }
                                                                        });
                                                                        return;
                                                                    }
                                                                });
                                                            }

                                                            // All encoding attempts failed
                                                            completed++;
                                                            req.log.debug({
                                                                objectKey: currentObjectKey,
                                                                triedKeys: [currentObjectKey, encodedKey, doubleEncodedKey]
                                                            }, 'S3_DEBUG: Object not found with any encoding attempt');

                                                            errors.push({
                                                                Key: currentObjectKey,
                                                                Code: 'NoSuchKey',
                                                                Message: 'Object not found (tried multiple encodings)'
                                                            });

                                                            if (completed === objectKeys.length) {
                                                                sendDeleteResult();
                                                            }
                                                        });
                                                        return;
                                                    }
                                                }

                                                completed++;

                                                if (encDelErr) {
                                                    req.log.debug({
                                                        error: encDelErr.message,
                                                        objectKey: currentObjectKey,
                                                        encodedKey: encodedKey
                                                    }, 'S3_DEBUG: Failed to delete object even with encoded key');

                                                    errors.push({
                                                        Key: currentObjectKey,
                                                        Code: encDelErr.restCode || 'InternalError',
                                                        Message: encDelErr.message || 'Failed to delete object'
                                                    });
                                                } else {
                                                    req.log.debug({
                                                        objectKey: currentObjectKey,
                                                        encodedKey: encodedKey
                                                    }, 'S3_DEBUG: Successfully deleted object using encoded key');

                                                    deleted.push({
                                                        Key: currentObjectKey
                                                    });
                                                }

                                                if (completed === objectKeys.length) {
                                                    sendDeleteResult();
                                                }
                                            });
                                        });
                                    });
                                    return;
                                } else {
                                    // Encoded key is same as original, no further attempts
                                    completed++;
                                    errors.push({
                                        Key: currentObjectKey,
                                        Code: delErr.restCode || 'NoSuchKey',
                                        Message: delErr.message || 'Object not found'
                                    });
                                    if (completed === objectKeys.length) {
                                        sendDeleteResult();
                                    }
                                }
                            } // End of tryEncodedVersions function
                            } else {
                                // Success case - original delete worked
                                completed++;
                                req.log.debug({
                                    objectKey: currentObjectKey
                                }, 'S3_DEBUG: Successfully deleted object');

                                deleted.push({
                                    Key: currentObjectKey
                                });

                                if (completed === objectKeys.length) {
                                    sendDeleteResult();
                                }
                            }
                        });
                    });
                });
            })(objectKey); // Pass the current objectKey to the closure
        });

        function sendDeleteResult() {
                // Build XML response
                var xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
                         '<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n';

                // Add deleted objects
                deleted.forEach(function(item) {
                    xml += '  <Deleted>\n';
                    xml += '    <Key>' + escapeXml(item.Key) + '</Key>\n';
                    xml += '  </Deleted>\n';
                });

                // Add error objects
                errors.forEach(function(item) {
                    xml += '  <Error>\n';
                    xml += '    <Key>' + escapeXml(item.Key) + '</Key>\n';
                    xml += '    <Code>' + escapeXml(item.Code) + '</Code>\n';
                    xml += '    <Message>' + escapeXml(item.Message) + '</Message>\n';
                    xml += '  </Error>\n';
                });

                xml += '</DeleteResult>';

                req.log.debug({
                    deletedCount: deleted.length,
                    errorCount: errors.length
                }, 'S3_DEBUG: Sending bulk delete response');

                res.setHeader('Content-Type', 'application/xml');
                res.send(200, xml);
                return next(false);
            }

        function escapeXml(str) {
            return str.replace(/[<>&'"]/g, function (c) {
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
    };
}

/* END JSSTYLED */

/**
 * S3 Set Bucket ACL Handler
 * Handles PUT /:bucket?acl requests (s3cmd setacl operations)
 */
function s3SetBucketACLHandler() {
    return function s3SetBucketACL(req, res, next) {
        req.log.debug({
            bucket: req.params.bucket,
            method: req.method,
            query: req.query
        }, 's3SetBucketACL: processing S3 set bucket ACL request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = req.params.bucket;

        // First, we need to parse the XML body if it exists to extract ACL
        // information
        if (req.body && req.body.length > 0) {
            // s3cmd sends XML body with ACL definitions
            // For now, we'll parse basic XML to extract permissions
            parseS3ACLFromXML(req, function (parseErr) {
                if (parseErr) {
                    req.log.warn(parseErr,
                       's3SetBucketACL: failed to parse XML ACL body');
                    // Continue with header-based ACL if XML parsing fails
                }
                processACLUpdate();
            });
        } else {
            // No XML body, process header-based ACL
            processACLUpdate();
        }

        function processACLUpdate() {
            // Apply S3 role translation middleware
            s3Compat.s3RoleTranslator(req, res, function (translationErr) {
                if (translationErr) {
                    next(translationErr);
                    return;
                }

                req.log.debug({
                    bucket: req.params.bucket,
                    translatedHeaders: {
                        'role-tag': req.headers['role-tag']
                    }
                }, 's3SetBucketACL: role translation completed');

                // Use createBucket but handle "already exists"
                // specially for ACL updates
                var mantaHandlerChain = buckets.createBucketHandler();
                executeMiddlewareChain(mantaHandlerChain, req, res,
                                       function (error) {
                    if (error && error.message &&
                        error.message.includes('already exists')) {
                        // Bucket already exists -
                        // this is expected for ACL updates
                        // Consider this success and return 200
                        req.log.debug({
                            bucket: req.params.bucket,
                            message: 'Bucket exists, ACL update completed'
                        }, 's3SetBucketACL: ACL update on existing bucket');
                        res.send(200);
                        next(false);
                    } else if (error) {
                        next(error);
                    } else {
                        // Return S3-compatible response
                        res.send(200);
                        next(false); // Stop route processing
                    }
                });
            });
        }
    };
}

/**
 * S3 Get Bucket ACL Handler
 * Handles GET /:bucket?acl requests
 */
function s3GetBucketACLHandler() {
    return function s3GetBucketACL(req, res, next) {
        req.log.debug({
            bucket: req.params.bucket
        }, 's3GetBucketACL: processing S3 get bucket ACL request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = req.params.bucket;

        // Simple approach: Just use the existing headBucket middleware but
        // skip successHandler
        var headBucket = require('./buckets/head');

        // Get the head bucket middleware chain
        var headBucketChain = headBucket.headBucketHandler();

        // Remove the last handler (successHandler) to avoid response conflict
        if (Array.isArray(headBucketChain)) {
            headBucketChain = headBucketChain.slice(0, -1);
            // Add our custom ACL response handler
            headBucketChain.push(function (req2, resp, nextstep) {
                // Extract roles from bucket metadata
                var roles = req2.bucket && req2.bucket.roles ?
                    req2.bucket.roles : [];
                var s3ACL = s3Compat.rolesToS3ACL(roles);

                req2.log.debug({
                    bucket: req2.params.bucket,
                    roles: roles,
                    s3ACL: s3ACL
                }, 's3GetBucketACL: converted roles to S3 ACL');

                // Generate S3 ACL XML response
                var aclXml = generateS3ACLXml(req2.caller.account.login, s3ACL);
                resp.setHeader('Content-Type', 'application/xml');
                resp.send(200, aclXml);
                nextstep(); // Continue to completion
            });
        } else {
            // If it's a single function, wrap it
            headBucketChain = [headBucketChain,
                               function (req2, resp, nextstep) {
                var roles = req2.bucket && req2.bucket.roles ?
                    req2.bucket.roles : [];
                var s3ACL = s3Compat.rolesToS3ACL(roles);

                req2.log.debug({
                    bucket: req2.params.bucket,
                    roles: roles,
                    s3ACL: s3ACL
                }, 's3GetBucketACL: converted roles to S3 ACL');

                var aclXml = generateS3ACLXml(req2.caller.account.login, s3ACL);
                resp.setHeader('Content-Type', 'application/xml');
                resp.send(200, aclXml);
                nextstep();
            }];
        }

        executeMiddlewareChain(headBucketChain, req, res, function (error) {
            if (error) {
                next(error);
            } else {
                // ACL response already sent, stop processing
                next(false);
            }
        });
    };
}

/**
 * Parse S3 ACL from XML body (sent by s3cmd setacl)
 * here we need to check for x-amz-acl, which means we need to apply a canned
 * ACL, the only one implemented today is public-read.
 * role-tag is a comma separated list of roles that we support.
 *
 * Reference:
 * https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
 */
function parseS3ACLFromXML(req, callback) {
    req.log.debug({
        hasBody: !!req.body,
        bodyLength: req.body ? req.body.length : 0,
        bodyType: typeof (req.body),
        contentLength: req.headers['content-length']
    }, 'parseS3ACLFromXML: entry point debugging');

    // If req.body is not available, try to read from the request stream
    if (!req.body || req.body.length === 0) {
        var contentLength = parseInt(req.headers['content-length'], 10);
        if (contentLength && contentLength > 0) {
            req.log.debug('parseS3ACLFromXML: reading body from request');
            var chunks = [];

            req.on('data', function (chunk) {
                chunks.push(chunk);
            });

            req.on('end', function () {
                var bodyBuffer = Buffer.concat(chunks);
                req.body = bodyBuffer;
                parseXMLBody();
            });

            req.on('error', function (err) {
                req.log.error(err,
                              'parseS3ACLFromXML: error reading request body');
                callback(err);
            });

            return;
        } else {
            req.log.debug('parseS3ACLFromXML' +
                          ': no body found, skipping XML parsing');
            callback(null);
            return;
        }
    }

    parseXMLBody();

    function parseXMLBody() {
        try {
            var xmlBody = req.body.toString();
            req.log.debug({
                xmlBody: xmlBody,
                bodyLength: req.body.length
            }, 'parseS3ACLFromXML: parsing XML ACL body');

            // Simple XML parsing for ACL permissions
            // Look for AllUsers read permission which indicates public-read
            var hasPublicRead = xmlBody.includes('AllUsers') &&
               (xmlBody.includes('<Permission>READ</Permission>') ||
               xmlBody.includes('<Permission>FULL_CONTROL</Permission>'));

            var hasPublicWrite = xmlBody.includes('AllUsers') &&
               xmlBody.includes('<Permission>WRITE</Permission>');

            var acl = 'private'; // default
            if (hasPublicRead && hasPublicWrite) {
                acl = 'public-read-write';
            } else if (hasPublicRead) {
                acl = 'public-read';
            }

            req.log.debug({
                acl: acl,
                hasPublicRead: hasPublicRead,
                hasPublicWrite: hasPublicWrite
            }, 'parseS3ACLFromXML: extracted ACL from XML');

            // Set the x-amz-acl header based on parsed XML
            req.headers['x-amz-acl'] = acl;

            req.log.debug({
                setAclHeader: acl,
                allHeadersAfterParsing: req.headers
            }, 'parseS3ACLFromXML: set x-amz-acl header');

            callback(null);
        } catch (err) {
            req.log.warn(err, 'parseS3ACLFromXML: error parsing XML');
            callback(err);
        }
    }
}

/**
 * Update object roles in metadata
 */
function updateObjectRoles(req, res, callback) {
    var owner = req.owner.account.uuid;
    var bucket = req.bucket;
    var bucketObject = req.bucketObject;
    var requestId = req.getId();
    var roleTags = req.headers['role-tag'];

    var log = req.log.child({
        method: 'updateObjectRoles',
        owner: owner,
        bucket: bucket.name,
        bucket_id: bucket.id,
        object: bucketObject.name,
        roleTags: roleTags,
        requestId: requestId
    });

    log.debug({
        originalRoleTags: roleTags,
        allHeaders: req.headers,
        method: req.method,
        query: req.query
    }, 'updateObjectRoles: requested - debugging headers');

    if (!roleTags) {
        log.debug('updateObjectRoles: no role-tag header, setting empty roles');
        roleTags = '';
    }

    // Convert role names to UUIDs using Mahi
    var roleNames = roleTags ? roleTags.split(',').map(function (role) {
        return (role.trim());
    }).filter(function (role) {
        return (role.length > 0);
    }) : [];

    log.debug({
        roleNames: roleNames
    }, 'updateObjectRoles: parsed role names');

    // Handle S3 ACL operations with smart role processing
    if (roleNames.length > 0) {
        // Separate system roles from user-defined roles
        var systemRoles = anonymousAuth.SYSTEM_ROLES;
        var systemRoleNames = [];
        var userRoleNames = [];

        roleNames.forEach(function (name) {
            if (systemRoles.indexOf(name) !== -1) {
                systemRoleNames.push(name);
            } else {
                userRoleNames.push(name);
            }
        });

        log.debug({
            allRoleNames: roleNames,
            systemRoleNames: systemRoleNames,
            userRoleNames: userRoleNames
        }, 'updateObjectRoles: separated system and user roles');

        // Start with system roles (stored as literal strings)
        var finalRoles = systemRoleNames.slice();

        // Convert user-defined roles to UUIDs if any exist
        if (userRoleNames.length > 0) {
            req.mahi.getUuid({
                account: req.owner.account.login,
                type: 'role',
                names: userRoleNames
            }, function (err, lookup) {
                if (err) {
                    log.error(err,
                       'updateObjectRoles: failed to resolve user role names');
                    callback(err);
                    return;
                }

                for (var i = 0; i < userRoleNames.length; i++) {
                    var roleName = userRoleNames[i];
                    if (!lookup.uuids[roleName]) {
                        var InvalidRoleTagError =
                            require('./errors').InvalidRoleTagError;
                        callback(new InvalidRoleTagError(roleName));
                        return;
                    }
                    finalRoles.push(lookup.uuids[roleName]);
                }

                log.debug({
                    systemRoleNames: systemRoleNames,
                    userRoleNames: userRoleNames,
                    resolvedUserUuids: Object.keys(lookup.uuids || {}),
                    finalRoles: finalRoles
                }, 'updateObjectRoles: resolved all roles');

                performObjectUpdate(finalRoles);
            });
        } else {
            // Only system roles, no UUID lookup needed
            log.debug({
                systemRoleNames: systemRoleNames,
                finalRoles: finalRoles
            }, 'updateObjectRoles: using only system roles');
            performObjectUpdate(finalRoles);
        }
    } else {
        // No roles to set - this handles private ACL (empty roles)
        // By default in manta objects are private, so removing the public-read
        // role just sets them up private again.
        log.debug('updateObjectRoles' +
                  ': no role names provided, setting empty roles (private)');
        performObjectUpdate([]);
    }

    function performObjectUpdate(roles) {
        var metadataLocation = req.metadataPlacement.getObjectLocation(owner,
            bucket.id, bucketObject.name_hash);
        var client =
            req.metadataPlacement.getBucketsMdapiClient(metadataLocation);

        // First get the existing object to preserve its content_type
        client.getObject(owner, bucket.id, bucketObject.name,
            metadataLocation.vnode, {}, requestId, function (getErr,
                                                            existingObject) {
            if (getErr) {
                log.error(getErr,
                          'updateObjectRoles: failed to get existing object');
                callback(getErr);
                return;
            }

            log.debug({
                existingContentType: existingObject.content_type,
                existingRoles: existingObject.properties ?
                    existingObject.properties.roles : existingObject.roles,
                existingObjectId: existingObject.id,
                newRoles: roles
            }, 'updateObjectRoles: got existing object metadata,' +
                      ' updating with new roles');

            // Update object with new roles, preserving existing
            // content_type and object_id
            client.updateObject(owner, bucket.id, bucketObject.name,
                existingObject.id, // preserve existing object ID
                existingObject.content_type, // preserve existing content type
                {}, // headers - empty object means don't change headers
                { roles: roles }, // properties - update roles
                metadataLocation.vnode,
                {}, // conditions - no conditions
                requestId,
                function (updateErr, updatedObject) {
                    if (updateErr) {
                        log.error(updateErr,
                                  'updateObjectRoles: failed to update object');
                        callback(updateErr);
                        return;
                    }

                    log.debug({
                        roles: roles,
                        updatedObject: updatedObject
                    }, 'updateObjectRoles: successfully updated object roles');

                    callback(null);
                });
        });
    }
}

/**
 * Generate S3-compatible ACL XML response
 */

/* BEGIN JSSTYLED */
function generateS3ACLXml(owner, acl) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<AccessControlPolicy>\n';
    xml += '  <Owner>\n';
    xml += '    <ID>' + owner + '</ID>\n';
    xml += '    <DisplayName>' + owner + '</DisplayName>\n';
    xml += '  </Owner>\n';
    xml += '  <AccessControlList>\n';

    // Owner always has FULL_CONTROL
    xml += '    <Grant>\n';
    xml += '      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">\n';
    xml += '        <ID>' + owner + '</ID>\n';
    xml += '        <DisplayName>' + owner + '</DisplayName>\n';
    xml += '      </Grantee>\n';
    xml += '      <Permission>FULL_CONTROL</Permission>\n';
    xml += '    </Grant>\n';

    // Add public permissions if present
    if (acl === 'public-read' || acl === 'public-read-write') {
        xml += '    <Grant>\n';
        xml += '      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">\n';
        xml += '        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\n';
        xml += '      </Grantee>\n';
        xml += '      <Permission>READ</Permission>\n';
        xml += '    </Grant>\n';
    }

    if (acl === 'public-read-write') {
        xml += '    <Grant>\n';
        xml += '      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">\n';
        xml += '        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\n';
        xml += '      </Grantee>\n';
        xml += '      <Permission>WRITE</Permission>\n';
        xml += '    </Grant>\n';
    }

    xml += '  </AccessControlList>\n';
    xml += '</AccessControlPolicy>\n';

    return xml;
}
/* END JSSTYLED */
/**
 * S3 Set Object ACL Handler
 * Handles PUT /:bucket/:object?acl requests
 */
function s3SetObjectACLHandler() {
    return function s3SetObjectACL(req, res, next) {
        var bucketName = req.params[0] || req.params.bucket;
        var objectPath = req.params[1] || req.params['*'] || '';

        req.log.debug({
            bucket: bucketName,
            object: objectPath,
            method: req.method,
            query: req.query
        }, 's3SetObjectACL: processing S3 set object ACL request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = bucketName;
        req.params.object_name = objectPath;

        // Parse XML ACL body if present
        req.log.debug({
            hasBody: !!req.body,
            bodyLength: req.body ? req.body.length : 0,
            contentLength: req.headers['content-length']
        }, 's3SetObjectACL: checking for XML body');

        // Always try to parse XML, regardless of req.body availability
        parseS3ACLFromXML(req, function (parseErr) {
            if (parseErr) {
                req.log.warn(parseErr,
                             's3SetObjectACL: failed to parse XML ACL body');
            }
            processObjectACLUpdate();
        });

        function processObjectACLUpdate() {
            // Apply S3 role translation middleware
            s3Compat.s3RoleTranslator(req, res, function (translationErr) {
                if (translationErr) {
                    next(translationErr);
                    return;
                }

                req.log.debug({
                    bucket: bucketName,
                    object: objectPath,
                    translatedHeaders: {
                        'role-tag': req.headers['role-tag']
                    }
                }, 's3SetObjectACL: role translation completed');

                // Update object metadata with roles using the updateObject API
                req.log.debug({
                    bucket: bucketName,
                    object: objectPath,
                    roleTags: req.headers['role-tag']
                }, 's3SetObjectACL: updating object metadata with roles');

                // Need to load bucket and object context first
                var loadChain = [
                    bucketHelpers.loadRequest,
                    bucketHelpers.getBucketIfExists
                ];

                executeMiddlewareChain(loadChain, req, res, function (loadErr) {
                    if (loadErr) {
                        req.log.error(loadErr,
                        's3SetObjectACL: failed to load bucket/object context');
                        next(loadErr);
                        return;
                    }

                    // Now call updateObjectRoles with proper context
                    updateObjectRoles(req, res, function (updateErr) {
                        if (updateErr) {
                            req.log.error(updateErr,
                              's3SetObjectACL: failed to update object roles');
                            next(updateErr);
                        } else {
                            req.log.debug({
                                bucket: bucketName,
                                object: objectPath
                            },
                          's3SetObjectACL: successfully updated object roles');
                            res.send(200);
                            next(false);
                        }
                    });
                });
            });
        }
    };
}

/**
 * S3 Get Object ACL Handler
 * Handles GET /:bucket/:object?acl requests
 */
function s3GetObjectACLHandler() {
    return function s3GetObjectACL(req, res, next) {
        var bucketName = req.params[0] || req.params.bucket;
        var objectPath = req.params[1] || req.params['*'] || '';

        req.log.debug({
            bucket: bucketName,
            object: objectPath
        }, 's3GetObjectACL: processing S3 get object ACL request');

        if (!req.caller || !req.caller.account) {
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = bucketName;
        req.params.object_name = objectPath;

        // Get object metadata to read roles
        var objectGet = require('./buckets/objects/get');
        var getObjectChain = objectGet.getBucketObjectHandler();

        // Remove streamFromSharks handler and replace with ACL response
        var metadataChain = getObjectChain.slice(0, -1); // Remove last handler
        metadataChain.push(function (req2, resp, nextstep) {
            // Extract roles from object metadata - roles are in
            // properties.roles as UUIDs
            var roleUuids = req2.metadata &&
                req2.metadata.properties && req2.metadata.properties.roles ?
                           req2.metadata.properties.roles : [];
            var s3ACL; // Declare once at function scope
            var aclXml; // Declare once at function scope

            req2.log.debug({
                bucket: bucketName,
                object: objectPath,
                roleUuids: roleUuids
            }, 's3GetObjectACL: found role UUIDs in metadata');

            // If no roles, return private ACL
            if (roleUuids.length === 0) {
                s3ACL = 'private';
                req2.log.debug({
                    bucket: bucketName,
                    object: objectPath,
                    roles: [],
                    s3ACL: s3ACL
                }, 's3GetObjectACL: no roles found, using private ACL');

                aclXml = generateS3ACLXml(req2.caller.account.login, s3ACL);
                resp.setHeader('Content-Type', 'application/xml');
                resp.send(200, aclXml);
                nextstep();
                return;
            }

            // Separate literal role names from UUIDs
            var systemRoles = anonymousAuth.SYSTEM_ROLES;
            var literalRoles = [];
            var uuidRoles = [];

            roleUuids.forEach(function (role) {
                if (systemRoles.indexOf(role) !== -1) {
                    literalRoles.push(role);
                } else {
                    uuidRoles.push(role);
                }
            });

            // If no UUIDs to resolve, process literal roles directly
            if (uuidRoles.length === 0) {
                s3ACL = s3Compat.rolesToS3ACL(literalRoles);

                req.log.debug({
                    bucket: bucketName,
                    object: objectPath,
                    literalRoles: literalRoles,
                    s3ACL: s3ACL
                }, 's3GetObjectACL: processed literal roles only');

                var objectAclXml =
                    generateS3ACLXml(req.caller.account.login, s3ACL);
                res.setHeader('Content-Type', 'application/xml');
                res.send(200, objectAclXml);
                next();
                return;
            }

            // Resolve role UUIDs to names using Mahi
            req.mahi.getName({
                account: req.caller.account.login,
                type: 'role',
                uuids: uuidRoles
            }, function (roleErr, roleNames) {
                if (roleErr) {
                    req.log.warn(roleErr,
                       's3GetObjectACL: failed to resolve role UUIDs');
                    // Use only literal roles if UUID resolution fails
                    s3ACL = s3Compat.rolesToS3ACL(literalRoles);
                    aclXml = generateS3ACLXml(req.caller.account.login, s3ACL);
                    res.setHeader('Content-Type', 'application/xml');
                    res.send(200, aclXml);
                    next();
                    return;
                }

                // Convert resolved role UUIDs to role names array
                var resolvedRoleNames = [];
                if (roleNames) {
                    Object.keys(roleNames).forEach(function (uuid) {
                        resolvedRoleNames.push(roleNames[uuid]);
                    });
                }

                // Combine literal and resolved roles
                var allRoleNames = literalRoles.concat(resolvedRoleNames);
                s3ACL = s3Compat.rolesToS3ACL(allRoleNames);

                req.log.debug({
                    bucket: bucketName,
                    object: objectPath,
                    roleUuids: uuidRoles,
                    literalRoles: literalRoles,
                    resolvedRoleNames: resolvedRoleNames,
                    allRoleNames: allRoleNames,
                    s3ACL: s3ACL
                }, 's3GetObjectACL: converted all roles to S3 ACL');

                // Generate S3 ACL XML response
                aclXml = generateS3ACLXml(req.caller.account.login, s3ACL);
                res.setHeader('Content-Type', 'application/xml');
                res.send(200, aclXml);
                next();
            });
        });

        executeMiddlewareChain(metadataChain, req, res, function (error) {
            if (error) {
                next(error);
            } else {
                // ACL response already sent, stop processing
                next(false);
            }
        });
    };
}

/**
 * S3 Copy Object Handler
 * Handles server-side copy operations using x-amz-copy-source header
 */
function s3CopyObjectHandler() {
    return function s3CopyObject(req, res, next) {
        var copySource = req.headers['x-amz-copy-source'];
        var destBucketName = req.params[0] || req.params.bucket;
        var destObjectPath = req.params[1] || req.params['*'] || '';

        req.log.debug({
            copySource: copySource,
            destBucket: destBucketName,
            destObject: destObjectPath
        }, 'S3_DEBUG: Processing server-side copy operation');

        // Parse copy source: /source-bucket/source-object
        // URL decode the copy source
        var decodedCopySource = decodeURIComponent(copySource);
        var sourceParts = decodedCopySource.replace(/^\//, '').split('/', 2);

        if (sourceParts.length !== 2) {
            var parseError = new Error('Invalid copy source format');
            parseError.statusCode = 400;
            next(parseError);
            return;
        }

        var sourceBucketName = sourceParts[0];
        var sourceObjectName = sourceParts[1];

        req.log.debug({
            sourceBucket: sourceBucketName,
            sourceObject: sourceObjectName,
            destBucket: destBucketName,
            destObject: destObjectPath
        }, 'S3_DEBUG: Parsed copy source and destination');

        if (!req.caller || !req.caller.account) {
            var authError = new Error('Authentication required');
            authError.statusCode = 401;
            next(authError);
            return;
        }

        // Set up destination object parameters for Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = destBucketName;
        req.params.object_name = destObjectPath;

        // Mark this as an S3 request
        req.isS3Request = true;

        // Use the copy object handler
        var copyObjectModule = require('./buckets/objects/copy');
        var copyHandlerChain = copyObjectModule.copyObjectHandler();
        executeMiddlewareChain(copyHandlerChain, req, res, function (error) {
            if (error) {
                next(error);
            } else {
                next(false); // Stop route processing
            }
        });
    };
}

///--- S3 Object Tagging Handlers

/**
 * PUT Object Tagging Handler - Sets tags on an object
 * https://docs.aws.amazon.com/cli/latest/reference/s3api/
 * put-object-tagging.html
 */
function s3PutObjectTaggingHandler() {
    return function s3PutObjectTagging(req, res, next) {
        var bucketName = req.params[0] || req.params.bucket;
        var objectPath = req.params[1] || req.params['*'] || '';

        req.log.debug({
            bucket: bucketName,
            object: objectPath
        }, 'S3_DEBUG: PUT Object tagging operation');

        if (!req.caller || !req.caller.account) {
            var authErr = new Error('Authentication required');
            authErr.statusCode = 401;
            next(authErr);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = bucketName;
        req.params.object_name = objectPath;

        // Parse tagging XML payload
        var body = '';
        req.on('data', function (chunk) {
            body += chunk.toString();
        });

        req.on('end', function () {
            // Debug: Log exactly what we received
            req.log.debug({
                rawBody: body,
                bodyLength: body.length,
                bodyType: typeof (body),
                bodyTrimmed: body.trim(),
                startsWithTagSet: body.trim().startsWith('TagSet='),
                startsWithXML: body.trim().startsWith('<'),
                containsTag: body.includes('<Tag>')
            }, 'S3_DEBUG: Raw tagging request body received');

            var tags;
            try {
                tags = s3Compat.parseTaggingXML(body);
            } catch (parseErr) {
                req.log.error(parseErr, 'Failed to parse tagging XML');
                var xmlError = new Error('Malformed XML');
                xmlError.statusCode = 400;
                xmlError.restCode = 'MalformedXML';
                next(xmlError);
                return;
            }

            req.log.debug({
                tags: tags,
                bodyContent: body,
                bodyLength: body.length,
                detectedFormat: body.trim().startsWith('TagSet=') ? 's3cmd' :
                              (body.trim().startsWith('<') ? 'xml' : 'unknown')
            }, 'S3_DEBUG: Parsed tagging payload');

            // Update object properties with tags
            updateObjectTagsInProperties(req, res, tags, function (err) {
                if (err) {
                    next(err);
                } else {
                    res.send(200);
                    next();
                }
            });
        });
    };
}

/**
 * GET Object Tagging Handler - Retrieves tags from an object
 * https://docs.aws.amazon.com/cli/latest/reference/s3api/
 * get-object-tagging.html
 */
function s3GetObjectTaggingHandler() {
    return function s3GetObjectTagging(req, res, next) {
        var bucketName = req.params[0] || req.params.bucket;
        var objectPath = req.params[1] || req.params['*'] || '';

        req.log.debug({
            bucket: bucketName,
            object: objectPath
        }, 'S3_DEBUG: GET Object tagging operation');

        if (!req.caller || !req.caller.account) {
            var authErr = new Error('Authentication required');
            authErr.statusCode = 401;
            next(authErr);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = bucketName;
        req.params.object_name = objectPath;

        // Get object tags from properties
        getObjectTagsFromProperties(req, res, function (err, tags) {
            if (err) {
                next(err);
            } else {
                // Convert tags to S3 XML format
                var xml = s3Compat.generateTaggingXML(tags);
                res.setHeader('Content-Type', 'application/xml');
                res.send(200, xml);
                next();
            }
        });
    };
}

/**
 * DELETE Object Tagging Handler - Removes all tags from an object
 */
function s3DeleteObjectTaggingHandler() {
    return function s3DeleteObjectTagging(req, res, next) {
        var bucketName = req.params[0] || req.params.bucket;
        var objectPath = req.params[1] || req.params['*'] || '';

        req.log.debug({
            bucket: bucketName,
            object: objectPath
        }, 'S3_DEBUG: DELETE Object tagging operation');

        if (!req.caller || !req.caller.account) {
            var authErr = new Error('Authentication required');
            authErr.statusCode = 401;
            next(authErr);
            return;
        }

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = bucketName;
        req.params.object_name = objectPath;

        // Remove all tags (set empty tags)
        updateObjectTagsInProperties(req, res, {}, function (err) {
            if (err) {
                next(err);
            } else {
                res.send(204); // No Content
                next();
            }
        });
    };
}

///--- S3 Tagging Utility Functions


/**
 * Update object tags in properties using mdapi (safe merge approach)
 */
function updateObjectTagsInProperties(req, res, tags, callback) {
    var owner = req.caller.account.uuid;

    // Load bucket and object context
    var loadChain = [
        bucketHelpers.loadRequest,
        bucketHelpers.getBucketIfExists,
        function loadObjectMetadata(loadReq, loadRes, next) {
            var metadataLocation = loadReq.metadataPlacement.getObjectLocation(
                loadReq.caller.account.uuid,
                loadReq.bucket.id,
                loadReq.bucketObject.name_hash);

            var client =
                loadReq.metadataPlacement.
                getBucketsMdapiClient(metadataLocation);

            client.getObject(
                loadReq.caller.account.uuid,
                loadReq.bucket.id,
                loadReq.bucketObject.name,
                metadataLocation.vnode,
                {},
                loadReq.getId(),
                function (err, existingObject) {
                    if (err) {
                        // Convert mdapi object not found error to proper
                        // S3 NoSuchKey error
                        if (err.name === 'ObjectNotFound' ||
                            err.restCode === 'ObjectNotFound') {
                            var s3Error =
                                new Error('The specified key does not exist.');
                            s3Error.statusCode = 404;
                            s3Error.restCode = 'NoSuchKey';
                            loadReq.log.debug({
                                originalError: err.message,
                                convertedError: s3Error.restCode
                            }, 'updateObjectTagsInProperties:' +
                               ' converted ObjectNotFound to NoSuchKey');
                            next(s3Error);
                        } else {
                            next(err);
                        }
                        return;
                    }

                    // Preserve existing properties and only update tags
                    var updatedProperties = existingObject.properties || {};
                    updatedProperties.tags = tags;

                    // Preserve existing headers (including metadata)
                    var preservedHeaders = existingObject.headers || {};

                    loadReq.log.debug({
                        existingTags: existingObject.properties ?
                            existingObject.properties.tags : 'none',
                        newTags: tags,
                        objectId: existingObject.id,
                        preservedProperties: Object.keys(updatedProperties),
                        preservedHeaders: Object.keys(preservedHeaders)
                    }, 'updateObjectTagsInProperties:' +
                       ' updating object tags safely with preserved headers');

                    // Update object with new tags in properties
                    // (headers preserved to maintain metadata)
                    client.updateObject(
                        owner,
                        loadReq.bucket.id,
                        loadReq.bucketObject.name,
                        existingObject.id,
                        existingObject.content_type,
                        preservedHeaders, // keep existing headers + metadata
                        updatedProperties, // Only update properties.tags
                        metadataLocation.vnode,
                        {},
                        loadReq.getId(),
                        function (updateErr) {
                            if (updateErr) {
                                loadReq.log.error(updateErr,
                                    'Failed to update object tags');
                            } else {
                                loadReq.log.debug({
                                    tags: tags
                                }, 'Successfully updated' +
                                   ' object tags in properties');
                            }
                            next(updateErr);
                        });
                });
        }];

    // Execute the chain
    var currentIndex = 0;
    function executeNext(err) {
        if (err || currentIndex >= loadChain.length) {
            callback(err);
            return;
        }

        var currentHandler = loadChain[currentIndex++];
        currentHandler(req, res, executeNext);
    }

    executeNext();
}

/**
 * Get object tags from properties using mdapi
 */
function getObjectTagsFromProperties(req, res, callback) {

    // Load bucket and object context
    var loadChain = [
        bucketHelpers.loadRequest,
        bucketHelpers.getBucketIfExists,
        function getObjectMetadata(loadReq, loadRes, next) {
            var metadataLocation = loadReq.metadataPlacement.getObjectLocation(
                loadReq.caller.account.uuid,
                loadReq.bucket.id,
                loadReq.bucketObject.name_hash);

            var client =
                loadReq.metadataPlacement.
                getBucketsMdapiClient(metadataLocation);

            client.getObject(
                loadReq.caller.account.uuid,
                loadReq.bucket.id,
                loadReq.bucketObject.name,
                metadataLocation.vnode,
                {},
                loadReq.getId(),
                function (err, existingObject) {
                    if (err) {
                        // Convert mdapi object not found error to proper S3
                        // NoSuchKey error
                        if (err.name === 'ObjectNotFound' ||
                            err.restCode === 'ObjectNotFound') {
                            var s3Error =
                                new Error('The specified key does not exist.');
                            s3Error.statusCode = 404;
                            s3Error.restCode = 'NoSuchKey';
                            loadReq.log.debug({
                                originalError: err.message,
                                convertedError: s3Error.restCode
                            }, 'getObjectTagsFromProperties:' +
                               ' converted ObjectNotFound to NoSuchKey');
                            next(s3Error);
                        } else {
                            next(err);
                        }
                        return;
                    }

                    var tags = (existingObject.properties &&
                                existingObject.properties.tags) || {};

                    loadReq.log.debug({
                        tags: tags,
                        hasProperties: !!existingObject.properties
                    }, 'getObjectTagsFromProperties: ' +
                       'retrieved object tags from properties');

                    callback(null, tags);
                });
        }
    ];

    // Execute the chain
    var currentIndex = 0;
    function executeNext(err) {
        if (err) {
            callback(err);
            return;
        }

        if (currentIndex >= loadChain.length) {
            return; // Chain completed
        }

        var currentHandler = loadChain[currentIndex++];
        currentHandler(req, res, executeNext);
    }

    executeNext();
}

///--- Exports

module.exports = {
    s3ListBucketsHandler: s3ListBucketsHandler,
    s3CreateBucketHandler: s3CreateBucketHandler,
    s3ListBucketObjectsHandler: s3ListBucketObjectsHandler,
    s3ListBucketObjectsV2Handler: s3ListBucketObjectsV2Handler,
    s3HeadBucketHandler: s3HeadBucketHandler,
    s3DeleteBucketHandler: s3DeleteBucketHandler,
    s3DeleteBucketObjectsHandler: s3DeleteBucketObjectsHandler,
    s3SetBucketACLHandler: s3SetBucketACLHandler,
    s3GetBucketACLHandler: s3GetBucketACLHandler,
    s3CreateBucketObjectHandler: s3CreateBucketObjectHandler,
    s3GetBucketObjectHandler: s3GetBucketObjectHandler,
    s3HeadBucketObjectHandler: s3HeadBucketObjectHandler,
    s3DeleteBucketObjectHandler: s3DeleteBucketObjectHandler,
    s3SetObjectACLHandler: s3SetObjectACLHandler,
    s3GetObjectACLHandler: s3GetObjectACLHandler,
    s3CopyObjectHandler: s3CopyObjectHandler,
    // S3 Object Tagging handlers
    s3PutObjectTaggingHandler: s3PutObjectTaggingHandler,
    s3GetObjectTaggingHandler: s3GetObjectTaggingHandler,
    s3DeleteObjectTaggingHandler: s3DeleteObjectTaggingHandler,
    // S3 Multipart Upload handlers
    s3InitiateMultipartUploadHandler:
    s3Multipart.s3InitiateMultipartUploadHandler,
    s3UploadPartHandler: s3Multipart.s3UploadPartHandler,
    s3CompleteMultipartUploadHandler:
    s3Multipart.s3CompleteMultipartUploadHandler,
    s3AbortMultipartUploadHandler: s3Multipart.s3AbortMultipartUploadHandler,
    s3ListPartsHandler: s3Multipart.listPartsHandler,
    s3ResumeUploadHandler: s3Multipart.resumeUploadHandler
};
