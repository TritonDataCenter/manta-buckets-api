/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var assert = require('assert-plus');
var buckets = require('./buckets');
var bucketHelpers = require('./buckets/buckets');

// Import S3 compatibility functions
var s3Compat = require('./s3-compat');

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

///--- S3 Route Handlers

/**
 * Add S3-compatible routes to the server
 * These routes handle S3-style paths and convert them to Manta format
 */
function addS3Routes(server) {
    assert.object(server, 'server');

    // S3 Root - List Buckets
    // GET / -> GET /:account/buckets
    server.get({
        path: '/',
        name: 'S3ListBuckets'
    }, s3ListBucketsHandler());

    // S3 Bucket Operations

    // Note: S3 requests are handled directly by server.js, not through these
    // routes. The ACL detection logic is now in the individual handler
    // functions

    // HEAD /:bucket -> HEAD /:account/buckets/:bucket
    server.head({
        path: '/:bucket',
        name: 'S3HeadBucket'
    }, s3HeadBucketHandler());

    // DELETE /:bucket -> DELETE /:account/buckets/:bucket
    server.del({
        path: '/:bucket',
        name: 'S3DeleteBucket'
    }, s3DeleteBucketHandler());


    // S3 Object Operations

    // PUT /:bucket/:object -> PUT /:account/buckets/:bucket/objects/:object
    server.put({
        path: new RegExp('^/([^/]+)/(.+)$'),
        name: 'S3CreateBucketObject',
        contentType: '*/*'
    }, s3CreateBucketObjectHandler());

    // GET /:bucket/:object -> GET /:account/buckets/:bucket/objects/:object
    server.get({
        path: new RegExp('^/([^/]+)/(.+)$'),
        name: 'S3GetBucketObject'
    }, s3GetBucketObjectHandler());

    // HEAD /:bucket/:object -> HEAD /:account/buckets/:bucket/objects/:object
    server.head({
        path: new RegExp('^/([^/]+)/(.+)$'),
        name: 'S3HeadBucketObject'
    }, s3HeadBucketObjectHandler());

    // DELETE /:bucket/:object ->
    // DELETE /:account/buckets/:bucket/objects/:object
    server.del({
        path: new RegExp('^/([^/]+)/(.+)$'),
        name: 'S3DeleteBucketObject'
    }, s3DeleteBucketObjectHandler());
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
            // Restore original functions
            res.write = originalWrite;
            res.end = originalEnd;

            req.log.debug({
                bucketCount: bucketData.length,
                buckets: bucketData.map(function (b) { return b.name; }),
                bucketData: bucketData
            }, 'S3_DEBUG: s3ListBuckets -'+
            ' collected all buckets, sending S3 response with status 200');

            // Send collected data via res.send() so S3 formatter
            // can convert to XML
            res.send(200, bucketData);
        };

        // Call the original Manta buckets list handler
        var mantaHandlerChain = buckets.listBucketsHandler();
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

        // Check if this is an ACL operation
        req.log.debug({
            hasQuery: !!req.query,
            query: req.query,
            hasAcl: req.query && req.query.acl !== undefined,
            aclValue: req.query ? req.query.acl : 'no-query'
        }, 'S3_DEBUG: Checking for ACL operation');

        if (req.query && req.query.acl !== undefined) {
            req.log.debug({
                bucket: bucketName,
                object: objectPath,
                query: req.query
            }, 'S3_DEBUG: PUT Object ACL operation detected');
            s3SetObjectACLHandler()(req, res, next);
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
        if (req.headers['content-type'] &&
        req.headers['content-type'].indexOf('image/') === 0) {
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

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = bucketName;
        req.params.object_name = objectPath;

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

        // Convert S3 parameters to Manta format
        req.params.account = req.caller.account.login;
        req.params.bucket_name = bucketName;
        req.params.object_name = objectPath;

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
        var systemRoles = ['public-read', 'public-writer',
                           'authenticated-reader', 'owner-reader',
                           'owner-full-control', 'log-writer'];
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
            var systemRoles = ['public-read', 'public-writer',
                               'authenticated-reader', 'owner-reader',
                               'owner-full-control', 'log-writer'];
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

///--- Exports

module.exports = {
    addS3Routes: addS3Routes,
    s3ListBucketsHandler: s3ListBucketsHandler,
    s3CreateBucketHandler: s3CreateBucketHandler,
    s3ListBucketObjectsHandler: s3ListBucketObjectsHandler,
    s3ListBucketObjectsV2Handler: s3ListBucketObjectsV2Handler,
    s3HeadBucketHandler: s3HeadBucketHandler,
    s3DeleteBucketHandler: s3DeleteBucketHandler,
    s3SetBucketACLHandler: s3SetBucketACLHandler,
    s3GetBucketACLHandler: s3GetBucketACLHandler,
    s3CreateBucketObjectHandler: s3CreateBucketObjectHandler,
    s3GetBucketObjectHandler: s3GetBucketObjectHandler,
    s3HeadBucketObjectHandler: s3HeadBucketObjectHandler,
    s3DeleteBucketObjectHandler: s3DeleteBucketObjectHandler,
    s3SetObjectACLHandler: s3SetObjectACLHandler,
    s3GetObjectACLHandler: s3GetObjectACLHandler
};
