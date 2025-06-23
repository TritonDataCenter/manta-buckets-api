/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 MNX Cloud, Inc.
 */

var assert = require('assert-plus');
var buckets = require('./buckets');

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
        } else if (typeof item === 'function') {
            flatChain.push(item);
        } else {
            req.log.warn({
                itemType: typeof item,
                item: item
            }, 'S3_DEBUG: executeMiddlewareChain - unexpected item type in chain');
        }
    }
    chain.forEach(flatten);
    
    var currentIndex = 0;
    
    req.log.info({
        originalChainLength: chain.length,
        flatChainLength: flatChain.length,
        chainHandlers: flatChain.map(function(h) { return h.name || 'anonymous'; })
    }, 'S3_DEBUG: executeMiddlewareChain - starting execution');
    
    function runNext(err) {
        if (err) {
            req.log.error(err, 'S3_DEBUG: executeMiddlewareChain - error in middleware');
            next(err);
            return;
        }
        
        if (currentIndex >= flatChain.length) {
            req.log.info('S3_DEBUG: executeMiddlewareChain - completed all handlers');
            next();
            return;
        }
        
        var currentHandler = flatChain[currentIndex];
        req.log.info({
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
    
    // PUT /:bucket -> PUT /:account/buckets/:bucket
    server.put({
        path: '/:bucket',
        name: 'S3CreateBucket',
        contentType: '*/*'
    }, s3CreateBucketHandler());
    
    // GET /:bucket -> GET /:account/buckets/:bucket/objects  
    server.get({
        path: '/:bucket',
        name: 'S3ListBucketObjects'
    }, s3ListBucketObjectsHandler());
    
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
    
    // DELETE /:bucket/:object -> DELETE /:account/buckets/:bucket/objects/:object
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
        req.log.info({
            caller: req.caller ? {
                login: req.caller.account ? req.caller.account.login : 'no-account',
                uuid: req.caller.account ? req.caller.account.uuid : 'no-uuid'
            } : 'no-caller'
        }, 'S3_DEBUG: s3ListBuckets - processing S3 list buckets request');
        
        // Ensure we have authentication context
        if (!req.caller || !req.caller.account) {
            req.log.error('S3_DEBUG: s3ListBuckets - Authentication required, no caller or account');
            var err = new Error('Authentication required');
            err.statusCode = 401;
            next(err);
            return;
        }
        
        // Set up Manta-style parameters
        req.params.account = req.caller.account.login;
        req.log.info({
            account: req.params.account
        }, 'S3_DEBUG: s3ListBuckets - calling Manta listBucketsHandler');
        
        // Intercept the response to collect bucket data for S3 XML formatting
        var originalWrite = res.write;
        var originalEnd = res.end;
        var bucketData = [];
        
        res.write = function(chunk) {
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
        
        res.end = function() {
            // Restore original functions
            res.write = originalWrite;
            res.end = originalEnd;
            
            req.log.info({
                bucketCount: bucketData.length,
                buckets: bucketData.map(function(b) { return b.name; }),
                bucketData: bucketData
            }, 'S3_DEBUG: s3ListBuckets - collected all buckets, sending S3 response with status 200');
            
            // Send collected data via res.send() so S3 formatter can convert to XML
            res.send(200, bucketData);
        };
        
        // Call the original Manta buckets list handler
        var mantaHandlerChain = buckets.listBucketsHandler();
        executeMiddlewareChain(mantaHandlerChain, req, res, next);
    };
}

/**
 * S3 Create Bucket Handler
 */
function s3CreateBucketHandler() {
    return function s3CreateBucket(req, res, next) {
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
        executeMiddlewareChain(mantaHandlerChain, req, res, next);
    };
}

/**
 * S3 List Bucket Objects Handler
 */
function s3ListBucketObjectsHandler() {
    return function s3ListBucketObjects(req, res, next) {
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
        executeMiddlewareChain(mantaHandlerChain, req, res, next);
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
        executeMiddlewareChain(mantaHandlerChain, req, res, next);
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
        executeMiddlewareChain(mantaHandlerChain, req, res, next);
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
        
        req.log.debug({
            bucket: bucketName,
            object: objectPath
        }, 's3CreateBucketObject: processing S3 create object request');
        
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
        
        // Call the original Manta create object handler
        var mantaHandlerChain = buckets.createBucketObjectHandler();
        executeMiddlewareChain(mantaHandlerChain, req, res, next);
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
        executeMiddlewareChain(mantaHandlerChain, req, res, next);
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
        executeMiddlewareChain(mantaHandlerChain, req, res, next);
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
        executeMiddlewareChain(mantaHandlerChain, req, res, next);
    };
}

///--- Exports

module.exports = {
    addS3Routes: addS3Routes,
    s3ListBucketsHandler: s3ListBucketsHandler,
    s3CreateBucketHandler: s3CreateBucketHandler,
    s3ListBucketObjectsHandler: s3ListBucketObjectsHandler,
    s3HeadBucketHandler: s3HeadBucketHandler,
    s3DeleteBucketHandler: s3DeleteBucketHandler,
    s3CreateBucketObjectHandler: s3CreateBucketObjectHandler,
    s3GetBucketObjectHandler: s3GetBucketObjectHandler,
    s3HeadBucketObjectHandler: s3HeadBucketObjectHandler,
    s3DeleteBucketObjectHandler: s3DeleteBucketObjectHandler
};