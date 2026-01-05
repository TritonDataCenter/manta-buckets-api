/*
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * routes.js: Route registration for traditional Manta bucket operations.
 *
 * Provides functions for:
 * - Traditional Manta bucket routes (non-S3)
 * - Method not allowed handler (405)
 */

var buckets = require('../buckets');


///--- Functions

/**
 * Handler for routes that should return 405 Method Not Allowed.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Restify next callback
 */
function methodNotAllowHandler(req, res, next) {
    req.log.debug('Method ' + req.method + ' disallowed for ' + req.url);
    res.send(405);
    next(false);
}


/**
 * Register traditional Manta bucket routes (non-S3).
 * Adds routes for:
 * - Listing buckets
 * - Creating a bucket
 * - Getting/heading a bucket
 * - Deleting a bucket
 * - Listing objects in a bucket
 * - Creating an object inside a bucket
 * - Getting/heading/deleting an object from a bucket
 * - Updating object metadata
 * - CORS preflight OPTIONS handlers
 * - Method not allowed handlers for invalid operations
 *
 * @param {Object} server - Restify server instance
 */
function addBucketsRoutes(server) {

    server.get({
        path: '/:account/buckets',
        name: 'ListBuckets'
    }, buckets.listBucketsHandler());

    server.opts({
        path: '/:account/buckets',
        name: 'OptionsBuckets'
    }, buckets.optionsBucketsHandler());

    server.put({
        path: '/:account/buckets/:bucket_name',
        name: 'CreateBucket',
        contentType: '*/*'
    }, buckets.createBucketHandler());

    server.head({
        path: '/:account/buckets/:bucket_name',
        name: 'HeadBucket'
    }, buckets.headBucketHandler());

    server.del({
        path: '/:account/buckets/:bucket_name',
        name: 'DeleteBucket'
    }, buckets.deleteBucketHandler());

    server.get({
        path: '/:account/buckets/:bucket_name/objects',
        name: 'ListBucketObjects'
    }, buckets.listBucketObjectsHandler());

    server.put({
        path: '/:account/buckets/:bucket_name/objects/:object_name',
        name: 'CreateBucketObject',
        contentType: '*/*'
    }, buckets.createBucketObjectHandler());

    // NOTE: GetBucketObject route moved to priority position before
    // generic regex routes
    // server.get({
    //     path: '/:account/buckets/:bucket_name/objects/:object_name',
    //     name: 'GetBucketObject'
    // }, buckets.getBucketObjectHandler());

    server.head({
        path: '/:account/buckets/:bucket_name/objects/:object_name',
        name: 'HeadBucketObject'
    }, buckets.headBucketObjectHandler());

    server.del({
        path: '/:account/buckets/:bucket_name/objects/:object_name',
        name: 'DeleteBucketObject'
    }, buckets.deleteBucketObjectHandler());

    // OPTIONS support for CORS preflight requests
    server.opts({
        path: '/:account/buckets/:bucket_name/objects/:object_name',
        name: 'OptionsObject'
    }, buckets.optionsBucketObjectHandler());

    server.put({
        path: '/:account/buckets/:bucket_name/objects/:object_name/metadata',
        name: 'UpdateBucketObjectMetadata',
        contentType: '*/*'
    }, buckets.updateBucketObjectMetadataHandler());

    server.post({
        path: '/:account/buckets',
        name: 'PostBuckets'
    }, methodNotAllowHandler);

    server.put({
        path: '/:account/buckets',
        name: 'PutBuckets'
    }, methodNotAllowHandler);

    server.head({
        path: '/:account/buckets',
        name: 'PutBuckets'
    }, methodNotAllowHandler);

    server.del({
        path: '/:account/buckets',
        name: 'DeleteBuckets'
    }, methodNotAllowHandler);

    server.post({
        path: '/:account/buckets/:bucket_name/objects',
        name: 'PostBucketObjects'
    }, methodNotAllowHandler);

    server.put({
        path: '/:account/buckets/:bucket_name/objects',
        name: 'PutBucketObjects'
    }, methodNotAllowHandler);

    server.head({
        path: '/:account/buckets/:bucket_name/objects',
        name: 'HeadBucketObjects'
    }, methodNotAllowHandler);

    server.del({
        path: '/:account/buckets/:bucket_name/objects',
        name: 'DeleteBucketObjects'
    }, methodNotAllowHandler);

    server.head({
        path: '/:account/buckets/:bucket_name/objects/:object_name/metadata',
        name: 'HeadBucketObjectMetadata'
    }, methodNotAllowHandler);

    server.post({
        path: '/:account/buckets/:bucket_name/objects/:object_name/metadata',
        name: 'PostBucketObjectMetadata'
    }, methodNotAllowHandler);

    server.del({
        path: '/:account/buckets/:bucket_name/objects/:object_name/metadata',
        name: 'DeleteBucketObjectMetadata'
    }, methodNotAllowHandler);

}


///--- Exports

module.exports = {
    methodNotAllowHandler: methodNotAllowHandler,
    addBucketsRoutes: addBucketsRoutes
};
