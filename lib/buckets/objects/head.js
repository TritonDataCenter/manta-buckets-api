/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

var auth = require('../../auth');
var buckets = require('../buckets');
var common = require('../../common');

var translateBucketError = require('../common').translateBucketError;

/*
 * A HeadBucketObject request is made up of the following RPC:
 *
 *     - getobject
 *
 * The following conditional headers are passed to this RPC:
 *
 *     - If-Match
 *     - If-Unmodified-Since
 *
 * The remainder of the supported conditional headers are as follows and are
 * handled here in buckets-api:
 *
 *     - If-None-Match
 *     - If-Modified-Since
 *
 * See lib/buckets/objects/get.js for the reasoning behind this.
 */
function headObject(req, res, next) {
    var owner = req.owner.account.uuid;
    var bucket = req.bucket;
    var bucketObject = req.bucketObject;
    var requestId = req.getId();

    var log = req.log.child({
        method: 'headBucketObject',
        owner: owner,
        bucket: bucket.name,
        bucket_id: bucket.id,
        object: bucketObject.name,
        requestId: requestId
    });

    log.debug('headBucketObject: requested');

    var onGetObject = function onGet(err, object_data) {
        if (err) {
            err = translateBucketError(req, err);

            log.debug({
                err: err,
                owner: owner,
                bucket: bucket.name,
                bucket_id: bucket.id,
                object: bucketObject.name
            }, 'headObject: error reading object metadata');

            next(err);
            return;
        }

        log.debug({
            owner: owner,
            bucket: bucket.name,
            bucket_id: bucket.id,
            object: bucketObject.name
        }, 'headObject: done');

        req.metadata = object_data;
        req.metadata.type = 'bucketobject';
        req.metadata.objectId = object_data.id;
        req.metadata.contentMD5 = object_data.content_md5;
        req.metadata.contentLength = object_data.content_length;
        req.metadata.contentType = object_data.content_type;
        req.metadata.storageLayoutVersion =
            object_data.storage_layout_version ||
            common.CURRENT_STORAGE_LAYOUT_VERSION;

        // Add other needed response headers
        res.set('Etag', object_data.id);
        res.set('Last-Modified', new Date(object_data.modified));
        res.set('Durability-Level', object_data.sharks.length);
        res.set('Content-Length', object_data.content_length);
        res.set('Content-MD5', object_data.content_md5);
        res.set('Content-Type', object_data.content_type);

        Object.keys(object_data.headers).forEach(function (k) {
            if (/^m-\w+/.test(k)) {
                res.set(k, object_data.headers[k]);
            }
        });

        next();
    };

    var metadataLocation = req.metadataPlacement.getObjectLocation(owner,
        bucket.id, bucketObject.name_hash);
    var client = req.metadataPlacement.getBucketsMdapiClient(metadataLocation);

    var conditions = {};
    conditions['if-match'] = req.conditions['if-match'];
    conditions['if-unmodified-since'] = req.conditions['if-unmodified-since'];

    client.getObject(owner, bucket.id, bucketObject.name,
        metadataLocation.vnode, conditions, requestId, onGetObject);
}

module.exports = {

    headBucketObjectHandler: function headBucketObjectHandler() {
        var chain = [
            buckets.loadRequest,
            buckets.getBucketIfExists,
            headObject,
            auth.authorizationHandler(),
            buckets.conditionalHandler,
            buckets.successHandler
        ];
        return (chain);
    }

};
