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
 * A GetBucketObject request is made up of the following RPC:
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
 * The reason for this is because in the case of precondition failure in the
 * latter headers, we don't want to respond with a 412 but with a 304, and this
 * 304 response still requires some portion of the object's metadata to
 * formulate (i.e. ETag and Last-Modified).
 */
function getObject(req, res, next) {
    var owner = req.owner.account.uuid;
    var bucket = req.bucket;
    var bucketObject = req.bucketObject;
    var requestId = req.getId();

    var log = req.log.child({
        method: 'getBucketObject',
        owner: owner,
        bucket: bucket.name,
        bucket_id: bucket.id,
        object: bucketObject.name,
        requestId: requestId
    });

    log.debug('getBucketObject: requested');

    function onGetObject(err, object_data) {
        if (err) {
            err = translateBucketError(req, err);

            log.debug(err, 'getBucketObject: error reading object metadata');

            next(err);
            return;
        }

        log.debug({
            metadata: object_data
        }, 'getBucketObject: done');

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

        next(null, object_data);
    }

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

    getBucketObjectHandler: function getBucketObjectHandler() {
        var chain = [
            buckets.loadRequest,
            buckets.getBucketIfExists,
            getObject,
            auth.authorizationHandler(),
            buckets.conditionalHandler,
            common.streamFromSharks
        ];
        return (chain);
    }
};
