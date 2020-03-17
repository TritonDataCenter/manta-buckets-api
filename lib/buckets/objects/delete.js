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
var common = require('../common');

var translateBucketError = require('../common').translateBucketError;

/*
 * A DeleteBucketObject request is made up of the following RPC:
 *
 *     - deleteobject
 *
 * The following conditional headers are passed to this RPC:
 *
 *     - If-Match
 *     - If-Unmodified-Since
 *     - If-None-Match
 *
 * Note: If-Modified-Since is not supported for DeleteBucketObject requests.
 */
function deleteObject(req, res, next) {
    var owner = req.owner.account.uuid;
    var bucket = req.bucket;
    var bucketObject = req.bucketObject;
    var requestId = req.getId();

    var log = req.log.child({
        method: 'deleteBucketObject',
        owner: owner,
        bucket: bucket.name,
        bucket_id: bucket.id,
        object: bucketObject.name,
        request_id: requestId
    });

    log.debug('deleteBucketObject: requested');

    var onObjectDelete = function onDelete(err, object_data) {
        if (err) {
            err = translateBucketError(req, err);

            log.debug(err, 'deleteBucketObject: error deleting object');

            next(err);
            return;
        }

        log.debug({
            metadata: object_data
        }, 'deleteBucketObject: done');

        req.deletedObjects = object_data;
        next(null, object_data);
    };

    var conditions = {};
    conditions['if-match'] = req.conditions['if-match'];
    conditions['if-none-match'] = req.conditions['if-none-match'];
    conditions['if-unmodified-since'] = req.conditions['if-unmodified-since'];

    var metadataLocation = req.metadataPlacement.getObjectLocation(owner,
        bucket.id, bucketObject.name_hash);
    var client = req.metadataPlacement.getBucketsMdapiClient(metadataLocation);

    client.deleteObject(owner, bucket.id, bucketObject.name,
        metadataLocation.vnode, req.conditions, requestId, onObjectDelete);
}

module.exports = {

    deleteBucketObjectHandler: function deleteBucketObjectHandler() {
        var chain = [
            buckets.loadRequest,
            buckets.getBucketIfExists,
            auth.authorizationHandler(),
            deleteObject,
            buckets.successHandler
        ];
        return (chain);
    }

};
