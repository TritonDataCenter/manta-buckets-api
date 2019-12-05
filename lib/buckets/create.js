/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

var auth = require('../auth');
var buckets = require('./buckets');
var common = require('./common');
var errors = require('../errors');

function createBucket(req, res, next) {

    var owner = req.owner.account.uuid;
    var bucket = req.bucket;
    var log = req.log;
    var requestId = req.getId();

    log.debug({
        owner: owner,
        bucket: bucket.name
    }, 'createBucket: entered');

    if (!common.isValidBucketName(bucket.name)) {
        next(new errors.InvalidBucketNameError(bucket.name));
        return;
    }

    var onCreateBucket = function onCreate(err, bucket_data) {
        if (bucket_data !== undefined && bucket_data._node) {
            // Record the name of the shard and vnode contacted.
            req.entryShard = bucket_data._node.pnode;
            req.entryVnode = bucket_data._node.vnode;
        }

        if (err) {
            err = common.translateBucketError(req, err);

            log.debug({
                err: err,
                owner: owner,
                bucket: bucket.name
            }, 'createBucket: error creating bucket');

            next(err);
            return;
        }

        log.debug({
            owner: owner,
            bucket: bucket.name,
            data: bucket_data
        }, 'createBucket: done');
        res.send(204, bucket_data);
        next(null, bucket_data);
    };

    var metadataLocation =
        req.metadataPlacement.getBucketLocation(owner, bucket.name);
    var client = req.metadataPlacement.getBorayClient(metadataLocation);

    client.createBucket(owner, bucket.name, metadataLocation.vnode, requestId,
        onCreateBucket);
}

module.exports = {

    createBucketHandler: function createBucketHandler() {
        var chain = [
            buckets.loadRequest,
            auth.authorizationHandler(),
            createBucket
        ];
        return (chain);
    }

};
