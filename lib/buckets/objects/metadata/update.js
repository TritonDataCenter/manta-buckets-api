/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

var auth = require('../../../auth');
var buckets = require('../../buckets');
var uuidv4 = require('uuid/v4');

var translateBucketError = require('../../common').translateBucketError;

/*
 * An UpdateBucketObjectMetadata request is made up of the following RPC:
 *
 *     - updateobject
 *
 * The following conditional headers are passed to this RPC:
 *
 *     - If-Match
 *     - If-None-Match
 *     - If-Unmodified-Since
 *
 * Note: If-Modified-Since is not supported for UpdateBucketObjectMetadata
 * requests.
 */
function updateObjectMetadata(req, res, next) {
    var owner = req.owner.account.uuid;
    var bucket = req.bucket;
    var bucketObject = req.bucketObject;
    var objectId = uuidv4();
    var type = bucket.type;
    var props = {};
    var requestId = req.getId();

    var log = req.log.child({
        method: 'createBucketObject',
        owner: owner,
        bucket_name: bucket.name,
        bucket_id: bucket.id,
        object: bucketObject.name,
        request_id: requestId
    });

    log.debug('createBucketObject: requested');

    buckets.createObjectMetadata(req, type,
        function onCreateMetadata(createErr, object_data) {

        if (createErr) {
            createErr = translateBucketError(req, createErr);
            next(createErr);
            return;
        }

        log.debug({
            metadata: object_data
        }, 'onCreateMetadata: entered');

        var onUpdateObject = function onUpdate(createErr2, response_data) {
            if (response_data !== undefined && response_data._node) {
                // Record the name of the shard and vnode contacted.
                req.entryShard = response_data._node.pnode;
                req.entryVnode = response_data._node.vnode;
            }

            if (createErr2) {
                createErr2 = translateBucketError(req, createErr2);
                log.debug(createErr2, 'createBucketObject: failed');
                next(createErr2);
            } else {
                log.debug({
                    bucket: bucketObject.bucket_name,
                    object: bucketObject.name
                }, 'createBucketObject: done');
                if (req.headers['origin']) {
                    res.header('Access-Control-Allow-Origin',
                               req.headers['origin']);
                }
                res.header('Etag', response_data.id);
                res.header('Last-Modified', new Date(response_data.modified));

                Object.keys(response_data.headers).forEach(function (k) {
                    if (/^m-\w+/.test(k)) {
                        res.set(k, response_data.headers[k]);
                    }
                });

                res.send(204);
                next(null, response_data);
            }
        };

        var metadataLocation = req.metadataPlacement.getObjectLocation(owner,
            bucket.id, bucketObject.name_hash);
        var client =
            req.metadataPlacement.getBucketsMdapiClient(metadataLocation);

        var conditions = {};
        conditions['if-match'] = req.conditions['if-match'];
        conditions['if-none-match'] = req.conditions['if-none-match'];
        conditions['if-unmodified-since'] =
            req.conditions['if-unmodified-since'];

        client.updateObject(owner, bucket.id,
            bucketObject.name, objectId, object_data.contentType,
            object_data.headers, props, metadataLocation.vnode,
            req.conditions, requestId, onUpdateObject);
    });
}


function parseArguments(req, res, next)  {
    if ([
        'content-length',
        'content-md5',
        'durability-level'
    ].some(function (k) {
        var bad = req.headers[k];
        if (bad) {
            setImmediate(function killRequest() {
                next(new InvalidUpdateError(k));
            });
        }
        return (bad);
    })) {
        return;
    }

    req.log.debug('updateObjectMetadata:parseArguments: done');
    next();
}


module.exports = {
    updateBucketObjectMetadataHandler:
        function updateBucketObjectMetadataHandler() {
        var chain = [
            buckets.loadRequest,
            buckets.getBucketIfExists,
            auth.authorizationHandler(),
            parseArguments,  // not blocking
            updateObjectMetadata // blocking
        ];
        return (chain);
    }
};
