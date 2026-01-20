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
var common = require('../common');
var corsMiddleware = require('../cors-middleware');
var anonymousAuth = require('../anonymous-auth');

var translateBucketError = require('./common').translateBucketError;

function options(req, res, next) {

    var log = req.log;
    log.debug('options: requested');

    res.setHeader('Allow', 'OPTIONS, GET');
    res.send(204);

    log.debug('options: done');

    next();
}

function loadObjectForOptions(req, res, next) {
    var owner = req.owner.account.uuid;
    var bucket = req.bucket;
    var bucketObject = req.bucketObject;
    var requestId = req.getId();

    var log = req.log.child({
        method: 'loadObjectForOptions',
        owner: owner,
        bucket: bucket.name,
        bucket_id: bucket.id,
        object: bucketObject.name,
        requestId: requestId
    });

    log.debug('loadObjectForOptions: requested');

    function onGetObject(err, object_data) {
        if (err) {
            err = translateBucketError(req, err);
            log.debug(err,
                      'loadObjectForOptions: error reading object metadata');
            next(err);
            return;
        }

        log.debug({
            metadata: object_data
        }, 'loadObjectForOptions: done - object metadata loaded');

        req.metadata = object_data;
        req.metadata.type = 'bucketobject';
        req.metadata.objectId = object_data.id;
        req.metadata.contentMD5 = object_data.content_md5;
        req.metadata.contentLength = object_data.content_length;
        req.metadata.contentType = object_data.content_type;
        req.metadata.storageLayoutVersion =
            object_data.storage_layout_version ||
            common.CURRENT_STORAGE_LAYOUT_VERSION;

        next(null, object_data);
    }

    var metadataLocation = req.metadataPlacement.getObjectLocation(owner,
        bucket.id, bucketObject.name_hash);
    var client = req.metadataPlacement.getBucketsMdapiClient(metadataLocation);

    var conditions = {};
    client.getObject(owner, bucket.id, bucketObject.name,
        metadataLocation.vnode, conditions, requestId, onGetObject);
}

module.exports = {

    optionsBucketsHandler: function optionsBucketsHandler() {
        var chain = [
            buckets.loadRequest,
            auth.authorizationHandler(),
            options
        ];
        return (chain);
    },

    optionsBucketObjectHandler: function optionsBucketObjectHandler() {
        var chain = [
            buckets.loadRequest,
            buckets.getBucketIfExists,
            loadObjectForOptions,
            corsMiddleware.handleCorsOptions,
            anonymousAuth.validateAnonymousObjectAccess,
            auth.authorizationHandler()
        ];
        return (chain);
    }

};
