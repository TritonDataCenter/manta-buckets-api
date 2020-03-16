/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

var assert = require('assert-plus');
var auth = require('../../auth');
var buckets = require('../buckets');
var common = require('../../common');
var uuidv4 = require('uuid/v4');

var translateBucketError = require('../common').translateBucketError;

function createObject(req, res, next) {
    var owner = req.owner.account.uuid;
    var bucket = req.bucket;
    var bucketObject = req.bucketObject;
    var objectId = req.objectId;
    var type = bucket.type;
    var props = {};
    var log = req.log;
    var requestId = req.getId();

    log.debug({
        owner: owner,
        bucket_name: bucket.name,
        bucket_id: bucket.id,
        object: bucketObject.name
    }, 'createObject: requested');

    buckets.createObjectMetadata(req, type,
        function onCreateMetadata(createErr, object_data) {

        if (createErr) {
            next(createErr);
            return;
        }

        log.debug({
            owner: owner,
            bucket_name: bucket.name,
            bucket_id: bucket.id,
            object: bucketObject.name,
            metadata: object_data
        }, 'onCreateMetadata: entered');

        var onCreateObject = function onCreate(createErr2, response_data) {
            if (object_data !== undefined && object_data._node) {
                // Record the name of the shard and vnode contacted.
                req.entryShard = response_data._node.pnode;
                req.entryVnode = response_data._node.vnode;
            }

            if (createErr2) {
                createErr2 = translateBucketError(req, createErr2);
                log.debug(createErr2, 'createObject: failed');
                next(createErr2);
            } else {
                log.debug({
                    bucket: bucketObject.bucket_name,
                    object: bucketObject.name
                }, 'createObject: done');
                if (req.headers['origin']) {
                    res.header('Access-Control-Allow-Origin',
                               req.headers['origin']);
                }
                res.header('Etag', response_data.id);
                res.header('Last-Modified', new Date(response_data.modified));
                res.header('Computed-MD5', req._contentMD5);
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

        client.createObject(owner, bucket.id, bucketObject.name, objectId,
            object_data.contentLength, object_data.contentMD5,
            object_data.contentType, object_data.headers, object_data.sharks,
            props, metadataLocation.vnode, req.conditions, requestId,
            onCreateObject);
    });
}


function parseArguments(req, res, next)  {
    var copies;
    var len;
    var maxObjectCopies = req.config.maxObjectCopies || common.DEF_MAX_COPIES;

    // First determine object size
    if (req.isChunked()) {
        var maxSize = req.msk_defaults.maxStreamingSize;
        assert.number(maxSize, 'maxSize');
        len = parseInt(req.header('max-content-length', maxSize), 10);
        if (len < 0) {
            next(new MaxContentLengthError(len));
            return;
        }
        req.log.debug('streaming upload: using max_size=%d', len);
    } else if ((len = req.getContentLength()) < 0) {
        // allow zero-byte objects
        next(new ContentLengthError());
        return;
    } else if ((req.getContentLength() || 0) === 0) {
        req._contentMD5 = common.ZERO_BYTE_MD5;
        req.sharks = [];
        req._zero = true;
        len = 0;
    }

    // Next determine the number of copies
    copies = parseInt((req.header('durability-level') ||
                       common.DEF_NUM_COPIES), 10);
    if (typeof (copies) !== 'number' || isNaN(copies) ||
        (copies < common.DEF_MIN_COPIES || copies > maxObjectCopies)) {

        next(new InvalidDurabilityLevelError(common.DEF_MIN_COPIES,
                                             maxObjectCopies));
        return;
    }

    req._copies = copies;
    req._size = len;
    req.objectId = uuidv4();

    assert.ok(len >= 0, 'len >= 0');
    assert.ok(copies >= 0, 'copies >= 0');
    assert.ok(req.objectId, 'req.objectId');

    req.log.debug({
        copies: req._copies,
        length: req._size
    }, 'putBucketObject:parseArguments: done');
    next();
}

function maybeGetObject(req, res, next) {
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
        requestId: requestId,
        via: 'createBucketObject'
    });

    if (!buckets.isConditional(req)) {
        log.debug('maybeGetObject: request is not conditional; skipping');

        next();
        return;
    }

    log.debug('maybeGetObject: requested');

    function onGetObject(err, object_data) {
        if (err) {
            err = translateBucketError(req, err);

            log.debug(err, 'maybeGetObject: error reading object metadata');

            next(err);
            return;
        }

        log.debug({
            metadata: object_data
        }, 'maybeGetObject: done');

        req.resource_exists = true;
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
    conditions['if-none-match'] = req.conditions['if-none-match'];

    client.getObject(owner, bucket.id, bucketObject.name,
        metadataLocation.vnode, conditions, requestId, onGetObject);
}

module.exports = {
    createBucketObjectHandler: function createBucketObjectHandler() {
        var chain = [
            buckets.loadRequest,
            buckets.getBucketIfExists,
            auth.authorizationHandler(),
            maybeGetObject,
            parseArguments,  // not blocking
            common.findSharks, // blocking
            common.startSharkStreams,
            common.sharkStreams, // blocking
            createObject // blocking
        ];
        return (chain);
    }
};
