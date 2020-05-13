/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

var assert = require('assert-plus');
var crypto = require('crypto');

var bucketsCommon = require('./common');
var common = require('../common');
var errors = require('../errors');
var restifyErrors = require('restify-errors');

var translateBucketError = require('./common').translateBucketError;

function loadRequest(req, res, next) {

    var resource = {};
    var requestType;
    req.metadata = {};

    if (req.params.bucket_name) {
        req.bucket = new Bucket(req);
        requestType = 'bucket';
        resource.key = req.bucket.name;

        if (req.params.object_name) {
            req.bucketObject = new BucketObject(req);
            requestType = 'object';
            resource.key = req.bucketObject.name;
        }
    } else {
        requestType = 'directory';
        resource.key = 'buckets';
    }

    /*
     * Bucket name and object name validity are checked here.  This way, any
     * handlers that run after the request is "loaded" can be guaranteed the
     * bucket and object names are valid.
     */
    if (req.bucket && !bucketsCommon.isValidBucketName(req.bucket.name)) {
        next(new errors.InvalidBucketNameError(req.bucket.name));
        return;
    }

    if (req.bucketObject &&
        !bucketsCommon.isValidBucketObjectName(req.bucketObject.name)) {

        next(new errors.InvalidBucketObjectNameError(req.bucketObject.name));
        return;
    }

    resource.owner = req.owner;

    switch (req.method) {
    case 'HEAD':
    case 'OPTIONS':
        /* falls through */
    case 'GET':
        req.authContext.action = 'get' + requestType;
        break;
    case 'DELETE':
        req.authContext.action = 'delete' + requestType;
        break;
    default:
        req.authContext.action = 'put' + requestType;
        break;
    }

    // TODO: Populate roles from headers
    resource.roles = [];
    req.authContext.resource = resource;

    var conditionsErr = validateAndSetConditions(req);
    if (conditionsErr) {
        next(conditionsErr);
        return;
    }

    next();

}

/* This is a function used before bucket object operations */
function getBucketIfExists(req, res, next) {
    var owner = req.owner.account.uuid;
    var bucket = req.bucket;
    var log = req.log;
    var requestId = req.getId();

    log.debug({
        owner: owner,
        bucket: bucket.name
    }, 'getBucketIfExists: requested');

    var onGetBucket = function onGet(err, bucket_data) {
        if (err) {
            err = bucketsCommon.translateBucketError(req, err);

            log.debug({
                err: err,
                owner: owner,
                bucket: bucket.name
            }, 'getBucketIfExists: failed');

            next(err);
            return;
        }

        log.debug({
            owner: owner,
            bucket: bucket.name
        }, 'getBucketIfExists: done');
        req.bucket.id = bucket_data.id;

        next(null, bucket_data);
    };

    var metadataLocation =
        req.metadataPlacement.getBucketLocation(owner, bucket.name);
    var client = req.metadataPlacement.getBucketsMdapiClient(metadataLocation);

    client.getBucket(owner, bucket.name, metadataLocation.vnode, requestId,
        onGetBucket);
}

function Bucket(req) {

    var self = this;

    assert.object(req, 'req');
    if (req.params.bucket_name) {
        self.name = req.params.bucket_name;
    }
    self.type = 'bucket';

    return (self);

}

/**
 * Create a new BucketObject
 *
 * Please note the presence of the name_hash field. This field represents the
 * MD5 hash of the object name. It is used as input to determine where to place
 * an object's metadata record. This decision to use this value rather than the
 * raw object name as input to the metadata location hash function was made in
 * order to allow us to construct the storage file path such that all the inputs
 * to the metadata placement hash function are present on the storage node and
 * also maintain a predictable, fixed size file path. The benefit of this
 * information on the storage node is that it becomes possible to determine the
 * location of the metadata for a storage node file without having to scan every
 * metadata shard. The inputs can be fed into the hash function in the same
 * manner as is done in the getObjectLocation function in the metadata_placement
 * module.
 */
function BucketObject(req) {

    var self = this;

    assert.object(req, 'req');
    assert.string(req.params.bucket_name, 'req.params.bucket_name');
    self.bucket_name = req.params.bucket_name;
    if (req.params.object_name) {
        self.name = req.params.object_name;
        self.name_hash =
            crypto.createHash('md5').update(self.name).digest('hex');
    }
    self.type = 'bucketobject';

    return (self);

}


// TODO: Break this up into smaller pieces
function createObjectMetadata(req, type, cb) {
    var names;
    var md = {
        headers: {},
        roles: [],
        type: 'bucketobject'
    };

    common.CORS_RES_HDRS.forEach(function (k) {
        var h = req.header(k);
        if (h) {
            md.headers[k] = h;
        }
    });

    if (req.headers['cache-control'])
        md.headers['Cache-Control'] = req.headers['cache-control'];

    if (req.headers['surrogate-key'])
        md.headers['Surrogate-Key'] = req.headers['surrogate-key'];

    var hdrSize = 0;
    Object.keys(req.headers).forEach(function (k) {
        if (/^m-\w+/.test(k)) {
            hdrSize += Buffer.byteLength(req.headers[k]);
            if (hdrSize < common.MAX_HDRSIZE)
                md.headers[k] = req.headers[k];
        }
    });

    md.contentLength = 0;
    md.contentMD5 = req._contentMD5 = '1B2M2Y8AsgTpgAmY7PhCfg==';
    md.contentType = req.header('content-type') ||
        'application/octet-stream';
    md.objectId = req.objectId;

    if (md.contentLength === 0) { // Chunked requests
        md.sharks = [];
    } else if (req.sharks && req.sharks.length) { // Normal requests
        md.sharks = req.sharks.map(function (s) {
            return ({
                datacenter: s._shark.datacenter,
                manta_storage_id: s._shark.manta_storage_id
            });
        });
    } else { // Take from the prev is for things like mchattr
        md.sharks = [];
    }

    // mchattr
    var requestedRoleTags;
    if (req.auth && typeof (req.auth['role-tag']) === 'string') { // from URL
        requestedRoleTags = req.auth['role-tag'];
    } else {
        requestedRoleTags = req.headers['role-tag'];
    }

    if (requestedRoleTags) {
        /* JSSTYLED */
        names = requestedRoleTags.split(/\s*,\s*/);
        req.mahi.getUuid({
            account: req.owner.account.login,
            type: 'role',
            names: names
        }, function (err, lookup) {
            if (err) {
                cb(err);
                return;
            }
            var i;
            for (i = 0; i < names.length; i++) {
                if (!lookup.uuids[names[i]]) {
                    cb(new InvalidRoleTagError(names[i]));
                    return;
                }
                md.roles.push(lookup.uuids[names[i]]);
            }
            cb(null, md);
        });
    // apply all active roles if no other roles are specified
    } else if (req.caller.user) {
        md.roles = req.activeRoles;
        setImmediate(function () {
            cb(null, md);
        });
    } else {
        setImmediate(function () {
            cb(null, md);
        });
    }
}

/*
 * Handles the 200->304 response code translation of some HTTP requests.  All
 * other precondition cases are handled by buckets-mdapi and will result in a
 * PreconditionFailedError error already being passed through the server's
 * response pipeline and thus not reaching this point.
 *
 * In particular, only GET and HEAD requests are subject to this translation,
 * and only when the "If-None-Match" header is present and matched upon, or in
 * its absence "If-Modified-Since" is after the object's "Last-Modified".
 */
function conditionalHandler(req, res, next) {
    assert.object(req.conditions, 'req.conditions');

    var if_modified_since, if_none_match;
    var code;

    if (!isConditional(req) ||
        (req.method !== 'HEAD' && req.method !== 'GET')) {
        next();
        return;
    }

    if ((if_none_match = req.conditions['if-none-match'])) {
        var object_etag = res.header('Etag');

        if_none_match.forEach(function (client_etag) {
            if (client_etag === '*' || client_etag === object_etag) {
                code = 304;
                return;
            }
        });
    }

    if ((if_modified_since = req.conditions['if-modified-since'])) {
        var object_last_modified = new Date(res.header('Last-Modified'));

        if (if_modified_since > object_last_modified) {
            code = 304;
        }
    }

    if (code) {
        res.send(code);
        next(false);
    } else {
        next();
    }
}

function successHandler(req, res, next) {
    var owner = req.owner.account.uuid;
    var log = req.log;

    log.debug({
        owner: owner
    }, 'successHandler: entered');

    if (req.method == 'PUT' || req.method == 'POST' || req.method == 'DELETE') {
        res.send(204);
    } else {
        res.send(200);
    }

    log.debug({
        owner: owner
    }, 'successHandler: done');

    next();
}

function isConditional(req) {
    return (req.headers['if-match'] !== undefined ||
            req.headers['if-none-match'] !== undefined ||
            req.headers['if-modified-since'] !== undefined ||
            req.headers['if-unmodified-since'] !== undefined);
}

/*
 * This function pulls applicable conditional headers out of req.headers and
 * creates/populates a new object called req.conditions.  This new object is
 * intended to be passed down to buckets-mdapi as part of a structured set of
 * conditional parameters.
 */
function validateAndSetConditions(req) {
    var conditions = {};

    var dateErr;

    [ 'if-modified-since', 'if-unmodified-since' ].forEach(function (name) {
        if (req.headers[name]) {
            var value = Date.parse(req.headers[name]);

            if (isNaN(value) || !value) {
                dateErr = new restifyErrors.BadRequestError(
                    'unable to parse %s ("%s") as a date',
                    name,
                    req.headers[name]);
                return;
            }

            assert.number(value);

            conditions[name] = new Date(value);
        }
    });

    if (dateErr) {
        return (dateErr);
    }

    [ 'if-match', 'if-none-match' ].forEach(function (name) {
        if (req.headers[name]) {
            var value = [];
            /* JSSTYLED */
            var etags = req.headers[name].split(/\s*,\s*/);

            for (var i = 0; i < etags.length; i++) {
                var cur = etags[i];
                // ignore weak validation
                cur = cur.replace(/^W\//, '');
                cur = cur.replace(/^"(\w*)"$/, '$1');

                value.push(cur);
            }

            if (value.length > 0) {
                conditions[name] = value;
            }
        }
    });

    req.conditions = conditions;
}

module.exports = {
    Bucket: Bucket,
    BucketObject: BucketObject,
    getBucketIfExists: getBucketIfExists,
    createObjectMetadata: createObjectMetadata,
    loadRequest: loadRequest,
    conditionalHandler: conditionalHandler,
    successHandler: successHandler,
    isConditional: isConditional
};
