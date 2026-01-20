/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

var assert = require('assert-plus');
var crypto = require('crypto');

var bucketsCommon = require('./common');
var common = require('../common');
var errors = require('../errors');
var restifyErrors = require('restify-errors');

// Import anonymous auth for SYSTEM_ROLES constant
var anonymousAuth = require('../anonymous-auth');

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
            resource.key = req.bucket.name + '/' + req.bucketObject.name;
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
    case 'GET':
        req.authContext.action = 'get' + requestType;
        break;
    case 'OPTIONS':
        req.authContext.action = 'opts' + requestType;
        break;
    case 'DELETE':
        req.authContext.action = 'delete' + requestType;
        break;
    default:
        req.authContext.action = 'put' + requestType;
        break;
    }

    // Populate roles from headers (role-tag header)
    var roleTags = req.headers['role-tag'];
    if (roleTags) {
        resource.roles = roleTags.split(',').map(function (role) {
            return (role.trim());
        }).filter(function (role) {
            return (role.length > 0);
        });
    } else {
        resource.roles = [];
    }
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
            bucket: bucket.name,
            bucketData: bucket_data
        }, 'getBucketIfExists: done');
        req.bucket.id = bucket_data.id;

        // Store bucket roles for anonymous access validation
        if (bucket_data.roles) {
            req.bucket.roles = bucket_data.roles;
        }

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

    md.contentLength = req._size;
    md.contentMD5 = req._contentMD5;
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

    // Handle S3 ACL operations specially
    if (req._s3AclOperation) {
        handleS3AclRoles(req, md, cb);
        return;
    }

    if (requestedRoleTags !== undefined && requestedRoleTags !== '') {
        /* JSSTYLED */
        names = requestedRoleTags.split(/\s*,\s*/);

        // Filter out empty strings that might result from splitting
        names = names.filter(function (name) {
            return (name && name.trim().length > 0);
        });

        if (names.length > 0) {
            // Separate system roles from user-defined roles
            var systemRoles = anonymousAuth.SYSTEM_ROLES;
            var systemRoleNames = [];
            var userRoleNames = [];

            names.forEach(function (name) {
                if (systemRoles.indexOf(name) !== -1) {
                    systemRoleNames.push(name);
                } else {
                    userRoleNames.push(name);
                }
            });

            // Add system roles as literal strings
            systemRoleNames.forEach(function (role) {
                md.roles.push(role);
            });

            // Convert user-defined roles to UUIDs if any exist
            if (userRoleNames.length > 0) {
                req.mahi.getUuid({
                    account: req.owner.account.login,
                    type: 'role',
                    names: userRoleNames
                }, function (err, lookup) {
                    if (err) {
                        cb(err);
                        return;
                    }
                    var i;
                    for (i = 0; i < userRoleNames.length; i++) {
                        if (!lookup.uuids[userRoleNames[i]]) {
                            cb(new InvalidRoleTagError(userRoleNames[i]));
                            return;
                        }
                        md.roles.push(lookup.uuids[userRoleNames[i]]);
                    }
                    cb(null, md);
                });
            } else {
                // Only system roles, no UUID lookup needed
                cb(null, md);
            }
        } else {
            // Empty roles array (for private ACL)
            cb(null, md);
        }
    } else if (requestedRoleTags === '') {
        // Explicitly empty role-tag (for private ACL) - no roles
        cb(null, md);
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
 * Handle S3 ACL operations by merging with existing object roles
 * Only removes/adds S3 public access roles, preserves other roles
 */
function handleS3AclRoles(req, md, cb) {
    // S3 public ACL roles - subset of system roles
    var s3PublicRoles = anonymousAuth.SYSTEM_ROLES.filter(function (role) {
        return (['public-read', 'public-writer',
                 'authenticated-reader'].indexOf(role) !== -1);
    });
    var newS3Roles = req._s3AclRoles || [];

    // For bucket creation, there are no existing roles to merge
    if (!req.metadata || !req.metadata.properties ||
        !req.metadata.properties.roles) {
        // No existing roles, just set the new S3 roles
        newS3Roles.forEach(function (role) {
            md.roles.push(role);
        });
        cb(null, md);
        return;
    }

    // Get existing roles from the object metadata
    var existingRoles = req.metadata.properties.roles || [];

    // Separate existing roles into S3 public roles and other roles
    var existingS3Roles = [];
    var otherRoles = [];

    existingRoles.forEach(function (role) {
        if (s3PublicRoles.indexOf(role) !== -1) {
            existingS3Roles.push(role);
        } else {
            otherRoles.push(role);
        }
    });

    // Start with non-S3 roles (preserve them)
    md.roles = otherRoles.slice();

    // Add the new S3 roles
    newS3Roles.forEach(function (role) {
        md.roles.push(role);
    });

    req.log.debug({
        existingRoles: existingRoles,
        existingS3Roles: existingS3Roles,
        otherRoles: otherRoles,
        newS3Roles: newS3Roles,
        finalRoles: md.roles
    }, 'handleS3AclRoles: merged S3 ACL roles with existing roles');

    cb(null, md);
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

    // Check if response has already been sent to prevent race condition
    if (res.headersSent) {
        log.debug('successHandler: response already sent, skipping');
        next();
        return;
    }

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
