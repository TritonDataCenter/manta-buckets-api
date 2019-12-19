/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * The metadata_placement module exposes an interface to determine routing for
 * metadata information. It establishes a connection to buckets-mdplacement and
 * periodically polls that service for data placement updates.
 */

var EventEmitter = require('events').EventEmitter;

var assert = require('assert-plus');
var bignum = require('bignum');
var buckets_mdapi = require('buckets-mdapi');
var crypto = require('crypto');
var fast = require('fast');
var jsprim = require('jsprim');
var once = require('once');
var util = require('util');
var vasync = require('vasync');
var verror = require('verror');

var buckets_mdapi_client = require('./buckets_mdapi_client');

///--- Globals

var sprintf = util.format;


///--- Private Functions

/**
 * Function to query buckets-mdplacement for updates to the metadata placement
 * information. This function is called periodically.
 */
function pollPlacementData() {
    assert.object(this.buckets_mdplacement_client,
        'no buckets-mdplacement client connected');

    this.log.trace('pollPlacementData: entered');
    clearTimeout(this._pollTimer);

    var self = this;

    this.buckets_mdplacement_client.getPlacementData(function (pErr, pd) {
        if (pErr) {
            throw new verror.VError(pErr,
                                    'unable to getPlacementData');
        }

        self.placementData = pd;
        self.log.debug('pollPlacementData: placement data updated');

        self._pollTimer =
            setTimeout(pollPlacementData.bind(self), self.pollInterval);

        self.log.trace('pollPlacementData: done');
    });
}

function getPnodes(dataPlacement) {
    if (dataPlacement.version === '1.0.0') {
        return (dataPlacement.ring.pnodes);
    } else {
        return ([]);
    }
}

///--- API

/**
 * Creates an instance of MetadataPlacement, and an underlying
 * buckets-mdplacement client.
 */
function MetadataPlacement(opts) {
    assert.object(opts, 'options');
    assert.object(opts.log, 'options.log');
    assert.object(opts.buckets_mdplacement, 'options.buckets_mdplacement');
    assert.optionalNumber(opts.pollInterval, 'options.pollInterval');

    EventEmitter.call(this);

    this.buckets_mdplacement_client = null;
    this.buckets_mdapi_clients = null;
    this.log = opts.log.child({component: 'MetadataPlacement'}, true);
    this.pollInterval = parseInt(opts.pollInterval || 1800000, 10);
    this.cfg = {
        buckets_mdplacement: opts.buckets_mdplacement,
        buckets_mdapi: opts.buckets_mdapi
    };
    this.cfg.buckets_mdplacement.log = this.log;
    this.placementData = null;

    var self = this;

    // Create buckets-mdplacement client connection
    this.buckets_mdplacement_client =
        new buckets_mdapi.createClient(this.cfg.buckets_mdplacement);

    this.buckets_mdplacement_client.once('error', function (err) {
        self.buckets_mdplacement_client.removeAllListeners('connect');

        self.log.error(err, 'buckets-mdplacement: failed to connect');
    });

    this.buckets_mdplacement_client.once('connect', function _onConnect() {
        self.buckets_mdplacement_client.removeAllListeners('error');

        self.log.info('buckets-mdplacement: connected');

        // Get the placement data
        self.buckets_mdplacement_client.getPlacementData(function (pErr, pd) {
            if (pErr) {
                throw new verror.VError(pErr,
                    'unable to getPlacementData');
            }

            self.placementData = pd;

            // Establish a buckets-mdapi connection to each shard
            self.log.info('creating buckets-mdapi clients');
            var pnodes = getPnodes(self.placementData);
            buckets_mdapi_client.createClient({
                pnodes: pnodes,
                bucketsMdapiOptions: self.cfg.buckets_mdapi.bucketMdapiOptions,
                log: self.log,
                crc_mode: fast.FAST_CHECKSUM_V2
            }, function (cErr, clients) {
                if (cErr) {
                    throw new verror.VError(cErr,
                        'unable to create buckets-mdapi clients');
                }
                self.log.info('finished buckets-mdapi client connection ' +
                    'attempts');
                self.buckets_mdapi_clients = clients;
                self._pollTimer =
                    setTimeout(pollPlacementData.bind(self), self.pollInterval);
                self.emit('connect');
            });
        });
    });
}
util.inherits(MetadataPlacement, EventEmitter);


MetadataPlacement.prototype.close = function close() {
    clearTimeout(this._pollTimer);

    if (this.buckets_mdapi_clients) {
        this.buckets_mdapi_clients.array.forEach(function (client) {
            client.close();
        });
    }
    if (this.buckets_mdplacement_client) {
        this.buckets_mdplacement_client.close();
    }
};

/**
 * Get the buckets-mdapi client for the metadata shard for the given function
 * arguments.
 *
 * @param {object} locationData An object containing vnode, pnode, and data keys
 */
MetadataPlacement.prototype.getBucketsMdapiClient =
    function getBucketsMdapiClient(locationData) {

    assert.object(locationData, 'locationData');
    assert.string(locationData.pnode, 'locationData.pnode');
    assert.number(locationData.vnode, 'locationData.vnode');

    var log = this.log;

    log.debug('getBucketsMdapiClient: entered');

    var pnode = locationData.pnode;

    log.debug('getBucketsMdapiClient: done');

    return (this.buckets_mdapi_clients.map[pnode]);
};

/**
 * Gets the location information for a bucket given an owner and bucket name.
 * @param {String} owner The account UUID for the bucket
 * @param {String} bucket The bucket name.
 *
 */
MetadataPlacement.prototype.getBucketLocation =
    function getBucketLocation(owner, bucket) {

    assert.string(owner, 'owner');
    assert.string(bucket, 'bucket');

    var self = this;
    var log = self.log;

    var tkey = owner + ':' + bucket;

    log.debug({
        owner: owner,
        bucket: bucket,
        tkey: tkey
    }, 'getBucketLocation');

    return (self._getLocation(tkey));
};

/**
 * Gets location information for a given key
 * @param {String} tkey The location key
 *
 */
MetadataPlacement.prototype._getLocation = function _getLocation(tkey) {
    assert.string(tkey, 'tkey');

    var self = this;
    var log = self.log;

    log.debug({
        tkey: tkey
    }, 'getLocation: entered');

    var value = crypto.createHash(this.placementData.ring.algorithm.NAME).
        update(tkey).digest('hex');
    // find the node that corresponds to this hash.
    var vnodeHashInterval =
        this.placementData.ring.algorithm.VNODE_HASH_INTERVAL;

    var vnode = parseInt(bignum(value, 16).div(bignum(vnodeHashInterval, 16)),
        10);

    var pnode = this.placementData.ring.vnodeToPnodeMap[vnode].pnode;
    var data = this.placementData.ring.pnodeToVnodeMap[pnode][vnode];

    var ret = {
        pnode: pnode,
        vnode: vnode,
        data: data
    };

    log.debug({
        data: ret
    }, 'getLocation: done');

    return (ret);
};

MetadataPlacement.prototype.getAllNodes = function getAllNodes() {
    var self = this;
    var ret = [];

    var map = self.placementData.ring.vnodeToPnodeMap;

    Object.keys(map).forEach(function (vnode) {
        vnode = parseInt(vnode, 10);
        assert.number(vnode, 'vnode');
        var pnode = map[vnode].pnode;
        assert.string(pnode, 'pnode');

        var obj = {
            vnode: vnode,
            pnode: map[vnode].pnode,
            client: self.buckets_mdapi_clients.map[pnode]
        };

        ret.push(obj);
    });

    return (ret);
};

MetadataPlacement.prototype.getObjectLocation =
    function getObjectLocation(owner, bucket, key) {

    assert.string(owner, 'owner');
    assert.string(bucket, 'bucket');
    assert.string(key, 'key');

    var self = this;
    var log = self.log;

    var tkey = owner + ':' + bucket + ':' + key;

    log.debug({
        owner: owner,
        bucket: bucket,
        key: key,
        tkey: tkey
    }, 'getObjectLocation');

    return (self._getLocation(tkey));
};


MetadataPlacement.prototype.toString = function toString() {
    var str = '[object MetadataPlacement <';
    str += 'pollInterval=' + this.pollInterval;
    str += '>]';

    return (str);
};



///--- Exports

module.exports = {
    createClient: function createClient(options) {
        return (new MetadataPlacement(options));
    }
};
