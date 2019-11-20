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
 * metadata information. It establishes a connection to electric-boray and
 * periodically polls that service for data placement updates.
 */

var EventEmitter = require('events').EventEmitter;

var assert = require('assert-plus');
var bignum = require('bignum');
var boray = require('boray');
var crypto = require('crypto');
var fast = require('fast');
var jsprim = require('jsprim');
var once = require('once');
var util = require('util');
var vasync = require('vasync');
var verror = require('verror');

var boray_client = require('./boray_client');

///--- Globals

var sprintf = util.format;


///--- Private Functions

/**
 * Function to query electric-boray for updates to the metadata placement
 * information. This function is called periodically.
 */
function pollPlacementData() {
    assert.object(this.electric_boray_client,
        'no electric-boray client connected');

    this.log.trace('pollPlacementData: entered');
    clearTimeout(this._pollTimer);

    this.placementData = this.electric_boray_client.getPlacementData();

    this._pollTimer =
        setTimeout(pollPlacementData.bind(this), this.pollInterval);
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
 * Creates an instance of MetadataPlacement, and an underlying electric-boray
 * client.
 */
function MetadataPlacement(opts) {
    assert.object(opts, 'options');
    assert.object(opts.log, 'options.log');
    assert.object(opts.electric_boray, 'options.electric_boray');
    assert.optionalNumber(opts.pollInterval, 'options.pollInterval');

    EventEmitter.call(this);

    this.electric_boray_client = null;
    this.boray_clients = null;
    this.log = opts.log.child({component: 'MetadataPlacement'}, true);
    this.pollInterval = parseInt(opts.pollInterval || 1800000, 10);
    this.cfg = {
        electric_boray: opts.electric_boray,
        boray: opts.boray
    };
    this.cfg.electric_boray.log = this.log;
    this.placementData = null;

    var self = this;

    // Create electric-boray client connection
    this.electric_boray_client =
        new boray.createClient(this.cfg.electric_boray);

    this.electric_boray_client.once('error', function (err) {
        self.electric_boray_client.removeAllListeners('connect');

        self.log.error(err, 'electric-boray: failed to connect');
    });

    this.electric_boray_client.once('connect', function _onConnect() {
        self.electric_boray_client.removeAllListeners('error');

        self.log.info('electric-boray: connected');

        // Get the placement data
        self.electric_boray_client.getPlacementData(function (pErr, pd) {
            if (pErr) {
                throw new verror.VError(pErr,
                    'unable to getPlacementData');
            }

            self.placementData = pd;

            // Establish a boray connection to each shard
            self.log.info('creating boray clients');
            var pnodes = getPnodes(self.placementData);
            boray_client.createClient({
                pnodes: pnodes,
                borayOptions: self.cfg.boray.borayOptions,
                log: self.log,
                crc_mode: fast.FAST_CHECKSUM_V2
            }, function (cErr, clients) {
                if (cErr) {
                    throw new verror.VError(cErr,
                        'unable to create boray clients');
                }
                self.log.info('finished boray client connection attempts');
                self.boray_clients = clients;
                self.emit('connect');
            });
        });
    });

    this._pollTimer =
        setTimeout(pollPlacementData.bind(self), self.pollInterval);
}
util.inherits(MetadataPlacement, EventEmitter);


MetadataPlacement.prototype.close = function close() {
    clearTimeout(this._pollTimer);

    if (this.boray_clients) {
        this.boray_clients.array.forEach(function (client) {
            client.close();
        });
    }
    if (this.electric_boray_client) {
        this.electric_boray_client.close();
    }
};

/**
 * Get the boray client for the metadata shard for the given function arguments.
 *
 * @param {object} locationData An object containing vnode, pnode, and data keys
 */
MetadataPlacement.prototype.getBorayClient =
    function getBorayClient(locationData) {

    assert.object(locationData, 'locationData');
    assert.string(locationData.pnode, 'locationData.pnode');
    assert.number(locationData.vnode, 'locationData.vnode');

    var log = this.log;

    log.debug('getBorayClient: entered');

    var pnode = locationData.pnode;

    log.debug('getBorayClient: done');

    return (this.boray_clients.map[pnode]);
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
            client: self.boray_clients.map[pnode]
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
