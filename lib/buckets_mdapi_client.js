/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

var assert = require('assert-plus');
var clone = require('clone');
var fs = require('fs');
var buckets_mdapi = require('buckets-mdapi');
var url = require('url');
var verror = require('verror');

/*
 * Create buckets-mdapi clients in order to interact with buckets-mdapi
 * instances.
 */
function createClient(options, callback) {
    assert.object(options, 'options');
    assert.object(options.log, 'options.log');
    assert.arrayOfString(options.pnodes, 'options.pnodes');
    assert.object(options.bucketsMdapiOptions, 'options.bucketsMdapiOptions');
    assert.func(callback, 'callback');

    var log = options.log;

    var clientMap = {};
    var clientArray = [];

    var pnodes = options.pnodes;

    pnodes.forEach(function (pnode) {
        var pnodeUrl = url.parse(pnode);
        assert.string(pnodeUrl.port, 'pnodeUrl.port');
        assert.string(pnodeUrl.hostname, 'pnodeUrl.hostname');

        log.info({
            url: pnodeUrl
        }, 'creating buckets-mdapi client');

        var buckets_mdapi_args = clone(options.bucketsMdapiOptions);
        if (!buckets_mdapi_args.cueballOptions) {
            buckets_mdapi_args.cueballOptions = {};
        }
        buckets_mdapi_args.unwrapErrors = true;
        buckets_mdapi_args.srvDomain = pnodeUrl.hostname;
        buckets_mdapi_args.cueballOptions.defaultPort =
            parseInt(pnodeUrl.port, 10);
        buckets_mdapi_args.log = options.log.child({
            component: 'BucketsMdapiClient',
            pnode: pnodeUrl.hostname
        });

        var client = buckets_mdapi.createClient(buckets_mdapi_args);
        clientMap[pnode] = client;
        clientArray.push(client);
    });

    if (clientArray.length <= 0) {
        throw new verror.VError('No buckets-mdapi clients exist!');
    }

    return callback(null, {
        map: clientMap,
        array: clientArray
    });
}

module.exports = {
    createClient: createClient
};
