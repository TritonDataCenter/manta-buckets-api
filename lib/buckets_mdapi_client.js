/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
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
    assert.object(options.collector, 'options.collector');
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
        buckets_mdapi_args.collector = options.collector;
        if (!buckets_mdapi_args.cueballOptions) {
            buckets_mdapi_args.cueballOptions = {};
        }
        buckets_mdapi_args.unwrapErrors = true;
        buckets_mdapi_args.srvDomain = pnodeUrl.hostname;
        buckets_mdapi_args.cueballOptions.defaultPort = parseInt(
            pnodeUrl.port, 10);
        // Create a completely filtered logger for buckets-mdapi to
        // suppress user errors
        var baseLogger = options.log.child({
            component: 'BucketsMdapiClient',
            pnode: pnodeUrl.hostname
        });
        var suppressUserErrors =
            process.env.SUPPRESS_USER_ERROR_LOGS !== 'false';
        // Function to create filtered logger instances
        function createFilteredLogger(logger, suppress) {
            return {
                child: function (childOptions) {
                    return createFilteredLogger(
                        logger.child(childOptions), suppress);
                },
                level: logger.level,
                trace: logger.trace.bind(logger),
                debug: logger.debug.bind(logger),
                info: logger.info.bind(logger),
                warn: logger.warn.bind(logger),
                error: function (err, msg) {
                    var isUserError = false;
                    var errorToCheck = err;
                    if ((typeof (err)) === 'string') {
                        errorToCheck = { message: err };
                    }
                    if (errorToCheck &&
                    (errorToCheck.name === 'BucketNotFound' ||
                        errorToCheck.name === 'ObjectNotFound' ||
                        (errorToCheck.message && (
                            errorToCheck.message.includes('not found') ||
                            errorToCheck.message.includes('already exists') ||
                            errorToCheck.message.includes(
                                'requested bucket not found') ||
                            errorToCheck.message.includes(
                                'requested object not found') ||
                            errorToCheck.message.includes('BucketNotFound') ||
                            errorToCheck.message.includes('ObjectNotFound')))))
                            {
                        isUserError = true;
                    }
                    if (isUserError && suppress) {
                        return; // Suppress user errors
                    } else {
                        logger.error(err, msg);
                    }
                },
                fatal: logger.fatal.bind(logger)
            };
        }
        // Use the filtered logger function
        var filteredLogger = createFilteredLogger(baseLogger,
            suppressUserErrors);
        buckets_mdapi_args.log = filteredLogger;

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
