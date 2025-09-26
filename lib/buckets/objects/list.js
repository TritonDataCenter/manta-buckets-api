/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

var assert = require('assert-plus');

var auth = require('../../auth');
var buckets = require('../buckets');
var common = require('../common');
var anonymousAuth = require('../../anonymous-auth');

function listBucketObjects(req, res, next) {
    var bucket = req.bucket;
    var log = req.log;

    assert.uuid(bucket.id, 'bucket.id');

    log.debug({
        bucket: req.name,
        query: req.query,
        params: req.params
    }, 'listBucketObjects: requested');

    log.info({
        bucket: req.name,
        queryDelimiter: req.query ? req.query.delimiter : 'undefined',
        queryPrefix: req.query ? req.query.prefix : 'undefined',
        queryMarker: req.query ? req.query.marker : 'undefined',
        queryLimit: req.query ? req.query.limit : 'undefined',
        fullQuery: req.query
    }, 'S3_LISTING_DEBUG: Query parameters for listBucketObjects');

    var mreq = common.listObjects(req, bucket.id);

    var entries = [];
    var message;

    mreq.once('error', function onError(err) {
        mreq.removeAllListeners('end');
        mreq.removeAllListeners('entry');

        err = common.translateBucketError(req, err);
        log.debug(err, 'listBucketObjects: failed');
        next(err);
    });

    mreq.on('message', function onMessage(_message) {
        message = _message;
        assert.object(message, 'message');
        assert.bool(message.finished, message.finished);
    });

    mreq.on('entry', function onEntry(entry, raw) {
        log.info({
            entryName: entry ? entry.name : 'undefined',
            entrySize: entry ? entry.size : 'undefined',
            entryMtime: entry ? entry.mtime : 'undefined',
            entryType: entry ? entry.type : 'undefined',
            rawNextMarker: raw ? raw.nextMarker : 'undefined',
            willBeFiltered: entry && entry.name &&
                entry.name.indexOf('.mpu-') === 0
        }, 'S3_LISTING_DEBUG: Found entry in listBucketObjects');

        entries.push({
            entry: entry,
            raw: raw
        });
    });

    mreq.once('end', function onEnd() {
        // ensure that we received a messaged
        assert.ok(message, 'message');

        log.debug({}, 'listBucketObjects: done');

        log.info({
            totalEntries: entries.length,
            finished: message.finished,
            entryNames: entries.map(function (e) {
                return (e.entry ? e.entry.name : 'no-name');
            })
        }, 'S3_LISTING_DEBUG: Final listBucketObjects result summary');

        if (!message.finished && entries.length > 0) {
            // If we are not finished and have entries, process pagination

            var lastObject = entries[entries.length - 1];
            var lastEntry = lastObject.entry;
            var lastRaw = lastObject.raw;

            assert.object(lastEntry, 'lastEntry');
            assert.string(lastEntry.name, 'lastEntry.name');

            if (lastRaw) {
                assert.object(lastRaw, 'lastRaw');
                assert.optionalString(lastRaw.nextMarker, 'lastRaw.nextMarker');
                res.header('Next-Marker', lastRaw.nextMarker || lastEntry.name);
            } else {
                res.header('Next-Marker', lastEntry.name);
            }
        }

        entries.forEach(function (obj) {
            var entry = obj.entry;
            res.write(JSON.stringify(entry, null, 0) + '\n');
        });

        res.end();
        next();
    });
}


module.exports = {

    listBucketObjectsHandler: function listBucketObjectsHandler() {
        var chain = [
            buckets.loadRequest,
            buckets.getBucketIfExists,
            anonymousAuth.validateAnonymousAccess,
            auth.authorizationHandler(),
            listBucketObjects
        ];
        return (chain);
    }

};
