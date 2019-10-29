/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

var EventEmitter = require('events').EventEmitter;

var assert = require('assert-plus');
var util = require('util');
var vasync = require('vasync');

var format = util.format;

require('../errors');

var LIST_LIMIT = 1024;
var BORAY_MULTIPLIER = 2;

/*
 * A valid bucket name is composed of one or more "labels," separated by
 * periods.
 *
 * A label is defined as a string that meets the following criteria:
 * - Contains only lowercase letters, numbers, and hyphens
 * - Does not start or end with a hyphen.
 *
 * Bucket names must also be between 3 and 63 characters long, and must not
 * "resemble an IP address," as defined immediately below.
 */
var bucketLabelRegexStr = '([a-z0-9]([a-z0-9-]*[a-z0-9])?)';
var bucketRegexStr =
    format('^(%s\\.)*%s$', bucketLabelRegexStr, bucketLabelRegexStr);
var bucketRegex = new RegExp(bucketRegexStr);

/*
 * S3 considers "resembling an IP address" to mean four groups of between one
 * and three digits each, separated by periods. This includes strings that are
 * not actually valid IP addresses. For example:
 *
 * - 1.1.1.1 resembles an IP address
 * - 999.999.999.999 also resembles an IP address
 * - 172.25.1234.1 does not, because there is a section with more than three
 *   digits. This is thus a valid bucket name.
 */
var threeDigitRegexStr = '[0-9]{1,3}';
var resemblesIpRegexStr = format('^%s\.%s\.%s\.%s$', threeDigitRegexStr,
    threeDigitRegexStr, threeDigitRegexStr, threeDigitRegexStr);
var resemblesIpRegex = new RegExp(resemblesIpRegexStr);

function isValidBucketName(name) {
    return bucketRegex.test(name) && !resemblesIpRegex.test(name) &&
        name.length >= 3 && name.length <= 63;
}

function listBuckets(req) {
    return (_list('buckets', req));
}

function listObjects(req, bucket_id) {
    return (_list('objects', req, bucket_id));
}

/*
 * Generic wrapper for listing buckets or objects
 */
function _list(type, req, bucket_id) {
    assert.string(type, 'type');
    assert.ok(['objects', 'buckets'].indexOf(type) >= 0,
        format('invalid _list type: %s', type));
    assert.object(req, 'req');
    assert.object(req.log, 'req.log');
    assert.object(req.boray, 'req.boray');
    assert.object(req.params, 'req.params');
    assert.optionalUuid(bucket_id, 'bucket_id');

    var ee = new EventEmitter();
    var log = req.log;
    var id = req.getId();

    var owner = req.owner.account.uuid;
    var prefix = req.params.prefix;
    var marker = req.params.marker;
    var delimiter = req.params.delimiter;

    var funcname = format('buckets.common._list(%s)', type);

    assert.uuid(owner, 'owner');

    // Validate optional delimiter
    if (delimiter && delimiter.length > 1) {
        ee.emit('error', new Error(
            '%s: delimiter larger than 1 character: %j',
            funcname, delimiter));
        return (ee);
    }

    // Validate optional limit
    var limit;
    if (req.params.limit) {
        limit = parseInt(req.params.limit, 10);
        if (isNaN(limit) || limit <= 0 || limit > LIST_LIMIT) {
            process.nextTick(function () {
                ee.emit('error', new InvalidLimitError(req.params.limit));
            });
            return (ee);
        }
    } else {
        limit = LIST_LIMIT;
    }

    assert.number(limit, 'limit');
    assert.ok(limit > 0, 'limit > 0');
    assert.ok(limit <= LIST_LIMIT,
        format('limit <= LIST_LIMIT (%d)', LIST_LIMIT));

    log.debug('%s: entered', funcname);

    // Get all vnodes and pnodes
    var nodes = req.metadataPlacement.getAllNodes();
    var vnodes = {};
    var totalVnodes = nodes.length;

    // Find an appropriate limit to use with boray
    var borayLimit = Math.ceil(limit / totalVnodes * BORAY_MULTIPLIER);

    log.debug('%d vnodes found total, want %d records, using limit of %d',
        totalVnodes, limit, borayLimit);

    // Create a mapping of vnodes to pnodes
    nodes.forEach(function (node) {
        var client = node.client;
        assert.object(client, 'client for pnode: ' + node.pnode);

        vnodes[node.vnode] = {
            lmstream: new LimitMarkerStream({
                marker: marker,
                markerKey: 'name',
                limit: borayLimit,
                log: log.child({vnode: node.vnode}),
                getStream: function (_marker, _limit) {
                    switch (type) {
                    case 'buckets':
                        return (client.listBuckets(owner, prefix, _limit,
                            _marker, node.vnode, id));
                    case 'objects':
                        return (client.listObjects(owner, bucket_id, prefix,
                            _limit, _marker, node.vnode, id));
                    default:
                        assert.ok(false, 'unknown type: ' + type);
                        break;
                    }
                }
            }),
            record: null
        };
    });

    // Create a pagination stream
    var opts = {
        limit: limit,
        prefix: prefix,
        delimiter: delimiter,
        order_by: 'name',
        log: log,
        vnodes: vnodes
    };
    paginationStream(opts,
        function onRecord(record) {
            assert.object(record, 'record');

            log.warn({record: record}, 'writing record');

            var obj;

            if (record.type === 'message') {
                assert.bool(record.finished, 'record.finished');
                obj = {
                    type: 'message',
                    finished: record.finished
                };

                ee.emit('message', record);
                return;
            }

            assert.string(record.name, 'record.name');

            if (record.type === 'group') {
                assert.optionalString(record.nextMarker, 'record.nextMarker');
                obj = {
                    name: record.name,
                    nextMarker: record.nextMarker,
                    type: 'group'
                };

                ee.emit('entry', obj);
                return;
            }

            assert.date(record.created, 'record.created');

            obj = {
                name: record.name,
                etag: record.etag,
                size: record.contentLength,
                contentType: record.contentType,
                contentMD5: record.contentMD5,
                mtime: record.created
            };

            switch (type) {
            case 'buckets':
                obj.type = 'bucket';
                break;
            case 'objects':
                obj.type = 'bucketobject';
                break;
            default:
                assert.ok(false, 'unknown type: ' + type);
                break;
            }

            ee.emit('entry', obj);
        },
        function done(err) {
            if (err) {
                log.error(err, '%s: error', funcname);
                ee.emit('error', err);
                return;
            }

            log.debug('%s: done', funcname);

            ee.emit('end');
        });


    return (ee);
}

///--- Exports

module.exports = {
    isValidBucketName: isValidBucketName,
    listBuckets: listBuckets,
    listObjects: listObjects
};

///--- Internal

util.inherits(LimitMarkerStream, EventEmitter);
function LimitMarkerStream(opts) {
    var self = this;

    assert.object(opts, 'opts');
    assert.object(opts.log, 'opts.log');
    assert.string(opts.markerKey, 'opts.markerKey');
    assert.func(opts.getStream, 'opts.getStream');
    assert.optionalString(opts.marker, 'opts.marker');
    assert.number(opts.limit, 'opts.limit');

    self.log = opts.log;
    self.marker = opts.marker || '';
    self.markerKey = opts.markerKey;
    self.getStream = opts.getStream;
    self.limit = opts.limit;
    self.pendingRecord = null;
    self.done = false;
}

LimitMarkerStream.prototype.setNewMarker = function setNewMarker(marker, cb) {
    var self = this;

    assert.string(marker, 'marker');
    assert.func(cb, 'cb');

    assert.ok(!self.done, 'stream already finished');

    var done = false;

    vasync.whilst(
        function testFunc() {
            return (!done);
        },
        function iterateFunc(cb2) {
            var opts = {
                autoPaginate: false
            };

            self.getNextRecord(opts, function (record, isDone) {
                if (isDone) {
                    self.log.debug('setNewMarker exhausted existing page');
                    done = true;
                    self.marker = marker;
                    self.res = null;
                    self.pendingRecord = null;
                    cb2();
                    return;
                }

                assert.object(record, 'record');
                if (record[self.markerKey] >= marker) {
                    // we are done fast forwarding
                    self.pendingRecord = record;
                    done = true;
                    self.marker = record[self.markerKey];
                    self.log.debug({pendingRecord: record, marker: self.marker},
                        'setNewMarker found record above marker');
                    cb2();
                    return;
                }

                // discard this record and keep going
                cb2();
            });
        },
        function whilstDone(err, arg) {
            // no error should be seen here
            assert.ifError(err, 'setNewMarker whilst error');
            cb(err);
        });
};

LimitMarkerStream.prototype._getNewStream = function _getNewStream() {
    var self = this;

    assert.ok(!self.done, 'stream already finished');

    self.log.debug({
        marker: self.marker,
        limit: self.limit
    }, 'calling getStream(marker=%j, limit=%d)',
        self.marker,
        self.limit);

    if (self.res) {
        self.res.removeAllListeners();
    }

    self.res = self.getStream(self.marker, self.limit);
    self.numRecords = 0;
    self.resEnded = false;
    self.recordPending = false;

    self.res.on('end', function () {
        self.log.debug('getNewStream ended');
        self.resEnded = true;
    });

    self.res.on('error', function (err) {
        self.log.error(err, 'getNewStream error');
        self.emit('error', err);
    });
};

LimitMarkerStream.prototype.getNextRecord =
    function getNextRecord(opts, cb) {

    var self = this;

    if (typeof (opts) === 'function') {
        cb = opts;
        opts = {};
    }

    assert.object(opts, 'opts');
    assert.optionalBool(opts.skipCheck, 'opts.skipCheck');
    assert.optionalBool(opts.autoPaginate, 'opts.autoPaginate');
    assert.func(cb, 'cb');

    assert.ok(!self.done, 'stream already finished');

    var autoPaginate = (opts.autoPaginate === false) ? false : true;

    if (self.pendingRecord) {
        // a record was left over from setNewMarker, send it out
        var r = self.pendingRecord;
        self.pendingRecord = null;
        self.log.warn({record: r}, 'returning pendingRecord');
        sendRecord(r);
        return;
    }

    if (!self.res) {
        self.log.debug('requesting new stream');
        self._getNewStream();
        setImmediate(function () {
            self.getNextRecord({skipCheck: true}, cb);
        });
        return;
    }

    if (!opts.skipCheck) {
        assert.ok(!self.recordingPending, 'self.recordPending');
    }

    self.recordPending = true;

    var record = self.res.read();

    if (record) {
        self.log.trace({record: record}, 'record available - returning');
        sendRecord(record);
        return;
    }

    if (self.resEnded) {
        self.log.debug('self.resEnded is true');
        self.res = null;

        if (self.numRecords === self.limit) {

            // callback with the isDone boolean set, but without setting
            // self.done
            if (!autoPaginate) {
                self.log.debug('autoPagination disabled, sending isDone');
                cb(null, true);
                return;
            }

            self.log.debug('autoPagination enabled, requesting next page');
            self._getNewStream();
            setImmediate(function () {
                self.getNextRecord({skipCheck: true}, cb);
            });
            return;
        }

        self.log.debug('stream is finished and all records exhausted, done');
        self.done = true;
        cb(null, true);
        return;
    }

    self.log.debug('attaching to readable and end events');

    self.res.on('readable', tryRead);
    self.res.on('end', tryRead);
    var done = false;

    function tryRead() {
        if (done) {
            return;
        }

        self.log.debug('detaching readable and end events');

        done = true;
        self.removeListener('readable', tryRead);
        self.removeListener('end', tryRead);

        setImmediate(function () {
            self.getNextRecord({skipCheck: true}, cb);
        });
    }

    function sendRecord(_record) {
        assert.object(_record, '_record');

        setImmediate(function () {
            self.numRecords++;
            self.recordPending = false;
            self.marker = _record[self.markerKey];
            cb(_record, false);
        });
    }
};

function paginationStream(opts, onRecord, done) {
    assert.object(opts, 'opts');
    assert.object(opts.vnodes, 'opts.vnodes');
    assert.object(opts.log, 'opts.log');
    assert.number(opts.limit, 'opts.limit');
    assert.string(opts.order_by, 'opts.order_by');
    assert.optionalString(opts.delimiter, 'opts.delimiter');
    assert.optionalString(opts.prefix, 'opts.prefix');
    assert.func(onRecord, 'onRecord');
    assert.func(done, 'done');

    var log = opts.log;
    var vnodes = opts.vnodes;
    var limit = opts.limit;
    var delimiter = opts.delimiter;
    var prefix = opts.prefix;

    var nextMarker;

    var totalRecordsSent = 0;
    var doneEarly = false;

    log.debug('paginationStream starting');
    vasync.whilst(
        function () {
            return (Object.keys(vnodes).length > 0 && !doneEarly);
        },
        function (cb) {
            vasync.forEachParallel({
                inputs: Object.keys(vnodes),
                func: function (vnode, cb2) {
                    var o = vnodes[vnode];

                    assert.object(o, util.format('vnodes[%d]', vnode));

                    if (o.record) {
                        cb2();
                        return;
                    }

                    if (o.lmstream.done) {
                        log.debug('pagination remove vnode %d from list',
                            vnode);
                        delete vnodes[vnode];
                        cb2();
                        return;
                    }

                    o.lmstream.getNextRecord(function (record, isDone) {
                        if (isDone) {
                            delete vnodes[vnode];
                            cb2();
                            return;
                        }

                        assert.object(record, 'record');
                        assert.string(record.created, 'record.created');
                        record.created = new Date(record.created);
                        o.record = record;
                        cb2();
                    });
                }
            }, function (err) {
                if (err) {
                    cb(err);
                    return;
                }

                if (totalRecordsSent >= limit) {
                    log.debug('limit hit (%d) - ending early', limit);
                    doneEarly = true;
                    cb();
                    return;
                }

                processRecords(cb);
            });
        }, function (err) {
            if (err) {
                done(err);
                return;
            }

            /*
             * If we have exhausted all vnodes of their records, then we know
             * *for sure* that there are no more pending records for the user
             * to request.
             */
            var finished = (Object.keys(vnodes).length === 0);
            vnodes = {};

            onRecord({
                type: 'message',
                finished: finished
            });

            done();
        });

    function processRecords(cb) {
        var keys = Object.keys(vnodes);

        if (keys.length === 0) {
            log.debug('no more records to process, we are done');
            cb();
            return;
        }

        keys.sort(function (a, b) {
            a = vnodes[a].record;
            b = vnodes[b].record;
            return (a[opts.order_by] < b[opts.order_by] ? -1 : 1);
        });

        var vnode = parseInt(keys[0], 10);
        assert.number(vnode, 'vnode');

        var o = vnodes[vnode];
        assert.object(o, 'o');

        var rec = o.record;
        o.record = null;

        // just send the plain record if no delimiter was specified
        if (!delimiter) {
            sendRecord(rec);
            cb();
            return;
        }

        // try to split the string by the delimiter
        var name = rec[opts.order_by];

        // delimiter is specified, chop off the prefix (if it is supplied) from
        // the name
        if (prefix) {
            assert.ok(name.length >= prefix.length,
                'name.length >= prefix.length');
            assert.equal(name.substr(0, prefix.length), prefix,
                'prefix correct');

            name = name.substr(prefix.length);
        }

        var idx = name.indexOf(delimiter);

        // no delimiter found, just send the plain record
        if (idx < 0) {
            sendRecord(rec);
            cb();
            return;
        }

        // delimiter found
        var base = (prefix || '') + name.substr(0, idx);
        nextMarker = base + String.fromCharCode(delimiter.charCodeAt(0) + 1);

        // send the group record
        sendRecord({
            name: base + delimiter,
            nextMarker: nextMarker,
            type: 'group'
        });

        // Fast forward each vnode stream to the next marker
        vasync.forEachParallel({
            inputs: Object.keys(vnodes),
            func: function (_vnode, cb2) {
                var ob = vnodes[_vnode];

                assert.object(ob, util.format('vnodes[%d]', _vnode));

                if (ob.lmstream.done) {
                    log.debug('fast-forward remove vnode %d from list',
                        _vnode);
                    delete vnodes[_vnode];
                    cb2();
                    return;
                }

                if (ob.record && ob.record[opts.order_by] &&
                    ob.record[opts.order_by] < nextMarker) {

                    ob.record = null;
                }

                ob.lmstream.setNewMarker(nextMarker, cb2);
            }
        }, function (err) {
            cb(err);
        });

        function sendRecord(_rec) {
            totalRecordsSent++;
            onRecord(_rec);
        }
    }
}
