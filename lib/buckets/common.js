/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

var EventEmitter = require('events').EventEmitter;

var assert = require('assert-plus');
var util = require('util');
var vasync = require('vasync');
var verror = require('verror');

var format = util.format;

var errors = require('../errors');

var LIST_LIMIT = 1024;
var BUCKETS_MDAPI_MULTIPLIER = 2;
var MIN_BUCKET_NAME_LENGTH = 3;
var MAX_BUCKET_NAME_LENGTH = 63;
var MIN_OBJECT_NAME_BYTE_SIZE = 1;
var MAX_OBJECT_NAME_BYTE_SIZE = 1024;

/*
 * Postgres does not like handling a nul UTF-8 byte (\x00)
 */
var nullRegex = /\x00/;

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
    assert.string(name, 'name');

    return (bucketRegex.test(name) && !resemblesIpRegex.test(name) &&
        !nullRegex.test(name) &&
        name.length >= MIN_BUCKET_NAME_LENGTH &&
        name.length <= MAX_BUCKET_NAME_LENGTH);
}

/*
 * A valid bucket object name contains characters with valid UTF-8 characters
 * (non-null) and is a maximum of 1024 characters.
 */
function isValidBucketObjectName(name) {
    assert.string(name, 'name');

    return (!nullRegex.test(name) &&
        Buffer.byteLength(name) >= MIN_OBJECT_NAME_BYTE_SIZE &&
        Buffer.byteLength(name) <= MAX_OBJECT_NAME_BYTE_SIZE);
}

// Given an error from buckets-mdapi, attempt to translate it to a suitable
// restify error
function translateBucketError(req, err) {
    assert.ok(req, 'req');
    assert.ok(req.log, 'req.log');
    assert.ok(err, 'err');

    var log = req.log;
    var oldname = err.name;

    // These errors are directly from buckets-mdapi
    switch (err.name) {
    case 'BucketAlreadyExists':
        assert.object(req.bucket, 'req.bucket');
        err = new errors.BucketExistsError(req.bucket.name);
        break;
    case 'BucketNotFound':
        assert.object(req.bucket, 'req.bucket');
        req.resource_exists = false;
        err = new errors.BucketNotFoundError(req.bucket.name);
        req.not_found_error = err;
        break;
    case 'ObjectNotFound':
        assert.object(req.bucketObject, 'req.bucketObject');
        req.resource_exists = false;
        err = new errors.ObjectNotFoundError(req.bucketObject.name);
        req.not_found_error = err;
        break;
    default:
        break;
    }

    if (oldname !== err.name) {
        log.debug('converted error %j to %j (%j)',
            oldname, err.name, err.restCode);
    }

    return (err);
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
    assert.object(req.query, 'req.query');
    assert.optionalUuid(bucket_id, 'bucket_id');

    var ee = new EventEmitter();
    var log = req.log;
    var requestId = req.getId();

    var owner = req.owner.account.uuid;
    var prefix = req.query.prefix;
    var marker = req.query.marker;
    var delimiter = req.query.delimiter;

    var funcname = format('buckets.common._list(%s)', type);

    assert.uuid(owner, 'owner');

    // Validate optional delimiter
        if (delimiter && delimiter.length > 1) {
            process.nextTick(function () {
                ee.emit('error', new InvalidParameterError('delimiter',
                    delimiter));
            });
            return (ee);
        }

    // Validate optional limit
    var limit;
    if (req.query.limit) {
        limit = parseInt(req.query.limit, 10);
        if (isNaN(limit) || limit <= 0 || limit > LIST_LIMIT) {
            process.nextTick(function () {
                ee.emit('error', new InvalidLimitError(req.query.limit));
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

    // Find an appropriate limit to use with buckets-mdapi
    var bucketsMdapiLimit =
        Math.ceil(limit / totalVnodes * BUCKETS_MDAPI_MULTIPLIER);

    log.debug('%d vnodes found total, want %d records, using limit of %d',
        totalVnodes, limit, bucketsMdapiLimit);

    // Create a mapping of vnodes to pnodes
    nodes.forEach(function (node) {
        var client = node.client;
        assert.object(client, 'client for pnode: ' + node.pnode);

        vnodes[node.vnode] = {
            lmstream: new LimitMarkerStream({
                marker: marker,
                markerKey: 'name',
                limit: bucketsMdapiLimit,
                log: log.child({vnode: node.vnode}),
                getStream: function (_marker, _limit) {
                    switch (type) {
                    case 'buckets':
                        return (client.listBuckets(owner, prefix, _limit,
                            _marker, node.vnode, requestId));
                    case 'objects':
                        return (client.listObjects(owner, bucket_id, prefix,
                            _limit, _marker, node.vnode, requestId));
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

            log.trace({paginationRecord: record}, 'got record');

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
                etag: record.id,
                size: record.content_length,
                contentType: record.content_type,
                contentMD5: record.content_md5,
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

            ee.emit('entry', obj, record);
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
    isValidBucketObjectName: isValidBucketObjectName,
    translateBucketError: translateBucketError,
    listBuckets: listBuckets,
    listObjects: listObjects
};

///--- Internal

/*
 * LimitMarkerStream
 *
 * This class provides a seamless wrapper on top of an object stream that
 * requires a limit and optionally a marker.  LimitMarkerStream will create the
 * stream automatically under-the-hood when needed, and will recreate the
 * stream with a new marker when the limit has been hit (automatic pagination).
 *
 * The constructor takes a single oject with the following options:
 *
 * log        Bunyan   [required] Bunyan logger object.
 * limit      Number   [required] The limit to use.
 * markerKey  String   [required] The object key which contains the marker.
 * marker     String   [optional] Initial marker to use.
 * getStream  Function [required] Function to retrieve a new stream, will be
 *                                called with the following signature:
 *                                opts.getStream(currentMarker, currentLimit)
 *                                and must return a new Stream to use.
 *
 * With an LimitMarkerStream like:
 *
 *  var lmstream = new LimitMarkerStream(opts);
 *
 * The `getNextRecord` method can be used:
 *
 *  lmstream.getNextRecord(record, isDone) {
 *    if (isDone) {
 *      return;
 *    }
 *    // record -> a single object from the underlying stream.read()
 *  });
 *
 * `getNextRecord` will handle automatically paginating the stream when needed,
 * without the user needing to be concerned with any of that logic.
 *
 * The `setNewMarker` method can be used to update the marker by throwing out
 * all records until the new marker is seen.  It is an error to pass a Marker
 * to this that is less-than (lexicographical sort) the current marker.
 *
 * Finally, the `lmstream` object has a `done` property set when the stream has
 * fully been exhausted.
 */
util.inherits(LimitMarkerStream, EventEmitter);
function LimitMarkerStream(opts) {
    var self = this;

    assert.object(opts, 'opts');
    assert.object(opts.log, 'opts.log');
    assert.optionalString(opts.marker, 'opts.marker');
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

/*
 * paginationStream takes a collection of vnodes (buckets-mdapi clients
 * specifically in this module) and a number of options to manage multiple
 * Streams simultaneously.  The purpose of this function is to take multiple
 * LimitMarkerStream objects, and expose to the caller a single function that
 * will be called on a per-record basis (sorted) regardless of which stream
 * contained the record.
 *
 * This function takes 3 arguments (all required):
 *
 * opts            Object   An object with various options:
 * opts.log        Bunyan  [required] A bunyan logger object.
 * opts.vnodes     Object  [required] An object, keyed off of the vnode number,
 *                                    that maps each vnode to an object that
 *                                    contains a LimitMarkerStream object.
 * opts.order_by   String  [required] The object key that will be used when
 *                                    sorting and matching records.
 * opts.limit      Number  [required] A global limit to use - paginationStream
 *                                    will end when this limit is hit.
 * opts.prefix     String  [optional] A prefix string that all records must
 *                                    match against - the `.order_by` property
 *                                    will be used for this match.
 * opts.delimiter  String  [optional] A delimiter character to use when
 *                                    matching records - the `.order_by`
 *                                    property will be used for this match.
 * onRecord   Function  A function to call once for each record seen.
 * done       Function  A function to call when everything is done.
 *
 */
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
    var errorsSeen = [];

    // Attach an error handler for all vnode objects
    Object.keys(vnodes).forEach(function (vnode) {
        var o = vnodes[vnode];

        assert.object(o, util.format('vnodes[%d]', vnode));
        assert.object(o.lmstream, util.format('vnodes[%d].lmstream', vnode));

        o.lmstream.once('error', function (err) {
            log.warn(err, 'vnode (%d) lmstream error', vnode);
            errorsSeen.push(err);
            doneEarly = true;
            delete vnodes[vnode];
        });
    });

    log.debug({
        vnodes: Object.keys(vnodes),
        limit: limit,
        order_by: opts.order_by,
        delimiter: delimiter,
        prefix: prefix
    }, 'paginationStream starting');

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
            }, function (whilstIterateErr) {
                /*
                 * There should be no errors seen in the above whilst iteration
                 * function.  Instead, errors will be emitted outside of this
                 * function and stored in the errorsSeen array and dealt with
                 * at the end of this whilst invocation.
                 */
                assert.ok(!whilstIterateErr,
                    'whilstIterateErr should not be set');

                if (doneEarly) {
                    cb();
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
        }, function (whilstErr) {
            /*
             * There should be no errors seen in the above whilst invocation.
             * Instead, errors will be emitted outside of this function and
             * stored in the errorsSeen array and condensed into a MultiError
             * object below if seen.
             */
            assert.ok(!whilstErr, 'whilstErr should not be set');

            var err = verror.errorFromList(errorsSeen);
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
