/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

var crypto = require('crypto');
var EventEmitter = require('events').EventEmitter;
var http = require('http');
var once = require('once');
var os = require('os');
var path = require('path');
var util = require('util');
var httpSignature = require('http-signature');

var assert = require('assert-plus');
var bignum = require('bignum');
var vasync = require('vasync');
var restifyErrors = require('restify-errors');
var VError = require('verror');

var CheckStream = require('./check_stream');
var libmantalite = require('./libmantalite');
require('./errors');
var muskieUtils = require('./utils');
var sharkClient = require('./shark_client');
var utils = require('./utils');

///--- Globals

var clone = utils.shallowCopy;
var sprintf = util.format;

var ANONYMOUS_USER = libmantalite.ANONYMOUS_USER;

var CORS_RES_HDRS = [
    'access-control-allow-headers',
    'access-control-allow-origin',
    'access-control-expose-headers',
    'access-control-max-age',
    'access-control-allow-methods'
];

/*
 * Default minimum and maximum number of copies of an object we will store,
 * as specified in the {x-}durability-level header.
 *
 * The max number of copies is configurable in the config file; the minimum
 * is not.
 */
var DEF_MIN_COPIES = 1;
var DEF_MAX_COPIES = 9;

// Default number of object copies to store.
var DEF_NUM_COPIES = 2;

// The MD5 sum string for a zero-byte object.
var ZERO_BYTE_MD5 = '1B2M2Y8AsgTpgAmY7PhCfg==';

/* JSSTYLED */
var BUCKETS_ROOT_PATH = /^\/([a-zA-Z][a-zA-Z0-9_\.@%]+)\/buckets\/?.*/;
/* JSSTYLED */
var BUCKETS_OBJECTS_PATH = /^\/([a-zA-Z][a-zA-Z0-9_\.@%]+)\/buckets\/([a-zA-Z][a-zA-Z0-9_\.@%]+)\/objects\/.*/;

// Thanks for being a PITA, javascriptlint (it doesn't like /../ form in [])
var ROOT_REGEXPS = [
    new RegExp('^\\/[a-zA-Z0-9_\\-\\.@%]+$'), // /:login
    new RegExp('^\\/[a-zA-Z0-9_\\-\\.@%]+\\/buckets\\/?$') // buckets (list)
];

var PATH_LOGIN_RE = libmantalite.PATH_LOGIN_RE;

var ZONENAME = os.hostname();

// Names of metric collectors.
var METRIC_REQUEST_COUNTER = 'http_requests_completed';
var METRIC_LATENCY_HISTOGRAM = 'http_request_latency_ms';
var METRIC_DURATION_HISTOGRAM = 'http_request_time_ms';
var METRIC_INBOUND_DATA_COUNTER = 'muskie_inbound_streamed_bytes';
var METRIC_OUTBOUND_DATA_COUNTER = 'muskie_outbound_streamed_bytes';
var METRIC_DELETED_DATA_COUNTER = 'muskie_deleted_bytes';

// The max number of headers we store on an object in Moray: 4 KB.
var MAX_HDRSIZE = 4 * 1024;

var DATA_TIMEOUT = parseInt(process.env.MUSKIE_DATA_TIMEOUT || 45000, 10);

const CURRENT_STORAGE_LAYOUT_VERSION = 2;

///--- Internals


///--- Patches

var HttpRequest = http.IncomingMessage.prototype; // save some chars

HttpRequest.abandonSharks = function abandonSharks() {
    var self = this;
    (this.sharks || []).forEach(function (shark) {
        shark.removeAllListeners('result');
        shark.abort();
        self.unpipe(shark);
    });
};


HttpRequest.encodeBucketObject = function encodeBucketObject() {
    var self = this;

    var splitPath = self.path().split('/');
    /* This slice is :account/buckets/:bucketname/objects/ */
    var baseBucketObjectPath = splitPath.slice(0, 5).join('/');

    var bucketObject = self.path().split('/objects/').pop();
    var encodedBucketObject = encodeURIComponent(bucketObject);
    var pathParts = [baseBucketObjectPath, encodedBucketObject];

    self._path = pathParts.join('/');
    return (self._path);
};


HttpRequest.isPresigned = function isPresigned() {
    return (this._presigned);
};


HttpRequest.isConditional = function isConditional() {
    return (this.headers['if-match'] !== undefined ||
            this.headers['if-none-match'] !== undefined);
};


HttpRequest.isReadOnly = function isReadOnly() {
    var ro = this.method === 'GET' ||
        this.method === 'HEAD' ||
        this.method === 'OPTIONS';

    return (ro);
};


HttpRequest.isBucketObject = function isBucketObject() {
    function _test(p) {
        return (BUCKETS_OBJECTS_PATH.test(p));
    }

    return (_test(this.path()));
};


///--- API

function addCustomHeaders(req, res) {
    var md = req.metadata.headers;
    var origin = req.headers.origin;

    Object.keys(md).forEach(function (k) {
        var add = false;
        var val = md[k];
        // See http://www.w3.org/TR/cors/#resource-requests
        if (origin && CORS_RES_HDRS.indexOf(k) !== -1) {
            if (k === 'access-control-allow-origin') {
                /* JSSTYLED */
                if (val.split(/\s*,\s*/).some(function (v) {
                    if (v === origin || v === '*') {
                        val = origin;
                        return (true);
                    }
                    return (false);
                })) {
                    add = true;
                } else {
                    CORS_RES_HDRS.forEach(function (h) {
                        res.removeHeader(h);
                    });
                }
            } else if (k === 'access-control-allow-methods') {
                /* JSSTYLED */
                if (val.split(/\s*,\s*/).some(function (v) {
                    return (v === req.method);
                })) {
                    add = true;
                } else {
                    CORS_RES_HDRS.forEach(function (h) {
                        res.removeHeader(h);
                    });
                }
            } else if (k === 'access-control-expose-headers') {
                add = true;
            }
        } else {
            add = true;
        }

        if (add)
            res.header(k, val);
    });
}


function findSharks(req, res, next) {
    if (req._zero || req.query.metadata) {
        next();
        return;
    }

    var log = req.log;
    var opts = {
        replicas: req._copies,
        requestId: req.getId(),
        size: req._size,
        isOperator: req.caller.account.isOperator
    };

    log.debug(opts, 'findSharks: entered');

    opts.log = req.log;
    req.storinfo.choose(opts, function (err, sharks) {
        if (err) {
            next(err);
        } else {
            req._sharks = sharks;
            log.debug({
                sharks: req._sharks
            }, 'findSharks: done');
            next();
        }
    });
}


/*
 * This handler attempts to connect to one of the pre-selected, cross-DC sharks.
 * If a connection to any shark in the set fails, we try a different set of
 * sharks.
 */
function startSharkStreams(req, res, next) {
    if (req._zero || req.query.metadata) {
        next();
        return;
    }

    assert.ok(req._sharks);

    var log = req.log;
    log.debug({
        objectId: req.objectId,
        sharks: req._sharks
    }, 'startSharkStreams: entered');

    var ndx = 0;
    var opts = {
        contentType: req.getContentType(),
        contentLength: req.isChunked() ? undefined : req._size,
        contentMd5: req.headers['content-md5'],
        owner: req.owner.account.uuid,
        bucketId: req.bucket.id,
        objectId: req.objectId,
        objectName: req.bucketObject.name,
        objectNameHash: req.bucketObject.name_hash,
        requestId: req.getId(),
        sharkConfig: req.sharkConfig,
        sharkAgent: req.sharkAgent,
        storageLayoutVersion: CURRENT_STORAGE_LAYOUT_VERSION
    };

    req.sharksContacted = [];

    (function attempt(inputs) {
        vasync.forEachParallel({
            func: function shark_connect(shark, cb) {
                var _opts = clone(opts);
                _opts.log = req.log;
                _opts.shark = shark;

                var sharkInfo = createSharkInfo(req, shark.manta_storage_id);
                sharkConnect(_opts, sharkInfo, cb);
            },
            inputs: inputs
        }, function (err, results) {
            req.sharks = results.successes || [];
            if (err || req.sharks.length < req._copies) {
                log.debug({
                    err: err,
                    sharks: inputs
                }, 'startSharkStreams: failed');

                req.abandonSharks();
                if (ndx < req._sharks.length) {
                    attempt(req._sharks[ndx++]);
                } else {
                    next(new SharksExhaustedError(res));
                }
                return;
            }
            if (log.debug()) {
                req.sharks.forEach(function (s) {
                    s.headers = s._headers;
                    log.debug({
                        client_req: s
                    }, 'mako: stream started');
                });

                log.debug({
                    objectId: req.objectId,
                    sharks: inputs
                }, 'startSharkStreams: done');
            }
            next();
        });
    })(req._sharks[ndx++]);
}


/*
 * Here we stream the data from the object to each connected shark, using a
 * check stream to compute the md5 sum of the data as it passes through muskie
 * to mako.
 *
 * This handler is blocking.
 */
function sharkStreams(req, res, next) {
    if (req._zero || req.query.metadata) {
        next();
        return;
    }

    /*
     * While in the process of streaming the object out to multiple sharks, if a
     * failure is experienced on one stream, we will essentially treat it as an
     * overall failure and abandon the process of streaming this object to all
     * sharks involved.  Note that `next_err()' is wrapped in the `once()'
     * method because we need only respond to a failure event once.
     */
    var next_err = once(function _next_err(err) {
        req.log.debug({
            err: err
        }, 'abandoning request');

        /* Record the number of bytes that we transferred. */
        req._size = check.bytes;

        req.removeListener('end', onEnd);
        req.removeListener('error', next_err);

        req.abandonSharks();
        req.unpipe(check);
        check.abandon();

        next(err);
    });

    var barrier = vasync.barrier();
    var check = new CheckStream({
        algorithm: 'md5',
        maxBytes: req._size,
        timeout: DATA_TIMEOUT,
        counter: req.collector.getCollector(METRIC_INBOUND_DATA_COUNTER)
    });
    var log = req.log;

    barrier.once('drain', function onCompleteStreams() {
        req._timeToLastByte = Date.now();

        req.connection.removeListener('error', abandonUpload);
        req.removeListener('error', next_err);

        if (req.sharks.some(function (s) {
            return (s.md5 !== check.digest('base64'));
        })) {
            var _md5s = req.sharks.map(function (s) {
                return (s.md5);
            });
            log.error({
                clientMd5: req.headers['content-md5'],
                muskieMd5: check.digest('base64'),
                makoMd5: _md5s
            }, 'mako didnt receive what muskie sent');
            var m = new VError('muskie md5 %s and mako md5 ' +
                            '%s don\'t match', check.digest('base64'),
                            _md5s.join());
            next_err(new InternalError(m));
        } else {
            log.debug('sharkStreams: done');
            next();
        }
    });

    log.debug('streamToSharks: streaming data');

    function abandonUpload() {
        next_err(new UploadAbandonedError());
    }

    req.connection.once('error', abandonUpload);

    req.once('error', next_err);

    barrier.start('client');
    req.pipe(check);
    req.sharks.forEach(function (s) {
        barrier.start(s._shark.manta_storage_id);
        req.pipe(s);
        s.once('response', function onSharkResult(sres) {
            log.debug({
                mako: s._shark.manta_storage_id,
                client_res: sres
            }, 'mako: response received');

            var sharkInfo = getSharkInfo(req, s._shark.manta_storage_id);
            sharkInfo.timeTotal = Date.now() - sharkInfo._startTime;
            sharkInfo.result = 'fail'; // most cases below here are failures

            s.md5 = sres.headers['x-joyent-computed-content-md5'] ||
                req._contentMD5;
            if (sres.statusCode === 469) {
                next_err(new ChecksumError(s.md5, req.headers['content-md5']));
            } else if (sres.statusCode === 400 && req.headers['content-md5']) {
                next_err(
                    new restifyErrors.BadRequestError('Content-MD5 invalid'));
            } else if (sres.statusCode > 400) {
                var body = '';
                sres.setEncoding('utf8');
                sres.on('data', function (chunk) {
                    body += chunk;
                });
                sres.once('end', function () {
                    log.debug({
                        mako: s._shark.manta_storage_id,
                        client_res: sres,
                        body: body
                    }, 'mako: response error');
                    var m = new VError('mako response error, storage id (%s)',
                        s._shark.manta_storage_id);
                    next_err(new InternalError(m));
                });
                sres.once('error', function (err) {
                    next_err(new InternalError(err));
                });
            } else {
                sharkInfo.result = 'ok';
                barrier.done(s._shark.manta_storage_id);
            }
            /*
             * Even though PUT requests that are successful normally result
             * in an empty resonse body from nginx, we still need to make sure
             * we let the response stream emit 'end'. Otherwise this will jam
             * up keep-alive agent connections (the node http.js needs that
             * 'end' even to happen before relinquishing the socket).
             *
             * Easiest thing to do is just call resume() which should make the
             * stream run out and emit 'end'.
             */
            sres.resume();
        });
    });

    check.once('timeout', function () {
        res.header('connection', 'close');
        next_err(new UploadTimeoutError());
    });

    check.once('length_exceeded', function (sz) {
        next_err(new MaxSizeExceededError(sz));
    });

    check.once('error', next_err);

    function onEnd() {
        // We replace the actual size, in case it was streaming, and
        // the content-md5 we actually calculated on the wire
        req._contentMD5 = check.digest('base64');
        req._size = check.bytes;
        barrier.done('client');
    }

    req.once('end', onEnd);

    barrier.start('check_stream');
    check.once('done', function () {
        barrier.done('check_stream');
    });

    if (req.header('expect') === '100-continue') {
        res.writeContinue();
        log.info({
            remoteAddress: req.connection._xff,
            remotePort: req.connection.remotePort,
            req_id: req.id,
            latency: (Date.now() - req.time()),
            'audit_100': true
        }, '100-continue sent');
    }

    req._timeAtFirstByte = Date.now();
}

// Here we pick a shark to talk to, and the first one that responds we
// just stream from. After that point any error is an internal error.
function streamFromSharks(req, res, next) {
    if (req.metadata.type !== 'object' &&
        req.metadata.type !== 'bucketobject') {
            next();
            return;
    }

    var connected = false;
    var log = req.log;
    var md = req.metadata;
    var opts = {
        owner: req.owner.account.uuid,
        bucketId: req.bucket.id,
        objectId: md.objectId,
        objectName: req.bucketObject.name,
        objectNameHash: req.bucketObject.name_hash,
        storageLayoutVersion: md.storageLayoutVersion,
        requestId: req.getId()
    };
    var queue;
    var savedErr = false;

    if (req.headers.range)
        opts.range = req.headers.range;

    log.debug('streamFromSharks: entered');

    addCustomHeaders(req, res);

    if (md.contentLength === 0 || req.method === 'HEAD') {
        log.debug('streamFromSharks: HEAD || zero-byte object');
        res.header('Durability-Level', req.metadata.sharks.length);
        res.header('Content-Disposition', req.metadata.contentDisposition);
        res.header('Content-Length', md.contentLength);
        res.header('Content-MD5', md.contentMD5);
        res.header('Content-Type', md.contentType);
        res.send(200);
        next();
        return;
    }

    req.sharksContacted = [];

    function respond(shark, sharkReq, sharkInfo) {
        log.debug('streamFromSharks: streaming data');
        // Response headers
        var sh = shark.headers;
        if (req.headers['range'] !== undefined) {
            res.header('Content-Type', sh['content-type']);
            res.header('Content-Range', sh['content-range']);
        } else {
            res.header('Accept-Ranges', 'bytes');
            res.header('Content-Type', md.contentType);
            res.header('Content-MD5', md.contentMD5);
        }

        res.header('Content-Disposition', req.metadata.contentDisposition);
        res.header('Content-Length', sh['content-length']);
        res.header('Durability-Level', req.metadata.sharks.length);

        req._size = sh['content-length'];

        // Response body
        req._totalBytes = 0;
        var check = new CheckStream({
            maxBytes: parseInt(sh['content-length'], 10) + 1024,
            timeout: DATA_TIMEOUT,
            counter: req.collector.getCollector(
                METRIC_OUTBOUND_DATA_COUNTER)
        });
        sharkInfo.timeToFirstByte = check.start - sharkInfo._startTime;
        check.once('done', function onCheckDone() {
            req.connection.removeListener('error', onConnectionClose);

            if (check.digest('base64') !== md.contentMD5 &&
                !req.headers.range) {
                // We can't set error now as the header has already gone out
                // MANTA-1821, just stop logging this for now XXX
                log.warn({
                    expectedMD5: md.contentMD5,
                    returnedMD5: check.digest('base64'),
                    expectedBytes: parseInt(sh['content-length'], 10),
                    computedBytes: check.bytes,
                    url: req.url
                }, 'GetObject: partial object returned');
                res.statusCode = 597;
            }

            log.debug('streamFromSharks: done');
            req._timeAtFirstByte = check.start;
            req._timeToLastByte = Date.now();
            req._totalBytes = check.bytes;

            sharkInfo.timeTotal = req._timeToLastByte - sharkInfo._startTime;

            next();
        });
        shark.once('error', next);

        function onConnectionClose(err) {
            /*
             * It's possible to invoke this function through multiple paths, as
             * when a socket emits 'error' and the request emits 'close' during
             * this phase.  But we only want to handle this once.
             */
            if (req._muskie_handle_close) {
                return;
            }

            req._muskie_handle_close = true;
            req._probes.client_close.fire(function onFire() {
                var _obj = {
                    id: req._id,
                    method: req.method,
                    headers: req.headers,
                    url: req.url,
                    bytes_sent: check.bytes,
                    bytes_expected: parseInt(sh['content-length'], 10)
                };
                return ([_obj]);
            });

            req.log.warn(err, 'handling closed client connection');
            check.removeAllListeners('done');
            shark.unpipe(check);
            shark.unpipe(res);
            sharkReq.abort();
            req._timeAtFirstByte = check.start;
            req._timeToLastByte = Date.now();
            req._totalBytes = check.bytes;
            res.statusCode = 499;
            next(false);
        }

        /*
         * It's possible that the client has already closed its connection at
         * this point, in which case we need to abort the request here in order
         * to avoid coming to rest in a broken state.  You might think we'd
         * notice this problem when we pipe the mako response to the client's
         * response and attempt to write to a destroyed Socket, but instead Node
         * drops such writes without emitting an error.  (It appears to assume
         * that the caller will be listening for 'close'.)
         */
        if (req._muskie_client_closed) {
            setImmediate(onConnectionClose,
                new Error('connection closed before streamFromSharks'));
        } else {
            req.connection.once('error', onConnectionClose);
            req.once('close', function () {
                onConnectionClose(new Error(
                    'connection closed during streamFromSharks'));
            });
        }

        res.writeHead(shark.statusCode);
        shark.pipe(check);
        shark.pipe(res);
    }

    queue = vasync.queuev({
        concurrency: 1,
        worker: function start(s, cb) {
            if (connected) {
                cb();
            } else {
                var sharkInfo = createSharkInfo(req, s.hostname);

                s.get(opts, function (err, cReq, cRes) {
                    if (err) {
                        sharkInfo.result = 'fail';
                        sharkInfo.timeTotal = Date.now() - sharkInfo._startTime;
                        log.warn({
                            err: err,
                            shark: s.toString()
                        }, 'mako: connection failed');
                        savedErr = err;
                        cb();
                    } else {
                        sharkInfo.result = 'ok';
                        connected = true;
                        respond(cRes, cReq, sharkInfo);
                        cb();
                    }
                });
            }
        }
    });

    queue.once('end', function () {
        if (!connected) {
            // Honor Nginx handling Range GET requests
            if (savedErr && savedErr._result) {
                var rh = savedErr._result.headers;
                if (req.headers['range'] !== undefined && rh['content-range']) {
                    res.setHeader('content-range', rh['content-range']);
                    next(new restifyErrors.RequestedRangeNotSatisfiableError());
                    return;
                }
            }
            next(savedErr || new InternalError());
        }
    });

    var shuffledSharks = utils.shuffle(req.metadata.sharks);

    shuffledSharks.forEach(function (s) {
        queue.push(sharkClient.getClient({
            connectTimeout: req.sharkConfig.connectTimeout,
            log: req.log,
            retry: req.sharkConfig.retry,
            shark: s,
            agent: req.sharkAgent
        }));
    });

    queue.close();
}

// Simple wrapper around sharkClient.getClient + put
//
// opts:
//   {
//      contentType: req.getContentType(),   // content-type from the request
//      contentLength: req.isChunked() ? undefined : req._size,
//      log: $bunyan,
//      shark: $shark,  // a specific shark from $storinfo.choose()
//      objectId: req.objectId,    // proposed objectId
//      owner: req.owner.account.uuid,   // /:login/stor/... (uuid for $login)
//      sharkConfig: {  // from config.json
//        connectTimeout: 4000,
//        retry: {
//          retries: 2
//        }
//      },
//      requestId: req.getId()   // current request_id
//   }
//
// sharkInfo: object used for logging information about the shark
//
function sharkConnect(opts, sharkInfo, cb) {
    var client = sharkClient.getClient({
        connectTimeout: opts.sharkConfig.connectTimeout,
        log: opts.log,
        retry: opts.sharkConfig.retry,
        shark: opts.shark,
        agent: opts.sharkAgent
    });
    assert.ok(client, 'sharkClient returned null');

    client.put(opts, function (err, req) {
        if (err) {
            cb(err);
        } else {
            req._shark = opts.shark;
            opts.log.debug({
                client_req: req
            }, 'SharkClient: put started');
            sharkInfo.timeToFirstByte = Date.now() - sharkInfo._startTime;
            cb(null, req);
        }
    });
}

// Creates a 'sharkInfo' object, used for logging purposes,
// and saves it on the input request object to log later.
//
// Input:
//      req: the request object to save this shark on
//      hostname: the name of the shark (e.g., '1.stor.emy-13.joyent.us')
// Output:
//      a sharkInfo object
function createSharkInfo(req, hostname) {
    var sharkInfo = {
        shark: hostname,
        result: null, // 'ok' or 'fail'
        // time until streaming object to or from the shark begins
        timeToFirstByte: null,
        timeTotal: null, // total request time

        // private: time request begins (used to calculate other time values)
        _startTime: Date.now()
    };

    req.sharksContacted.push(sharkInfo);
    return (sharkInfo);
}

// Given a request object and shark name, returns the matching sharkInfo object.
// This is only meant to be used if we are certain the shark is in this request,
// and will cause an assertion failure otherwise.
function getSharkInfo(req, hostname) {
    var sharks = req.sharksContacted.filter(function (sharkInfo) {
        return (sharkInfo.shark === hostname);
    });

    assert.equal(sharks.length, 1, 'There should only be one sharkInfo ' +
        'with hostname "' + hostname + '"');

    return (sharks[0]);
}

// Maps a key to the location of its metadata in Manta.
//
// This function is in common.js so the mlocate tool can use it as well.
//
// Input:
//      placementData: A placementData object retrieved from buckets-mdplacemet
//      tkey: the key to locate
// Output:
//      an object with the location data, of the form:
//      {
//          pnode (string)
//          vnode (integer)
//          data (integer)
//      }
function getDataLocation(placementData, tkey) {
    assert.object(placementData, 'placementData');
    assert.string(tkey, 'tkey');

    var value = crypto.createHash(placementData.ring.algorithm.NAME).
        update(tkey).digest('hex');
    // find the node that corresponds to this hash.
    var vnodeHashInterval =
        placementData.ring.algorithm.VNODE_HASH_INTERVAL;

    var vnode = parseInt(bignum(value, 16).div(bignum(vnodeHashInterval, 16)),
        10);

    var pnode = placementData.ring.vnodeToPnodeMap[vnode].pnode;
    var data = placementData.ring.pnodeToVnodeMap[pnode][vnode];

    return {
        pnode: pnode,
        vnode: vnode,
        data: data
    };
}

///--- Exports

module.exports = {

    DEF_MIN_COPIES: DEF_MIN_COPIES,
    DEF_MAX_COPIES: DEF_MAX_COPIES,
    DEF_NUM_COPIES: DEF_NUM_COPIES,
    ZERO_BYTE_MD5: ZERO_BYTE_MD5,

    ANONYMOUS_USER: ANONYMOUS_USER,

    CORS_RES_HDRS: CORS_RES_HDRS,

    PATH_LOGIN_RE: PATH_LOGIN_RE,

    BUCKETS_ROOT_PATH: BUCKETS_ROOT_PATH,

    MAX_HDRSIZE: MAX_HDRSIZE,

    METRIC_REQUEST_COUNTER: METRIC_REQUEST_COUNTER,

    METRIC_LATENCY_HISTOGRAM: METRIC_LATENCY_HISTOGRAM,

    METRIC_DURATION_HISTOGRAM: METRIC_DURATION_HISTOGRAM,

    METRIC_INBOUND_DATA_COUNTER: METRIC_INBOUND_DATA_COUNTER,

    METRIC_OUTBOUND_DATA_COUNTER: METRIC_OUTBOUND_DATA_COUNTER,

    METRIC_DELETED_DATA_COUNTER: METRIC_DELETED_DATA_COUNTER,

    CURRENT_STORAGE_LAYOUT_VERSION: CURRENT_STORAGE_LAYOUT_VERSION,

    addCustomHeaders: addCustomHeaders,

    earlySetupHandler: function (opts) {
        assert.object(opts, 'options');

        function earlySetup(req, res, next) {
            res.once('header', function onHeader() {
                var now = Date.now();
                res.header('Date', new Date());
                res.header('x-request-id', req.getId());

                var xrt = res.getHeader('x-response-time');
                if (xrt === undefined) {
                    var t = now - req.time();
                    res.header('x-response-time', t);
                }
                res.header('x-server-name', ZONENAME);
            });

            // This will only be null on the _first_ request, and in
            // that instance, we're guaranteed that HAProxy sent us
            // an X-Forwarded-For header
            if (!req.connection._xff) {
                // Clean up clientip if IPv6
                var xff = req.headers['x-forwarded-for'];
                if (xff) {
                    /* JSSTYLED */
                    xff = xff.split(/\s*,\s*/).pop() || '';
                    xff = xff.replace(/^(f|:)+/, '');
                    req.connection._xff = xff;
                } else {
                    req.connection._xff =
                        req.connection.remoteAddress;
                }
            }

            /*
             * This might seem over-gratuitous, but it's necessary.  Per the
             * node.js documentation, if the socket is destroyed, it is possible
             * for `remoteAddress' to be undefined later on when we attempt to
             * log the specifics around this request.  As an insurance policy
             * against that, save off the remoteAddress now.
             */
            req.remoteAddress = req.connection.remoteAddress;

            var ua = req.headers['user-agent'];
            if (ua && /^curl.+/.test(ua))
                res.set('Connection', 'close');

            next();
        }

        return (earlySetup);
    },

    authorizationParser: function (req, res, next) {
        req.authorization = {};

        if (!req.headers.authorization)
            return (next());

        var pieces = req.headers.authorization.split(' ', 2);
        if (!pieces || pieces.length !== 2) {
            var e = new restifyErrors.InvalidHeaderError(
                'Invalid Authorization header');
            return (next(e));
        }

        req.authorization.scheme = pieces[0];
        req.authorization.credentials = pieces[1];

        if (pieces[0].toLowerCase() === 'signature') {
            try {
                req.authorization.signature = httpSignature.parseRequest(req);
            } catch (e2) {
                var err = new restifyErrors.InvalidHeaderError(
                    'Invalid Signature Authorization header: ' + e2.message);
                return (next(err));
            }
        }

        next();
    },

    setupHandler: function (options, clients) {
        assert.object(options, 'options');
        assert.object(clients, 'clients');

        function setup(req, res, next) {
            // General request setup
            req.config = options;
            req.metadataPlacement = clients.metadataPlacement;

            req.log = (req.log || options.log).child({
                method: req.method,
                path: req.path(),
                req_id: req.getId()
            }, true);

            // Attach an artedi metric collector to each request object.
            req.collector = options.collector;

            req.sharks = [];
            req.sharkConfig = options.sharkConfig;
            req.sharkAgent = clients.sharkAgent;
            req.msk_defaults = {
                maxStreamingSize: options.storage.defaultMaxStreamingSizeMB *
                    1024 * 1024
            };

            // Write request setup
            if (!req.isReadOnly()) {
                req.storinfo = clients.storinfo;
            }

            next();
        }

        return (setup);
    },

    findSharks: findSharks,
    startSharkStreams: startSharkStreams,
    sharkStreams: sharkStreams,
    streamFromSharks: streamFromSharks,

    getDataLocation: getDataLocation
};
