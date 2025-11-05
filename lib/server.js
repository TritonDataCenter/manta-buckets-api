/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
 */

var crypto = require('crypto');
var fs = require('fs');
var path = require('path');
var url = require('url');
var verror = require('verror');

var assert = require('assert-plus');
var bunyan = require('bunyan');
var mime = require('mime');
var restify = require('restify');

var audit = require('./audit');
var auth = require('./auth');
var buckets = require('./buckets');
var common = require('./common');
var other = require('./other');
var throttle = require('./throttle');
var s3Routes = require('./s3-routes');
var s3Compat = require('./s3-compat');
var anonymousAuth = require('./anonymous-auth');

var muskieUtils = require('./utils');

// injects into the global namespace
require('./errors');

///--- Globals

/* BEGIN JSSTYLED */
/*
 * from https://www.w3.org/Protocols/rfc1341/4_Content-Type.html
 * match 'type/subtype' where subtypes can be +/- delimited
 */
var VALID_CONTENT_TYPE_RE = /.+\/.+/;
/* END JSSTYLED */

///--- Helpers

// Binary formatter that passes data through unchanged (for S3 object downloads)
function formatBinary(req, res, body) {
    if (body instanceof Error) {
        // For errors, fall back to JSON formatting
        return (formatJSON(req, res, body));
    }

    // For binary data, return as-is without any conversion
    if (Buffer.isBuffer(body)) {
        return (body);
    }

    // For strings, convert to buffer to preserve binary data
    if (typeof (body) === 'string') {
        return (Buffer.from(body, 'binary'));
    }

    // For other data types, fall back to JSON
    return (formatJSON(req, res, body));
}

// Always force JSON
function formatJSON(req, res, body) {
    if (body instanceof Error) {
        body = translateError(body, req);
        res.statusCode = body.statusCode || 500;
        if (res.statusCode >= 500)
            req.log.warn(body, 'request failed: internal error');

        if (body.headers !== undefined) {
            for (var h in body.headers) {
                res.setHeader(h, body.headers[h]);
            }
        }

        if (body.body) {
            body = body.body;
        } else {
            body = {
                message: body.message
            };
        }

    } else if (Buffer.isBuffer(body)) {
        body = body.toString('base64');
    }

    var data = JSON.stringify(body);
    var md5 = crypto.createHash('md5').update(data).digest('base64');

    res.setHeader('Content-Length', Buffer.byteLength(data));
    res.setHeader('Content-MD5', md5);
    res.setHeader('Content-Type', 'application/json');

    return (data);
}

///--- API

/**
 * Wrapper over restify's createServer to make testing and
 * configuration handling easier.
 *
 * @param {object} options            - options object.
 * @param {object} options.log        - bunyan logger.
 * @param {object} options.collector  - artedi metric collector.
 * @param {object} clients            - client connection object.
 * @throws {TypeError} on bad input.
 */
function createServer(options, clients) {
    assert.object(options, 'options');
    assert.object(options.log, 'options.log');
    assert.object(options.collector, 'options.collector');
    assert.object(options.throttle, 'options.throttle');
    assert.object(clients, 'clients');

    // Custom formatter selection based on request type
    function selectFormatter(contentType, req, res) {
        // For S3 binary operations marked to skip processing, use NO formatter
        if (req && (req._skipS3ResponseProcessing ||
        req._binaryUpload || req._binaryOperation)) {
            return function (innerReq, innerRes, body) {
                // Return body completely unchanged - no formatting at all
                return (body);
            };
        }
        // For S3 object operations,
        // use binary formatter to preserve data integrity
        if (req && req.isS3Request &&
            req.s3Request &&
            (req.s3Request.operation === 'GetBucketObject' ||
            req.s3Request.operation === 'CreateBucketObject')) {
            return (formatBinary);
        }
        // For all other requests (traditional Manta), use JSON formatter
        return (formatJSON);
    }

    options.formatters = {
        'application/json': function (req, res, body) {
            return selectFormatter('application/json', req, res)
            (req, res, body);
        },
        'text/plain': function (req, res, body) {
            return (selectFormatter('text/plain', req, res)(req, res, body));
        },
        'application/octet-stream': function (req, res, body) {
            return (selectFormatter('application/octet-stream', req, res)
            (req, res, body));
        },
        'application/x-json-stream': function (req, res, body) {
            return (selectFormatter('application/x-json-stream', req, res)
            (req, res, body));
        },
        'image/gif': function (req, res, body) {
            return (selectFormatter('image/gif', req, res)(req, res, body));
        },
        'image/jpeg': function (req, res, body) {
            return (selectFormatter('image/jpeg', req, res)(req, res, body));
        },
        'image/png': function (req, res, body) {
            return (selectFormatter('image/png', req, res)(req, res, body));
        },
        '*/*': function (req, res, body) {
            return (selectFormatter('*/*', req, res)(req, res, body));
        }
    };
    options.noWriteContinue = true;
    options.handleUpgrades = true;
    options.version = ['1.0.0'];

    var log = options.log.child({
        component: 'HttpServer'
    }, true);
    var server = restify.createServer(options);

    /* Initialize metric collectors for use in handlers and audit logger. */
    // A counter to track the number of HTTP requests serviced.
    options.collector.counter({
        name: common.METRIC_REQUEST_COUNTER,
        help: 'count of Muskie requests completed'
    });
    /*
     * A mostly log-linear histogram to track the time to first byte.
     * Track values between 2 and 60000 ms (2ms to 1 minute).
     */
    options.collector.histogram({
        name: common.METRIC_LATENCY_HISTOGRAM,
        help: 'time-to-first-byte of Muskie requests',
        // These were generated with artedi.logLinearBuckets(10, 1, 3, 10); and
        // then some manual tweaking. Slightly different from muskie, but if
        // you're interested in the reasoning also see MANTA-5268 and MANTA-4388
        // for details.
        buckets: [
            2,
            4,
            6,
            8,
            10,
            12,
            14,
            16,
            18,
            20,
            25,
            30,
            35,
            40,
            45,
            50,
            60,
            70,
            80,
            90,
            100,
            200,
            300,
            400,
            500,
            600,
            700,
            800,
            900,
            1000,
            2000,
            4000,
            6000,
            8000,
            10000,
            30000,
            60000
        ]
    });
    // A pair of counters to track inbound and outbound throughput.
    options.collector.counter({
        name: common.METRIC_INBOUND_DATA_COUNTER,
        help: 'count of object bytes streamed from client to storage'
    });
    options.collector.counter({
        name: common.METRIC_OUTBOUND_DATA_COUNTER,
        help: 'count of object bytes streamed from storage to client'
    });
    options.collector.counter({
        name: common.METRIC_DELETED_DATA_COUNTER,
        help: 'count of deleted object bytes'
    });

    var _timeout = parseInt((process.env.SOCKET_TIMEOUT || 120), 10) * 1000;
    server.server.setTimeout(_timeout, function onTimeout(socket) {
        var l = (((socket._httpMessage || {}).req || {}).log || log);
        var req = socket.parser && socket.parser.incoming;
        var res = socket._httpMessage;

        if (req && req.complete && res) {
            l.warn('socket timeout: destroying connection');
            options.dtrace_probes.socket_timeout.fire(function onFire() {
                var dobj = req ? {
                    method: req.method,
                    url: req.url,
                    headers: req.headers,
                    id: req._id
                } : {};
                return ([dobj]);
            });
            socket.destroy();
        }
    });

    server.pre(function watchClose(req, res, next) {
        /*
         * In some cases, we proactively check for closed client connections.
         * Add a listener early on that just records this fact.
         */
        req.on('close', function () {
            req.log.warn('client closed connection');
            req._muskie_client_closed = true;
        });

        next();
    });
    server.pre(function stashPath(req, res, next) {
        req._probes = options.dtrace_probes;
        req.config = options;
        req.pathPreSanitize = url.parse(req.url).pathname;
        next();
    });

    // Add comprehensive request logging to debug AWS CLI behavior
    server.pre(function logAllRequests(req, res, next) {
        req.log.debug({
            method: req.method,
            url: req.url,
            path: req.path(),
            host: req.headers.host,
            userAgent: req.headers['user-agent'],
            authorization: req.headers.authorization ?
            req.headers.authorization.substring(0, 50) + '...' : 'NONE',
            contentType: req.headers['content-type'],
            contentLength: req.headers['content-length'],
            encoding: req.headers['content-encoding'],
            transferEncoding: req.headers['transfer-encoding'],
            allHeaders: Object.keys(req.headers)
        }, 'REQUEST_DEBUG: Incoming request details');

        var authHeader = req.headers.authorization ||
                         req.headers.Authorization || '';
        var isSigV4 = authHeader.toLowerCase().startsWith('aws4-hmac-sha256');

        // For S3 PUT or POST requests (object uploads),
        // force binary mode immediately to prevent corruption.
        if ((req.method === 'PUT' || req.method === 'POST') && isSigV4) {
            req.log.debug({
                isS3Upload: true,
                contentType: req.headers['content-type'],
                isChunked: req.isChunked()
            }, 'BINARY_DEBUG: S3 upload request detected;' +
                          ' forcing binary mode.');

            // Force binary mode as early as possible to prevent text
            // encoding corruption by subsequent handlers.
            if (req.setEncoding) {
                req.setEncoding(null);
            }
            if (req.readable && req.readable.setEncoding) {
                req.readable.setEncoding(null);
            }
            if (req._readableState) {
                req._readableState.encoding = null;
                req._readableState.decoder = null;
                req._readableState.objectMode = false;
            }
            if (req.connection && req.connection.setEncoding) {
                req.connection.setEncoding(null);
            }

            // Mark for binary handling to inform other parts of the system.
            req._binaryMode = true;
            req._forceRawData = true; // Potentially for disabling gzip, etc.

            // CRITICAL: Bypass restify processing by using the raw HTTP request
            // to ensure the stream is not consumed or altered.
            var rawReq = req.raw || req.connection.parser.incoming || req;
            if (rawReq && rawReq !== req) {
                req.log.debug('BINARY_DEBUG: Preserving binary stream ' +
                             'using raw request object.');
                req._rawRequest = rawReq;
                req._preserveBinaryData = true;
            }
        }

        next();
    });
    /*
     * MANTA-331: while a trailing '/' is ok in HTTP, this messes with
     * the consistent hashing, so ensure there isn't one by using
     * sanitizePath()
     */
    server.pre(restify.pre.sanitizePath());
    server.pre(function cleanupContentType(req, res, next) {
        var ct = req.headers['content-type'];
        /*
         * content-type must have a type, '/' and sub-type
         */
        if (ct && !VALID_CONTENT_TYPE_RE.test(ct)) {
            req.log.debug('receieved a malformed content-type: %s', ct);
            req.headers['content-type'] = mime.lookup(ct);
        }

        next();
    });

    // Raw body preservation pre-middleware for S3 signature verification
    // This MUST run before ANY other middleware that might consume the request
    // stream
    server.pre(function preserveRawBodyPreMiddleware(req, res, next) {
        // Check if this is a Complete Multipart Upload request
        var isCompleteMultipartUpload = false;
        if (req.method === 'POST' && req.url) {
            // Simple check for uploadId query parameter
            // (Complete Multipart Upload)
            isCompleteMultipartUpload = req.url.includes('uploadId=') &&
                                       !req.url.includes('uploads');
        }

        // Preserve raw body for POST requests that might be S3 bulk operations
        // Include: XML content-type requests, bulk delete requests,
        // OR Complete Multipart Upload requests
        var contentType = req.headers['content-type'] || '';
        var isBulkDeleteRequest = req.url && req.url.includes('delete');
        var isXmlRequest = contentType === 'application/xml' ||
                          contentType.startsWith('application/x-amz-json') ||
                          contentType.startsWith('text/xml');

        if (req.method === 'POST' &&
            req.headers['content-length'] &&
            parseInt(req.headers['content-length'], 10) > 0 &&
            req.headers.authorization &&
            (isXmlRequest || isCompleteMultipartUpload ||
             isBulkDeleteRequest)) {

            req.log.debug({
                method: req.method,
                contentLength: req.headers['content-length'],
                contentType: req.headers['content-type'],
                url: req.url,
                isCompleteMultipartUpload: isCompleteMultipartUpload,
                isBulkDeleteRequest: isBulkDeleteRequest,
                isXmlRequest: isXmlRequest
            }, 'S3_DEBUG: PRE-MIDDLEWARE - Preserving raw body for' +
            ' S3 signature verification, bulk delete,' +
            ' or multipart upload completion');

            var chunks = [];

            // Set up immediate data capture
            req.pause(); // Pause the stream to prevent data loss

            req.on('data', function (chunk) {
                chunks.push(chunk);
            });

            req.on('end', function () {
                if (chunks.length > 0) {
                    req._rawBodyBuffer = Buffer.concat(chunks);
                    req._rawBodyString = req._rawBodyBuffer.toString('utf8');

                    // Calculate and store the original content-md5
                    var md5Hash = crypto.createHash('md5');
                    md5Hash.update(req._rawBodyBuffer);
                    req._originalContentMD5 = md5Hash.digest('base64');

                    req.log.debug({
                        rawBodyLength: req._rawBodyBuffer.length,
                        originalContentMD5: req._originalContentMD5,
                        headerContentMD5: req.headers['content-md5'],
                        md5Match: req._originalContentMD5 ===
                            req.headers['content-md5'],
                        bodyPreview: req._rawBodyString.substring(0, 200)
                    }, 'S3_DEBUG: PRE-MIDDLEWARE - Raw body preserved' +
                                  ' for signature verification');

                    // Set req.body to the parsed content for immediate
                    // availability
                    req.body = req._rawBodyString;
                }

                // Call next() here to ensure body is available
                // before proceeding
                next();
            });

            req.on('error', function (err) {
                req.log.error(err, 'S3_DEBUG: PRE-MIDDLEWARE'+
                              ' - Error while preserving raw body');
                next(err);
            });

            req.resume(); // Resume the stream

            // Don't call next() here - wait for the 'end' event
            return;
        }
        next();
    });

    // S3 request detection middleware BEFORE other routes
    server.pre(function s3RequestDetectorEarly(req, res, next) {
        // Check if this is a SigV4 request and mark it for later processing
        var authHeader = req.headers.authorization ||
                        req.headers.Authorization ||
                        '';

        var authHeaderLower = authHeader.toLowerCase();
        var startsWithAws4 = authHeaderLower.indexOf('aws4-hmac-sha256') === 0;
        var host = req.headers.host || '';

        // Simple and clear S3 detection: ONLY SigV4 requests are S3 requests
        // Traditional Manta requests use HTTP Signature auth, not SigV4
        // Regardless of host format (virtual-hosted or path-style),
        // only SigV4 = S3
        var isSigV4 = startsWithAws4;
        var isS3Format = isSigV4;

        req.log.debug({
            method: req.method,
            path: req.path(),
            host: host,
            isSigV4: isSigV4,
            isS3Format: isS3Format,
            authHeaderFirst50: authHeader.substring(0, 50),
            detectionReason: isSigV4 ? 'SigV4_AUTH' : 'NOT_S3'
        }, 'S3_DEBUG: Strict S3 detection - Only SigV4 = S3');

        if (isS3Format) {
            req.log.debug('S3_DEBUG: DETECTED S3 REQUEST');
            req.isS3Request = true;
            req.s3Request = s3Compat.parseS3Request(req);
            req.log.debug({
                s3Request: req.s3Request
            }, 'S3_DEBUG: Parsed S3 request details');

            // For S3 object operations (uploads AND downloads),
            // mark to skip S3 response processing
            if ((req.method === 'PUT' &&
                req.s3Request.operation === 'CreateBucketObject') ||
                (req.method === 'GET' &&
                  req.s3Request.operation === 'GetBucketObject')) {
                req.log.debug('S3_DEBUG: Marking S3 object operation'+
                ' to skip response processing (method=' + req.method + ')');

                // Mark this request to skip ALL S3 response processing
                req._skipS3ResponseProcessing = true;
                req._binaryOperation = true;
            }
        } else {
           // req.log.debug('S3_DEBUG: Not S3 request'+
           // ' - using traditional Manta routing');
            req.isS3Request = false;
        }

        next();
    });

    // NOTE: S3 root handler will be added after authentication middleware
    // look at consolidatedRootHandler(req, res, next)

    // Set up other routes (ping, docs, etc..)
    server.get({
        path: '/ping',
        name: 'ping'
    }, function ping(req, res, next) {
        res.set('Connection', 'close');
        res.set('Content-Length', 0);
        res.writeHead(200);
        res.end();
        next();
    });

    server.get(/^\/docs\/?/, function redirect(req, res, next) {
        res.set('Content-Length', 0);
        res.set('Connection', 'keep-alive');
        res.set('Date', new Date());
        res.set('Location', 'http://apidocs.joyent.com/manta/');
        res.send(302);
        next(false);
    });

    server.use(function _traceTTFB(req, res, next) {
        //
        // When it sends the header, restify's response object emits `header`.
        // See the `Response.prototype.writeHead` function.
        //
        // We use that here as our best proxy for time to first byte. Since the
        // header is the first part of our response. Some methods (specifically
        // streamFromSharks and sharkStreams) will override this to set their
        // own idea of when the first byte was (which might be before we send
        // anything to the client). The `audit.auditLogger` in the `after`
        // handler will use the final value when writing out metrics.
        //
        res.once('header', function _onHeader() {
            if (!req._timeAtFirstByte) {
                req._timeAtFirstByte = Date.now();
            }
        });

        next();
    });

    server.use(common.earlySetupHandler(options));
    server.use(restify.plugins.dateParser(options.maxRequestAge || 300));


    server.use(restify.plugins.queryParser());

    server.use(common.authorizationParser);
    server.use(auth.convertS3PresignedToManta);
    server.use(auth.checkIfPresigned);

    server.use(function ensureDependencies(req, res, next) {
        var ok = true;
        var errors = [];
        var error;

        if (!clients.mahi) {
            error = 'mahi unavailable';
            errors.push(new Error(error));
            req.log.error(error);
            ok = false;
        }

        if (!clients.storinfo && !req.isReadOnly()) {
            error = 'storinfo unavailable';
            errors.push(new Error(error));
            req.log.error(error);
            ok = false;
        }

        if (!clients.metadataPlacement) {
            error = 'metadataPlacement client unavailable';
            errors.push(new Error(error));
            req.log.error(error);
            ok = false;
        }

        if (!ok) {
            next(new ServiceUnavailableError(req,
                        new verror.MultiError(errors)));
        } else {
            next();
        }
    });

    if (options.throttle.enabled) {
        options.throttle.log = options.log;
        var throttleHandle = throttle.createThrottle(options.throttle);
        server.use(throttle.throttleHandler(throttleHandle));
    }
    // Add debug logging before authentication
    server.use(function preAuthDebug(req, res, next) {
        if (req.isS3Request) {
            req.log.debug('S3_DEBUG: About to run authentication handler');
        }
        next();
    });

    // Anonymous access handler for public buckets (before authentication,
    // with metadata client)
    server.use(function (req, res, next) {
        // Set up metadataPlacement early for anonymous access handler
        req.metadataPlacement = clients.metadataPlacement;
        anonymousAuth.anonymousAccessHandler(req, res, next);
    });

    server.use(auth.authenticationHandler({
        log: log,
        mahi: clients.mahi,
        keyapi: clients.keyapi
    }));

    // Add debug logging after authentication
    server.use(function postAuthDebug(req, res, next) {
        if (req.isS3Request) {
            req.log.debug({
                caller: req.caller ? {
                    type: req.caller.account ? 'account' : 'user',
                    login: req.caller.account ?
                    req.caller.account.login : 'unknown',
                    uuid: req.caller.account ?
                    req.caller.account.uuid : 'unknown'
                } : null,
                hasAuthorization: !!req.authorization
            }, 'S3_DEBUG: Authentication completed');
        }
        next();
    });

    server.use(auth.gatherContext);

    // Add various fields to the 'req' object before ANY
    // S3 handlers get called.
    // This MUST come before both root handler
    // and S3 routing so req.metadataPlacement is available
    server.use(common.setupHandler(options, clients));

    // Add consolidated root handler AFTER authentication AND setup
    server.get('/', function consolidatedRootHandler(req, res, next) {
        if (req.isS3Request) {
            var addressingStyle = req.s3Request ?
            req.s3Request.addressingStyle : 'unknown';
            req.log.debug({
                addressingStyle: addressingStyle,
                host: req.headers.host,
                s3Request: req.s3Request
            }, 'S3_DEBUG: Consolidated root handler - processing S3 request');

            // Apply S3 middleware
            s3Compat.s3HeaderTranslator(req, res, function (headerErr) {
                if (headerErr) {
                    req.log.error(headerErr,
                    'S3_DEBUG: Error in s3HeaderTranslator');
                    next(headerErr);
                    return;
                }
                req.log.debug('S3_DEBUG: s3HeaderTranslator completed');

                s3Compat.s3ConditionalHeaders(req, res,
                                              function (conditionalErr) {
                    if (conditionalErr) {
                        req.log.error(conditionalErr,
                        'S3_DEBUG: Error in s3ConditionalHeaders');
                        next(conditionalErr);
                        return;
                    }

                    req.log.debug('S3_DEBUG: s3ConditionalHeaders completed');

                    s3Compat.s3RoleTranslator(req, res, function (roleErr) {
                        if (roleErr) {
                            req.log.error(roleErr,
                            'S3_DEBUG: Error in s3RoleTranslator');
                            next(roleErr);
                            return;
                        }
                        req.log.debug('S3_DEBUG: s3RoleTranslator completed');

                        s3Compat.s3ResponseFormatter(req, res,
                            function (formatterErr) {
                                if (formatterErr) {
                                    req.log.error(formatterErr,
                                        'S3_DEBUG: s3ResponseFormatter Failed');
                                    next(formatterErr);
                                    return;
                            }
                            req.log.debug('S3_DEBUG: s3ResponseFormatter ' +
                                          'completed, calling handleS3Request');

                            // Route to S3 handler
                            handleS3Request(req, res, function (handlerErr) {
                                // Always terminate S3 requests to
                                // prevent double execution
                                if (handlerErr) {
                                    // Convert error to S3 XML format and
                                    // send directly Log user errors at info
                                    // level, system errors at error level
                                    var isUserError = (handlerErr.statusCode >=
                                        400 && handlerErr.statusCode < 500) ||
                                        (handlerErr.name &&
                                        (handlerErr.name.includes('NotFound') ||
                                         handlerErr.name.includes('Exists') ||
                                         handlerErr.name.
                                             includes('BadRequest')));

                                    if (isUserError) {
                                        req.log.debug({
                                            errorName: handlerErr.name,
                                            errorCode: handlerErr.restCode ||
                                                handlerErr.code,
                                            statusCode: handlerErr.statusCode,
                                            bucket: req.s3Request ?
                                                req.s3Request.bucket :
                                                'unknown',
                                            object: req.s3Request ?
                                                req.s3Request.object :
                                                'unknown'
                                            },
                                            'S3: User error in S3 handler'+
                                          ', returning S3 XML error response');
                                    } else {
                                        req.log.error(handlerErr, 'S3:' +
                                            ' System error in S3 handler,' +
                                            ' converting to S3 XML format');
                                    }

                                    var s3XmlError =
                                        s3Compat.convertErrorToS3(handlerErr,
                                                                  req.s3Request,
                                                                  req);

                                    // Get proper status code
                                    // (ObjectNotFoundError should be 404)
                                    var statusCode = 500; // default
                                    if (handlerErr.name ===
                                        'ObjectNotFoundError' ||
                                        handlerErr.restCode ===
                                        'ObjectNotFoundError') {
                                        statusCode = 404;
                                    } else if (handlerErr.name ===
                                               'BucketNotFoundError' ||
                                               handlerErr.restCode ===
                                               'BucketNotFoundError') {
                                               statusCode = 404;
                                    } else if (handlerErr.name ===
                                               'BucketExistsError' ||
                                               handlerErr.restCode ===
                                               'BucketExistsError') {
                                               statusCode = 409;
                                    } else if (handlerErr.statusCode &&
                                        typeof (handlerErr.statusCode) ===
                                               'number') {
                                               statusCode =
                                               handlerErr.statusCode;
                                    } else if (handlerErr.code &&
                                               typeof (handlerErr.code) ===
                                               'number') {
                                               statusCode = handlerErr.code;
                                    }

                                    res.writeHead(statusCode, {
                                        'Content-Type': 'application/xml',
                                        'Content-Length':
                                            Buffer.byteLength(s3XmlError,
                                            'utf8'),
                                        'x-amz-request-id':
                                            res.getHeader('x-amz-request-id') ||
                                            'unknown',
                                        'x-amz-id-2':
                                            res.getHeader('x-amz-id-2') ||
                                            'unknown'
                                    });
                                    res.write(s3XmlError, 'utf8');
                                    res.end();
                                }
                                next(false); // Stop route processing
                            });
                        });
                    });
                });
            });
        } else {
            // Traditional redirect for docs
            req.log.debug('Consolidated root handler - redirecting to docs');
            res.set('Content-Length', 0);
            res.set('Connection', 'keep-alive');
            res.set('Date', new Date());
            res.set('Location', 'http://apidocs.tritondatacenter.com/manta/');
            res.send(302);
            next(false);
        }
    });

    /*
     * Add S3 routes BEFORE traditional Manta routes to ensure S3
     * requests are handled first S3 catch-all routes that will route detected
     * S3 requests to handleS3Request. These need to be broad enough to catch S3
     * paths but only process S3 requests.
     *
     * s3RouteHandler:
     * This how we handle S3 requests, we route them to the appropiate
     * handler through handleS3request, but first we need to examine the S3
     * request to start creating a bucket/object request that Manta could
     * understand, and a XML response that S3 clients could process.
     */
    function s3RouteHandler(req, res, next) {
        if (req.isS3Request) {
            req.log.debug('S3_DEBUG: S3 route handler processing S3 request');
            // Convert S3 AWS headers to ones that Manta could use/understand
            s3Compat.s3HeaderTranslator(req, res, function (headerErr) {
                if (headerErr) {
                    req.log.error(headerErr,
                                  'S3_DEBUG: Error in s3HeaderTranslator');
                    next(headerErr);
                    return;
                }
                req.log.debug('S3_DEBUG: s3HeaderTranslator completed');

                /*
                 * Here we take care of the headers that deal with
                 * conditional object creation:
                 *  - If-Unmodified-Since
                 *  - If-Match
                 *  - If-None-Match
                 */
                s3Compat.s3ConditionalHeaders(req, res,
                                              function (conditionalErr) {
                    if (conditionalErr) {
                        req.log.error(conditionalErr,
                        'S3_DEBUG: Error in s3ConditionalHeaders');
                        next(conditionalErr);
                        return;
                    }

                    req.log.debug('S3_DEBUG: s3ConditionalHeaders completed');

                    /*
                     * Handle basic ACL, we translate the AWS supplied role
                     * to one that exists(we need to create it before) in Manta.
                     */

                    s3Compat.s3RoleTranslator(req, res, function (roleErr) {
                        if (roleErr) {
                            req.log.error(roleErr,
                            'S3_DEBUG: Error in s3RoleTranslator');
                            next(roleErr);
                            return;
                        }
                        req.log.debug('S3_DEBUG: s3RoleTranslator completed');

                        s3Compat.s3ResponseFormatter(req, res,
                                                     function (formatterErr) {
                            if (formatterErr) {
                                req.log.error(formatterErr,
                                'S3_DEBUG: Error in s3ResponseFormatter');
                                next(formatterErr);
                                return;
                            }
                            req.log.debug('S3_DEBUG:'+
                            ' s3ResponseFormatter completed,' +
                            ' calling handleS3Request');

                            // Routes request to the appropiate S3 handler
                            handleS3Request(req, res, function (handlerErr) {
                                // Always terminate S3 requests to
                                // prevent double execution
                                if (handlerErr) {
                                    // Convert error to S3 XML format and
                                    // send directly
                                    // Log user errors at info level,
                                    // system errors at error level
                                    var isUserError =
                                        (handlerErr.statusCode >=
                                         400 && handlerErr.statusCode < 500) ||
                                         (handlerErr.name &&
                                          (handlerErr.name.
                                               includes('NotFound') ||
                                           handlerErr.name.
                                               includes('Exists') ||
                                           handlerErr.name.
                                               includes('BadRequest')));

                                    if (isUserError) {
                                        req.log.debug({
                                            errorName: handlerErr.name,
                                            errorCode: handlerErr.restCode ||
                                                handlerErr.code,
                                            statusCode: statusCode,
                                            bucket: req.s3Request ?
                                                req.s3Request.bucket :
                                                    'unknown',
                                            object: req.s3Request ?
                                                req.s3Request.object : 'unknown'
                                        }, 'S3_DEBUG: User error '+
                                               'in S3 handler'+
                                               ', returning S3 XML error' +
                                               ' response');
                                    } else {
                                        req.log.debug(handlerErr,
                                           'S3_DEBUG: System error' +
                                           ' in S3 handler,' +
                                           ' converting to S3 XML format');
                                    }
                                    var s3XmlError = s3Compat.convertErrorToS3(
                                        handlerErr, req.s3Request, req);

                                    /*
                                     * Get proper status code
                                     * (ObjectNotFoundError  should be 404)
                                     */
                                    var statusCode = 500; // default
                                    if (handlerErr.name ===
                                        'ObjectNotFoundError' ||
                                        handlerErr.restCode ===
                                        'ObjectNotFoundError') {
                                            statusCode = 404;
                                    } else if (handlerErr.name ===
                                               'BucketNotFoundError' ||
                                               handlerErr.restCode ===
                                               'BucketNotFoundError') {
                                                   statusCode = 404;
                                    } else if (handlerErr.name ===
                                               'BucketExistsError' ||
                                               handlerErr.restCode ===
                                               'BucketExistsError') {
                                                   statusCode = 409;
                                    } else if (handlerErr.statusCode &&
                                               typeof (handlerErr. statusCode)
                                               === 'number') {
                                                   statusCode =
                                                       handlerErr.statusCode;
                                    } else if (handlerErr.code &&
                                               typeof (handlerErr.code) ===
                                               'number') {
                                        statusCode = handlerErr.code;
                                    }

                                    res.writeHead(statusCode, {
                                        'Content-Type': 'application/xml',
                                        'Content-Length':
                                        Buffer.byteLength(s3XmlError, 'utf8'),
                                        'x-amz-request-id':
                                        res.getHeader('x-amz-request-id') ||
                                            'unknown',
                                        'x-amz-id-2':
                                            res.getHeader('x-amz-id-2') ||
                                                'unknown'});

                                    res.write(s3XmlError, 'utf8');
                                    res.end();
                                }
                                next(false); // Stop route processing
                            });
                        });
                    });
                });
            });
        } else {
            // Not an S3 request, let it continue to traditional routes
            req.log.debug('S3_DEBUG: Not S3 request, passing to next handler');
            next();
        }
    }

    /*
     * Add specific S3 route handlers that won't interfere with traditional
     * Manta routes. These catch S3-style paths but let traditional Manta paths
     * pass through
     *
     * Buckets API (traditional Manta routes) - REGISTER FIRST for priority
     * Requests that don't match the traditional manta routes will fall in the
     * S3 routes. The intention was to keep both styles and encapsulate functio-
     * nality.
     */
    addBucketsRoutes(server);

    /*
     * Here we expose the S3 routes that we currently support.
     */

     /*
      * S3 root path (List all buckets)
      */
    server.get('/', s3RouteHandler);


    /*
     * The magic happens here, on the server.pre hook we detect if the request
     * requires the S3 layer (is the only one that requires SigV4 auth). Hence
     * here we conditionally do pass the request to the s3RouteHandler is
     * the request is for the S3 layer or we just passed through to the tradion-
     * al manta-buckets-api.
     */


     /*
      * Single path segment Bucket Operations
      * What does it means?
      * Single path just means the request has the following form
      * s3://<bucket-name>/, so we are directly operating on a bucket
      * and those operations are : GET, HEAD, PUT, DELETE, POST
      * Which translates to :
      *  - List buckets
      *  - List bucket contents
      *  - Check if Bucket exists
      *  - Create Bucket
      *  - Delete Bucket (here post is a special case when bulk deleting)
      */
    server.get(/^\/([^\/]+)$/, function (req, res, next) {
        if (req.isS3Request) {
            req.log.debug('S3_DEBUG: S3 single-segment GET route'+
            ' handling S3 request');
            s3RouteHandler(req, res, next);
        } else {
            req.log.debug('S3_DEBUG: S3 single-segment GET route '+
            'passing through non-S3 request');
            next();
        }
    });

    server.put(/^\/([^\/]+)$/, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.head(/^\/([^\/]+)$/, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.del(/^\/([^\/]+)$/, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.post(/^\/([^\/]+)$/, function (req, res, next) {
        if (req.isS3Request) {
            req.log.debug('S3_DEBUG: S3 single-segment POST' +
                          ' route handling S3 request');
            s3RouteHandler(req, res, next);
        } else {
            req.log.debug('S3_DEBUG: S3 single-segment POST' +
                          ' route passing through non-S3 request');
            next();
        }
    });

     /*
      * One or more path segment Bucket Operations for S3 and Manta bucket
      * objects
      *
      *  The regex route /^\/([^\/]+)\/(.+)$/ catches both:
      *  - S3 requests: /bucket/object
      *  - Manta requests: /account/buckets/bucket_name/objects/object_name
      *
      * What does it means?
      * It just means the request has the following form:
      *  For S3 requests:
      *  - /bucket/object
      *  - /bucket/somepath/object
      *  For Manta requests:
      *  - /account/buckets/bucket_name/objects/object_name
      *
      * Here we are directly operating on a bucket object
      * and those operations are : GET, HEAD, PUT, DELETE
      * Which translates to :
      *  - List bucket contents
      *  - Check if object exists
      *  - Create Object in Bucket
      *  - Delete Object in Bucket
      */

    server.get(/^\/([^\/]+)\/(.+)$/, function (req, res, next) {
        req.log.debug({
            path: req.path(),
            isS3Request: !!req.isS3Request
        }, 'S3_DEBUG: GET two-segment route - checking if S3 request');

        if (req.isS3Request) {
            req.log.debug('S3_DEBUG: Processing as S3 request'+
            ' in GET two-segment route');
            s3RouteHandler(req, res, next);
        } else {
                /*
                 * We should really process the traditional Manta route but,
                 * as we allowed anonymous object access through http
                 * that falls into a Manta route so we need to execute more
                 * steps before falling through, only if the object has
                 * anonymous access.
                 */

                /*
                 * Check for Manta-style bucket object path:
                 * /account/buckets/bucket_name/objects/...
                 * if we are here, it probably  means we are trying to get the
                 * object and we need to account if this object has anonymous
                 * access.
                 */

                /*
                 * Normalize URI, removing blanks.
                 */
                var requestPath = req.path();
                var pathParts = requestPath.split('/').filter(function (part) {
                    return (part.length > 0);
                });

                /*
                 * This is important, req.potentialAnonymousAccess means
                 * this request is not authenticated through SigV4 nor HTTP
                 * signature, so we need to know if we could reach this object
                 * without auth.
                 *
                 */

                if (pathParts.length >= 5 && pathParts[1] === 'buckets' &&
                    pathParts[3] === 'objects' &&
                    req.potentialAnonymousAccess) {
                        req.log.debug('S3_DEBUG: Detected Manta bucket' +
                                      ' object request' +
                                      ' with potential anonymous access' +
                                      ', routing to bucket handler');

                        /*
                         * Set up the route parameters that the bucket object
                         * handler expects
                         */
                        req.params = req.params || {};
                        req.params.account = pathParts[0];
                        req.params.bucket_name = pathParts[2];
                        req.params.object_name = pathParts.slice(4).join('/');

                        req.log.debug({
                            account: req.params.account,
                            bucket_name: req.params.bucket_name,
                            object_name: req.params.object_name
                            }, 'S3_DEBUG: Set up Manta route parameters' +
                            ' for bucket' +
                            ' object request');

                        /*
                         * Execute the bucket object handler chain using
                         * Restify's built-in chaining
                         */
                        var rawHandlers = buckets.getBucketObjectHandler();

                        // Flatten the handler chain since some handlers
                        // return arrays
                        var handlers = [];
                        rawHandlers.forEach(function (handler) {
                            if (Array.isArray(handler)) {
                                handlers = handlers.concat(handler);
                            } else {
                                    handlers.push(handler);
                            }});

                        req.log.debug({
                            rawHandlerCount: rawHandlers.length,
                            flattenedHandlerCount: handlers.length
                        }, 'S3_DEBUG: Flattened bucket object handler chain');

                        /*
                         * Create a mini-router to execute the handler chain
                         * Why?, Restify cannot handle nested arrays that
                         * getBucketObjectHandler() returns.
                         * The relevant thing here is that
                         * getBucketObjectHandler has the middleware that allows
                         * us to determinate if we have access to the object,
                         * through setting req.caller to roles ['public-read']
                         * and, isAnonymousPublicAccess: true
                         */
                        var chainedHandler =
                            function (request, response, nextHandler) {
                                var index = 0;
                                function executeNext(err) {
                                    if (err) {
                                        return (nextHandler(err));
                                    }

                                    if (index >= handlers.length) {
                                        return (nextHandler());
                                    }

                                    var currentHandler = handlers[index++];

                                    // Ensure we have a valid function before
                                    // calling
                                    if (typeof (currentHandler) ===
                                        'function') {
                                            try {
                                                currentHandler(request,
                                                               response,
                                                               executeNext);
                                            } catch (e) {
                                                nextHandler(e);
                                            }
                                    } else {
                                        request.log.error({
                                            handlerIndex: index - 1,
                                            handlerType:
                                                typeof (currentHandler),
                                            handler: currentHandler
                                        }, 'Invalid handler in' +
                                           ' bucket object chain');

                                        nextHandler(new Error(
                                             'Invalid handler in bucket' +
                                             ' object chain at index ' +
                                             (index - 1)));
                                    }
                            }
                                executeNext();
                        };
                        return (chainedHandler(req, res, next));
            } else {
                req.log.debug('S3_DEBUG: Passing through to next '+
                    'handler in GET two-segment route');
                next();
            }
        }
    });

    server.put(/^\/([^\/]+)\/(.+)$/, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }});

    server.head(/^\/([^\/]+)\/(.+)$/, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }});

    server.del(/^\/([^\/]+)\/(.+)$/, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }});

    server.post(/^\/([^\/]+)\/(.+)$/, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }});

    // Tokens

    server.post({
        path: '/:account/tokens',
        name: 'CreateToken'
    }, auth.postAuthTokenHandler());


    var _audit = audit.auditLogger({
        collector: options.collector,
        log: log
    });

    server.on('after', function (req, res, route, err) {
        _audit(req, res, route, err);

        if ((req.method === 'PUT' || req.method === 'POST') &&
            res.statusCode >= 400) {
            /*
             * An error occurred on a PUT or POST request, but there may still
             * be incoming data on the request stream. Call resume() in order to
             * dump any remaining request data so the stream emits an 'end' and
             * the socket resources are not leaked.
             */
            req.resume();
        }
    });

    return (server);
}


function methodNotAllowHandler(req, res, next) {
    req.log.debug('Method ' + req.method + ' disallowed for ' + req.url);
    res.send(405);
    next(false);
}

/*
 * Handle S3 requests by routing to appropriate S3 handlers based on path
 * and method. This function is called only for SigV4 authenticated requests,
 * which are the request that the S3 layer is intended to process.
 */
function handleS3Request(req, res, next) {
    var method = req.method.toLowerCase();
    var requestPath = req.path();
    var pathParts = requestPath.split('/').filter(function (part) {
        return (part.length > 0); });

    req.log.debug({
        method: method,
        path: requestPath,
        pathParts: pathParts,
        hasAuth: !!req.authorization,
        hasCaller: !!req.caller
    }, 'S3_DEBUG: handleS3Request - routing S3 request');

    try {
        /*
         *  S3 List Buckets for account: GET /
         *  as pathParts.length === 0
         *  the user is requesting a list for the
         *  root path not specifying a particular bucket,
         *  so in a nutshell the user just wants list
         *  the buckets available in the account.
         *
         *  For example:
         *  $ s3cmd ls s3://
         *
         *  Falls in this case.
         *
         */
        if (method === 'get' && pathParts.length === 0) {
                req.log.debug('S3_DEBUG: Routing to s3ListBucketsHandler');
                return (s3Routes.s3ListBucketsHandler()(req, res, next));

        }

        /*
         * S3 Bucket Operations: /:bucket
         * as pathParts.lenght at least has one element, it means the user
         * is requesting an operation using /<bucketname>/, as the parameter.
         *
         * The HTTP verb and req.s3RequestOperation serves as keys to decide
         * which is the actual operation that the user is requesting.
         *
         *
         *  +------------+-------------------+-----------------------------+
         *  |HTTP VERB   |S3Request          |Handler                      |
         *  +------------+-------------------+-----------------------------+
         *  |PUT         |NONE               |s3CreateBucketHandler        |
         *  +------------+-------------------+-----------------------------+
         *  |GET         |ListBucketObjectsV2| s3ListBucketObjectsV2Handler|
         *  +------------+-------------------+-----------------------------+
         *  |GET         |ListBucketObjects  | s3ListBucketObjectsHandler  |
         *  +------------+-------------------+-----------------------------+
         *  |HEAD        |NONE               | s3HeadBucketHandler         |
         *  +------------+-------------------+-----------------------------+
         *  |POST        |DeleteBucketObjects| s3DeleteBucketObjectsHandler|
         *  +------------+-------------------+-----------------------------+
         *  |DELETE      |NONE               | s3DeleteBucketHandler       |
         *  +------------+-------------------+-----------------------------+
         *
         */
        if (pathParts.length === 1) {
            var pathBucketName = pathParts[0];
            req.params = req.params || {};
            req.params.bucket = pathBucketName;
            req.params[0] = pathBucketName; // For regex routes compatibility

            req.log.debug({
                operation: 'bucket-' + method,
                bucket: pathBucketName
            }, 'S3_DEBUG: Routing to bucket operation handler');

            switch (method) {
                case 'put':
                    return (s3Routes.s3CreateBucketHandler()(req, res, next));
                case 'get':
                    // DEBUG: Log routing decision
                    req.log.debug('S3_DEBUG_ROUTING: handleS3Request GET case'+
                    ' - making routing decision');
                    req.log.debug('S3_DEBUG_ROUTING: req.s3Request exists:',
                    !!req.s3Request);
                    req.log.debug('S3_DEBUG_ROUTING: req.s3Request.operation:',
                    req.s3Request ? req.s3Request.operation : 'undefined');
                    req.log.debug('S3_DEBUG_ROUTING: operation ==='+
                    ' ListBucketObjectsV2:',
                    req.s3Request && req.s3Request.operation ===
                    'ListBucketObjectsV2');

                    // Check if this is a ListObjectsV2 request based on
                    // s3Request.operation
                    if (req.s3Request && req.s3Request.operation ===
                    'ListBucketObjectsV2') {
                        req.log.debug('S3_DEBUG_ROUTING:  '+
                        'ROUTING TO s3ListBucketObjectsV2Handler');
                        return (s3Routes.s3ListBucketObjectsV2Handler()(req,
                        res, next));
                    } else {
                        req.log.debug('S3_DEBUG_ROUTING:  '+
                        'ROUTING TO s3ListBucketObjectsHandler (V1)');
                        return (s3Routes.s3ListBucketObjectsHandler()(req,
                        res, next));
                    }
                case 'head':
                    return (s3Routes.s3HeadBucketHandler()(req, res, next));
                case 'delete':
                    return (s3Routes.s3DeleteBucketHandler()(req, res, next));
                case 'post':
                    // Check if this is a bulk delete operation
                    if (req.s3Request && req.s3Request.operation
                        === 'DeleteBucketObjects') {
                        req.log.debug('S3_DEBUG_ROUTING:' +
                           'ROUTING TO s3DeleteBucketObjectsHandler');
                        return (s3Routes.s3DeleteBucketObjectsHandler()
                                (req, res, next));
                    } else {
                        req.log.warn('S3_WARN: Unsupported POST' +
                                     ' operation for bucket');
                        res.send(405, {
                            code: 'MethodNotAllowed',
                            message: 'The specified method is not allowed' +
                                ' against this resource.'
                        });
                        return (next(false));
                    }
                default:
                    req.log.warn({
                        method: method,
                        path: path
                    },
                    'S3_DEBUG: unsupported HTTP method for bucket operation');
                    res.send(405, {
                        code: 'MethodNotAllowed',
                        message: 'The specified'+
                        ' method is not allowed against this resource.'
                    });
                    next(false);
                    break;
            }
        }

        /*
         * S3 Bucket Operations: /:bucket/path/to/object
         * as pathParts.lenght has more than one element, it means the user
         * is requesting an operation on an object existing or new using
         * it's path or future path as parameter for example:
         *
         * - /bucketname/path/to/object
         * - /mybucket/myfiles/somefile.txt
         * - /mybucket/file.txt
         *
         * In the special case of multipart uploads that only the S3Request
         * is used to determinate that we need to process a MPU request.
         *
         * a MPU request has the following steps:
         *
         * Steps                            |S1| S2 |  S3   | S4 |
         * -------------------------------------------------------
         * s3InitiateMultipartUploadHandler |==|
         * s3UploadPartHandler                  |===|
         * s3CompleteMultipartUploadHandler          |======|
         * s3AbortMultipartUploadHandler                    |====|
         *
         * User could call s3CompleteMultipartUpload to generate the final
         * file, or just Abort the MPU request.
         *
         * As before the HTTP verb and req.s3RequestOperation serves as keys to
         * decide which is the actual operation that the user is requesting.
         *
         *  +------------+-------------------+-----------------------------+
         *  |HTTP VERB   |S3Request          |Handler                      |
         *  +------------+-------------------+-----------------------------+
         *  |HEAD        |NONE               | s3HeadBucketObjectHandler   |
         *  +------------+-------------------+-----------------------------+
         *  |POST || PUT |NONE               | s3CreateBucketObjectsHandler|
         *  +------------+-------------------+-----------------------------+
         *  |DELETE      |NONE               | s3DeleteBucketObjectHandler |
         *  +------------+-------------------+-----------------------------+
         *  |GET         |NONE               | s3GetBucketObjectHandler    |
         *  +------------+-------------------+-----------------------------+
         *
         */

        if (pathParts.length >= 2) {
            var objectBucketName = pathParts[0];
            var objectPath = pathParts.slice(1).join('/');
            req.params = req.params || {};
            req.params.bucket = objectBucketName;
            req.params['*'] = objectPath;
            req.params[0] = objectBucketName; // For regex routes compatibility
            req.params[1] = objectPath; // For regex routes compatibility

            req.log.debug({
                operation: 'object-' + method,
                bucket: objectBucketName,
                object: objectPath
            }, 'S3_DEBUG: Routing to object operation handler');

            // Check for multipart upload operations first
            if (req.s3Request && req.s3Request.operation ===
                'InitiateMultipartUpload') {
                req.log.debug('S3_DEBUG_ROUTING:' +
                              ' ROUTING TO s3InitiateMultipartUploadHandler');
                return s3Routes.s3InitiateMultipartUploadHandler()
                (req, res, next);
            } else if (req.s3Request &&
                       req.s3Request.operation === 'UploadPart') {
                req.log.debug('S3_DEBUG_ROUTING:' +
                              '  ROUTING TO s3UploadPartHandler');
                return (s3Routes.s3UploadPartHandler()(req, res, next));
            } else if (req.s3Request && req.s3Request.operation
                       === 'CompleteMultipartUpload') {
                req.log.debug('S3_DEBUG_ROUTING:' +
                      ' ROUTING TO s3CompleteMultipartUploadHandler');
                return (s3Routes.s3CompleteMultipartUploadHandler()
                        (req, res, next));
            } else if (req.s3Request && req.s3Request.operation ===
                       'AbortMultipartUpload') {
                req.log.debug('S3_DEBUG_ROUTING:' +
                             ' ROUTING TO s3AbortMultipartUploadHandler');
                return (s3Routes.s3AbortMultipartUploadHandler()
                        (req, res, next));
            } else if (req.s3Request && req.s3Request.operation ===
                       'ListParts') {
                req.log.debug('S3_DEBUG_ROUTING:' +
                             ' ROUTING TO s3ListPartsHandler');
                return (s3Routes.s3ListPartsHandler()
                        (req, res, next));
            } else if (req.s3Request && req.s3Request.operation ===
                       'ResumeUpload') {
                req.log.debug('S3_DEBUG_ROUTING:' +
                             ' ROUTING TO s3ResumeUploadHandler');
                return (s3Routes.s3ResumeUploadHandler()
                        (req, res, next));
            }

            switch (method) {
                case 'post': // Fallthrough
                case 'put':
                    return s3Routes.s3CreateBucketObjectHandler()(req, res,
                    next);
                case 'get':
                    return s3Routes.s3GetBucketObjectHandler()(req, res,
                    next);
                case 'head':
                    return s3Routes.s3HeadBucketObjectHandler()(req, res,
                    next);
                case 'delete':
                    return s3Routes.s3DeleteBucketObjectHandler()(req, res,
                    next);
                default:
                    req.log.warn({
                        method: method,
                        path: requestPath
                    },
                    'S3_WARN: unsupported HTTP method for object operation');
                    res.send(405, {
                        code: 'MethodNotAllowed',
                        message: 'The specified method'+
                        ' is not allowed against this resource.'
                    });
                return (next(false));
            }
        }

        // If we get here, no S3 route matched
        req.log.warn({
            method: method,
            path: path
        }, 'S3_DEBUG: no S3 route matched for SigV4 request');

        res.send(404, {
            code: 'NoSuchKey',
            message: 'The specified key does not exist.'
        });
        next(false);

    } catch (err) {
        req.log.error(err, 'S3_DEBUG: error routing S3 request');
        next(err);
    }
}

/*
 * This function adds the following routes (Non S3 routes):
 *  - listing buckets
 *  - creating a bucket
 *  - getting a bucket
 *  - deleting a bucket
 *  - listing objects in a bucket
 *  - creating an object inside a bucket
 *  - getting an object from a bucket
 *  - deleting an object from a bucket
 */
function addBucketsRoutes(server) {

    server.get({
        path: '/:account/buckets',
        name: 'ListBuckets'
    }, buckets.listBucketsHandler());

    server.opts({
        path: '/:account/buckets',
        name: 'OptionsBuckets'
    }, buckets.optionsBucketsHandler());

    server.put({
        path: '/:account/buckets/:bucket_name',
        name: 'CreateBucket',
        contentType: '*/*'
    }, buckets.createBucketHandler());

    server.head({
        path: '/:account/buckets/:bucket_name',
        name: 'HeadBucket'
    }, buckets.headBucketHandler());

    server.del({
        path: '/:account/buckets/:bucket_name',
        name: 'DeleteBucket'
    }, buckets.deleteBucketHandler());

    server.get({
        path: '/:account/buckets/:bucket_name/objects',
        name: 'ListBucketObjects'
    }, buckets.listBucketObjectsHandler());

    server.put({
        path: '/:account/buckets/:bucket_name/objects/:object_name',
        name: 'CreateBucketObject',
        contentType: '*/*'
    }, buckets.createBucketObjectHandler());

    // NOTE: GetBucketObject route moved to priority position before
    // generic regex routes
    // server.get({
    //     path: '/:account/buckets/:bucket_name/objects/:object_name',
    //     name: 'GetBucketObject'
    // }, buckets.getBucketObjectHandler());

    server.head({
        path: '/:account/buckets/:bucket_name/objects/:object_name',
        name: 'HeadBucketObject'
    }, buckets.headBucketObjectHandler());

    server.del({
        path: '/:account/buckets/:bucket_name/objects/:object_name',
        name: 'DeleteBucketObject'
    }, buckets.deleteBucketObjectHandler());

    server.put({
        path: '/:account/buckets/:bucket_name/objects/:object_name/metadata',
        name: 'UpdateBucketObjectMetadata',
        contentType: '*/*'
    }, buckets.updateBucketObjectMetadataHandler());

    server.post({
        path: '/:account/buckets',
        name: 'PostBuckets'
    }, methodNotAllowHandler);

    server.put({
        path: '/:account/buckets',
        name: 'PutBuckets'
    }, methodNotAllowHandler);

    server.head({
        path: '/:account/buckets',
        name: 'PutBuckets'
    }, methodNotAllowHandler);

    server.del({
        path: '/:account/buckets',
        name: 'DeleteBuckets'
    }, methodNotAllowHandler);

    server.post({
        path: '/:account/buckets/:bucket_name/objects',
        name: 'PostBucketObjects'
    }, methodNotAllowHandler);

    server.put({
        path: '/:account/buckets/:bucket_name/objects',
        name: 'PutBucketObjects'
    }, methodNotAllowHandler);

    server.head({
        path: '/:account/buckets/:bucket_name/objects',
        name: 'HeadBucketObjects'
    }, methodNotAllowHandler);

    server.del({
        path: '/:account/buckets/:bucket_name/objects',
        name: 'DeleteBucketObjects'
    }, methodNotAllowHandler);

    server.head({
        path: '/:account/buckets/:bucket_name/objects/:object_name/metadata',
        name: 'HeadBucketObjectMetadata'
    }, methodNotAllowHandler);

    server.post({
        path: '/:account/buckets/:bucket_name/objects/:object_name/metadata',
        name: 'PostBucketObjectMetadata'
    }, methodNotAllowHandler);

    server.del({
        path: '/:account/buckets/:bucket_name/objects/:object_name/metadata',
        name: 'DeleteBucketObjectMetadata'
    }, methodNotAllowHandler);

}

///--- Exports

module.exports = {

    createServer: createServer,

    startKangServer: other.startKangServer,

    getMetricsHandler: other.getMetricsHandler
};
