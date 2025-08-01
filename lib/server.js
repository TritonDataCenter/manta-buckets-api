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

    // Enhanced S3 request detection middleware BEFORE other routes
    server.pre(function s3RequestDetectorEarly(req, res, next) {
        req.log.debug('S3_DEBUG: S3 detection middleware executing for ' +
        req.method + ' ' + req.path());

        // Check if this is a SigV4 request and mark it for later processing
        var authHeader = req.headers.authorization ||
                        req.headers.Authorization ||
                        '';

        var authHeaderLower = authHeader.toLowerCase();
        var startsWithAws4 = authHeaderLower.indexOf('aws4-hmac-sha256') === 0;

        // Also check for virtual-hosted style requests
        var host = req.headers.host || '';
        var hostParts = host.split('.');
        // Virtual-hosted format: bucket.domain or bucket.domain:port
        // Examples: test5.localhost:8080, mybucket.s3.amazonaws.com
        // Simplified: if host has a dot and doesn't start with just "localhost"
        // XXX the above assumption is incorrect this needs work/thought,
        // will be disabled by default as path-style is just easier and
        // more straight forward to deploy.
        var isVirtualHostedFormat = hostParts.length >= 2 &&
                                   hostParts[0] !== 'localhost' &&
                                   host.indexOf('.') > 0;

        if (!process.env.S3_VIRTUAL_HOST_STYLE) {
            isVirtualHostedFormat = false;
        }

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
            isVirtualHostedFormat: isVirtualHostedFormat,
            isSigV4: isSigV4,
            isS3Format: isS3Format,
            authHeaderFirst50: authHeader.substring(0, 50),
            detectionReason: isSigV4 ? 'SigV4_AUTH' : 'NOT_S3'
        }, 'S3_DEBUG: Strict S3 detection - Only SigV4 = S3');

        if (isS3Format) {
            req.log.debug('S3_DEBUG: ✅ DETECTED S3 REQUEST');
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
            req.log.debug('S3_DEBUG: Not S3 request'+
            ' - using traditional Manta routing');
            req.isS3Request = false;
        }

        next();
    });

    // NOTE: S3 root handler will be added after authentication middleware

    // Set up other routes (ping, docs, crossdomain)
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

    server.get('/crossdomain.xml', function flashXML(req, res, next) {
        var CROSSDOMAIN_XML =
            '<?xml version="1.0" encoding="UTF-8"?>\n' +
            '<cross-domain-policy' +
            ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' +
            ' xsi:noNamespaceSchemaLocation='+
            '"http://www.adobe.com/xml/schemas/PolicyFile.xsd">\n' +
            '<cross-domain-policy>\n' +
            '    <allow-access-from domain="*" />\n' +
            '    <allow-http-request-headers-from domain="*" headers="*"/>\n' +
            '</cross-domain-policy>';
        var CROSSDOMAIN_LEN = Buffer.byteLength(CROSSDOMAIN_XML);

        res.set('Connection', 'keep-alive');
        res.set('Content-Length', CROSSDOMAIN_LEN);
        res.set('Content-Type', 'text/xml');
        res.set('Date', new Date());

        res.writeHead(200);
        res.write(CROSSDOMAIN_XML, 'utf8');
        res.end();

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
                    ' s3ResponseFormatter completed, calling handleS3Request');

                    // Route to S3 handler (supports both addressing styles)
                    handleS3Request(req, res, function (handlerErr) {
                        // Always terminate S3 requests
                        // to prevent double execution
                        if (handlerErr) {
                            // Convert error to S3 XML format and send directly
                            // Log user errors at info level,
                            // system errors at error level
                            var isUserError = (handlerErr.statusCode >= 400 &&
                            handlerErr.statusCode < 500) ||
                            (handlerErr.name &&
                            (handlerErr.name.includes('NotFound') ||
                            handlerErr.name.includes('Exists') ||
                            handlerErr.name.includes('BadRequest')));

                            if (isUserError) {
                                req.log.debug({
                                    errorName: handlerErr.name,
                                    errorCode: handlerErr.restCode ||
                                    handlerErr.code,
                                    statusCode: statusCode,
                                    bucket: req.s3Request ?
                                    req.s3Request.bucket : 'unknown',
                                    object: req.s3Request ?
                                    req.s3Request.object : 'unknown'
                                }, 'S3_DEBUG: User error in S3 handler'+
                                ', returning S3 XML error response');
                            } else {
                                req.log.error(handlerErr,
                                'S3_DEBUG: System error'+
                                ' in S3 handler, converting to S3 XML format');
                            }
                            var s3XmlError =
                            s3Compat.convertErrorToS3(handlerErr,
                            req.s3Request);

                            // Get proper status code (ObjectNotFoundError
                            // should be 404)
                            var statusCode = 500; // default
                            if (handlerErr.name === 'ObjectNotFoundError' ||
                            handlerErr.restCode === 'ObjectNotFoundError') {
                                statusCode = 404;
                            } else if (handlerErr.name ===
                            'BucketNotFoundError' ||
                            handlerErr.restCode === 'BucketNotFoundError') {
                                statusCode = 404;
                            } else if (handlerErr.name ===
                            'BucketExistsError' ||
                            handlerErr.restCode === 'BucketExistsError') {
                                statusCode = 409;
                            } else if (handlerErr.statusCode &&
                            typeof (handlerErr.statusCode) === 'number') {
                                statusCode = handlerErr.statusCode;
                            } else if (handlerErr.code &&
                            typeof (handlerErr.code) === 'number') {
                                statusCode = handlerErr.code;
                            }

                            res.writeHead(statusCode, {
                                'Content-Type': 'application/xml',
                                'Content-Length':
                                Buffer.byteLength(s3XmlError, 'utf8'),
                                'x-amz-request-id':
                                res.getHeader('x-amz-request-id') || 'unknown',
                                'x-amz-id-2':
                                res.getHeader('x-amz-id-2') || 'unknown'
                            });
                            res.write(s3XmlError, 'utf8');
                            res.end();
                            next(false); // Stop route processing
                        } else {
                            next(false); // Stop route processing
                        }
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

    // Add S3 routes BEFORE traditional Manta routes to ensure S3
    // requests are handled first
    // S3 catch-all routes that will route detected S3 requests to
    // handleS3Request
    // These need to be broad enough to catch S3 paths but only
    // process S3 requests

    function s3RouteHandler(req, res, next) {
        if (req.isS3Request) {
            req.log.debug('S3_DEBUG: S3 route handler processing S3 request');

            // Apply S3 middleware
            s3Compat.s3HeaderTranslator(req, res, function (headerErr) {
                if (headerErr) {
                    req.log.error(headerErr,
                    'S3_DEBUG: Error in s3HeaderTranslator');
                    next(headerErr);
                    return;
                }
                req.log.debug('S3_DEBUG: s3HeaderTranslator completed');

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
                    ' s3ResponseFormatter completed, calling handleS3Request');

                    // Route to S3 handler (supports both addressing styles)
                    handleS3Request(req, res, function (handlerErr) {
                        // Always terminate S3 requests to
                        // prevent double execution
                        if (handlerErr) {
                            // Convert error to S3 XML format and send directly
                            // Log user errors at info level,
                            // system errors at error level
                            var isUserError = (handlerErr.statusCode >= 400 &&
                            handlerErr.statusCode < 500) ||
                              (handlerErr.name &&
                              (handlerErr.name.includes('NotFound') ||
                              handlerErr.name.includes('Exists') ||
                              handlerErr.name.includes('BadRequest')));

                            if (isUserError) {
                                req.log.debug({
                                    errorName: handlerErr.name,
                                    errorCode: handlerErr.restCode ||
                                    handlerErr.code,
                                    statusCode: statusCode,
                                    bucket: req.s3Request ?
                                    req.s3Request.bucket : 'unknown',
                                    object: req.s3Request ?
                                    req.s3Request.object : 'unknown'
                                }, 'S3_DEBUG: User error '+
                                'in S3 handler'+
                                ', returning S3 XML error response');
                            } else {
                                req.log.error(handlerErr,
                                'S3_DEBUG: System error in S3 handler,'+
                                ' converting to S3 XML format');
                            }
                            var s3XmlError = s3Compat.convertErrorToS3(
                            handlerErr, req.s3Request);

                            // Get proper status code (ObjectNotFoundError
                            // should be 404)
                            var statusCode = 500; // default
                            if (handlerErr.name === 'ObjectNotFoundError' ||
                            handlerErr.restCode === 'ObjectNotFoundError') {
                                statusCode = 404;
                            } else if (handlerErr.name ===
                            'BucketNotFoundError' ||
                            handlerErr.restCode === 'BucketNotFoundError') {
                                statusCode = 404;
                            } else if
                            (handlerErr.name === 'BucketExistsError' ||
                            handlerErr.restCode === 'BucketExistsError') {
                                statusCode = 409;
                            } else if (handlerErr.statusCode &&
                            typeof (handlerErr.statusCode) === 'number') {
                                statusCode = handlerErr.statusCode;
                            } else if (handlerErr.code &&
                            typeof (handlerErr.code) === 'number') {
                                statusCode = handlerErr.code;
                            }

                            res.writeHead(statusCode, {
                                'Content-Type': 'application/xml',
                                'Content-Length':
                                Buffer.byteLength(s3XmlError, 'utf8'),
                                'x-amz-request-id':
                                res.getHeader('x-amz-request-id') || 'unknown',
                                'x-amz-id-2': res.getHeader('x-amz-id-2') ||
                                'unknown'
                            });
                            res.write(s3XmlError, 'utf8');
                            res.end();
                            next(false); // Stop route processing
                        } else {
                            next(false); // Stop route processing
                        }
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

    // Add specific S3 route handlers that won't interfere with traditional
    // Manta routes
    // These catch S3-style paths but let traditional Manta paths pass through

    // Buckets API (traditional Manta routes) - REGISTER FIRST for priority
    addBucketsRoutes(server);

    // S3 root path (list buckets)
    server.get('/', s3RouteHandler);

    // S3 bucket operations (single path segment) - ONLY for S3 requests
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

    // Browser-friendly redirect: /user/buckets/bucketname/filename ->
    // /user/buckets/bucketname/objects/filename
    // This MUST come before the general two-segment route
    server.get(/^\/([^\/]+)\/buckets\/([^\/]+)\/(.+)$/,
              function (req, res, next) {
        var userName = req.params[0];
        var bucketName = req.params[1];
        var objectPath = req.params[2];
        var userAgent = req.headers['user-agent'] || '';
        var acceptHeader = req.headers['accept'] || '';

        // Check if this path already contains 'objects' segment
        var pathSegments = req.path().split('/').filter(
            function (s) { return s.length > 0; });
        var hasObjectsSegment = pathSegments.indexOf('objects') !== -1;

        // Only redirect if:
        // 1. This is a browser request (HTML accept header)
        // 2. Path doesn't already contain 'objects' segment
        // 3. Not an S3 API request
        var isBrowserRequest = acceptHeader.includes('text/html') &&
                               (userAgent.includes('Mozilla') ||
                                userAgent.includes('Chrome') ||
                                userAgent.includes('Safari') ||
                                userAgent.includes('Firefox') ||
                                userAgent.includes('Edge'));

        if (isBrowserRequest && !hasObjectsSegment && !req.isS3Request) {
            var redirectPath = '/' + userName + '/buckets/' + bucketName +
                '/objects/' + objectPath;

            req.log.info({
                originalPath: req.path(),
                redirectPath: redirectPath,
                userAgent: userAgent,
                accept: acceptHeader,
                user: userName,
                bucket: bucketName,
                object: objectPath
            }, 'Browser redirect: adding missing objects segment to URL');

            res.redirect(302, redirectPath, next);
        } else {
            next();
        }
    });

    // S3 object operations (two or more path segments) - ONLY for S3 requests
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
            req.log.debug('S3_DEBUG: Passing through to next '+
            'handler in GET two-segment route');
            next();
        }
    });

    server.put(/^\/([^\/]+)\/(.+)$/, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.head(/^\/([^\/]+)\/(.+)$/, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.del(/^\/([^\/]+)\/(.+)$/, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.post(/^\/([^\/]+)\/(.+)$/, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

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
 * and method
 * This function is called only for SigV4 authenticated requests
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
        // S3 List Buckets: GET / (but only for non-virtual-hosted requests)
        if (method === 'get' && pathParts.length === 0) {
            // Check if this is a virtual-hosted request
            var host = req.headers.host || '';
            var hostParts = host.split('.');
            var isVirtualHosted = hostParts.length >= 2 &&
                                 hostParts[0] !== 'localhost' &&
                                 host.indexOf('.') > 0;

            //XXX Disabled by default
            if (!process.env.S3_VIRTUAL_HOST_STYLE) {
                isVirtualHosted = false;
            }

            if (isVirtualHosted) {
                // Virtual-hosted GET / = list objects in bucket
                var bucketName = hostParts[0];
                req.params = req.params || {};
                req.params.bucket = bucketName;
                req.params[0] = bucketName;

                req.log.debug({
                    operation: 'bucket-get-virtual-hosted',
                    bucket: bucketName,
                    host: host
                }, 'S3_DEBUG: Routing virtual-hosted GET' +
                             ' / to bucket objects handler');

                // Route to bucket objects handler
                if (req.s3Request && req.s3Request.operation ===
                    'ListBucketObjectsV2') {
                    req.log.debug('S3_DEBUG_ROUTING:  ROUTING TO ' +
                               's3ListBucketObjectsV2Handler (virtual-hosted)');
                    return (s3Routes.s3ListBucketObjectsV2Handler()
                            (req, res, next));
                } else {
                    req.log.debug('S3_DEBUG_ROUTING:  ROUTING TO ' +
                              's3ListBucketObjectsHandler (V1 virtual-hosted)');
                    return (s3Routes.s3ListBucketObjectsHandler()
                            (req, res, next));
                }
            } else {
                // Non-virtual-hosted GET / = list all buckets
                req.log.debug('S3_DEBUG: Routing to s3ListBucketsHandler');
                return (s3Routes.s3ListBucketsHandler()(req, res, next));
            }
        }

        // S3 Bucket Operations: /:bucket
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

        // S3 Object Operations: /:bucket/path/to/object
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
 * This function adds the following routes:
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

    server.get({
        path: '/:account/buckets/:bucket_name/objects/:object_name',
        name: 'GetBucketObject'
    }, buckets.getBucketObjectHandler());

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
