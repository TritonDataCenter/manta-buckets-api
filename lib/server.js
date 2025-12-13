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
var bucketHelpers = require('./buckets/buckets');
var common = require('./common');
var other = require('./other');
var throttle = require('./throttle');
var s3Routes = require('./s3-routes');
var s3Compat = require('./s3-compat');
var anonymousAuth = require('./anonymous-auth');
var corsMiddleware = require('./cors-middleware');
var stsHandlers = require('./sts-handlers');
var iamHandlers = require('./iam-handlers');
var iamPolicyEngine = require('./iam-policy-engine');
var constants = require('./constants');
var formatters = require('./server/formatters');

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

    options.formatters = formatters.createFormatters();
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
        var isSigV4 = authHeader.toLowerCase().indexOf(
            constants.AWS_AUTH.SCHEME_SIGV4) === 0;

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

        // Check if this is a CORS configuration request
        var isCorsRequest = req.method === 'PUT' && req.url &&
                           req.url.includes('?cors');

        // Preserve raw body for POST requests that might be S3 bulk operations
        // Include: XML content-type requests, Complete Multipart Upload
        // requests,
        // bulk delete requests, OR STS requests
        // Also preserve for PUT CORS configuration requests
        var contentType = req.headers['content-type'] || '';
        var isBulkDeleteRequest = req.url && req.url.includes('delete');
        var isXmlRequest = contentType === 'application/xml' ||
                          contentType.startsWith('application/x-amz-json') ||
                          contentType.startsWith('text/xml');

        // Check if this is an STS request (POST to / with Action parameter)
        var isStsRequest = req.method === 'POST' &&
                          req.url === '/' &&
                          req.headers.authorization &&
                          req.headers.authorization.toLowerCase().
            indexOf(constants.AWS_AUTH.SCHEME_SIGV4) !== -1;

        if (((req.method === 'POST' &&
              req.headers.authorization &&
              (isXmlRequest || isCompleteMultipartUpload ||
               isBulkDeleteRequest || isStsRequest)) ||
             (req.method === 'PUT' && isCorsRequest)) &&
            req.headers['content-length'] &&
            parseInt(req.headers['content-length'], 10) > 0) {

            req.log.debug({
                method: req.method,
                contentLength: req.headers['content-length'],
                contentType: req.headers['content-type'],
                url: req.url,
                isCompleteMultipartUpload: isCompleteMultipartUpload,
                isBulkDeleteRequest: isBulkDeleteRequest,
                isXmlRequest: isXmlRequest,
                isCorsRequest: isCorsRequest,
                isStsRequest: isStsRequest
            }, 'S3_DEBUG: PRE-MIDDLEWARE - Preserving raw body for' +
            ' S3 signature verification, bulk delete,' +
            ' multipart upload, CORS configuration, or STS operations');

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
        var startsWithAws4 = authHeaderLower.indexOf(
            constants.AWS_AUTH.SCHEME_SIGV4) === 0;
        var host = req.headers.host || '';

        // Simple and clear S3 detection: ONLY SigV4 requests are S3 requests
        // Traditional Manta requests use HTTP Signature auth, not SigV4
        // Regardless of host format (virtual-hosted or path-style),
        // only SigV4 = S3
        // Also detect presigned URLs which have SigV4 signatures in
        // query parameters
        var isSigV4 = startsWithAws4;
        var isPresignedV4 = req.query && (req.query['X-Amz-Algorithm'] ||
                                          req.query['x-amz-algorithm']);
        var isS3Format = isSigV4 || isPresignedV4;

        req.log.debug({
            method: req.method,
            path: req.path(),
            host: host,
            isSigV4: isSigV4,
            isPresignedV4: isPresignedV4,
            isS3Format: isS3Format,
            authHeaderFirst50: authHeader.substring(0, 50),
            detectionReason: isSigV4 ? 'SigV4_AUTH' :
                (isPresignedV4 ? 'PRESIGNED_V4' : 'NOT_S3')
        }, 'S3_DEBUG: S3 detection - SigV4 auth or presigned URLs');

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

    server.get({
        name: 'DocsRedirect',
        path: /^\/docs\/?/
    }, function redirect(req, res, next) {
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
    // Handle CORS preflight OPTIONS requests BEFORE authentication
    // JSSTYLED
    server.opts(/.*/, function (req, res, next) {
        if (req.headers['access-control-request-method']) {
            var origin = req.headers.origin || '*';

            req.log.debug({
                origin: origin,
                requestMethod: req.headers['access-control-request-method'],
                url: req.url
            }, 'CORS: Handling preflight OPTIONS request');

            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Access-Control-Allow-Methods',
                          'GET,POST,PUT,DELETE,HEAD,OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type,' +
                          'authorization,x-amz-content-sha256,x-amz-date,' +
                          'x-amz-security-token,x-amz-user-agent');
            res.setHeader('Access-Control-Max-Age', '3600');
            res.setHeader('Access-Control-Allow-Credentials', 'true');

            res.send(200);
            next(false); // Stop processing - complete the preflight
        } else {
            next(); // Not a preflight, continue
        }
    });


    // Create STS client for AWS STS operations
    var stsClient = stsHandlers.createSTSClient(options, log);

    // Create IAM client for AWS IAM operations
    var iamClient = iamHandlers.createIAMClient(options, log);

    // Add AWS STS endpoints BEFORE authentication (POST /?Action=AssumeRole
    // and /?Action=GetSessionToken)
    // STS requests need to bypass regular S3 authentication since
    // they use service='sts'
    server.post('/', function stsRequestHandler(req, res, next) {
        req.log.debug({
            method: req.method,
            url: req.url,
            isS3Request: !!req.isS3Request,
            hasQuery: !!req.query,
            hasBody: !!req.body,
            query: req.query,
            body: req.body,
            queryAction: req.query ? req.query.Action : 'none',
            bodyAction: req.body ? req.body.Action : 'none'
        }, 'STS_DEBUG: stsRequestHandler called');

        if (req.isS3Request) {
            req.log.debug({
                method: req.method,
                url: req.url,
                hasQuery: !!req.query,
                hasBody: !!req.body,
                query: req.query,
                body: req.body,
                queryAction: req.query ? req.query.Action : 'none',
                bodyAction: req.body ? req.body.Action : 'none'
            }, 'S3_DEBUG: Checking if request is STS request');
        }

        var action = req.query.Action || req.body.Action;

        // If body is a string (URL-encoded), parse it manually for
        // Action parameter
        if (!action && typeof (req.body) === 'string' &&
            req.body.includes('Action=')) {
            //JSSTYLED
            var actionMatch = req.body.match(/Action=([^&]+)/);
            if (actionMatch) {
                action = decodeURIComponent(actionMatch[1]);
                req.log.debug({
                    bodyString: req.body,
                    extractedAction: action
                }, 'S3_DEBUG: Extracted Action from URL-encoded body string');
            }
        }

        if (action === 'AssumeRole' || action === 'GetSessionToken' ||
            action === 'GetCallerIdentity') {
            req.log.debug({
                action: action,
                method: req.method,
                url: req.url,
                hasAuth: !!req.headers.authorization,
                contentType: req.headers['content-type']
            }, 'STS request detected ' +
                          '- bypassing authentication and routing directly');
        } else if (action === 'CreateRole' ||
                   action === 'GetRole' ||
                   action === 'DeleteRole' ||
                   action === 'ListRoles' ||
                   action === 'PutRolePolicy' ||
                   action === 'DeleteRolePolicy' ||
                   action === 'ListRolePolicies' ||
                   action === 'GetRolePolicy') {
            req.log.debug({
                action: action,
                method: req.method,
                url: req.url,
                hasAuth: !!req.headers.authorization,
                contentType: req.headers['content-type']
            }, 'IAM request detected - ' +
               'handling like STS with optimized auth lookup');

            // Handle IAM requests like STS - extract caller and
            // route immediately
            var authHeader = req.headers.authorization;
            if (!authHeader) {
                req.log.warn('IAM request missing Authorization header');
                res.send(400, {error:
                   'Authorization header required for IAM operations'});
                return (next(false));
            }

            // Extract access key from Authorization header
            // JSSTYLED
            var accessKeyMatch = authHeader.match(/Credential=([^\/]+)/);
            if (!accessKeyMatch) {
                req.log.warn('IAM request Authorization header malformed');
                res.send(400, {error: 'Invalid Authorization header format'});
                return (next(false));
            }

            var accessKeyId = accessKeyMatch[1];

            req.log.debug({
                accessKeyId: accessKeyId,
                action: action
            }, 'IAM: Extracted access key,' +
                          ' getting caller info with fast lookup');

            // Get real user data from Mahi using access key with timeout
            var mabiClient = clients.mahi;
            var timeoutHandle = setTimeout(function () {
                req.log.error({
                    accessKeyId: accessKeyId,
                    action: action
                }, 'IAM: getUserByAccessKey timeout after 5 seconds');
                res.send(503, {error: 'Authentication service timeout'});
                return (next(false));
            }, 5000);

            var authStartTime = Date.now();
            mabiClient.getUserByAccessKey(accessKeyId,
                                          function (authErr, authRes) {
                clearTimeout(timeoutHandle);
                var authEndTime = Date.now();

                if (authErr) {
                    req.log.error({
                        err: authErr,
                        accessKeyId: accessKeyId,
                        action: action,
                        authLookupMs: authEndTime - authStartTime,
                        totalDurationMs: authEndTime - (req._startTime ||
                                                        authStartTime)
                    }, 'IAM: Failed to get user by access key');
                    res.send(401, {error: 'Invalid credentials'});
                    return (next(false));
                }

                req.caller = authRes;

                /*
                 * Mahi returns assumedRole as a string ARN, but
                 * iam-policy-engine.js expects an object with an 'arn'
                 * property and a 'policies' array. Extract policies from
                 * authRes.roles if available.
                 */
                if (authRes.assumedRole &&
                    typeof (authRes.assumedRole) === 'string') {
                    try {
                        var roleArnStringIam = authRes.assumedRole;
                        var policies = [];
                        // Extract policies from roles object
                        if (authRes.roles &&
                            typeof (authRes.roles) === 'object') {
                            var roleUuids = Object.keys(authRes.roles);
                            if (roleUuids.length > 0) {
                                var roleData = authRes.roles[roleUuids[0]];
                                if (roleData &&
                                    Array.isArray(roleData.policies)) {
                                    policies = roleData.policies;
                                }
                            }
                        }

                        authRes.assumedRole = {
                            arn: roleArnStringIam,
                            policies: policies
                        };
                    } catch (conversionErr) {
                        req.log.error({
                            err: conversionErr,
                            assumedRole: authRes.assumedRole
                        }, 'Failed to convert assumedRole format for IAM');
                        // Continue with original format
                    }
                }

                req.log.debug({
                    callerUuid: authRes.account.uuid,
                    callerLogin: authRes.account.login,
                    action: action,
                    authLookupMs: authEndTime - authStartTime,
                    totalDurationMs: authEndTime - (req._startTime ||
                                                    authStartTime)
                }, 'IAM: Got caller info, measuring handler execution time');

                // Check IAM access based on credential type and policy
                var accessCheck = iamPolicyEngine.checkIamAccess(
                    accessKeyId, authRes, action, req.log);

                if (!accessCheck.allowed) {
                    var accessError = s3Compat.convertErrorToS3({
                        name: accessCheck.error,
                        message: accessCheck.message,
                        statusCode: 403
                    }, null, req);
                    res.setHeader('Content-Type',
                        constants.CONTENT_TYPES.XML);
                    res.writeHead(403);
                    res.end(accessError);
                    return (next(false));
                }

                var handlerStartTime = Date.now();

                // Route to appropriate IAM handler
                req.log.debug({
                    action: action,
                    handlerStartTime: handlerStartTime
                }, 'IAM: About to call IAM handler');

                if (action === 'CreateRole') {
                    return iamHandlers.
                        createRoleHandler(iamClient)(req, res, next);
                } else if (action === 'GetRole') {
                    return iamHandlers.
                        getRoleHandler(iamClient)(req, res, next);
                } else if (action === 'PutRolePolicy') {
                    return iamHandlers.
                        putRolePolicyHandler(iamClient)(req, res, next);
                } else if (action === 'DeleteRolePolicy') {
                    return iamHandlers.
                        deleteRolePolicyHandler(iamClient)(req, res, next);
                } else if (action === 'DeleteRole') {
                    return iamHandlers.
                        deleteRoleHandler(iamClient)(req, res, next);
                } else if (action === 'ListRoles') {
                    return iamHandlers.
                        listRolesHandler(iamClient)(req, res, next);
                } else if (action === 'ListRolePolicies') {
                    return iamHandlers.
                        listRolePoliciesHandler(iamClient)(req, res, next);
                } else if (action === 'GetRolePolicy') {
                    return iamHandlers.
                        getRolePolicyHandler(iamClient)(req, res, next);
                } else {
                    res.send(501, {error: action + ' not implemented yet'});
                    return (next(false));
                }
            });
            return; // Important: don't continue to regular auth flow
        }

        if (action === 'AssumeRole' || action === 'GetSessionToken' ||
            action === 'GetCallerIdentity') {

            // For STS requests, bypass authentication and route directly
            // but first get a real caller UUID from the authorization header
            var stsAuthHeader = req.headers.authorization;
            if (stsAuthHeader) {
                // Extract access key from authorization header for UUID lookup
                var stsAccessKeyMatch =
                    //JSSTYLED
                    stsAuthHeader.match(/Credential=([^\/]+)/);
                if (stsAccessKeyMatch) {
                    var stsAccessKeyId = stsAccessKeyMatch[1];
                    req.log.debug({accessKeyId: stsAccessKeyId},
                                  'STS: Extracted access key from auth header');

                    // Make a quick call to Mahi to get the user UUID for
                    // this access key
                    var stsMahiClient = clients.mahi;
                    if (stsMahiClient) {
                        stsMahiClient.getUserByAccessKey(stsAccessKeyId,
                                                         function (authErr,
                                                                   authRes) {
                            if (authErr || !authRes.account) {
                                req.log.warn({
                                    err: authErr,
                                    accessKeyId: stsAccessKeyId
                                }, 'STS: Failed to get caller from access key' +
                                   ' - failing securely');
                                var keyAuthError = s3Compat.convertErrorToS3({
                                    name: 'InvalidUserID.NotFound',
                                    message:
                                    'Invalid access key for STS operation',
                                    statusCode: 401
                                }, null, req);
                                res.setHeader('Content-Type',
                                              'application/xml');
                                res.writeHead(401);
                                res.end(keyAuthError);
                                return (next(false));
                            } else {
                                req.caller = authRes;
                                /*
                                 * Mahi returns assumedRole as a string ARN, but
                                 * sts-client.js expects an object with an 'arn'
                                 * property.
                                 */
                                if (req.caller.assumedRole &&
                                    typeof (req.caller.assumedRole) ===
                                    'string') {
                                    var roleArnString = req.caller.assumedRole;
                                    req.caller.assumedRole = {
                                        arn: roleArnString
                                    };
                                }

                                req.log.debug({authRes: authRes,
                                              keyused: stsAccessKeyId },
                                             'STS AUTH');
                                /*
                                 * Set req.auth from Mahi response. Mahi
                                 * returns credential type info directly,
                                 * no need to check access key prefix.
                                 */
                                req.auth = {
                                    accessKeyId: stsAccessKeyId,
                                    assumedRole: authRes.assumedRole || null,
                                    isTemporaryCredential:
                                        authRes.isTemporaryCredential ||
                                        authRes.isTemporary || false,
                                    sessionName: authRes.sessionName || null,
                                    principalUuid: authRes.principalUuid ||
                                        (authRes.account &&
                                         authRes.account.uuid)
                                };
                                req.log.debug({
                                    callerUuid: req.caller.account.uuid,
                                    callerLogin: req.caller.account.login,
                                    isTemporaryCredential:
                                        req.auth.isTemporaryCredential,
                                    hasAssumedRole: !!req.auth.assumedRole,
                                    assumedRole: req.auth.assumedRole
                                }, 'STS: Got caller from access key lookup');
                            }

                            // Route to STS handler
                            if (action === 'AssumeRole') {
                                return stsHandlers.
                                    assumeRoleHandler(stsClient)
                                (req, res, next);
                            } else if (action === 'GetSessionToken') {
                                return stsHandlers.
                                    getSessionTokenHandler(stsClient)
                                (req, res, next);
                            } else if (action === 'GetCallerIdentity') {
                                return stsHandlers.
                                    getCallerIdentityHandler(stsClient)
                                (req, res, next);
                            }
                        });
                        return;
                    }
                }
            }
            req.log.warn('STS request missing auth header or Mahi' +
                        ' unavailable - failing securely');
            var stsAuthError = s3Compat.convertErrorToS3({
                name: 'InvalidUserID.NotFound',
                message: 'Authentication required for STS operations',
                statusCode: 401
            }, null, req);
            res.setHeader('Content-Type', 'application/xml');
            res.writeHead(401);
            res.end(stsAuthError);
            return (next(false));
        }

        // Continue to regular authentication for non-STS requests
        // (including IAM)
        if (req.isS3Request) {
            if (req.isIAMRequest) {
                req.log.debug('S3_DEBUG: IAM request,' +
                              ' continuing to regular authentication');
            } else {
                req.log.debug('S3_DEBUG: Not an STS or IAM request,' +
                              ' continuing to regular authentication');
            }
        }
        next();
    });


    // Anonymous access handler for public buckets (before authentication)
    server.use(function (req, res, next) {
        // Set up metadataPlacement early for anonymous access handler
        req.metadataPlacement = clients.metadataPlacement;
        anonymousAuth.anonymousAccessHandler(req, res, next);
    });

    server.use(auth.authenticationHandler({
        log: log,
        mahi: clients.mahi,
        keyapi: clients.keyapi,
        iamClient: iamClient
    }));


    server.use(auth.gatherContext);

    // IAM requests are now handled immediately like STS requests above

    // Add various fields to the 'req' object before ANY
    // S3 handlers get called.
    // This MUST come before both root handler
    // and S3 routing so req.metadataPlacement is available
    server.use(common.setupHandler(options, clients));

    // CORS processing is handled in addCustomHeaders function in common.js
    // for both object-level metadata and bucket-level CORS configuration

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
      * OPTIONS handlers for S3 CORS preflight - must be BEFORE other routes
      */
    server.opts(/^\/([^\/]+)$/, function (req, res, next) {
        if (req.isS3Request) {
            req.log.debug('S3_DEBUG: S3 single-segment' +
                          ' OPTIONS route handling S3 CORS preflight');
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.opts(/^\/([^\/]+)\/(.+)$/, function (req, res, next) {
        if (req.isS3Request) {
            req.log.debug('S3_DEBUG: S3 two-segment OPTIONS route' +
                          ' handling S3 CORS preflight');
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

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
    server.get({
        name: 'S3GetBucket',
        path: /^\/([^\/]+)$/
    }, function (req, res, next) {
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

    server.put({
        name: 'S3PutBucket',
        path: /^\/([^\/]+)$/
    }, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.head({
        name: 'S3HeadBucket',
        path: /^\/([^\/]+)$/
    }, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.del({
        name: 'S3DeleteBucket',
        path: /^\/([^\/]+)$/
    }, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.post({
        name: 'S3PostBucket',
        path: /^\/([^\/]+)$/
    }, function (req, res, next) {
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

    server.get({
        name: 'S3GetObject',
        path: /^\/([^\/]+)\/(.+)$/
    }, function (req, res, next) {
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

    server.put({
        name: 'S3PutObject',
        path: /^\/([^\/]+)\/(.+)$/
    }, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.head({
        name: 'S3HeadObject',
        path: /^\/([^\/]+)\/(.+)$/
    }, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.del({
        name: 'S3DeleteObject',
        path: /^\/([^\/]+)\/(.+)$/
    }, function (req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.post({
        name: 'S3PostObject',
        path: /^\/([^\/]+)\/(.+)$/
    }, function (req, res, next) {
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
 * S3 List Multipart Uploads Handler
 * Returns an empty list of multipart uploads to satisfy AWS SDK validation
 */
function s3ListMultipartUploadsHandler(req, res, next) {
    req.log.debug({
        bucket: req.params.bucket
    }, 'S3_DEBUG: s3ListMultipartUploads - returning empty response');

    // Return empty multipart uploads list as XML
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
              '<ListMultipartUploadsResult' +
              ' xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n' +
              '  <Bucket>' + req.params.bucket + '</Bucket>\n' +
              '  <KeyMarker></KeyMarker>\n' +
              '  <UploadIdMarker></UploadIdMarker>\n' +
              '  <NextKeyMarker></NextKeyMarker>\n' +
              '  <NextUploadIdMarker></NextUploadIdMarker>\n' +
              '  <MaxUploads>1000</MaxUploads>\n' +
              '  <IsTruncated>false</IsTruncated>\n' +
              '</ListMultipartUploadsResult>';

    res.setHeader('Content-Type', 'application/xml');

    // Add CORS headers from bucket CORS configuration
    function applyCorsAndSend() {
        common.tryBucketLevelCors(req, res, req.headers.origin, function () {
            req.log.debug({
                responseHeaders: res._headers || res.getHeaders()
            }, 'S3_DEBUG: tryBucketLevelCors completed' +
               ' for ListMultipartUploads');
            res.send(200, xml);
            next(false);
        });
    }

    // Ensure bucket object is loaded for CORS processing
    if (!req.bucket && req.params && req.params.bucket) {
        req.log.debug('S3_DEBUG: Loading bucket for CORS processing');
        var corsReq = Object.create(req);
        corsReq.params = { bucket_name: req.params.bucket };
        // Create Bucket object first (required by getBucketIfExists)
        corsReq.bucket = new bucketHelpers.Bucket(corsReq);
        bucketHelpers.getBucketIfExists(corsReq, null, function (bucketErr) {
            if (bucketErr) {
                req.log.warn(bucketErr,
                             'S3_DEBUG: Failed to load bucket for CORS');
            } else {
                req.bucket = corsReq.bucket;
                req.log.debug({
                    bucketName: req.bucket.name,
                    bucketId: req.bucket.id
                }, 'S3_DEBUG: Successfully loaded bucket for CORS');
            }
            applyCorsAndSend();
        });
    } else {
        applyCorsAndSend();
    }
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
                    // Check for CORS configuration operation
                    if (req.s3Request && req.s3Request.operation ===
                        'PutBucketCors') {
                        req.log.debug('S3_DEBUG_ROUTING:' +
                                      ' ROUTING TO s3PutBucketCorsHandler');
                        return (s3Routes.s3PutBucketCorsHandler()
                                (req, res, next));
                    } else {
                        return (s3Routes.s3CreateBucketHandler()
                                (req, res, next));
                    }
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

                    // Check for CORS configuration operation
                    if (req.s3Request && req.s3Request.operation ===
                        'GetBucketCors') {
                        req.log.debug('S3_DEBUG_ROUTING:' +
                                      ' ROUTING TO s3GetBucketCorsHandler');
                        return (s3Routes.s3GetBucketCorsHandler()
                                (req, res, next));
                    } else if (req.s3Request && req.s3Request.operation ===
                        'ListMultipartUploads') {
                        req.log.debug('S3_DEBUG_ROUTING:' +
                            ' ROUTING TO s3ListMultipartUploadsHandler');
                        return (s3ListMultipartUploadsHandler(req, res, next));
                    } else if (req.s3Request && req.s3Request.operation ===
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
                    // Check for CORS configuration operation
                    if (req.s3Request && req.s3Request.operation ===
                        'DeleteBucketCors') {
                        req.log.debug('S3_DEBUG_ROUTING:' +
                                      ' ROUTING TO s3DeleteBucketCorsHandler');
                        return (s3Routes.s3DeleteBucketCorsHandler()
                                (req, res, next));
                    } else {
                        return (s3Routes.s3DeleteBucketHandler()
                                (req, res, next));
                    }
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

    // OPTIONS support for CORS preflight requests
    server.opts({
        path: '/:account/buckets/:bucket_name/objects/:object_name',
        name: 'OptionsObject'
    }, buckets.optionsBucketObjectHandler());

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
