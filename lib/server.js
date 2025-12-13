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
var stsIamRouting = require('./server/sts-iam-routing');
var s3Routing = require('./server/s3-routing');
var middleware = require('./server/middleware');
var requestPipeline = require('./server/request-pipeline');
var metrics = require('./server/metrics');
var routes = require('./server/routes');

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
    metrics.initializeMetrics(options.collector);

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

    server.use(middleware.traceTTFB);

    server.use(common.earlySetupHandler(options));
    server.use(restify.plugins.dateParser(options.maxRequestAge || 300));


    server.use(restify.plugins.queryParser());

    server.use(common.authorizationParser);
    server.use(auth.convertS3PresignedToManta);
    server.use(auth.checkIfPresigned);

    server.use(middleware.createDependencyChecker(clients));

    if (options.throttle.enabled) {
        options.throttle.log = options.log;
        var throttleHandle = throttle.createThrottle(options.throttle);
        server.use(throttle.throttleHandler(throttleHandle));
    }
    // Handle CORS preflight OPTIONS requests BEFORE authentication
    // JSSTYLED
    server.opts(/.*/, middleware.corsPreflightHandler);


    // Create STS client for AWS STS operations
    var stsClient = stsHandlers.createSTSClient(options, log);

    // Create IAM client for AWS IAM operations
    var iamClient = iamHandlers.createIAMClient(options, log);

    // Create S3 request handler for routing S3 operations
    var handleS3Request = s3Routing.createS3RequestHandler(s3Routes);

    // Add AWS STS endpoints BEFORE authentication (POST /?Action=AssumeRole
    // and /?Action=GetSessionToken)
    // STS requests need to bypass regular S3 authentication since
    // they use service='sts'
    server.post('/', stsIamRouting.createStsIamHandler(
        clients, iamClient, stsClient, stsHandlers, iamHandlers));

    // Anonymous access handler for public buckets (before authentication)
    server.use(middleware.createAnonymousAccessHandler(
        clients, anonymousAuth));

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
    server.get('/', requestPipeline.createConsolidatedRootHandler(
        handleS3Request));

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
    var s3RouteHandler = requestPipeline.createS3RouteHandler(
        handleS3Request);

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
    routes.addBucketsRoutes(server);

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

    // Set up audit logging and request completion handling
    metrics.setupAuditLogging(options, log, server);

    return (server);
}

///--- Exports

module.exports = {

    createServer: createServer,

    startKangServer: other.startKangServer,

    getMetricsHandler: other.getMetricsHandler
};
