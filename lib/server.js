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
var restify = require('restify');

var auth = require('./auth');
var buckets = require('./buckets');
var common = require('./common');
var other = require('./other');
var throttle = require('./throttle');
var s3Routes = require('./s3-routes');
var anonymousAuth = require('./anonymous-auth');
var stsHandlers = require('./sts-handlers');
var iamHandlers = require('./iam-handlers');
var formatters = require('./server/formatters');
var stsIamRouting = require('./server/sts-iam-routing');
var s3Routing = require('./server/s3-routing');
var middleware = require('./server/middleware');
var requestPipeline = require('./server/request-pipeline');
var metrics = require('./server/metrics');
var routes = require('./server/routes');

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

    server.pre(middleware.watchClose);
    server.pre(middleware.createStashPath(options));
    server.pre(middleware.logAllRequests);
    server.pre(middleware.detectS3Uploads);
    server.pre(middleware.configureBinaryMode);
    /*
     * MANTA-331: while a trailing '/' is ok in HTTP, this messes with
     * the consistent hashing, so ensure there isn't one by using
     * sanitizePath()
     */
    server.pre(restify.pre.sanitizePath());
    server.pre(middleware.createCleanupContentType(VALID_CONTENT_TYPE_RE));
    server.pre(middleware.preserveRawBodyPreMiddleware);
    server.pre(middleware.s3RequestDetectorEarly);

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
    server.opts(/^\/([^\/]+)$/,
        function handleS3SingleSegmentOptions(req, res, next) {
        if (req.isS3Request) {
            req.log.debug('S3_DEBUG: S3 single-segment' +
                          ' OPTIONS route handling S3 CORS preflight');
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.opts(/^\/([^\/]+)\/(.+)$/,
        function handleS3TwoSegmentOptions(req, res, next) {
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
    }, function s3GetBucket(req, res, next) {
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
    }, function s3PutBucket(req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.head({
        name: 'S3HeadBucket',
        path: /^\/([^\/]+)$/
    }, function s3HeadBucket(req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.del({
        name: 'S3DeleteBucket',
        path: /^\/([^\/]+)$/
    }, function s3DeleteBucket(req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.post({
        name: 'S3PostBucket',
        path: /^\/([^\/]+)$/
    }, function s3PostBucket(req, res, next) {
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

    /*
     * Anonymous Access Handler - Helper Functions
     * ========================================================================
     * Extracted helpers for S3GetObject route to reduce complexity from
     * 151 lines/8 nesting levels to ~40 lines/3 nesting levels.
     */

    /*
     * Parse Manta bucket object path into parts
     * Removes empty segments from path
     */
    function parseMantaBucketObjectPath(requestPath) {
        var pathParts = requestPath.split('/').filter(function (part) {
            return (part.length > 0);
        });
        return (pathParts);
    }

    /**
     * Check if request is for Manta anonymous object access
     * Path format: /account/buckets/bucket_name/objects/object_name
     */
    function isMantaAnonymousObjectAccess(pathParts, req) {
        return (pathParts.length >= 5 &&
                pathParts[1] === 'buckets' &&
                pathParts[3] === 'objects' &&
                req.potentialAnonymousAccess);
    }

    /**
     * Setup Manta route parameters from path parts
     * Extracts account, bucket_name, and object_name
     */
    function setupMantaObjectParams(req, pathParts) {
        req.params = req.params || {};
        req.params.account = pathParts[0];
        req.params.bucket_name = pathParts[2];
        req.params.object_name = pathParts.slice(4).join('/');

        req.log.debug({
            account: req.params.account,
            bucket_name: req.params.bucket_name,
            object_name: req.params.object_name
        }, 'S3_DEBUG: Set up Manta route parameters for' +
           ' bucket object request');
    }

    /**
     * Flatten nested handler arrays into single array
     * Some handlers return arrays of handlers
     */
    function flattenHandlers(rawHandlers) {
        var handlers = [];
        rawHandlers.forEach(function (handler) {
            if (Array.isArray(handler)) {
                handlers = handlers.concat(handler);
            } else {
                handlers.push(handler);
            }
        });
        return (handlers);
    }

    /**
     * Execute handler chain with error handling
     * Custom middleware runner for bucket object handlers
     */
    function executeHandlerChain(handlers, req, res, next) {
        var index = 0;

        function executeNext(err) {
            if (err) {
                return (next(err));
            }

            if (index >= handlers.length) {
                return (next());
            }

            var currentHandler = handlers[index++];

            if (typeof (currentHandler) === 'function') {
                try {
                    currentHandler(req, res, executeNext);
                } catch (e) {
                    next(e);
                }
            } else {
                req.log.error({
                    handlerIndex: index - 1,
                    handlerType: typeof (currentHandler),
                    handler: currentHandler
                }, 'Invalid handler in bucket object chain');

                next(new Error('Invalid handler in bucket object chain' +
                    ' at index ' + (index - 1)));
            }
        }

        executeNext();
    }

    /**
     * Handle Manta anonymous object access routing
     * Orchestrates path parsing, parameter setup, and handler execution
     */
    function handleMantaAnonymousAccess(req, res, next, bucketsModule) {
        var requestPath = req.path();
        var pathParts = parseMantaBucketObjectPath(requestPath);

        if (!isMantaAnonymousObjectAccess(pathParts, req)) {
            req.log.debug('S3_DEBUG: Passing through to next handler' +
                ' in GET two-segment route');
            return (next());
        }

        req.log.debug('S3_DEBUG: Detected Manta bucket object request' +
            ' with potential anonymous access, routing to bucket handler');

        setupMantaObjectParams(req, pathParts);

        var rawHandlers = bucketsModule.getBucketObjectHandler();
        var handlers = flattenHandlers(rawHandlers);

        req.log.debug({
            rawHandlerCount: rawHandlers.length,
            flattenedHandlerCount: handlers.length
        }, 'S3_DEBUG: Flattened bucket object handler chain');

        executeHandlerChain(handlers, req, res, next);
    }

    server.get({
        name: 'S3GetObject',
        path: /^\/([^\/]+)\/(.+)$/
    }, function s3GetObject(req, res, next) {
        req.log.debug({
            path: req.path(),
            isS3Request: !!req.isS3Request
        }, 'S3_DEBUG: GET two-segment route - checking if S3 request');

        if (req.isS3Request) {
            req.log.debug('S3_DEBUG: Processing as S3 request' +
                ' in GET two-segment route');
            return (s3RouteHandler(req, res, next));
        }

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
         * if we are here, it probably means we are trying to get the
         * object and we need to account if this object has anonymous
         * access.
         */

        handleMantaAnonymousAccess(req, res, next, buckets);
    });

    server.put({
        name: 'S3PutObject',
        path: /^\/([^\/]+)\/(.+)$/
    }, function s3PutObject(req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.head({
        name: 'S3HeadObject',
        path: /^\/([^\/]+)\/(.+)$/
    }, function s3HeadObject(req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.del({
        name: 'S3DeleteObject',
        path: /^\/([^\/]+)\/(.+)$/
    }, function s3DeleteObject(req, res, next) {
        if (req.isS3Request) {
            s3RouteHandler(req, res, next);
        } else {
            next();
        }
    });

    server.post({
        name: 'S3PostObject',
        path: /^\/([^\/]+)\/(.+)$/
    }, function s3PostObject(req, res, next) {
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
