/*
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * middleware.js: Middleware functions for Restify server.
 *
 * Provides middleware for:
 * - Time to first byte (TTFB) tracking
 * - Dependency validation
 * - CORS preflight handling
 * - Anonymous access setup
 * - Pre-middleware functions (request preprocessing)
 */

var crypto = require('crypto');
var url = require('url');
var verror = require('verror');
var mime = require('mime');

var s3Compat = require('../s3-compat');
var constants = require('../constants');

require('../errors');


///--- Functions

/**
 * Middleware to track time to first byte (TTFB).
 * Sets req._timeAtFirstByte when the response header is sent.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Restify next callback
 */
function traceTTFB(req, res, next) {
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
}


/**
 * Middleware to ensure required client dependencies are available.
 * Checks for mahi, storinfo (for write operations), and metadataPlacement.
 *
 * @param {Object} clients - Client connections object
 * @return {Function} Restify middleware function
 */
function createDependencyChecker(clients) {
    return function ensureDependencies(req, res, next) {
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
    };
}


/**
 * CORS preflight OPTIONS handler.
 *
 * For service-level requests (path "/"), returns a safe
 * wildcard CORS response without credentials.
 *
 * For bucket-scoped requests (path "/bucket/..."), does NOT
 * set CORS headers — defers to the bucket-specific CORS
 * handler (cors-middleware.js) which validates the Origin
 * against the bucket's PutBucketCors configuration.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Restify next callback
 */
function corsPreflightHandler(req, res, next) {
    if (!req.headers['access-control-request-method']) {
        next();
        return;
    }

    var path = req.path();
    var pathParts = path.split('/').filter(function (p) {
        return (p.length > 0);
    });

    req.log.debug({
        origin: req.headers.origin,
        requestMethod: req.headers['access-control-request-method'],
        url: req.url,
        pathSegments: pathParts.length
    }, 'CORS: Handling preflight OPTIONS request');

    //
    // The S3 API has two categories of endpoints:
    //
    // 1. Service-level (path = "/"):
    //    STS operations  — POST / with Action=AssumeRole,
    //                      GetSessionToken, etc.
    //    IAM operations  — POST / with Action=CreateRole,
    //                      PutRolePolicy, etc.
    //    ListBuckets     — GET /
    //    These have no bucket context, so there is no per-bucket
    //    CORS config to consult. We return a safe wildcard CORS
    //    response (no credentials).
    //
    // 2. Bucket-scoped (path = "/bucket" or "/bucket/object/..."):
    //    All S3 data operations — GetObject, PutObject,
    //    DeleteObject, etc.
    //    These belong to a specific bucket which MAY have a CORS
    //    configuration set via PutBucketCors. We must NOT answer
    //    the preflight here — instead we let the request continue
    //    to cors-middleware.js which loads the bucket's CORS config
    //    and validates the Origin against it.
    //
    // We distinguish the two by counting path segments:
    //   pathParts.length === 0  →  "/"            →  service-level
    //   pathParts.length >= 1   →  "/bucket/..."  →  bucket-scoped
    //
    // This matches AWS S3 behavior: CORS headers are ONLY returned
    // for bucket requests when the bucket has an explicit CORS
    // configuration that lists the requesting origin. No config =
    // no CORS headers = browser blocks the cross-origin request.
    //

    if (pathParts.length === 0) {
        // Service-level: safe wildcard, no credentials
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods',
                      'GET,POST,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers',
                      'Content-Type,authorization,' +
                      'x-amz-content-sha256,x-amz-date,' +
                      'x-amz-security-token');
        res.setHeader('Access-Control-Max-Age', '3600');
        res.send(200);
        next(false);
        return;
    }

    // Bucket-scoped: we cannot look up the bucket's CORS config
    // here because preflight runs before authentication, and
    // bucket metadata requires the account UUID (which comes from
    // auth). This is an architectural difference from AWS S3 where
    // bucket names are globally unique.
    //
    // Strategy: return a permissive preflight (allow common methods
    // and headers) with Access-Control-Allow-Origin: * but WITHOUT
    // Access-Control-Allow-Credentials. This lets the browser send
    // the actual request, which goes through the full auth + CORS
    // pipeline in common.js / cors-middleware.js. The actual response
    // will only include Access-Control-Allow-Origin if the bucket's
    // CORS config allows the requesting origin.
    //
    // Why this is safe:
    //   - Allow-Origin: * without Allow-Credentials means the browser
    //     will NOT send cookies or auth headers automatically
    //   - Presigned URLs (which carry auth in the URL, not headers)
    //     will work — the actual response includes CORS headers if
    //     the bucket config allows it
    //   - SDK calls with Authorization header will work — the browser
    //     sees Authorization in Allow-Headers and sends it, then the
    //     actual response's CORS headers determine if JS can read it
    //   - An attacker page cannot steal data because the actual
    //     response must have Allow-Origin matching the attacker's
    //     origin, which only happens if the bucket CORS config says so
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods',
                  'GET,PUT,POST,DELETE,HEAD,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',
                  'Content-Type,authorization,' +
                  'x-amz-content-sha256,x-amz-date,' +
                  'x-amz-security-token,x-amz-user-agent');
    res.setHeader('Access-Control-Max-Age', '3600');
    res.setHeader('Vary', 'Origin');
    // NO Access-Control-Allow-Credentials
    res.send(200);
    next(false);
}


/**
 * Anonymous access setup handler.
 * Sets up metadataPlacement for anonymous access handler to use.
 *
 * @param {Object} clients - Client connections object
 * @param {Object} anonymousAuth - Anonymous authentication module
 * @return {Function} Restify middleware function
 */
function createAnonymousAccessHandler(clients, anonymousAuth) {
    return function anonymousAccessSetup(req, res, next) {
        // Set up metadataPlacement early for anonymous access handler
        req.metadataPlacement = clients.metadataPlacement;
        anonymousAuth.anonymousAccessHandler(req, res, next);
    };
}


///--- Pre-Middleware Functions

/**
 * Pre-middleware to monitor client connection close events.
 * Adds listener to track when clients close connections prematurely.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Restify next callback
 */
function watchClose(req, res, next) {
    /*
     * In some cases, we proactively check for closed client connections.
     * Add a listener early on that just records this fact.
     */
    req.on('close', function () {
        req.log.warn('client closed connection');
        req._muskie_client_closed = true;
    });

    next();
}


/**
 * Pre-middleware to stash request configuration and path before sanitization.
 * Sets up dtrace probes, config, and original path on request object.
 *
 * @param {Object} options - Server options object containing dtrace_probes
 * @return {Function} Restify pre-middleware function
 */
function createStashPath(options) {
    return function stashPath(req, res, next) {
        req._probes = options.dtrace_probes;
        req.config = options;
        req.pathPreSanitize = url.parse(req.url).pathname;
        next();
    };
}


/**
 * Pre-middleware for comprehensive request logging.
 * Logs all incoming request details for debugging purposes.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Restify next callback
 */
function logAllRequests(req, res, next) {
    req.log.debug({
        method: req.method,
        url: req.url,
        path: req.path(),
        host: req.headers.host,
        userAgent: req.headers['user-agent'],
        authorization: (req.headers.authorization || '').substring(0, 50) ||
            'NONE',
        contentType: req.headers['content-type'],
        contentLength: req.headers['content-length'],
        encoding: req.headers['content-encoding'],
        transferEncoding: req.headers['transfer-encoding'],
        allHeaders: Object.keys(req.headers)
    }, 'REQUEST_DEBUG: Incoming request details');

    next();
}


/**
 * Pre-middleware to detect S3 upload requests.
 * Identifies PUT/POST requests with SigV4 authentication that require
 * binary mode handling.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Restify next callback
 */
function detectS3Uploads(req, res, next) {
    var authHeader = req.headers.authorization || '';
    var isSigV4 = authHeader.toLowerCase().indexOf(
        constants.AWS_AUTH.SCHEME_SIGV4) === 0;

    // Mark S3 upload requests for binary mode configuration
    if ((req.method === 'PUT' || req.method === 'POST') && isSigV4) {
        req._isS3Upload = true;
        req.log.debug({
            isS3Upload: true,
            contentType: req.headers['content-type'],
            isChunked: req.isChunked()
        }, 'BINARY_DEBUG: S3 upload request detected');
    }

    next();
}


/**
 * Pre-middleware to configure binary mode for S3 uploads.
 * Forces binary mode for detected S3 upload requests to prevent
 * data corruption from text encoding.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Restify next callback
 */
function configureBinaryMode(req, res, next) {
    // Only configure binary mode if this was marked as an S3 upload
    if (!req._isS3Upload) {
        next();
        return;
    }

    req.log.debug('BINARY_DEBUG: Forcing binary mode for S3 upload');

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

    next();
}


/**
 * Pre-middleware to cleanup malformed content-type headers.
 * Validates and fixes content-type headers using mime.lookup().
 *
 * @param {RegExp} validContentTypeRe - Regex to validate content-type format
 * @return {Function} Restify pre-middleware function
 */
function createCleanupContentType(validContentTypeRe) {
    return function cleanupContentType(req, res, next) {
        var ct = req.headers['content-type'];
        /*
         * content-type must have a type, '/' and sub-type
         */
        if (ct && !validContentTypeRe.test(ct)) {
            req.log.debug('receieved a malformed content-type: %s', ct);
            req.headers['content-type'] = mime.lookup(ct);
        }

        next();
    };
}


/**
 * Pre-middleware to preserve raw request body for S3 signature verification.
 * Captures and buffers request body for POST/PUT operations that require
 * signature verification (multipart uploads, bulk deletes, STS, CORS config).
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Restify next callback
 */
function preserveRawBodyPreMiddleware(req, res, next) {
    // Check if this is a Complete Multipart Upload request
    var isCompleteMultipartUpload = false;
    if (req.method === 'POST' && req.url) {
        // Parse query parameters to check for uploadId
        // (Complete Multipart Upload) and exclude uploads
        // (Initiate Multipart Upload)
        var parsedUrl = url.parse(req.url, true);
        var query = parsedUrl.query || {};
        isCompleteMultipartUpload = ('uploadId' in query) &&
                                   !('uploads' in query);
    }

    // Check if this is a CORS configuration request
    var isCorsRequest = false;
    if (req.method === 'PUT' && req.url) {
        var parsedCorsUrl = url.parse(req.url, true);
        var corsQuery = parsedCorsUrl.query || {};
        isCorsRequest = ('cors' in corsQuery);
    }

    // Preserve raw body for POST requests that might be S3 bulk operations
    // Include: XML content-type requests, Complete Multipart Upload
    // requests,
    // bulk delete requests, OR STS requests
    // Also preserve for PUT CORS configuration requests
    var contentType = req.headers['content-type'] || '';
    var isBulkDeleteRequest = false;
    if (req.url) {
        var parsedDeleteUrl = url.parse(req.url, true);
        var deleteQuery = parsedDeleteUrl.query || {};
        isBulkDeleteRequest = ('delete' in deleteQuery);
    }
    var isXmlRequest = contentType === 'application/xml' ||
                      contentType.startsWith('application/x-amz-json') ||
                      contentType.startsWith('text/xml');

    // Check if this is an STS request (POST to / with Action parameter)
    var authHeader = req.headers.authorization || '';
    var isStsRequest = req.method === 'POST' &&
                      req.url === '/' &&
                      authHeader &&
                      authHeader.toLowerCase().
        indexOf(constants.AWS_AUTH.SCHEME_SIGV4) !== -1;

    if (((req.method === 'POST' &&
          authHeader &&
          (isXmlRequest || isCompleteMultipartUpload ||
           isBulkDeleteRequest || isStsRequest)) ||
         (isCorsRequest)) &&
        req.headers['content-length'] &&
        parseInt(req.headers['content-length'], 10) > 0) {

        req.log.debug({
            contentLength: req.headers['content-length'],
            contentType: req.headers['content-type'],
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
}


/**
 * Pre-middleware for early S3 request detection.
 * Detects S3 requests by checking for SigV4 auth headers or presigned URLs,
 * parses S3 request details, and marks binary operations.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Restify next callback
 */
function s3RequestDetectorEarly(req, res, next) {
    // Check if this is a SigV4 request and mark it for later processing
    var authHeader = req.headers.authorization || '';

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
}


///--- Exports

/**
 * MANTA-331 sanitizePath() strips trailing slashes, this breaks
 * SigV4 signature validation, the S3 clients sign the original URL,
 * but as the original URL is already tampered this will cause that
 * all authentication attempts to fail, as signatures will NEVER match.
 *
 * This must be registered as a pre-routing middleware BEFORE sanitizePath().
 */
function preserveRawUrl(req, res, next) {
    req._rawSignedUrl = req.url;
    next();
}

module.exports = {
    traceTTFB: traceTTFB,
    createDependencyChecker: createDependencyChecker,
    corsPreflightHandler: corsPreflightHandler,
    createAnonymousAccessHandler: createAnonymousAccessHandler,
    watchClose: watchClose,
    createStashPath: createStashPath,
    logAllRequests: logAllRequests,
    detectS3Uploads: detectS3Uploads,
    configureBinaryMode: configureBinaryMode,
    createCleanupContentType: createCleanupContentType,
    preserveRawBodyPreMiddleware: preserveRawBodyPreMiddleware,
    preserveRawUrl: preserveRawUrl,
    s3RequestDetectorEarly: s3RequestDetectorEarly
};
