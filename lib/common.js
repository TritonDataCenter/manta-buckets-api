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
var AwsChunkedDecoder = require('./aws-chunked-decoder');
var constants = require('./constants');

///--- Globals

var clone = utils.shallowCopy;
var sprintf = util.format;

var ANONYMOUS_USER = libmantalite.ANONYMOUS_USER;

var CORS_RES_HDRS = [
    'access-control-allow-headers',
    'access-control-allow-origin',
    'access-control-expose-headers',
    'access-control-max-age',
    'access-control-allow-methods',
    'access-control-allow-credentials'
];

/*
 * Default minimum and maximum number of copies of an object we will store,
 * as specified in the {x-}durability-level header.
 *
 * The max number of copies is configurable in the config file; the minimum
 * is not.
 */
var DEF_MIN_COPIES = constants.COPY_LIMITS.MIN_COPIES;
var DEF_MAX_COPIES = constants.COPY_LIMITS.MAX_COPIES;

// Default number of object copies to store.
var DEF_NUM_COPIES = constants.COPY_LIMITS.DEFAULT_COPIES;

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
var METRIC_INBOUND_DATA_COUNTER = 'muskie_inbound_streamed_bytes';
var METRIC_OUTBOUND_DATA_COUNTER = 'muskie_outbound_streamed_bytes';
var METRIC_DELETED_DATA_COUNTER = 'muskie_deleted_bytes';

// The max number of headers we store on an object in Moray: 4 KB.
var MAX_HDRSIZE = constants.SIZE_LIMITS.MAX_HEADER_SIZE;

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

function addCustomHeaders(req, res, next) {
    var md = req.metadata.headers;
    var origin = req.headers.origin;
    req.log.debug({
        origin: origin,
        hasMetadata: !!req.metadata,
        metadataHeaders: md ? Object.keys(md) : 'undefined',
        metadataHeadersRaw: md,
        requestUrl: req.url,
        requestMethod: req.method
    }, 'CORS DEBUG: addCustomHeaders called');

    // Separate CORS headers from other headers
    var corsHeaders = {};
    var regularHeaders = {};

    if (md && Object.keys(md).length > 0) {
        var mdKeys = Object.keys(md);
        req.log.debug({
            metadataKeysCount: mdKeys.length,
            firstFewKeys: mdKeys.slice(0, 10)
        }, 'CORS DEBUG: Processing metadata headers');

        // Log each metadata key individually to see exact names
        mdKeys.forEach(function (k) {
            if (k.toLowerCase().includes('control') || k.toLowerCase().
                includes('origin') || k.toLowerCase().includes('method')) {
                req.log.debug({
                    key: k,
                    value: md[k],
                    inCorsHeaders: CORS_RES_HDRS.indexOf(k) !== -1
                }, 'CORS DEBUG: Potential CORS key');
            }
        });
    }

    Object.keys(md || {}).forEach(function (k) {
        // Handle Manta's m- prefix for metadata headers
        var headerName = k;
        if (k.startsWith('m-')) {
            headerName = k.substring(2); // Remove 'm-' prefix
        }

        var isCorsHeader = CORS_RES_HDRS.indexOf(headerName) !== -1;
        if (isCorsHeader) {
            corsHeaders[headerName] = md[k]; // Use the clean header name as key
            req.log.debug({
                originalKey: k,
                cleanKey: headerName,
                value: md[k],
                detected: 'CORS'
            }, 'CORS DEBUG: Found CORS header');
        } else {
            regularHeaders[k] = md[k];
        }
    });

    // Always process non-CORS headers
    Object.keys(regularHeaders).forEach(function (k) {
        res.header(k, regularHeaders[k]);
    });

    // Process CORS headers if we have CORS configuration
    // For presigned URLs, browsers don't send Origin header but we
    // still need CORS headers
    if (Object.keys(corsHeaders).length > 0) {
        var originAllowed = false;

        // First, check if origin is allowed
        if (corsHeaders['access-control-allow-origin']) {

            var allowedOrigins = corsHeaders['access-control-allow-origin'].
                //JSSTYLED
                split(/\s*,\s*/);
            for (var i = 0; i < allowedOrigins.length; i++) {
                var allowedOrigin = allowedOrigins[i];
                if (allowedOrigin === origin || allowedOrigin === '*' ||
                    allowedOrigin === 'star') {
                    originAllowed = true;

                    // For wildcard, use '*' for presigned URLs (no origin),
                    // otherwise reflect origin
                    if ((allowedOrigin === '*' || allowedOrigin === 'star') &&
                        (!origin || origin === 'null')) {
                        req.log.debug({
                            allowedOrigin: allowedOrigin,
                            actualOrigin: origin,
                            action: 'CORS_WILDCARD_FOR_PRESIGNED'
                        }, 'CORS DEBUG: Using wildcard for presigned URL' +
                                     ' (no origin)');
                        if (!res.getHeader('Access-Control-Allow-Origin')) {
                            req.log.debug('CORS DEBUG:' +
                                         ' Setting ' +
                                         'Access-Control-Allow-Origin to *');
                            res.setHeader('Access-Control-Allow-Origin', '*');
                        }
                    } else {
                        // Always reflect the actual origin for security when
                        // origin is present
                        req.log.debug({
                            allowedOrigin: allowedOrigin,
                            actualOrigin: origin,
                            action: 'CORS_ORIGIN_REFLECTION'
                        }, 'CORS DEBUG: Reflecting origin instead of wildcard');
                        if (!res.getHeader('Access-Control-Allow-Origin')) {
                            req.log.debug('CORS DEBUG: Setting ' +
                                          'Access-Control-Allow-Origin to: ' +
                                          origin);
                            res.setHeader('Access-Control-Allow-Origin',
                                          origin);
                        }
                    }
                    break;
                }
            }
        }

        // If origin is allowed, check method and add other CORS headers
        if (originAllowed) {
            // Check methods
            if (corsHeaders['access-control-allow-methods']) {
                var methodsVal = corsHeaders['access-control-allow-methods'];
                var methodSeparator;
                if (methodsVal.includes(',')) {
                    //JSSTYLED
                    methodSeparator = /\s*,\s*/;
                } else {
                    //JSSTYLED
                    methodSeparator = /\s*-\s*/;
                }
                var methodsArray = methodsVal.split(methodSeparator);

                if (methodsArray.some(function (v) {
                    return (v === req.method); })) {
                    // Convert dashes back to commas for proper
                    // CORS header format
                    if (!methodsVal.includes(',') && methodsVal.includes('-')) {
                        methodsVal = methodsVal.replace(/-/g, ', ');
                    }
                    res.header('access-control-allow-methods', methodsVal);
                } else {
                    // Method not allowed, remove all CORS headers
                    CORS_RES_HDRS.forEach(function (h) {
                        res.removeHeader(h);
                    });
                    return;
                }
            }

            // Add other CORS headers if present
            Object.keys(corsHeaders).forEach(function (k) {
                if (k !== 'access-control-allow-origin' &&
                    k !== 'access-control-allow-methods') {
                    res.header(k, corsHeaders[k]);
                }
            });

            // Ensure Access-Control-Allow-Credentials is exposed to JavaScript
            if (corsHeaders['access-control-allow-credentials']) {
                var exposeHeaders =
                    corsHeaders['access-control-expose-headers'] || '';
                if (exposeHeaders && !exposeHeaders.
                    includes('Access-Control-Allow-Credentials')) {
                    exposeHeaders += ', Access-Control-Allow-Credentials';
                } else if (!exposeHeaders) {
                    exposeHeaders = 'Access-Control-Allow-Credentials';
                }
                res.header('access-control-expose-headers', exposeHeaders);
            }
        }
    }

    // If no object-level CORS headers were applied,
    // try bucket-level CORS configuration as fallback
    // This works for both regular CORS requests (with origin)
    // and presigned URLs (without origin)
    var existingOriginHeader1 = res.getHeader('access-control-allow-origin');
    var existingOriginHeader2 = res.getHeader('Access-Control-Allow-Origin');

    // Treat string "null" as no header (from presigned URLs)
    var hasRealOriginHeader = (existingOriginHeader1 &&
                              existingOriginHeader1 !== 'null') ||
                             (existingOriginHeader2 &&
                              existingOriginHeader2 !== 'null');

    req.log.debug({
        existingOriginHeader1: existingOriginHeader1,
        existingOriginHeader2: existingOriginHeader2,
        hasRealOriginHeader: hasRealOriginHeader,
        willCallBucketCors: !hasRealOriginHeader
    }, 'CORS DEBUG: Checking existing CORS headers before bucket fallback');

    if (!hasRealOriginHeader) {
        tryBucketLevelCors(req, res, origin, function () {
            // Continue to next middleware after CORS processing
            if (next && typeof (next) === 'function') {
                next();
            }
        });
    } else {
        // Continue to next middleware immediately
        if (next && typeof (next) === 'function') {
            next();
        }
    }
}

function tryBucketLevelCors(req, res, origin, callback) {
    // Try bucket-level CORS configuration (AWS S3 compatible)
    // Since bucket CORS config is stored as a special object, we'll attempt
    // to retrieve it when needed (this could be optimized later)

    if (!req.bucket) {
        req.log.debug({
            hasBucket: !!req.bucket,
            origin: origin,
            originType: typeof (origin)
        }, 'tryBucketLevelCors: skipping due to missing bucket');
        if (callback) callback();
        return;
    }

    var log = req.log;
    var owner = req.owner.account.uuid;
    var requestId = req.getId();
    var corsObjectName = '.cors-configuration';

    log.debug({
        bucketName: req.bucket ? req.bucket.name : 'unknown',
        bucketId: req.bucket ? req.bucket.id : 'unknown',
        bucketObject: req.bucket,
        origin: origin,
        originType: typeof (origin),
        ownerUuid: owner
    }, 'tryBucketLevelCors: attempting to load bucket CORS config');

    // Try to retrieve the CORS configuration object synchronously
    var corsNameHash = require('crypto').createHash('md5').
        update(corsObjectName).digest('hex');
    var bucketIdentifier = req.bucket.id;
    var objectLocation = req.metadataPlacement.getObjectLocation(owner,
        bucketIdentifier, corsNameHash);
    var objectClient = req.metadataPlacement.
        getBucketsMdapiClient(objectLocation);

    log.debug({
        corsObjectName: corsObjectName,
        bucketId: req.bucket.id,
        bucketName: req.bucket.name,
        bucketIdentifier: bucketIdentifier,
        owner: owner,
        requestId: requestId,
        objectLocation: objectLocation
    }, 'tryBucketLevelCors: about to getObject for CORS config');

    objectClient.getObject(owner, bucketIdentifier, corsObjectName,
        objectLocation.vnode, {}, requestId, function (getErr, corsObjectData) {
        if (getErr) {
            log.debug({
                err: getErr,
                errCode: getErr.code,
                errMessage: getErr.message,
                corsObjectName: corsObjectName,
                bucketId: req.bucket.id,
                bucketName: req.bucket.name
            }, 'tryBucketLevelCors: no bucket CORS config found');
            if (callback) callback();
            return;
        }

        log.debug({
            corsObjectData: corsObjectData,
            headers: corsObjectData.headers,
            corsData: corsObjectData.headers ?
                corsObjectData.headers['cors-data'] : 'no-headers'
        }, 'tryBucketLevelCors: retrieved CORS object data');

        try {
            var corsConfig = corsObjectData.headers['cors-data'];
            if (!corsConfig) {
                log.debug('tryBucketLevelCors: cors-data header is missing');
                if (callback) callback();
                return;
            }
            var parsedConfig = JSON.parse(corsConfig);
            var corsRules = parsedConfig.CORSRules || [];

            log.debug({
                corsRulesCount: corsRules.length,
                origin: origin
            }, 'tryBucketLevelCors: found bucket CORS config');

            // Find matching CORS rule
            for (var i = 0; i < corsRules.length; i++) {
                var rule = corsRules[i];
                var allowedOrigins = rule.AllowedOrigins || [];

                // Check if origin matches any allowed origin
                var matchedOrigin = null;
                for (var j = 0; j < allowedOrigins.length; j++) {
                    var allowedOrigin = allowedOrigins[j];
                    if (allowedOrigin === '*' || allowedOrigin === origin) {
                        matchedOrigin = allowedOrigin;
                        break;
                    }
                }

                if (matchedOrigin) {
                    log.debug({
                        origin: origin,
                        rule: rule
                    }, 'tryBucketLevelCors: applying bucket CORS rule');

                    // Apply CORS headers from matching rule
                    if (matchedOrigin === '*' &&
                        (!origin || origin === 'null')) {
                        // For presigned URLs (no origin),
                        // use wildcard when allowed
                        res.setHeader('Access-Control-Allow-Origin', '*');
                    } else {
                        // Always reflect the actual origin for
                        // security when origin is present
                        res.setHeader('Access-Control-Allow-Origin', origin);
                    }

                    // Set Access-Control-Allow-Methods
                    var allowedMethods = rule.AllowedMethods || [];
                    if (allowedMethods.length > 0) {
                        res.setHeader('Access-Control-Allow-Methods',
                                      allowedMethods.join(', '));
                    }

                    // Set Access-Control-Allow-Headers
                    var allowedHeaders = rule.AllowedHeaders || [];
                    if (allowedHeaders.length > 0) {
                        res.setHeader('Access-Control-Allow-Headers',
                                      allowedHeaders.join(', '));
                    }

                    // Set Access-Control-Expose-Headers
                    var exposeHeaders = rule.ExposeHeaders || [];
                    if (exposeHeaders.length > 0) {
                        res.setHeader('Access-Control-Expose-Headers',
                                      exposeHeaders.join(', '));
                    }

                    // Set Access-Control-Max-Age
                    if (rule.MaxAgeSeconds) {
                        res.setHeader('Access-Control-Max-Age',
                                   rule.MaxAgeSeconds);
                    }

                    // Set Access-Control-Allow-Credentials for
                    // credentials requests
                    if (rule.AllowCredentials === true ||
                        rule.AllowCredentials === 'true') {
                        res.header('Access-Control-Allow-Credentials', 'true');

                        // Ensure credentials header is exposed to JavaScript
                        var currentExposeHeaders =
                            res.getHeader('Access-Control-Expose-Headers') ||
                            '';
                        if (currentExposeHeaders && !currentExposeHeaders.
                            includes('Access-Control-Allow-Credentials')) {
                            currentExposeHeaders +=
                                ', Access-Control-Allow-Credentials';
                        } else if (!currentExposeHeaders) {
                            currentExposeHeaders =
                                'Access-Control-Allow-Credentials';
                        }
                        res.header('Access-Control-Expose-Headers',
                                   currentExposeHeaders);
                    }

                    break; // Stop at first matching rule
                }
            }

            // Call callback when CORS processing is complete
            if (callback) callback();
        } catch (parseErr) {
            log.error({err: parseErr},
                      'tryBucketLevelCors: failed to parse bucket CORS config');
            if (callback) callback();
        }
    });
}


function findSharks(req, res, next) {
    if (req._zero || req.query.metadata) {
        next();
        return;
    }

    // Check for pre-allocated sharks (used by multipart uploads)
    if (req.preAllocatedSharks && Array.isArray(req.preAllocatedSharks)) {
        // Wrap pre-allocated sharks in array format expected by
        // startSharkStreams
        // Format should be: [[shark1, shark2, .. sharkn]] to match
        // storinfo.choose() output
        req._sharks = [req.preAllocatedSharks];

        req.log.debug({
            sharkCount: req.preAllocatedSharks.length,
            sharks: req.preAllocatedSharks.map(function (s) {
                return (s ? s.manta_storage_id : 'null');
            }),
            preAllocatedUsed: true,
            wrappedFormat: true
        }, 'findSharks: using pre-allocated' +
                     ' sharks for MPU part (wrapped format)');
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
    var reallocationCount = 0;
    var maxReallocations = 3;

    // For AWS chunked requests, use the decoded content length instead of
    // undefined
    // This ensures shark client uses content-length header instead of
    // transfer-encoding: chunked
    var contentLength;
    if (req.isChunked() && req.header('content-encoding') === 'aws-chunked') {
        // AWS chunked: use decoded content length for shark connections
        var decodedLength = req.header('x-amz-decoded-content-length');
        contentLength = decodedLength ? parseInt(decodedLength, 10) : req._size;
        req.log.debug({
            originalSize: req._size,
            decodedLength: decodedLength,
            usingContentLength: contentLength
        }, 'AWS chunked: using decoded content-length for shark connections');
    } else if (req.isChunked()) {
        // Regular chunked requests
        contentLength = undefined;
    } else {
        // Normal requests
        contentLength = req._size;
    }

    var opts = {
        contentType: req.getContentType(),
        contentLength: contentLength,
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
    req.failedSharks = req.failedSharks || [];

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

                // Identify failed sharks to exclude them from requests
                var failedSharkIds = [];
                if (results && results.operations) {
                    results.operations.forEach(function (op, i) {
                        if (op.err) {
                            var sharkId = inputs[i].manta_storage_id;
                            failedSharkIds.push(sharkId);

                            // Only exclude on infrastructure errors,
                            // not timeouts
                            var shouldExclude = op.err.code ===
                                'ECONNREFUSED' ||
                                op.err.code === 'ENOTFOUND' ||
                                op.err.code === 'ENETUNREACH';

                            // Don't exclude cueball timeout errors -
                            // these are often transient
                            if (op.err.name === 'ConnectionTimeoutError' ||
                                op.err.message.
                                includes('Connection timed out') ||
                                op.err.message.includes('failed to connect')) {
                                shouldExclude = false;
                            }

                            // Only add to failedSharks if it
                            // should be excluded
                            if (shouldExclude &&
                                req.failedSharks.indexOf(sharkId) === -1) {
                                req.failedSharks.push(sharkId);
                            }

                            log.debug({
                                sharkId: sharkId,
                                errorCode: op.err.code,
                                errorMessage: op.err.message,
                                willExclude: shouldExclude,
                                addedToExcludeList: shouldExclude
                            }, 'startSharkStreams: shark connection failed');
                        }
                    });
                }

                req.abandonSharks();

                // For timeout errors, try the same sharks again before
                // reallocating
                var hasTimeoutErrors = failedSharkIds.length > 0 &&
                    results && results.operations &&
                    results.operations.some(function (op) {
                        return op.err && op.err.message &&
                            op.err.message.includes('failed to connect');
                    });

                // Try next set of sharks if available
                if (ndx < req._sharks.length) {
                    attempt(req._sharks[ndx++]);
                } else if (hasTimeoutErrors && reallocationCount === 0) {
                    // For timeout errors on first attempt,
                    // retry the same sharks before reallocation
                    log.debug({
                        timeoutRetryAttempt: 1,
                        sharksWithTimeouts: failedSharkIds
                    }, 'startSharkStreams:' +
                       ' retrying same sharks due to timeout errors');

                    reallocationCount++; // Count this as a reallocation attempt
                    ndx = 0;
                    attempt(req._sharks[ndx++]);
                } else if (reallocationCount < maxReallocations) {
                    // Check if this is an MPU request with pre-allocated sharks
                    var isMPURequest = req.preAllocatedSharks &&
                        Array.isArray(req.preAllocatedSharks);

                    if (isMPURequest) {
                        // For MPU requests with pre-allocated sharks,
                        // don't reallocate
                        // All parts must go to the same sharks for v2
                        // commit to work
                        log.warn({
                            reallocationAttempt: reallocationCount + 1,
                            failedSharks: req.failedSharks,
                            preAllocatedSharks: req.preAllocatedSharks.map(
                                function (s) {
                                    return (s.manta_storage_id);
                            })
                        }, 'startSharkStreams: MPU part' +
                           ' failed on pre-allocated sharks, not reallocating');

                        // Fail the request rather than breaking MPU shark
                        // consistency
                        next(new SharksExhaustedError(res));
                        return;
                    }

                    // Reallocate with excluded sharks filtered out
                    // (non-MPU only)
                    log.debug({
                        reallocationAttempt: reallocationCount + 1,
                        maxReallocations: maxReallocations,
                        failedSharks: req.failedSharks,
                        totalFailedCount: req.failedSharks.length
                    }, 'startSharkStreams: attempting shark reallocation');

                    reallocationCount++;

                    // Request new sharks, filtering out failed ones
                    var storinfo = req.storinfo;
                    var reallocOpts = {
                        replicas: req._copies,
                        requestId: req.getId(),
                        size: req._size,
                        isOperator: req.caller.account.isOperator,
                        log: req.log
                    };

                    storinfo.choose(reallocOpts,
                                    function (reallocErr, availableSharks) {
                        if (reallocErr) {
                            log.debug({
                                err: reallocErr,
                                reallocationAttempt: reallocationCount
                            }, 'startSharkStreams: reallocation failed');
                        } else if (availableSharks && availableSharks.length >=
                                   req._copies) {
                            // Filter out failed sharks manually if storinfo
                            // doesn't support excluding sharks
                            var filteredSharks = availableSharks.
                                filter(function (shark) {
                                return req.failedSharks.
                                        indexOf(shark.manta_storage_id) === -1;
                            });

                            if (filteredSharks.length >= req._copies) {
                                req._sharks = filteredSharks;
                                ndx = 0;
                                attempt(req._sharks[ndx++]);
                                return;
                            }
                        }

                        log.debug({
                            availableSharksCount: availableSharks ?
                                availableSharks.length : 0,
                            requiredCopies: req._copies,
                            err: reallocErr
                        }, 'startSharkStreams:' +
                           ' insufficient sharks after reallocation');

                        // Continue to exhausted sharks error
                        log.debug({
                            reallocationAttempts: reallocationCount,
                            totalSharksExhausted: req._sharks.length,
                            failedSharkIds: req.failedSharks
                        }, 'startSharkStreams: exhausted all shark options');
                        next(new SharksExhaustedError(res));
                    });
                    return;
                } else {
                    // All options exhausted
                    log.debug({
                        reallocationAttempts: reallocationCount,
                        totalSharksExhausted: req._sharks.length,
                        failedSharkIds: req.failedSharks
                    }, 'startSharkStreams: exhausted all shark options');
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

    // AWS chunked decoder variable (declared here for scope)
    var awsDecoder = null;

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
        // Clean up AWS decoder if it exists
        if (awsDecoder) {
            req.unpipe(awsDecoder);
            awsDecoder.unpipe(check);
            awsDecoder.removeAllListeners();
        } else {
            req.unpipe(check);
        }
        check.abandon();

        next(err);
    });

    var barrier = vasync.barrier();
    // For AWS chunked uploads, account for encoding overhead
    var maxBytes = req._size;
    var isAwsChunked = req._awsChunkedMPU || // Support multipart uploads
        // AWS CLI uses content-encoding: aws-chunked
        (req.isS3Request && req.header('content-encoding') === 'aws-chunked');

    if (isAwsChunked && req.isS3Request) {
        // AWS chunked encoding can have unpredictable overhead due to
        // chunk sizes, checksums, metadata. For S3 compatibility, disable
        // the size check and let underlying Manta limits handle it
        maxBytes = Math.max(req._size * 10,
                           constants.SIZE_LIMITS.STREAMING_BUFFER);
    }

    var check = new CheckStream({
        algorithm: 'md5',
        maxBytes: maxBytes,
        timeout: DATA_TIMEOUT,
        counter: req.collector.getCollector(METRIC_INBOUND_DATA_COUNTER)
    });
    var log = req.log;

    barrier.once('drain', function onCompleteStreams() {
        req._timeToLastByte = Date.now();

        req.connection.removeListener('error', abandonUpload);
        req.removeListener('error', next_err);

        if (req._awsChunkedMPU) {
            log.debug({
                isS3Request: req.isS3Request,
                awsChunkedMPU: req._awsChunkedMPU
            }, 'MD5 check decision for AWS chunked MPU');
        }

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
            }, 'mako didnt receive what buckets-api sent');
            var m = new VError('buckets-api md5 %s and mako md5 ' +
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

    // Send 100-continue response immediately
    if (req.header('expect') === '100-continue') {
        res.writeContinue();
        log.debug({
            remoteAddress: req.connection._xff,
            remotePort: req.connection.remotePort,
            req_id: req.id,
            latency: (Date.now() - req.time()),
            'audit_100': true
        }, '100-continue sent early');
    }

    // Handle AWS chunked encoding
    var sourceStream = req;

    if (isAwsChunked && req.isS3Request) {
        awsDecoder = new AwsChunkedDecoder({
            log: req.log.child({component: 'aws-chunked-decoder'})
        });


        // Set up error handling for decoder
        awsDecoder.on('error', function (err) {
            req.log.error({
                error: err.message,
                isMultipartUpload: !!req._awsChunkedMPU
            }, 'AWS chunked decoder error');
            next_err(err);
        });


        // For multipart uploads, handle trailing checksums gracefully
        if (req._awsChunkedMPU || isAwsChunked && req.isS3Request) {
            awsDecoder.on('trailerHeaders', function (headers) {
                req.log.debug({
                    trailerHeaders: headers
                }, 'S3_MPU: Received AWS chunked trailer headers');

                // Store trailer checksums for validation if needed
                if (headers['x-amz-checksum-crc64nvme']) {
                    req._awsTrailerChecksum =
                        headers['x-amz-checksum-crc64nvme'];
                }
            });
        }

        // Connect the decoder chain: req -> awsDecoder -> check -> sharks
        req.pipe(awsDecoder);
        sourceStream = awsDecoder;

    }

    sourceStream.pipe(check);

    req.sharks.forEach(function (s) {
        var sharkId, sharkStream;

        if (typeof (s) === 'string') {
            // AWS chunked requests: s is just a shark ID string
            // This indicates startSharkStreams didn't run properly
            req.log.error({
                sharkId: s,
                awsChunked: req.header('content-encoding') === 'aws-chunked'
            }, 'CRITICAL: AWS chunked request has shark strings instead of ' +
                ' objects - startSharkStreams may not have run');

            // Fail the request rather than hanging indefinitely
            next(new Error('Shark streams not properly initialized' +
                           ' for AWS chunked request'));
            return;
        } else if (s && s._shark) {
            // Normal requests: s is a shark stream object
            sharkId = s._shark.manta_storage_id;
            sharkStream = s;
        } else {
            req.log.error({
                sharkType: typeof (s),
                hasShark: !!s,
                hasSharkProp: s && !!s._shark
            }, 'Invalid shark object format');
            return;
        }

        barrier.start(sharkId);
        sourceStream.pipe(sharkStream);

        sharkStream.once('response', function onSharkResult(sres) {
            log.debug({
                mako: sharkId,
                client_res: sres
            }, 'mako: response received');

            var sharkInfo = getSharkInfo(req, sharkId);
            sharkInfo.timeTotal = Date.now() - sharkInfo._startTime;
            sharkInfo.result = 'fail'; // most cases below here are failures

            sharkStream.md5 = sres.headers['x-joyent-computed-content-md5'] ||
                req._contentMD5;
            if (sres.statusCode === 469) {
                next_err(new ChecksumError(sharkStream.md5,
                                           req.headers['content-md5']));
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
                        mako: sharkId,
                        client_res: sres,
                        body: body
                    }, 'mako: response error');
                    var m = new VError('mako response error, storage id (%s)',
                        sharkId);
                    next_err(new InternalError(m));
                });
                sres.once('error', function (err) {
                    next_err(new InternalError(err));
                });
            } else {
                sharkInfo.result = 'ok';
                barrier.done(sharkId);
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

        // For AWS chunked MPU, preserve the decoded size we set earlier
        // Don't let CheckStream override with potentially incorrect size
        if (req._awsChunkedMPU && req._awsChunkedExpectedSize) {
            req.log.debug({
                checkStreamBytes: check.bytes,
                expectedDecodedSize: req._awsChunkedExpectedSize,
                preservingExpectedSize: true
            }, 'S3_MPU: Preserving expected decoded size' +
               ' for AWS chunked upload');
            req._size = req._awsChunkedExpectedSize;
        } else {
            req._size = check.bytes;
        }
        barrier.done('client');
    }

    // For AWS chunked uploads, we need to coordinate between decoder end
    // and CheckStream completion to ensure proper barrier timing
    if (isAwsChunked && req.isS3Request && awsDecoder) {
        var decoderEnded = false;
        var checkStreamDone = false;

        function maybeCallOnEnd() {
            if (decoderEnded && checkStreamDone) {
                onEnd();
            }
        }

        awsDecoder.once('end', function () {
            decoderEnded = true;
            maybeCallOnEnd();
        });

        // Override the existing check 'done' handler to coordinate
        check.removeAllListeners('done');
        check.once('done', function () {
            checkStreamDone = true;
            barrier.done('check_stream');
            maybeCallOnEnd();
        });
    } else {
        req.once('end', onEnd);
    }

    barrier.start('check_stream');
    if (!isAwsChunked || !req.isS3Request || !awsDecoder) {
        // Only set up default check 'done' handler for non-AWS chunked requests
        check.once('done', function () {
            barrier.done('check_stream');
        });
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

    log.debug({
        objectId: md.objectId,
        objectName: req.bucketObject.name,
        objectNameHash: req.bucketObject.name_hash,
        storageLayoutVersion: md.storageLayoutVersion,
        sharksAvailable: md.sharks ? md.sharks.length : 0,
        sharks: md.sharks ? md.sharks.map(function (s) {
            return (s.manta_storage_id);
        }) : [],
        hasRangeHeader: !!req.headers.range,
        rangeHeader: req.headers.range,
        userAgent: req.headers['user-agent'],
        contentLength: md.contentLength
    }, 'streamFromSharks: entered with metadata details');

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
        log.debug({
            hasRangeHeader: !!req.headers.range,
            rangeHeader: req.headers.range,
            userAgent: req.headers['user-agent'],
            objectId: md.objectId
        }, 'streamFromSharks: streaming data');

        // Check if headers have already been sent to prevent race condition
        if (res.headersSent) {
            log.debug('respond: headers already sent, aborting');
            return;
        }

        // Check if client connection is still open
        if (req.connection.destroyed || !req.connection.readable) {
            log.debug({
                connectionDestroyed: req.connection.destroyed,
                connectionReadable: req.connection.readable,
                userAgent: req.headers['user-agent']
            }, 'respond: client connection already closed, aborting');
            return;
        }

        // Response headers
        var sh = shark.headers;
        var isAwsCli = req.headers['user-agent'] &&
                      req.headers['user-agent'].indexOf('aws-cli') !== -1;

        if (req.headers['range'] !== undefined) {
            log.debug({
                requestedRange: req.headers.range,
                sharkResponse: {
                    statusCode: shark.statusCode,
                    contentType: sh['content-type'],
                    contentRange: sh['content-range'],
                    contentLength: sh['content-length'],
                    allHeaders: sh
                },
                isAwsCli: isAwsCli,
                objectId: md.objectId
            }, 'streamFromSharks:' +
               ' RANGE REQUEST DEBUG - shark response details');

            // Check if shark returned proper range response
            if (shark.statusCode !== 206) {
                log.warn({
                    requestedRange: req.headers.range,
                    sharkStatusCode: shark.statusCode,
                    expected: 206,
                    objectId: md.objectId
                }, 'streamFromSharks: WARNING' +
                   ' - shark did not return 206 for range request');
            }

            // Check if Content-Range header exists
            if (!sh['content-range']) {
                log.error({
                    requestedRange: req.headers.range,
                    sharkHeaders: sh,
                    objectId: md.objectId
                }, 'streamFromSharks: ERROR' +
                   ' - shark missing Content-Range header for range request');
            }

            res.header('Content-Type', sh['content-type']);
            res.header('Content-Range', sh['content-range']);
            res.header('Accept-Ranges', 'bytes');

            log.debug({
                rangeHeader: req.headers.range,
                contentRange: sh['content-range'],
                contentType: sh['content-type'],
                objectId: md.objectId
            }, 'streamFromSharks: range request headers set');
        } else {
            res.header('Accept-Ranges', 'bytes');
            res.header('Content-Type', md.contentType);
            res.header('Content-MD5', md.contentMD5);
        }

        res.header('Content-Disposition', req.metadata.contentDisposition);
        res.header('Durability-Level', req.metadata.sharks.length);

        // Set Content-Length for non-range requests
        if (!req.headers.range) {
            res.header('Content-Length', sh['content-length']);
        }

        if (req.headers.range) {
            // Remove any Transfer-Encoding header that might conflict
            res.removeHeader('Transfer-Encoding');

            // CRITICAL: Remove conflicting headers before setting correct ones
            res.removeHeader('Content-Length');
            res.removeHeader('Server');

            // Set correct headers for range response
            res.header('Content-Length', sh['content-length']); // range size
            res.header('Connection', 'keep-alive');
            res.header('Server', 'Manta/2'); // Single server header

            // Ensure proper S3-compatible headers
            res.header('x-amz-request-id', req.getId());

            // Set socket options to prevent premature disconnection
            try {
                if (req.connection.setTimeout) {
                    req.connection.setTimeout(0); // Disable timeout
                }
                if (req.connection.setKeepAlive) {
                    req.connection.setKeepAlive(true, 0);
                }
                if (req.connection.setNoDelay) {
                    req.connection.setNoDelay(true); // Disable Nagle algorithm
                }
            } catch (e) {
                log.debug(e,
                'streamFromSharks:' +
                ' Socket option setting failed (non-critical)');
            }

            log.debug({
                contentLength: sh['content-length'],
                contentRange: sh['content-range'],
                objectId: md.objectId,
                requestId: req.getId()
            }, 'streamFromSharks: range request' +
               ' - configured headers and socket');
        }

        req._size = sh['content-length'];

        // Response body
        req._totalBytes = 0;
        var check = new CheckStream({
            maxBytes: parseInt(sh['content-length'], 10) +
                constants.SIZE_LIMITS.BUFFER_OVERHEAD,
            timeout: DATA_TIMEOUT,
            counter: req.collector.getCollector(
                METRIC_OUTBOUND_DATA_COUNTER)
        });

        // Set up early error detection for disconnections
        log.debug({
            userAgent: req.headers['user-agent'],
            hasRangeHeader: !!req.headers.range,
            objectId: md.objectId
        }, 'streamFromSharks: ' +
                  ', enabling enhanced error handling');
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

            log.warn({
                err: err,
                userAgent: req.headers['user-agent'],
                hasRangeHeader: !!req.headers.range,
                objectId: md.objectId,
                streamingBytes: req._totalBytes || 0,
                expectedBytes: md.contentLength
            }, 'streamFromSharks: client closed connection during streaming');
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

        if (req.headers.range) {
            log.debug({
                sharkStatusCode: shark.statusCode,
                contentLength: sh['content-length'],
                rangeHeader: req.headers.range,
                objectId: md.objectId,
                allResponseHeaders: res._headers,
                responseHeaderNames: Object.keys(res._headers || {}),
                serverHeader: res._headers.server,
                contentLengthHeader: res._headers['content-length'],
                hasDuplicates: {
                    server: Array.isArray(res._headers.server),
                    contentLength: Array.isArray(res._headers['content-length'])
                }
            }, 'streamFromSharks:' +
                'range response - headers before writeHead');

            // Ensure proper HTTP/1.1 206 response
            res.statusCode = 206;
            res.writeHead(206);

            log.debug({
                statusCode: res.statusCode,
                headersSent: res.headersSent,
                objectId: md.objectId
            }, 'streamFromSharks: ' +
               'range response - status after writeHead');

            // Immediate validation - check if client is still connected after
            // writeHead
            if (req.connection.destroyed || !req.connection.writable) {
                log.error({
                    objectId: md.objectId,
                    rangeHeader: req.headers.range,
                    statusCode: res.statusCode
                }, 'streamFromSharks:' +
                   ' disconnected immediately after writeHead');
                return;
            }
        } else {
            res.writeHead(shark.statusCode);
        }

        log.debug({
            userAgent: req.headers['user-agent'],
            objectId: md.objectId,
            connectionWritable: req.connection.writable,
            connectionReadable: req.connection.readable
        }, 'streamFromSharks: Setting up stream monitoring');

        // Monitor connection state during streaming
        var connectionMonitor = setInterval(function () {
            if (req.connection.destroyed || !req.connection.writable) {
                log.warn({
                    userAgent: req.headers['user-agent'],
                    objectId: md.objectId,
                    bytesStreamed: req._totalBytes || 0
                }, 'streamFromSharks:' +
                         ' connection closed, aborting streams');

                clearInterval(connectionMonitor);
                try {
                    shark.unpipe(check);
                    shark.unpipe(res);
                    shark.destroy();
                    check.abandon();
                } catch (e) {
                    log.debug(e,
                              'streamFromSharks: Error during stream cleanup');
                }
                return;
            }
        }, 50); // Check every 50ms for faster response

        // Clean up monitor when check completes
        check.once('done', function () {
            clearInterval(connectionMonitor);
        });

        // Clean up monitor on errors
        check.once('error', function () {
            clearInterval(connectionMonitor);
        });

        if (req.headers.range) {
            // Add explicit error handling for range requests
            shark.on('error', function (err) {
                log.warn({
                    err: err,
                    objectId: md.objectId,
                    rangeHeader: req.headers.range
                }, 'streamFromSharks: ' +
                    'shark stream error during range request');
            });

            check.on('error', function (err) {
                log.warn({
                    err: err,
                    objectId: md.objectId,
                    bytesProcessed: check.bytes
                }, 'streamFromSharks:' +
                   ' check stream error during range request');
            });

            log.debug({
                objectId: md.objectId,
                rangeHeader: req.headers.range,
                expectedBytes: sh['content-length']
            }, 'streamFromSharks: Using controlled streaming');

            var totalSent = 0;
            var expectedBytes = parseInt(sh['content-length'], 10);

            shark.on('data', function (chunk) {
                totalSent += chunk.length;
                log.trace({
                    chunkSize: chunk.length,
                    totalSent: totalSent,
                    expectedBytes: expectedBytes,
                    objectId: md.objectId
                }, 'streamFromSharks: data chunk processed');
            });

            shark.on('end', function () {
                log.debug({
                    totalSent: totalSent,
                    expectedBytes: expectedBytes,
                    objectId: md.objectId
                }, 'streamFromSharks: stream ended');
            });
        }

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

                        // Calculate expected storage path for debugging
                        var expectedPath =
                            require('./shark_client').storagePath({
                            storageLayoutVersion: opts.storageLayoutVersion,
                            owner: opts.owner,
                            bucketId: opts.bucketId,
                            objectNameHash: opts.objectNameHash,
                            objectId: opts.objectId
                        });

                        log.warn({
                            err: err,
                            shark: s.toString(),
                            expectedStoragePath: expectedPath,
                            objectId: opts.objectId,
                            objectName: opts.objectName,
                            storageLayoutVersion: opts.storageLayoutVersion
                        }, 'mako: connection failed' +
                        ' - multipart object might not exist at expected path');
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

    if (sharks.length === 0) {
        req.log.warn({
            hostname: hostname,
            totalSharksContacted: req.sharksContacted.length
        }, 'getSharkInfo: No sharkInfo found for hostname');
        return (null);
    }

    if (sharks.length > 1) {
        req.log.debug({
            hostname: hostname,
            duplicateCount: sharks.length,
            sharkStates: sharks.map(function (s) { return s.result; })
        }, 'getSharkInfo: Multiple sharkInfo entries found, using first');
        // Return the first one, preferably one with a non-null result
        var withResult = sharks.find(function (s) { return s.result; });
        return (withResult || sharks[0]);
    }

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

    METRIC_INBOUND_DATA_COUNTER: METRIC_INBOUND_DATA_COUNTER,

    METRIC_OUTBOUND_DATA_COUNTER: METRIC_OUTBOUND_DATA_COUNTER,

    METRIC_DELETED_DATA_COUNTER: METRIC_DELETED_DATA_COUNTER,

    CURRENT_STORAGE_LAYOUT_VERSION: CURRENT_STORAGE_LAYOUT_VERSION,

    addCustomHeaders: addCustomHeaders,
    tryBucketLevelCors: tryBucketLevelCors,

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
