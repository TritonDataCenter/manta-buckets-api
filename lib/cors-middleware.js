/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/**
 * @file CORS (Cross-Origin Resource Sharing) middleware for manta-buckets-api
 * @brief Handles CORS preflight OPTIONS requests and applies CORS headers to
 * responses
 * @details This middleware provides comprehensive CORS support for web
 *          applications accessing S3-compatible resources. It supports both
 *          object-level CORS (via metadata headers) and bucket-level CORS
 *          (via AWS S3 compatible configuration).
 *          The middleware handles origin validation, method checking,
 *          and proper header reflection for browser security compliance.
 *
 * Key features:
 * - CORS preflight request handling (OPTIONS)
 * - Object-level CORS via metadata (m-access-control-* headers)
 * - Bucket-level CORS configuration support
 * - Origin validation and reflection
 * - Method and header validation
 * - Support for wildcard (*) and 'star' origin formats
 * - Presigned URL compatibility
 *
 */


var crypto = require('crypto');

/**
 * @brief Handle CORS OPTIONS preflight requests
 * @details This middleware responds to CORS preflight requests with appropriate
 *          headers based on object-level metadata or bucket-level CORS
 *          configuration.
 *          Only processes OPTIONS requests with Origin and
 *          Access-Control-Request-Method headers.
 *          Implements the CORS specification for browser security compliance.
 *
 * @param req {Object} HTTP request object containing headers and metadata
 * @param res {Object} HTTP response object for setting CORS headers
 * @param next {Function} Next middleware function in the chain
 *
 * @return {void}
 *
 * @note Checks object metadata first, then falls back to bucket CORS
 * configuration
 * @note Sends 200 response with CORS headers or 403 for policy violations
 * @see processCorsOptions, getCorsHeadersFromMetadata, getBucketCorsConfigAsync
 *
 * @example
 * // Browser sends preflight for cross-origin request:
 * // OPTIONS /bucket/object
 * // Origin: https://example.com
 * // Access-Control-Request-Method: GET
 */
function handleCorsOptions(req, res, next) {
    var log = req.log;
    log.debug({
        method: req.method,
        origin: req.headers.origin,
        requestMethod: req.headers['access-control-request-method'],
        requestHeaders: req.headers['access-control-request-headers'],
        url: req.url
    }, 'CORS: Handling OPTIONS preflight request');

    // Only process OPTIONS requests
    if (req.method !== 'OPTIONS') {
        next();
        return;
    }

    var origin = req.headers.origin;
    var requestMethod = req.headers['access-control-request-method'];
    var requestHeaders = req.headers['access-control-request-headers'];

    // Check if this is actually a CORS preflight request
    if (!origin || !requestMethod) {
        log.debug('CORS: Not a CORS preflight request' +
                  ' (missing Origin or Access-Control-Request-Method)');
        next();
        return;
    }

    // Try to get CORS configuration from object metadata first
    var corsHeaders = getCorsHeadersFromMetadata(req);

    if (corsHeaders) {
        // Process with object-level CORS
        processCorsOptions(req, res, next, corsHeaders, origin, requestMethod,
                           requestHeaders, log);
        return;
    }

    // Try bucket-level CORS configuration asynchronously
    getBucketCorsConfigAsync(req,
        function handleBucketCorsConfig(bucketCorsHeaders) {
        if (bucketCorsHeaders) {
            processCorsOptions(req, res, next, bucketCorsHeaders, origin,
                               requestMethod, requestHeaders, log);
        } else {
            // No CORS configuration found
            log.debug('CORS: No CORS configuration found' +
                      ' for preflight request');
            res.send(200, ''); // Send empty response for OPTIONS
            next(false);
        }
    });
}

/**
 * @brief Process CORS options with given headers and validate the request
 * @details Validates the origin and method against CORS configuration, then
 *          sets appropriate CORS response headers. Implements proper origin
 *          reflection and header validation according to CORS specification.
 *
 * @param req {Object} HTTP request object
 * @param res {Object} HTTP response object for setting headers
 * @param next {Function} Next middleware function
 * @param corsHeaders {Object} CORS configuration headers object
 * @param origin {string} Request origin header value
 * @param requestMethod {string} Requested HTTP method from
 * Access-Control-Request-Method
 * @param requestHeaders {string} Requested headers from
 * Access-Control-Request-Headers
 * @param log {Object} Logger instance for debugging
 *
 * @return {void} Calls next(false) to complete the request
 *
 * @throws {403} CORS policy violation for disallowed origins or methods
 *
 * @note Always reflects the origin in Access-Control-Allow-Origin for security
 * @note Allows requested headers if no specific headers are configured
 * @see isOriginAllowed, isMethodAllowed
 */
function processCorsOptions(req, res, next, corsHeaders, origin, requestMethod,
                            requestHeaders, log) {
    log.debug({
        corsHeaders: corsHeaders,
        origin: origin,
        requestMethod: requestMethod
    }, 'CORS: Processing preflight request with CORS configuration');

    // Validate origin
    if (!isOriginAllowed(origin, corsHeaders['access-control-allow-origin'])) {
        log.debug('CORS: Origin not allowed in CORS configuration');
        res.send(403, 'CORS policy violation: Origin not allowed');
        return (next(false));
    }

    // Validate method
    if (!isMethodAllowed(requestMethod,
                         corsHeaders['access-control-allow-methods'])) {
        log.debug('CORS: Method not allowed in CORS configuration');
        res.send(403, 'CORS policy violation: Method not allowed');
        return (next(false));
    }

    // Set CORS response headers for prefligh
    // Always reflect origin
    res.header('Access-Control-Allow-Origin', origin);

    if (corsHeaders['access-control-allow-methods']) {
        res.header('Access-Control-Allow-Methods',
                   corsHeaders['access-control-allow-methods']);
    }

    if (corsHeaders['access-control-allow-headers']) {
        res.header('Access-Control-Allow-Headers',
                   corsHeaders['access-control-allow-headers']);
    } else if (requestHeaders) {
        // If no specific headers configured, allow requested headers
        res.header('Access-Control-Allow-Headers', requestHeaders);
    }

    if (corsHeaders['access-control-max-age']) {
        res.header('Access-Control-Max-Age',
                   corsHeaders['access-control-max-age']);
    }

    if (corsHeaders['access-control-allow-credentials']) {
        res.header('Access-Control-Allow-Credentials',
                   corsHeaders['access-control-allow-credentials']);
    }

    log.debug({
        origin: origin,
        method: requestMethod,
        headers: requestHeaders
    }, 'CORS: Preflight request approved');

    res.send(200, '');
    return (next(false));
}

/**
 * @brief Asynchronously retrieve bucket-level CORS configuration
 * @details Loads CORS configuration from the special '.cors-configuration'
 *          object stored in the bucket. This configuration is set via AWS S3
 *          CORS API (PutBucketCors) and provides bucket-wide CORS rules.
 *
 * @param req {Object} HTTP request object containing bucket and owner
 *                     information
 * @param callback {Function} Callback function called with (corsHeaders) or
 *                            (null)
 *
 * @return {void} Calls callback asynchronously with result
 *
 * @callback callback
 * @param corsHeaders {Object|null} Converted CORS headers or null if not found
 *
 * @note Returns null if bucket has no CORS configuration
 * @note Configuration is stored as JSON in object metadata
 * @see convertBucketCorsToHeaders, storeCorsConfiguration
 *
 * @example
 * getBucketCorsConfigAsync(req, function(corsHeaders) {
 *   if (corsHeaders) {
 *     // Apply bucket CORS rules
 *   }
 * });
 */
function getBucketCorsConfigAsync(req, callback) {
    if (!req.bucket) {
        return (callback(null));
    }

    var log = req.log;
    var owner = req.owner.account.uuid;
    var requestId = req.getId();
    var corsObjectName = '.cors-configuration';

    try {
        var corsNameHash = crypto.createHash('md5').
            update(corsObjectName).digest('hex');
        var objectLocation = req.metadataPlacement.getObjectLocation(owner,
            req.bucket.id, corsNameHash);
        var objectClient = req.metadataPlacement.
            getBucketsMdapiClient(objectLocation);

        objectClient.getObject(owner, req.bucket.id, corsObjectName,
            objectLocation.vnode, {}, requestId,
            function handleGetCorsObject(getErr, corsObjectData) {

            if (getErr) {
                log.debug('CORS middleware: No bucket CORS config found');
                return (callback(null));
            }

            try {
                var corsData = corsObjectData.headers['cors-data'];
                var corsConfig = JSON.parse(corsData);

                log.debug({
                    corsRulesCount: corsConfig.CORSRules ?
                        corsConfig.CORSRules.length : 0
                }, 'CORS middleware: Found bucket CORS config');

                // Convert bucket CORS config to CORS headers format
                var corsHeaders = convertBucketCorsToHeaders(corsConfig, req);
                return (callback(corsHeaders));

            } catch (parseErr) {
                log.error({err: parseErr}, 'CORS middleware: Failed to' +
                          ' parse bucket CORS config');
                return (callback(null));
            }
        });

    } catch (err) {
        log.debug({err: err},
                  'CORS middleware: Failed to load bucket CORS config');
        return (callback(null));
    }
}

/**
 * @brief Convert bucket CORS configuration to middleware headers format
 * @details Transforms AWS S3 CORS configuration format to internal CORS headers
 *          format used by the middleware. Finds the first CORS rule that
 *          matches the request origin and converts it to headers.
 *
 * @param corsConfig {Object} AWS S3 CORS configuration with CORSRules array
 * @param req {Object} HTTP request object containing origin header
 *
 * @return {Object|null} CORS headers object or null if no matching rule
 *
 * @note Only returns the first matching CORS rule for the origin
 * @note Supports both exact origin matches and wildcard (*)
 * @see getBucketCorsConfigAsync, isOriginAllowed
 *
 * @example
 * // Input corsConfig:
 * {
 *   "CORSRules": [{
 *     "AllowedOrigins": ["https://example.com"],
 *     "AllowedMethods": ["GET", "PUT"]
 *   }]
 * }
 *
 * // Output headers:
 * {
 *   "access-control-allow-origin": "https://example.com",
 *   "access-control-allow-methods": "GET, PUT"
 * }
 */
function convertBucketCorsToHeaders(corsConfig, req) {
    if (!corsConfig.CORSRules || corsConfig.CORSRules.length === 0) {
        return (null);
    }

    var origin = req.headers.origin;
    var corsHeaders = {};

    // Find the first matching CORS rule for the origin
    for (var i = 0; i < corsConfig.CORSRules.length; i++) {
        var rule = corsConfig.CORSRules[i];

        if (!rule.AllowedOrigins) continue;

        var originMatches = false;
        for (var j = 0; j < rule.AllowedOrigins.length; j++) {
            var allowedOrigin = rule.AllowedOrigins[j];
            if (allowedOrigin === '*' || allowedOrigin === origin) {
                originMatches = true;
                break;
            }
        }

        if (originMatches) {
            // Convert rule to CORS headers format
            if (rule.AllowedOrigins) {
                corsHeaders['access-control-allow-origin'] =
                    rule.AllowedOrigins.join(', ');
            }
            if (rule.AllowedMethods) {
                corsHeaders['access-control-allow-methods'] =
                    rule.AllowedMethods.join(', ');
            }
            if (rule.AllowedHeaders) {
                corsHeaders['access-control-allow-headers'] =
                    rule.AllowedHeaders.join(', ');
            }
            if (rule.ExposeHeaders) {
                corsHeaders['access-control-expose-headers'] =
                    rule.ExposeHeaders.join(', ');
            }
            if (rule.MaxAgeSeconds) {
                corsHeaders['access-control-max-age'] =
                    rule.MaxAgeSeconds.toString();
            }

            return (corsHeaders);
        }
    }

    return (null);
}

/**
 * @brief Extract CORS headers from object metadata
 * @details Scans object metadata for CORS-related headers with 'm-' prefix
 *          and converts them to standard CORS header format. This enables
 *          object-level CORS configuration via metadata.
 *
 * @param req {Object} HTTP request object containing metadata
 * @param req.metadata.headers {Object} Object metadata headers
 *
 * @return {Object|null} CORS headers object or null if none found
 *
 * @note Removes 'm-' prefix from metadata header names
 * @note Only returns headers starting with 'access-control-'
 * @see handleCorsOptions, processCorsHeaders
 *
 * @example
 * // Object uploaded with metadata:
 * // m-access-control-allow-origin: https://example.com
 * // m-access-control-allow-methods: GET,PUT
 *
 * // Returns:
 * {
 *   "access-control-allow-origin": "https://example.com",
 *   "access-control-allow-methods": "GET,PUT"
 * }
 */
function getCorsHeadersFromMetadata(req) {
    if (!req.metadata || !req.metadata.headers) {
        return (null);
    }

    var md = req.metadata.headers;
    var corsHeaders = {};
    var foundCors = false;

    // Check for CORS headers in metadata (with m- prefix)
    Object.keys(md).forEach(function extractCorsHeader(k) {
        var headerName = k;
        if (k.startsWith('m-')) {
            headerName = k.substring(2); // Remove 'm-' prefix
        }

        if (headerName.toLowerCase().startsWith('access-control-')) {
            corsHeaders[headerName.toLowerCase()] = md[k];
            foundCors = true;
        }
    });

    return (foundCors ? corsHeaders : null);
}


/**
 * @brief Check if request origin is allowed by CORS policy
 * @details Validates the request origin against the list of allowed origins
 *          from CORS configuration. Supports exact matches, wildcard (*),
 *          and custom 'star' format for compatibility.
 *
 * @param origin {string} Request origin header value (e.g.,
 *                        "https://example.com")
 * @param allowedOrigins {string} Comma-separated list of allowed origins
 *
 * @return {boolean} True if origin is allowed, false otherwise
 *
 * @note Supports both '*' and 'star' as wildcard values for backward
 *       compatibility
 * @note Origins are compared as exact strings (case-sensitive)
 * @see processCorsOptions, convertBucketCorsToHeaders
 *
 * @example
 * isOriginAllowed("https://example.com",
 *                 "https://example.com,https://test.com") // true
 * isOriginAllowed("https://evil.com", "https://example.com") // false
 * isOriginAllowed("https://any.com", "*") // true
 * isOriginAllowed("https://any.com", "star") // true
 */
function isOriginAllowed(origin, allowedOrigins) {
    if (!allowedOrigins || !origin) {
        return (false);
    }

    //JSSTYLED
    var origins = allowedOrigins.split(/\s*,\s*/);
    for (var i = 0; i < origins.length; i++) {
        var allowed = origins[i];
        if (allowed === '*' || allowed === 'star' || allowed === origin) {
            return (true);
        }
    }

    return (false);
}

/**
 * @brief Check if HTTP method is allowed by CORS policy
 * @details Validates the requested HTTP method against the list of allowed
 *          methods  from CORS configuration. Handles both comma and dash
 *          separators for compatibility with different metadata encoding
 *          schemes.
 *
 * @param method {string} HTTP method name (e.g., "GET", "POST", "PUT")
 * @param allowedMethods {string} Comma or dash-separated list of allowed
 *                                methods
 *
 * @return {boolean} True if method is allowed, false otherwise
 *
 * @note Supports wildcard (*) to allow all methods
 * @note Handles both "GET,POST" and "GET-POST" separator formats
 * @see processCorsOptions, processCorsHeaders
 *
 * @example
 * isMethodAllowed("GET", "GET,POST,PUT") // true
 * isMethodAllowed("DELETE", "GET,POST") // false
 * isMethodAllowed("PUT", "GET-POST-PUT") // true (dash separator)
 * isMethodAllowed("PATCH", "*") // true (wildcard)
 */
function isMethodAllowed(method, allowedMethods) {
    if (!allowedMethods || !method) {
        return (false);
    }

    // Handle both comma and dash separators (from metadata encoding)
    var methodSeparator;
    if (allowedMethods.includes(',')) {
    //JSSTYLED
        methodSeparator = /\s*,\s*/;
    } else {
    //JSSTYLED
        methodSeparator = /\s*-\s*/;
    }
    var methods = allowedMethods.split(methodSeparator);

    for (var i = 0; i < methods.length; i++) {
        if (methods[i] === method || methods[i] === '*') {
            return (true);
        }
    }

    return (false);
}

/**
 * @brief Process CORS headers for actual requests (non-preflight)
 * @details Applies CORS headers to actual HTTP requests (GET, POST, PUT, etc.)
 *          after validating origin and method permissions. Called from
 *          common.js addCustomHeaders function during response processing.
 *
 * @param req {Object} HTTP request object
 * @param res {Object} HTTP response object for setting headers
 * @param corsHeaders {Object} CORS configuration headers
 * @param origin {string} Request origin header value
 *
 * @return {void}
 *
 * @note Always reflects the origin for security (never returns wildcard)
 * @note Converts dash-separated methods back to comma format for proper CORS
 * headers
 * @note Silently returns if origin or method is not allowed
 * @see isOriginAllowed, isMethodAllowed, addCustomHeaders
 *
 * @example
 * // Called for actual requests like:
 * // GET /bucket/object
 * // Origin: https://example.com
 * // (Sets Access-Control-Allow-Origin: https://example.com)
 */
function processCorsHeaders(req, res, corsHeaders, origin) {
    var log = req.log;

    if (!origin || !corsHeaders) {
        return;
    }

    log.debug({
        corsHeaders: corsHeaders,
        origin: origin,
        method: req.method
    }, 'CORS: Processing CORS headers for actual request');

    // Validate origin
    if (!isOriginAllowed(origin, corsHeaders['access-control-allow-origin'])) {
        log.debug('CORS: Origin not allowed for actual request');
        return;
    }

    // Validate method
    if (!isMethodAllowed(req.method,
                         corsHeaders['access-control-allow-methods'])) {
        log.debug('CORS: Method not allowed for actual request');
        return;
    }

    // Set CORS response headers
    res.header('Access-Control-Allow-Origin', origin); // Always reflect origin

    if (corsHeaders['access-control-allow-methods']) {
        var methods = corsHeaders['access-control-allow-methods'];
        // Convert dashes back to commas for proper CORS header format
        if (!methods.includes(',') && methods.includes('-')) {
            methods = methods.replace(/-/g, ', ');
        }
        res.header('Access-Control-Allow-Methods', methods);
    }

    if (corsHeaders['access-control-expose-headers']) {
        res.header('Access-Control-Expose-Headers',
                   corsHeaders['access-control-expose-headers']);
    }

    if (corsHeaders['access-control-allow-credentials']) {
        res.header('Access-Control-Allow-Credentials',
                   corsHeaders['access-control-allow-credentials']);
    }

    if (corsHeaders['access-control-max-age']) {
        res.header('Access-Control-Max-Age',
                   corsHeaders['access-control-max-age']);
    }

    log.debug({
        origin: origin,
        method: req.method
    }, 'CORS: CORS headers applied to actual request');
}

module.exports = {
    handleCorsOptions: handleCorsOptions,
    processCorsHeaders: processCorsHeaders,
    isOriginAllowed: isOriginAllowed,
    isMethodAllowed: isMethodAllowed
};
