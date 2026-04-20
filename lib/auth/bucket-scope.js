/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Per-bucket access key scope enforcement middleware.
 *
 * When an access key carries an `accesskeyscope` attribute,
 * this middleware restricts the request to the buckets and
 * permission levels specified in the scope. Keys without
 * scope are unrestricted (backward compatible).
 *
 * Enforcement point: runs after gatherContext (which sets
 * req.caller) and before route handlers (which call
 * authorize()).
 *
 * Time complexity:  O(n) where n = scope permissions count
 * Space complexity: O(1) beyond the parsed scope object
 *
 * Invariants:
 *   - null/undefined scope = unrestricted (next())
 *   - malformed scope JSON = deny (fail closed, NFR-10)
 *   - permission hierarchy: full > readwrite > read
 *   - max 1000 scope entries (validated at UFDS layer)
 */

var assert = require('assert-plus');

var errors = require('../errors');
var AccessDeniedByKeyScopeError = errors.AccessDeniedByKeyScopeError;

/*
 * Permission level numeric values for comparison.
 * Higher value = more permissive.
 */
var LEVEL_READ = 1;
var LEVEL_READWRITE = 2;
var LEVEL_FULL = 3;

var LEVEL_MAP = {
    read: LEVEL_READ,
    readwrite: LEVEL_READWRITE,
    full: LEVEL_FULL
};

/**
 * @brief Map HTTP method to required permission level
 *
 * Uses req.method and path structure to determine
 * the required permission level. This runs before
 * route handlers override authContext.action, so we
 * derive the level from HTTP method semantics.
 *
 * @param {string} method - HTTP method (GET, PUT, etc.)
 * @param {boolean} isBucketLevel - true if path has
 *   no object key (single-segment path or root)
 * @return {number} Required permission level constant
 */
function requiredLevel(method, isBucketLevel) {
    if (isBucketLevel) {
        /*
         * Bucket-level operations:
         *   GET/HEAD = list/check bucket (read)
         *   PUT = create bucket (full)
         *   DELETE = delete bucket (full)
         */
        switch (method) {
            case 'GET':
            case 'HEAD':
            case 'OPTIONS':
                return (LEVEL_READ);
            case 'POST':
                /* POST at bucket level = bulk delete (?delete) */
                return (LEVEL_READWRITE);
            default:
                return (LEVEL_FULL);
        }
    }

    /*
     * Object-level operations:
     *   GET/HEAD = read object (read)
     *   PUT/POST = write object (readwrite)
     *   DELETE = delete object (readwrite)
     */
    switch (method) {
        case 'GET':
        case 'HEAD':
        case 'OPTIONS':
            return (LEVEL_READ);
        default:
            return (LEVEL_READWRITE);
    }
}

/**
 * @brief Match a bucket name against a scope pattern
 *
 * Supports exact match and trailing wildcard (e.g.
 * 'logs-*' matches 'logs-2026', 'logs-jan').
 *
 * @param {string} pattern - Scope bucket pattern
 * @param {string} name - Actual bucket name
 * @return {boolean} true if pattern matches name
 */
function matchBucketPattern(pattern, name) {
    if (pattern === '*') {
        return (true);
    }
    if (pattern.charAt(pattern.length - 1) === '*') {
        var prefix = pattern.substring(0, pattern.length - 1);
        return (name.indexOf(prefix) === 0);
    }
    return (pattern === name);
}

/*
 * @brief Parse and validate bucket scope JSON
 * We don't validate the actual permission array
 * just that this payload has the expected schema.
 *
 * Returns null on invalid input (fail closed).
 *
 * @param {string} raw - JSON scope string
 * @return {Object|null} Parsed scope or null
 */
function parseScope(raw) {
    var scope;
    try {
        scope = JSON.parse(raw);
    } catch (e) {
        return (null);
    }

    if (!scope || scope.version !== 1 || !Array.isArray(scope.permissions)) {
        return (null);
    }

    return (scope);
}

/**
 * @brief Check if scope grants access to a bucket at
 *   the required permission level
 *
 * Scans the permissions array for a matching bucket
 * pattern with sufficient permission level.
 *
 * @param {Array} permissions - Scope permissions array
 * @param {string} bucket - Target bucket name
 * @param {number} needed - Required LEVEL_* constant
 * @return {boolean} true if access is granted
 */
function scopeGrantsAccess(permissions, bucket, needed) {
    for (var i = 0; i < permissions.length; i++) {
        var perm = permissions[i];
        var granted = LEVEL_MAP[perm.level] || 0;
        if (granted >= needed && matchBucketPattern(perm.bucket, bucket)) {
            return (true);
        }
    }
    return (false);
}

/**
 * @brief Extract bucket name from the request path
 *
 * S3 paths are /{bucket} or /{bucket}/{key...}. This
 * returns the first path segment, or null for root (/).
 *
 * @param {Object} req - Restify request object
 * @return {string|null} Bucket name or null for root
 */
function extractBucket(req) {
    /*
     * req.params[0] is set by s3-routing.js for regex
     * routes. Fall back to parsing the path directly.
     */
    if (req.params && req.params[0]) {
        return (req.params[0]);
    }
    if (req.params && req.params.bucket) {
        return (req.params.bucket);
    }

    /* Parse from URL path as last resort */
    var path = req.path();
    if (!path || path === '/') {
        return (null);
    }
    var segments = path.split('/');
    /* segments[0] is empty string before leading / */
    return (segments[1] || null);
}

/**
 * @brief Collect list of bucket names allowed by scope
 *
 * Used for ListBuckets filtering. Returns an array of
 * all bucket patterns in the scope, plus a flag for
 * whether any pattern uses wildcards.
 *
 * @param {Array} permissions - Scope permissions array
 * @return {Array} Array of bucket name patterns
 */
function allowedBucketPatterns(permissions) {
    var patterns = [];
    for (var i = 0; i < permissions.length; i++) {
        patterns.push(permissions[i].bucket);
    }
    return (patterns);
}

/**
 * @brief Enforce per-bucket access key scope
 *
 * Restify middleware function. Checks req.caller
 * .bucketScope and denies requests that fall outside
 * the scope.
 *
 * @param {Object} req - Restify request
 * @param {Object} res - Restify response
 * @param {Function} next - Next middleware
 */
function enforceBucketScope(req, res, next) {
    /*
     * No scope = unrestricted key (backward compat).
     * Also skip for non-S3 requests and anonymous access.
     */
    if (!req.caller || !req.caller.bucketScope) {
        /*
         * Fail-open detection: if this is a temporary credential
         * with an assumed role but no bucket scope, the scope was
         * likely lost in transit.  Log a warning so operators can
         * spot the gap.
         */
        if (req.auth && req.auth.isTemporaryCredential &&
            req.auth.assumedRole) {
            req.log.warn({
                accessKeyId: req.auth.accessKeyId,
                assumedRole: typeof (req.auth.assumedRole) === 'string' ?
                    req.auth.assumedRole :
                    (req.auth.assumedRole.arn || true)
            }, 'enforceBucketScope: assumed-role temp credential ' +
                'has no bucketScope — scope enforcement skipped');
        }
        next();
        return;
    }

    var scope = parseScope(req.caller.bucketScope);
    /* Cache parsed scope for downstream handlers (copy checks) */
    req._parsedBucketScope = scope;
    if (scope === null) {
        /*
         * Malformed scope JSON: fail closed.
         * This should not happen if UFDS validation is
         * working, but defense-in-depth.
         */
        req.log.error({
            bucketScope: req.caller.bucketScope
        }, 'Malformed bucket scope JSON — denying ' +
            'request (fail closed)');
        // We just return unknown here to avoid leakage of information
        next(new AccessDeniedByKeyScopeError('(unknown)', req.method));
        return;
    }

    var bucket = extractBucket(req);

    /*
     * Root-level request (ListBuckets): allow but set
     * filter for downstream handler to apply.
     */
    if (bucket === null) {
        req._bucketScopeFilter = allowedBucketPatterns(scope.permissions);
        next();
        return;
    }

    /*
     * Determine if this is a bucket-level or
     * object-level operation based on path depth.
     */
    var path = req.path();
    var segments = path.split('/').filter(function (s) {
        return (s.length > 0);
    });
    var isBucketLevel = segments.length <= 1;

    var needed = requiredLevel(req.method, isBucketLevel);

    if (!scopeGrantsAccess(scope.permissions, bucket, needed)) {
        req.log.info({
            accessKeyId: req.auth ? req.auth.accessKeyId : '(unknown)',
            bucket: bucket,
            method: req.method,
            neededLevel: needed
        }, 'Request denied by bucket scope');
        next(new AccessDeniedByKeyScopeError(bucket, req.method));
        return;
    }

    /*
     * Access granted. Also set the scope filter so
     * ListBuckets can filter if this request happens
     * to hit a multi-bucket listing.
     */
    req._bucketScopeFilter = allowedBucketPatterns(scope.permissions);
    next();
}

module.exports = {
    enforceBucketScope: enforceBucketScope,
    matchBucketPattern: matchBucketPattern,
    parseScope: parseScope,
    scopeGrantsAccess: scopeGrantsAccess,
    extractBucket: extractBucket,
    requiredLevel: requiredLevel,
    LEVEL_READ: LEVEL_READ,
    LEVEL_READWRITE: LEVEL_READWRITE,
    LEVEL_FULL: LEVEL_FULL
};
