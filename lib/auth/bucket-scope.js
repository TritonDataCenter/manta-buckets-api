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
var scopeSchema = require('mahi').scopeSchema;

/*
 * Import constants and functions from the canonical
 * scope schema module (shared with sdc-cloudapi,
 * mahi, and sdc-ufds).
 */
var LEVEL_READ = scopeSchema.LEVEL_READ;
var LEVEL_READWRITE = scopeSchema.LEVEL_READWRITE;
var LEVEL_FULL = scopeSchema.LEVEL_FULL;
var LEVEL_MAP = scopeSchema.LEVEL_MAP;
var matchBucketPattern = scopeSchema.matchBucketPattern;
var parseScope = scopeSchema.parseScope;

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
    assert.string(method, 'method');
    assert.bool(isBucketLevel, 'isBucketLevel');
    if (isBucketLevel) {
        /*
         * Bucket-level operations:
         *   GET/HEAD = list/check bucket (read)
         *   POST = bulk delete (readwrite)
         *   PUT = create bucket (full)
         *   DELETE = delete bucket (full)
         */
        switch (method) {
            case 'GET':
            case 'HEAD':
            case 'OPTIONS':
               return (LEVEL_READ);
            case 'POST':
               return (LEVEL_READWRITE);
            case 'PUT':
            case 'DELETE':
               return (LEVEL_FULL);
            default:
                throw new Error('requiredLevel: unknown ' +
                    'method ' + method);
        }
    }

    /*
     * Object-level operations:
     *   GET/HEAD = read object (read)
     *   PUT/POST/DELETE = write/delete object (readwrite)
     */
    switch (method) {
        case 'GET':
        case 'HEAD':
        case 'OPTIONS':
            return (LEVEL_READ);
        case 'PUT':
        case 'POST':
        case 'DELETE':
            return (LEVEL_READWRITE);
        default:
            throw new Error('requiredLevel: unknown ' +
                'method ' + method);
    }
}

/**
 * @brief Map numeric level to human-readable name
 *
 * @param {number} level - LEVEL_* constant
 * @return {string} Level name or 'unknown'
 */
function levelName(level) {
    switch (level) {
        case LEVEL_READ:
            return ('read');
        case LEVEL_READWRITE:
            return ('readwrite');
        case LEVEL_FULL:
            return ('full');
        default:
            return ('unknown');
    }
}

/**
 * @brief Find highest granted level for a bucket
 *
 * Scans scope permissions and returns the highest
 * level matching the given bucket, or 0 if none.
 *
 * @param {Array} permissions - Scope permissions
 * @param {string} bucket - Target bucket name
 * @return {number} Highest granted LEVEL_* or 0
 */
function highestGrantedLevel(permissions, bucket) {
    var highest = 0;
    for (var i = 0; i < permissions.length; i++) {
        var perm = permissions[i];
        if (!matchBucketPattern(perm.bucket, bucket)) {
            continue;
        }
        highest = Math.max(highest, LEVEL_MAP[perm.level] || 0);
        if (highest === LEVEL_FULL) {
            break;
        }
    }
    return (highest);
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
 * Used for ListBuckets filtering. Returns an array of all bucket patterns in
 * the scope whether any pattern uses wildcards.
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
 * On success, sets req.scopeContext:
 *   {
 *     scope:    {Object} parsed scope (version,
 *                        permissions)
 *     patterns: {Array}  bucket name patterns from
 *                        scope permissions
 *   }
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
         * No scope on caller — permanent unscoped key,
         * non-S3 request, or anonymous access, don't
         * need bucket scope validation.
         */
        next();
        return;
    }

    /*
     * STS temporary credentials from unscoped parent keys
     * carry the sentinel "none" instead of a scope JSON
     * string.  This distinguishes "parent was explicitly
     * unscoped" (allow) from "scope was lost in transit"
     * (deny via parseScope returning null below).
     *
     * This check MUST precede the parseScope call because
     * parseScope("none") returns null (not valid JSON),
     * which would incorrectly trigger a fail-closed deny.
     */
    if (req.caller.bucketScope === 'none') {
        next();
        return;
    }

    /*
     * Use scope pre-parsed in loadCaller() to avoid
     * repeated JSON.parse on the same request.
     * parsedBucketScope is always set when bucketScope
     * is set (see credential-provider.js loadCaller).
     */
    var scope = req.caller.parsedBucketScope !== undefined
        ? req.caller.parsedBucketScope
        : parseScope(req.caller.bucketScope);

    if (scope === null) {
        /*
         * Malformed scope JSON: fail closed.
         * This should not happen if UFDS validation is
         * working, but defense-in-depth.
         */
        req.log.error(
            {
                audit: true,
                decision: 'deny',
                reason: 'malformed_scope',
                accessKeyId: req.auth ? req.auth.accessKeyId : '(unknown)',
                bucketScope: req.caller.bucketScope,
                caller: req.caller ? req.caller.uuid : '(unknown)'
            },
            'enforceBucketScope: DENY — ' +
                'malformed bucket scope JSON (fail closed)');
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
        req.scopeContext = {
            scope: scope,
            patterns: allowedBucketPatterns(scope.permissions)
        };
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
        var granted = highestGrantedLevel(scope.permissions, bucket);
        req.log.warn(
            {
                audit: true,
                decision: 'deny',
                accessKeyId: req.auth ? req.auth.accessKeyId : '(unknown)',
                bucket: bucket,
                method: req.method,
                path: req.path(),
                requiredLevel: levelName(needed),
                grantedLevel: levelName(granted),
                scopeVersion: scope.version,
                scopeEntryCount: scope.permissions.length,
                caller: req.caller ? req.caller.uuid : '(unknown)'
            },
            'enforceBucketScope: DENY — ' + 'insufficient scope permission');
        next(new AccessDeniedByKeyScopeError(bucket, req.method));
        return;
    }

    /*
     * Access granted.  Expose parsed scope and bucket
     * patterns for downstream handlers (ListBuckets
     * filtering, CopyObject source-bucket checks).
     * As those handlers need to filter which buckets are
     * allow to be seen by this request.
     */
    req.scopeContext = {
        scope: scope,
        patterns: allowedBucketPatterns(scope.permissions)
    };
    next();
}

/**
 * @brief Enforce scope on a copy-source bucket
 *
 * Used by CopyObject and UploadPartCopy to check that
 * the source bucket (from x-amz-copy-source header) is
 * permitted at LEVEL_READ.  The destination bucket is
 * already checked by the enforceBucketScope middleware.
 *
 * @param {Object} req - Restify request (must have
 *   req.scopeContext set by enforceBucketScope)
 * @param {string} sourceBucket - Source bucket name
 * @param {Function} next - Restify next callback
 * @return {boolean} true if denied (caller should
 *   return), false if allowed (caller continues)
 */
function enforceCopySourceScope(req, sourceBucket, next) {
    if (req.scopeContext && req.scopeContext.scope) {
        if (!scopeGrantsAccess(
                req.scopeContext.scope.permissions,
                sourceBucket, LEVEL_READ)) {
            next(new AccessDeniedByKeyScopeError(
                sourceBucket, req.method));
            return (true);
        }
    }
    return (false);
}

module.exports = {
    enforceBucketScope: enforceBucketScope,
    enforceCopySourceScope: enforceCopySourceScope,
    matchBucketPattern: matchBucketPattern,
    parseScope: parseScope,
    scopeGrantsAccess: scopeGrantsAccess,
    extractBucket: extractBucket,
    requiredLevel: requiredLevel,
    levelName: levelName,
    highestGrantedLevel: highestGrantedLevel,
    LEVEL_READ: LEVEL_READ,
    LEVEL_READWRITE: LEVEL_READWRITE,
    LEVEL_FULL: LEVEL_FULL
};
