/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


/* Copyright 2025 Edgecast Cloud LLC.  */

/*
 * File:     anonymous-auth.js
 * Purpose:  Anonymous access support for public buckets
 *
 * Description:
 * This file implements support for anonymous access to buckets (which means all
 * objects in a bucket) or just specific objects in a bucket.
 *
 *
 * Notes:
 * By default all buckets are private, which means only the owner is able to
 * execute operations on it's objects. Following the traditional manta approach
 * if a user creates a bucket named 'public', then anonymous users could read
 * all the objects from this bucket.
 * Now users could provide access to anonymous users to specific objects in
 * a bucket without requiring to give access to the full bucket, this is accomp-
 * lished by using canned ACLs which for manta-buckets-api are just manta
 * policies and roles. Today we only create the public-read role/policy so
 * that manta policy is applied to an object through a canned ACL, which is app-
 * lied for example using s3cmd:
 *
 *   s3cmd setacl --acl-public  s3://mybucket/myobject
 *
 * anonymous access currently is configured by the ANONYMOUS_ACCESS_CONFIG
 * object, by default is enabled.
 *
 */


var assert = require('assert-plus');
var AuthorizationError = require('./errors').AuthorizationError;

///--- Constants

// System roles that are predefined in Manta and stored as literal strings
// rather than UUIDs. These must be created in Manta CLOUDAPI first.
// Currently only 'public-read' is actively used.
var SYSTEM_ROLES = Object.freeze([
    'public-read',
    'public-writer',
    'authenticated-reader',
    'owner-reader',
    'owner-full-control',
    'log-writer'
]);

///--- Configuration

var ANONYMOUS_ACCESS_CONFIG = {
    enabled: process.env.MANTA_ANONYMOUS_ACCESS_ENABLED !== 'false',
    auditAll: process.env.MANTA_ANONYMOUS_AUDIT_ALL === 'true' || false
};

// Production safety check
if (ANONYMOUS_ACCESS_CONFIG.enabled) {
    console.log('MANTA ANONYMOUS ACCESS ENABLED - Configuration:',
                JSON.stringify(ANONYMOUS_ACCESS_CONFIG, null, 2));
}

///--- Globals

var ANONYMOUS_USER = Object.freeze({
    account: Object.freeze({
        uuid: 'anonymous',
        login: 'anonymous',
        isAdmin: false
    }),
    user: Object.freeze({
        uuid: 'anonymous',
        login: 'anonymous'
    }),
    roles: Object.freeze(['public-read']), // Anonymous users have public-read
    // NOTE: Do NOT set anonymous: true here, as that triggers old
    // Manta anonymous logic
    publicReader: true // Use a different flag to identify public reader access
});

///--- Helper Functions

/**
 * Validate account name format for security
 *
 * Account names extracted from URL paths must be validated to prevent
 * security vulnerabilities such as path traversal, injection attacks,
 * and authorization bypass.
 *
 * Supports multiple account name formats:
 * - Human-readable: testuser, my-account, user_123
 * - UUIDs: 550e8400-e29b-41d4-a716-446655440000
 * - Mixed: user-123_prod.test
 *
 * @param {string} accountName - The account name to validate
 * @returns {boolean} - True if valid format, false otherwise
 *
 * Validation rules:
 * - Length: 1-64 characters (UUIDs are 36 chars)
 * - Characters: alphanumeric (a-z, A-Z, 0-9), hyphens, underscores,
 *   periods
 * - Must start and end with alphanumeric character
 * - Cannot contain path traversal patterns (.., /, \)
 * - Must be a non-empty string
 *
 * Security invariant: All account names used in security contexts
 * MUST pass this validation.
 */
function isValidAccountName(accountName) {
    // Type and existence check
    if (!accountName || typeof (accountName) !== 'string') {
        return (false);
    }

    // Length check: reasonable limits to prevent abuse
    // UUIDs are 36 characters, allow up to 64 for flexibility
    if (accountName.length < 1 || accountName.length > 64) {
        return (false);
    }

    // Reject path traversal patterns explicitly
    if (accountName.indexOf('..') !== -1 ||
        accountName.indexOf('/') !== -1 ||
        accountName.indexOf('\\') !== -1) {
        return (false);
    }

    // Pattern check: alphanumeric start/end, allow hyphens/underscores/
    // periods in middle
    // This pattern matches human-readable names AND UUIDs
    // For single character names, only alphanumeric allowed
    if (accountName.length === 1) {
        return (/^[a-zA-Z0-9]$/.test(accountName));
    }

    // Multi-character names: must start and end with alphanumeric
    var validPattern = /^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$/;
    return (validPattern.test(accountName));
}

/**
 * Check if a request is for a public resource
 * This requires a bucket metadata lookup to check roles
 */
function isPublicResourceRequest(req, callback) {
    assert.object(req, 'req');
    assert.func(callback, 'callback');

    // Only allow GET/HEAD/OPTIONS operations for anonymous access
    if (req.method !== 'GET' && req.method !== 'HEAD' &&
        req.method !== 'OPTIONS') {
        callback(null, false);
        return;
    }

    // Extract bucket name from request
    var bucketName = extractBucketName(req);
    if (!bucketName) {
        callback(null, false);
        return;
    }

    // Look up bucket metadata to check if it has public-read role
    lookupBucketRoles(req, bucketName,
        function handleBucketRolesLookup(err, roles) {
        if (err) {
            req.log.debug(err,
                          'Error looking up bucket roles for anonymous access');
            callback(null, false);
            return;
        }

        var isPublic = roles && roles.includes('public-read');
        req.log.debug({
            bucket: bucketName,
            roles: roles,
            isPublic: isPublic
        }, 'Checked bucket public access');

        callback(null, isPublic);
    });
}

/**
 * Extract bucket name from request path
 */
function extractBucketName(req) {
    // Handle both Manta and S3 style paths
    if (req.params && req.params.bucket_name) {
        return (req.params.bucket_name);
    }

    if (req.params && req.params.bucket) {
        return (req.params.bucket);
    }

    // Parse from path for early requests
    var path = req.path();
    var pathParts = path.split('/').filter(function isNonEmptyPart(part) {
        return (part.length > 0);
    });

    req.log.debug({
        path: path,
        pathParts: pathParts
    }, 'extractBucketName: parsing path');

    // Manta style: /user/buckets/bucket or /user/buckets/bucket/objects/...
    if (pathParts.length >= 3 && pathParts[1] === 'buckets') {
        req.log.debug({
            bucketName: pathParts[2]
        }, 'extractBucketName: found Manta-style bucket');
        return (pathParts[2]);
    }

    // S3 style: /bucket or /bucket/object (only if not a Manta path)
    if (pathParts.length >= 1 && !pathParts[0].includes('@') &&
        pathParts[1] !== 'buckets') {
        req.log.debug({
            bucketName: pathParts[0]
        }, 'extractBucketName: found S3-style bucket');
        return (pathParts[0]);
    }

    req.log.debug('extractBucketName: no bucket found');
    return (null);
}

/**
 * Look up bucket roles from metadata using the same client as buckets-api
 */
function lookupBucketRoles(req, bucketName, callback) {
    assert.object(req, 'req');
    assert.string(bucketName, 'bucketName');
    assert.func(callback, 'callback');

    req.log.debug({
        bucket: bucketName
    }, 'Looking up bucket roles for anonymous access');

    // Check if bucket metadata is already available from previous auth/routing
    if (req.bucket && req.bucket.roles !== undefined) {
        req.log.debug({
            bucket: bucketName,
            roles: req.bucket.roles,
            message: 'Using bucket roles from existing request context'
        }, 'Bucket metadata already available');

        callback(null, req.bucket.roles);
        return;
    }

    // if the role is not found or is not public-read,
    // just check if we need to allow access to the bucket/object
    // based in naming.
    // Only allow exact bucket name matches, not substring matches
    var isPublicBucket = ANONYMOUS_ACCESS_CONFIG.enabled &&
        bucketName === 'public';
    var fallbackRoles = isPublicBucket ? ['public-read'] : [];

    req.log.debug({
        bucket: bucketName,
        isPublicBucket: isPublicBucket,
        anonymousEnabled: ANONYMOUS_ACCESS_CONFIG.enabled,
        roles: fallbackRoles,
        message: 'Using strict exact-name role detection'
    }, 'Anonymous access: exact-name detection');

    callback(null, fallbackRoles);
}

/**
 * Create anonymous user context
 * Returns a deep frozen copy of ANONYMOUS_USER
 */
function createAnonymousUser() {
    // Create deep copy and then deep freeze it
    var copy = JSON.parse(JSON.stringify(ANONYMOUS_USER));
    return (deepFreeze(copy));
}

/**
 * Recursively freeze an object and all its properties
 */
function deepFreeze(obj) {
    // Retrieve the property names defined on obj
    Object.getOwnPropertyNames(obj).forEach(function freezeProperty(prop) {
        var value = obj[prop];

        // Freeze properties that are objects/arrays before freezing self
        if (value && typeof (value) === 'object') {
            deepFreeze(value);
        }
    });

    return (Object.freeze(obj));
}

/**
 * Anonymous access middleware
 * Should be called before authentication for requests that might be public
 */
function anonymousAccessHandler(req, res, next) {
    req.log.debug({
        method: req.method,
        path: req.path(),
        hasAuth: !!(req.headers.authorization || req.headers.Authorization)
    }, 'Checking for anonymous access');

    // Check if anonymous access is enabled
    if (!ANONYMOUS_ACCESS_CONFIG.enabled) {
        req.log.debug('Anonymous access disabled by configuration');
        next();
        return;
    }

    // Production audit logging for anonymous access attempts
    if (ANONYMOUS_ACCESS_CONFIG.auditAll) {
        req.log.warn({
            event: 'anonymous_access_attempt',
            method: req.method,
            path: req.path(),
            userAgent: req.headers['user-agent'],
            sourceIP: req.connection.remoteAddress,
            timestamp: new Date().toISOString()
        }, 'AUDIT: Anonymous access attempt');
    }

    // If request already has authentication, skip anonymous handling
    if (req.headers.authorization || req.headers.Authorization) {
        req.log.debug(
            'Request has authentication headers, skipping anonymous access');
        next();
        return;
    }

    // Only allow GET/HEAD/OPTIONS operations for anonymous access
    if (req.method !== 'GET' && req.method !== 'HEAD' &&
        req.method !== 'OPTIONS') {
        req.log.debug('Anonymous access only allowed for' +
                      ' GET/HEAD/OPTIONS operations');
        next();
        return;
    }

    // Extract bucket name from request
    var bucketName = extractBucketName(req);
    if (!bucketName) {
        req.log.debug('No bucket name found, skipping anonymous access');
        next();
        return;
    }

    // Mark this request as potentially anonymous and defer the decision
    // The actual check will happen later when bucket metadata is available
    req.log.debug({
        bucket: bucketName,
        method: req.method,
        path: req.path()
    }, 'Marking request for potential anonymous access - will verify later');

    // Extract the account name from the path (/account/buckets/bucket)
    var pathParts = req.path().split('/').filter(
        function isNonEmptyPathPart(part) {
        return (part.length > 0);
    });
    var accountName = pathParts[0]; // First part is the account name

    // Validate account name format (Phase 1: format validation)
    if (!isValidAccountName(accountName)) {
        req.log.warn({
            accountName: accountName,
            path: req.path(),
            method: req.method,
            sourceIP: req.connection.remoteAddress,
            userAgent: req.headers['user-agent']
        }, 'Rejected invalid account name format in anonymous access attempt');
        next();
        return;
    }

    // Set up anonymous context tentatively - this will be validated later
    req.potentialAnonymousAccess = {
        bucketName: bucketName,
        accountName: accountName
    };

    req.log.debug({
        bucketName: bucketName,
        accountName: accountName
    }, 'Set up potential anonymous access context');

    next();
}

/**
 * Validate and activate anonymous access when bucket metadata is available
 * This should be called after bucket metadata has been loaded
 */
function validateAnonymousAccess(req, res, next) {
    req.log.debug({
        hasPotentialAnonymousAccess: !!req.potentialAnonymousAccess,
        hasCaller: !!req.caller,
        callerType: req.caller ? (req.caller.publicReader ? 'publicReader' :
                                  'authenticated') : 'none',
        hasBucket: !!req.bucket,
        bucketId: req.bucket ? req.bucket.id : 'none',
        bucketRoles: req.bucket ? req.bucket.roles : 'none'
    }, 'validateAnonymousAccess: entered');

    // Only proceed if this was marked as potential anonymous access
    if (!req.potentialAnonymousAccess) {
        req.log.debug('No potential anonymous access marked, skipping');
        next();
        return;
    }

    // If caller is already set and is not anonymous, authentication succeeded,
    // so skip
    if (req.caller && !req.caller.anonymous && !req.caller.publicReader) {
        req.log.debug('Request has authenticated caller,'+
                      ' skipping anonymous validation');
        delete req.potentialAnonymousAccess;
        next();
        return;
    }

    var bucketName = req.potentialAnonymousAccess.bucketName;
    var accountName = req.potentialAnonymousAccess.accountName;

    req.log.debug({
        bucket: bucketName,
        account: accountName,
        hasBucketMetadata: !!(req.bucket && req.bucket.roles !== undefined)
    }, 'Validating anonymous access with bucket metadata');

    // Check if this is a bucket or object request
    var isObjectRequest = req.bucketObject && req.bucketObject.name;

    // SECURITY: Only allow buckets named exactly "public" (case-sensitive)
    var isPublicBucket = bucketName === 'public';

     req.log.debug({
        bucket: bucketName,
        isPublicBucket: isPublicBucket,
        isObjectRequest: isObjectRequest,
        objectName: isObjectRequest ? req.bucketObject.name : 'N/A'
    }, 'Anonymous access validation');

    if (isPublicBucket) {
        // Verify account exists before granting anonymous access
        // (Phase 2: account existence validation via mahi)
        if (!req.mahi) {
            req.log.error('Mahi client not available for account validation');
            delete req.potentialAnonymousAccess;
            next(new AuthorizationError('anonymous', req.path(),
                               'Cannot validate account for anonymous access'));
            return;
        }

        req.mahi.getAccount(accountName,
            function handleAccountValidation(mahiErr, account) {
            if (mahiErr) {
                req.log.error({
                    err: mahiErr,
                    accountName: accountName
                }, 'Failed to validate account existence for anonymous access');
                delete req.potentialAnonymousAccess;
                next(new AuthorizationError('anonymous', req.path(),
                                       'Failed to validate account'));
                return;
            }

            if (!account) {
                req.log.warn({
                    accountName: accountName,
                    path: req.path(),
                    sourceIP: req.connection.remoteAddress
                }, 'Account does not exist for anonymous access attempt');
                delete req.potentialAnonymousAccess;
                next(new AuthorizationError('anonymous', req.path(),
                                       'Account does not exist'));
                return;
            }

            req.log.debug({
                accountName: accountName,
                accountUuid: account.uuid
            }, 'Account existence validated for anonymous access');

            // Account exists - activate anonymous access
            req.caller = {
                account: {
                    uuid: 'anonymous-' + accountName,
                    login: accountName,
                    isAdmin: false
                },
                user: {
                    uuid: 'anonymous-user',
                    login: 'anonymous'
                },
                roles: ['public-read'],
                publicReader: true,
                isAnonymousPublicAccess: true
            };

            req.isAnonymousAccess = true;

            req.log.debug({
                caller: req.caller,
                bucket: bucketName
            }, 'Anonymous access granted based on bucket metadata');

            // Clean up the potential access flag
            delete req.potentialAnonymousAccess;
            next();
        });
        return;
    } else {
        req.log.debug({
            bucket: bucketName
        }, 'Anonymous access denied - bucket must be named exactly "public"');

        // Clean up the potential access flag
        delete req.potentialAnonymousAccess;

        // Return authorization error instead of continuing with
        // anonymous caller
        next(new AuthorizationError('anonymous', req.path(),
                               'Anonymous access not allowed for this bucket'));
        return;
    }
}

/**
 * Validate anonymous access for objects based on object metadata
 * This should be called after object metadata has been loaded
 */
function validateAnonymousObjectAccess(req, res, next) {
    // Only check if we have potential anonymous access
    if (!req.potentialAnonymousAccess) {
        next();
        return;
    }

    // Skip if caller is already authenticated
    if (req.caller && !req.caller.anonymous && !req.caller.publicReader) {
        req.log.debug('Request has authenticated caller' +
                      ', skipping object anonymous validation');
        delete req.potentialAnonymousAccess;
        next();
        return;
    }

    var bucketName = req.potentialAnonymousAccess.bucketName;
    var accountName = req.potentialAnonymousAccess.accountName;
    var objectName = req.bucketObject ? req.bucketObject.name : null;

    req.log.debug({
        bucket: bucketName,
        object: objectName,
        hasMetadata: !!req.metadata,
        metadataRoles: req.metadata ? req.metadata.roles : 'no metadata',
        metadataKeys: req.metadata ? Object.keys(req.metadata) : 'no metadata',
        fullMetadata: req.metadata
    }, 'Validating anonymous access for object - full metadata dump');

    // Check if object has public-read role OR if it's in the "public" bucket
    var isInPublicBucket = bucketName === 'public';
    var hasPublicReader = false;

    // Check roles in metadata - roles are stored as UUIDs, need to resolve them
    if (req.metadata && req.metadata.properties &&
        req.metadata.properties.roles &&
        Array.isArray(req.metadata.properties.roles)) {
        var roleUuids = req.metadata.properties.roles;

        req.log.debug({
            objectRoles: roleUuids,
            roleCount: roleUuids.length
        }, 'Object has roles - resolving UUIDs to check for public-read');

        // Separate literal role names from UUIDs
        // All these roles must be created in Manta CLOUDAPI first.
        // The only being used today is public-reader
        var systemRoles = SYSTEM_ROLES;
        var literalRoles = [];
        var uuidRoles = [];

        roleUuids.forEach(function categorizeRole(role) {
            if (systemRoles.indexOf(role) !== -1) {
                literalRoles.push(role);
            } else {
                uuidRoles.push(role);
            }
        });

        // Check literal roles first
        hasPublicReader = literalRoles.indexOf('public-read') !== -1;

        // If we already found public-read or no UUIDs to resolve, continue
        if (hasPublicReader || uuidRoles.length === 0 || !req.mahi) {
            req.log.debug({
                literalRoles: literalRoles,
                uuidRoles: uuidRoles,
                hasPublicReader: hasPublicReader
            }, 'validateAnonymousObjectAccess:' +
                          ' processed literal and UUID roles');
            continueValidation();
            return;
        }

        // Resolve remaining role UUIDs to names using Mahi
        req.mahi.getName({
            uuids: uuidRoles
        }, function handleResolveRoleUuids(err, roleNames) {
            if (err) {
                req.log.warn(err, 'validateAnonymousObjectAccess:'+
                             ' failed to resolve role UUIDs');
                // Continue with other checks
                continueValidation();
                return;
            }

            req.log.debug({
                roleUuids: uuidRoles,
                resolvedNames: roleNames
            }, 'validateAnonymousObjectAccess: resolved role UUIDs to names');

            // Check if any resolved role name is 'public-read'
            var roleNamesList = [];
            if (roleNames) {
                Object.keys(roleNames).forEach(function extractRoleName(uuid) {
                    roleNamesList.push(roleNames[uuid]);
                });
            }

            // Combine literal and resolved roles for final check
            if (!hasPublicReader) {
                hasPublicReader = roleNamesList.some(
                    function isPublicReadRole(roleName) {
                    return (roleName === 'public-read');
                });
            }

            req.log.debug({
                literalRoles: literalRoles,
                roleNamesList: roleNamesList,
                hasPublicReader: hasPublicReader
            }, 'validateAnonymousObjectAccess: checked for public-read role');

            continueValidation();
        });

        // Return early - will continue in callback
        return;
    }

    // Continue with validation (called both sync and async)
    continueValidation();

    function continueValidation() {
        // For objects that have been subject to ACL operations, check if they
        // should be public
        var objectKey = accountName + '/' + bucketName + '/' + objectName;
        // Objects must have explicit public-read role or be in exact "public"
        // bucket

        req.log.debug({
            object: objectName,
            bucket: bucketName,
            objectKey: objectKey,
            roles: req.metadata && req.metadata.properties ?
                req.metadata.properties.roles : [],
            hasPublicReader: hasPublicReader
        }, 'Object anonymous access check');

        if (hasPublicReader || isInPublicBucket) {
            // Grant anonymous access for this object
            req.caller = {
                account: {
                    uuid: 'anonymous-' + accountName,
                    login: accountName,
                    isAdmin: false
                },
                user: {
                    uuid: 'anonymous-user',
                    login: 'anonymous'
                },
                roles: ['public-read'],
                publicReader: true,
                isAnonymousPublicAccess: true,
                anonymous: false  // Don't set this to true to avoid old
                                  // anonymous logic
            };

            req.isAnonymousAccess = true;

            req.log.debug({
                caller: req.caller,
                object: objectName
            }, 'Anonymous access granted for public object');
        } else {
            req.log.debug({
                object: objectName,
                bucket: bucketName,
                roles: req.metadata && req.metadata.properties ?
                    req.metadata.properties.roles : []
            }, 'Anonymous access denied ' +
                          '- object is not public and not in public bucket');

            // Clean up the potential access flag
            delete req.potentialAnonymousAccess;

            // Return authorization error instead of continuing with
            // anonymous caller
            next(new AuthorizationError('anonymous', req.path(),
                               'Anonymous access not allowed for this object'));
            return;
        }

        // Clean up the potential access flag
        delete req.potentialAnonymousAccess;
        next();
    }
}

///--- Exports

module.exports = {
    anonymousAccessHandler: anonymousAccessHandler,
    validateAnonymousAccess: validateAnonymousAccess,
    validateAnonymousObjectAccess: validateAnonymousObjectAccess,
    isPublicResourceRequest: isPublicResourceRequest,
    createAnonymousUser: createAnonymousUser,
    extractBucketName: extractBucketName,
    isValidAccountName: isValidAccountName,
    SYSTEM_ROLES: SYSTEM_ROLES
};
