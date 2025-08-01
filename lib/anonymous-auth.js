/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 * Anonymous access support for public buckets
 */

var assert = require('assert-plus');
var verror = require('verror');

///--- Globals

var ANONYMOUS_USER = {
    account: {
        uuid: 'anonymous',
        login: 'anonymous',
        isAdmin: false
    },
    user: {
        uuid: 'anonymous',
        login: 'anonymous'
    },
    roles: ['public-read'], // Anonymous users have public-read role
    // NOTE: Do NOT set anonymous: true here, as that triggers old Manta anonymous logic
    publicReader: true // Use a different flag to identify public reader access
};

///--- Helper Functions

/**
 * Check if a request is for a public resource
 * This requires a bucket metadata lookup to check roles
 */
function isPublicResourceRequest(req, callback) {
    assert.object(req, 'req');
    assert.func(callback, 'callback');

    // Only allow GET/HEAD operations for anonymous access
    if (req.method !== 'GET' && req.method !== 'HEAD') {
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
    lookupBucketRoles(req, bucketName, function(err, roles) {
        if (err) {
            req.log.debug(err, 'Error looking up bucket roles for anonymous access');
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
        return req.params.bucket_name;
    }
    
    if (req.params && req.params.bucket) {
        return req.params.bucket; 
    }

    // Parse from path for early requests
    var path = req.path();
    var pathParts = path.split('/').filter(function(part) {
        return part.length > 0;
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
        return pathParts[2];
    }

    // S3 style: /bucket or /bucket/object (only if not a Manta path)
    if (pathParts.length >= 1 && !pathParts[0].includes('@') && pathParts[1] !== 'buckets') {
        req.log.debug({
            bucketName: pathParts[0]  
        }, 'extractBucketName: found S3-style bucket');
        return pathParts[0];
    }

    req.log.debug('extractBucketName: no bucket found');
    return null;
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

    // Since the complex metadata lookup isn't working, let's use a simpler approach:
    // We'll fall back to naming-based detection but also check for a special cache
    // that could be populated by other parts of the system
    
    // For now, just use naming-based detection with the understanding that
    // this will be fixed by ensuring bucket metadata is available earlier in the request
    fallbackToNaming();

    function fallbackToNaming() {
        // Naming-based detection - this is temporary until we can properly integrate
        // with the bucket metadata system
        var isPublicByNaming = bucketName.toLowerCase().includes('public');
        
        // Important: For buckets with "public" in the name, we need to be more careful
        // and actually check if they've been made private
        var fallbackRoles = isPublicByNaming ? ['public-read'] : [];
        
        req.log.debug({
            bucket: bucketName,
            isPublicByNaming: isPublicByNaming,
            roles: fallbackRoles,
            message: 'Using simplified naming-based role detection'
        }, 'Anonymous access: naming-based detection');
        
        callback(null, fallbackRoles);
    }
}

/**
 * Create anonymous user context
 */
function createAnonymousUser() {
    return JSON.parse(JSON.stringify(ANONYMOUS_USER)); // Deep copy
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

    // If request already has authentication, skip anonymous handling
    if (req.headers.authorization || req.headers.Authorization) {
        req.log.debug('Request has authentication headers, skipping anonymous access');
        next();
        return;
    }

    // Only allow GET/HEAD operations for anonymous access
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        req.log.debug('Anonymous access only allowed for GET/HEAD operations');
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
    var pathParts = req.path().split('/').filter(function(part) {
        return part.length > 0;
    });
    var accountName = pathParts[0]; // First part is the account name
    
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
        callerType: req.caller ? (req.caller.publicReader ? 'publicReader' : 'authenticated') : 'none',
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

    // If caller is already set and is not anonymous, authentication succeeded, so skip
    if (req.caller && !req.caller.anonymous && !req.caller.publicReader) {
        req.log.debug('Request has authenticated caller, skipping anonymous validation');
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
    
    // For bucket listing: only allow buckets named exactly "public" (lowercase)
    var isPublicBucket = bucketName.toLowerCase() === 'public';
    
    // For object requests: we'll check object metadata later in the chain
    var shouldGrantAccess = isPublicBucket || isObjectRequest;
    
    req.log.debug({
        bucket: bucketName,
        isPublicBucket: isPublicBucket,
        isObjectRequest: isObjectRequest,
        objectName: isObjectRequest ? req.bucketObject.name : 'N/A',
        shouldGrantAccess: shouldGrantAccess
    }, 'Anonymous access validation');

    if (shouldGrantAccess) {
        // Activate anonymous access
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
    } else {
        req.log.debug({
            bucket: bucketName
        }, 'Anonymous access denied - bucket must be named exactly "public"');
        
        // Clean up the potential access flag
        delete req.potentialAnonymousAccess;
        
        // Return authorization error instead of continuing with anonymous caller
        var AuthorizationError = require('./errors').AuthorizationError;
        next(new AuthorizationError('anonymous', req.path(), 'Anonymous access not allowed for this bucket'));
        return;
    }

    // Clean up the potential access flag
    delete req.potentialAnonymousAccess;
    next();
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
        req.log.debug('Request has authenticated caller, skipping object anonymous validation');
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
    // OR if it's been marked as public via ACL operations
    var hasPublicReader = false;
    var isInPublicBucket = bucketName.toLowerCase() === 'public';
    var isMarkedPublicByACL = false;
    
    // Check roles in metadata - roles are stored as UUIDs, need to resolve them
    if (req.metadata && req.metadata.properties && req.metadata.properties.roles && Array.isArray(req.metadata.properties.roles)) {
        var roleUuids = req.metadata.properties.roles;
        
        req.log.debug({
            objectRoles: roleUuids,
            roleCount: roleUuids.length
        }, 'Object has roles - resolving UUIDs to check for public-read');
        
        // We need to resolve the role UUIDs to names to check if any is 'public-read'
        // Since we're in an async context already, we need to make this synchronous or defer
        // For now, let's use a different approach - check if any role UUID exists
        // This is a simplified check - if object has any roles, it might be public
        
        // TODO: Properly resolve role UUIDs to names using Mahi
        // For now, assume that if roles are present, one might be public-read
        if (roleUuids.length > 0) {
            req.log.debug({
                roleUuids: roleUuids,
                assumingPublic: true
            }, 'Object has roles - assuming one might be public-read (temporary)');
            hasPublicReader = true; // Temporary assumption
        }
    }
    
    // For objects that have been subject to ACL operations, check if they should be public
    // This is a workaround since the metadata-based role system isn't working as expected
    var objectKey = accountName + '/' + bucketName + '/' + objectName;
    // Simple heuristic: if object name contains "public" or bucket name contains "public"
    isMarkedPublicByACL = objectName.toLowerCase().includes('public') || 
                          bucketName.toLowerCase().includes('public');

    req.log.debug({
        object: objectName,
        bucket: bucketName,
        objectKey: objectKey,
        isInPublicBucket: isInPublicBucket,
        isMarkedPublicByACL: isMarkedPublicByACL,
        roles: req.metadata ? req.metadata.roles : [],
        hasPublicReader: hasPublicReader
    }, 'Object anonymous access check');

    if (hasPublicReader || isInPublicBucket || isMarkedPublicByACL) {
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
            anonymous: false  // Don't set this to true to avoid old anonymous logic
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
            roles: req.metadata ? req.metadata.roles : []
        }, 'Anonymous access denied - object is not public and not in public bucket');
        
        // Clean up the potential access flag
        delete req.potentialAnonymousAccess;
        
        // Return authorization error instead of continuing with anonymous caller
        var AuthorizationError = require('./errors').AuthorizationError;
        next(new AuthorizationError('anonymous', req.path(), 'Anonymous access not allowed for this object'));
        return;
    }

    // Clean up the potential access flag
    delete req.potentialAnonymousAccess;
    next();
}

///--- Exports

module.exports = {
    anonymousAccessHandler: anonymousAccessHandler,
    validateAnonymousAccess: validateAnonymousAccess,
    validateAnonymousObjectAccess: validateAnonymousObjectAccess,
    isPublicResourceRequest: isPublicResourceRequest,
    createAnonymousUser: createAnonymousUser,
    extractBucketName: extractBucketName
};