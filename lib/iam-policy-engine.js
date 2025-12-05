/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * IAM Policy Evaluation Engine for S3 operations
 * Evaluates IAM permission policies against S3 actions and resources
 */

var assert = require('assert-plus');

/**
 * Evaluate IAM permission policies for assumed roles
 */
function evaluatePermissionPolicies(policies, action, resource,
    log) {
    assert.array(policies, 'policies');
    assert.string(action, 'action');
    assert.string(resource, 'resource');
    assert.object(log, 'log');

    if (!policies || policies.length === 0) {
        log.debug('No permission policies to evaluate - ' +
            'denying access');
        return (false);
    }

    log.debug({
        policiesCount: policies.length,
        action: action,
        resource: resource
    }, 'IAM_EVAL_DEBUG: Starting permission policy evaluation');

    // Evaluate each policy
    for (var i = 0; i < policies.length; i++) {
        var policy = policies[i];

        try {
            var policyDoc;
            log.debug({
                policyIndex: i,
                policyType: typeof (policy),
                hasObjPolicyDocument: !!(policy && policy.policyDocument),
                policyStringPreview: typeof (policy) === 'string' ?
                    policy.substring(0, 100) + '...' : null
            }, 'IAM_EVAL_DEBUG: Processing policy');

            if (typeof (policy) === 'string') {
                if (policy.indexOf('policyDocument') !== -1) {
                    // Might be a policy object serialized as string
                    var policyObj = JSON.parse(policy);
                    policyDoc = typeof (policyObj.policyDocument) === 'string' ?
                        JSON.parse(policyObj.policyDocument) :
                        policyObj.policyDocument;
                } else {
                    // Raw policy string
                    policyDoc = JSON.parse(policy);
                }
            } else if (policy.policyDocument) {
                // Policy object with policyDocument field
                policyDoc = typeof (policy.policyDocument) === 'string' ?
                    JSON.parse(policy.policyDocument) : policy.policyDocument;
            } else {
                // Direct policy object
                policyDoc = policy;
            }

            log.debug({
                policyIndex: i,
                policyName: policy.policyName || 'unnamed',
                hasPolicyDoc: !!policyDoc,
                policyDocStatementCount: policyDoc && policyDoc.Statement ?
                    policyDoc.Statement.length : 0,
                action: action,
                resource: resource
            }, 'IAM_EVAL_DEBUG: About to evaluate policy document');

            if (evaluatePolicy(policyDoc, action, resource, log)) {
                log.debug({
                    policyIndex: i,
                    action: action,
                    resource: resource
                }, 'IAM_EVAL_DEBUG: Policy evaluation: ALLOW');
                return (true);
            } else {
                log.debug({
                    policyIndex: i,
                    policyName: policy.policyName || 'unnamed'
                }, 'IAM_DEBUG: Policy evaluation: DENY');
            }
        } catch (parseErr) {
            log.error({
                err: parseErr,
                policyIndex: i,
                policy: policy
            }, 'Failed to parse IAM permission policy');
            // Continue to next policy
        }
    }

    log.debug({
        policiesCount: policies.length,
        action: action,
        resource: resource
    }, 'IAM_EVAL_DEBUG: FINAL DENY - no policy allowed access');

    return (false);
}

/**
 * Evaluate a single IAM policy document
 */
function evaluatePolicy(policyDoc, action, resource, log) {
    log.debug({
        hasPolicyDoc: !!policyDoc,
        hasStatement: !!(policyDoc && policyDoc.Statement),
        isStatementArray: !!(policyDoc && policyDoc.Statement &&
                             Array.isArray(policyDoc.Statement)),
        statementLength: policyDoc && policyDoc.Statement ?
            policyDoc.Statement.length : 0,
        policyDocKeys: policyDoc ? Object.keys(policyDoc) : [],
        fullPolicyDoc: policyDoc
    }, 'IAM_DEBUG: Policy document structure check');

    if (!policyDoc.Statement ||
        !Array.isArray(policyDoc.Statement)) {
        log.debug({
            hasStatement: !!policyDoc.Statement,
            isArray: policyDoc.Statement ?
                Array.isArray(policyDoc.Statement) : false,
            statementType: policyDoc.Statement ?
                typeof (policyDoc.Statement) : 'undefined'
        }, 'IAM_DEBUG: Policy missing Statement array');
        return (false);
    }

    log.debug({
        statementCount: policyDoc.Statement.length
    }, 'IAM_DEBUG: Found valid Statement array, processing statements');

    // AWS IAM evaluation order:
    // 1. Explicit Deny always wins (overrides any Allow)
    // 2. Explicit Allow overrides implicit deny
    // 3. Default is implicit deny

    var hasExplicitAllow = false;

    // Check each statement
    for (var i = 0; i < policyDoc.Statement.length; i++) {
        var statement = policyDoc.Statement[i];

        log.debug({
            statementIndex: i,
            effect: statement.Effect,
            statement: statement
        }, 'IAM_DEBUG: Processing statement');

        // Check if statement matches action and resource
        var statementMatches = evaluateStatement(statement, action, resource,
            log);

        if (!statementMatches) {
            continue;
        }

        // Explicit Deny takes precedence - deny immediately
        if (statement.Effect === 'Deny') {
            log.debug({
                statementIndex: i,
                action: action,
                resource: resource
            }, 'IAM_DEBUG: Explicit DENY matched - denying access');
            return (false);
        }

        // Track if we found an Allow
        if (statement.Effect === 'Allow') {
            log.debug({
                statementIndex: i
            }, 'IAM_DEBUG: Explicit ALLOW matched');
            hasExplicitAllow = true;
        }
    }

    if (hasExplicitAllow) {
        log.debug('IAM_DEBUG: Access allowed by explicit Allow statement');
        return (true);
    }

    log.debug('IAM_DEBUG: No statements matched - implicit deny');
    return (false);
}

/**
 * Evaluate a single IAM policy statement
 */
function evaluateStatement(statement, action, resource, log) {
    log.debug({
        statementEffect: statement.Effect,
        statementActions: statement.Action,
        statementResources: statement.Resource,
        requestAction: action,
        requestResource: resource
    }, 'IAM_DEBUG: Evaluating statement');

    // Check Action
    var actionMatches = matchesAction(statement.Action, action);
    log.debug({
        actionMatches: actionMatches,
        statementActions: statement.Action,
        requestAction: action
    }, 'IAM_DEBUG: Action matching result');

    if (!actionMatches) {
        return (false);
    }

    // Check Resource
    var resourceMatches = matchesResource(statement.Resource, resource);
    log.debug({
        resourceMatches: resourceMatches,
        statementResources: statement.Resource,
        requestResource: resource
    }, 'IAM_DEBUG: Resource matching result');

    if (!resourceMatches) {
        return (false);
    }

    log.debug({
        statementEffect: statement.Effect,
        action: action,
        resource: resource
    }, 'IAM_DEBUG: Statement matched action and resource - ALLOWING');

    return (true);
}

/**
 * Check if action matches statement actions
 */
function matchesAction(statementActions, requestAction) {
    var actions = Array.isArray(statementActions) ?
        statementActions : [statementActions];

    for (var i = 0; i < actions.length; i++) {
        var actionPattern = actions[i];

        if (actionPattern === '*') {
            return (true);
        }

        if (actionPattern === requestAction) {
            return (true);
        }

        // Manta compatibility: treat s3:ListBucket and s3:ListObjectsV2
        // as equivalent since they perform the same underlying
        // operation in Manta
        if ((actionPattern === 's3:ListBucket' &&
             requestAction === 's3:ListObjectsV2') ||
            (actionPattern === 's3:ListObjectsV2' &&
             requestAction === 's3:ListBucket')) {
            return (true);
        }

        // Handle wildcards like "s3:*" or "s3:Get*"
        if (actionPattern.indexOf('*') !== -1) {
            //JSSTYLED
            var pattern = actionPattern.replace(/\*/g, '.*');
            var regex = new RegExp('^' + pattern + '$');
            if (regex.test(requestAction)) {
                return (true);
            }
        }
    }

    return (false);
}

/**
 * Check if resource matches statement resources
 */
function matchesResource(statementResources, requestResource) {
    var resources = Array.isArray(statementResources) ?
        statementResources : [statementResources];

    for (var i = 0; i < resources.length; i++) {
        var resourcePattern = resources[i];

        if (resourcePattern === '*') {
            return (true);
        }

        if (resourcePattern === requestResource) {
            return (true);
        }

        // Handle wildcards like "arn:aws:s3:::bucket/*"
        // JSSTYLED
        if (resourcePattern.indexOf('*') !== -1) {
        // JSSTYLED
            var pattern = resourcePattern.replace(/\*/g, '.*');
            var regex = new RegExp('^' + pattern + '$');
            if (regex.test(requestResource)) {
                return (true);
            }
        }
    }

    return (false);
}

/**
 * Convert S3 operation to IAM action format
 */
function s3OperationToIamAction(operation) {
    var actionMap = {
        // Bucket operations
        'listbucket': 's3:ListBucket',
        'listbuckets': 's3:ListAllMyBuckets',
        'createbucket': 's3:CreateBucket',
        'putbucket': 's3:CreateBucket',  // PUT bucket is create bucket
        'deletebucket': 's3:DeleteBucket',
        'getbucketlocation': 's3:GetBucketLocation',
        'headbucket': 's3:ListBucket',

        // Object operations
        'getobject': 's3:GetObject',
        'putobject': 's3:PutObject',
        'deleteobject': 's3:DeleteObject',
        'listobjects': 's3:ListBucket',
        'headobject': 's3:GetObject',
        'copyobject': 's3:GetObject',

        // Multipart uploads
        'createmultipartupload': 's3:PutObject',
        'uploadpart': 's3:PutObject',
        'completemultipartupload': 's3:PutObject',
        'abortmultipartupload': 's3:AbortMultipartUpload',
        'listmultipartuploads': 's3:ListMultipartUploadParts',
        'listparts': 's3:ListMultipartUploadParts'
    };

    return (actionMap[operation.toLowerCase()] || operation);
}

/**
 * Convert Manta resource path to S3 ARN format
 */
function mantaResourceToS3Arn(accountUuid, resource) {
    // Extract bucket and object from Manta resource path
    // Resource format: /accountUuid/stor/bucket/object
    if (!resource || typeof (resource) !== 'string') {
        return (resource);
    }

    // Remove leading slash and split
    var parts = resource.replace(/^\//, '').split('/');

    if (parts.length < 3 || parts[0] !== accountUuid ||
        parts[1] !== 'stor') {
        return (resource); // Not a standard Manta storage path
    }

    var bucket = parts[2];

    if (parts.length === 3) {
        // Bucket-level resource
        return ('arn:aws:s3:::' + bucket);
    } else {
        // Object-level resource
        var objectPath = parts.slice(3).join('/');
        return ('arn:aws:s3:::' + bucket + '/' + objectPath);
    }
}

/**
 * Check if credential is allowed to call IAM endpoint.
 *
 * Access rules:
 * - Permanent credentials: always allowed
 * - MSTS (GetSessionToken): never allowed (AWS restriction)
 * - MSAR (AssumeRole): allowed if role policy permits
 *
 * @param {string} accessKeyId - The access key ID
 * @param {object} authRes - Auth response from Mahi
 * @param {string} action - IAM action (e.g., 'CreateRole')
 * @param {object} log - Bunyan logger
 * @returns {object} { allowed, error?, message? }
 */
function checkIamAccess(accessKeyId, authRes, action, log) {
    // Permanent credentials - always allowed
    if (accessKeyId.indexOf('MSTS') !== 0 &&
        accessKeyId.indexOf('MSAR') !== 0) {
        log.debug({ accessKeyId: accessKeyId, action: action },
            'IAM access: permanent credentials allowed');
        return ({ allowed: true });
    }

    // MSTS (GetSessionToken) - never allowed for IAM
    if (accessKeyId.indexOf('MSTS') === 0) {
        log.warn({ accessKeyId: accessKeyId, action: action },
            'IAM access: MSTS credentials blocked');
        return ({
            allowed: false,
            error: 'AccessDenied',
            message: 'Cannot call IAM operations with ' +
                'GetSessionToken credentials.'
        });
    }

    // MSAR (AssumeRole) - check role policy
    var policies = [];
    if (authRes.assumedRole && authRes.assumedRole.policies) {
        policies = authRes.assumedRole.policies;
    }
    var iamAction = 'iam:' + action;

    log.debug({
        accessKeyId: accessKeyId,
        action: iamAction,
        policiesCount: policies.length
    }, 'IAM access: checking MSAR role policy');

    if (!evaluatePermissionPolicies(policies, iamAction, '*', log)) {
        log.warn({
            accessKeyId: accessKeyId,
            action: iamAction
        }, 'IAM access: role policy denied');
        return ({
            allowed: false,
            error: 'AccessDenied',
            message: 'Role policy does not allow ' + iamAction
        });
    }

    log.debug({ accessKeyId: accessKeyId, action: iamAction },
        'IAM access: role policy allowed');
    return ({ allowed: true });
}

module.exports = {
    evaluatePermissionPolicies: evaluatePermissionPolicies,
    s3OperationToIamAction: s3OperationToIamAction,
    mantaResourceToS3Arn: mantaResourceToS3Arn,
    checkIamAccess: checkIamAccess
};
