/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * AWS IAM Policy to Manta Policy Converter
 *
 * Converts AWS IAM policy documents (like AssumeRolePolicyDocument)
 * into Manta-compatible policy format for use with roles and RBAC.
 */

var assert = require('assert-plus');

/**
 * AWS S3 Action to Manta Action mapping
 */
var AWS_TO_MANTA_ACTIONS = {
    // Bucket operations
    's3:ListBucket': 'getbucket',
    's3:ListBuckets': 'getbucket',  // Special case for listing all buckets
    's3:GetBucket': 'getbucket',
    's3:GetBucketLocation': 'getbucket',
    's3:GetBucketVersioning': 'getbucket',
    's3:CreateBucket': 'putbucket',
    's3:PutBucket': 'putbucket',
    's3:DeleteBucket': 'deletebucket',

    // Object operations
    's3:GetObject': 'getobject',
    's3:GetObjectVersion': 'getobject',
    's3:PutObject': 'putobject',
    's3:PutObjectAcl': 'putobject',
    's3:DeleteObject': 'deleteobject',
    's3:DeleteObjectVersion': 'deleteobject',

    // Multipart operations
    's3:ListMultipartUploads': 'getbucket',
    's3:ListParts': 'getobject',
    's3:InitiateMultipartUpload': 'putobject',
    's3:UploadPart': 'putobject',
    's3:CompleteMultipartUpload': 'putobject',
    's3:AbortMultipartUpload': 'putobject',

    // Wildcard permissions
    's3:*': ['getbucket', 'putbucket', 'deletebucket', 'getobject',
             'putobject', 'deleteobject']
};

/**
 * Convert AWS S3 action to Manta action(s)
 * @param {string} awsAction - AWS action like 's3:GetObject'
 * @returns {Array<string>} Array of Manta actions
 */
function convertAction(awsAction) {
    var mantaActions = AWS_TO_MANTA_ACTIONS[awsAction];

    if (!mantaActions) {
        // If no direct mapping, try to infer from action name
        var actionName = awsAction.toLowerCase().replace('s3:', '');

        if (actionName.includes('get') || actionName.includes('list') ||
            actionName.includes('head')) {
            if (actionName.includes('bucket')) {
                return (['getbucket']);
            } else {
                return (['getobject']);
            }
        } else if (actionName.includes('put') ||
                   actionName.includes('create') ||
                   actionName.includes('upload')) {
            if (actionName.includes('bucket')) {
                return (['putbucket']);
            } else {
                return (['putobject']);
            }
        } else if (actionName.includes('delete')) {
            if (actionName.includes('bucket')) {
                return (['deletebucket']);
            } else {
                return (['deleteobject']);
            }
        }

        // Default fallback - grant minimal read permission
        return (['getobject']);
    }

    return (Array.isArray(mantaActions) ? mantaActions : [mantaActions]);
}

/**
 * Convert AWS S3 ARN resource to Manta resource pattern
 * @param {string} arnResource - AWS ARN like 'arn:aws:s3:::bucket-name/<star>'
 * @returns {string} Manta resource pattern like 'bucket-name/<star>'
 */
function convertResource(arnResource) {
    if (!arnResource || typeof (arnResource) !== 'string') {
        return ('*');
    }

    // Handle ARN format: arn:aws:s3:::bucket-name/object-pattern
    if (arnResource.startsWith('arn:aws:s3:::')) {
        var resourcePath = arnResource.substring('arn:aws:s3:::'.length);

        // Empty resource path means all resources
        if (!resourcePath) {
            return ('*');
        }

        return (resourcePath);
    }

    // Handle direct resource references (not ARN format)
    if (arnResource.includes('/')) {
        return (arnResource);
    }

    // Bucket-only reference
    return (arnResource);
}

/**
 * Convert AWS IAM policy statement to Manta policy rules
 * @param {Object} statement - AWS IAM policy statement
 * @returns {Array<string>} Array of Manta policy rules
 */
function convertStatement(statement) {
    assert.object(statement, 'statement');

    var rules = [];

    // Only process Allow statements
    if (statement.Effect !== 'Allow') {
        return (rules);
    }

    var actions = Array.isArray(statement.Action) ?
        statement.Action : [statement.Action];
    var resources = Array.isArray(statement.Resource) ?
        statement.Resource : [statement.Resource];

    // Handle case where Resource might not be specified (grants access to all)
    if (!statement.Resource) {
        resources = ['*'];
    }

    actions.forEach(function (awsAction) {
        var mantaActions = convertAction(awsAction);

        resources.forEach(function (awsResource) {
            var mantaResource = convertResource(awsResource);

            mantaActions.forEach(function (mantaAction) {
                // Match action type to appropriate resource pattern
                var finalResource = mantaResource;

                //JSSTYLED
                // Bucket operations need bucket name only (no /*)
                if (mantaAction === 'getbucket' ||
                    mantaAction === 'putbucket' ||
                    mantaAction === 'deletebucket') {
                    if (finalResource.endsWith('/*')) {
                        finalResource =
                            finalResource.substring(0,
                                                    finalResource.length - 2);
                    }
                }
                //JSSTYLED
                // Object operations need bucket/* pattern
                else if (mantaAction === 'getobject' ||
                         mantaAction === 'putobject' ||
                         mantaAction === 'deleteobject') {
                    if (!finalResource.includes('/') &&
                        !finalResource.endsWith('/*')) {
                        finalResource = finalResource + '/*';
                    }
                }

                var rule = 'CAN ' + mantaAction + ' ' + finalResource;
                rules.push(rule);
            });
        });
    });

    return (rules);
}

/**
 * Convert AWS IAM AssumeRolePolicyDocument to Manta policy
 * @param {Object} opts - Options object
 * @param {string} opts.policyDocument - JSON string of AWS IAM policy document
 * @param {string} opts.roleName - Role name for policy naming
 * @param {string} [opts.accountUuid] - Account UUID for policy scoping
 * @returns {Object} Manta policy object
 */
function convertAssumeRolePolicyToMantaPolicy(opts) {
    assert.object(opts, 'opts');
    assert.string(opts.policyDocument, 'opts.policyDocument');
    assert.string(opts.roleName, 'opts.roleName');

    var policy;
    try {
        policy = JSON.parse(opts.policyDocument);
    } catch (err) {
        throw new Error('Invalid JSON in policy document: ' + err.message);
    }

    assert.object(policy, 'parsed policy');

    // AWS AssumeRolePolicyDocument typically has trust policies,
    // but for S3 compatibility
    // we'll convert any permission statements into Manta rules
    var statements = Array.isArray(policy.Statement) ?
        policy.Statement : [policy.Statement];
    var allRules = [];

    statements.forEach(function (statement) {
        var rules = convertStatement(statement);
        allRules = allRules.concat(rules);
    });

    // If no rules generated, create a deny-all policy
    // (principle of least privilege)
    if (allRules.length === 0) {
        allRules = [
            'DENY * *'  // Explicit deny-all for security
        ];
    }

    // Remove duplicate rules
    allRules = allRules.filter(function (rule, index, self) {
        return (self.indexOf(rule) === index);
    });

    // Generate a UUID for the policy
    var policyId = require('crypto').randomBytes(16).toString('hex');
    var policyName = opts.roleName + '-policy';

    return ({
        name: policyName,
        id: policyId,
        rules: allRules,
        // Additional metadata
        sourceRole: opts.roleName,
        sourceType: 'aws-assume-role-policy',
        createdAt: new Date().toISOString()
    });
}

/**
 * Convert AWS IAM permission policy to Manta policy
 * @param {Object} opts - Options object
 * @param {string} opts.policyDocument - JSON string of AWS IAM policy document
 * @param {string} opts.policyName - Policy name
 * @param {string} [opts.roleName] - Associated role name
 * @returns {Object} Manta policy object
 */
function convertPermissionPolicyToMantaPolicy(opts) {
    assert.object(opts, 'opts');
    assert.string(opts.policyDocument, 'opts.policyDocument');
    assert.string(opts.policyName, 'opts.policyName');

    var policy;
    try {
        policy = JSON.parse(opts.policyDocument);
    } catch (err) {
        throw new Error('Invalid JSON in policy document: ' + err.message);
    }

    assert.object(policy, 'parsed policy');

    var statements = Array.isArray(policy.Statement) ?
        policy.Statement : [policy.Statement];
    var allRules = [];

    statements.forEach(function (statement) {
        var rules = convertStatement(statement);
        allRules = allRules.concat(rules);
    });

    // For permission policies, if no rules generated,
    // deny all access (principle of least privilege)
    if (allRules.length === 0) {
        allRules = ['DENY * *'];
    }

    // Remove duplicate rules
    allRules = allRules.filter(function (rule, index, self) {
        return (self.indexOf(rule) === index);
    });

    // Generate a UUID for the policy
    var policyId = require('crypto').randomBytes(16).toString('hex');

    return ({
        name: opts.policyName,
        id: policyId,
        rules: allRules,
        // Additional metadata
        sourceRole: opts.roleName || null,
        sourceType: 'aws-permission-policy',
        createdAt: new Date().toISOString()
    });
}

/**
 * Create a Manta role object with policies for S3 compatibility
 * @param {Object} opts - Options object
 * @param {string} opts.roleName - Role name
 * @param {Array<Object>} opts.policies - Array of Manta policy objects
 * @param {string} opts.principalUuid - Principal user UUID who will
 * assume this role
 * @returns {Object} Manta role object
 */
function createMantaRoleWithPolicies(opts) {
    assert.object(opts, 'opts');
    assert.string(opts.roleName, 'opts.roleName');
    assert.arrayOfObject(opts.policies, 'opts.policies');
    assert.string(opts.principalUuid, 'opts.principalUuid');

    var policyNames = opts.policies.map(function (policy) {
        return (policy.name);
    });

    return ({
        name: opts.roleName,
        members: [opts.principalUuid],
        default_members: [opts.principalUuid], // Critical for S3 compatibility
        policies: policyNames,
        // Additional metadata
        sourceType: 'aws-iam-role',
        createdAt: new Date().toISOString()
    });
}

/**
 * Example AWS AssumeRolePolicyDocument for testing
 */
function getExampleAwsPolicyDocument() {
    return (JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Action': [
                    's3:GetObject',
                    's3:PutObject',
                    's3:ListBucket'
                ],
                'Resource': [
                    'arn:aws:s3:::my-test-bucket/*',
                    'arn:aws:s3:::my-test-bucket'
                ]
            }
        ]
    }));
}

module.exports = {
    convertAssumeRolePolicyToMantaPolicy: convertAssumeRolePolicyToMantaPolicy,
    convertPermissionPolicyToMantaPolicy: convertPermissionPolicyToMantaPolicy,
    createMantaRoleWithPolicies: createMantaRoleWithPolicies,
    convertAction: convertAction,
    convertResource: convertResource,
    convertStatement: convertStatement,
    getExampleAwsPolicyDocument: getExampleAwsPolicyDocument
};
