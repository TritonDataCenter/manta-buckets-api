/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * STS Client Trust Policy Integration Tests
 *
 * Tests the integration between STS client and trust policy engine
 * to ensure proper role assumption authorization.
 */

var helper = require('./s3-test-helper.js');
var bunyan = require('bunyan');
var STSClient = require('../lib/sts-client');

// Test logger
var LOG = bunyan.createLogger({
    name: 'sts-client-trust-policy-test',
    level: process.env.LOG_LEVEL || 'fatal'
});

var stsClient;

// Mock IAM client that returns role data
function MockIAMClient() {
    this.log = LOG.child({component: 'MockIAMClient'});
}

MockIAMClient.prototype.getRole = function getRole(opts, callback) {
    var roleName = opts.roleName;

    // Mock role data responses
    var mockRoles = {
        'admin-role': {
            name: 'admin-role',
            arn: 'arn:manta:iam::123456789012:role/admin-role',
            assumeRolePolicyDocument: {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': 'arn:manta:iam::123456789012:user/alice'
                        },
                        'Action': 'sts:AssumeRole'
                    }
                ]
            }
        },
        'service-role': {
            name: 'service-role',
            arn: 'arn:manta:iam::123456789012:role/service-role',
            assumeRolePolicyDocument: {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Principal': {
                            'Service': 'ec2.amazonaws.com'
                        },
                        'Action': 'sts:AssumeRole'
                    }
                ]
            }
        },
        'conditional-role': {
            name: 'conditional-role',
            arn: 'arn:manta:iam::123456789012:role/conditional-role',
            assumeRolePolicyDocument: JSON.stringify({
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Principal': {
                            'AWS': 'arn:manta:iam::123456789012:user/alice'
                        },
                        'Action': 'sts:AssumeRole',
                        'Condition': {
                            'StringEquals': {
                                'sts:ExternalId': 'secret-123'
                            },
                            'Bool': {
                                'aws:MultiFactorAuthPresent': 'true'
                            }
                        }
                    }
                ]
            })
        },
        'no-trust-policy-role': {
            name: 'no-trust-policy-role',
            arn: 'arn:manta:iam::123456789012:role/no-trust-policy-role'
            // No assumeRolePolicyDocument
        },
        'deny-role': {
            name: 'deny-role',
            arn: 'arn:manta:iam::123456789012:role/deny-role',
            assumeRolePolicyDocument: {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Deny',
                        'Principal': '*',
                        'Action': 'sts:AssumeRole'
                    }
                ]
            }
        }
    };

    var roleData = mockRoles[roleName];
    if (!roleData) {
        var err = new Error('Role not found: ' + roleName);
        err.name = 'NoSuchRole';
        err.statusCode = 404;
        return (callback(err));
    }

    return (callback(null, roleData));
};

// Mock principal data
var alicePrincipal = {
    account: {uuid: '123456789012'},
    uuid: 'alice-uuid',
    login: 'alice',
    type: 'user',
    mfaAuthenticated: true
};

var bobPrincipal = {
    account: {uuid: '123456789012'},
    uuid: 'bob-uuid',
    login: 'bob',
    type: 'user',
    mfaAuthenticated: false
};

var servicePrincipal = {
    account: {uuid: '123456789012'},
    uuid: 'service-uuid',
    login: 'ec2.amazonaws.com',
    type: 'service',
    service: 'ec2.amazonaws.com'
};

helper.test('setup', function (t) {
    stsClient = new STSClient({
        url: 'http://localhost:8080',
        log: LOG
    });

    // Replace IAM client with mock
    stsClient.iamClient = new MockIAMClient();

    t.ok(stsClient, 'STS client created');
    t.ok(stsClient.trustPolicyEngine, 'trust policy engine initialized');
    t.end();
});

// Test successful role assumption
helper.test('validateRole - alice can assume admin-role', function (t) {
    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/admin-role',
        caller: alicePrincipal,
        sourceIp: '192.168.1.100',
        userAgent: 'test-agent'
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ifError(err, 'should not error');
        t.ok(result, 'should return result');
        t.equal(result.valid, true, 'should be valid');
        t.ok(result.trustPolicyEvaluation,
             'should include trust policy evaluation');
        t.equal(result.trustPolicyEvaluation.decision, 'Allow',
                'should allow access');
        t.end();
    });
});

// Test denied role assumption
helper.test('validateRole - bob cannot assume admin-role', function (t) {
    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/admin-role',
        caller: bobPrincipal,
        sourceIp: '192.168.1.100',
        userAgent: 'test-agent'
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ok(err, 'should error for unauthorized user');
        t.equal(err.name, 'AccessDenied', 'should be access denied error');
        t.equal(err.statusCode, 403, 'should be 403 status');
        t.end();
    });
});

// Test service principal role assumption
helper.test('validateRole - service can assume service-role', function (t) {
    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/service-role',
        caller: servicePrincipal,
        sourceIp: '10.0.0.1',
        userAgent: 'aws-sdk'
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ifError(err, 'should not error');
        t.ok(result, 'should return result');
        t.equal(result.valid, true, 'should be valid');
        t.equal(result.trustPolicyEvaluation.decision, 'Allow',
                'should allow service');
        t.end();
    });
});

// Test user cannot assume service role
helper.test('validateRole - user cannot assume service-role', function (t) {
    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/service-role',
        caller: alicePrincipal,
        sourceIp: '192.168.1.100',
        userAgent: 'test-agent'
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ok(err,
             'should error for user trying to assume service role');
        t.equal(err.name, 'AccessDenied', 'should be access denied');
        t.end();
    });
});

// Test conditional role assumption - success
helper.test('validateRole - conditional role with valid conditions',
            function (t) {
    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/conditional-role',
        caller: alicePrincipal,
        sourceIp: '192.168.1.100',
        userAgent: 'test-agent',
        externalId: 'secret-123'
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ifError(err, 'should not error with valid conditions');
        t.ok(result, 'should return result');
        t.equal(result.valid, true, 'should be valid');
        t.equal(result.trustPolicyEvaluation.decision, 'Allow',
                'should allow with conditions');
        t.end();
    });
});

// Test conditional role assumption - failure
helper.test('validateRole - conditional role with invalid external ID',
            function (t) {
    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/conditional-role',
        caller: alicePrincipal,
        sourceIp: '192.168.1.100',
        userAgent: 'test-agent',
        externalId: 'wrong-key'
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ok(err, 'should error with invalid external ID');
        t.equal(err.name, 'AccessDenied', 'should be access denied');
        t.ok(err.message.indexOf('external') > -1 ||
             err.message.indexOf('Condition') > -1,
             'should mention condition failure');
        t.end();
    });
});

// Test conditional role assumption - MFA failure
helper.test('validateRole - conditional role without MFA', function (t) {
    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/conditional-role',
        caller: bobPrincipal, // MFA not authenticated
        sourceIp: '192.168.1.100',
        userAgent: 'test-agent',
        externalId: 'secret-123'
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ok(err, 'should error without MFA');
        t.equal(err.name, 'AccessDenied', 'should be access denied');
        t.end();
    });
});

// Test role with no trust policy
helper.test('validateRole - role without trust policy', function (t) {
    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/no-trust-policy-role',
        caller: alicePrincipal,
        sourceIp: '192.168.1.100',
        userAgent: 'test-agent'
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ok(err, 'should error for role without trust policy');
        t.equal(err.name, 'AccessDenied', 'should be access denied');
        t.ok(err.message.indexOf('NoTrustPolicy') > -1,
             'should indicate no trust policy');
        t.end();
    });
});

// Test explicit deny policy
helper.test('validateRole - explicit deny role', function (t) {
    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/deny-role',
        caller: alicePrincipal,
        sourceIp: '192.168.1.100',
        userAgent: 'test-agent'
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ok(err, 'should error for explicit deny role');
        t.equal(err.name, 'AccessDenied', 'should be access denied');
        t.end();
    });
});

// Test nonexistent role
helper.test('validateRole - nonexistent role', function (t) {
    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/nonexistent-role',
        caller: alicePrincipal,
        sourceIp: '192.168.1.100',
        userAgent: 'test-agent'
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ok(err, 'should error for nonexistent role');
        t.equal(err.name, 'NoSuchRole', 'should be no such role error');
        t.equal(err.statusCode, 404, 'should be 404 status');
        t.end();
    });
});

// Test principal ARN building
helper.test('buildPrincipalArn - user principal', function (t) {
    var arn = stsClient._buildPrincipalArn(alicePrincipal);
    t.equal(arn, 'arn:manta:iam::123456789012:user/alice',
            'should build correct user ARN');
    t.end();
});

helper.test('buildPrincipalArn - service principal', function (t) {
    var arn = stsClient._buildPrincipalArn(servicePrincipal);
    t.equal(arn,
            'arn:manta:iam::123456789012:service/ec2.amazonaws.com',
            'should build correct service ARN');
    t.end();
});

// Test principal type detection
helper.test('getPrincipalType - user detection', function (t) {
    var type = stsClient._getPrincipalType(alicePrincipal);
    t.equal(type, 'user', 'should detect user type');
    t.end();
});

helper.test('getPrincipalType - service detection', function (t) {
    var type = stsClient._getPrincipalType(servicePrincipal);
    t.equal(type, 'service', 'should detect service type');
    t.end();
});

// Test edge cases
helper.test('validateRole - malformed trust policy JSON', function (t) {
    // Mock role with invalid JSON
    stsClient.iamClient.getRole = function (getRoleOpts, callback) {
        callback(null, {
            name: 'bad-json-role',
            arn: 'arn:manta:iam::123456789012:role/bad-json-role',
            assumeRolePolicyDocument: '{invalid json'
        });
    };

    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/bad-json-role',
        caller: alicePrincipal,
        sourceIp: '192.168.1.100',
        userAgent: 'test-agent'
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ok(err, 'should error for malformed JSON');
        t.equal(err.name, 'AccessDenied', 'should be access denied');
        t.ok(err.message.indexOf('InvalidTrustPolicy') > -1,
             'should indicate invalid trust policy');
        t.end();
    });
});

// Test security validation
helper.test('security - null caller injection', function (t) {
    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/admin-role',
        caller: null,
        sourceIp: '192.168.1.100',
        userAgent: 'test-agent'
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ok(err, 'should error for null caller');
        t.end();
    });
});

helper.test('security - undefined context values', function (t) {
    var opts = {
        roleArn: 'arn:manta:iam::123456789012:role/conditional-role',
        caller: alicePrincipal,
        sourceIp: undefined,
        userAgent: undefined,
        externalId: undefined
    };

    stsClient.validateRole(opts, function (err, result) {
        t.ok(err, 'should error with undefined context values');
        t.equal(err.name, 'AccessDenied', 'should be access denied');
        t.end();
    });
});
