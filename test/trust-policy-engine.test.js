/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * Trust Policy Engine Tests
 *
 * Comprehensive tests for AWS STS trust policy evaluation engine
 * covering security controls, policy validation, and edge cases.
 */

var helper = require('./s3-test-helper.js');
var bunyan = require('bunyan');
var TrustPolicyEngine = require('../lib/trust-policy-engine').TrustPolicyEngine;

// Test logger
var LOG = bunyan.createLogger({
    name: 'trust-policy-engine-test',
    level: process.env.LOG_LEVEL || 'fatal'
});

// Test fixtures
var validTrustPolicy = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Principal': {
                'AWS': 'arn:aws:iam::123456789012:user/alice'
            },
            'Action': 'sts:AssumeRole'
        }
    ]
};

var conditionalTrustPolicy = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Principal': {
                'AWS': 'arn:aws:iam::123456789012:user/alice'
            },
            'Action': 'sts:AssumeRole',
            'Condition': {
                'StringEquals': {
                    'sts:ExternalId': 'secret-key-123'
                },
                'Bool': {
                    'aws:MultiFactorAuthPresent': 'true'
                },
                'IpAddress': {
                    'aws:SourceIp': '192.168.1.100'
                }
            }
        }
    ]
};

var denyPolicy = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Deny',
            'Principal': {
                'AWS': 'arn:aws:iam::123456789012:user/bob'
            },
            'Action': 'sts:AssumeRole'
        },
        {
            'Effect': 'Allow',
            'Principal': '*',
            'Action': 'sts:AssumeRole'
        }
    ]
};

var servicePrincipalPolicy = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Principal': {
                'Service': ['ec2.amazonaws.com', 'lambda.amazonaws.com']
            },
            'Action': 'sts:AssumeRole'
        }
    ]
};

var accountPrincipalPolicy = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Principal': {
                'AWS': 'arn:aws:iam::123456789012:root'
            },
            'Action': 'sts:AssumeRole'
        }
    ]
};

// Test principals
var alicePrincipal = {
    arn: 'arn:aws:iam::123456789012:user/alice',
    account: '123456789012',
    type: 'user',
    userId: 'alice-uuid',
    userName: 'alice'
};

var bobPrincipal = {
    arn: 'arn:aws:iam::123456789012:user/bob',
    account: '123456789012',
    type: 'user',
    userId: 'bob-uuid',
    userName: 'bob'
};

var servicePrincipal = {
    arn: 'arn:aws:iam::123456789012:service/ec2.amazonaws.com',
    account: '123456789012',
    type: 'service',
    service: 'ec2.amazonaws.com'
};

var outsideAccountPrincipal = {
    arn: 'arn:aws:iam::999999999999:user/mallory',
    account: '999999999999',
    type: 'user',
    userId: 'mallory-uuid',
    userName: 'mallory'
};

// Test context
var baseContext = {
    sourceIp: '192.168.1.100',
    requestTime: new Date('2023-01-01T12:00:00Z'),
    mfa: true,
    externalId: 'secret-key-123',
    userAgent: 'test-agent'
};

// Initialize test engine
var engine;

helper.test('setup', function (t) {
    engine = new TrustPolicyEngine({
        log: LOG,
        strictMode: true
    });
    t.ok(engine, 'engine created');
    t.end();
});

// Policy structure validation tests
helper.test('policy validation - valid policy', function (t) {
    var result = engine.evaluate(validTrustPolicy, alicePrincipal, baseContext);
    t.equal(result.decision, 'Allow', 'valid policy should be accepted');
    t.end();
});

helper.test('policy validation - missing version', function (t) {
    var invalidPolicy = {
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': '*'},
                'Action': 'sts:AssumeRole'
            }
        ]
    };
    var result = engine.evaluate(invalidPolicy, alicePrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'should deny for missing version');
    t.equal(result.reason, 'InvalidPolicyDocument',
            'should indicate invalid document');
    t.end();
});

helper.test('policy validation - unsupported version', function (t) {
    var invalidPolicy = {
        'Version': '2020-01-01',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': '*'},
                'Action': 'sts:AssumeRole'
            }
        ]
    };
    var result = engine.evaluate(invalidPolicy, alicePrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'should deny for unsupported version');
    t.end();
});

helper.test('policy validation - missing statement', function (t) {
    var invalidPolicy = {
        'Version': '2012-10-17'
    };
    var result = engine.evaluate(invalidPolicy, alicePrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'should deny for missing statement');
    t.end();
});

helper.test('policy validation - empty statement array', function (t) {
    var invalidPolicy = {
        'Version': '2012-10-17',
        'Statement': []
    };
    var result = engine.evaluate(invalidPolicy, alicePrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'should deny for empty statement array');
    t.end();
});

// Principal matching tests
helper.test('principal matching - exact ARN match', function (t) {
    var result = engine.evaluate(validTrustPolicy, alicePrincipal, baseContext);
    t.equal(result.decision, 'Allow', 'should allow exact ARN match');
    t.equal(result.reason, 'ExplicitAllow', 'should be explicit allow');
    t.end();
});

helper.test('principal matching - no match', function (t) {
    var result = engine.evaluate(validTrustPolicy, bobPrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'should deny non-matching principal');
    t.equal(result.reason, 'ImplicitDeny', 'should be implicit deny');
    t.end();
});

helper.test('principal matching - wildcard principal', function (t) {
    var wildcardPolicy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': '*',
                'Action': 'sts:AssumeRole'
            }
        ]
    };
    var result = engine.evaluate(wildcardPolicy, alicePrincipal, baseContext);
    t.equal(result.decision, 'Allow', 'should allow wildcard principal');
    t.end();
});

helper.test('principal matching - account root match', function (t) {
    var result = engine.evaluate(accountPrincipalPolicy, alicePrincipal,
                                  baseContext);
    t.equal(result.decision, 'Allow', 'should allow account root match');
    t.end();
});

helper.test('principal matching - account root no match', function (t) {
    var result = engine.evaluate(accountPrincipalPolicy,
                                 outsideAccountPrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'should deny outside account');
    t.end();
});

helper.test('principal matching - service principal match', function (t) {
    var result = engine.evaluate(servicePrincipalPolicy,
                                 servicePrincipal, baseContext);
    t.equal(result.decision, 'Allow',
            'should allow matching service principal');
    t.end();
});

helper.test('principal matching - service principal no match', function (t) {
    var result = engine.evaluate(servicePrincipalPolicy,
                                 alicePrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'should deny user when service required');
    t.end();
});

// Action matching tests
helper.test('action matching - exact match', function (t) {
    var result = engine.evaluate(validTrustPolicy,
                                 alicePrincipal, baseContext);
    t.equal(result.decision, 'Allow', 'should match exact action');
    t.end();
});

helper.test('action matching - wildcard action', function (t) {
    var wildcardActionPolicy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': alicePrincipal.arn},
                'Action': '*'
            }
        ]
    };
    var result = engine.evaluate(wildcardActionPolicy,
                                 alicePrincipal, baseContext);
    t.equal(result.decision, 'Allow', 'should match wildcard action');
    t.end();
});

helper.test('action matching - service wildcard', function (t) {
    var serviceWildcardPolicy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': alicePrincipal.arn},
                'Action': 'sts:*'
            }
        ]
    };
    var result = engine.evaluate(serviceWildcardPolicy,
                                 alicePrincipal, baseContext);
    t.equal(result.decision, 'Allow', 'should match service wildcard');
    t.end();
});

// Condition evaluation tests
helper.test('conditions - all conditions pass', function (t) {
    var result = engine.evaluate(conditionalTrustPolicy,
                                 alicePrincipal, baseContext);
    t.equal(result.decision, 'Allow', 'should allow when all conditions pass');
    t.end();
});

helper.test('conditions - external ID mismatch', function (t) {
    var badContext = Object.assign({}, baseContext, {externalId: 'wrong-key'});
    var result = engine.evaluate(conditionalTrustPolicy, alicePrincipal,
                                  badContext);
    t.equal(result.decision, 'Deny', 'should deny when external ID mismatches');
    t.end();
});

helper.test('conditions - MFA not present', function (t) {
    var badContext = Object.assign({}, baseContext, {mfa: false});
    var result = engine.evaluate(conditionalTrustPolicy, alicePrincipal,
                                  badContext);
    t.equal(result.decision, 'Deny', 'should deny when MFA not present');
    t.end();
});

helper.test('conditions - IP address mismatch', function (t) {
    var badContext = Object.assign({}, baseContext, {sourceIp: '10.0.0.1'});
    var result = engine.evaluate(conditionalTrustPolicy, alicePrincipal,
                                  badContext);
    t.equal(result.decision, 'Deny', 'should deny when IP mismatches');
    t.end();
});

helper.test('conditions - missing context value', function (t) {
    var badContext = Object.assign({}, baseContext);
    delete badContext.externalId;
    var result = engine.evaluate(conditionalTrustPolicy, alicePrincipal,
                                  badContext);
    t.equal(result.decision, 'Deny', 'should deny when context value missing');
    t.end();
});

// AWS policy evaluation logic tests
helper.test('evaluation logic - explicit deny wins', function (t) {
    var result = engine.evaluate(denyPolicy, bobPrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'explicit deny should win over allow');
    t.equal(result.reason, 'ExplicitDeny', 'should indicate explicit deny');
    t.end();
});

helper.test('evaluation logic - allow when no deny', function (t) {
    var result = engine.evaluate(denyPolicy, alicePrincipal, baseContext);
    t.equal(result.decision, 'Allow', 'should allow when no deny matches');
    t.end();
});

helper.test('evaluation logic - implicit deny by default', function (t) {
    var noMatchPolicy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': 'arn:aws:iam::123456789012:user/charlie'},
                'Action': 'sts:AssumeRole'
            }
        ]
    };
    var result = engine.evaluate(noMatchPolicy, alicePrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'should deny by default');
    t.equal(result.reason, 'ImplicitDeny', 'should be implicit deny');
    t.end();
});

// Complex condition tests
helper.test('conditions - string like wildcard match', function (t) {
    var wildcardConditionPolicy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': alicePrincipal.arn},
                'Action': 'sts:AssumeRole',
                'Condition': {
                    'StringLike': {
                        'sts:ExternalId': 'secret-key-*'
                    }
                }
            }
        ]
    };
    var result = engine.evaluate(wildcardConditionPolicy,
                                 alicePrincipal, baseContext);
    t.equal(result.decision, 'Allow', 'should match wildcard pattern');
    t.end();
});

helper.test('conditions - date greater than', function (t) {
    var dateConditionPolicy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': alicePrincipal.arn},
                'Action': 'sts:AssumeRole',
                'Condition': {
                    'DateGreaterThan': {
                        'aws:RequestTime': '2022-12-31T23:59:59Z'
                    }
                }
            }
        ]
    };
    var result = engine.evaluate(dateConditionPolicy,
                                 alicePrincipal, baseContext);
    t.equal(result.decision, 'Allow',
            'should pass date greater than condition');
    t.end();
});

// Error handling tests
helper.test('error handling - invalid policy structure', function (t) {
    var malformedPolicy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                // Missing Effect
                'Principal': {'AWS': alicePrincipal.arn},
                'Action': 'sts:AssumeRole'
            }
        ]
    };
    var result = engine.evaluate(malformedPolicy, alicePrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'should deny malformed policy');
    t.equal(result.reason, 'InvalidPolicyDocument',
            'should indicate invalid document');
    t.end();
});

helper.test('error handling - exception during evaluation', function (t) {
    // Force an error by passing invalid principal
    var result = engine.evaluate(validTrustPolicy, null, baseContext);
    t.equal(result.decision, 'Deny', 'should deny on evaluation error');
    t.equal(result.reason, 'EvaluationError',
            'should indicate evaluation error');
    t.end();
});

// Security edge cases
helper.test('security - null principal injection', function (t) {
    var nullPrincipal = {
        arn: null,
        account: '123456789012',
        type: 'user'
    };
    var result = engine.evaluate(validTrustPolicy, nullPrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'should deny null principal');
    t.end();
});

helper.test('security - empty context', function (t) {
    var result = engine.evaluate(conditionalTrustPolicy, alicePrincipal, {});
    t.equal(result.decision, 'Deny', 'should deny with empty context');
    t.end();
});

helper.test('security - condition type injection', function (t) {
    var maliciousPolicy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': alicePrincipal.arn},
                'Action': 'sts:AssumeRole',
                'Condition': {
                    'UnsupportedCondition': {
                        'key': 'value'
                    }
                }
            }
        ]
    };
    var result = engine.evaluate(maliciousPolicy, alicePrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'should deny unsupported condition type');
    t.end();
});

// Performance and robustness tests
helper.test('robustness - large policy document', function (t) {
    var largePolicy = {
        'Version': '2012-10-17',
        'Statement': []
    };

    // Add 100 statements to test performance
    for (var i = 0; i < 100; i++) {
        largePolicy.Statement.push({
            'Effect': i === 99 ? 'Allow' : 'Deny',  // Last one allows
            'Principal': {
                'AWS': 'arn:aws:iam::123456789012:user/user' + i
            },
            'Action': 'sts:AssumeRole'
        });
    }

    var result = engine.evaluate(largePolicy, alicePrincipal, baseContext);
    t.equal(result.decision, 'Deny', 'should handle large policy document');
    t.end();
});

helper.test('robustness - deep condition nesting', function (t) {
    var deepConditionPolicy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': alicePrincipal.arn},
                'Action': 'sts:AssumeRole',
                'Condition': {
                    'StringEquals': {
                        'key1': 'value1',
                        'key2': 'value2',
                        'key3': 'value3'
                    },
                    'Bool': {
                        'aws:MultiFactorAuthPresent': 'true'
                    },
                    'IpAddress': {
                        'aws:SourceIp': '192.168.1.100'
                    }
                }
            }
        ]
    };

    var complexContext = Object.assign({}, baseContext, {
        key1: 'value1',
        key2: 'value2',
        key3: 'value3'
    });

    var result = engine.evaluate(deepConditionPolicy, alicePrincipal,
                                  complexContext);
    t.equal(result.decision, 'Allow', 'should handle complex conditions');
    t.end();
});
