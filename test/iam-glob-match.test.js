/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Unit tests for MANTA-5516: IAM glob matching.
 *
 * Verifies that iamGlobMatch implements AWS IAM wildcard semantics
 * (* and ? only) and that special characters are treated as literals.
 */

var iamEngine = require('../lib/iam-policy-engine');

var iamGlobMatch = iamEngine.iamGlobMatch;

// Mock logger for evaluatePermissionPolicies
var mockLog = {
    debug: function () {},
    error: function () {},
    warn: function () {}
};


///--- iamGlobMatch unit tests

exports['iamGlobMatch: exact match'] = function (t) {
    t.ok(iamGlobMatch('s3:GetObject', 's3:GetObject'));
    t.ok(!iamGlobMatch('s3:GetObject', 's3:PutObject'));
    t.done();
};

exports['iamGlobMatch: * matches everything'] = function (t) {
    t.ok(iamGlobMatch('*', ''));
    t.ok(iamGlobMatch('*', 's3:GetObject'));
    t.ok(iamGlobMatch('*', 'anything at all'));
    t.done();
};

exports['iamGlobMatch: * at end matches suffix'] = function (t) {
    t.ok(iamGlobMatch('s3:*', 's3:GetObject'));
    t.ok(iamGlobMatch('s3:*', 's3:PutObject'));
    t.ok(iamGlobMatch('s3:*', 's3:'));
    t.ok(!iamGlobMatch('s3:*', 'iam:CreateRole'));
    t.done();
};

exports['iamGlobMatch: * in middle matches any chars'] = function (t) {
    t.ok(iamGlobMatch('s3:Get*Object', 's3:GetObject'));
    t.ok(iamGlobMatch('s3:Get*Object', 's3:GetSomeObject'));
    t.ok(!iamGlobMatch('s3:Get*Object', 's3:PutObject'));
    t.done();
};

exports['iamGlobMatch: multiple *s'] = function (t) {
    t.ok(iamGlobMatch('s3:*Bucket*', 's3:ListBucket'));
    t.ok(iamGlobMatch('s3:*Bucket*', 's3:CreateBucketAcl'));
    t.ok(!iamGlobMatch('s3:*Bucket*', 's3:GetObject'));
    t.done();
};

exports['iamGlobMatch: ? matches exactly one char'] = function (t) {
    t.ok(iamGlobMatch('s3:Get?bject', 's3:GetObject'));
    t.ok(!iamGlobMatch('s3:Get?bject', 's3:Getbject'));
    t.ok(!iamGlobMatch('s3:Get?bject', 's3:GetABbject'));
    t.done();
};

exports['iamGlobMatch: combined * and ?'] = function (t) {
    t.ok(iamGlobMatch('s3:?et*', 's3:GetObject'));
    t.ok(iamGlobMatch('s3:?et*', 's3:SetBucketAcl'));
    // ? requires exactly one char before 'et'
    t.ok(!iamGlobMatch('s3:?et*', 's3:et'));
    t.done();
};

exports['iamGlobMatch: empty pattern and string'] = function (t) {
    t.ok(iamGlobMatch('', ''));
    t.ok(!iamGlobMatch('', 'notempty'));
    t.ok(!iamGlobMatch('notempty', ''));
    t.done();
};

exports['iamGlobMatch: special characters are literals'] = function (t) {
    // These chars should be plain literals in IAM glob matching
    t.ok(iamGlobMatch('a.b', 'a.b'));
    t.ok(!iamGlobMatch('a.b', 'axb'),
        '. must be literal');

    t.ok(iamGlobMatch('a+b', 'a+b'));
    t.ok(!iamGlobMatch('a+b', 'aab'),
        '+ must be literal');

    t.ok(iamGlobMatch('a[0]b', 'a[0]b'));
    t.ok(!iamGlobMatch('a[0]b', 'a0b'),
        '[] must be literal');

    t.ok(iamGlobMatch('a(b|c)', 'a(b|c)'));
    t.ok(!iamGlobMatch('a(b|c)', 'ab'),
        '() and | must be literal');

    t.ok(iamGlobMatch('a{2}', 'a{2}'));
    t.ok(!iamGlobMatch('a{2}', 'aa'),
        '{} must be literal');

    t.ok(iamGlobMatch('^abc$', '^abc$'));
    t.ok(!iamGlobMatch('^abc$', 'abc'),
        '^ and $ must be literal');

    t.ok(iamGlobMatch('a\\b', 'a\\b'));
    t.ok(!iamGlobMatch('a\\b', 'ab'),
        'backslash must be literal');
    t.done();
};

exports['iamGlobMatch: resource ARN patterns'] = function (t) {
    t.ok(iamGlobMatch('arn:aws:s3:::mybucket/*',
        'arn:aws:s3:::mybucket/foo.txt'));
    t.ok(iamGlobMatch('arn:aws:s3:::mybucket/*',
        'arn:aws:s3:::mybucket/dir/file.txt'));
    t.ok(!iamGlobMatch('arn:aws:s3:::mybucket/*',
        'arn:aws:s3:::otherbucket/foo.txt'));
    t.ok(iamGlobMatch('arn:aws:s3:::*',
        'arn:aws:s3:::mybucket'));
    t.done();
};


///--- Integration: special characters in policy patterns

exports['MANTA-5516: dot-star in action pattern treated as literal'] =
function (t) {
    // "s3:.*" as a glob means literal dot followed by any chars,
    // so it should NOT match "s3:GetObject".
    var policy = {
        Statement: [ {
            Effect: 'Allow',
            Action: 's3:.*',
            Resource: '*'
        } ]
    };

    var result = iamEngine.evaluatePermissionPolicies(
        [JSON.stringify(policy)], 's3:GetObject', '*', mockLog);
    t.ok(!result, 's3:.* must not match s3:GetObject (dot is literal)');
    t.done();
};

exports['MANTA-5516: dot-star in resource pattern treated as literal'] =
function (t) {
    var policy = {
        Statement: [ {
            Effect: 'Allow',
            Action: '*',
            Resource: 'arn:aws:s3:::.*'
        } ]
    };

    var result = iamEngine.evaluatePermissionPolicies(
        [JSON.stringify(policy)], 's3:GetObject',
        'arn:aws:s3:::mybucket', mockLog);
    t.ok(!result,
        'arn:aws:s3:::.* must not match bucket ARN (dot is literal)');
    t.done();
};

exports['MANTA-5516: legitimate s3:* wildcard still works'] =
function (t) {
    var policy = {
        Statement: [ {
            Effect: 'Allow',
            Action: 's3:*',
            Resource: '*'
        } ]
    };

    var result = iamEngine.evaluatePermissionPolicies(
        [JSON.stringify(policy)], 's3:GetObject',
        'arn:aws:s3:::mybucket', mockLog);
    t.ok(result, 's3:* should match any s3 action');
    t.done();
};

exports['MANTA-5516: s3:Get* matches Get actions only'] = function (t) {
    var policy = {
        Statement: [ {
            Effect: 'Allow',
            Action: 's3:Get*',
            Resource: '*'
        } ]
    };

    var allowGet = iamEngine.evaluatePermissionPolicies(
        [JSON.stringify(policy)], 's3:GetObject', '*', mockLog);
    t.ok(allowGet, 's3:Get* should match s3:GetObject');

    var denyPut = iamEngine.evaluatePermissionPolicies(
        [JSON.stringify(policy)], 's3:PutObject', '*', mockLog);
    t.ok(!denyPut, 's3:Get* should not match s3:PutObject');
    t.done();
};

exports['MANTA-5516: ? wildcard in action matching'] = function (t) {
    var policy = {
        Statement: [ {
            Effect: 'Allow',
            Action: 's3:?etObject',
            Resource: '*'
        } ]
    };

    var allowGet = iamEngine.evaluatePermissionPolicies(
        [JSON.stringify(policy)], 's3:GetObject', '*', mockLog);
    t.ok(allowGet, 's3:?etObject should match s3:GetObject');

    var allowSet = iamEngine.evaluatePermissionPolicies(
        [JSON.stringify(policy)], 's3:SetObject', '*', mockLog);
    // 'S' is one char so ?etObject matches SetObject
    t.ok(allowSet, 's3:?etObject should match s3:SetObject');

    var denyList = iamEngine.evaluatePermissionPolicies(
        [JSON.stringify(policy)], 's3:ListBucket', '*', mockLog);
    t.ok(!denyList, 's3:?etObject should not match s3:ListBucket');
    t.done();
};

exports['MANTA-5516: resource ARN with wildcard path'] = function (t) {
    var policy = {
        Statement: [ {
            Effect: 'Allow',
            Action: 's3:GetObject',
            Resource: 'arn:aws:s3:::mybucket/*'
        } ]
    };

    var allowObj = iamEngine.evaluatePermissionPolicies(
        [JSON.stringify(policy)], 's3:GetObject',
        'arn:aws:s3:::mybucket/foo.txt', mockLog);
    t.ok(allowObj, 'mybucket/* should match mybucket/foo.txt');

    var denyOther = iamEngine.evaluatePermissionPolicies(
        [JSON.stringify(policy)], 's3:GetObject',
        'arn:aws:s3:::otherbucket/foo.txt', mockLog);
    t.ok(!denyOther, 'mybucket/* should not match otherbucket/foo.txt');
    t.done();
};

exports['MANTA-5516: explicit deny with glob still works'] =
function (t) {
    var policy = {
        Statement: [
            {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
            },
            {
                Effect: 'Deny',
                Action: 's3:Delete*',
                Resource: '*'
            }
        ]
    };

    var allowGet = iamEngine.evaluatePermissionPolicies(
        [JSON.stringify(policy)], 's3:GetObject', '*', mockLog);
    t.ok(allowGet, 'Allow s3:* should permit GetObject');

    var denyDelete = iamEngine.evaluatePermissionPolicies(
        [JSON.stringify(policy)], 's3:DeleteObject', '*', mockLog);
    t.ok(!denyDelete,
        'Deny s3:Delete* should override Allow s3:*');
    t.done();
};
