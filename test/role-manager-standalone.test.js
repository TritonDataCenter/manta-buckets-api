/*
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * role-manager-standalone.test.js: Standalone unit
 * tests for role-manager module without dependencies
 */

var roleManager =
    require('../lib/auth/role-manager');


///--- Tests

exports['makeStarRule creates correct rule structure'] =
function (t) {
    var result = roleManager.makeStarRule('getobject');
    t.ok(Array.isArray(result));
    t.equal(result.length, 2);
    t.equal(result[0], 'CAN getobject *');
    t.ok(result[1]);
    t.equal(result[1].effect, true);
    t.ok(result[1].actions);
    t.ok(result[1].actions.exact);
    t.equal(result[1].actions.exact.getobject, true);
    t.ok(Array.isArray(result[1].actions.regex));
    t.equal(result[1].actions.regex.length, 0);
    t.ok(Array.isArray(result[1].conditions));
    t.equal(result[1].resources, 1);
    t.done();
};


exports['makeStarRule handles different actions'] =
function (t) {
    var result1 = roleManager.makeStarRule('putobject');
    var result2 = roleManager.makeStarRule('getdirectory');

    t.equal(result1[0], 'CAN putobject *');
    t.equal(result1[1].actions.exact.putobject, true);

    t.equal(result2[0], 'CAN getdirectory *');
    t.equal(result2[1].actions.exact.getdirectory,
        true);

    t.done();
};


exports['convertIAMRoleToMantaRole basic conversion'] =
function (t) {
    var iamRole = {
        RoleName: 'TestRole',
        RoleId: 'role-id-12345',
        PermissionPolicies: [
            {
                PolicyName: 'TestPolicy',
                mantaPolicyName: 'manta-policy-1'
            }
        ]
    };

    var result = roleManager.convertIAMRoleToMantaRole(
        iamRole,
        'account-uuid-123');

    t.ok(result);
    t.equal(result.name, 'TestRole');
    t.equal(result.uuid, 'role-id-12345');
    t.equal(result.account, 'account-uuid-123');
    t.equal(result.type, 'role');
    t.ok(Array.isArray(result.policies));
    t.equal(result.policies.length, 1);
    t.equal(result.policies[0], 'manta-policy-1');
    t.ok(Array.isArray(result.members));
    t.ok(Array.isArray(result.default_members));
    t.done();
};


exports['convertIAMRoleToMantaRole multiple policies'] =
function (t) {
    var iamRole = {
        RoleName: 'MultiPolicyRole',
        RoleId: 'role-id-multi',
        PermissionPolicies: [
            {
                PolicyName: 'Policy1',
                mantaPolicyName: 'manta-policy-1'
            },
            {
                PolicyName: 'Policy2',
                mantaPolicyName: 'manta-policy-2'
            },
            {
                PolicyName: 'Policy3',
                mantaPolicyName: 'manta-policy-3'
            }
        ]
    };

    var result = roleManager.convertIAMRoleToMantaRole(
        iamRole,
        'account-uuid-456');

    t.equal(result.policies.length, 3);
    t.equal(result.policies[0], 'manta-policy-1');
    t.equal(result.policies[1], 'manta-policy-2');
    t.equal(result.policies[2], 'manta-policy-3');
    t.done();
};


exports['convertIAMRoleToMantaRole no policies'] =
function (t) {
    var iamRole = {
        RoleName: 'EmptyRole',
        RoleId: 'role-id-empty'
    };

    var result = roleManager.convertIAMRoleToMantaRole(
        iamRole,
        'account-uuid-789');

    t.ok(result);
    t.equal(result.name, 'EmptyRole');
    t.ok(Array.isArray(result.policies));
    t.equal(result.policies.length, 0);
    t.done();
};


exports['convertIAMRoleToMantaRole filters without' +
    ' mantaPolicyName'] =
function (t) {
    var iamRole = {
        RoleName: 'FilterRole',
        RoleId: 'role-id-filter',
        PermissionPolicies: [
            {
                PolicyName: 'ValidPolicy',
                mantaPolicyName: 'manta-policy-valid'
            },
            {
                PolicyName: 'InvalidPolicy'
                // No mantaPolicyName
            },
            {
                PolicyName: 'AnotherValid',
                mantaPolicyName: 'manta-policy-valid-2'
            }
        ]
    };

    var result = roleManager.convertIAMRoleToMantaRole(
        iamRole,
        'account-uuid-filter');

    t.equal(result.policies.length, 2);
    t.equal(result.policies[0], 'manta-policy-valid');
    t.equal(result.policies[1], 'manta-policy-valid-2');
    t.done();
};


exports['makeGlobalReaderRole structure'] =
function (t) {
    var result = roleManager.makeGlobalReaderRole(
        'account-uuid-reader');

    t.ok(result);
    t.equal(result.type, 'role');
    t.equal(result.uuid,
        '76b9ad78-5351-45a3-89f3-b6b48482ed65');
    t.equal(result.name, '_global_readers');
    t.equal(result.account, 'account-uuid-reader');
    t.ok(Array.isArray(result.rules));
    t.done();
};


exports['makeGlobalReaderRole rules'] = function (t) {
    var result = roleManager.makeGlobalReaderRole(
        'account-uuid-test');

    t.equal(result.rules.length, 4);

    // Check each rule is properly formatted
    result.rules.forEach(function (rule) {
        t.ok(Array.isArray(rule));
        t.equal(rule.length, 2);
        t.ok(typeof (rule[0]) === 'string');
        t.ok(rule[0].indexOf('CAN ') === 0);
        t.ok(rule[1]);
        t.equal(rule[1].effect, true);
    });

    // Check specific actions are included
    var ruleStrings = result.rules.map(function (r) {
        return (r[0]);
    });
    t.ok(ruleStrings.indexOf('CAN getobject *') !== -1);
    t.ok(ruleStrings.indexOf('CAN getdirectory *') !==
        -1);
    t.ok(ruleStrings.indexOf('CAN listjobs *') !== -1);
    t.ok(ruleStrings.indexOf('CAN getjob *') !== -1);

    t.done();
};


exports['makeGlobalReaderRole consistent UUID'] =
function (t) {
    var result1 = roleManager.makeGlobalReaderRole(
        'account-1');
    var result2 = roleManager.makeGlobalReaderRole(
        'account-2');

    // UUID should be the same for all global reader
    // roles
    t.equal(result1.uuid, result2.uuid);
    t.equal(result1.uuid,
        '76b9ad78-5351-45a3-89f3-b6b48482ed65');

    t.done();
};
