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
 * role-manager.js: Role management utilities for IAM
 * and Manta roles.
 *
 * Provides functions to load, convert, and manage roles
 * including assumed IAM roles, global reader roles, and
 * active role selection for requests.
 */

var IAMClient = require('../iam-client');
var errors = require('../errors');


///--- Functions

/**
 * Helper for makeGlobalReaderRole(). Makes a 'CAN
 * action *' aperture rule.
 *
 * @param {String} action - Action name
 * @return {Array} Aperture rule tuple
 */
function makeStarRule(action) {
    var exact = {};
    exact[action] = true;
    return ([
        'CAN ' + action + ' *',
        {
            effect: true,
            actions: { exact: exact, regex: [] },
            conditions: [],
            resources: 1
        }
    ]);
}


/**
 * Convert IAM role to Manta role format
 *
 * @param {Object} iamRole - IAM role object
 * @param {String} accountUuid - Account UUID
 * @return {Object} Manta role object
 */
function convertIAMRoleToMantaRole(iamRole, accountUuid) {
    // Extract permission policies from the IAM role
    // (NOT trust policies)
    var policies = [];

    // Use permission policies attached to the role
    // via PutRolePolicy
    if (iamRole.PermissionPolicies &&
        Array.isArray(iamRole.PermissionPolicies)) {
        // Each permission policy should have been
        // converted to a Manta policy
        iamRole.PermissionPolicies.forEach(
            function (permissionPolicy) {
            if (permissionPolicy.mantaPolicyName) {
                policies.push(
                    permissionPolicy.mantaPolicyName);
            }
        });
    }

    // If no permission policies, the role has no
    // permissions (principle of least privilege)
    // This is correct - roles without explicit
    // permissions should deny access
    // No fallback policies are created to ensure
    // security

    var mantaRole = {
        name: iamRole.RoleName,
        uuid: iamRole.RoleId,
        account: accountUuid,
        type: 'role',
        policies: policies,
        members: [],
        default_members: []
    };

    return (mantaRole);
}


/**
 * Generate a fake role that provides global read-only
 * access. Used to implement the special 'readers' group
 * in getActiveRoles().
 *
 * @param {String} acctuuid - Account UUID
 * @return {Object} Global reader role object
 */
function makeGlobalReaderRole(acctuuid) {
    return ({
        type: 'role',
        /*
         * This uuid and name are arbitrary and fixed
         * -- if they collide with a role added by an
         * actual user, things will probably not work.
         * Don't do that.
         */
        uuid: '76b9ad78-5351-45a3-89f3-b6b48482ed65',
        name: '_global_readers',
        account: acctuuid,
        /*
         * If we add any new actions that are
         * "read-only", they need to be listed here.
         */
        rules: [
            'getobject', 'getdirectory', 'listjobs',
            'getjob'
        ].map(makeStarRule)
    });
}


/**
 * Load and convert an assumed IAM role to Manta role
 * format. This is called when processing requests with
 * STS temporary credentials.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Callback function
 */
function loadAssumedRole(req, res, next) {
    var assumedRoleData = req.auth.assumedRole;
    var roleArn = (typeof (assumedRoleData) ===
        'string') ?
        assumedRoleData : assumedRoleData.arn;
    var log = req.log;

    // Parse role name from ARN (multi-cloud support)
    var roleName = null;
    // Support arn:aws:iam::, arn:manta:iam::,
    // arn:triton:iam::
    if (roleArn && (roleArn.indexOf('arn:aws:iam::') ===
                        0 ||
                    roleArn.indexOf('arn:manta:iam::') ===
                        0 ||
                    roleArn.indexOf('arn:triton:iam::') ===
                        0)) {
        var arnParts = roleArn.split(':');
        if (arnParts.length >= 6) {
            roleName = arnParts[5].replace('role/', '');
        }
    }

    if (!roleName) {
        log.debug({roleArn: roleArn},
            'AUTH_DEBUG: Invalid role ARN format');
        return (next(new Error('Invalid role ARN')));
    }

    log.debug({
        roleArn: roleArn,
        roleName: roleName,
        callerUuid: req.caller.account.uuid
    }, 'AUTH_DEBUG: Loading assumed IAM role');

    // Create IAM client to fetch role details
    var iamClient = new IAMClient({
        url: req.config ?
            req.config.auth.url :
            'http://authcache.coal.joyent.us',
        log: log,
        connectTimeout: 1000,
        requestTimeout: 10000
    });

    // Get the IAM role details
    iamClient.getRole({
        roleName: roleName,
        caller: req.caller
    }, function (err, roleData) {
        if (err) {
            log.debug({
                err: err,
                roleName: roleName,
                roleArn: roleArn
            }, 'AUTH_DEBUG:' +
               ' Failed to load assumed role (role' +
               ' may not exist yet)');

            // For missing roles during tests, just
            // continue without the role
            // This handles the case where tests
            // assume roles that don't exist yet
            return (next());
        }

        log.debug({
            roleName: roleName,
            roleData: roleData
        }, 'AUTH_DEBUG: Loaded IAM role,' +
           ' converting to Manta role');

        // Convert IAM role to Manta role format
        var mantaRole = convertIAMRoleToMantaRole(
            roleData.Role,
            req.caller.account.uuid);

        // Add the converted role to the caller's
        // available roles
        req.caller.roles = req.caller.roles || {};
        req.caller.roles[mantaRole.uuid] = mantaRole;

        // Set the active roles to only include this
        // assumed role UUID
        req.activeRoles = [mantaRole.uuid];

        log.debug({
            roleName: roleName,
            roleArn: roleArn,
            mantaRoleName: mantaRole.name,
            mantaRoleUuid: mantaRole.uuid,
            policies: mantaRole.policies
        }, 'AUTH_DEBUG: Successfully loaded and' +
           ' converted assumed role');

        next();
    });
}


/**
 * Determine the active roles for the request.
 * If the request used token auth, roles from the
 * token override any other requested roles (from
 * headers, presigned URL). The token is created by
 * muskie so the roles in the token have already been
 * verified.
 * Then, check the roles from the URL or headers, if
 * present (with ones from the URL taking precedence).
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Callback function
 */
function getActiveRoles(req, res, next) {
    if (req.auth.token && req.auth.token.conditions) {
        var conds = req.auth.token.conditions;
        /*
         * Merge same-account and cross-account roles from auth tokens.
         * NOTE: Cross-account roles are tracked but not supported for
         * authorization in manta-buckets-api due to Manta's single-account
         * RBAC model. Manta's architecture requires resources to be owned
         * by a single account, and the authorization system (libmantalite)
         * only evaluates roles within the resource owner's account.
         * Cross-account roles are preserved here for:
         * 1. Token compatibility with other Manta services
         * 2. Maintaining standard Manta auth token structure
         * 3. Proper error detection when cross-account access is attempted
         */
        req.activeRoles = (conds.activeRoles ||
            []).concat(
            conds.activeXAcctRoles || []);
        setImmediate(next);
        return;
    }

    // Handle temporary credentials with assumed
    // roles (STS)
    if (req.auth && req.auth.isTemporaryCredential &&
        req.auth.assumedRole) {
        req.log.debug({
            assumedRole: req.auth.assumedRole,
            principalUuid: req.auth.principalUuid,
            accessKeyId: req.auth.accessKeyId
        }, 'AUTH_DEBUG: Handling assumed role for' +
           ' temporary credentials');

        // Load the IAM role and convert to Manta
        // role
        return (loadAssumedRole(req, res, next));
    }

    var requestedRoles;

    if (req.auth &&
        typeof (req.auth.role) === 'string') { // from URL
        requestedRoles = req.auth.role;
    } else {
        requestedRoles = req.headers['role'];
    }

    var caller = req.caller;
    var owner = req.owner;

    var isRoleOper = false, isGlobalReader = false;
    if (caller.account.groups) {
        if (caller.account.groups.indexOf(
                'role-operators') !== -1) {
            isRoleOper = true;
        }
        if (caller.account.groups.indexOf('readers') !==
            -1) {
            isGlobalReader = true;
        }
    }

    /*
     * Check if we need to do per-request req.caller,
     * either for role-operator or global read-only.
     */
    if (isRoleOper || isGlobalReader) {
        /*
         * The req.caller object is cached and potentially shared between
         * multiple requests. We're either going to alter the roles or the
         * isOperator flag on req.caller.account on a per-request basis,
         * so we need a per-request copy of req.caller, req.caller.account
         * and req.caller.roles.
         *
         * We can keep sharing all the other child objects of req.caller
         * other than req.caller.account and req.caller.roles (i.e. we
         * don't have to do a full deep copy), because we're not changing
         * those.
         */
        var newCaller = {};
        Object.keys(caller).forEach(function (k) {
            newCaller[k] = caller[k];
        });
        var newAccount = {};
        Object.keys(caller.account).forEach(function (k) {
            newAccount[k] = caller.account[k];
        });
        var newRoles = {};
        Object.keys(caller.roles).forEach(function (k) {
            newRoles[k] = caller.roles[k];
        });
        newCaller.account = newAccount;
        newCaller.roles = newRoles;
        req.caller = newCaller;
        caller = newCaller;
    }

    /*
     * Handle the special _operator role if the user
     * is a member of the "role-operators" group (this
     * overrides the regular isOperator status, if
     * present).
     */
    if (isRoleOper) {
        /*
         * Since they're in role-operators, make them
         * always non-operator unless the Role header
         * is provided.
         */
        caller.account.isOperator = false;

        /*
         * We treat a Role header value of "_operator"
         * basically as a magic value. If we have it,
         * we skip all further role processing (since
         * we're just going to authorize this request
         * using our operator rights anyway).
         */
        if (requestedRoles === '_operator') {
            caller.account.isOperator = true;
            setImmediate(next);
            return;
        }
    }

    /*
     * Handle global read-only access (membership in
     * the 'readers' group) by generating a 'fake'
     * role here with a well-known UUID.
     */
    var readerRole;
    if (isGlobalReader) {
        readerRole = makeGlobalReaderRole(
            owner.account.uuid);
        caller.roles[readerRole.uuid] = readerRole;
    }

    var activeRoles = [];

    if (requestedRoles) {   // The user passed in roles
                            // to assume
        /*
         * We only support role='*' for sub-users and
         * roles within the account. Cross-account
         * roles have to be taken up by name or made
         * default.
         */
        if (requestedRoles  === '*' && caller.user) {
            activeRoles = caller.user.roles || [];
            req.activeRoles = activeRoles;
            req.authContext.conditions.activeRoles =
                activeRoles;
            setImmediate(next);

            return;
        }

        var lookup = {};
        for (var uuid in caller.roles) {
            var role = caller.roles[uuid];
            if (lookup[role.name] === undefined) {
                lookup[role.name] = [];
            }
            lookup[role.name].push(uuid);
        }

        var i, names;
        /* JSSTYLED */
        names = requestedRoles.split(/\s*,\s*/);
        for (i = 0; i < names.length; ++i) {
            var roles = lookup[names[i]];
            if (roles === undefined || roles.length < 1) {
                var InvalidRoleError = errors.InvalidRoleError;
                next(new InvalidRoleError(names[i]));
                return;
            }
            activeRoles = activeRoles.concat(roles);
        }
        if (readerRole) {
            activeRoles.push(readerRole.uuid);
        }
        req.activeRoles = activeRoles;
        setImmediate(next);
    } else {                // No explicit roles, use
                            // default set
        /*
         * Sub-users don't get any default
         * cross-account roles, only the ones within
         * their account.
         */
        if (caller.user) {
            activeRoles = caller.user.defaultRoles || [];
        } else {
            activeRoles = caller.account.defaultRoles ||
                [];
        }
        if (readerRole) {
            /*
             * Make a copy of activeRoles before we
             * push, so we don't modify the
             * defaultRoles on caller.user.
             */
            activeRoles = activeRoles.slice();
            activeRoles.push(readerRole.uuid);
        }
        req.activeRoles = activeRoles;
        setImmediate(next);
    }
}


///--- Exports

module.exports = {
    makeStarRule: makeStarRule,
    convertIAMRoleToMantaRole: convertIAMRoleToMantaRole,
    makeGlobalReaderRole: makeGlobalReaderRole,
    loadAssumedRole: loadAssumedRole,
    getActiveRoles: getActiveRoles
};
