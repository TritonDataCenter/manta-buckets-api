/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
 */

//
// Generate keys for the muskie config with:
//
// $ openssl enc -aes-128-cbc -k $(uuid) -P
// salt=C93A670ACC05C166
// key=5163205CA0C7F2752FD3A574E30F64DD
// iv=6B11F0F0B786F96812D5A0799D5B217A
//

var assert = require('assert-plus');
var httpSignature = require('http-signature');
var path = require('path');
var querystring = require('querystring');
var sprintf = require('util').format;
var vasync = require('vasync');

var libmantalite = require('./libmantalite');
var common = require('./common');
var s3Compat = require('./s3-compat');
var constants = require('./constants');
var tokenManager = require('./auth/token-manager');
var iamMapper = require('./auth/iam-mapper');
var roleManager = require('./auth/role-manager');
var signatureVerifier = require('./auth/signature-verifier');
require('./errors');


function parseKeyId(req, res, next) {
    // Skip parsing for S3 presigned URLs - they use different key format
    if (req._s3PresignedAuthComplete) {
        req.log.debug('parseKeyId: skipping' +
                      ' - S3 presigned URL uses different key format');
        next();
        return;
    }

    if (!req.auth.callerKey) {
        next();
        return;
    }

    req.log.debug('parseKeyId: entered');
    var k;
    try {
        k = req.auth.callerKey.split('/');
    } catch (e) {
        next(new InvalidKeyIdError());
        return;
    }

    if (!k) {
        next(new InvalidKeyIdError());
        return;
    }

    if (k.length === 4) {
        // account key. like '/poseidon/keys/<keyId>'
        if (k[2] !== 'keys') {
            next(new InvalidKeyIdError());
            return;
        }
        req.auth.keyId = decodeURIComponent(k[3]);
        req.auth.account = decodeURIComponent(k[1]);
    } else if (k.length === 5) {
        // user key. like '/poseidon/fred/keys/<keyId>'
        if (k[3] !== 'keys') {
            next(new InvalidKeyIdError());
            return;
        }
        req.auth.keyId = decodeURIComponent(k[4]);
        req.auth.account = decodeURIComponent(k[1]);
        req.auth.user = decodeURIComponent(k[2]);
        if (req.auth.user === '') {
            next(new InvalidKeyIdError());
            return;
        }
    } else {
        next(new InvalidKeyIdError());
        return;
    }

    if (req.auth.keyId === '' || req.auth.account === '') {
        next(new InvalidKeyIdError());
        return;
    }

    req.log.debug('parseKeyId: done');
    next();
}

function loadCaller(req, res, next) {
    // Skip loadCaller processing for public reader anonymous access
    // This means that the object requested has the 'public-read' role
    // and anonymous access is granted, hence we are skipping this call.
    if (req.isAnonymousAccess && req.caller && req.caller.publicReader) {
        req.log.debug(
            'loadCaller: skipping for public reader anonymous access');
        next();
        return;
    }

    var account = req.auth.account;
    var accountid = req.auth.accountid;
    var user = req.auth.user;
    var userid = req.auth.userid;
    var accessKeyId = req.auth.accessKeyId; // support for access key lookup

    req.log.debug('loadCaller: entered');

        // Helper function to parse role ARN and extract role name
    function parseRoleArn(roleArn) {
        if (!roleArn || typeof (roleArn) !== 'string') {
            return (null);
        }
        // Expected format: arn:aws:iam::account:role/rolename
        var arnParts = roleArn.split(':');
        if (arnParts.length < 6 || arnParts[2] !== 'iam') {
            return (null);
        }
        var resourcePart = arnParts[5];
        if (resourcePart.indexOf('role/') !== 0) {
            return (null);
        }
        return ({
            accountId: arnParts[4],
            roleName: resourcePart.substring(5)
        });
    }

    // Helper function to load assumed role permissions
    function loadAssumedRoleInfo(roleArn, callback) {
        req.log.debug({
            roleArn: roleArn,
            roleArnType: typeof (roleArn)
        }, 'IAM_DEBUG_ALWAYS: loadAssumedRole called');

        var roleInfo = parseRoleArn(roleArn);
        req.log.debug({
            roleInfo: roleInfo,
            hasRoleInfo: !!roleInfo
        }, 'IAM_DEBUG_ALWAYS: parseRoleArn result');

        if (!roleInfo) {
            return (callback(new Error('Invalid role ARN format')));
        }

        var iamClient = req.iamClient;
        if (!iamClient) {
            return (callback(new Error('IAM client not available')));
        }

        iamClient.getRole({
            roleName: roleInfo.roleName,
            caller: {
                account: { uuid: req.caller.account.uuid }
            }
        }, function (roleErr, roleData) {
            if (roleErr) {
                return (callback(roleErr));
            }

            // Now load permission policies using AWS-compliant operations
            iamClient.listRolePolicies({
                roleName: roleInfo.roleName,
                caller: {
                    account: { uuid: req.caller.account.uuid }
                }
            }, function (listErr, listResponse) {
                if (listErr) {
                    req.log.warn({
                        err: listErr,
                        roleName: roleInfo.roleName
                    }, 'Failed to list role policies,' +
                                 ' continuing without policies');
                    // Continue without policies rather than failing completely
                    roleData.PermissionPolicies = [];
                    return (callback(null, roleData));
                }

                var policyNames = listResponse &&
                    listResponse.PolicyNames ? listResponse.PolicyNames : [];
                if (policyNames.length === 0) {
                    // No policies attached
                    roleData.PermissionPolicies = [];
                    return (callback(null, roleData));
                }

                // Load each policy document
                var permissionPolicies = [];
                var pendingPolicies = policyNames.length;

                policyNames.forEach(function (policyName) {
                    iamClient.getRolePolicy({
                        roleName: roleInfo.roleName,
                        policyName: policyName,
                        caller: {
                            account: { uuid: req.caller.account.uuid }
                        }
                    }, function (getPolicyErr, policyData) {
                        if (getPolicyErr) {
                            req.log.warn({
                                err: getPolicyErr,
                                roleName: roleInfo.roleName,
                                policyName: policyName
                            }, 'Failed to get role policy, skipping');
                        } else {
                            permissionPolicies.push({
                                policyName: policyName,
                                policyDocument: policyData.PolicyDocument
                            });
                        }

                        pendingPolicies--;
                        if (pendingPolicies === 0) {
                            // All policies loaded
                            roleData.PermissionPolicies = permissionPolicies;
                            return (callback(null, roleData));
                        }
                    });
                });
            });
        });
    }

    function gotCaller(err, info) {
        if (err) {
            switch (err.restCode || err.name) {
            case 'AccountDoesNotExist':
                next(new AccountDoesNotExistError(account));
                break;
            case 'UserDoesNotExist':
                next(new UserDoesNotExistError(account, user));
                break;

            /*
             * Technically these should never happen because uuids are only
             * used if we're using token auth, and tokens are generated by
             * muskie and we never delete users. Including them anyway in case
             * we ever do support deleting users.
             */
            case 'UserIdDoesNotExist':
                next(new UserDoesNotExistError(null, userid));
                break;
            case 'AccountIdDoesNotExist':
                next(new AccountDoesNotExistError(accountid));
                break;
            // Add handling for access key errors
            case 'AccessKeyNotFound':
                next(new AccountDoesNotExistError(accessKeyId));
                break;

            default:
                next(new InternalError(err));
                break;
            }
            return;
        }

        if (!info.account.approved_for_provisioning &&
            !info.account.isOperator) {
            next(new AccountBlockedError(info.account.login));
            return;
        }

        req.caller = info;

        // Debug: Log authentication context
        req.log.debug({
            isTemporaryCredential: req.auth.isTemporaryCredential,
            hasAssumedRole: !!req.auth.assumedRole,
            authKeys: Object.keys(req.auth || {}),
            callerType: info.account ? 'account' : 'user'
        }, 'IAM_DEBUG: gotCaller - authentication context');

        // For subusers, ensure roles and defaultRoles are properly
        // structured
        if (req.caller.user && req.caller.type === 'user') {
            // Copy roles and defaultRoles from the top-level response
            // to user object
            if (req.caller.roles && !req.caller.user.roles) {
                req.caller.user.roles = req.caller.roles;
            }
            if (req.caller.defaultRoles && !req.caller.user.defaultRoles) {
                req.caller.user.defaultRoles = req.caller.defaultRoles;
            }
        }

        // Handle assumed role authorization for temporary credentials
        req.log.debug({
            conditionCheck1: !!req.auth.isTemporaryCredential,
            conditionCheck2: !!req.auth.assumedRole,
            assumedRoleType: typeof (req.auth.assumedRole),
            assumedRoleValue: req.auth.assumedRole
        }, 'IAM_DEBUG_ALWAYS: Checking assumed role conditions');

        if (req.auth.isTemporaryCredential && req.auth.assumedRole) {
            req.log.debug({
                assumedRole: req.auth.assumedRole,
                isTemporary: req.auth.isTemporaryCredential,
                hasIamClient: !!req.iamClient,
                iamClientType: req.iamClient ? typeof (req.iamClient) : 'null'
            }, 'IAM_DEBUG_ALWAYS: ' +
               'Loading assumed role permissions for temporary credential');

            // Fix: Handle assumedRole as string (ARN) or object
            // with .arn property
            var roleArn = (typeof (req.auth.assumedRole) === 'string') ?
                req.auth.assumedRole : req.auth.assumedRole.arn;

            req.log.info({
                reqAuthAssumedRole: req.auth.assumedRole,
                reqAuthAssumedRoleType: typeof (req.auth.assumedRole),
                extractedRoleArn: roleArn,
                extractedRoleArnType: typeof (roleArn),
                extractedRoleArnIsNull: roleArn === null,
                extractedRoleArnIsUndefined: roleArn === undefined
            }, 'STEP8_DEBUG: Extracted roleArn from req.auth.assumedRole');

            loadAssumedRoleInfo(roleArn,
                function (roleErr, roleData) {
                req.log.debug({
                    roleErr: roleErr,
                    hasRoleData: !!roleData,
                    roleDataKeys: roleData ? Object.keys(roleData) : null,
                    assumedRoleArn: req.auth.assumedRole ?
                        req.auth.assumedRole.arn : null
                }, 'IAM_DEBUG_ALWAYS: loadAssumedRole callback result');

                if (roleErr) {
                    req.log.debug({
                        err: roleErr,
                        assumedRole: req.auth.assumedRole
                    }, 'Failed to load assumed role permissions');
                    // Continue with normal authorization but log the issue
                    return (continueWithNormalAuth());
                }

                req.log.debug({
                    roleName: roleData.Role ? roleData.Role.RoleName :
                        roleData.RoleName,
                    hasRoleObject: !!roleData.Role,
                    hasPermissionPoliciesOnRole:
                    !!(roleData.Role &&
                       roleData.Role.PermissionPolicies),
                    hasPermissionPoliciesOnRoot: !!roleData.PermissionPolicies,
                    permissionPoliciesCountOnRole:
                    (roleData.Role && roleData.Role.PermissionPolicies) ?
                        roleData.Role.PermissionPolicies.length : 0,
                    permissionPoliciesCountOnRoot: roleData.PermissionPolicies ?
                        roleData.PermissionPolicies.length : 0,
                    roleDataKeys: Object.keys(roleData),
                    roleObjectKeys: roleData.Role ?
                        Object.keys(roleData.Role) : []
                }, 'IAM_DEBUG: Successfully loaded assumed role data');

                // Store role data in caller context
                req.caller.assumedRole = {
                    arn: roleArn,
                    name: roleData.Role ? roleData.Role.RoleName :
                        roleData.RoleName,
                    permissionPolicies:
                        (roleData.Role && roleData.Role.PermissionPolicies) ?
                        roleData.Role.PermissionPolicies :
                        (roleData.PermissionPolicies || []),
                    originalPrincipal: req.auth.principalUuid
                };

                // Debug: Log what actually got extracted and stored
                req.log.info({
                    extractedRoleName: req.caller.assumedRole.name,
                    extractedRoleArn: req.caller.assumedRole.arn,
                    roleArnType: typeof (req.caller.assumedRole.arn),
                    roleArnIsNull: req.caller.assumedRole.arn === null,
                    roleArnIsUndefined: req.caller.assumedRole.arn ===
                        undefined,
                    inputRoleArn: roleArn,
                    extractedPermissionPoliciesCount:
                    req.caller.assumedRole.permissionPolicies.length
                }, 'STEP8_DEBUG: Stored assumed role data in req.caller');

                    return (continueWithNormalAuth());
            });
        } else {
            // Clear any assumed role data from previous
            // requests when not using temporary credentials
            if (req.caller.assumedRole) {
                req.log.debug({
                    clearedAssumedRole: req.caller.assumedRole.name,
                    isTemporaryCredential: req.auth.isTemporaryCredential
                }, 'IAM_DEBUG: Clearing assumed role' +
                              ' data for non-temporary credential request');
                req.caller.assumedRole = null;
            }
            return (continueWithNormalAuth());
        }

        function continueWithNormalAuth() {
            req.log.debug('IAM_DEBUG: continueWithNormalAuth called');
            if (req.isS3Request) {
                req.log.debug({
                    callerType: info.account ? 'account' : 'user',
                    accountLogin: info.account ? info.account.login : 'unknown',
                    accountUuid: info.account ? info.account.uuid : 'unknown',
                    isProvisioned: info.account ?
                    info.account.approved_for_provisioning : false,
                    hasAssumedRole: !!req.caller.assumedRole
                }, 'S3_AUTH_DEBUG: AUTHENTICATION COMPLETE'+
                ' - Caller loaded successfully');
            }

            var sanitizedCaller = {
                uuid: req.caller.account ? req.caller.account.uuid : undefined,
                login: req.caller.account ?
                    req.caller.account.login : undefined,
                type: req.caller.account ? req.caller.account.type : undefined,
                isOperator: req.caller.account ?
                    req.caller.account.isOperator : undefined,
                roles: req.caller.roles ? Object.keys(req.caller.roles) : [],
                assumedRole: req.caller.assumedRole ?
                    req.caller.assumedRole.name : undefined
            };
            req.log.debug({caller: sanitizedCaller}, 'loadCaller: done');
            next();
        }
    }

    // S3 presigned URL authentication: Get user info by access key
    if (accessKeyId && req.auth.method === 'presigned-s3') {
        req.log.debug({
            accessKeyId: accessKeyId,
            method: 'presigned-s3'
        }, 'S3_PRESIGNED_DEBUG: Loading caller via access key lookup');

        req.mahi.getUserByAccessKey(accessKeyId, function (err, data) {
            if (err) {
                req.log.debug({
                    error: err.message || err,
                    accessKeyId: accessKeyId
                }, 'S3_PRESIGNED_DEBUG: AUTHENTICATION FAILED' +
                              ' - Access key lookup failed');
            } else {
                req.log.debug({
                    accessKeyId: accessKeyId,
                    userUuid: data ? data.uuid : 'unknown',
                    userLogin: data ? data.login : 'unknown'
                }, 'S3_PRESIGNED_DEBUG: AUTHENTICATION SUCCESS' +
                              ' - Access key lookup successful');
            }
            gotCaller(err, data);
        });
    } else if (accessKeyId && req.auth.method === 'sigv4') {
        req.log.debug({
            accessKeyId: accessKeyId,
            userUuid: req.auth.accountid,
            method: 'sigv4'
        }, 'S3_AUTH_DEBUG:'+
        ' Loading caller via userUuid from SigV4 verification');

        // Try getAccountById first
        // If it fails, fallback to getUserById for subusers
        req.mahi.getAccountById(req.auth.accountid, function (err, data) {
            if (err) {
                req.log.debug({
                    userUuid: req.auth.accountid,
                    error: err.message || err,
                    action: 'Trying getUserById as fallback'
                }, 'S3_AUTH_DEBUG: getAccountById failed, trying user lookup');

                // Fallback to getUserById for subusers
                req.mahi.getUserById(req.auth.accountid,
                                     function (err2, data2) {
                    if (err2) {
                        req.log.debug({
                            error: err2.message || err2,
                            userUuid: req.auth.accountid,
                            accessKeyId: accessKeyId,
                            originalError: err.message || err
                        }, 'S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
                        ' - Both account and user lookup failed');
                        // Return the original account error since that was
                        // tried first
                        gotCaller(err, data);
                    } else {
                        req.log.debug({
                            accessKeyId: accessKeyId,
                            userUuid: data2 ? data2.uuid : 'unknown',
                            userLogin: data2 ? data2.login : 'unknown',
                            userType: 'sub-user'
                        }, 'S3_AUTH_DEBUG: AUTHENTICATION SUCCESS'+
                        ' - User lookup successful (fallback)');
                        gotCaller(null, data2);
                    }
                });
            } else {
                req.log.debug({
                    accessKeyId: accessKeyId,
                    userUuid: data ? data.uuid : 'unknown',
                    userLogin: data ? data.login : 'unknown',
                    userType: 'account'
                }, 'S3_AUTH_DEBUG: AUTHENTICATION SUCCESS'+
                ' - Account lookup successful');
                gotCaller(null, data);
            }
        });
    } else if (user && account) {
        req.mahi.getUser(user, account, false, gotCaller);
    } else if (userid) {
        req.mahi.getUserById(userid, gotCaller);
    } else if (account) {
        req.mahi.getAccount(account, gotCaller);
    } else if (accountid) {
        req.mahi.getAccountById(accountid, gotCaller);
    } else {
        req.caller = {
            anonymous: true,
            user: {},
            roles: {},
            account: {}
        };

        var sanitizedCallerAnon = {
            anonymous: req.caller.anonymous,
            uuid: req.caller.account ? req.caller.account.uuid : undefined,
            login: req.caller.account ? req.caller.account.login : undefined,
            type: req.caller.account ? req.caller.account.type : undefined,
            isOperator: req.caller.account ? req.caller.account.isOperator :
                undefined,
            roles: req.caller.roles ? Object.keys(req.caller.roles) : []
        };
        req.log.debug({caller: sanitizedCallerAnon}, 'loadCaller: done');
        setImmediate(next);
        return;
    }
}
function parseHttpAuthToken(req, res, next) {
    // Skip HTTP auth token processing for SigV4 requests
    // HTTP auth tokens require SSH signatures which are incompatible with SigV4
    if (req.auth.method === 'sigv4') {
        req.log.debug('parseHttpAuthToken: skipping for SigV4 request');
        setImmediate(next);
        return;
    }

    if (!req.header('x-auth-token')) {
        next();
        return;
    }

    var log = req.log;
    var token;

    try {
        token = JSON.parse(req.header('x-auth-token'));
    } catch (e) {
        log.warn(e, 'invalid auth token (JSON parse)');
        next(new InvalidHttpAuthTokenError('malformed auth token'));
        return;
    }

    log.debug('parseHttpAuthToken: calling keyAPI');
    req.keyapi.detoken(token, function (tokerr, tokobj) {

        function gotInfo(err, info) {
            if (err) {
                switch (err.restCode) {
                case 'AccountDoesNotExist':
                    next(new AccountDoesNotExistError(req.auth.account));
                    return;
                case 'UserDoesNotExist':
                    next(new UserDoesNotExistError(req.auth.account,
                            req.auth.user));
                    return;
                default:
                    next(new InternalError(err));
                    return;
                }
            }

            req.caller = info;
            log.debug(req.auth.account, 'parseHttpAuthToken: done');
            next();
        }

        if (tokerr || !tokobj) {
            log.warn(tokerr, 'invalid auth token (detoken)');
            next(new InvalidHttpAuthTokenError('malformed auth token'));
        } else if (tokobj.expires &&
                   (Date.now() > new Date(tokobj.expires).getTime())) {
            next(new InvalidHttpAuthTokenError('auth token expired'));
        } else if (!req.authorization || !req.authorization.signature ||
                   !req.authorization.signature.keyId) {
            next(new AuthorizationRequiredError('signature is required'));
        } else if (tokobj.devkeyId !== req.authorization.signature.keyId) {
            next(new InvalidHttpAuthTokenError('not authorized for token'));
        } else {
            req.auth.delegate = req.auth.account;
            req.auth.account = tokobj.account.login;
            if (tokobj.subuser) {
                req.auth.user = tokobj.subuser.login;
                req.mahi.getUser(req.auth.user, req.auth.account, gotInfo);
            } else {
                req.mahi.getAccount(req.auth.account, gotInfo);
            }
        }
    });
}


function loadOwner(req, res, next) {
    var p = req.path();
    loadOwnerFromPath(req, p, next);
}


/*
 * Extract the owner of a resource based on the input path, verify that
 * the account exists, and set the `owner` field on the request object
 * to the object returned from Mahi.
 */
function loadOwnerFromPath(req, p, next) {
    req.log.debug('loadOwner: entered');

    var account;

    // For S3 requests, use the authenticated user's account instead of
    // extracting from path
    // S3 paths like '/mybucket' don't contain account info - bucket is
    // owned by authenticated user
    if (req.isS3Request && req.caller &&
    req.caller.account && req.caller.account.login) {
        account = req.caller.account.login;
        req.log.debug({
            s3Request: true,
            extractedAccount: account,
            originalPath: p
        }, 'loadOwner: using authenticated user account for S3 request');
    } else {
        // Traditional Manta path: /account/buckets/bucket -> extract account
        try {
            account = decodeURIComponent(p.split('/', 2).pop());
        } catch (e) {
            next(new InvalidPathError(p));
            return;
        }
    }

    req.auth.owner = account;
    var user = common.ANONYMOUS_USER;
    var fallback = true;

    req.mahi.getUser(user, account, fallback, function (err, owner) {
        if (err) {
            switch (err.restCode || err.name) {
            case 'AccountDoesNotExist':
                next(new AccountDoesNotExistError(account));
                return;
            default:
                next(new InternalError(err));
                return;
            }
        }

        req.owner = owner;

        // Handle public-reader anonymous access AND potential anonymous access
        if ((req.isAnonymousAccess && req.caller && req.caller.publicReader) ||
            req.potentialAnonymousAccess) {
            req.log.debug({
                isAnonymousAccess: req.isAnonymousAccess,
                potentialAnonymousAccess: !!req.potentialAnonymousAccess,
                publicReader: req.caller && req.caller.publicReader,
                callerRoles: req.caller ? req.caller.roles : 'no caller'
            }, 'Allowing public-reader/potential' +
                          'anonymous access in loadOwner');
            next();
            return;
        } else if (req.caller.anonymous && !owner.user) {
            next(new AuthorizationError(common.ANONYMOUS_USER, p,
                'owner ' + account + ' has no anonymous user'));
            return;
        } else if (req.caller.anonymous) {
            req.log.debug('loadOwner: using owner\'s anonymous user');
            req.caller.account = owner.account;
            req.caller.user = owner.user;
            req.caller.roles = owner.roles;
        }

        if (!owner.account.approved_for_provisioning &&
            !owner.account.isOperator &&
            (req.caller.user || !req.caller.account.isOperator)) {

            next(new AccountBlockedError(account));
            return;
        }

        req.log.debug('loadOwner: done');
        next();
    });
}


function gatherContext(req, res, next) {
    var action = req.route.authAction || req.route.name;

    /*
     * We share these conditions with other systems as part of an auth token
     * (e.g. marlin for jobs).
     */
    var conditions = req.authContext.conditions;
    conditions.owner = req.owner.account;
    conditions.method = req.method;

    // Safety check: Ensure req.caller exists and has required structure
    if (!req.caller) {
        req.log.debug('AUTH_ERROR: req.caller is undefined in gatherContext');
        return next(
            new InternalError('Authentication context not properly set'));
    }

    if (!req.caller.account) {
        req.log.debug({
            callerKeys: Object.keys(req.caller),
            callerType: typeof (req.caller),
            caller: req.caller
        }, 'AUTH_ERROR: req.caller.account is undefined in gatherContext');
        return next(
            new InternalError('Authentication account context missing'));
    }

    /*
     * Separate the xacct and non-xacct roles so that old systems that don't
     * support them can't get confused and authorize actions improperly.
     */
    conditions.activeRoles = [];
    conditions.activeXAcctRoles = [];
    (req.activeRoles || []).forEach(function (role) {
        if (req.caller && req.caller.roles && req.caller.roles[role] &&
            req.caller.roles[role].account === req.owner.account.uuid) {
            conditions.activeRoles.push(role);
        } else if (req.caller && req.caller.roles &&
            req.caller.roles[role]) {
            conditions.activeXAcctRoles.push(role);
        }
    });

    var t = req.date();
    conditions.date = t;
    conditions.day = t;
    conditions.time = t;
    conditions.region = req.config.region;
    var ip = req.headers['x-forwarded-for'];
    if (ip) {
        conditions.sourceip = ip.split(',')[0].trim();
    }
    conditions['user-agent'] = req.headers['user-agent'];
    conditions.fromjob = false;

    // Override conditions with ones that are provided in the token
    if (req.auth.token) {
        Object.keys(req.auth.token.conditions).forEach(function (k) {
            conditions[k] = req.auth.token.conditions[k];
        });
    }

    req.authContext.principal = req.caller;
    req.authContext.action = action.toLowerCase();
    next();
}


/*
 * Authorization is only bypassed in only two situations:
 * - A bucket is called 'public'
 * - An object inside a bucket has the 'public-read' role.
 * The internal state variables that handle these situation are the following:
 *
 * req.isAnonymousAccess: Boolean flag set to true when anonymous access is
 * validated and activated. Set by validateAnonymousAccess() for buckets named
 * exactly "public", or by validateAnonymousObjectAccess() for objects with
 * "public-read" role (or in strict mode, objects in buckets named "public").
 * Used to bypass authentication steps in the auth pipeline.
 *
 * req.caller.publicReader: Boolean flag set to true on the anonymous caller
 * object that gets created when anonymous access is granted. The caller also
 * gets roles: ['public-read'] and isAnonymousPublicAccess: true. This caller
 * object replaces any existing req.caller during anonymous access validation.
 */
function authorize(req, res, next) {
    var log = req.log;

    var sanitizedCaller = req.caller ?
        Object.assign({}, req.caller, {
            account: req.caller.account ?
                Object.assign({}, req.caller.account, {
                    accesskeys: req.caller.account.accesskeys ? '[REDACTED]' :
                        undefined
                }) : req.caller.account
        }) : req.caller;
    var sanitizedOwner = req.owner ?
        Object.assign({}, req.owner, {
            account: req.owner.account ?
                Object.assign({}, req.owner.account, {
                    accesskeys: req.owner.account.accesskeys ? '[REDACTED]' :
                        undefined
                }) : req.owner.account
        }) : req.owner;

    log.debug({caller: sanitizedCaller, owner: sanitizedOwner},
              'authorize: entered');

    // Handle public bucket access for anonymous users - bypass all Mahi
    // authorization.Also handle potential anonymous access that hasn't been
    // validated yet
    if ((req.isAnonymousAccess && req.caller && req.caller.publicReader) ||
        req.potentialAnonymousAccess) {
        var resource = req.authContext ? req.authContext.resource : null;
        var action = req.authContext ? req.authContext.action : null;

        log.debug({
            isAnonymous: req.isAnonymousAccess,
            potentialAnonymous: !!req.potentialAnonymousAccess,
            publicReader: req.caller && req.caller.publicReader,
            resourceRoles: resource ? resource.roles : null,
            callerRoles: req.caller ? req.caller.roles : 'no caller',
            action: action
        }, 'authorize: handling anonymous/potential anonymous access');

        // For potential anonymous access, we need to defer authorization until
        // after bucket metadata is loaded and validated
        if (req.potentialAnonymousAccess) {
            log.debug(
                'authorize: deferring authorization' +
                    'for potential anonymous access');
            next();
            return;
        }

        // For validated public reader anonymous access, completely bypass Mahi
        // authorization. The bucket/object public status was already verified
        // in the anonymous access handler
        if (req.isAnonymousAccess && req.caller.publicReader) {
            if ((action === 'getobject' || action === 'getdirectory' ||
                 action === 'getbucket' || action === 'optsobject' ||
                 action === 'optsdirectory' || action === 'optsbucket' ||
                 !action)) {
                log.debug('authorize: allowing public access' +
                          ' - bypassing Mahi authorization completely');
                next();
                return;
            } else {
                log.debug({action: action},
                          'authorize: denying non-GET/OPTIONS' +
                          'action for anonymous access');
                next(new AuthorizationError('anonymous',
                   req.path(),
                   'Anonymous access only allowed for GET/OPTIONS operations'));
                return;
            }
        }

        // If we reach here with anonymous access, something is wrong
        log.warn('authorize: unexpected state' +
                 '- anonymous access not properly handled');
        next(new AuthorizationError('anonymous',
           req.path(), 'Anonymous access configuration error'));
        return;
    }

    var login;

    // Handle case where we have an anonymous caller with publicReader set
    if (req.caller.publicReader && req.isAnonymousAccess) {
        login = 'anonymous';
    } else if (!req.caller.user) {
        login = req.caller.account.login;
    } else {
        login = req.caller.account.login + '/' + req.caller.user.login;
    }

    var sanitizedAuthContext = req.authContext ?
        Object.assign({}, req.authContext, {
            conditions: req.authContext.conditions ?
                Object.assign({}, req.authContext.conditions, {
                    owner: req.authContext.conditions.owner &&
                        req.authContext.conditions.owner.accesskeys ?
                        Object.assign({}, req.authContext.conditions.owner, {
                            accesskeys: '[REDACTED]'
                        }) : req.authContext.conditions.owner
                }) : req.authContext.conditions,
            principal: req.authContext.principal ?
                Object.assign({}, req.authContext.principal, {
                    account: req.authContext.principal.account ?
                        Object.assign({}, req.authContext.principal.account, {
                            accesskeys: '[REDACTED]'
                        }) : req.authContext.principal.account
                }) : req.authContext.principal,
            resource: req.authContext.resource ?
                Object.assign({}, req.authContext.resource.owner, {
                    account: req.authContext.resource.owner.account ?
                        Object.assign({}, req.authContext.resource.owner.
                                      account, {
                            accesskeys: '[REDACTED]'
                        }) : req.authContext.resource.owner.account
                }) : req.authContext.resource
        }) : req.authContext;

    req.log.debug(sanitizedAuthContext, 'authorizing...');

    try {
        // Debug: Always log the state of assumed role for debugging
        req.log.debug({
            hasAssumedRole: !!req.caller.assumedRole,
            assumedRoleData: req.caller.assumedRole,
            isTemporaryCredential: !!req.auth.isTemporaryCredential,
            authAssumedRole: req.auth.assumedRole,
            authMethod: req.auth.method
        }, 'IAM_DEBUG_ALWAYS: Checking assumed' +
           ' role state before IAM evaluation');

        // Check IAM permission policies for assumed roles BEFORE
        // standard Manta authorization
        if (req.caller.assumedRole &&
            req.caller.assumedRole.permissionPolicies) {
            req.log.debug(
                'IAM_DEBUG_ALWAYS: IAM policy evaluation is starting!');
            var iamPolicyEngine = require('./iam-policy-engine');

            // Map Manta action to IAM action
            var iamAction = iamMapper.toIamAction(req.authContext.action);

            // Map Manta resource to IAM resource
            var iamResource = iamMapper.toIamResource(
                req.authContext.resource.key, req.path());

            req.log.debug({
                mantaAction: req.authContext.action,
                iamAction: iamAction,
                mantaResource: req.authContext.resource.key,
                requestPath: req.path(),
                iamResource: iamResource,
                permissionPoliciesCount:
                req.caller.assumedRole.permissionPolicies.length,
                permissionPolicies:
                req.caller.assumedRole.permissionPolicies.map(function (p) {
                    return ({
                        policyName: p.policyName,
                        policyDocument: typeof (p.policyDocument) === 'string' ?
                            p.policyDocument : JSON.stringify(p.policyDocument)
                    });
                })
            }, 'IAM_DEBUG: Evaluating assumed role permission policies');

            var iamAllowed = iamPolicyEngine.evaluatePermissionPolicies(
                req.caller.assumedRole.permissionPolicies, iamAction,
                iamResource, req.log);

            if (!iamAllowed) {
                req.log.debug({
                    action: iamAction,
                    resource: iamResource,
                    policies: req.caller.assumedRole.permissionPolicies
                }, 'IAM_DEBUG: Access denied by IAM permission policy');

                // Create IAM access denied error
                var iamError =
                    new Error('Access denied by IAM ' +
                              'permission policy for assumed role');
                iamError.restCode = 'AccessDenied';
                iamError.statusCode = constants.HTTP_STATUS.FORBIDDEN;
                iamError.iamRole = req.caller.assumedRole.name;
                iamError.iamAction = iamAction;
                iamError.iamResource = iamResource;
                throw iamError;
            }

            req.log.debug({
                action: iamAction,
                resource: iamResource
            }, 'IAM_DEBUG: Access allowed by IAM permission policy');

            // IAM allows access, skip standard Manta RBAC
            next();
            return;
        } else {
            req.log.debug({
                hasAssumedRole: !!req.caller.assumedRole,
                hasPermissionPolicies:
                !!(req.caller.assumedRole &&
                   req.caller.assumedRole.permissionPolicies)
            }, 'IAM_DEBUG_ALWAYS: Skipping IAM evaluation ' +
               '- no assumed role or policies, using standard Manta auth');
        }

        // For non-assumed roles, use standard Manta authorization
        libmantalite.authorize({
            mahi: req.mahi,
            context: req.authContext,
            log: req.log
        });
    } catch (e) {
        // Debug IAM policy errors
        if (req.caller.assumedRole &&
            req.caller.assumedRole.permissionPolicies) {
            req.log.debug({
                errorName: e.name,
                errorCode: e.code,
                errorRestCode: e.restCode,
                errorMessage: e.message,
                errorStatusCode: e.statusCode,
                allErrorProps: Object.keys(e)
            }, 'IAM_DEBUG: Authorization error details');
        }
        switch (e.restCode || e.code || e.name) {
        case 'AccountBlocked':
            next(new AccountBlockedError(req.caller.account.login));
            return;
        case 'NoMatchingRoleTag':
            /*
             * If we didn't activate any owner roles, we want to return an
             * AuthorizationError here, like we would have previously if we
             * got a CrossAccount Error before cross-account role support was
             * added.
             */
            var ownerRoles = (req.activeRoles || []).filter(function (role) {
                return (req.caller.roles[role].account ===
                    req.owner.account.uuid);
            });
            if (!ownerRoles.length) {
                next(new AuthorizationError(login, req.path(), e));
            } else {
                next(new NoMatchingRoleTagError());
            }
            return;
        case 'InvalidRole':
            next(new InvalidRoleError(e.message));
            return;
        case 'CrossAccount':
            /* This should never happen. */
            next(new AuthorizationError(login, req.path(), e));
            return;
        case 'RulesEvaluationFailed':
            next(new AuthorizationError(login, req.path(), e));
            return;
        case 'AccessDenied':
            // Handle IAM permission policy access denied errors
            if (e.iamRole) {
                // This is an IAM role-based access denial
                var iamErrorMsg = 'Access denied for assumed role \'' +
                    e.iamRole + '\' - action \'' + e.iamAction +
                    '\' not permitted for resource \'' + e.iamResource + '\'';
                var authErr = new AuthorizationError(e.iamRole, req.path(),
                    iamErrorMsg);
                // Preserve the original IAM error's restCode for correct
                // S3 XML error response
                authErr.restCode = 'AccessDenied';
                next(authErr);
            } else {
                next(new AuthorizationError(login, req.path(), e));
            }
            return;
        default:
            if (e.statusCode >= 400 && e.statusCode <= 499) {
                next(new AuthorizationError(login, req.path(), e));
                return;
            }
            return (next(new InternalError(e)));
        }
    }

    next();
}


///--- Exports

module.exports = {

    authenticationHandler: function handlers(options) {
        assert.object(options, 'options');
        assert.object(options.log, 'options.log');
        assert.object(options.mahi, 'options.mahi');
        assert.optionalObject(options.iamClient,
            'options.iamClient');

        return ([
            function _authSetup(req, res, next) {
                req.mahi = options.mahi;
                req.keyapi = options.keyapi;
                req.iamClient = options.iamClient;
                req.auth = {};
                req.authContext = {
                    conditions: {}
                };
                next();
            },
            signatureVerifier.preSignedUrl,
            signatureVerifier.checkAuthzScheme,
            tokenManager.parseHandler,
            signatureVerifier.signatureHandler,
            // Add SigV4 authentication handler
            signatureVerifier.sigv4Handler,
            parseKeyId,
            loadCaller,
            signatureVerifier.verifySignature,
            parseHttpAuthToken,
            loadOwner,
            roleManager.getActiveRoles
        ]);
    },

    authorizationHandler: function authz() {
        return ([
            authorize
        ]);
    },

    loadOwnerFromPath: loadOwnerFromPath,

    gatherContext: gatherContext,
    createAuthToken: tokenManager.create,
    parseAuthToken: tokenManager.parse,
    convertS3PresignedToManta: signatureVerifier.convertS3PresignedToManta,
    checkIfPresigned: signatureVerifier.checkIfPresigned,

    postAuthTokenHandler: function () {
        return ([tokenManager.createHandler]);
    }
};
