/*
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * credential-provider.js: Credential loading and
 * management for authentication.
 *
 * Handles SSH key ID parsing, caller credential loading
 * via Mahi, HTTP auth token validation, and assumed role
 * loading for STS temporary credentials.
 */

require('../errors');


///--- Functions

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
    } catch (_e) {
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
        }, function handleGetRoleResponse(roleErr, roleData) {
            if (roleErr) {
                return (callback(roleErr));
            }

            // Now load permission policies using AWS-compliant operations
            iamClient.listRolePolicies({
                roleName: roleInfo.roleName,
                caller: {
                    account: { uuid: req.caller.account.uuid }
                }
            }, function handleListRolePoliciesResponse(listErr, listResponse) {
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

                policyNames.forEach(function loadEachPolicy(policyName) {
                    iamClient.getRolePolicy({
                        roleName: roleInfo.roleName,
                        policyName: policyName,
                        caller: {
                            account: { uuid: req.caller.account.uuid }
                        }
                    }, function handleGetRolePolicyResponse(getPolicyErr,
                                                             policyData) {
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

        // Extract secret access key for AWS chunked signature verification
        // For SigV4 requests, we need the secret key to verify chunk signatures
        if (req.auth && req.auth.method === 'sigv4' && req.auth.accessKeyId &&
            info.account && info.account.accesskeys) {

            // accesskeys can be an array or object, handle both
            var accesskeys = info.account.accesskeys;
            var secretKey = null;

            if (Array.isArray(accesskeys)) {
                // Array format: find the matching access key object
                for (var i = 0; i < accesskeys.length; i++) {
                    if (accesskeys[i].accessKeyId === req.auth.accessKeyId) {
                        secretKey = accesskeys[i].secret ||
                                    accesskeys[i].secretAccessKey;
                        break;
                    }
                }
            } else if (typeof accesskeys === 'object') {
                // Object format: keyed by accessKeyId
                var keyInfo = accesskeys[req.auth.accessKeyId];
                if (keyInfo) {
                    secretKey = keyInfo.secret || keyInfo.secretAccessKey;
                }
            }

            if (secretKey) {
                req.auth.secretAccessKey = secretKey;
                req.log.debug({
                    hasSecretKey: true,
                    accessKeyId: req.auth.accessKeyId
                }, 'Loaded secret access key for chunk signature verification');
            } else {
                req.log.warn({
                    hasAccessKeys: true,
                    accessKeyId: req.auth.accessKeyId,
                    accessKeysType: Array.isArray(accesskeys) ? 'array' : 'object',
                    accessKeysCount: Array.isArray(accesskeys) ?
                        accesskeys.length : Object.keys(accesskeys).length
                }, 'Secret access key not found in account accesskeys');
            }
        }

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
                function handleLoadAssumedRoleResponse(roleErr, roleData) {
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

        req.mahi.getUserByAccessKey(accessKeyId,
            function handleGetUserByAccessKeyResponse(err, data) {
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
        req.mahi.getAccountById(req.auth.accountid,
            function handleGetAccountByIdResponse(err, data) {
            if (err) {
                req.log.debug({
                    userUuid: req.auth.accountid,
                    error: err.message || err,
                    action: 'Trying getUserById as fallback'
                }, 'S3_AUTH_DEBUG: getAccountById failed, trying user lookup');

                // Fallback to getUserById for subusers
                req.mahi.getUserById(req.auth.accountid,
                    function handleGetUserByIdFallbackResponse(err2, data2) {
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
    req.keyapi.detoken(token, function handleDetokenResponse(tokerr, tokobj) {

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


///--- Exports

module.exports = {
    parseKeyId: parseKeyId,
    loadCaller: loadCaller,
    parseHttpAuthToken: parseHttpAuthToken
};
