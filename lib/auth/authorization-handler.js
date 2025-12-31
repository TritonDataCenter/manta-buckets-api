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
 * authorization-handler.js: Authorization and owner
 * management for requests.
 *
 * Handles resource owner loading, authorization context
 * gathering, and authorization evaluation including IAM
 * policy enforcement and Manta RBAC.
 */

var libmantalite = require('../libmantalite');
var common = require('../common');
var constants = require('../constants');
var iamMapper = require('./iam-mapper');
var validators = require('../validators');
require('../errors');


///--- Functions

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
        } catch (_e) {
            next(new InvalidPathError(p));
            return;
        }
    }

    // Validate account identifier format before Mahi lookup (defense-in-depth)
    if (!validators.isValidAccountIdentifier(account)) {
        req.log.warn({
            account: account,
            path: p,
            sourceIP: req.connection.remoteAddress,
            userAgent: req.headers['user-agent']
        }, 'Invalid account identifier format in path');

        next(new InvalidArgumentError(
            'Invalid account identifier format'));
        return;
    }

    req.auth.owner = account;
    var user = common.ANONYMOUS_USER;
    var fallback = true;

    req.mahi.getUser(user, account, fallback,
        function handleGetUserResponse(err, owner) {
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
    (req.activeRoles || []).forEach(function categorizeActiveRole(role) {
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
        Object.keys(req.auth.token.conditions).forEach(
            function applyTokenCondition(k) {
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
            var iamPolicyEngine = require('../iam-policy-engine');

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
                req.caller.assumedRole.permissionPolicies.map(
                    function extractPolicyDebugInfo(p) {
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
            var ownerRoles = (req.activeRoles || []).filter(
                function isOwnerAccountRole(role) {
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
    loadOwner: loadOwner,
    loadOwnerFromPath: loadOwnerFromPath,
    gatherContext: gatherContext,
    authorize: authorize
};
