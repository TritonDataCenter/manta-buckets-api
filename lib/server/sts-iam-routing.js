/*
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * sts-iam-routing.js: STS and IAM request routing handler.
 *
 * Provides request routing logic for AWS STS (Security Token Service)
 * and IAM (Identity and Access Management) operations. Handles action
 * detection, credential extraction, and delegation to appropriate handlers.
 */

var s3Compat = require('../s3-compat');
var iamPolicyEngine = require('../iam-policy-engine');
var constants = require('../constants');


///--- Functions

/**
 * Creates the STS/IAM request handler for POST / endpoint.
 * This handler detects STS and IAM actions and routes them to
 * appropriate handlers, bypassing the normal authentication flow.
 *
 * @param {Object} clients - Client connections (mahi, etc.)
 * @param {Object} iamClient - IAM client for role operations
 * @param {Object} stsClient - STS client for token operations
 * @param {Object} stsHandlers - STS handler functions
 * @param {Object} iamHandlers - IAM handler functions
 * @return {Function} Restify route handler
 */
function createStsIamHandler(clients, iamClient, stsClient,
                              stsHandlers, iamHandlers) {
    return function stsRequestHandler(req, res, next) {
        req.log.debug({
            method: req.method,
            url: req.url,
            isS3Request: !!req.isS3Request,
            hasQuery: !!req.query,
            hasBody: !!req.body,
            query: req.query,
            body: req.body,
            queryAction: req.query ? req.query.Action : 'none',
            bodyAction: req.body ? req.body.Action : 'none'
        }, 'STS_DEBUG: stsRequestHandler called');

        if (req.isS3Request) {
            req.log.debug({
                method: req.method,
                url: req.url,
                hasQuery: !!req.query,
                hasBody: !!req.body,
                query: req.query,
                body: req.body,
                queryAction: req.query ? req.query.Action : 'none',
                bodyAction: req.body ? req.body.Action : 'none'
            }, 'S3_DEBUG: Checking if request is STS request');
        }

        var action = req.query.Action || req.body.Action;

        // If body is a string (URL-encoded), parse it manually for
        // Action parameter
        if (!action && typeof (req.body) === 'string' &&
            req.body.includes('Action=')) {
            //JSSTYLED
            var actionMatch = req.body.match(/Action=([^&]+)/);
            if (actionMatch) {
                action = decodeURIComponent(actionMatch[1]);
                req.log.debug({
                    bodyString: req.body,
                    extractedAction: action
                }, 'S3_DEBUG: Extracted Action from URL-encoded body string');
            }
        }

        if (action === 'AssumeRole' || action === 'GetSessionToken' ||
            action === 'GetCallerIdentity') {
            req.log.debug({
                action: action,
                method: req.method,
                url: req.url,
                hasAuth: !!req.headers.authorization,
                contentType: req.headers['content-type']
            }, 'STS request detected ' +
                          '- bypassing authentication and routing directly');
        } else if (action === 'CreateRole' ||
                   action === 'GetRole' ||
                   action === 'DeleteRole' ||
                   action === 'ListRoles' ||
                   action === 'PutRolePolicy' ||
                   action === 'DeleteRolePolicy' ||
                   action === 'ListRolePolicies' ||
                   action === 'GetRolePolicy') {
            req.log.debug({
                action: action,
                method: req.method,
                url: req.url,
                hasAuth: !!req.headers.authorization,
                contentType: req.headers['content-type']
            }, 'IAM request detected - ' +
               'handling like STS with optimized auth lookup');

            // Handle IAM requests like STS - extract caller and
            // route immediately
            var authHeader = req.headers.authorization;
            if (!authHeader) {
                req.log.warn('IAM request missing Authorization header');
                res.send(400, {error:
                   'Authorization header required for IAM operations'});
                return (next(false));
            }

            // Extract access key from Authorization header
            // JSSTYLED
            var accessKeyMatch = authHeader.match(/Credential=([^\/]+)/);
            if (!accessKeyMatch) {
                req.log.warn('IAM request Authorization header malformed');
                res.send(400, {error: 'Invalid Authorization header format'});
                return (next(false));
            }

            var accessKeyId = accessKeyMatch[1];

            /*
             * Check for session token header. IAM operations require
             * permanent credentials and cannot be called with temporary
             * credentials from AssumeRole (MSAR/MSTS).
             */
            var sessionToken = req.headers['x-amz-security-token'];
            if (sessionToken) {
                req.log.warn({
                    accessKeyId: accessKeyId,
                    action: action,
                    hasSessionToken: true
                }, 'IAM operation attempted with temporary credentials');

                res.send(403, {
                    error: 'AccessDenied',
                    message: 'IAM operations require permanent ' +
                        'credentials. Temporary credentials from ' +
                        'AssumeRole cannot be used.'
                });
                return (next(false));
            }

            req.log.debug({
                accessKeyId: accessKeyId,
                action: action
            }, 'IAM: Extracted access key,' +
                          ' getting caller info with fast lookup');

            // Get real user data from Mahi using access key with timeout
            var mabiClient = clients.mahi;
            var timeoutHandle = setTimeout(function () {
                req.log.error({
                    accessKeyId: accessKeyId,
                    action: action
                }, 'IAM: getUserByAccessKey timeout after 5 seconds');
                res.send(503, {error: 'Authentication service timeout'});
                return (next(false));
            }, 5000);

            var authStartTime = Date.now();
            mabiClient.getUserByAccessKey(accessKeyId,
                                          function (authErr, authRes) {
                clearTimeout(timeoutHandle);
                var authEndTime = Date.now();

                if (authErr) {
                    req.log.error({
                        err: authErr,
                        accessKeyId: accessKeyId,
                        action: action,
                        authLookupMs: authEndTime - authStartTime,
                        totalDurationMs: authEndTime - (req._startTime ||
                                                        authStartTime)
                    }, 'IAM: Failed to get user by access key');
                    res.send(401, {error: 'Invalid credentials'});
                    return (next(false));
                }

                req.caller = authRes;

                /*
                 * Mahi returns assumedRole as a string ARN, but
                 * iam-policy-engine.js expects an object with an 'arn'
                 * property and a 'policies' array. Extract policies from
                 * authRes.roles if available.
                 */
                if (authRes.assumedRole &&
                    typeof (authRes.assumedRole) === 'string') {
                    try {
                        var roleArnStringIam = authRes.assumedRole;
                        var policies = [];
                        // Extract policies from roles object
                        if (authRes.roles &&
                            typeof (authRes.roles) === 'object') {
                            var roleUuids = Object.keys(authRes.roles);
                            if (roleUuids.length > 0) {
                                var roleData = authRes.roles[roleUuids[0]];
                                if (roleData &&
                                    Array.isArray(roleData.policies)) {
                                    policies = roleData.policies;
                                }
                            }
                        }

                        authRes.assumedRole = {
                            arn: roleArnStringIam,
                            policies: policies
                        };
                    } catch (conversionErr) {
                        req.log.error({
                            err: conversionErr,
                            assumedRole: authRes.assumedRole
                        }, 'Failed to convert assumedRole format for IAM');
                        // Continue with original format
                    }
                }

                req.log.debug({
                    callerUuid: authRes.account.uuid,
                    callerLogin: authRes.account.login,
                    action: action,
                    authLookupMs: authEndTime - authStartTime,
                    totalDurationMs: authEndTime - (req._startTime ||
                                                    authStartTime)
                }, 'IAM: Got caller info, measuring handler execution time');

                // Check IAM access based on credential type and policy
                var accessCheck = iamPolicyEngine.checkIamAccess(
                    accessKeyId, authRes, action, req.log);

                if (!accessCheck.allowed) {
                    var accessError = s3Compat.convertErrorToS3({
                        name: accessCheck.error,
                        message: accessCheck.message,
                        statusCode: 403
                    }, null, req);
                    res.setHeader('Content-Type',
                        constants.CONTENT_TYPES.XML);
                    res.writeHead(403);
                    res.end(accessError);
                    return (next(false));
                }

                var handlerStartTime = Date.now();

                // Route to appropriate IAM handler
                req.log.debug({
                    action: action,
                    handlerStartTime: handlerStartTime
                }, 'IAM: About to call IAM handler');

                if (action === 'CreateRole') {
                    return iamHandlers.
                        createRoleHandler(iamClient)(req, res, next);
                } else if (action === 'GetRole') {
                    return iamHandlers.
                        getRoleHandler(iamClient)(req, res, next);
                } else if (action === 'PutRolePolicy') {
                    return iamHandlers.
                        putRolePolicyHandler(iamClient)(req, res, next);
                } else if (action === 'DeleteRolePolicy') {
                    return iamHandlers.
                        deleteRolePolicyHandler(iamClient)(req, res, next);
                } else if (action === 'DeleteRole') {
                    return iamHandlers.
                        deleteRoleHandler(iamClient)(req, res, next);
                } else if (action === 'ListRoles') {
                    return iamHandlers.
                        listRolesHandler(iamClient)(req, res, next);
                } else if (action === 'ListRolePolicies') {
                    return iamHandlers.
                        listRolePoliciesHandler(iamClient)(req, res, next);
                } else if (action === 'GetRolePolicy') {
                    return iamHandlers.
                        getRolePolicyHandler(iamClient)(req, res, next);
                } else {
                    res.send(501, {error: action + ' not implemented yet'});
                    return (next(false));
                }
            });
            return; // Important: don't continue to regular auth flow
        }

        if (action === 'AssumeRole' || action === 'GetSessionToken' ||
            action === 'GetCallerIdentity') {

            // For STS requests, bypass authentication and route directly
            // but first get a real caller UUID from the authorization header
            var stsAuthHeader = req.headers.authorization;
            if (stsAuthHeader) {
                // Extract access key from authorization header for UUID lookup
                var stsAccessKeyMatch =
                    //JSSTYLED
                    stsAuthHeader.match(/Credential=([^\/]+)/);
                if (stsAccessKeyMatch) {
                    var stsAccessKeyId = stsAccessKeyMatch[1];
                    req.log.debug({accessKeyId: stsAccessKeyId},
                                  'STS: Extracted access key from auth header');

                    // Make a quick call to Mahi to get the user UUID for
                    // this access key
                    var stsMahiClient = clients.mahi;
                    if (stsMahiClient) {
                        stsMahiClient.getUserByAccessKey(stsAccessKeyId,
                                                         function (authErr,
                                                                   authRes) {
                            if (authErr || !authRes.account) {
                                req.log.warn({
                                    err: authErr,
                                    accessKeyId: stsAccessKeyId
                                }, 'STS: Failed to get caller from access key' +
                                   ' - failing securely');
                                var keyAuthError = s3Compat.convertErrorToS3({
                                    name: 'InvalidUserID.NotFound',
                                    message:
                                    'Invalid access key for STS operation',
                                    statusCode: 401
                                }, null, req);
                                res.setHeader('Content-Type',
                                              'application/xml');
                                res.writeHead(401);
                                res.end(keyAuthError);
                                return (next(false));
                            } else {
                                req.caller = authRes;
                                /*
                                 * Mahi returns assumedRole as a string ARN, but
                                 * sts-client.js expects an object with an 'arn'
                                 * property.
                                 */
                                if (req.caller.assumedRole &&
                                    typeof (req.caller.assumedRole) ===
                                    'string') {
                                    var roleArnString = req.caller.assumedRole;
                                    req.caller.assumedRole = {
                                        arn: roleArnString
                                    };
                                }

                                req.log.debug({authRes: authRes,
                                              keyused: stsAccessKeyId },
                                             'STS AUTH');
                                /*
                                 * Set req.auth from Mahi response. Mahi
                                 * returns credential type info directly,
                                 * no need to check access key prefix.
                                 */
                                req.auth = {
                                    accessKeyId: stsAccessKeyId,
                                    assumedRole: authRes.assumedRole || null,
                                    isTemporaryCredential:
                                        authRes.isTemporaryCredential ||
                                        authRes.isTemporary || false,
                                    sessionName: authRes.sessionName || null,
                                    principalUuid: authRes.principalUuid ||
                                        (authRes.account &&
                                         authRes.account.uuid)
                                };
                                req.log.debug({
                                    callerUuid: req.caller.account.uuid,
                                    callerLogin: req.caller.account.login,
                                    isTemporaryCredential:
                                        req.auth.isTemporaryCredential,
                                    hasAssumedRole: !!req.auth.assumedRole,
                                    assumedRole: req.auth.assumedRole
                                }, 'STS: Got caller from access key lookup');
                            }

                            // Route to STS handler
                            if (action === 'AssumeRole') {
                                return stsHandlers.
                                    assumeRoleHandler(stsClient)
                                (req, res, next);
                            } else if (action === 'GetSessionToken') {
                                return stsHandlers.
                                    getSessionTokenHandler(stsClient)
                                (req, res, next);
                            } else if (action === 'GetCallerIdentity') {
                                return stsHandlers.
                                    getCallerIdentityHandler(stsClient)
                                (req, res, next);
                            }
                        });
                        return;
                    }
                }
            }
            req.log.warn('STS request missing auth header or Mahi' +
                        ' unavailable - failing securely');
            var stsAuthError = s3Compat.convertErrorToS3({
                name: 'InvalidUserID.NotFound',
                message: 'Authentication required for STS operations',
                statusCode: 401
            }, null, req);
            res.setHeader('Content-Type', 'application/xml');
            res.writeHead(401);
            res.end(stsAuthError);
            return (next(false));
        }

        // Continue to regular authentication for non-STS requests
        // (including IAM)
        if (req.isS3Request) {
            if (req.isIAMRequest) {
                req.log.debug('S3_DEBUG: IAM request,' +
                              ' continuing to regular authentication');
            } else {
                req.log.debug('S3_DEBUG: Not an STS or IAM request,' +
                              ' continuing to regular authentication');
            }
        }
        next();
    };
}


///--- Exports

module.exports = {
    createStsIamHandler: createStsIamHandler
};
