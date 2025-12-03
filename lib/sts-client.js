/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * STS client for communicating with Mahi STS endpoints
 */

var assert = require('assert-plus');
var restifyClients = require('restify-clients');
var VError = require('verror');
var IAMClient = require('./iam-client');
var TrustPolicyEngine = require('./trust-policy-engine').TrustPolicyEngine;

function STSClient(options) {
    assert.object(options, 'options');
    assert.string(options.url, 'options.url');
    assert.object(options.log, 'options.log');
    assert.optionalNumber(options.connectTimeout, 'options.connectTimeout');
    assert.optionalNumber(options.requestTimeout, 'options.requestTimeout');

    this.log = options.log.child({component: 'STSClient'});
    this.client = restifyClients.createJsonClient({
        url: options.url,
        connectTimeout: options.connectTimeout || 1000,
        requestTimeout: options.requestTimeout || 10000,
        userAgent: 'manta-buckets-api-sts-client',
        retry: false
    });

    // String client for XML responses (like GetCallerIdentity)
    this.stringClient = restifyClients.createStringClient({
        url: options.url,
        connectTimeout: options.connectTimeout || 1000,
        requestTimeout: options.requestTimeout || 10000,
        userAgent: 'manta-buckets-api-sts-client',
        retry: false
    });

    // IAM client for role validation
    this.iamClient = new IAMClient({
        url: options.url,
        log: options.log,
        connectTimeout: options.connectTimeout,
        requestTimeout: options.requestTimeout
    });

    // Trust policy engine for role assumption validation
    this.trustPolicyEngine = new TrustPolicyEngine({
        log: options.log,
        strictMode: true
    });
}

/**
 * Call Mahi's AssumeRole STS endpoint
 */
STSClient.prototype.assumeRole = function assumeRole(opts, callback) {
    assert.object(opts, 'opts');
    assert.string(opts.roleArn, 'opts.roleArn');
    assert.string(opts.roleSessionName, 'opts.roleSessionName');
    assert.optionalNumber(opts.durationSeconds, 'opts.durationSeconds');
    assert.object(opts.caller, 'opts.caller');
    assert.func(callback, 'callback');

    var log = this.log;
    var client = this.client;

    // Convert Manta role to ARN format if needed
    var roleArn = opts.roleArn;
    if (!roleArn.startsWith('arn:aws:iam::')) {
        // Convert Manta role to AWS ARN format
        // Format: arn:aws:iam::ACCOUNT_UUID:role/ROLE_NAME
        roleArn = 'arn:aws:iam::' + opts.caller.account.uuid + ':role/' +
            opts.roleArn;
    }

    // we send subuser as well, in the caller context for authentication.
    var requestBody = {
        RoleArn: roleArn,
        RoleSessionName: opts.roleSessionName,
        DurationSeconds: opts.durationSeconds || 3600,
        caller: {
          account: opts.caller.account ? {
              uuid: opts.caller.account.uuid,
              login: opts.caller.account.login
          }: null,
          user: opts.caller.user ? {
              uuid: opts.caller.user.uuid,
              login: opts.caller.user.login
          } : null
      }
    };

    log.debug({
        roleArn: roleArn,
        roleSessionName: opts.roleSessionName,
        durationSeconds: requestBody.DurationSeconds,
        caller: requestBody.caller
    }, 'Calling Mahi AssumeRole endpoint');

    client.post({
        path: '/sts/assume-role'
    }, requestBody, function (err, req, res, data) {
        if (err) {
            log.debug({
                err: err,
                roleArn: roleArn,
                statusCode: res ? res.statusCode : 'unknown'
            }, 'AssumeRole request to Mahi failed');

            var stsError = new VError(err, 'Failed to assume role');
            stsError.statusCode = (res && res.statusCode) || 500;
            return (callback(stsError));
        }

        if (!data || !data.AssumeRoleResponse ||
            !data.AssumeRoleResponse.AssumeRoleResult) {
            log.debug({
                data: data,
                roleArn: roleArn
            }, 'Invalid response from Mahi AssumeRole');

            var invalidError =
                new VError('Invalid STS response from authentication service');
            invalidError.statusCode = 502;
            return (callback(invalidError));
        }

        log.debug({
            roleArn: roleArn,
            accessKeyId:
            data.AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId,
            expiration:
            data.AssumeRoleResponse.AssumeRoleResult.Credentials.Expiration
        }, 'Successfully assumed role via Mahi');

        callback(null, data.AssumeRoleResponse.AssumeRoleResult);
    });
};

/**
 * Call Mahi's GetSessionToken STS endpoint
 */
STSClient.prototype.getSessionToken = function getSessionToken(opts, callback) {
    assert.object(opts, 'opts');
    assert.optionalNumber(opts.durationSeconds, 'opts.durationSeconds');
    assert.object(opts.caller, 'opts.caller');
    assert.func(callback, 'callback');

    var log = this.log;
    var client = this.client;

    var requestBody = {
        DurationSeconds: opts.durationSeconds || 3600
    };

    // Add caller context for authentication
    var requestHeaders = {
        'x-caller-uuid': opts.caller.account.uuid,
        'x-caller-login': opts.caller.account.login
    };

    if (opts.caller.user) {
        requestHeaders['x-caller-user-uuid'] = opts.caller.user.uuid;
        requestHeaders['x-caller-user-login'] = opts.caller.user.login;
    }

    log.debug({
        durationSeconds: requestBody.DurationSeconds,
        callerUuid: opts.caller.account.uuid
    }, 'Calling Mahi GetSessionToken endpoint');

    client.post({
        path: '/sts/get-session-token',
        headers: requestHeaders
    }, requestBody, function (err, req, res, data) {
        if (err) {
            log.debug({
                err: err,
                statusCode: res ? res.statusCode : 'unknown'
            }, 'GetSessionToken request to Mahi failed');

            var stsError = new VError(err, 'Failed to get session token');
            stsError.statusCode = (res && res.statusCode) || 500;
            return (callback(stsError));
        }

        if (!data || !data.GetSessionTokenResponse ||
            !data.GetSessionTokenResponse.GetSessionTokenResult) {
            log.debug({
                data: data
            }, 'Invalid response from Mahi GetSessionToken');

            var invalidError =
                new VError('Invalid STS response from authentication service');
            invalidError.statusCode = 502;
            return (callback(invalidError));
        }

        log.debug({
            accessKeyId:
            data.GetSessionTokenResponse.GetSessionTokenResult.Credentials.
                AccessKeyId,
            expiration:
            data.GetSessionTokenResponse.GetSessionTokenResult.Credentials.
                Expiration
        }, 'Successfully obtained session token via Mahi');

        callback(null, data.GetSessionTokenResponse.GetSessionTokenResult);
    });
};

/**
 * Call Mahi's GetCallerIdentity STS endpoint
 */
STSClient.prototype.getCallerIdentity =
    function getCallerIdentity(opts, callback) {
    assert.object(opts, 'opts');
    assert.object(opts.caller, 'opts.caller');
    assert.func(callback, 'callback');

    var log = this.log;
    var client = this.stringClient;  // Use string client for XML response

    // Add caller context for authentication
    var requestHeaders = {
        'x-caller-uuid': opts.caller.account.uuid,
        'x-caller-login': opts.caller.account.login
    };

    if (opts.caller.user) {
        requestHeaders['x-caller-user-uuid'] = opts.caller.user.uuid;
        requestHeaders['x-caller-user-login'] = opts.caller.user.login;
    }

    // Pass assumed role info for temporary credentials
    if (opts.isTemporaryCredential && opts.assumedRole) {
        var roleArn = (typeof (opts.assumedRole) === 'string') ?
            opts.assumedRole : opts.assumedRole.arn;
        requestHeaders['x-assumed-role-arn'] = roleArn;
        if (opts.sessionName) {
            requestHeaders['x-session-name'] = opts.sessionName;
        }
        requestHeaders['x-is-temporary-credential'] = 'true';
    }

    log.debug({
        callerUuid: opts.caller.account.uuid,
        callerLogin: opts.caller.account.login,
        isTemporaryCredential: opts.isTemporaryCredential,
        assumedRoleArn: opts.assumedRole ?
            (typeof (opts.assumedRole) === 'string' ?
                opts.assumedRole : opts.assumedRole.arn) : null
    }, 'Calling Mahi GetCallerIdentity endpoint');

    client.post({
        path: '/sts/get-caller-identity',
        headers: requestHeaders
    }, {}, function (err, req, res, data) {
        if (err) {
            log.debug({
                err: err,
                statusCode: res ? res.statusCode : 'unknown'
            }, 'GetCallerIdentity request to Mahi failed');

            var stsError = new VError(err, 'Failed to get caller identity');
            stsError.statusCode = (res && res.statusCode) || 500;
            return (callback(stsError));
        }

        // For GetCallerIdentity, Mahi returns XML directly
        // No need to parse JSON response
        log.debug({
            callerUuid: opts.caller.account.uuid,
            callerLogin: opts.caller.account.login,
            responseLength: data ? data.length : 0
        }, 'Successfully obtained caller identity via Mahi');

        // Return the raw XML data from Mahi
        callback(null, { body: data });
    });
};

/**
 * Validate that a role exists and caller has permission to assume it
 */
STSClient.prototype.validateRole = function validateRole(opts, callback) {
    assert.object(opts, 'opts');
    assert.string(opts.roleArn, 'opts.roleArn');
    assert.object(opts.caller, 'opts.caller');
    assert.func(callback, 'callback');

    var self = this;
    var log = this.log;
    var roleArn = opts.roleArn;

    // Extract role name from ARN
    var roleName = null;
    if (roleArn && roleArn.indexOf('arn:aws:iam::') === 0) {
        var arnParts = roleArn.split(':');
        if (arnParts.length >= 6) {
            roleName = arnParts[5].replace('role/', '');
        }
    }

    if (!roleName) {
        var invalidError = new Error('Invalid role ARN format');
        invalidError.name = 'InvalidParameterValue';
        invalidError.statusCode = 400;
        return (callback(invalidError));
    }

    log.debug({
        roleArn: roleArn,
        roleName: roleName,
        callerUuid: opts.caller.account.uuid
    }, 'Validating role exists via IAM client');

    // Check if role exists via IAM client
    this.iamClient.getRole({
        roleName: roleName,
        caller: opts.caller
    }, function (err, roleData) {
        if (err) {
            if (err.statusCode === 404) {
                log.debug({
                    roleArn: roleArn,
                    roleName: roleName,
                    callerUuid: opts.caller.account.uuid
                }, 'Role does not exist');

                var notFoundError =
                    new Error('Role does not exist: ' + roleName);
                notFoundError.name = 'NoSuchRole';
                notFoundError.statusCode = 404;
                return (callback(notFoundError));
            }
            return (callback(err));
        }

        log.debug({
            roleArn: roleArn,
            roleName: roleName,
            callerUuid: opts.caller.account.uuid
        }, 'Role validation successful - role exists');

        // Role exists - now validate trust policy for role assumption
        self._validateTrustPolicy(roleData, opts.caller, {
            sourceIp: opts.sourceIp,
            requestTime: new Date(),
            mfa: opts.caller.mfaAuthenticated || false,
            externalId: opts.externalId,
            userAgent: opts.userAgent
        }, function (trustErr, evaluation) {
            if (trustErr) {
                log.debug({
                    err: trustErr,
                    roleArn: roleArn,
                    callerUuid: opts.caller.account.uuid
                }, 'Trust policy validation failed');
                return (callback(trustErr));
            }

            if (evaluation.decision !== 'Allow') {
                log.debug({
                    roleArn: roleArn,
                    callerUuid: opts.caller.account.uuid,
                    decision: evaluation.decision,
                    reason: evaluation.reason
                }, 'Role assumption denied by trust policy');

                var accessDeniedError =
                    new Error('Access denied: ' + evaluation.reason);
                accessDeniedError.name = 'AccessDenied';
                accessDeniedError.statusCode = 403;
                accessDeniedError.code = 'AccessDenied';
                return (callback(accessDeniedError));
            }

            log.debug({
                roleArn: roleArn,
                roleName: roleName,
                callerUuid: opts.caller.account.uuid,
                trustPolicyDecision: evaluation.decision
            }, 'Role assumption authorized by trust policy');

            callback(null, {
                roleArn: roleArn,
                roleName: roleName,
                roleData: roleData,
                valid: true,
                trustPolicyEvaluation: evaluation
            });
        });
    });
};

/**
 * @brief Validates trust policy for role assumption
 *
 * Evaluates the role's AssumeRolePolicyDocument against the requesting
 * principal and context to determine if role assumption should be allowed.
 *
 * @param {Object} roleData Role information from IAM
 * @param {Object} caller Requesting principal information
 * @param {Object} context Request context for condition evaluation
 * @param {Function} callback Callback function (err, evaluation)
 */
STSClient.prototype._validateTrustPolicy = function _validateTrustPolicy(
    roleData, caller, context, callback) {
    assert.object(roleData, 'roleData');
    assert.object(caller, 'caller');
    assert.object(context, 'context');
    assert.func(callback, 'callback');

    var self = this;
    var log = self.log;

    try {
        // Extract trust policy from role data
        var trustPolicyDoc = roleData.assumeRolePolicyDocument;

        if (!trustPolicyDoc) {
            log.debug({
                roleArn: roleData.arn,
                callerUuid: caller.account.uuid
            }, 'Role has no trust policy document - denying assumption');

            return (callback(null, {
                decision: 'Deny',
                reason: 'NoTrustPolicy',
                details: 'Role has no AssumeRolePolicyDocument'
            }));
        }

        // Parse trust policy if it's a string
        var trustPolicy;
        if (typeof (trustPolicyDoc) === 'string') {
            try {
                trustPolicy = JSON.parse(trustPolicyDoc);
            } catch (parseErr) {
                log.debug({
                    err: parseErr,
                    roleArn: roleData.arn,
                    trustPolicyDoc: trustPolicyDoc
                }, 'Failed to parse trust policy document');

                return (callback(null, {
                    decision: 'Deny',
                    reason: 'InvalidTrustPolicy',
                    details: 'Trust policy document is not valid JSON'
                }));
            }
        } else {
            trustPolicy = trustPolicyDoc;
        }

        // Build principal information for evaluation
        var principal = {
            arn: self._buildPrincipalArn(caller),
            account: caller.account.uuid,
            type: self._getPrincipalType(caller),
            userId: caller.uuid,
            userName: caller.login
        };

        // Add service or federated principal info if applicable
        if (principal.type === 'service') {
            principal.service = caller.service;
        } else if (principal.type === 'federated') {
            principal.provider = caller.provider;
        }

        log.debug({
            roleArn: roleData.arn,
            principal: principal,
            context: context
        }, 'Evaluating trust policy for role assumption');

        // Evaluate trust policy using the engine
        var evaluation = self.trustPolicyEngine.evaluate(trustPolicy,
                                                         principal, context);

        log.debug({
            roleArn: roleData.arn,
            principalArn: principal.arn,
            decision: evaluation.decision,
            reason: evaluation.reason
        }, 'Trust policy evaluation completed');

        callback(null, evaluation);

    } catch (err) {
        log.debug({
            err: err,
            roleArn: roleData.arn,
            callerUuid: caller.account.uuid
        }, 'Trust policy validation failed with unexpected error');

        callback(null, {
            decision: 'Deny',
            reason: 'EvaluationError',
            details: err.message
        });
    }
};

/**
 * @brief Builds ARN for the requesting principal
 * @private
 */
STSClient.prototype._buildPrincipalArn = function _buildPrincipalArn(caller) {
    // Build Manta-style ARN for the caller
    // Format: arn:manta:iam::account:user/username or
    // arn:manta:iam::account:role/rolename

    var accountId = caller.account.uuid;
    var principalType = this._getPrincipalType(caller);
    var principalName = caller.login;

    if (principalType === 'user') {
        return ('arn:manta:iam::' + accountId + ':user/' + principalName);
    } else if (principalType === 'role') {
        return ('arn:manta:iam::' + accountId + ':role/' + principalName);
    } else if (principalType === 'service') {
        return ('arn:manta:iam::' + accountId + ':service/' +
                (caller.service || principalName));
    } else {
        // Default to user type
        return ('arn:manta:iam::' + accountId + ':user/' + principalName);
    }
};

/**
 * @brief Determines the type of the requesting principal
 * @private
 */
STSClient.prototype._getPrincipalType = function _getPrincipalType(caller) {
    // Determine principal type based on caller properties
    if (caller.type) {
        return (caller.type);
    }

    // Check if this is a service principal
    if (caller.service || (caller.login &&
                           caller.login.endsWith('.amazonaws.com'))) {
        return ('service');
    }

    // Check if this is a federated principal
    if (caller.provider || caller.federatedProvider) {
        return ('federated');
    }

    // Check if this is a role (has role-like properties)
    if (caller.isRole || (caller.roles && caller.roles.length > 0)) {
        return ('role');
    }

    // Default to user
    return ('user');
};

module.exports = STSClient;
