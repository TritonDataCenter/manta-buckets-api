/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * STS client for communicating with Mahi STS endpoints
 */

var assert = require('assert-plus');
var restifyClients = require('restify-clients');
var VError = require('verror');

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
          } : null,
          // Pass roleArn if caller is using assumed-role credentials
          // This is needed for trust policy validation in Mahi
          roleArn: opts.caller.assumedRole ? opts.caller.assumedRole.arn : null
      }
    };

    log.debug({
        roleArn: roleArn,
        roleSessionName: opts.roleSessionName,
        durationSeconds: requestBody.DurationSeconds,
        caller: requestBody.caller,
        callerHasAssumedRole: !!opts.caller.assumedRole,
        callerAssumedRoleArn: opts.caller.assumedRole ?
            opts.caller.assumedRole.arn : null
    }, 'SECURITY DEBUG: Calling Mahi AssumeRole endpoint with caller info');

    client.post({
        path: '/sts/assume-role'
    }, requestBody, function (err, req, res, data) {
        if (err) {
            log.debug({
                err: err,
                errBody: err.body,
                errName: err.name,
                errCode: err.code,
                roleArn: roleArn,
                statusCode: res ? res.statusCode : 'unknown'
            }, 'AssumeRole request to Mahi failed');

            // Extract error details from Mahi response
            var errorCode = 'InternalError';
            var errorMessage = 'Failed to assume role';

            // Check if error has a body with error details
            if (err.body && typeof (err.body) === 'object') {
                errorCode = err.body.code || err.body.name || errorCode;
                errorMessage = err.body.message || err.message || errorMessage;
            } else if (err.name && err.name !== 'Error') {
                errorCode = err.name;
                errorMessage = err.message || errorMessage;
            } else if (err.message) {
                errorMessage = err.message;
            }

            // Create error with proper code/name for XML conversion
            var stsError = new Error(errorMessage);
            stsError.name = errorCode;
            stsError.code = errorCode;
            stsError.statusCode = (res && res.statusCode) || 500;

            log.debug({
                finalErrorCode: errorCode,
                finalErrorMessage: errorMessage,
                statusCode: stsError.statusCode
            }, 'AssumeRole error details extracted');

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
        DurationSeconds: opts.durationSeconds || 3600,
        caller: {
            account: opts.caller.account ? {
                uuid: opts.caller.account.uuid,
                login: opts.caller.account.login
            } : null,
            user: opts.caller.user ? {
                uuid: opts.caller.user.uuid,
                login: opts.caller.user.login
            } : null
        }
    };

    log.debug({
        durationSeconds: requestBody.DurationSeconds,
        callerUuid: opts.caller.account.uuid
    }, 'Calling Mahi GetSessionToken endpoint');

    client.post({
        path: '/sts/get-session-token'
    }, requestBody, function (err, req, res, data) {
        if (err) {
            log.debug({
                err: err,
                errBody: err.body,
                errName: err.name,
                errCode: err.code,
                statusCode: res ? res.statusCode : 'unknown'
            }, 'GetSessionToken request to Mahi failed');

            // Extract error details from Mahi response
            var errorCode = 'InternalError';
            var errorMessage = 'Failed to get session token';

            // Check if error has a body with error details
            if (err.body && typeof (err.body) === 'object') {
                errorCode = err.body.code || err.body.name || errorCode;
                errorMessage = err.body.message || err.message || errorMessage;
            } else if (err.name && err.name !== 'Error') {
                errorCode = err.name;
                errorMessage = err.message || errorMessage;
            } else if (err.message) {
                errorMessage = err.message;
            }

            // Create error with proper code/name for XML conversion
            var stsError = new Error(errorMessage);
            stsError.name = errorCode;
            stsError.code = errorCode;
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

    var requestBody = {
        caller: {
            account: opts.caller.account ? {
                uuid: opts.caller.account.uuid,
                login: opts.caller.account.login
            } : null,
            user: opts.caller.user ? {
                uuid: opts.caller.user.uuid,
                login: opts.caller.user.login
            } : null
        }
    };

    // Pass assumed role info for temporary credentials in headers
    var requestHeaders = {};
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

    var postOptions = {
        path: '/sts/get-caller-identity',
        headers: requestHeaders
    };

    // Ensure Content-Type is set for JSON body
    if (!postOptions.headers) {
        postOptions.headers = {};
    }
    postOptions.headers['content-type'] = 'application/json';

    // StringClient doesn't auto-serialize JSON, so we need to do it manually
    var requestBodyString = JSON.stringify(requestBody);

    client.post(postOptions, requestBodyString, function (err, req, res, data) {
        if (err) {
            log.debug({
                err: err,
                errBody: err.body,
                errName: err.name,
                errCode: err.code,
                statusCode: res ? res.statusCode : 'unknown'
            }, 'GetCallerIdentity request to Mahi failed');

            // Extract error details from Mahi response
            var errorCode = 'InternalError';
            var errorMessage = 'Failed to get caller identity';

            // Check if error has a body with error details
            if (err.body && typeof (err.body) === 'object') {
                errorCode = err.body.code || err.body.name || errorCode;
                errorMessage = err.body.message || err.message || errorMessage;
            } else if (err.name && err.name !== 'Error') {
                errorCode = err.name;
                errorMessage = err.message || errorMessage;
            } else if (err.message) {
                errorMessage = err.message;
            }

            // Create error with proper code/name for XML conversion
            var stsError = new Error(errorMessage);
            stsError.name = errorCode;
            stsError.code = errorCode;
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

module.exports = STSClient;
