/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * AWS STS endpoint handlers for manta-buckets-api
 * These proxy STS requests to Mahi's STS service
 */

var assert = require('assert-plus');
var STSClient = require('./sts-client');
var s3Compat = require('./s3-compat');
var iamUtils = require('./iam-utils');

/**
 * Create STS client instance
 */
function createSTSClient(config, log) {
    assert.object(config, 'config');
    assert.string(config.auth.url, 'config.auth.url');
    assert.object(log, 'log');

    return new STSClient({
        url: config.auth.url,
        log: log,
        connectTimeout: config.auth.connectTimeout || 1000,
        requestTimeout: config.auth.requestTimeout || 10000
    });
}

/**
 * Build AWS STS/IAM error response (different format from S3 errors)
 */
function buildSTSErrorXMLResponse(error) {
    var requestId = s3Compat.generateRequestId(16);
    var errorCode = error.name || error.code || 'InternalFailure';
    var errorMessage = s3Compat.escapeXml(error.message || 'An error occurred');
    var errorType = (error.statusCode && error.statusCode < 500) ?
        'Sender' : 'Receiver';

    return '<?xml version="1.0" encoding="UTF-8"?>\n' +
        '<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">\n' +
        '  <Error>\n' +
        '    <Type>' + errorType + '</Type>\n' +
        '    <Code>' + s3Compat.escapeXml(errorCode) + '</Code>\n' +
        '    <Message>' + errorMessage + '</Message>\n' +
        '  </Error>\n' +
        '  <RequestId>' + requestId + '</RequestId>\n' +
        '</ErrorResponse>';
}

/**
 * AWS STS AssumeRole handler
 * Handles POST requests to /?Action=AssumeRole
 */
function assumeRoleHandler(stsClient) {
    return function handleAssumeRole(req, res, next) {
        var log = req.log;

        log.debug({
            query: req.query,
            body: req.body,
            headers: req.headers
        }, 'STS AssumeRole request received');

        // Parse STS parameters (can come from query or body)
        // awscli sends them in body.
        var roleArn = req.query.RoleArn || req.body.RoleArn;
        var roleSessionName = req.query.RoleSessionName ||
            req.body.RoleSessionName;
        var durationSeconds = req.query.DurationSeconds ||
            req.body.DurationSeconds;

        // If body is a URL-encoded string, parse parameters manually
        if (!roleArn && typeof (req.body) === 'string') {
            var params = iamUtils.parseUrlEncodedBody(req.body);

            roleArn = roleArn || params.RoleArn;
            roleSessionName = roleSessionName || params.RoleSessionName;
            durationSeconds = durationSeconds || params.DurationSeconds;

            log.debug({
                parsedParams: params,
                extractedRoleArn: roleArn,
                extractedRoleSessionName: roleSessionName
            }, 'STS: Parsed parameters from URL-encoded body');
        }

        // Validate required parameters
        if (!roleArn) {
            var error = buildSTSErrorXMLResponse({
                name: 'InvalidParameterValue',
                message: 'RoleArn is required for AssumeRole operation',
                statusCode: 400
            });
            res.setHeader('Content-Type', 'text/xml');
            res.writeHead(400);
            res.end(error);
            return (next(false));
        }

        if (!roleSessionName) {
            var sessionNameError = buildSTSErrorXMLResponse({
                name: 'InvalidParameterValue',
                message: 'RoleSessionName is required for AssumeRole operation',
                statusCode: 400
            });
            res.setHeader('Content-Type', 'text/xml');
            res.writeHead(400);
            res.end(sessionNameError);
            return (next(false));
        }

        // STS requests should have caller set by the routing layer
        log.debug({
            callerUuid: req.caller ? req.caller.account.uuid : null,
            callerLogin: req.caller ? req.caller.account.login : null,
            callerStructure: req.caller ?
                JSON.stringify(req.caller, null, 2) : null
        }, 'STS: AssumeRole called with caller');

        // Validate caller authentication
        if (!iamUtils.requireAuthentication(req, res, next, 'STS')) {
            return;
        }

        // Note: Trust policy validation is now implemented in
        // mahi/lib/server/sts.js
        // Mahi will fetch the role's AssumeRolePolicyDocument and
        // validate against the caller

        // Call Mahi's AssumeRole endpoint which includes
        // trust policy validation
        stsClient.assumeRole({
            roleArn: roleArn,
            roleSessionName: roleSessionName,
            durationSeconds: durationSeconds ?
                parseInt(durationSeconds, 10) : undefined,
            caller: req.caller
        }, function (err, result) {
            if (err) {
                log.debug({
                    err: err,
                    roleArn: roleArn,
                    callerUuid: req.caller.account.uuid
                }, 'AssumeRole operation failed');

                var assumeError = buildSTSErrorXMLResponse(err);
                res.setHeader('Content-Type', 'text/xml');
                res.writeHead(err.statusCode || 500);
                res.end(assumeError);
                return (next(false));
            }

            log.debug({
                roleArn: roleArn,
                roleSessionName: roleSessionName,
                accessKeyId: result.Credentials.AccessKeyId,
                callerUuid: req.caller.account.uuid
            }, 'AssumeRole operation completed successfully');

            // Convert to AWS STS XML response format
            var xmlResponse = buildAssumeRoleXMLResponse(result);

            res.setHeader('Content-Type', 'text/xml');
            res.writeHead(200);
            res.end(xmlResponse);
            next(false); // Stop middleware chain
        });
    };
}

/**
 * AWS STS GetSessionToken handler
 * Handles POST requests to /?Action=GetSessionToken
 */
function getSessionTokenHandler(stsClient) {
    return function handleGetSessionToken(req, res, next) {
        var log = req.log;

        log.debug({
            query: req.query,
            body: req.body,
            headers: req.headers
        }, 'STS GetSessionToken request received');

        // Parse STS parameters
        var durationSeconds = req.query.DurationSeconds ||
            req.body.DurationSeconds;

        // If body is a URL-encoded string, parse parameters manually
        if (!durationSeconds && typeof (req.body) === 'string') {
            var params = iamUtils.parseUrlEncodedBody(req.body);

            durationSeconds = durationSeconds || params.DurationSeconds;

            log.debug({
                parsedParams: params,
                extractedDurationSeconds: durationSeconds
            }, 'STS: Parsed parameters from URL-encoded body');
        }

        // STS requests should have caller set by the routing layer
        log.debug({
            callerUuid: req.caller ? req.caller.account.uuid : null,
            callerLogin: req.caller ? req.caller.account.login : null
        }, 'STS: GetSessionToken called with caller');

        // Validate caller authentication
        if (!iamUtils.requireAuthentication(req, res, next, 'STS')) {
            return;
        }

        // Call Mahi's GetSessionToken endpoint
        stsClient.getSessionToken({
            durationSeconds: durationSeconds ?
                parseInt(durationSeconds, 10) : undefined,
            caller: req.caller
        }, function (err, result) {
            if (err) {
                log.debug({
                    err: err,
                    callerUuid: req.caller.account.uuid
                }, 'GetSessionToken operation failed');

                var sessionError = buildSTSErrorXMLResponse(err);
                res.setHeader('Content-Type', 'text/xml');
                res.writeHead(err.statusCode || 500);
                res.end(sessionError);
                return (next(false));
            }

            log.debug({
                accessKeyId: result.Credentials.AccessKeyId,
                callerUuid: req.caller.account.uuid
            }, 'GetSessionToken operation completed successfully');

            // Convert to AWS STS XML response format
            var xmlResponse = buildGetSessionTokenXMLResponse(result);

            res.setHeader('Content-Type', 'text/xml');
            res.writeHead(200);
            res.end(xmlResponse);
            next(false); // Stop middleware chain
        });
    };
}

/**
 * Build AWS STS AssumeRole XML response
 */
function buildAssumeRoleXMLResponse(result) {
    var credentials = result.Credentials;
    var assumedRoleUser = result.AssumedRoleUser;
    /* BEGIN JSSTYLED */
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">\n';
    xml += '  <AssumeRoleResult>\n';
    xml += '    <Credentials>\n';
    xml += '      <AccessKeyId>' + s3Compat.escapeXml(credentials.AccessKeyId) + '</AccessKeyId>\n';
    xml += '      <SecretAccessKey>' + s3Compat.escapeXml(credentials.SecretAccessKey) + '</SecretAccessKey>\n';
    xml += '      <SessionToken>' + s3Compat.escapeXml(credentials.SessionToken) + '</SessionToken>\n';
    xml += '      <Expiration>' + s3Compat.escapeXml(credentials.Expiration) + '</Expiration>\n';
    xml += '    </Credentials>\n';
    xml += '    <AssumedRoleUser>\n';
    xml += '      <AssumedRoleId>' + s3Compat.escapeXml(assumedRoleUser.AssumedRoleId) + '</AssumedRoleId>\n';
    xml += '      <Arn>' + s3Compat.escapeXml(assumedRoleUser.Arn) + '</Arn>\n';
    xml += '    </AssumedRoleUser>\n';
    xml += '  </AssumeRoleResult>\n';
    xml += '  <ResponseMetadata>\n';
    xml += '    <RequestId>' + s3Compat.generateRequestId(16) + '</RequestId>\n';
    xml += '  </ResponseMetadata>\n';
    xml += '</AssumeRoleResponse>\n';
    /* END JSSTYLED */
    return (xml);
}

/**
 * Build AWS STS GetSessionToken XML response
 */
function buildGetSessionTokenXMLResponse(result) {
    var credentials = result.Credentials;

    /* BEGIN JSSTYLED */
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<GetSessionTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">\n';
    xml += '  <GetSessionTokenResult>\n';
    xml += '    <Credentials>\n';
    xml += '      <AccessKeyId>' + s3Compat.escapeXml(credentials.AccessKeyId) + '</AccessKeyId>\n';
    xml += '      <SecretAccessKey>' + s3Compat.escapeXml(credentials.SecretAccessKey) + '</SecretAccessKey>\n';
    xml += '      <SessionToken>' + s3Compat.escapeXml(credentials.SessionToken) + '</SessionToken>\n';
    xml += '      <Expiration>' + s3Compat.escapeXml(credentials.Expiration) + '</Expiration>\n';
    xml += '    </Credentials>\n';
    xml += '  </GetSessionTokenResult>\n';
    xml += '  <ResponseMetadata>\n';
    xml += '    <RequestId>' + s3Compat.generateRequestId(16) + '</RequestId>\n';
    xml += '  </ResponseMetadata>\n';
    xml += '</GetSessionTokenResponse>\n';
    /* END JSSTYLED */
    return (xml);
}

/**
 * Generate AWS-compatible request ID
 */
/**
 * AWS STS GetCallerIdentity handler
 * Handles POST requests to /?Action=GetCallerIdentity
 */
function getCallerIdentityHandler(stsClient) {
    return function handleGetCallerIdentity(req, res, next) {
        var log = req.log;

        log.debug({
            query: req.query,
            body: req.body,
            headers: req.headers
        }, 'STS GetCallerIdentity request received');

        // STS requests should have caller set by the routing layer
        log.debug({
            callerUuid: req.caller ? req.caller.account.uuid : null,
            callerLogin: req.caller ? req.caller.account.login : null
        }, 'STS: GetCallerIdentity called with caller');

        // Validate caller authentication
        if (!iamUtils.requireAuthentication(req, res, next, 'STS')) {
            return;
        }

        // Call Mahi's GetCallerIdentity endpoint
        // Pass assumed role info if using temporary credentials
        log.debug({
            hasReqAuth: !!req.auth,
            reqAuthKeys: req.auth ? Object.keys(req.auth) : [],
            isTemporaryCredential: req.auth && req.auth.isTemporaryCredential,
            hasAssumedRole: req.auth && !!req.auth.assumedRole,
            assumedRole: req.auth && req.auth.assumedRole,
            sessionName: req.auth && req.auth.sessionName
        }, 'GetCallerIdentity: checking req.auth before calling Mahi');

        stsClient.getCallerIdentity({
            caller: req.caller,
            accessKeyId: req.auth && req.auth.accessKeyId,
            isTemporaryCredential: req.auth && req.auth.isTemporaryCredential,
            assumedRole: req.auth && req.auth.assumedRole,
            sessionName: req.auth && req.auth.sessionName
        }, function (err, result) {
            if (err) {
                log.error({
                    err: err,
                    callerUuid: req.caller.account.uuid,
                    callerLogin: req.caller.account.login,
                    statusCode: err.statusCode
                }, 'GetCallerIdentity operation failed');

                var callerIdError = buildSTSErrorXMLResponse(err);
                res.setHeader('Content-Type', 'text/xml');
                res.writeHead(err.statusCode || 500);
                res.end(callerIdError);
                return (next(false));
            }

            log.debug({
                callerUuid: req.caller.account.uuid,
                callerLogin: req.caller.account.login
            }, 'GetCallerIdentity operation successful');

            // Return the XML response directly (Mahi already formats it)
            res.setHeader('Content-Type', 'text/xml');
            res.writeHead(200);
            res.end(result.body || result);
            return (next(false));
        });
    };
}


module.exports = {
    createSTSClient: createSTSClient,
    assumeRoleHandler: assumeRoleHandler,
    getSessionTokenHandler: getSessionTokenHandler,
    getCallerIdentityHandler: getCallerIdentityHandler
};
