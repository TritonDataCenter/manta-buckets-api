/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * AWS IAM endpoint handlers for manta-buckets-api
 * These proxy IAM requests to Mahi's IAM service
 */

var assert = require('assert-plus');
var IAMClient = require('./iam-client');
var s3Compat = require('./s3-compat');
var policyConverter = require('./policy-converter');
var constants = require('./constants');
var iamUtils = require('./iam-utils');

/**
 * Create IAM client instance
 */
function createIAMClient(config, log) {
    assert.object(config, 'config');
    assert.string(config.auth.url, 'config.auth.url');
    assert.object(log, 'log');

    return new IAMClient({
        url: config.auth.url,
        log: log,
        connectTimeout: config.auth.connectTimeout || 1000,
        requestTimeout: config.auth.requestTimeout || 10000
    });
}

/**
 * AWS IAM CreateRole handler
 * Handles POST requests to /?Action=CreateRole
 */
function createRoleHandler(iamClient) {
    return function handleCreateRole(req, res, next) {
        var log = req.log;

        log.debug({
            query: req.query,
            body: req.body,
            headers: req.headers
        }, 'IAM CreateRole request received');

        // Parse IAM parameters from URL-encoded body
        var roleName, assumeRolePolicyDocument, description, path;

        // Parse from query parameters or body
        roleName = req.query.RoleName || req.body.RoleName;
        assumeRolePolicyDocument = req.query.AssumeRolePolicyDocument ||
            req.body.AssumeRolePolicyDocument;
        description = req.query.Description || req.body.Description;
        path = req.query.Path || req.body.Path;

        // If body is a URL-encoded string, parse parameters manually
        if (!roleName && typeof (req.body) === 'string') {
            var params = iamUtils.parseUrlEncodedBody(req.body);

            roleName = roleName || params.RoleName;
            assumeRolePolicyDocument = assumeRolePolicyDocument ||
                params.AssumeRolePolicyDocument;
            description = description || params.Description;
            path = path || params.Path;

            log.debug({
                parsedParams: params,
                extractedRoleName: roleName
            }, 'IAM: Parsed parameters from URL-encoded body');
        }

        // Decode URL-encoded policy document if needed
        // (fix + characters and decode)
        if (assumeRolePolicyDocument &&
            typeof (assumeRolePolicyDocument) === 'string') {
            try {
                // First replace + with spaces, then decode URI component
                var decodedPolicy = decodeURIComponent(assumeRolePolicyDocument.
                                                       replace(/\+/g, ' '));
                assumeRolePolicyDocument = decodedPolicy;

                log.debug({
                    originalPolicy: req.query.AssumeRolePolicyDocument ||
                        req.body.AssumeRolePolicyDocument,
                    decodedPolicy: decodedPolicy
                }, 'IAM: Decoded policy document');

            } catch (decodeErr) {
                log.warn({
                    err: decodeErr,
                    originalPolicy: assumeRolePolicyDocument
                }, 'IAM: Failed to decode policy document, using original');
            }
        }

        // Set default path if not provided
        path = path || '/';

        // Validate required parameters
        if (!roleName) {
            var error = s3Compat.convertErrorToS3({
                name: 'InvalidParameterValue',
                message: 'RoleName is required for CreateRole operation',
                statusCode: 400
            }, null, req);
            res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
            res.writeHead(400);
            res.end(error);
            return (next(false));
        }

        // IAM requests should have caller set by the routing layer
        log.debug({
            callerUuid: req.caller ? req.caller.account.uuid : null,
            callerLogin: req.caller ? req.caller.account.login : null
        }, 'IAM: CreateRole called with caller');

        // Validate caller authentication
        if (!iamUtils.requireAuthentication(req, res, next, 'IAM')) {
            return;
        }

        log.debug({
            roleName: roleName,
            path: path,
            callerUuid: req.caller.account.uuid
        }, 'IAM: CreateRole operation starting');

        // Trust policies are only for role assumption -
        // no permission conversion needed
        // Permissions come from separate permission policies attached
        // via PutRolePolicy
        var mantaPolicy = null;  // No default permissions for roles

        // Validate that the trust policy is well-formed JSON,
        // but don't convert it to permissions
        if (assumeRolePolicyDocument) {
            try {
                JSON.parse(assumeRolePolicyDocument);
                log.debug({
                    roleName: roleName
                }, 'IAM: Trust policy validated ' +
                   '(not converted to permissions)');
            } catch (parseErr) {
                log.debug({
                    err: parseErr,
                    roleName: roleName,
                    policyDocument: assumeRolePolicyDocument
                }, 'IAM: Trust policy JSON validation failed');

                var policyParseError = s3Compat.convertErrorToS3({
                    name: 'MalformedPolicyDocument',
                    message: 'Invalid JSON in assume role policy: ' +
                             parseErr.message,
                    statusCode: 400
                }, null, req);
                res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
                res.writeHead(400);
                res.end(policyParseError);
                return (next(false));
            }
        }

        // Log the operation being attempted
        log.debug({
            operation: 'CreateRole',
            roleName: roleName,
            hasAssumeRolePolicy: !!assumeRolePolicyDocument,
            hasMantaPolicy: !!mantaPolicy,
            mantaPolicyName: mantaPolicy ? mantaPolicy.name : null,
            callerUuid: req.caller.account.uuid
        }, 'Attempting IAM CreateRole operation');

        // Call Mahi's CreateRole endpoint with converted policy
        iamClient.createRole({
            roleName: roleName,
            assumeRolePolicyDocument: assumeRolePolicyDocument,
            mantaPolicy: mantaPolicy, // Add converted Manta policy
            description: description,
            path: path,
            caller: req.caller
        }, function (err, result) {
            if (err) {
                return iamUtils.handleIAMError(err, 'CreateRole', {
                    operation: 'CreateRole',
                    roleName: roleName,
                    callerUuid: req.caller.account.uuid
                }, res, next, log);
            }

            log.debug({
                roleName: roleName,
                roleArn: result.Role ? result.Role.Arn : 'unknown',
                callerUuid: req.caller.account.uuid
            }, 'CreateRole operation completed successfully');

            // Convert to AWS IAM XML response format
            var createRoleXml = buildCreateRoleXMLResponse(result);

            iamUtils.sendIAMSuccessResponse(res, createRoleXml, next);
        });
    };
}

/**
 * AWS IAM GetRole handler
 * Handles POST requests to /?Action=GetRole
 */
function getRoleHandler(iamClient) {
    return function handleGetRole(req, res, next) {
        var log = req.log;

        log.debug({
            query: req.query,
            body: req.body,
            headers: req.headers
        }, 'IAM GetRole request received');

        // Parse IAM parameters
        var roleName = req.query.RoleName || req.body.RoleName;

        // If body is a URL-encoded string, parse parameters manually
        if (!roleName && typeof (req.body) === 'string') {
            var params = iamUtils.parseUrlEncodedBody(req.body);

            roleName = roleName || params.RoleName;

            log.debug({
                parsedParams: params,
                extractedRoleName: roleName
            }, 'IAM: Parsed parameters from URL-encoded body');
        }

        // Validate required parameters
        if (!roleName) {
            var error = s3Compat.convertErrorToS3({
                name: 'InvalidParameterValue',
                message: 'RoleName is required for GetRole operation',
                statusCode: 400
            }, null, req);
            res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
            res.writeHead(400);
            res.end(error);
            return (next(false));
        }

        // IAM requests should have caller set by the routing layer
        log.debug({
            callerUuid: req.caller ? req.caller.account.uuid : null,
            callerLogin: req.caller ? req.caller.account.login : null
        }, 'IAM: GetRole called with caller');

        // Validate caller authentication
        if (!iamUtils.requireAuthentication(req, res, next, 'IAM')) {
            return;
        }

        log.debug({roleName: roleName}, 'IAM: GetRole operation starting');

        // Call Mahi's GetRole endpoint
        iamClient.getRole({
            roleName: roleName,
            caller: req.caller
        }, function (err, result) {
            if (err) {
                return iamUtils.handleIAMError(err, 'GetRole', {
                    operation: 'GetRole',
                    roleName: roleName,
                    callerUuid: req.caller.account.uuid
                }, res, next, log);
            }

            log.debug({
                roleName: roleName,
                roleArn: result.Role ? result.Role.Arn : 'unknown',
                callerUuid: req.caller.account.uuid
            }, 'GetRole operation completed successfully');

            // DEBUG: Log what mahi returned
            log.debug({
                mahiResponse: JSON.stringify(result, null, 2)
            }, 'DEBUG: Raw response from mahi');

            // Convert to AWS IAM XML response format
            var getRoleXml = buildGetRoleXMLResponse(result);

            // DEBUG: Log what we're sending to client
            log.debug({
                xmlResponseLength: getRoleXml.length,
                xmlResponse: getRoleXml
            }, 'DEBUG: XML response being sent to client');

            iamUtils.sendIAMSuccessResponse(res, getRoleXml, next);
        });
    };
}

/**
 * Build AWS IAM CreateRole XML response
 */
/* BEGIN JSSTYLED */
function buildCreateRoleXMLResponse(result) {
    var role = result.Role;
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<CreateRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">\n';
    xml += '  <CreateRoleResult>\n';
    xml += '    <Role>\n';
    xml += '      <Path>' + s3Compat.escapeXml(role.Path) + '</Path>\n';
    xml += '      <RoleName>' + s3Compat.escapeXml(role.RoleName) + '</RoleName>\n';
    xml += '      <RoleId>' + s3Compat.escapeXml(role.RoleId) + '</RoleId>\n';
    xml += '      <Arn>' + s3Compat.escapeXml(role.Arn) + '</Arn>\n';
    xml += '      <CreateDate>' + s3Compat.escapeXml(role.CreateDate) + '</CreateDate>\n';
    xml += '      <AssumeRolePolicyDocument>' + s3Compat.escapeXml(role.AssumeRolePolicyDocument) + '</AssumeRolePolicyDocument>\n';
    if (role.Description) {
        xml += '      <Description>' + s3Compat.escapeXml(role.Description) + '</Description>\n';
    }
    xml += '      <MaxSessionDuration>' + (role.MaxSessionDuration || 3600) + '</MaxSessionDuration>\n';
    xml += '    </Role>\n';
    xml += '  </CreateRoleResult>\n';
    xml += '  <ResponseMetadata>\n';
    xml += '    <RequestId>' + s3Compat.generateRequestId(16) + 
           '</RequestId>\n';
    xml += '  </ResponseMetadata>\n';
    xml += '</CreateRoleResponse>\n';

    return xml;
}

/* END JSSTYLED */
/**
 * Build AWS IAM GetRole XML response
 */
/* BEGIN JSSTYLED */
function buildGetRoleXMLResponse(result) {
    var role = result.Role;

    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<GetRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">\n';
    xml += '  <GetRoleResult>\n';
    xml += '    <Role>\n';
    xml += '      <Path>' + s3Compat.escapeXml(role.Path) + '</Path>\n';
    xml += '      <RoleName>' + s3Compat.escapeXml(role.RoleName) + '</RoleName>\n';
    xml += '      <RoleId>' + s3Compat.escapeXml(role.RoleId) + '</RoleId>\n';
    xml += '      <Arn>' + s3Compat.escapeXml(role.Arn) + '</Arn>\n';
    xml += '      <CreateDate>' + s3Compat.escapeXml(role.CreateDate) + '</CreateDate>\n';
    xml += '      <AssumeRolePolicyDocument>' + s3Compat.escapeXml(role.AssumeRolePolicyDocument) + '</AssumeRolePolicyDocument>\n';
    if (role.Description) {
        xml += '      <Description>' + s3Compat.escapeXml(role.Description) + '</Description>\n';
    }
    xml += '      <MaxSessionDuration>' + (role.MaxSessionDuration || 3600) + '</MaxSessionDuration>\n';

    // AWS GetRole standard response does NOT include attached policies
    // According to AWS docs, GetRole only returns basic role info and
    // trust policy
    // To retrieve attached policies, AWS uses separate operations:
    // - ListAttachedRolePolicies for managed policies
    // - ListRolePolicies for inline policies
    // - GetRolePolicy for specific inline policy documents

    xml += '    </Role>\n';
    xml += '  </GetRoleResult>\n';
    xml += '  <ResponseMetadata>\n';
    xml += '    <RequestId>' + s3Compat.generateRequestId(16) + 
           '</RequestId>\n';
    xml += '  </ResponseMetadata>\n';
    xml += '</GetRoleResponse>\n';

    return xml;
}

/* END JSSTYLED */

/**
 * AWS IAM PutRolePolicy handler
 * Handles POST requests to /?Action=PutRolePolicy
 */
function putRolePolicyHandler(iamClient) {
    return function handlePutRolePolicy(req, res, next) {
        var log = req.log;

        log.debug({
            query: req.query,
            body: req.body,
            headers: req.headers
        }, 'IAM PutRolePolicy request received');

        // Parse IAM parameters
        var roleName, policyName, policyDocument;

        // Parse from query parameters or body
        roleName = req.query.RoleName || req.body.RoleName;
        policyName = req.query.PolicyName || req.body.PolicyName;
        policyDocument = req.query.PolicyDocument || req.body.PolicyDocument;

        // If body is a URL-encoded string, parse parameters manually
        if (!roleName && typeof (req.body) === 'string') {
            var params = iamUtils.parseUrlEncodedBody(req.body);

            roleName = roleName || params.RoleName;
            policyName = policyName || params.PolicyName;
            policyDocument = policyDocument || params.PolicyDocument;

            log.debug({
                parsedParams: params,
                extractedRoleName: roleName,
                extractedPolicyName: policyName
            }, 'IAM: Parsed PutRolePolicy parameters from URL-encoded body');
        }

        // Decode URL-encoded policy document if needed
        if (policyDocument && typeof (policyDocument) === 'string') {
            try {
                var decodedPolicy =
                    decodeURIComponent(policyDocument.replace(/\+/g, ' '));
                policyDocument = decodedPolicy;

                log.debug({
                    originalPolicy: req.query.PolicyDocument ||
                        req.body.PolicyDocument,
                    decodedPolicy: decodedPolicy
                }, 'IAM: Decoded permission policy document');

            } catch (decodeErr) {
                log.warn({
                    err: decodeErr,
                    originalPolicy: policyDocument
                }, 'IAM: Failed to' +
                   ' decode permission policy document, using original');
            }
        }

        // Validate required parameters
        if (!roleName) {
            var error = s3Compat.convertErrorToS3({
                name: 'InvalidParameterValue',
                message: 'RoleName is required for PutRolePolicy operation',
                statusCode: 400
            }, null, req);
            res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
            res.writeHead(400);
            res.end(error);
            return (next(false));
        }

        if (!policyName) {
            var policyNameError = s3Compat.convertErrorToS3({
                name: 'InvalidParameterValue',
                message: 'PolicyName is required for PutRolePolicy operation',
                statusCode: 400
            }, null, req);
            res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
            res.writeHead(400);
            res.end(policyNameError);
            return (next(false));
        }

        if (!policyDocument) {
            var policyDocError = s3Compat.convertErrorToS3({
                name: 'InvalidParameterValue',
                message:
                'PolicyDocument is required for PutRolePolicy operation',
                statusCode: 400
            }, null, req);
            res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
            res.writeHead(400);
            res.end(policyDocError);
            return (next(false));
        }

        // Validate caller authentication
        if (!iamUtils.requireAuthentication(req, res, next, 'IAM')) {
            return;
        }

        log.debug({
            roleName: roleName,
            policyName: policyName,
            callerUuid: req.caller.account.uuid
        }, 'IAM: PutRolePolicy operation starting');

        // Convert AWS IAM permission policy to Manta policy
        var mantaPolicy = null;
        try {
            mantaPolicy = policyConverter.convertPermissionPolicyToMantaPolicy({
                policyDocument: policyDocument,
                policyName: policyName,
                roleName: roleName,
                accountUuid: req.caller.account.uuid
            });

            log.debug({
                roleName: roleName,
                policyName: policyName,
                mantaPolicyName: mantaPolicy.name,
                mantaRules: mantaPolicy.rules
            }, 'IAM: Converted AWS permission policy to Manta policy');

        } catch (conversionErr) {
            log.debug({
                err: conversionErr,
                roleName: roleName,
                policyName: policyName,
                policyDocument: policyDocument
            }, 'IAM: Permission policy conversion failed');

            var policyConversionError = s3Compat.convertErrorToS3({
                name: 'MalformedPolicyDocument',
                message: 'Invalid policy document: ' + conversionErr.message,
                statusCode: 400
            }, null, req);
            res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
            res.writeHead(400);
            res.end(policyConversionError);
            return (next(false));
        }

        // Log the operation being attempted
        log.debug({
            operation: 'PutRolePolicy',
            roleName: roleName,
            policyName: policyName,
            hasPolicyDocument: !!policyDocument,
            hasMantaPolicy: !!mantaPolicy,
            mantaPolicyName: mantaPolicy ? mantaPolicy.name : null,
            callerUuid: req.caller.account.uuid
        }, 'Attempting IAM PutRolePolicy operation');

        // Call Mahi's PutRolePolicy endpoint
        iamClient.putRolePolicy({
            roleName: roleName,
            policyName: policyName,
            policyDocument: policyDocument,
            mantaPolicy: mantaPolicy,
            caller: req.caller
        }, function (err, _result) {
            if (err) {
                return iamUtils.handleIAMError(err, 'PutRolePolicy', {
                    operation: 'PutRolePolicy',
                    roleName: roleName,
                    policyName: policyName,
                    callerUuid: req.caller.account.uuid
                }, res, next, log);
            }

            log.debug({
                roleName: roleName,
                policyName: policyName,
                callerUuid: req.caller.account.uuid
            }, 'PutRolePolicy operation completed successfully');

            // AWS PutRolePolicy returns empty success response
            var putRolePolicyXml = buildPutRolePolicyXMLResponse();

            iamUtils.sendIAMSuccessResponse(res, putRolePolicyXml, next);
        });
    };
}

/**
 * Build AWS IAM PutRolePolicy XML response
 */
/* BEGIN JSSTYLED */
function buildPutRolePolicyXMLResponse() {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<PutRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">\n';
    xml += '  <ResponseMetadata>\n';
    xml += '    <RequestId>' + s3Compat.generateRequestId(16) + 
           '</RequestId>\n';
    xml += '  </ResponseMetadata>\n';
    xml += '</PutRolePolicyResponse>\n';

    return xml;
}
/* END JSSTYLED */
/**
 * Build AWS IAM DeleteRolePolicy XML response
 */


/* BEGIN JSSTYLED */
function buildDeleteRolePolicyXMLResponse() {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<DeleteRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">\n';
    xml += '  <ResponseMetadata>\n';
    xml += '    <RequestId>' + s3Compat.generateRequestId(16) + 
           '</RequestId>\n';
    xml += '  </ResponseMetadata>\n';
    xml += '</DeleteRolePolicyResponse>\n';

    return xml;
}
/* END JSSTYLED */

/**
 * AWS IAM DeleteRolePolicy handler
 * Handles POST requests to /?Action=DeleteRolePolicy
 */
function deleteRolePolicyHandler(iamClient) {
    return function handleDeleteRolePolicy(req, res, next) {
        var log = req.log;

        log.debug({
            query: req.query,
            body: req.body,
            headers: req.headers
        }, 'IAM DeleteRolePolicy request received');

        // Parse IAM parameters
        var roleName, policyName;

        // Parse from query parameters or body
        roleName = req.query.RoleName || req.body.RoleName;
        policyName = req.query.PolicyName || req.body.PolicyName;

        // If body is a URL-encoded string, parse parameters manually
        if ((!roleName || !policyName) && typeof (req.body) === 'string') {
            var params = iamUtils.parseUrlEncodedBody(req.body);

            roleName = roleName || params.RoleName;
            policyName = policyName || params.PolicyName;

            log.debug({
                parsedParams: params,
                extractedRoleName: roleName,
                extractedPolicyName: policyName
            }, 'IAM: Parsed parameters from URL-encoded body');
        }

        if (!roleName) {
            log.warn('IAM DeleteRolePolicy request missing RoleName parameter');
            var error = {
                name: 'ValidationError',
                message:
                'RoleName parameter is required for DeleteRolePolicy operation',
                statusCode: 400
            };
            var xmlResponse = iamUtils.buildIAMErrorXMLResponse(error);
            res.setHeader('Content-Type', 'text/xml');
            res.writeHead(400);
            res.end(xmlResponse);
            return (next(false));
        }

        if (!policyName) {
            log.warn(
                'IAM DeleteRolePolicy request missing PolicyName parameter');
            var deletePolicyError = {
                name: 'ValidationError',
                message:
                'PolicyName parameter' +
                    ' is required for DeleteRolePolicy operation',
                statusCode: 400
            };
            var deletePolicyXml = iamUtils.buildIAMErrorXMLResponse(
                deletePolicyError);
            res.setHeader('Content-Type', 'text/xml');
            res.writeHead(400);
            res.end(deletePolicyXml);
            return (next(false));
        }

        log.debug({
            roleName: roleName,
            policyName: policyName,
            callerUuid: req.caller.account.uuid
        }, 'DeleteRolePolicy operation started');

        // Call Mahi via IAM client
        iamClient.deleteRolePolicy({
            roleName: roleName,
            policyName: policyName,
            caller: req.caller
        }, function (err, _result) {
            if (err) {
                return iamUtils.handleIAMError(err, 'DeleteRolePolicy', {
                    operation: 'DeleteRolePolicy',
                    roleName: roleName,
                    policyName: policyName,
                    callerUuid: req.caller.account.uuid
                }, res, next, log);
            }

            log.debug({
                roleName: roleName,
                policyName: policyName,
                callerUuid: req.caller.account.uuid
            }, 'DeleteRolePolicy operation completed successfully');

            // Convert to AWS IAM XML response format
            var deleteRolePolicyXml = buildDeleteRolePolicyXMLResponse();

            iamUtils.sendIAMSuccessResponse(res, deleteRolePolicyXml, next);
        });
    };
}

/**
 * AWS IAM DeleteRole handler
 * Handles POST requests to /?Action=DeleteRole
 */
function deleteRoleHandler(iamClient) {
    return function handleDeleteRole(req, res, next) {
        var log = req.log;

        log.debug({
            query: req.query,
            body: req.body,
            headers: req.headers
        }, 'IAM DeleteRole request received');

        // Parse IAM parameters
        var roleName = req.query.RoleName || req.body.RoleName;

        // If body is a URL-encoded string, parse parameters manually
        if (!roleName && typeof (req.body) === 'string') {
            var params = iamUtils.parseUrlEncodedBody(req.body);

            roleName = roleName || params.RoleName;

            log.debug({
                parsedParams: params,
                extractedRoleName: roleName
            }, 'IAM: Parsed DeleteRole parameters from URL-encoded body');
        }

        // Validate required parameters
        if (!roleName) {
            var error = s3Compat.convertErrorToS3({
                name: 'InvalidParameterValue',
                message: 'RoleName is required for DeleteRole operation',
                statusCode: 400
            }, null, req);
            res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
            res.writeHead(400);
            res.end(error);
            return (next(false));
        }

        // Validate caller authentication
        if (!iamUtils.requireAuthentication(req, res, next, 'IAM')) {
            return;
        }

        log.debug({
            roleName: roleName,
            callerUuid: req.caller.account.uuid
        }, 'IAM: DeleteRole operation starting');

        log.debug({
            operation: 'DeleteRole',
            roleName: roleName,
            callerUuid: req.caller.account.uuid
        }, 'Attempting IAM DeleteRole operation');

        // Call Mahi's DeleteRole endpoint
        iamClient.deleteRole({
            roleName: roleName,
            caller: req.caller
        }, function (err, _result) {
            if (err) {
                // Use debug level for 4xx errors (expected test scenarios)
                var logLevel = (err.statusCode >= 400 &&
                                err.statusCode < 500) ? 'debug' : 'error';
                log[logLevel]({
                    err: err,
                    roleName: roleName,
                    callerUuid: req.caller.account.uuid
                }, 'DeleteRole operation failed');

                // Map specific IAM errors to AWS IAM error codes
                // Handle DeleteConflict (409) specifically for DeleteRole
                var mappedError = err;
                if (err.statusCode === 409) {
                    mappedError = {
                        name: 'DeleteConflict',
                        message: 'Cannot delete role ' + roleName +
                            ' because it has attached policies.',
                        statusCode: 409
                    };
                    var xmlResponse = iamUtils.buildIAMErrorXMLResponse(
                        mappedError);
                    res.setHeader('Content-Type', 'text/xml');
                    res.writeHead(mappedError.statusCode);
                    res.end(xmlResponse);
                    return (next(false));
                }

                // Use shared error handling for other error types
                return iamUtils.handleIAMError(err, 'DeleteRole', {
                    operation: 'DeleteRole',
                    roleName: roleName,
                    callerUuid: req.caller.account.uuid
                }, res, next, log);
            }

            log.debug({
                roleName: roleName,
                callerUuid: req.caller.account.uuid
            }, 'DeleteRole operation completed successfully');

            // AWS DeleteRole returns empty success response
            var deleteRoleXml = buildDeleteRoleXMLResponse();

            iamUtils.sendIAMSuccessResponse(res, deleteRoleXml, next);
        });
    };
}

/**
 * Build AWS IAM DeleteRole XML response
 */
/* BEGIN JSSTYLED */
function buildDeleteRoleXMLResponse() {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<DeleteRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">\n';
    xml += '  <ResponseMetadata>\n';
    xml += '    <RequestId>' + s3Compat.generateRequestId(16) + 
           '</RequestId>\n';
    xml += '  </ResponseMetadata>\n';
    xml += '</DeleteRoleResponse>\n';

    return xml;
}
/* END JSSTYLED */

/**
 * AWS IAM ListRoles handler
 * Handles POST requests to /?Action=ListRoles
 */
function listRolesHandler(iamClient) {
    return function handleListRoles(req, res, next) {
        var log = req.log;

        log.debug({
            query: req.query,
            body: req.body,
            headers: req.headers
        }, 'IAM ListRoles request received');

        // Extract parameters
        var maxItems = req.query.MaxItems || req.body.MaxItems || 100;
        var marker = req.query.Marker || req.body.Marker;

        iamClient.listRoles({
            maxItems: maxItems,
            marker: marker,
            caller: req.caller
        }, function (err, result) {
            if (err) {
                log.debug({err: err}, 'IAM ListRoles failed');

                // Map IAM client errors to AWS IAM errors
                if (err.statusCode === 404 ||
                    err.restCode === 'ResourceNotFound') {
                    return (next(false));
                }

                var iamError = {
                    message: err.message || 'Failed to list roles',
                    code: 'ServiceUnavailable',
                    statusCode: 503
                };
                return (next(iamError));
            }

            log.debug({result: result}, 'IAM ListRoles successful');

            log.debug({
                roleCount: result.roles ? result.roles.length : 0,
                isTruncated: result.IsTruncated,
                marker: result.Marker
            }, 'Building ListRoles XML response');

            var xmlResponse = buildListRolesXMLResponse(result);

            log.debug({
                xmlLength: xmlResponse.length,
                xmlPreview: xmlResponse.substring(0, 200)
            }, 'XML response built, sending to client');

            res.setHeader('Content-Type', 'text/xml');
            res.setHeader('Content-Length',
                          Buffer.byteLength(xmlResponse, 'utf8'));
            res.writeHead(200);

            log.debug({
                contentType: res.getHeader('Content-Type'),
                contentLength: res.getHeader('Content-Length'),
                statusCode: 200
            }, 'Setting HTTP headers before sending response');

            res.end(xmlResponse);
            next(false);
        });
    };
}

/**
 * Build AWS IAM ListRoles XML response
 */
/* BEGIN JSSTYLED */
function buildListRolesXMLResponse(result) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<ListRolesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">\n';
    xml += '  <ListRolesResult>\n';
    xml += '    <Roles>\n';

    // Add roles if any exist
    if (result.roles && result.roles.length > 0) {
        result.roles.forEach(function (role) {
            xml += '      <member>\n';
            xml += '        <RoleName>' + s3Compat.escapeXml(role.RoleName || role.name) + '</RoleName>\n';
            xml += '        <Arn>' + s3Compat.escapeXml(role.Arn) + '</Arn>\n';
            xml += '        <CreateDate>' + (role.CreateDate || new Date().toISOString()) + '</CreateDate>\n';
            xml += '        <Path>' + s3Compat.escapeXml(role.Path || '/') + '</Path>\n';
            if (role.AssumeRolePolicyDocument) {
                xml += '        <AssumeRolePolicyDocument>' + s3Compat.escapeXml(encodeURIComponent(role.AssumeRolePolicyDocument)) + '</AssumeRolePolicyDocument>\n';
            }
            xml += '      </member>\n';
        });
    }

    xml += '    </Roles>\n';
    xml += '    <IsTruncated>' + (result.IsTruncated ? 'true' : 'false') + '</IsTruncated>\n';

    if (result.Marker) {
        xml += '    <Marker>' + s3Compat.escapeXml(result.Marker) + '</Marker>\n';
    }

    xml += '  </ListRolesResult>\n';
    xml += '  <ResponseMetadata>\n';
    xml += '    <RequestId>' + s3Compat.generateRequestId(16) + 
           '</RequestId>\n';
    xml += '  </ResponseMetadata>\n';
    xml += '</ListRolesResponse>\n';

    return xml;
}
/* END JSSTYLED */

/**
 * AWS IAM ListRolePolicies handler
 * Handles POST requests to /?Action=ListRolePolicies
 */
function listRolePoliciesHandler(iamClient) {
    return function handleListRolePolicies(req, res, next) {
        var log = req.log;

        log.debug({
            query: req.query,
            body: req.body,
            headers: req.headers
        }, 'IAM ListRolePolicies request received');

        // Parse IAM parameters from URL-encoded body
        var roleName = req.query.RoleName || req.body.RoleName;
        var marker = req.query.Marker || req.body.Marker;
        var maxItems = parseInt(req.query.MaxItems ||
                                req.body.MaxItems || '100', 10);

        // If body is a URL-encoded string, parse parameters manually
        if (!roleName && typeof (req.body) === 'string') {
            var params = iamUtils.parseUrlEncodedBody(req.body);

            roleName = params.RoleName || roleName;
            marker = params.Marker || marker;
            if (params.MaxItems) {
                maxItems = parseInt(params.MaxItems, 10);
            }

            log.debug({
                parsedParams: params,
                extractedRoleName: roleName
            }, 'IAM ListRolePolicies: Parsed parameters from URL-encoded body');
        }

        // Validate required parameters
        if (!roleName) {
            var listPoliciesParamError = s3Compat.convertErrorToS3({
                name: 'InvalidParameterValue',
                message: 'RoleName is required for ListRolePolicies operation',
                statusCode: 400
            }, null, req);
            res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
            res.writeHead(400);
            res.end(listPoliciesParamError);
            return (next(false));
        }

        // Validate caller authentication
        if (!iamUtils.requireAuthentication(req, res, next, 'IAM')) {
            return;
        }

        log.debug({
            roleName: roleName,
            marker: marker,
            maxItems: maxItems,
            callerUuid: req.caller.account.uuid
        }, 'BUCKETS-API: ListRolePolicies operation starting');

        // Call Mahi's ListRolePolicies endpoint
        iamClient.listRolePolicies({
            roleName: roleName,
            marker: marker,
            maxItems: maxItems,
            caller: req.caller
        }, function (err, result) {
            if (err) {
                return iamUtils.handleIAMError(err, 'ListRolePolicies', {
                    operation: 'ListRolePolicies',
                    roleName: roleName,
                    callerUuid: req.caller.account.uuid
                }, res, next, log);
            }

            log.debug({
                roleName: roleName,
                policyCount: result.PolicyNames ? result.PolicyNames.length : 0,
                callerUuid: req.caller.account.uuid
            }, 'ListRolePolicies operation completed successfully');

            // Convert to AWS IAM XML response format
            var listPoliciesXml = buildListRolePoliciesXMLResponse(result);

            iamUtils.sendIAMSuccessResponse(res, listPoliciesXml, next);
        });
    };
}

/**
 * AWS IAM GetRolePolicy handler
 * Handles POST requests to /?Action=GetRolePolicy
 */
function getRolePolicyHandler(iamClient) {
    return function handleGetRolePolicy(req, res, next) {
        var log = req.log;

        log.debug({
            query: req.query,
            body: req.body,
            headers: req.headers
        }, 'IAM GetRolePolicy request received');

        // Parse IAM parameters from URL-encoded body
        var roleName = req.query.RoleName || req.body.RoleName;
        var policyName = req.query.PolicyName || req.body.PolicyName;

        // If body is a URL-encoded string, parse parameters manually
        if (!roleName && typeof (req.body) === 'string') {
            var params = iamUtils.parseUrlEncodedBody(req.body);

            roleName = params.RoleName || roleName;
            policyName = params.PolicyName || policyName;

            log.debug({
                parsedParams: params,
                extractedRoleName: roleName,
                extractedPolicyName: policyName
            }, 'IAM GetRolePolicy: Parsed parameters from URL-encoded body');
        }

        // Validate required parameters
        if (!roleName) {
            var error = s3Compat.convertErrorToS3({
                name: 'InvalidParameterValue',
                message: 'RoleName is required for GetRolePolicy operation',
                statusCode: 400
            }, null, req);
            res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
            res.writeHead(400);
            res.end(error);
            return (next(false));
        }

        if (!policyName) {
            var getRolePolicyParamError = s3Compat.convertErrorToS3({
                name: 'InvalidParameterValue',
                message: 'PolicyName is required for GetRolePolicy operation',
                statusCode: 400
            }, null, req);
            res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
            res.writeHead(400);
            res.end(getRolePolicyParamError);
            return (next(false));
        }

        // Validate caller authentication
        if (!iamUtils.requireAuthentication(req, res, next, 'IAM')) {
            return;
        }

        log.debug({
            roleName: roleName,
            policyName: policyName,
            callerUuid: req.caller.account.uuid
        }, 'BUCKETS-API: GetRolePolicy operation starting');

        // Call Mahi's GetRolePolicy endpoint
        iamClient.getRolePolicy({
            roleName: roleName,
            policyName: policyName,
            caller: req.caller
        }, function (err, result) {
            if (err) {
                return iamUtils.handleIAMError(err, 'GetRolePolicy', {
                    operation: 'GetRolePolicy',
                    roleName: roleName,
                    policyName: policyName,
                    callerUuid: req.caller.account.uuid
                }, res, next, log);
            }

            log.debug({
                roleName: roleName,
                policyName: policyName,
                callerUuid: req.caller.account.uuid
            }, 'GetRolePolicy operation completed successfully');

            // Convert to AWS IAM XML response format
            var getRolePolicyXml = buildGetRolePolicyXMLResponse(result);

            iamUtils.sendIAMSuccessResponse(res, getRolePolicyXml, next);
        });
    };
}

/**
 * Build AWS IAM ListRolePolicies XML response
 */
/* BEGIN JSSTYLED */
function buildListRolePoliciesXMLResponse(result) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<ListRolePoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">\n';
    xml += '  <ListRolePoliciesResult>\n';

    if (result.PolicyNames && Array.isArray(result.PolicyNames)) {
        xml += '    <PolicyNames>\n';
        result.PolicyNames.forEach(function (policyName) {
            xml += '      <member>' + s3Compat.escapeXml(policyName) + '</member>\n';
        });
        xml += '    </PolicyNames>\n';
    } else {
        xml += '    <PolicyNames></PolicyNames>\n';
    }

    xml += '    <IsTruncated>' + (result.IsTruncated ? 'true' : 'false') + '</IsTruncated>\n';

    if (result.Marker) {
        xml += '    <Marker>' + s3Compat.escapeXml(result.Marker) + '</Marker>\n';
    }

    xml += '  </ListRolePoliciesResult>\n';
    xml += '  <ResponseMetadata>\n';
    xml += '    <RequestId>' + s3Compat.generateRequestId(16) + 
           '</RequestId>\n';
    xml += '  </ResponseMetadata>\n';
    xml += '</ListRolePoliciesResponse>\n';

    return xml;
}
/* END JSSTYLED */
/**
 * Build AWS IAM GetRolePolicy XML response
 */
/* BEGIN JSSTYLED */
function buildGetRolePolicyXMLResponse(result) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<GetRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">\n';
    xml += '  <GetRolePolicyResult>\n';
    xml += '    <RoleName>' + s3Compat.escapeXml(result.RoleName) + '</RoleName>\n';
    xml += '    <PolicyName>' + s3Compat.escapeXml(result.PolicyName) + '</PolicyName>\n';
    xml += '    <PolicyDocument>' + s3Compat.escapeXml(result.PolicyDocument) + '</PolicyDocument>\n';
    xml += '  </GetRolePolicyResult>\n';
    xml += '  <ResponseMetadata>\n';
    xml += '    <RequestId>' + s3Compat.generateRequestId(16) + 
           '</RequestId>\n';
    xml += '  </ResponseMetadata>\n';
    xml += '</GetRolePolicyResponse>\n';

    return (xml);
}
/* END JSSTYLED */

module.exports = {
    createIAMClient: createIAMClient,
    createRoleHandler: createRoleHandler,
    getRoleHandler: getRoleHandler,
    putRolePolicyHandler: putRolePolicyHandler,
    deleteRolePolicyHandler: deleteRolePolicyHandler,
    deleteRoleHandler: deleteRoleHandler,
    listRolesHandler: listRolesHandler,
    listRolePoliciesHandler: listRolePoliciesHandler,
    getRolePolicyHandler: getRolePolicyHandler
};
