/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * Common utility functions for IAM and STS request handling
 * Eliminates code duplication across IAM/STS handlers
 */

var s3Compat = require('./s3-compat');
var constants = require('./constants');

/**
 * Parse URL-encoded body parameters
 * Handles AWS CLI and SDK request format which sends parameters
 * as URL-encoded string in request body
 *
 * @param {String} body - Request body (URL-encoded string)
 * @returns {Object} Parsed parameters as key-value pairs
 */
function parseUrlEncodedBody(body) {
    if (typeof (body) !== 'string') {
        return {};
    }

    var params = {};
    body.split('&').forEach(function (pair) {
        var parts = pair.split('=');
        if (parts.length === 2) {
            params[parts[0]] = decodeURIComponent(parts[1]);
        }
    });

    return params;
}

/**
 * Require authentication for IAM/STS operations
 * Sends error response if authentication is missing
 *
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {Function} next - Next middleware function
 * @param {String} serviceName - Service name ('IAM' or 'STS')
 * @returns {Boolean} true if authenticated, false if error was sent
 */
function requireAuthentication(req, res, next, serviceName) {
    if (!req.caller || !req.caller.account) {
        var authError = s3Compat.convertErrorToS3({
            name: 'InvalidUserID.NotFound',
            message: 'Authentication required for ' + serviceName + ' operations',
            statusCode: 401
        }, null, req);
        res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
        res.writeHead(401);
        res.end(authError);
        next(false);
        return false;
    }
    return true;
}

/**
 * Require a parameter to be present
 * Sends error response if parameter is missing
 *
 * @param {String} paramName - Parameter name
 * @param {*} value - Parameter value
 * @param {String} operationName - Operation name (e.g., 'CreateRole')
 * @param {Object} res - Response object
 * @param {Function} next - Next middleware function
 * @returns {Boolean} true if present, false if error was sent
 */
function requireParameter(paramName, value, operationName, res, next) {
    if (!value) {
        var error = s3Compat.convertErrorToS3({
            name: 'InvalidParameterValue',
            message: paramName + ' is required for ' + operationName + ' operation',
            statusCode: 400
        }, null, null);
        res.setHeader('Content-Type', constants.CONTENT_TYPES.XML);
        res.writeHead(400);
        res.end(error);
        next(false);
        return false;
    }
    return true;
}

/**
 * Handle IAM operation errors
 * Maps errors to AWS IAM error codes and sends XML response
 *
 * @param {Error} err - Error object
 * @param {String} operationName - Operation name (e.g., 'CreateRole')
 * @param {Object} context - Context object with roleName, policyName, etc.
 * @param {Object} res - Response object
 * @param {Function} next - Next middleware function
 * @param {Object} log - Logger instance
 * @returns {*} Result of next(false)
 */
function handleIAMError(err, operationName, context, res, next, log) {
    log.debug({
        err: err,
        operation: operationName,
        context: context
    }, operationName + ' operation failed');

    var mappedError = mapIAMError(err, context, log);

    var xmlResponse = buildIAMErrorXMLResponse(mappedError);
    res.setHeader('Content-Type', 'text/xml');
    res.writeHead(mappedError.statusCode || 500);
    res.end(xmlResponse);
    return next(false);
}

/**
 * Map generic errors to IAM-specific errors
 *
 * @param {Error} err - Error object
 * @param {Object} context - Context object with operation, roleName, etc.
 * @param {Object} log - Logger instance
 * @returns {Object} Mapped error with name, message, statusCode
 */
function mapIAMError(err, context, log) {
    var mappedError = err;

    if (err.statusCode === 404) {
        mappedError = {
            name: 'NoSuchEntity',
            message: buildNoSuchEntityMessage(context),
            statusCode: 404
        };
    } else if (err.statusCode === 400) {
        mappedError = {
            name: 'InvalidParameterValue',
            message: err.message || 'Invalid parameter value',
            statusCode: 400
        };
    } else if (err.statusCode === 409 ||
               (err.message && err.message.indexOf('already exists') !== -1) ||
               (err.restCode === 'EntityAlreadyExists') ||
               (err.body && err.body.details &&
                err.body.details.indexOf('not unique') !== -1)) {
        mappedError = {
            name: 'EntityAlreadyExists',
            message: buildAlreadyExistsMessage(context),
            statusCode: 409
        };
    } else {
        // Log comprehensive error details for debugging
        log.debug({
            operation: context.operation,
            errorDetails: {
                name: err.name,
                code: err.code,
                restCode: err.restCode,
                statusCode: err.statusCode,
                message: err.message,
                body: err.body,
                stack: err.stack
            }
        }, 'Detailed error information for ' + context.operation + ' failure');

        var detailedMessage = context.operation + ' failed: ' +
            (err.message || err.toString());
        if (err.body && typeof (err.body) === 'object' && err.body.error) {
            detailedMessage += ' | Server error: ' + err.body.error;
        }
        if (err.code) {
            detailedMessage += ' | Error code: ' + err.code;
        }
        if (err.restCode) {
            detailedMessage += ' | REST code: ' + err.restCode;
        }

        mappedError = {
            name: 'InternalFailure',
            message: detailedMessage,
            statusCode: err.statusCode || 500
        };
    }

    return mappedError;
}

/**
 * Build NoSuchEntity error message based on context
 *
 * @param {Object} context - Context with roleName, policyName, etc.
 * @returns {String} Error message
 */
function buildNoSuchEntityMessage(context) {
    if (context.roleName && context.policyName) {
        return 'Policy ' + context.policyName +
               ' not found for role ' + context.roleName;
    } else if (context.roleName) {
        return 'The role with name ' + context.roleName + ' cannot be found.';
    }
    return 'The requested entity cannot be found.';
}

/**
 * Build EntityAlreadyExists error message based on context
 *
 * @param {Object} context - Context with roleName, etc.
 * @returns {String} Error message
 */
function buildAlreadyExistsMessage(context) {
    if (context.roleName) {
        return 'Role with name ' + context.roleName + ' already exists.';
    }
    return 'The entity already exists.';
}

/**
 * Build AWS IAM XML error response
 *
 * @param {Object} error - Error object with name, message, statusCode
 * @returns {String} XML error response
 */
function buildIAMErrorXMLResponse(error) {
    var requestId = s3Compat.generateRequestId(16);
    var errorCode = error.name || 'InternalFailure';
    var errorMessage = s3Compat.escapeXml(error.message || 'An error occurred');

    return '<?xml version="1.0" encoding="UTF-8"?>\n' +
           '<ErrorResponse>\n' +
           '  <Error>\n' +
           '    <Type>Sender</Type>\n' +
           '    <Code>' + s3Compat.escapeXml(errorCode) + '</Code>\n' +
           '    <Message>' + errorMessage + '</Message>\n' +
           '  </Error>\n' +
           '  <RequestId>' + requestId + '</RequestId>\n' +
           '</ErrorResponse>';
}

/**
 * Send IAM success response
 *
 * @param {Object} res - Response object
 * @param {String} xmlResponse - XML response string
 * @param {Function} next - Next middleware function
 */
function sendIAMSuccessResponse(res, xmlResponse, next) {
    res.setHeader('Content-Type', 'text/xml');
    res.writeHead(200);
    res.end(xmlResponse);
    next(false);
}

/**
 * Add ResponseMetadata to XML response
 *
 * @returns {String} ResponseMetadata XML fragment
 */
function addResponseMetadata() {
    var xml = '  <ResponseMetadata>\n';
    xml += '    <RequestId>' + s3Compat.generateRequestId(16) +
           '</RequestId>\n';
    xml += '  </ResponseMetadata>\n';
    return xml;
}

/**
 * Serialize a role object to XML format
 *
 * @param {Object} role - Role object with Path, RoleName, RoleId, etc.
 * @returns {String} XML fragment representing the role
 */
function serializeRoleToXML(role) {
    var xml = '';
    xml += '      <Path>' + s3Compat.escapeXml(role.Path) + '</Path>\n';
    xml += '      <RoleName>' + s3Compat.escapeXml(role.RoleName) +
           '</RoleName>\n';
    xml += '      <RoleId>' + s3Compat.escapeXml(role.RoleId) + '</RoleId>\n';
    xml += '      <Arn>' + s3Compat.escapeXml(role.Arn) + '</Arn>\n';
    xml += '      <CreateDate>' + s3Compat.escapeXml(role.CreateDate) +
           '</CreateDate>\n';
    xml += '      <AssumeRolePolicyDocument>' +
           s3Compat.escapeXml(role.AssumeRolePolicyDocument) +
           '</AssumeRolePolicyDocument>\n';
    if (role.Description) {
        xml += '      <Description>' + s3Compat.escapeXml(role.Description) +
               '</Description>\n';
    }
    xml += '      <MaxSessionDuration>' +
           (role.MaxSessionDuration || 3600) + '</MaxSessionDuration>\n';
    return xml;
}

/**
 * Build XML response wrapper for IAM operations
 *
 * @param {String} operationName - Operation name (e.g., 'CreateRole')
 * @param {String} xmlns - XML namespace URL
 * @param {String} content - Response content (XML fragment)
 * @returns {String} Complete XML response
 */
function buildXMLResponseWrapper(operationName, xmlns, content) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<' + operationName + 'Response xmlns="' + xmlns + '">\n';
    xml += content;
    xml += addResponseMetadata();
    xml += '</' + operationName + 'Response>\n';
    return xml;
}

module.exports = {
    parseUrlEncodedBody: parseUrlEncodedBody,
    requireAuthentication: requireAuthentication,
    requireParameter: requireParameter,
    handleIAMError: handleIAMError,
    buildIAMErrorXMLResponse: buildIAMErrorXMLResponse,
    sendIAMSuccessResponse: sendIAMSuccessResponse,
    addResponseMetadata: addResponseMetadata,
    serializeRoleToXML: serializeRoleToXML,
    buildXMLResponseWrapper: buildXMLResponseWrapper
};
