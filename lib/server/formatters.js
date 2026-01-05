/*
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * formatters.js: Response formatters for Restify server.
 *
 * Provides binary and JSON formatters with dynamic
 * formatter selection based on request type (S3 vs Manta).
 * Handles error translation and content-type negotiation.
 */

var crypto = require('crypto');
var s3Compat = require('../s3-compat');

require('../errors');


///--- Functions

/**
 * Binary formatter that passes data through unchanged.
 * Used for S3 object downloads to preserve binary data
 * integrity.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {*} body - Response body
 * @return {Buffer|String} Formatted response
 */
function formatBinary(req, res, body) {
    if (body instanceof Error) {
        // For errors, fall back to JSON formatting
        return (formatJSON(req, res, body));
    }

    // For binary data, return as-is without any conversion
    if (Buffer.isBuffer(body)) {
        return (body);
    }

    // For strings, convert to buffer to preserve binary data
    if (typeof (body) === 'string') {
        return (Buffer.from(body, 'binary'));
    }

    // For other data types, fall back to JSON
    return (formatJSON(req, res, body));
}


/**
 * Checks if a request is an S3 request by inspecting auth headers.
 * Uses same logic as S3 detection middleware to handle errors that
 * occur before middleware runs.
 *
 * @param {Object} req - Restify request object
 * @return {Boolean} True if S3 request
 */
function isS3Request(req) {
    if (!req || !req.headers) {
        return (false);
    }

    // Check if already detected by middleware
    if (req.isS3Request === true) {
        return (true);
    }

    // Detect SigV4 auth (AWS4-HMAC-SHA256)
    var authHeader = req.headers.authorization || '';
    var isSigV4 = authHeader.indexOf('AWS4-HMAC-SHA256') === 0;

    // Detect presigned URLs
    var isPresignedV4 = req.query && (req.query['X-Amz-Algorithm'] ||
        req.query['x-amz-algorithm']);

    return (isSigV4 || isPresignedV4);
}


/**
 * JSON formatter with MD5 checksum generation.
 * Converts responses to JSON format with proper headers.
 * For S3 requests, errors are formatted as XML per AWS S3 API spec.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {*} body - Response body
 * @return {String} JSON or XML-formatted response
 */
function formatJSON(req, res, body) {
    if (body instanceof Error) {
        body = translateError(body, req);
        res.statusCode = body.statusCode || 500;
        if (res.statusCode >= 500)
            req.log.warn(body, 'request failed: internal error');

        if (body.headers !== undefined) {
            for (var h in body.headers) {
                res.setHeader(h, body.headers[h]);
            }
        }

        // For S3 requests, format errors as XML per AWS S3 API spec
        // This ensures AWS SDK v3 compatibility
        // Detect S3 even if middleware hasn't run yet
        if (isS3Request(req)) {
            req.log.debug({
                statusCode: res.statusCode,
                errorCode: body.code,
                errorMessage: body.message
            }, 'formatJSON: Converting S3 error to XML');
            var xmlError = s3Compat.convertErrorToS3(body,
                req.s3Request, req);
            // Set headers for XML response
            // Use setHeader so Restify can manage header lifecycle
            res.setHeader('Content-Type', 'application/xml');
            res.setHeader('Content-Length', Buffer.byteLength(xmlError));
            req.log.debug('formatJSON: Set Content-Type to application/xml');
            return (xmlError);
        }

        if (body.body) {
            body = body.body;
        } else {
            body = {
                message: body.message
            };
        }

    } else if (Buffer.isBuffer(body)) {
        body = body.toString('base64');
    }

    var data = JSON.stringify(body);
    var md5 = crypto.createHash('md5').update(data).digest('base64');

    res.setHeader('Content-Length', Buffer.byteLength(data));
    res.setHeader('Content-MD5', md5);
    // Only set Content-Type to JSON if not already set
    // (e.g., already set to XML for S3 errors)
    if (!res.getHeader('Content-Type')) {
        res.setHeader('Content-Type', 'application/json');
    }

    return (data);
}


/**
 * Dynamically selects the appropriate formatter based on
 * request type and operation.
 *
 * @param {String} contentType - Content type being formatted
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @return {Function} Formatter function
 */
function selectFormatter(contentType, req, _res) {
    // For S3 binary operations marked to skip processing,
    // use NO formatter
    if (req && (req._skipS3ResponseProcessing ||
    req._binaryUpload || req._binaryOperation)) {
        return function passthroughFormatter(innerReq, innerRes, body) {
            // Return body completely unchanged -
            // no formatting at all
            return (body);
        };
    }
    // For S3 object operations, use binary formatter
    // to preserve data integrity
    if (req && req.isS3Request &&
        req.s3Request &&
        (req.s3Request.operation === 'GetBucketObject' ||
        req.s3Request.operation === 'CreateBucketObject')) {
        return (formatBinary);
    }
    // For all other requests (traditional Manta),
    // use JSON formatter
    return (formatJSON);
}


/**
 * Creates formatters configuration object for Restify.
 * Provides formatters for various content types with
 * dynamic selection.
 *
 * @return {Object} Formatters configuration object
 */
function createFormatters() {
    return ({
        'application/json': function formatApplicationJson(req, res, body) {
            return selectFormatter('application/json',
                req, res)(req, res, body);
        },
        'text/plain': function formatTextPlain(req, res, body) {
            return (selectFormatter('text/plain', req, res)
                (req, res, body));
        },
        'application/octet-stream': function formatOctetStream(req, res, body) {
            return (selectFormatter(
                'application/octet-stream', req, res)
                (req, res, body));
        },
        'application/x-json-stream': function formatJsonStream(req, res, body) {
            return (selectFormatter(
                'application/x-json-stream', req, res)
                (req, res, body));
        },
        'image/gif': function formatImageGif(req, res, body) {
            return (selectFormatter('image/gif', req, res)
                (req, res, body));
        },
        'image/jpeg': function formatImageJpeg(req, res, body) {
            return (selectFormatter('image/jpeg', req, res)
                (req, res, body));
        },
        'image/png': function formatImagePng(req, res, body) {
            return (selectFormatter('image/png', req, res)
                (req, res, body));
        },
        '*/*': function formatAny(req, res, body) {
            return (selectFormatter('*/*', req, res)
                (req, res, body));
        }
    });
}


///--- Exports

module.exports = {
    formatBinary: formatBinary,
    formatJSON: formatJSON,
    selectFormatter: selectFormatter,
    createFormatters: createFormatters
};