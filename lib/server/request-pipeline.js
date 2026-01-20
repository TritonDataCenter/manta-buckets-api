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
 * request-pipeline.js: Request processing pipeline for S3 requests.
 *
 * Provides request pipeline functions for S3 request processing:
 * - S3 middleware chain application (header translation,
 * conditional headers, etc.)
 * - S3 error handling and XML conversion
 * - Route handlers for S3 requests
 */

var s3Compat = require('../s3-compat');


///--- Functions

/**
 * Process an S3 request through the middleware pipeline and route to handler.
 * Applies S3 compatibility middleware in sequence:
 * 1. s3HeaderTranslator - Convert S3 headers to Manta format
 * 2. s3ConditionalHeaders - Handle conditional request headers
 * 3. s3RoleTranslator - Translate AWS roles to Manta roles
 * 4. s3ResponseFormatter - Set up response formatting
 * 5. handleS3Request - Route to appropriate S3 handler
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} handleS3Request - S3 request routing function
 * @param {Function} next - Restify next callback
 */
function processS3Request(req, res, handleS3Request, next) {
    req.log.debug('S3_DEBUG: Processing S3 request through pipeline');

    // Convert S3 AWS headers to ones that Manta could use/understand
    s3Compat.s3HeaderTranslator(req, res, function (headerErr) {
        if (headerErr) {
            req.log.error(headerErr,
                'S3_DEBUG: Error in s3HeaderTranslator');
            next(headerErr);
            return;
        }
        req.log.debug('S3_DEBUG: s3HeaderTranslator completed');

        // Handle conditional headers (If-Unmodified-Since, If-Match, etc.)
        s3Compat.s3ConditionalHeaders(req, res, function (conditionalErr) {
            if (conditionalErr) {
                req.log.error(conditionalErr,
                    'S3_DEBUG: Error in s3ConditionalHeaders');
                next(conditionalErr);
                return;
            }

            req.log.debug('S3_DEBUG: s3ConditionalHeaders completed');

            // Translate AWS roles to Manta roles
            s3Compat.s3RoleTranslator(req, res, function (roleErr) {
                if (roleErr) {
                    req.log.error(roleErr,
                        'S3_DEBUG: Error in s3RoleTranslator');
                    next(roleErr);
                    return;
                }
                req.log.debug('S3_DEBUG: s3RoleTranslator completed');

                // Set up response formatter
                s3Compat.s3ResponseFormatter(req, res, function (formatterErr) {
                    if (formatterErr) {
                        req.log.error(formatterErr,
                            'S3_DEBUG: s3ResponseFormatter Failed');
                        next(formatterErr);
                        return;
                    }
                    req.log.debug('S3_DEBUG: s3ResponseFormatter ' +
                                  'completed, calling handleS3Request');

                    // Route to appropriate S3 handler
                    handleS3Request(req, res, function (handlerErr) {
                        if (handlerErr) {
                            handleS3Error(req, res, handlerErr);
                        }
                        // Always terminate S3 requests to prevent
                        // double execution
                        next(false);
                    });
                });
            });
        });
    });
}


/**
 * Handle S3 request errors by converting to S3 XML format and sending response.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Error} handlerErr - Error from S3 handler
 */
function handleS3Error(req, res, handlerErr) {
    // Determine if error is user error (4xx) or system error (5xx)
    var isUserError = (handlerErr.statusCode >= 400 &&
                       handlerErr.statusCode < 500) ||
                      (handlerErr.name &&
                       (handlerErr.name.includes('NotFound') ||
                        handlerErr.name.includes('Exists') ||
                        handlerErr.name.includes('BadRequest')));

    if (isUserError) {
        req.log.debug({
            errorName: handlerErr.name,
            errorCode: handlerErr.restCode || handlerErr.code,
            statusCode: handlerErr.statusCode,
            bucket: req.s3Request ? req.s3Request.bucket : 'unknown',
            object: req.s3Request ? req.s3Request.object : 'unknown'
        }, 'S3: User error in S3 handler, returning S3 XML error response');
    } else {
        req.log.error(handlerErr,
            'S3: System error in S3 handler, converting to S3 XML format');
    }

    // Convert error to S3 XML format
    var s3XmlError = s3Compat.convertErrorToS3(handlerErr,
                                                req.s3Request,
                                                req);

    // Determine proper HTTP status code
    var statusCode = 500; // default
    if (handlerErr.name === 'ObjectNotFoundError' ||
        handlerErr.restCode === 'ObjectNotFoundError') {
        statusCode = 404;
    } else if (handlerErr.name === 'BucketNotFoundError' ||
               handlerErr.restCode === 'BucketNotFoundError') {
        statusCode = 404;
    } else if (handlerErr.name === 'BucketExistsError' ||
               handlerErr.restCode === 'BucketExistsError') {
        statusCode = 409;
    } else if (handlerErr.statusCode &&
               typeof (handlerErr.statusCode) === 'number') {
        statusCode = handlerErr.statusCode;
    } else if (handlerErr.code &&
               typeof (handlerErr.code) === 'number') {
        statusCode = handlerErr.code;
    }

    // Send S3 XML error response
    res.writeHead(statusCode, {
        'Content-Type': 'application/xml',
        'Content-Length': Buffer.byteLength(s3XmlError, 'utf8'),
        'x-amz-request-id': res.getHeader('x-amz-request-id') || 'unknown',
        'x-amz-id-2': res.getHeader('x-amz-id-2') || 'unknown'
    });
    res.write(s3XmlError, 'utf8');
    res.end();
}


/**
 * Create consolidated root handler for GET / requests.
 * Handles both S3 requests (processes through pipeline) and
 * traditional Manta requests (redirects to docs).
 *
 * @param {Function} handleS3Request - S3 request routing function
 * @return {Function} Restify route handler
 */
function createConsolidatedRootHandler(handleS3Request) {
    return function consolidatedRootHandler(req, res, next) {
        if (req.isS3Request) {
            var addressingStyle = req.s3Request ?
                req.s3Request.addressingStyle : 'unknown';
            req.log.debug({
                addressingStyle: addressingStyle,
                host: req.headers.host,
                s3Request: req.s3Request
            }, 'S3_DEBUG: Consolidated root handler - processing S3 request');

            processS3Request(req, res, handleS3Request, next);
        } else {
            // Traditional redirect for docs
            req.log.debug('Consolidated root handler - redirecting to docs');
            res.set('Content-Length', 0);
            res.set('Connection', 'keep-alive');
            res.set('Date', new Date());
            res.set('Location', 'http://apidocs.tritondatacenter.com/manta/');
            res.send(302);
            next(false);
        }
    };
}


/**
 * Create S3 route handler for catch-all S3 routes.
 * Processes S3 requests through the pipeline or passes non-S3 requests
 * to traditional Manta handlers.
 *
 * @param {Function} handleS3Request - S3 request routing function
 * @return {Function} Restify route handler
 */
function createS3RouteHandler(handleS3Request) {
    return function s3RouteHandler(req, res, next) {
        if (req.isS3Request) {
            req.log.debug('S3_DEBUG: S3 route handler processing S3 request');
            processS3Request(req, res, handleS3Request, next);
        } else {
            // Not an S3 request, let it continue to traditional routes
            req.log.debug('S3_DEBUG: Not S3 request, passing to next handler');
            next();
        }
    };
}


///--- Exports

module.exports = {
    processS3Request: processS3Request,
    handleS3Error: handleS3Error,
    createConsolidatedRootHandler: createConsolidatedRootHandler,
    createS3RouteHandler: createS3RouteHandler
};
