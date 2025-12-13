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
 * middleware.js: Middleware functions for Restify server.
 *
 * Provides middleware for:
 * - Time to first byte (TTFB) tracking
 * - Dependency validation
 * - CORS preflight handling
 * - Anonymous access setup
 */

var verror = require('verror');

require('../errors');


///--- Functions

/**
 * Middleware to track time to first byte (TTFB).
 * Sets req._timeAtFirstByte when the response header is sent.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Restify next callback
 */
function traceTTFB(req, res, next) {
    //
    // When it sends the header, restify's response object emits `header`.
    // See the `Response.prototype.writeHead` function.
    //
    // We use that here as our best proxy for time to first byte. Since the
    // header is the first part of our response. Some methods (specifically
    // streamFromSharks and sharkStreams) will override this to set their
    // own idea of when the first byte was (which might be before we send
    // anything to the client). The `audit.auditLogger` in the `after`
    // handler will use the final value when writing out metrics.
    //
    res.once('header', function _onHeader() {
        if (!req._timeAtFirstByte) {
            req._timeAtFirstByte = Date.now();
        }
    });

    next();
}


/**
 * Middleware to ensure required client dependencies are available.
 * Checks for mahi, storinfo (for write operations), and metadataPlacement.
 *
 * @param {Object} clients - Client connections object
 * @return {Function} Restify middleware function
 */
function createDependencyChecker(clients) {
    return function ensureDependencies(req, res, next) {
        var ok = true;
        var errors = [];
        var error;

        if (!clients.mahi) {
            error = 'mahi unavailable';
            errors.push(new Error(error));
            req.log.error(error);
            ok = false;
        }

        if (!clients.storinfo && !req.isReadOnly()) {
            error = 'storinfo unavailable';
            errors.push(new Error(error));
            req.log.error(error);
            ok = false;
        }

        if (!clients.metadataPlacement) {
            error = 'metadataPlacement client unavailable';
            errors.push(new Error(error));
            req.log.error(error);
            ok = false;
        }

        if (!ok) {
            next(new ServiceUnavailableError(req,
                        new verror.MultiError(errors)));
        } else {
            next();
        }
    };
}


/**
 * CORS preflight OPTIONS handler.
 * Handles preflight requests by setting appropriate CORS headers
 * and terminating the request.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {Function} next - Restify next callback
 */
function corsPreflightHandler(req, res, next) {
    if (req.headers['access-control-request-method']) {
        var origin = req.headers.origin || '*';

        req.log.debug({
            origin: origin,
            requestMethod: req.headers['access-control-request-method'],
            url: req.url
        }, 'CORS: Handling preflight OPTIONS request');

        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods',
                      'GET,POST,PUT,DELETE,HEAD,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type,' +
                      'authorization,x-amz-content-sha256,x-amz-date,' +
                      'x-amz-security-token,x-amz-user-agent');
        res.setHeader('Access-Control-Max-Age', '3600');
        res.setHeader('Access-Control-Allow-Credentials', 'true');

        res.send(200);
        next(false); // Stop processing - complete the preflight
    } else {
        next(); // Not a preflight, continue
    }
}


/**
 * Anonymous access setup handler.
 * Sets up metadataPlacement for anonymous access handler to use.
 *
 * @param {Object} clients - Client connections object
 * @param {Object} anonymousAuth - Anonymous authentication module
 * @return {Function} Restify middleware function
 */
function createAnonymousAccessHandler(clients, anonymousAuth) {
    return function anonymousAccessSetup(req, res, next) {
        // Set up metadataPlacement early for anonymous access handler
        req.metadataPlacement = clients.metadataPlacement;
        anonymousAuth.anonymousAccessHandler(req, res, next);
    };
}


///--- Exports

module.exports = {
    traceTTFB: traceTTFB,
    createDependencyChecker: createDependencyChecker,
    corsPreflightHandler: corsPreflightHandler,
    createAnonymousAccessHandler: createAnonymousAccessHandler
};
