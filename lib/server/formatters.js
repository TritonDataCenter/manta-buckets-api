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
 * formatters.js: Response formatters for Restify server.
 *
 * Provides binary and JSON formatters with dynamic
 * formatter selection based on request type (S3 vs Manta).
 * Handles error translation and content-type negotiation.
 */

var crypto = require('crypto');

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
 * JSON formatter with MD5 checksum generation.
 * Converts responses to JSON format with proper headers.
 *
 * @param {Object} req - Restify request object
 * @param {Object} res - Restify response object
 * @param {*} body - Response body
 * @return {String} JSON-formatted response
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
	res.setHeader('Content-Type', 'application/json');

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
function selectFormatter(contentType, req, res) {
	// For S3 binary operations marked to skip processing,
	// use NO formatter
	if (req && (req._skipS3ResponseProcessing ||
	req._binaryUpload || req._binaryOperation)) {
		return function (innerReq, innerRes, body) {
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
		'application/json': function (req, res, body) {
			return selectFormatter('application/json',
				req, res)(req, res, body);
		},
		'text/plain': function (req, res, body) {
			return (selectFormatter('text/plain', req, res)
				(req, res, body));
		},
		'application/octet-stream': function (req, res, body) {
			return (selectFormatter(
				'application/octet-stream', req, res)
				(req, res, body));
		},
		'application/x-json-stream': function (req, res, body) {
			return (selectFormatter(
				'application/x-json-stream', req, res)
				(req, res, body));
		},
		'image/gif': function (req, res, body) {
			return (selectFormatter('image/gif', req, res)
				(req, res, body));
		},
		'image/jpeg': function (req, res, body) {
			return (selectFormatter('image/jpeg', req, res)
				(req, res, body));
		},
		'image/png': function (req, res, body) {
			return (selectFormatter('image/png', req, res)
				(req, res, body));
		},
		'*/*': function (req, res, body) {
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
