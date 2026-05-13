/*
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * signature-verifier.js: Signature verification handlers
 * for HTTP signatures, AWS SigV4, and presigned URLs.
 *
 * Provides middleware functions for authenticating requests
 * using various signature schemes including legacy HTTP
 * signatures, AWS Signature Version 4, and S3 presigned URLs.
 */

var httpSignature = require('http-signature');

var constants = require('../constants');
var s3Compat = require('../s3-compat');

require('../errors');


///--- Constants

var SIGN_ALG = {
    'RSA-SHA1': true,
    'RSA-SHA256': true,
    'RSA-SHA384': true,
    'RSA-SHA512': true,
    'DSA-SHA1': true,
    'DSA-SHA256': true,
    'ECDSA-SHA256': true,
    'ECDSA-SHA384': true,
    'ECDSA-SHA512': true
};


///--- Helper Functions

/*
 * Enforce the wire-format invariant for `result.bucketScope`
 * coming from mahi's verifySigV4 response: must be null,
 * undefined, or a JSON string.
 *
 * Mahi's contract (see mahi/test/accesskey-scope.test.js)
 * already guarantees a string|null, but a parsed-object
 * leak would propagate silently through req.auth → req.caller
 * → STS POST body and re-emerge as "[object Object]" in
 * LDAP. Detect drift here, log loudly, and coerce to a JSON
 * string so the downstream contract still holds.
 *
 * @param {*} scope - value from mahi response
 * @param {Object} log - request logger
 * @return {string|null}
 */
function normalizeAuthBucketScope(scope, log) {
    if (scope === undefined || scope === null) {
        return null;
    }
    if (typeof scope === 'string') {
        return scope;
    }
    log.warn({
        bucketScopeType: typeof scope,
        bucketScopeValue: scope
    }, 'signature-verifier: mahi returned non-string ' +
        'bucketScope; coercing to JSON. This indicates ' +
        'a contract drift in node-mahi or the mahi auth ' +
        'response and should be fixed at the source.');
    return JSON.stringify(scope);
}

/**
 * Helper function to safely send InvalidSignatureError
 * XML error response for S3 requests.
 *
 * @param {Object} req - Restify request
 * @param {Object} res - Restify response
 * @param {Function} next - Callback
 * @param {String} message - Error message
 */
function sendInvalidSignatureError(req, res, next,
    message, s3ErrorCode) {
    try {
        var authError = new InvalidSignatureError(message);

        /*
         * Override restCode when the caller specifies a
         * distinct S3 error code (e.g. InvalidAccessKeyId,
         * AuthorizationHeaderMalformed).  This lets
         * convertErrorToS3 look up the correct
         * S3_ERROR_RESPONSES entry.
         */
        if (s3ErrorCode) {
            authError.restCode = s3ErrorCode;
        }

        req.log.info({
            audit: true,
            accessKeyId: (req.auth && req.auth.accessKeyId)
                ? req.auth.accessKeyId : '(unknown)',
            s3ErrorCode: s3ErrorCode || 'InvalidSignature',
            reason: message,
            method: req.method,
            path: req.path(),
            sourceIp: req.connection
                ? req.connection.remoteAddress
                : '(closed)'
        }, 'sigv4 auth denied');

        // For S3 requests, send XML error response
        if (req.s3Request && req.s3Request.isS3Request) {
            var xmlError = s3Compat.convertErrorToS3(
                authError, req.s3Request, req);
            // Use writeHead + end to bypass Restify formatters
            // which would override Content-Type
            res.writeHead(constants.HTTP_STATUS.FORBIDDEN, {
                'Content-Type': constants.CONTENT_TYPES.XML,
                'Content-Length': Buffer.byteLength(xmlError)
            });
            res.end(xmlError);
        } else {
            res.send(constants.HTTP_STATUS.FORBIDDEN,
                authError.message);
        }
    } catch (sendErr) {
        req.log.error(sendErr,
            'Failed to send error response');
        res.end();
    }
}


/**
 * Map a mahi authentication error to the appropriate
 * S3 error code and send the response.
 *
 * Centralizes the error-code switch that was previously
 * duplicated in the temp-credential and permanent-
 * credential callbacks.
 *
 * @param {Object} req - Restify request
 * @param {Object} res - Restify response
 * @param {Function} next - Restify next
 * @param {Object} err - Error from mahi
 */
function handleMahiAuthError(req, res, next, err) {
    switch (err.restCode || err.name) {
    case 'InvalidSignature':
    case 'InvalidSignatureError':
    case 'SignatureDoesNotMatch':
        sendInvalidSignatureError(req, res, next,
            'Invalid Signature',
            'InvalidSignature');
        break;
    case 'AccessKeyNotFound':
        sendInvalidSignatureError(req, res, next,
            'Invalid access key',
            'InvalidAccessKeyId');
        break;
    case 'RequestTimeTooSkewed':
        sendInvalidSignatureError(req, res, next,
            'Request timestamp too skewed',
            'RequestTimeTooSkewed');
        break;
    default:
        sendInvalidSignatureError(req, res, next,
            'Authentication failed: ' +
            (typeof (err.message) === 'string' ?
                err.message : 'Unknown error'),
            'InvalidSignature');
        break;
    }
}


/**
 * RFC 3986 URL encoding helper
 *
 * @param {String} str - String to encode
 * @return {String} Encoded string
 */
function rfc3986(str) {
    /* JSSTYLED */
    return (encodeURIComponent(str)
            /* JSSTYLED */
            .replace(/[!'()]/g, escape)
            /* JSSTYLED */
            .replace(/\*/g, '%2A'));
}


///--- Handler Functions
function convertS3PresignedToManta(req, res, next) {
    var log = req.log;
    log.debug({queryParams: Object.keys(req.query)},
              'convertS3PresignedToManta: checking query params');

    // Check if this is an S3 presigned URL
    // (only convert if it has S3-specific parameters)
    // Reject early if Algorithm/Credential are present but Signature
    // is missing or empty — this is a malformed presigned URL that
    // must not fall through to the normal (unauthenticated) path.
    if (req.query['X-Amz-Algorithm'] && req.query['X-Amz-Credential'] &&
        !req.query['X-Amz-Signature']) {
        next(new PreSignedRequestError(
            'X-Amz-Signature is required'));
        return;
    }
    if (req.query['X-Amz-Algorithm'] && req.query['X-Amz-Signature'] &&
        req.query['X-Amz-Credential']) {
        log.debug('convertS3PresignedToManta: detected S3' +
                 ' presigned URL - converting');

        try {
            // Preserve original S3 parameters for signature validation
            req._originalS3Credential = req.query['X-Amz-Credential'];
            req._originalS3Date = req.query['X-Amz-Date'];
            req._originalS3Expires = req.query['X-Amz-Expires'];
            req._originalS3SignedHeaders =
                decodeURIComponent(req.query['X-Amz-SignedHeaders'] || 'host');
            req._originalS3Signature = req.query['X-Amz-Signature'];

            // Extract access key from X-Amz-Credential
            // Format: AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request
            var credential = req.query['X-Amz-Credential'];
            if (!credential) {
                next(new PreSignedRequestError('X-Amz-Credential is required'));
                return;
            }

            var credentialParts = credential.split('/');
            if (credentialParts.length < 2) {
                next(new
                     PreSignedRequestError('Invalid X-Amz-Credential format'));
                return;
            }

            var accessKeyId = credentialParts[0];

            // Convert X-Amz-Date + X-Amz-Expires to absolute expires timestamp
            var amzDate = req.query['X-Amz-Date'];
            var amzExpires = parseInt(req.query['X-Amz-Expires'], 10);

            if (!amzDate || !amzExpires) {
                next(new PreSignedRequestError
                     ('X-Amz-Date and X-Amz-Expires are required'));
                return;
            }

            // Check for X-Amz-Date format (ISO8601: 20230101T120000Z)
            // https://docs.aws.amazon.com/AmazonS3/latest/API/
            // sigv4-query-string-auth.html
            if (typeof (amzDate) !== 'string' ||
                amzDate.length !== 16 ||
                !/^\d{8}T\d{6}Z$/.test(amzDate)) {
                next(new PreSignedRequestError(
                    'X-Amz-Date must be in ISO8601 format (YYYYMMDDTHHMMSSZ)'));
                return;
            }

            // Check for X-Amz-Expires
            if (isNaN(amzExpires) || amzExpires <= 0 || amzExpires > 604800) {
                next(new PreSignedRequestError(
                    'X-Amz-Expires must be a positive integer' +
                    ' (max 604800 seconds/7 days)'));
                return;
            }

            // Parse ISO8601 date: 20230101T120000Z (UTC)
            var year = parseInt(amzDate.substr(0, 4), 10);
            var month = parseInt(amzDate.substr(4, 2), 10) - 1;
            var day = parseInt(amzDate.substr(6, 2), 10);
            var hour = parseInt(amzDate.substr(9, 2), 10);
            var minute = parseInt(amzDate.substr(11, 2), 10);
            var second = parseInt(amzDate.substr(13, 2), 10);

            // Additional validation for parsed date components
            // for the closed interval, the lower bound is 1983
            // because TCP/IP was introduced in that date.
            if (year < 1983 || year > (new Date().getFullYear() + 100) ||
                month < 0 || month > 11 ||
                day < 1 || day > 31 ||
                hour < 0 || hour > 23 ||
                minute < 0 || minute > 59 ||
                second < 0 || second > 59) {
                next(new PreSignedRequestError
                     ('Invalid date components in X-Amz-Date'));
                return;
            }

            var requestTime = new Date(Date.UTC(year, month, day, hour,
                                                minute, second));

            // Validate the created date is valid
            if (isNaN(requestTime.getTime())) {
                next(new PreSignedRequestError('Invalid date in X-Amz-Date'));
                return;
            }
            var expiresTime = Math.floor(requestTime.getTime() / 1000) +
                amzExpires;

            // Map algorithm
            var algorithm;
            switch (req.query['X-Amz-Algorithm']) {
                case 'AWS4-HMAC-SHA256':
                    algorithm = 'rsa-sha256'; // Map to Manta's default
                    break;
                default:
                    algorithm = 'rsa-sha256';
                    break;
            }

            // Convert to Manta presigned format
            req.query.keyId = accessKeyId;
            req.query.algorithm = algorithm;
            req.query.expires = expiresTime.toString();
            req.query.signature = req.query['X-Amz-Signature'];
            // S3 presigned URLs are method-specific
            req.query.method = req.method;

            // Mark this as an S3 presigned URL conversion
            req._s3PresignedConverted = true;
            req.isS3Request = true;

            // Set up S3 request object for compatibility layer
            // strip leading /
            var pathParts = req.path().substring(1).split('/');
            var operation;

            // Check if this is a multipart upload part operation
            if (req.query.uploadId && req.query.partNumber &&
                req.method === 'PUT') {
                operation = 'UploadPart';
            } else {
                switch (req.method) {
                    case 'GET':
                        operation = 'GetBucketObject';
                        break;
                    case 'PUT':
                        operation = 'CreateBucketObject';
                        break;
                    case 'HEAD':
                        operation = 'HeadBucketObject';
                        break;
                    case 'DELETE':
                        operation = 'DeleteBucketObject';
                        break;
                    default:
                        operation = 'GetBucketObject';
                        break;
                }
            }

            req.s3Request = {
                bucket: pathParts[0],
                object: pathParts.slice(1).join('/'),
                operation: operation,
                isS3Request: true
            };

            // Preserve MPU parameters for UploadPart operations
            if (operation === 'UploadPart') {
                req.s3Request.uploadId = req.query.uploadId;
                req.s3Request.partNumber = parseInt(req.query.partNumber, 10);
            }

            log.debug({
                s3Request: req.s3Request
            }, 'convertS3PresignedToManta: set up S3 request object');

            // Clean up S3-specific parameters
            delete req.query['X-Amz-Algorithm'];
            delete req.query['X-Amz-Credential'];
            delete req.query['X-Amz-Date'];
            delete req.query['X-Amz-Expires'];
            delete req.query['X-Amz-SignedHeaders'];
            delete req.query['X-Amz-Signature'];
            delete req.query['X-Amz-Security-Token'];

            log.debug({
                keyId: req.query.keyId,
                algorithm: req.query.algorithm,
                expires: req.query.expires,
                remainingQueryParams: Object.keys(req.query)
            }, 'convertS3PresignedToManta:' +
                     ' successfully converted to Manta format');

        } catch (err) {
            log.error(err, 'convertS3PresignedToManta: conversion failed');
            next(new PreSignedRequestError('Invalid S3 presigned URL format'));
            return;
        }
    }

    next();
}
function checkIfPresigned(req, res, next) {
    var hasAuthHeader = req.headers.authorization;
    var hasMantaPresigned = req.query.expires && req.query.signature &&
                           req.query.keyId && req.query.algorithm;
    var hasS3Presigned = req.query['X-Amz-Algorithm'] &&
        req.query['X-Amz-Signature'];

    req.log.debug({
        hasAuthHeader: !!hasAuthHeader,
        hasMantaPresigned: hasMantaPresigned,
        hasS3Presigned: hasS3Presigned,
        queryKeys: Object.keys(req.query)
    }, 'checkIfPresigned: checking request type');

    if (hasAuthHeader || (!hasMantaPresigned && !hasS3Presigned)) {
        req.log.debug('checkIfPresigned: not presigned, proceeding normally');
        next();
    } else {
        req.log.debug('checkIfPresigned: detected presigned request');
        req._presigned = true;
        next();
    }
}
function preSignedUrl(req, res, next) {

    var isPresigned = req.isPresigned();
    req.log.debug({isPresigned: isPresigned},
                  'preSignedUrl: checking if presigned');
    if (!isPresigned) {
        req.log.debug('preSignedUrl: not presigned, skipping');
        next();
        return;
    }

    req.log.debug('preSignedUrl: processing presigned URL request');

    var expires;
    var log = req.log;

    if (!req.query) {
        next(new PreSignedRequestError('Missing query parameters'));
        return;
    }

    if (!req.method) {
        next(new PreSignedRequestError('Missing request method'));
        return;
    }

    /* JSSTYLED */
    var methods = (req.query.method || req.method).split(/\s*,\s*/);
    var now = Math.floor(Date.now()/1000);

    methods.sort();

    log.debug('preSignedUrl: entered');

    if (methods.indexOf(req.method) === -1) {
        next(new PreSignedRequestError(req.method +
                                       ' was not a signed method'));
        return;
    }

    var missing = [
        'algorithm',
        'expires',
        'keyId',
        'signature'].filter(function isMissingParam(k) {
            return (!req.query[k]);
        });

    if (missing.length) {
        next(new PreSignedRequestError('parameters "' +
                                       missing.join(', ') +
                                       '" are required'));
        return;
    }

    try {
        expires = parseInt(req.query.expires, 10);
    } catch (_e) {
        next(new PreSignedRequestError('expires is invalid'));
        return;
    }

    log.debug({
        expires: expires,
        now: now
    }, 'checking if request is  expired');
    if (now > expires) {
        next(new PreSignedRequestError('request expired'));
        return;
    }

    if (!req.query.algorithm || typeof (req.query.algorithm) !== 'string') {
        next(new PreSignedRequestError('Algorithm must be a valid string'));
        return;
    }

    var parsed = {
        scheme: 'Signature',
        algorithm: req.query.algorithm.toUpperCase(),
        params: {
            keyId: req.query.keyId,
            signature: req.query.signature,
            role: req.query.role,
            'role-tag': req.query['role-tag']
        },
        signature: req.query.signature,
        signingString: ''
    };

    // Build the signing string, which is:
    // METHOD\n
    // $value_of_host_header
    // REQUEST_URL\n
    // key=val&...
    // with sorted query params (lexicographically),
    // minus the actual signature.
    parsed.signingString =
        methods.join(',') + '\n' +
        req.header('host') + '\n' +
        req.pathPreSanitize + '\n' +
        Object.keys(req.query).sort(function compareQueryKeys(a, b) {
            return (a.localeCompare(b));
        }).filter(function excludeSignatureParam(k) {
            return (k.toLowerCase() !== 'signature');
        }).map(function encodeQueryParam(k) {
            return (rfc3986(k) + '=' + rfc3986(req.query[k]));
        }).join('&');

    log.debug({signatureOptions: parsed}, 'preSignedUrl: parsed');

    if (SIGN_ALG[parsed.algorithm] !== true) {
        next(new PreSignedRequestError(parsed.algorithm +
                                       ' is not a supported signing ' +
                                       'algorithm'));
        return;
    }

    req.auth = {
        role: req.query.role || '',
        'role-tag': req.query['role-tag'] || '',
        callerKey: req.query.keyId,
        signature: parsed
    };

    // For S3 presigned URLs, use Mahi's SigV4 validation
    if (req._s3PresignedConverted) {
        req.auth.accessKeyId = req.query.keyId;
        req.auth.method = 'presigned-s3';

        log.debug('preSignedUrl: S3 presigned URL' +
                  ' - validating signature via Mahi');

        // For presigned URLs, we need to reconstruct the canonical request that
        // Mahi expects by creating an Authorization header from query
        // parameters
        try {
            // Get the original S3 query parameters that were
            // preserved before conversion
            var credential = req._originalS3Credential;
            var amzDate = req._originalS3Date;
            var signedHeaders = req._originalS3SignedHeaders || 'host';
            var signature = req._originalS3Signature;

            if (!credential || !amzDate || !signature) {
                next(new PreSignedRequestError
                     ('Missing required S3 presigned URL parameters'));
                return;
            }

            // Reconstruct Authorization header from presigned URL parameters
            var authHeader = 'AWS4-HMAC-SHA256 Credential=' + credential +
                           ', SignedHeaders=' + signedHeaders +
                           ', Signature=' + signature;

            // Create headers object for verification
            var verificationHeaders = {
                'authorization': authHeader,
                'x-amz-date': amzDate,
                'host': req.headers.host || 'localhost'
            };

            // Add any other headers that were signed
            if (signedHeaders !== 'host') {
                var headerList = signedHeaders.split(';');
                headerList.forEach(function addSignedHeader(headerName) {
                    if (headerName !== 'host' && req.headers[headerName]) {
                        verificationHeaders[headerName] =
                            req.headers[headerName];
                    }
                });
            }

            // Construct URL for verification with original S3 query parameters
            // For presigned URLs, we need to reconstruct the original URL
            // that was signed
            var urlForVerification = req.url.split('?')[0];

            // Reconstruct the original S3 presigned URL query string
            // that was signed
            var originalQueryParams = [];
            if (req._originalS3Credential) {
                originalQueryParams.push('X-Amz-Algorithm=AWS4-HMAC-SHA256');
                originalQueryParams.push('X-Amz-Credential=' +
                             encodeURIComponent(req._originalS3Credential));
                originalQueryParams.push('X-Amz-Date=' + req._originalS3Date);
                originalQueryParams.push('X-Amz-Expires=' +
                                         req._originalS3Expires);
                if (req._originalS3SignedHeaders) {
                    originalQueryParams.push('X-Amz-SignedHeaders=' +
                                             req._originalS3SignedHeaders);
                }
            }

            // Add any additional query parameters that were in the original
            // request (but skip the converted Manta parameters)
            var skipParams = ['keyId', 'algorithm', 'expires', 'signature',
                              'method'];
            Object.keys(req.query).forEach(function addOriginalQueryParam(key) {
                if (skipParams.indexOf(key) === -1 &&
                    !key.startsWith('X-Amz-')) {
                    originalQueryParams.push(key + '=' +
                        encodeURIComponent(req.query[key]));
                }
            });

            if (originalQueryParams.length > 0) {
                urlForVerification += '?' + originalQueryParams.join('&');
            }

            // Create request object for Mahi verification
            var requestForVerification = {
                method: req.method,
                url: urlForVerification,
                headers: verificationHeaders
            };

            log.debug({
                originalUrl: req.url,
                verificationUrl: urlForVerification,
                authHeader: authHeader.substring(0, 100) + '...',
                signedHeaders: signedHeaders
            }, 'S3_PRESIGNED_DEBUG: Constructed verification request');

            // Use Mahi's verifySigV4 with reconstructed request
            req.mahi.verifySigV4(requestForVerification,
                                 function onS3PresignedVerified(err, result) {
                if (err) {
                    log.debug({
                        error: err.message || err,
                        accessKeyId: req.query.keyId,
                        restCode: err.restCode
                    }, 'S3_PRESIGNED_DEBUG: Signature validation failed');
                    next(new PreSignedRequestError('Invalid signature: ' +
                                                   (err.message || err)));
                    return;
                }

                log.debug({
                    accessKeyId: result.accessKeyId,
                    userUuid: result.userUuid
                }, 'S3_PRESIGNED_DEBUG: Signature validation successful');

                // Store validation result for later use
                req.auth.accountid = result.userUuid;
                req.auth.accessKeyId = result.accessKeyId;
                req.auth.bucketScope = normalizeAuthBucketScope(
                    result.bucketScope, log);
                req._s3PresignedAuthComplete = true;

                log.debug({auth: req.auth}, 'preSignedUrl:' +
                          ' S3 presigned URL validation completed');
                next();
            });
        } catch (err) {
            log.error(err, 'preSignedUrl: Failed to reconstruct S3 presigned' +
                      ' URL for validation');
            next(new PreSignedRequestError('Invalid S3 presigned URL format'));
        }
        return; // Don't call next() here, it's called in the callback
    }

    log.debug({auth: req.auth}, 'preSignedUrl: done');
    next();
}
function checkAuthzScheme(req, res, next) {
    // Skip auth scheme check for anonymous access
    if (req.isAnonymousAccess) {
        req.log.debug('checkAuthzScheme: skipping for anonymous access');
        next();
        return;
    }

    if (!req.authorization.scheme) {
        req.log.debug('checkAuthzScheme: no auth scheme found');
        next();
        return;
    }

    var scheme = req.authorization.scheme.toLowerCase();
    var ok = [constants.AWS_AUTH.SCHEME_SIGNATURE,
              constants.AWS_AUTH.SCHEME_TOKEN,
              constants.AWS_AUTH.SCHEME_SIGV4].indexOf(scheme) >= 0;

    req.log.debug({
        authScheme: scheme,
        isS3Request: !!req.isS3Request,
        isValidScheme: ok
    }, 'S3_AUTH_DEBUG: Detected authorization scheme');

    if (!ok) {
        req.log.debug('S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
        ' - Invalid authorization scheme: ' + scheme);
        next(new AuthSchemeError(scheme));
    } else {
        next();
    }
}
function signatureHandler(req, res, next) {
    // Skip if already authenticated via S3 presigned URL
    if (req._s3PresignedAuthComplete) {
        req.log.debug('signatureHandler: ' +
                      'skipping - S3 presigned URL already authenticated');
        next();
        return;
    }

    if ((req.authorization.scheme || '').toLowerCase() !== 'signature') {
        next();
        return;
    }

    req.log.debug('using signature auth');
    var algorithm = req.authorization.signature.algorithm;
    if (SIGN_ALG[algorithm] !== true) {
        next(new InvalidAlgorithmError(algorithm,
            Object.keys(SIGN_ALG).join(', ')));
        return;
    }

    req.auth = {
        signature: req.authorization.signature,
        callerKey: req.authorization.signature.keyId
    };
    next();
}
/**
 * SigV4 Authentication Handler
 *
 * Processes AWS Signature Version 4 requests by forwarding them to Mahi
 * for signature verification and user lookup.
 */
function sigv4Handler(req, res, next) {
    // Skip if already authenticated via S3 presigned URL
    if (req._s3PresignedAuthComplete) {
        req.log.debug('sigv4Handler: skipping -' +
                      ' S3 presigned URL already authenticated');
        next();
        return;
    }

    // Only process AWS4-HMAC-SHA256 requests
    if ((req.authorization.scheme || '').toLowerCase() !==
        constants.AWS_AUTH.SCHEME_SIGV4) {
        next();
        return;
    }

    req.log.debug({
        authorizationScheme: req.authorization ?
        req.authorization.scheme : 'undefined',
        hasAuthorizationHeader: !!req.headers.authorization,
        authHeaderLength: req.headers.authorization ?
        req.headers.authorization.length : 0,
        authHeaderPrefix: req.headers.authorization ?
        req.headers.authorization.substring(0, 100) + '...' : 'none'
    }, 'S3_AUTH_DEBUG: Starting AWS SigV4 authentication');

    // Validate required headers for SigV4
    var authHeader = req.headers.authorization;
    var dateHeader = req.headers['x-amz-date'] || req.headers.date;
    var sessionToken = req.headers['x-amz-security-token'];

    // Debug: Log session token detection
    req.log.debug({
        hasAuthHeader: !!authHeader,
        hasSessionToken: !!sessionToken,
        sessionTokenLength: sessionToken ? sessionToken.length : 0
    }, 'S3_AUTH_DEBUG: Headers received for session token detection');

    // Debug session token detection
    req.log.debug({
        hasSessionTokenHeader: !!sessionToken,
        sessionTokenValue: sessionToken ? '[REDACTED]' : null,
        sessionTokenLength: sessionToken ? sessionToken.length : 0,
        willUseTempCredPath: !!(sessionToken &&
                                typeof (sessionToken) === 'string' &&
            sessionToken.trim().length > 10)
    }, 'S3_AUTH_DEBUG: Session token detection' +
                  ' for credential type determination');

    // INFO level logging for STS requests to debug role chaining
    var isStsRequest = req.url && req.url.indexOf('Action=AssumeRole') > -1;
    if (isStsRequest) {
        req.log.debug({
            requestUrl: req.url,
            hasSessionToken: !!sessionToken,
            sessionTokenPrefix: sessionToken ?
                sessionToken.substring(0, 50) + '...' : null,
            sessionTokenLength: sessionToken ? sessionToken.length : 0,
            headerKeys: Object.keys(req.headers),
            authHeaderPrefix: authHeader ?
                authHeader.substring(0, 50) + '...' : null
        }, 'STS_SESSION_TOKEN_DEBUG: Incoming AssumeRole request headers');
    }

    if (!authHeader) {
        req.log.debug('S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
        ' - Missing Authorization header');
        sendInvalidSignatureError(req, res, next,
           'Missing Authorization header');
        return;
    }

    if (!dateHeader) {
        req.log.debug('S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
        ' - Missing date header');
        sendInvalidSignatureError(req, res, next, 'Missing date header');
        return;
    }

    // Use preserved raw body for signature verification if available
    if (req._rawBodyBuffer && req._originalContentMD5) {
        req.log.debug({
            preservedBodyLength: req._rawBodyBuffer.length,
            originalContentMD5: req._originalContentMD5,
            headerContentMD5: req.headers['content-md5'],
            contentMD5Match: req._originalContentMD5 ===
                req.headers['content-md5']
        }, 'S3_AUTH_DEBUG: Using preserved raw body for' +
                      ' signature verification');

        // If our calculated MD5 doesn't match the header, the client sent
        // the wrong MD5
        // But we should use the client's MD5 for signature verification since
        // that's what they signed
        if (req._originalContentMD5 !== req.headers['content-md5']) {
            req.log.debug({
                calculated: req._originalContentMD5,
                header: req.headers['content-md5'],
                action: 'Using client header for signature verification'
            }, 'S3_AUTH_DEBUG: Content-MD5 mismatch' +
               ' - client may have sent incorrect MD5');
        }
    }

    // Prepare request object for node-mahi verifySigV4 function
    // Only skip headers that cause connection issues, but preserve all
    // values for signature verification
    var filteredHeaders = {};
    var skipHeaders = [
        'transfer-encoding',
        'expect'
    ];

    Object.keys(req.headers).forEach(function filterHeaderForVerification(key) {
        var lowerKey = key.toLowerCase();
        if (skipHeaders.indexOf(lowerKey) !== -1) {
            // Skip completely (these cause connection issues)
            return;
        } else {
            // Include with original value
            // (needed for correct signature verification)
            filteredHeaders[key] = req.headers[key];
        }
    });

    // Don't override content-md5 for SigV4 verification
    // must use client's signed value
    if (req._rawBodyBuffer && req._originalContentMD5) {
        // Only log the discrepancy if there is one, but preserve
        // client's signed value
        if (req._originalContentMD5 !== req.headers['content-md5']) {
            req.log.debug({
                calculated: req._originalContentMD5,
                header: req.headers['content-md5'],
                action: 'Preserving client header for SigV4 verification'
            }, 'S3_AUTH_DEBUG: Content-MD5 mismatch' +
                         ' - keeping client signed value');
        }
        // Keep the original client header value for signature verification
        // The client signed the request with this value, so mahi must verify
        // with the same
    }

    // Some clients rely in content-length for sigv4
    // but restify overwrites this header, to bypass this
    // we add a new header that mahi can read and adjust it's
    // canonical url to match with the one send by the client.
    if ('content-length' in filteredHeaders) {
        filteredHeaders['manta-s3-content-length'] =
            filteredHeaders['content-length'];
    }
    // The same applies for content-md5 header
    if ('content-md5' in filteredHeaders) {
        filteredHeaders['manta-s3-content-md5'] =
            filteredHeaders['content-md5'];
    }

    /*
     * Use the original URL (_rawSignedUrl) for SigV4, before
     * MANTA-331 sanitizePath() stripped trailing slashes.
     */
    var urlForVerification = req._rawSignedUrl || req.url;

    req.log.debug({
        rawSignedUrl: req._rawSignedUrl,
        sanitizedUrl: req.url,
        urlForVerification: urlForVerification
    }, 'S3_AUTH_DEBUG: Using raw URL for SigV4 verification');

    var requestForVerification = {
        method: req.method,
        url: urlForVerification,
        headers: filteredHeaders
    };

    // Include preserved raw body for signature verification if available
    if (req._rawBodyBuffer) {
        requestForVerification.body = req._rawBodyBuffer;
        req.log.debug({
            hasRawBody: true,
            bodyLength: req._rawBodyBuffer.length,
            bodyMD5: req._originalContentMD5
        }, 'S3_AUTH_DEBUG: Including preserved ' +
                      'raw body in verification request');
    } else if (req.method === 'POST' && req.headers['content-length'] &&
               parseInt(req.headers['content-length'], 10) > 0) {
        req.log.warn({
            method: req.method,
            contentLength: req.headers['content-length']
        }, 'S3_AUTH_DEBUG: POST request with body' +
                     ' but no preserved raw body available');
    }

    var originalHeaderKeys = Object.keys(req.headers).sort();
    var filteredHeaderKeys = Object.keys(requestForVerification.headers).
    sort();
    var skippedHeaders = originalHeaderKeys.filter(
        function wasHeaderSkipped(key) {
        return (skipHeaders.indexOf(key.toLowerCase()) !== -1);
    });

    req.log.debug({
        method: requestForVerification.method,
        url: requestForVerification.url,
        originalRequestMethod: req.method,
        originalRequestUrl: req.url,
        rawSignedUrl: req._rawSignedUrl,
        authHeaderPrefix: (requestForVerification.headers.authorization ||
        '').substring(0, 50) + '...',
        hasAuthHeader: !!requestForVerification.headers.authorization,
        hasDateHeader: !!(requestForVerification.headers['x-amz-date'] ||
        requestForVerification.headers.date),
        originalHeaderCount: originalHeaderKeys.length,
        filteredHeaderCount: filteredHeaderKeys.length,
        skippedHeaders: skippedHeaders,
        filteredHeaderKeys: filteredHeaderKeys,
        criticalHeaders: {
            'content-encoding':
            requestForVerification.headers['content-encoding'],
            'x-amz-decoded-content-length':
            requestForVerification.headers['x-amz-decoded-content-length'],
            'x-amz-sdk-checksum-algorithm':
            requestForVerification.headers['x-amz-sdk-checksum-algorithm'],
            'x-amz-trailer': requestForVerification.headers['x-amz-trailer']
        },
        originalHeaders: req.rawHeaders,
        CONTENT_MD5_DEBUG: {
            originalClientHeader: req.headers['content-md5'],
            calculatedMD5: req._originalContentMD5,
            sentToMahi: requestForVerification.headers['content-md5'],
            match: req.headers['content-md5'] ===
                requestForVerification.headers['content-md5']
        }
    }, 'S3_AUTH_DEBUG:'+
    ' Calling node-mahi verifySigV4 for signature verification'+
    ' (only skipped connection-breaking headers)');

    // Use node-mahi's verifySigV4 method
    // (extended for session tokens via custom request)
    // Only use temporary credential path if session token is present and
    // token will be validated in mahi.
    var isTemporaryCredential = sessionToken &&
        typeof (sessionToken) === 'string' &&
                               sessionToken.trim().length > 10;
                               // AWS session tokens are much longer

    if (isTemporaryCredential) {
        // For temporary credentials, use custom request to
        // include session token
        req.auth.isTemporaryCredential = isTemporaryCredential;
        req.log.debug({
            sessionTokenPresent: true,
            sessionTokenPrefix: sessionToken.substring(0, 20) + '...'
        }, 'S3_AUTH_DEBUG:' +
           ' Including session token for temporary credential validation');

        // Create custom request with session token as query parameter
        var customReq = {
            method: requestForVerification.method,
            url: requestForVerification.url +
                (requestForVerification.url.includes('?') ? '&' : '?') +
                'sessionToken=' + encodeURIComponent(sessionToken),
            headers: requestForVerification.headers,
            body: requestForVerification.body
        };

        req.log.debug({
            mahiClient: !!req.mahi,
            mahiUrl: req.mahi && req.mahi.url,
            customReqUrl: customReq.url
        }, 'S3_AUTH_DEBUG:' +
           ' About to call mahi.verifySigV4 for temporary credentials');

        // INFO level logging for STS requests
        if (isStsRequest) {
            req.log.debug({
                customReqUrl: customReq.url,
                customReqMethod: customReq.method,
                sessionTokenInUrl: customReq.url.indexOf('sessionToken=') > -1,
                urlLength: customReq.url.length
            }, 'STS_SESSION_TOKEN_DEBUG: Sending to Mahi verifySigV4');
        }

        req.mahi.verifySigV4(customReq,
            function onTempCredentialVerified(err, result) {
        // Debug: Log raw mahi response
        if (result && isTemporaryCredential) {
            req.log.debug({
                accessKeyId: result.accessKeyId,
                assumedRole: result.assumedRole,
                assumedRoleType: typeof (result.assumedRole),
                assumedRoleIsNull: result.assumedRole === null,
                assumedRoleIsUndefined: result.assumedRole === undefined,
                assumedRoleKeys: result.assumedRole &&
                    typeof (result.assumedRole) === 'object' ?
                    Object.keys(result.assumedRole) : null,
                assumedRoleArn: result.assumedRole &&
                    typeof (result.assumedRole) === 'object' ?
                    result.assumedRole.arn : null,
                isTemporaryCredential: result.isTemporaryCredential,
                principalUuid: result.principalUuid
            }, 'DEBUG: Raw mahi response for temporary credentials');
        }

        if (err) {
            req.log.debug({
                error: err.message || err,
                restCode: err.restCode,
                errorName: err.name,
                statusCode: err.statusCode
            }, 'S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
            ' - SigV4 verification failed');

            handleMahiAuthError(req, res, next, err);
            return;
        }

        if (!result || !result.valid || !result.userUuid) {
            req.log.debug({
                result: result,
                hasResult: !!result,
                isValid: result ? result.valid : false,
                hasUserUuid: result ? !!result.userUuid : false
            }, 'S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
            ' - Invalid response from SigV4 verification');
            sendInvalidSignatureError(req, res, next, 'Authentication failed');
            return;
        }

        // Note: Temporary credential role handling done in loadAssumedRole

        // Debug: Check specifically for assumedRole field
        if (isTemporaryCredential) {
            req.log.debug('IAM_DEBUG: TempCred AccessKey=' +
                result.accessKeyId + ' HasAssumedRole=' +
                !!result.assumedRole + ' AssumedRole=' +
                (result.assumedRole || 'NULL'));
        }

        // Set authentication context for downstream handlers
        req.auth = {
            accountid: result.userUuid,
            accessKeyId: result.accessKeyId,
            method: 'sigv4',
            signature: {
                verified: true,
                keyId: result.accessKeyId
            },
            assumedRole: result.assumedRole || null,
            isTemporaryCredential: isTemporaryCredential,
            principalUuid: result.principalUuid || result.userUuid,
            bucketScope: normalizeAuthBucketScope(
                result.bucketScope, req.log)
        };

        // Store secret key for AWS chunked signature verification
        // Note: Secret key may be provided directly in verifySigV4 response
        // or loaded later by credential-provider from account.accesskeys
        if (result.secretAccessKey) {
            req.auth.secretAccessKey = result.secretAccessKey;
            req.log.debug({
                hasSecretKey: true,
                isTemporaryCredential: isTemporaryCredential
            }, 'Stored secret access key for chunk signature verification');
        } else {
            req.log.debug({
                hasSecretKey: false,
                isTemporaryCredential: isTemporaryCredential,
                willLoadFromCredentialProvider: true
            }, 'Secret access key not in verifySigV4 response - ' +
                'will be loaded by credential-provider from account ' +
                'accesskeys');
        }

        if (result.signingKey) {
            req.auth.signingKey = Buffer.from(
                result.signingKey, 'hex');
        }

        req.log.debug({
            accessKeyId: result.accessKeyId,
            userUuid: result.userUuid,
            method: 'sigv4',
            isTemporaryCredential: isTemporaryCredential,
            assumedRole: result.assumedRole,
            principalUuid: result.principalUuid,
            resultKeys: Object.keys(result)
        }, 'S3_AUTH_DEBUG:' +
            ' AUTHENTICATION SUCCESS - SigV4 verification successful');

        // Check if client has closed connection before proceeding
        if (req._muskie_client_closed) {
            req.log.debug('S3_AUTH_DEBUG:' +
                ' Client closed connection during auth, skipping next()');
            return;
        }

        next();
    });
    } else {
        // For permanent credentials, use standard verifySigV4 method
        req.log.debug('S3_AUTH_DEBUG:' +
                      ' Using standard verifySigV4 for permanent credentials');

        req.log.debug({
            mahiClient: !!req.mahi,
            mahiUrl: req.mahi && req.mahi.url,
            requestUrl: requestForVerification.url
        }, 'S3_AUTH_DEBUG:' +
           ' About to call mahi.verifySigV4 for permanent credentials');

        req.mahi.verifySigV4(requestForVerification,
            function onPermanentCredentialVerified(err, result) {
            if (err) {
                req.log.debug({
                    error: err.message || err,
                    restCode: err.restCode,
                    errorName: err.name,
                    statusCode: err.statusCode
                }, 'S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
                ' - SigV4 verification failed');

                handleMahiAuthError(req, res, next, err);
                return;
            }

            if (!result || !result.valid || !result.userUuid) {
                req.log.debug({
                    result: result,
                    hasResult: !!result,
                    isValid: result ? result.valid : false,
                    hasUserUuid: result ? !!result.userUuid : false
                }, 'S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
                ' - Invalid response from SigV4 verification');
                sendInvalidSignatureError(req, res, next,
                                          'Authentication failed');
                return;
            }

            // Set authentication context for downstream handlers
            req.auth = {
                accountid: result.userUuid,
                accessKeyId: result.accessKeyId,
                method: 'sigv4',
                signature: {
                    verified: true,
                    keyId: result.accessKeyId
                },
                bucketScope: normalizeAuthBucketScope(
                    result.bucketScope, req.log)
            };

            // Store secret key for AWS chunked signature verification
            // Note: Secret key may be provided directly in verifySigV4 response
            // or loaded later by credential-provider from account.accesskeys
            if (result.secretAccessKey) {
                req.auth.secretAccessKey = result.secretAccessKey;
                req.log.debug({
                    hasSecretKey: true
                }, 'Stored secret access key for chunk signature verification');
            } else {
                req.log.debug({
                    hasSecretKey: false,
                    willLoadFromCredentialProvider: true
                }, 'Secret access key not in verifySigV4 response - ' +
                    'will be loaded by credential-provider from account ' +
                    'accesskeys');
            }

            if (result.signingKey) {
                req.auth.signingKey = Buffer.from(
                    result.signingKey, 'hex');
            }

            req.log.debug({
                accessKeyId: result.accessKeyId,
                userUuid: result.userUuid,
                method: 'sigv4'
            }, 'S3_AUTH_DEBUG: AUTHENTICATION SUCCESS'+
            ' - SigV4 verification successful');

            // Check if client has closed connection before proceeding
            if (req._muskie_client_closed) {
                req.log.debug('S3_AUTH_DEBUG:' +
                    ' Client closed connection during auth, skipping next()');
                return;
            }

            next();
        });
    }
}
function verifySignature(req, res, next) {
    // Skip signature verification for S3 presigned URLs
    if (req._s3PresignedAuthComplete) {
        req.log.debug('verifySignature: skipping ' +
                      '- S3 presigned URL already validated');
        next();
        return;
    }

    // Skip signature verification for anonymous access
    if (req.isAnonymousAccess) {
        req.log.debug('verifySignature: skipping for anonymous access');
        next();
        return;
    }

    // Skip SSH signature verification if SigV4
    // authentication was already completed
    if (req.auth.method === 'sigv4') {
        req.log.debug('verifySignature:'+
        ' skipping SSH signature verification for SigV4 request');
        setImmediate(next);
        return;
    }

    if (!req.auth.signature) {
        setImmediate(next);
        return;
    }

    req.log.debug('verifySignature: entered');

    var user = req.caller.user;
    var account = req.caller.account;

    var keyId = req.auth.keyId;
    var signature = req.auth.signature;

    var keys = user ? user.keys : account.keys;
    if (!keys || !keys[keyId]) {
        next(new KeyDoesNotExistError(
            account.login,
            keyId,
            user ? user.login : null));
        return;
    }

    var key = keys[keyId];
    try {
        var ok = httpSignature.verifySignature(signature, key);
    } catch (e) {
        next(new InternalError(e));
        return;
    }
    if (!ok) {
        sendInvalidSignatureError(req, res, next,
           'Signature verification failed');
        return;
    }

    req.log.debug('verifySignature: done');
    next();
}


///--- Exports

module.exports = {
    sendInvalidSignatureError: sendInvalidSignatureError,
    rfc3986: rfc3986,
    convertS3PresignedToManta: convertS3PresignedToManta,
    checkIfPresigned: checkIfPresigned,
    preSignedUrl: preSignedUrl,
    checkAuthzScheme: checkAuthzScheme,
    signatureHandler: signatureHandler,
    sigv4Handler: sigv4Handler,
    verifySignature: verifySignature,
    SIGN_ALG: SIGN_ALG
};
