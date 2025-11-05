/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
 */

//
// Generate keys for the muskie config with:
//
// $ openssl enc -aes-128-cbc -k $(uuid) -P
// salt=C93A670ACC05C166
// key=5163205CA0C7F2752FD3A574E30F64DD
// iv=6B11F0F0B786F96812D5A0799D5B217A
//

var crypto = require('crypto');
var zlib = require('zlib');

var assert = require('assert-plus');
var httpSignature = require('http-signature');
var path = require('path');
var querystring = require('querystring');
var sprintf = require('util').format;
var vasync = require('vasync');

var libmantalite = require('./libmantalite');
var common = require('./common');
var s3Compat = require('./s3-compat');
require('./errors');

/**
 * Map Manta action to IAM action for policy evaluation
 */
function mapMantaToIamAction(mantaAction) {
    var mapping = {
        'getdirectory': 's3:ListAllMyBuckets',  // List all buckets
        'getbucket': 's3:ListBucket',       // List objects in specific bucket
        'listbucketobjectsv2': 's3:ListObjectsV2', // List objects V2 API
        'listbucketobjects': 's3:ListBucket',   // Legacy list objects
        'listobjects': 's3:ListBucket',    // Legacy list objects (duplicate?)
        'putbucket': 's3:CreateBucket',
        'deletebucket': 's3:DeleteBucket',
        'getobject': 's3:GetObject',
        'putobject': 's3:PutObject',
        'deleteobject': 's3:DeleteObject'
    };

    return (mapping[mantaAction] || mantaAction);
}

/**
 * Map Manta resource key to IAM ARN format for policy evaluation
 * Uses both the resource key and request path to determine the correct bucket
 */
function mapMantaToIamResource(mantaResourceKey, requestPath) {
    // Extract bucket name from request path if available
    if (requestPath && typeof (requestPath) === 'string') {
        // Request path format: /bucket or /bucket/object
        var pathParts = requestPath.split('/').filter(
            function (part) { return part.length > 0; });
        if (pathParts.length >= 1) {
            var bucket = pathParts[0];
            var objectPath = pathParts.slice(1).join('/');

            if (objectPath) {
                return ('arn:aws:s3:::' + bucket + '/' + objectPath);
            } else {
                return ('arn:aws:s3:::' + bucket);
            }
        }
    }

    // Fallback to parsing the Manta resource key
    if (mantaResourceKey && typeof (mantaResourceKey) === 'string') {
        var parts = mantaResourceKey.split('/');

        // Handle case where resource is just bucket name (no account prefix)
        if (parts.length === 1 && parts[0]) {
            return ('arn:aws:s3:::' + parts[0]);
        }

        // Handle case with account/bucket or account/bucket/object format
        if (parts.length >= 2 && parts[1]) {
            var resourceBucket = parts[1];
            var resourceObjectPath = parts.slice(2).join('/');

            if (resourceObjectPath) {
                return ('arn:aws:s3:::' + resourceBucket + '/' +
                        resourceObjectPath);
            } else {
                return ('arn:aws:s3:::' + resourceBucket);
            }
        }
    }

    // Last resort: return wildcard (this should rarely happen)
    return ('*');
}

// Helper function to safely send InvalidSignatureError
// XML error response for S3 requests.
function sendInvalidSignatureError(req, res, next, message) {
    try {
        var authError = new InvalidSignatureError(message);
        // For S3 requests, send XML error response
        if (req.s3Request && req.s3Request.isS3Request) {
            var xmlError = s3Compat.convertErrorToS3(authError,
                                                     req.s3Request, req);
            res.setHeader('Content-Type', 'application/xml');
            res.send(403, xmlError);
        } else {
            res.send(403, authError.message);
        }
    } catch (sendErr) {
        req.log.error(sendErr, 'Failed to send error response');
        res.end();
    }
}

///--- Messages

var TOKEN_ALG = 'aes-128-cbc';
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


///--- Helpers

function rfc3986(str) {
    /* JSSTYLED */
    return (encodeURIComponent(str)
            /* JSSTYLED */
            .replace(/[!'()]/g, escape)
            /* JSSTYLED */
            .replace(/\*/g, '%2A'));
}

function createAuthToken(opts, aes, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.caller, 'opts.caller');
    assert.optionalObject(opts.context, 'opts.context');
    assert.optionalBool(opts.fromjob, 'opts.fromjob');
    assert.object(aes, 'aes');
    assert.string(aes.salt, 'aes.salt');
    assert.string(aes.key, 'aes.key');
    assert.string(aes.iv, 'aes.iv');
    assert.func(cb, 'callback');

    if (aes.key.length > 128 || aes.iv.length > 64) {
        throw new Error('Crypto key or IV too long');
    }
    var cipher = crypto.createCipheriv(TOKEN_ALG,
                                       new Buffer(aes.key, 'hex'),
                                       new Buffer(aes.iv, 'hex'));
    assert.ok(cipher, 'failed to create crypto cipher');

    var caller = opts.caller;
    var context = opts.context;
    var fromjob = opts.fromjob;

    var principal = {
        account: null,
        user: null,
        roles: caller.roles || null
    };

    /*
     * Pick out the context conditions that should be contained in the token.
     * This should include any Manta-defined conditions that are used by Manta
     * itself during authorization, like activeRoles, but shouldn't include any
     * other conditions like date or sourceip, which aren't used by Manta.
     */
    var conditions = {};
    if (context && context.conditions) {
        conditions.activeRoles = context.conditions.activeRoles;
        conditions.activeXAcctRoles = context.conditions.activeXAcctRoles;
    }
    if (opts.fromjob) {
        conditions.fromjob = fromjob;
    }

    if (caller.account) {
        principal.account = {
            uuid: caller.account.uuid
        };
    }

    if (caller.user) {
        principal.user = {
            uuid: caller.user.uuid
        };
    }

    var str = JSON.stringify({
        t: Date.now(),
        p: principal,
        c: conditions,
        v: 2
    });

    // Safe buffer creation for Node.js v0.10.48 compatibility
    if (str.length > 1048576) { // 1MB limit for compression
        return (cb(new Error('String too large for compression (max 1MB)')));
    }
    zlib.gzip(new Buffer(str, 'utf8'), function (err, buf) {
        if (err) {
            cb(err);
            return;
        }

        var token = cipher.update(buf, 'binary', 'base64');
        token += cipher.final('base64');
        cb(null, token);
    });
}


function parseAuthToken(token, aes, cb) {
    assert.string(token, 'token');
    assert.object(aes, 'aes');
    assert.string(aes.salt, 'aes.salt');
    assert.string(aes.key, 'aes.key');
    assert.string(aes.iv, 'aes.iv');
    assert.number(aes.maxAge, 'aes.maxAge');
    assert.func(cb, 'callback');


    // Safe buffer creation for Node.js v0.10.48 compatibility
    if (aes.key.length > 128 || aes.iv.length > 64) {
        return (cb(new Error('Crypto key or IV too long')));
    }
    var decipher = crypto.createDecipheriv(TOKEN_ALG,
                                           new Buffer(aes.key, 'hex'),
                                           new Buffer(aes.iv, 'hex'));
    assert.ok(decipher, 'failed to create crypto cipher');
    var buf;
    try {
        buf = decipher.update(token, 'base64', 'binary');
        buf += decipher.final('binary');
    } catch (e) {
        setImmediate(function () {
            cb(new InvalidAuthTokenError());
        });
        return;
    }

    zlib.gunzip(new Buffer(buf, 'binary'), function (err, str) {
        if (err) {
            cb(new InvalidAuthTokenError());
            return;
        }

        var cracked;
        try {
            cracked = JSON.parse(str) || {};
        } catch (e) {
            cb(new InvalidAuthTokenError());
            return;
        }

        if (cracked.v !== 1 && cracked.v !== 2) {
            cb(new InvalidAuthTokenError('an invalid version'));
            return;
        }

        if ((Date.now() - cracked.t) > aes.maxAge) {
            cb(new InvalidAuthTokenError('expired'));
            return;
        }

        var obj;
        if (cracked.v === 1) {
            obj = {
                caller: {
                    roles: {},
                    account: {
                        uuid: cracked.u,
                        login: cracked.l,
                        groups: cracked.g,
                        approved_for_provisioning: true,
                        isOperator: cracked.g.some(function (e) {
                            return (e === 'operators');
                        })
                    }
                },
                ctime: cracked.t
            };
        } else if (cracked.v === 2) {
            obj = {
                principal: cracked.p,
                conditions: cracked.c,
                ctime: cracked.t
            };
        }

        cb(null, obj);
    });
}




///--- Handlers

function createAuthTokenHandler(req, res, next) {
    var aes = req.config.authToken;
    var caller = req.caller;
    var context = req.authContext;
    var log = req.log;

    var opts = {
        caller: caller,
        context: context,
        fromjob: false
    };

    log.debug(opts, 'createAuthToken: entered');
    createAuthToken(opts, aes, function (err, token) {
        if (err) {
            log.error(err, 'unable to create auth token');
            next(new InternalError());
            return;
        }

        // HAProxy has an 8k limit on header size
        if (Buffer.byteLength(token) > 8192) {
            log.error({token: token}, 'createAuthToken: token too big');
            next(new InternalError());
            return;
        }

        log.debug({token: token}, 'createAuthToken: done');
        res.send(201, {token: token});
        next();
    });
}


function convertS3PresignedToManta(req, res, next) {
    var log = req.log;
    log.debug({queryParams: Object.keys(req.query)},
              'convertS3PresignedToManta: checking query params');

    // Check if this is an S3 presigned URL
    // (only convert if it has S3-specific parameters)
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

            req.s3Request = {
                bucket: pathParts[0],
                object: pathParts.slice(1).join('/'),
                operation: operation,
                isS3Request: true
            };

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
        'signature'].filter(function (k) {
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
    } catch (e) {
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
        Object.keys(req.query).sort(function (a, b) {
            return (a.localeCompare(b));
        }).filter(function (k) {
            return (k.toLowerCase() !== 'signature');
        }).map(function (k) {
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
                headerList.forEach(function (headerName) {
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
            Object.keys(req.query).forEach(function (key) {
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
                                 function (err, result) {
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
    var ok = ['signature', 'token', 'aws4-hmac-sha256'].indexOf(scheme) >= 0;

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


function parseAuthTokenHandler(req, res, next) {
    if ((req.authorization.scheme || '').toLowerCase() !== 'token') {
        setImmediate(next);
        return;
    }

    req.log.debug('using token auth');
    req.log.debug('parseAuthTokenHandler: entered');

    var aes = req.config.authToken;
    var tkn = req.authorization.credentials;
    parseAuthToken(tkn, aes, function (err, token) {
        if (err) {
            req.log.debug(err, 'failed to crack token');
            next(new InvalidAuthTokenError());
            return;
        }

        req.auth = {
            accountid: token.principal.account.uuid,
            token: token
        };

        if (token.principal.user) {
            req.auth.userid = token.principal.user.uuid;
        }

        req.log.debug('parseAuthTokenHandler: done');
        next();
    });
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
    if ((req.authorization.scheme || '').toLowerCase() !== 'aws4-hmac-sha256') {
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

    Object.keys(req.headers).forEach(function (key) {
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

    var urlForVerification = req.url;
    var pathPart = urlForVerification.split('?')[0];
    var queryPart = urlForVerification.split('?')[1];

    // For virtual-hosted-style requests, the bucket name is the first
    // component of the host header.
    var hostHeader = req.headers.host || '';
    var virtualHostBucketName = hostHeader.split('.')[0];

    // For path-style requests, extract bucket name from the path
    var pathStyleBucketName = null;
    var pathSegments = pathPart.split('/').filter(function (segment) {
        return (segment.length > 0);
    });
    if (pathSegments.length >= 1) {
        pathStyleBucketName = pathSegments[0];
    }

    // Get user agent for client-specific logic
    var userAgent = req.headers['user-agent'] || 'none';

    // Determine the actual bucket name based on request style
    var bucketName = null;
    if (virtualHostBucketName !== hostHeader &&
        virtualHostBucketName.length > 0) {
        // Virtual-hosted style: bucket.domain.com
        bucketName = virtualHostBucketName;
        req.log.debug({
            bucket: bucketName,
            style: 'virtual-hosted'
        }, 'S3_AUTH_DEBUG: Detected virtual-hosted bucket name');
    } else if (pathStyleBucketName) {
        // Path-style: domain.com/bucket
        bucketName = pathStyleBucketName;
        req.log.debug({
            bucket: bucketName,
            style: 'path-style'
        }, 'S3_AUTH_DEBUG: Detected path-style bucket name');
    }

    // Determine if this is AWS CLI or related tools that handle paths correctly
    var isAwsCli = userAgent &&
        (userAgent.toLowerCase().includes('aws-cli') ||
         userAgent.toLowerCase().includes('boto3') ||
         userAgent.toLowerCase().includes('aws-sdk') ||
         userAgent.toLowerCase().includes('botocore'));

    // If the URI path is the bucket name, some S3 clients sign the request with
    // a canonical URI ending with /. We must normalize the URL we send to mahi
    // for verification to match what the client signed.
    // AWS CLI does NOT add trailing slash, but other clients like s3cmd do.
    if (bucketName && pathPart === '/' + bucketName) {

        if (!isAwsCli) {
            req.log.debug({
                bucket: bucketName,
                originalPath: pathPart,
                newPath: '/' + bucketName + '/',
                userAgent: userAgent
            }, 'S3_AUTH_DEBUG: Adding trailing slash' +
                          ' for bucket URI SigV4 verification');
            pathPart = '/' + bucketName + '/';
        } else {
            req.log.debug({
                bucket: bucketName,
                originalPath: pathPart,
                userAgent: userAgent
            }, 'S3_AUTH_DEBUG: AWS CLI detected -' +
                          ' NOT adding trailing slash for bucket URI');
        }
    }

    // MANTA-331 removes trailing slashes, here minio requires them
    // to sign the request if pathPart is just a bucket request then add /
    // Most S3 clients need trailing slash appended to bucket paths for
    // proper SigV4 signature validation. This is needed because Manta strips
    // trailing slashes (manta 331) but clients calculate signatures with them.
    // AWS CLI is excluded as it handles paths correctly.
    // For example /bucket needs to be /bucket/ for signature validation,
    // while /bucket/file.txt doesn't need patching.
    var regex = /\/[^/]+\.(?:$|\/)|\/[^/]+\/[^/]+/;
    // Exclude directory creation requests - they are handled at URL
    // reconstruction
    var isDirectoryCreation = req.headers['content-type'] ===
        'application/x-directory';

    var shouldAddSlash = !isAwsCli &&
        !regex.test(pathPart) &&
        pathPart !== '/' &&
        !pathPart.endsWith('/') &&
        !isDirectoryCreation;

    req.log.debug({
        userAgent: userAgent,
        pathPart: pathPart,
        regexTest: regex.test(pathPart),
        shouldAddSlash: shouldAddSlash,
        isDirectoryCreation: isDirectoryCreation,
        originalPath: pathPart
    }, 'S3_AUTH_DEBUG: Trailing slash logic evaluation');

    if (shouldAddSlash) {
        req.log.debug({
            originalPath: pathPart,
            newPath: pathPart + '/'
        }, 'S3_AUTH_DEBUG: Adding trailing slash via regex fallback logic');
        pathPart += '/';
    }

    // Fix double-encoding issue in query parameters before sending to mahi
    // AWS CLI sends delimiter=%2F but when we URL-encode the whole URL for
    // mahi, it becomes delimiter=%252F which breaks signature verification
    // However, continuation-token parameters must preserve their exact
    // encoding as sent by the client to match the signature.

    if (queryPart) {
        try {
            // Check if this contains parameters that need preserved encoding
            // for signature match
            // Apply directory creation check when query parameters are present
            var finalPathPart = pathPart;
            if (isDirectoryCreation && !pathPart.endsWith('/')) {
                finalPathPart = pathPart + '/';
                req.log.debug({
                    originalPath: pathPart,
                    modifiedPath: finalPathPart
                }, 'S3_AUTH_DEBUG: Adding trailing slash for directory ' +
                   'creation with query params');
            }

            if (queryPart.includes('continuation-token=') ||
                queryPart.includes('marker=')) {
                // For continuation-token and marker requests, don't decode to
                // preserve signature match
                urlForVerification = finalPathPart + '?' + queryPart;
                req.log.debug({
                    originalUrl: req.url,
                    finalUrl: urlForVerification,
                    reason: 'Continuation token or marker present'  +
                        ' - preserving original encoding'
                }, 'S3_AUTH_DEBUG: Preserving query encoding' +
                   ' for pagination parameters');
            } else {
                // For other requests, decode query parameters once to prevent
                // double-encoding
                var decodedQuery = decodeURIComponent(queryPart);
                urlForVerification = finalPathPart + '?' + decodedQuery;
                req.log.debug({
                    originalUrl: req.url,
                    finalUrl: urlForVerification
                }, 'S3_AUTH_DEBUG:'+
                ' Fixed query parameter encoding for SigV4 verification');
            }
        } catch (e) {
            // If decoding fails, keep original URL but still apply directory
            // creation logic
            var errorFinalPathPart = pathPart;
            if (isDirectoryCreation && !pathPart.endsWith('/')) {
                errorFinalPathPart = pathPart + '/';
            }
            urlForVerification = errorFinalPathPart + '?' + queryPart;
            req.log.debug({
                originalUrl: req.url,
                error: e.message,
                reason: 'Query decoding failed, using original query part'
            }, 'S3_AUTH_DEBUG: Using original URL for SigV4 verification');
        }
    } else {
        // Apply directory creation check when setting final urlForVerification
        if (isDirectoryCreation && !pathPart.endsWith('/')) {
            // For directory creation requests, ensure trailing slash for
            // signature verification
            urlForVerification = pathPart + '/';
            req.log.debug({
                originalPath: pathPart,
                finalUrl: urlForVerification,
                reason: 'Directory creation request - adding trailing slash'
            }, 'S3_AUTH_DEBUG: Modified URL' +
               ' for directory creation signature verification');
        } else {
            urlForVerification = pathPart;
            req.log.debug({
                url: urlForVerification,
                reason: 'No query parameters'
            }, 'S3_AUTH_DEBUG: Using original URL for SigV4 verification');
        }
    }

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
    var skippedHeaders = originalHeaderKeys.filter(function (key) {
        return (skipHeaders.indexOf(key.toLowerCase()) !== -1);
    });

    req.log.debug({
        method: requestForVerification.method,
        url: requestForVerification.url,
        originalRequestMethod: req.method,
        originalRequestUrl: req.url,
        pathPart: pathPart,
        queryPart: queryPart,
        bucketName: bucketName,
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
    // looks valid
    var isTemporaryCredential = sessionToken &&
        typeof (sessionToken) === 'string' &&
                               sessionToken.trim().length > 10;
                               // AWS session tokens are much longer

    if (isTemporaryCredential) {
        // For temporary credentials, use custom request to
        // include session token
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

        req.mahi.verifySigV4(customReq, function (err, result) {
        // Debug: Log raw mahi response
        if (result && isTemporaryCredential) {
            req.log.error({
                rawResult: result,
                resultKeys: Object.keys(result),
                assumedRole: result.assumedRole,
                isTemporaryCredential: result.isTemporaryCredential,
                isTemporary: result.isTemporary,
                credentialType: result.credentialType,
                principalUuid: result.principalUuid
            }, 'IAM_DEBUG: Raw mahi response for temporary credentials');
        }

        if (err) {
            req.log.debug({
                error: err.message || err,
                restCode: err.restCode,
                errorName: err.name,
                statusCode: err.statusCode
            }, 'S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
            ' - SigV4 verification failed');

            // Map node-mahi errors to appropriate HTTP errors
            switch (err.restCode || err.name) {
            case 'InvalidSignature':
            case 'InvalidSignatureError':
            case 'SignatureDoesNotMatch':
                sendInvalidSignatureError(req, res, next, 'Invalid Signature');
                break;
            case 'AccessKeyNotFound':
                sendInvalidSignatureError(req, res, next, 'Invalid access key');
                break;
            case 'RequestTimeTooSkewed':
                sendInvalidSignatureError(req, res, next,
                    'Request timestamp too skewed');
                break;
            default:
                sendInvalidSignatureError(req, res, next,
                   'Authentication failed: ' +
                                          (typeof (err.message) === 'string' ?
                    err.message : 'Unknown error'));
                break;
            }
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
            req.log.info('IAM_DEBUG: TempCred AccessKey=' +
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
            // Add role information for temporary credentials
            assumedRole: result.assumedRole || null,
            isTemporaryCredential: isTemporaryCredential,
            principalUuid: result.principalUuid || result.userUuid
        };

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

        req.mahi.verifySigV4(requestForVerification, function (err, result) {
            if (err) {
                req.log.debug({
                    error: err.message || err,
                    restCode: err.restCode,
                    errorName: err.name,
                    statusCode: err.statusCode
                }, 'S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
                ' - SigV4 verification failed');

                // Map node-mahi errors to appropriate HTTP errors
                switch (err.restCode || err.name) {
                case 'InvalidSignature':
                case 'InvalidSignatureError':
                case 'SignatureDoesNotMatch':
                    sendInvalidSignatureError(req, res, next,
                                              'Invalid Signature');
                    break;
                case 'AccessKeyNotFound':
                    sendInvalidSignatureError(req, res, next,
                                              'Invalid access key');
                    break;
                case 'RequestTimeTooSkewed':
                    sendInvalidSignatureError(req, res, next,
                        'Request timestamp too skewed');
                    break;
                default:
                    sendInvalidSignatureError(req, res, next,
                       'Authentication failed: ' +
                                              (typeof (err.message) ===
                                               'string' ?
                        err.message : 'Unknown error'));
                    break;
                }
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
                }
            };

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


function parseKeyId(req, res, next) {
    // Skip parsing for S3 presigned URLs - they use different key format
    if (req._s3PresignedAuthComplete) {
        req.log.debug('parseKeyId: skipping' +
                      ' - S3 presigned URL uses different key format');
        next();
        return;
    }

    if (!req.auth.callerKey) {
        next();
        return;
    }

    req.log.debug('parseKeyId: entered');
    var k;
    try {
        k = req.auth.callerKey.split('/');
    } catch (e) {
        next(new InvalidKeyIdError());
        return;
    }

    if (!k) {
        next(new InvalidKeyIdError());
        return;
    }

    if (k.length === 4) {
        // account key. like '/poseidon/keys/<keyId>'
        if (k[2] !== 'keys') {
            next(new InvalidKeyIdError());
            return;
        }
        req.auth.keyId = decodeURIComponent(k[3]);
        req.auth.account = decodeURIComponent(k[1]);
    } else if (k.length === 5) {
        // user key. like '/poseidon/fred/keys/<keyId>'
        if (k[3] !== 'keys') {
            next(new InvalidKeyIdError());
            return;
        }
        req.auth.keyId = decodeURIComponent(k[4]);
        req.auth.account = decodeURIComponent(k[1]);
        req.auth.user = decodeURIComponent(k[2]);
        if (req.auth.user === '') {
            next(new InvalidKeyIdError());
            return;
        }
    } else {
        next(new InvalidKeyIdError());
        return;
    }

    if (req.auth.keyId === '' || req.auth.account === '') {
        next(new InvalidKeyIdError());
        return;
    }

    req.log.debug('parseKeyId: done');
    next();
}


function loadCaller(req, res, next) {
    // Skip loadCaller processing for public reader anonymous access
    // This means that the object requested has the 'public-read' role
    // and anonymous access is granted, hence we are skipping this call.
    if (req.isAnonymousAccess && req.caller && req.caller.publicReader) {
        req.log.debug(
            'loadCaller: skipping for public reader anonymous access');
        next();
        return;
    }

    var account = req.auth.account;
    var accountid = req.auth.accountid;
    var user = req.auth.user;
    var userid = req.auth.userid;
    var accessKeyId = req.auth.accessKeyId; // support for access key lookup

    req.log.debug('loadCaller: entered');

        // Helper function to parse role ARN and extract role name
    function parseRoleArn(roleArn) {
        if (!roleArn || typeof (roleArn) !== 'string') {
            return (null);
        }
        // Expected format: arn:aws:iam::account:role/rolename
        var arnParts = roleArn.split(':');
        if (arnParts.length < 6 || arnParts[2] !== 'iam') {
            return (null);
        }
        var resourcePart = arnParts[5];
        if (resourcePart.indexOf('role/') !== 0) {
            return (null);
        }
        return ({
            accountId: arnParts[4],
            roleName: resourcePart.substring(5)
        });
    }

    // Helper function to load assumed role permissions
    function loadAssumedRoleInfo(roleArn, callback) {
        req.log.error({
            roleArn: roleArn,
            roleArnType: typeof (roleArn)
        }, 'IAM_DEBUG_ALWAYS: loadAssumedRole called');

        var roleInfo = parseRoleArn(roleArn);
        req.log.error({
            roleInfo: roleInfo,
            hasRoleInfo: !!roleInfo
        }, 'IAM_DEBUG_ALWAYS: parseRoleArn result');

        if (!roleInfo) {
            return (callback(new Error('Invalid role ARN format')));
        }

        var iamClient = req.iamClient;
        if (!iamClient) {
            return (callback(new Error('IAM client not available')));
        }

        iamClient.getRole({
            roleName: roleInfo.roleName,
            caller: {
                account: { uuid: req.caller.account.uuid }
            }
        }, function (roleErr, roleData) {
            if (roleErr) {
                return (callback(roleErr));
            }

            // Now load permission policies using AWS-compliant operations
            iamClient.listRolePolicies({
                roleName: roleInfo.roleName,
                caller: {
                    account: { uuid: req.caller.account.uuid }
                }
            }, function (listErr, listResponse) {
                if (listErr) {
                    req.log.warn({
                        err: listErr,
                        roleName: roleInfo.roleName
                    }, 'Failed to list role policies,' +
                                 ' continuing without policies');
                    // Continue without policies rather than failing completely
                    roleData.PermissionPolicies = [];
                    return (callback(null, roleData));
                }

                var policyNames = listResponse &&
                    listResponse.PolicyNames ? listResponse.PolicyNames : [];
                if (policyNames.length === 0) {
                    // No policies attached
                    roleData.PermissionPolicies = [];
                    return (callback(null, roleData));
                }

                // Load each policy document
                var permissionPolicies = [];
                var pendingPolicies = policyNames.length;

                policyNames.forEach(function (policyName) {
                    iamClient.getRolePolicy({
                        roleName: roleInfo.roleName,
                        policyName: policyName,
                        caller: {
                            account: { uuid: req.caller.account.uuid }
                        }
                    }, function (getPolicyErr, policyData) {
                        if (getPolicyErr) {
                            req.log.warn({
                                err: getPolicyErr,
                                roleName: roleInfo.roleName,
                                policyName: policyName
                            }, 'Failed to get role policy, skipping');
                        } else {
                            permissionPolicies.push({
                                policyName: policyName,
                                policyDocument: policyData.PolicyDocument
                            });
                        }

                        pendingPolicies--;
                        if (pendingPolicies === 0) {
                            // All policies loaded
                            roleData.PermissionPolicies = permissionPolicies;
                            return (callback(null, roleData));
                        }
                    });
                });
            });
        });
    }

    function gotCaller(err, info) {
        if (err) {
            switch (err.restCode || err.name) {
            case 'AccountDoesNotExist':
                next(new AccountDoesNotExistError(account));
                break;
            case 'UserDoesNotExist':
                next(new UserDoesNotExistError(account, user));
                break;

            /*
             * Technically these should never happen because uuids are only
             * used if we're using token auth, and tokens are generated by
             * muskie and we never delete users. Including them anyway in case
             * we ever do support deleting users.
             */
            case 'UserIdDoesNotExist':
                next(new UserDoesNotExistError(null, userid));
                break;
            case 'AccountIdDoesNotExist':
                next(new AccountDoesNotExistError(accountid));
                break;
            // Add handling for access key errors
            case 'AccessKeyNotFound':
                next(new AccountDoesNotExistError(accessKeyId));
                break;

            default:
                next(new InternalError(err));
                break;
            }
            return;
        }

        if (!info.account.approved_for_provisioning &&
            !info.account.isOperator) {
            next(new AccountBlockedError(info.account.login));
            return;
        }

        req.caller = info;

        // Debug: Log authentication context
        req.log.info({
            isTemporaryCredential: req.auth.isTemporaryCredential,
            hasAssumedRole: !!req.auth.assumedRole,
            authKeys: Object.keys(req.auth || {}),
            callerType: info.account ? 'account' : 'user'
        }, 'IAM_DEBUG: gotCaller - authentication context');

        // For subusers, ensure roles and defaultRoles are properly
        // structured
        if (req.caller.user && req.caller.type === 'user') {
            // Copy roles and defaultRoles from the top-level response
            // to user object
            if (req.caller.roles && !req.caller.user.roles) {
                req.caller.user.roles = req.caller.roles;
            }
            if (req.caller.defaultRoles && !req.caller.user.defaultRoles) {
                req.caller.user.defaultRoles = req.caller.defaultRoles;
            }
        }

        // Handle assumed role authorization for temporary credentials
        req.log.error({
            conditionCheck1: !!req.auth.isTemporaryCredential,
            conditionCheck2: !!req.auth.assumedRole,
            assumedRoleType: typeof (req.auth.assumedRole),
            assumedRoleValue: req.auth.assumedRole
        }, 'IAM_DEBUG_ALWAYS: Checking assumed role conditions');

        if (req.auth.isTemporaryCredential && req.auth.assumedRole) {
            req.log.error({
                assumedRole: req.auth.assumedRole,
                isTemporary: req.auth.isTemporaryCredential,
                hasIamClient: !!req.iamClient,
                iamClientType: req.iamClient ? typeof (req.iamClient) : 'null'
            }, 'IAM_DEBUG_ALWAYS: ' +
               'Loading assumed role permissions for temporary credential');

            // Fix: Handle assumedRole as string (ARN) or object
            // with .arn property
            var roleArn = (typeof (req.auth.assumedRole) === 'string') ?
                req.auth.assumedRole : req.auth.assumedRole.arn;

            loadAssumedRoleInfo(roleArn,
                function (roleErr, roleData) {
                req.log.error({
                    roleErr: roleErr,
                    hasRoleData: !!roleData,
                    roleDataKeys: roleData ? Object.keys(roleData) : null,
                    assumedRoleArn: req.auth.assumedRole ?
                        req.auth.assumedRole.arn : null
                }, 'IAM_DEBUG_ALWAYS: loadAssumedRole callback result');

                if (roleErr) {
                    req.log.error({
                        err: roleErr,
                        assumedRole: req.auth.assumedRole
                    }, 'Failed to load assumed role permissions');
                    // Continue with normal authorization but log the issue
                    return (continueWithNormalAuth());
                }

                req.log.info({
                    roleName: roleData.Role ? roleData.Role.RoleName :
                        roleData.RoleName,
                    hasRoleObject: !!roleData.Role,
                    hasPermissionPoliciesOnRole:
                    !!(roleData.Role &&
                       roleData.Role.PermissionPolicies),
                    hasPermissionPoliciesOnRoot: !!roleData.PermissionPolicies,
                    permissionPoliciesCountOnRole:
                    (roleData.Role && roleData.Role.PermissionPolicies) ?
                        roleData.Role.PermissionPolicies.length : 0,
                    permissionPoliciesCountOnRoot: roleData.PermissionPolicies ?
                        roleData.PermissionPolicies.length : 0,
                    roleDataKeys: Object.keys(roleData),
                    roleObjectKeys: roleData.Role ?
                        Object.keys(roleData.Role) : []
                }, 'IAM_DEBUG: Successfully loaded assumed role data');

                // Store role data in caller context
                req.caller.assumedRole = {
                    arn: roleArn,
                    name: roleData.Role ? roleData.Role.RoleName :
                        roleData.RoleName,
                    permissionPolicies:
                        (roleData.Role && roleData.Role.PermissionPolicies) ?
                        roleData.Role.PermissionPolicies :
                        (roleData.PermissionPolicies || []),
                    originalPrincipal: req.auth.principalUuid
                };

                // Debug: Log what actually got extracted and stored
                req.log.debug({
                    extractedRoleName: req.caller.assumedRole.name,
                    extractedPermissionPoliciesCount:
                    req.caller.assumedRole.permissionPolicies.length,
                    extractedPermissionPolicies:
                    req.caller.assumedRole.permissionPolicies,
                    roleArn: req.caller.assumedRole.arn
                }, 'IAM_DEBUG: Successfully' +
                              ' stored assumed role data in req.caller');

                    return (continueWithNormalAuth());
            });
        } else {
            // Clear any assumed role data from previous
            // requests when not using temporary credentials
            if (req.caller.assumedRole) {
                req.log.debug({
                    clearedAssumedRole: req.caller.assumedRole.name,
                    isTemporaryCredential: req.auth.isTemporaryCredential
                }, 'IAM_DEBUG: Clearing assumed role' +
                              ' data for non-temporary credential request');
                req.caller.assumedRole = null;
            }
            return (continueWithNormalAuth());
        }

        function continueWithNormalAuth() {
            req.log.debug('IAM_DEBUG: continueWithNormalAuth called');
            if (req.isS3Request) {
                req.log.debug({
                    callerType: info.account ? 'account' : 'user',
                    accountLogin: info.account ? info.account.login : 'unknown',
                    accountUuid: info.account ? info.account.uuid : 'unknown',
                    isProvisioned: info.account ?
                    info.account.approved_for_provisioning : false,
                    hasAssumedRole: !!req.caller.assumedRole
                }, 'S3_AUTH_DEBUG: AUTHENTICATION COMPLETE'+
                ' - Caller loaded successfully');
            }

            var sanitizedCaller = {
                uuid: req.caller.account ? req.caller.account.uuid : undefined,
                login: req.caller.account ?
                    req.caller.account.login : undefined,
                type: req.caller.account ? req.caller.account.type : undefined,
                isOperator: req.caller.account ?
                    req.caller.account.isOperator : undefined,
                roles: req.caller.roles ? Object.keys(req.caller.roles) : [],
                assumedRole: req.caller.assumedRole ?
                    req.caller.assumedRole.name : undefined
            };
            req.log.debug({caller: sanitizedCaller}, 'loadCaller: done');
            next();
        }
    }

    // S3 presigned URL authentication: Get user info by access key
    if (accessKeyId && req.auth.method === 'presigned-s3') {
        req.log.debug({
            accessKeyId: accessKeyId,
            method: 'presigned-s3'
        }, 'S3_PRESIGNED_DEBUG: Loading caller via access key lookup');

        req.mahi.getUserByAccessKey(accessKeyId, function (err, data) {
            if (err) {
                req.log.debug({
                    error: err.message || err,
                    accessKeyId: accessKeyId
                }, 'S3_PRESIGNED_DEBUG: AUTHENTICATION FAILED' +
                              ' - Access key lookup failed');
            } else {
                req.log.debug({
                    accessKeyId: accessKeyId,
                    userUuid: data ? data.uuid : 'unknown',
                    userLogin: data ? data.login : 'unknown'
                }, 'S3_PRESIGNED_DEBUG: AUTHENTICATION SUCCESS' +
                              ' - Access key lookup successful');
            }
            gotCaller(err, data);
        });
    } else if (accessKeyId && req.auth.method === 'sigv4') {
        req.log.debug({
            accessKeyId: accessKeyId,
            userUuid: req.auth.accountid,
            method: 'sigv4'
        }, 'S3_AUTH_DEBUG:'+
        ' Loading caller via userUuid from SigV4 verification');

        // Try getAccountById first
        // If it fails, fallback to getUserById for subusers
        req.mahi.getAccountById(req.auth.accountid, function (err, data) {
            if (err) {
                req.log.debug({
                    userUuid: req.auth.accountid,
                    error: err.message || err,
                    action: 'Trying getUserById as fallback'
                }, 'S3_AUTH_DEBUG: getAccountById failed, trying user lookup');

                // Fallback to getUserById for subusers
                req.mahi.getUserById(req.auth.accountid,
                                     function (err2, data2) {
                    if (err2) {
                        req.log.debug({
                            error: err2.message || err2,
                            userUuid: req.auth.accountid,
                            accessKeyId: accessKeyId,
                            originalError: err.message || err
                        }, 'S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
                        ' - Both account and user lookup failed');
                        // Return the original account error since that was
                        // tried first
                        gotCaller(err, data);
                    } else {
                        req.log.debug({
                            accessKeyId: accessKeyId,
                            userUuid: data2 ? data2.uuid : 'unknown',
                            userLogin: data2 ? data2.login : 'unknown',
                            userType: 'sub-user'
                        }, 'S3_AUTH_DEBUG: AUTHENTICATION SUCCESS'+
                        ' - User lookup successful (fallback)');
                        gotCaller(null, data2);
                    }
                });
            } else {
                req.log.debug({
                    accessKeyId: accessKeyId,
                    userUuid: data ? data.uuid : 'unknown',
                    userLogin: data ? data.login : 'unknown',
                    userType: 'account'
                }, 'S3_AUTH_DEBUG: AUTHENTICATION SUCCESS'+
                ' - Account lookup successful');
                gotCaller(null, data);
            }
        });
    } else if (user && account) {
        req.mahi.getUser(user, account, false, gotCaller);
    } else if (userid) {
        req.mahi.getUserById(userid, gotCaller);
    } else if (account) {
        req.mahi.getAccount(account, gotCaller);
    } else if (accountid) {
        req.mahi.getAccountById(accountid, gotCaller);
    } else {
        req.caller = {
            anonymous: true,
            user: {},
            roles: {},
            account: {}
        };

        var sanitizedCallerAnon = {
            anonymous: req.caller.anonymous,
            uuid: req.caller.account ? req.caller.account.uuid : undefined,
            login: req.caller.account ? req.caller.account.login : undefined,
            type: req.caller.account ? req.caller.account.type : undefined,
            isOperator: req.caller.account ? req.caller.account.isOperator :
                undefined,
            roles: req.caller.roles ? Object.keys(req.caller.roles) : []
        };
        req.log.debug({caller: sanitizedCallerAnon}, 'loadCaller: done');
        setImmediate(next);
        return;
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


function parseHttpAuthToken(req, res, next) {
    // Skip HTTP auth token processing for SigV4 requests
    // HTTP auth tokens require SSH signatures which are incompatible with SigV4
    if (req.auth.method === 'sigv4') {
        req.log.debug('parseHttpAuthToken: skipping for SigV4 request');
        setImmediate(next);
        return;
    }

    if (!req.header('x-auth-token')) {
        next();
        return;
    }

    var log = req.log;
    var token;

    try {
        token = JSON.parse(req.header('x-auth-token'));
    } catch (e) {
        log.warn(e, 'invalid auth token (JSON parse)');
        next(new InvalidHttpAuthTokenError('malformed auth token'));
        return;
    }

    log.debug('parseHttpAuthToken: calling keyAPI');
    req.keyapi.detoken(token, function (tokerr, tokobj) {

        function gotInfo(err, info) {
            if (err) {
                switch (err.restCode) {
                case 'AccountDoesNotExist':
                    next(new AccountDoesNotExistError(req.auth.account));
                    return;
                case 'UserDoesNotExist':
                    next(new UserDoesNotExistError(req.auth.account,
                            req.auth.user));
                    return;
                default:
                    next(new InternalError(err));
                    return;
                }
            }

            req.caller = info;
            log.debug(req.auth.account, 'parseHttpAuthToken: done');
            next();
        }

        if (tokerr || !tokobj) {
            log.warn(tokerr, 'invalid auth token (detoken)');
            next(new InvalidHttpAuthTokenError('malformed auth token'));
        } else if (tokobj.expires &&
                   (Date.now() > new Date(tokobj.expires).getTime())) {
            next(new InvalidHttpAuthTokenError('auth token expired'));
        } else if (!req.authorization || !req.authorization.signature ||
                   !req.authorization.signature.keyId) {
            next(new AuthorizationRequiredError('signature is required'));
        } else if (tokobj.devkeyId !== req.authorization.signature.keyId) {
            next(new InvalidHttpAuthTokenError('not authorized for token'));
        } else {
            req.auth.delegate = req.auth.account;
            req.auth.account = tokobj.account.login;
            if (tokobj.subuser) {
                req.auth.user = tokobj.subuser.login;
                req.mahi.getUser(req.auth.user, req.auth.account, gotInfo);
            } else {
                req.mahi.getAccount(req.auth.account, gotInfo);
            }
        }
    });
}


function loadOwner(req, res, next) {
    var p = req.path();
    loadOwnerFromPath(req, p, next);
}


/*
 * Extract the owner of a resource based on the input path, verify that
 * the account exists, and set the `owner` field on the request object
 * to the object returned from Mahi.
 */
function loadOwnerFromPath(req, p, next) {
    req.log.debug('loadOwner: entered');

    var account;

    // For S3 requests, use the authenticated user's account instead of
    // extracting from path
    // S3 paths like '/mybucket' don't contain account info - bucket is
    // owned by authenticated user
    if (req.isS3Request && req.caller &&
    req.caller.account && req.caller.account.login) {
        account = req.caller.account.login;
        req.log.debug({
            s3Request: true,
            extractedAccount: account,
            originalPath: p
        }, 'loadOwner: using authenticated user account for S3 request');
    } else {
        // Traditional Manta path: /account/buckets/bucket -> extract account
        try {
            account = decodeURIComponent(p.split('/', 2).pop());
        } catch (e) {
            next(new InvalidPathError(p));
            return;
        }
    }

    req.auth.owner = account;
    var user = common.ANONYMOUS_USER;
    var fallback = true;

    req.mahi.getUser(user, account, fallback, function (err, owner) {
        if (err) {
            switch (err.restCode || err.name) {
            case 'AccountDoesNotExist':
                next(new AccountDoesNotExistError(account));
                return;
            default:
                next(new InternalError(err));
                return;
            }
        }

        req.owner = owner;

        // Handle public-reader anonymous access AND potential anonymous access
        if ((req.isAnonymousAccess && req.caller && req.caller.publicReader) ||
            req.potentialAnonymousAccess) {
            req.log.debug({
                isAnonymousAccess: req.isAnonymousAccess,
                potentialAnonymousAccess: !!req.potentialAnonymousAccess,
                publicReader: req.caller && req.caller.publicReader,
                callerRoles: req.caller ? req.caller.roles : 'no caller'
            }, 'Allowing public-reader/potential' +
                          'anonymous access in loadOwner');
            next();
            return;
        } else if (req.caller.anonymous && !owner.user) {
            next(new AuthorizationError(common.ANONYMOUS_USER, p,
                'owner ' + account + ' has no anonymous user'));
            return;
        } else if (req.caller.anonymous) {
            req.log.debug('loadOwner: using owner\'s anonymous user');
            req.caller.account = owner.account;
            req.caller.user = owner.user;
            req.caller.roles = owner.roles;
        }

        if (!owner.account.approved_for_provisioning &&
            !owner.account.isOperator &&
            (req.caller.user || !req.caller.account.isOperator)) {

            next(new AccountBlockedError(account));
            return;
        }

        req.log.debug('loadOwner: done');
        next();
    });
}

/* Helper for makeGlobalReaderRole(). Makes a 'CAN action *' aperture rule. */
function makeStarRule(action) {
    var exact = {};
    exact[action] = true;
    return ([
        'CAN ' + action + ' *',
        {
            effect: true,
            actions: { exact: exact, regex: [] },
            conditions: [],
            resources: 1
        }
    ]);
}

/*
 * Load and convert an assumed IAM role to Manta role format
 */
function loadAssumedRole(req, res, next) {
    var assumedRoleData = req.auth.assumedRole;
    var roleArn = (typeof (assumedRoleData) === 'string') ?
        assumedRoleData : assumedRoleData.arn;
    var log = req.log;

    // Parse role name from ARN (multi-cloud support)
    var roleName = null;
    // Support arn:aws:iam::, arn:manta:iam::, arn:triton:iam::
    if (roleArn && (roleArn.indexOf('arn:aws:iam::') === 0 ||
                    roleArn.indexOf('arn:manta:iam::') === 0 ||
                    roleArn.indexOf('arn:triton:iam::') === 0)) {
        var arnParts = roleArn.split(':');
        if (arnParts.length >= 6) {
            roleName = arnParts[5].replace('role/', '');
        }
    }

    if (!roleName) {
        log.error({roleArn: roleArn}, 'AUTH_DEBUG: Invalid role ARN format');
        return (next(new Error('Invalid role ARN')));
    }

    log.debug({
        roleArn: roleArn,
        roleName: roleName,
        callerUuid: req.caller.account.uuid
    }, 'AUTH_DEBUG: Loading assumed IAM role');

    // Create IAM client to fetch role details
    var IAMClient = require('./iam-client');
    var iamClient = new IAMClient({
        url: req.config ?
            req.config.auth.url : 'http://authcache.coal.joyent.us',
        log: log,
        connectTimeout: 1000,
        requestTimeout: 10000
    });

    // Get the IAM role details
    iamClient.getRole({
        roleName: roleName,
        caller: req.caller
    }, function (err, roleData) {
        if (err) {
            log.debug({
                err: err,
                roleName: roleName,
                roleArn: roleArn
            }, 'AUTH_DEBUG:' +
               ' Failed to load assumed role (role may not exist yet)');

            // For missing roles during tests, just continue without the role
            // This handles the case where tests assume roles that
            // don't exist yet
            return (next());
        }

        log.debug({
            roleName: roleName,
            roleData: roleData
        }, 'AUTH_DEBUG: Loaded IAM role, converting to Manta role');

        // Convert IAM role to Manta role format
        var mantaRole = convertIAMRoleToMantaRole(roleData.Role,
                                                  req.caller.account.uuid);

        // Add the converted role to the caller's available roles
        req.caller.roles = req.caller.roles || {};
        req.caller.roles[mantaRole.uuid] = mantaRole;

        // Set the active roles to only include this assumed role UUID
        req.activeRoles = [mantaRole.uuid];

        log.info({
            roleName: roleName,
            roleArn: roleArn,
            mantaRoleName: mantaRole.name,
            mantaRoleUuid: mantaRole.uuid,
            policies: mantaRole.policies
        }, 'AUTH_DEBUG: Successfully loaded and converted assumed role');

        next();
    });
}

/*
 * Convert IAM role to Manta role format
 */
function convertIAMRoleToMantaRole(iamRole, accountUuid) {
    // Extract permission policies from the IAM role (NOT trust policies)
    var policies = [];

    // Use permission policies attached to the role via PutRolePolicy
    if (iamRole.PermissionPolicies &&
        Array.isArray(iamRole.PermissionPolicies)) {
        // Each permission policy should have been converted to a Manta policy
        iamRole.PermissionPolicies.forEach(function (permissionPolicy) {
            if (permissionPolicy.mantaPolicyName) {
                policies.push(permissionPolicy.mantaPolicyName);
            }
        });
    }

    // If no permission policies, the role has no
    // permissions (principle of least privilege)
    // This is correct - roles without explicit permissions should deny access
    // No fallback policies are created to ensure security

    var mantaRole = {
        name: iamRole.RoleName,
        uuid: iamRole.RoleId,
        account: accountUuid,
        type: 'role',
        policies: policies,
        members: [],
        default_members: []
    };

    return (mantaRole);
}

/*
 * Generate a fake role that provides global read-only access. Used to
 * implement the special 'readers' group in getActiveRoles().
 */
function makeGlobalReaderRole(acctuuid) {
    return ({
        type: 'role',
        /*
         * This uuid and name are arbitrary and fixed -- if they collide with a
         * role added by an actual user, things will probably not work. Don't
         * do that.
         */
        uuid: '76b9ad78-5351-45a3-89f3-b6b48482ed65',
        name: '_global_readers',
        account: acctuuid,
        /*
         * If we add any new actions that are "read-only", they need to be
         * listed here.
         */
        rules: [
            'getobject', 'getdirectory', 'listjobs', 'getjob'
        ].map(makeStarRule)
    });
}

/*
 * Determine the active roles for the request.
 * If the request used token auth, roles from the token override any other
 * requested roles (from headers, presigned URL). The token is created by
 * muskie so the roles in the token have already been verified.
 * Then, check the roles from the URL or headers, if present (with ones from the
 * URL taking precedence).
 */
function getActiveRoles(req, res, next) {
    if (req.auth.token && req.auth.token.conditions) {
        var conds = req.auth.token.conditions;
        req.activeRoles = (conds.activeRoles || []).concat(
            conds.activeXAcctRoles || []);
        setImmediate(next);
        return;
    }

    // Handle temporary credentials with assumed roles (STS)
    if (req.auth && req.auth.isTemporaryCredential && req.auth.assumedRole) {
        req.log.debug({
            assumedRole: req.auth.assumedRole,
            principalUuid: req.auth.principalUuid,
            accessKeyId: req.auth.accessKeyId
        }, 'AUTH_DEBUG: Handling assumed role for temporary credentials');

        // Load the IAM role and convert to Manta role
        return (loadAssumedRole(req, res, next));
    }

    var requestedRoles;

    if (req.auth && typeof (req.auth.role) === 'string') { // from URL
        requestedRoles = req.auth.role;
    } else {
        requestedRoles = req.headers['role'];
    }

    var caller = req.caller;
    var owner = req.owner;

    var isRoleOper = false, isGlobalReader = false;
    if (caller.account.groups) {
        if (caller.account.groups.indexOf('role-operators') !== -1) {
            isRoleOper = true;
        }
        if (caller.account.groups.indexOf('readers') !== -1) {
            isGlobalReader = true;
        }
    }

    /*
     * Check if we need to do per-request req.caller, either for role-operator
     * or global read-only.
     */
    if (isRoleOper || isGlobalReader) {
        /*
         * The req.caller object is cached and potentially shared between
         * multiple requests. We're either going to alter the roles or the
         * isOperator flag on req.caller.account on a per-request basis, so we
         * need a per-request copy of req.caller, req.caller.account and
         * req.caller.roles.
         *
         * We can keep sharing all the other child objects of req.caller other
         * than req.caller.account and req.caller.roles (i.e. we don't have to
         * do a full deep copy), because we're not changing those.
         */
        var newCaller = {};
        Object.keys(caller).forEach(function (k) {
            newCaller[k] = caller[k];
        });
        var newAccount = {};
        Object.keys(caller.account).forEach(function (k) {
            newAccount[k] = caller.account[k];
        });
        var newRoles = {};
        Object.keys(caller.roles).forEach(function (k) {
            newRoles[k] = caller.roles[k];
        });
        newCaller.account = newAccount;
        newCaller.roles = newRoles;
        req.caller = newCaller;
        caller = newCaller;
    }

    /*
     * Handle the special _operator role if the user is a member of the
     * "role-operators" group (this overrides the regular isOperator
     * status, if present).
     */
    if (isRoleOper) {
        /*
         * Since they're in role-operators, make them always non-operator
         * unless the Role header is provided.
         */
        caller.account.isOperator = false;

        /*
         * We treat a Role header value of "_operator" basically as a magic
         * value. If we have it, we skip all further role processing (since
         * we're just going to authorize this request using our operator
         * rights anyway).
         */
        if (requestedRoles === '_operator') {
            caller.account.isOperator = true;
            setImmediate(next);
            return;
        }
    }

    /*
     * Handle global read-only access (membership in the 'readers' group) by
     * generating a 'fake' role here with a well-known UUID.
     */
    var readerRole;
    if (isGlobalReader) {
        readerRole = makeGlobalReaderRole(owner.account.uuid);
        caller.roles[readerRole.uuid] = readerRole;
    }

    var activeRoles = [];

    if (requestedRoles) {           // The user passed in roles to assume
        /*
         * We only support role='*' for sub-users and roles within the
         * account. Cross-account roles have to be taken up by name or made
         * default.
         */
        if (requestedRoles  === '*' && caller.user) {
            activeRoles = caller.user.roles || [];
            req.activeRoles = activeRoles;
            req.authContext.conditions.activeRoles = activeRoles;
            setImmediate(next);

            return;
        }

        var lookup = {};
        for (var uuid in caller.roles) {
            var role = caller.roles[uuid];
            if (lookup[role.name] === undefined) {
                lookup[role.name] = [];
            }
            lookup[role.name].push(uuid);
        }

        var i, names;
        /* JSSTYLED */
        names = requestedRoles.split(/\s*,\s*/);
        for (i = 0; i < names.length; ++i) {
            var roles = lookup[names[i]];
            if (roles === undefined || roles.length < 1) {
                next(new InvalidRoleError(names[i]));
                return;
            }
            activeRoles = activeRoles.concat(roles);
        }
        if (readerRole) {
            activeRoles.push(readerRole.uuid);
        }
        req.activeRoles = activeRoles;
        setImmediate(next);
    } else {                            // No explicit roles, use default set
        /*
         * Sub-users don't get any default cross-account roles, only the ones
         * within their account.
         */
        if (caller.user) {
            activeRoles = caller.user.defaultRoles || [];
        } else {
            activeRoles = caller.account.defaultRoles || [];
        }
        if (readerRole) {
            /*
             * Make a copy of activeRoles before we push, so we don't modify
             * the defaultRoles on caller.user.
             */
            activeRoles = activeRoles.slice();
            activeRoles.push(readerRole.uuid);
        }
        req.activeRoles = activeRoles;
        setImmediate(next);
    }
}


function gatherContext(req, res, next) {
    var action = req.route.authAction || req.route.name;

    /*
     * We share these conditions with other systems as part of an auth token
     * (e.g. marlin for jobs).
     */
    var conditions = req.authContext.conditions;
    conditions.owner = req.owner.account;
    conditions.method = req.method;

    // Safety check: Ensure req.caller exists and has required structure
    if (!req.caller) {
        req.log.error('AUTH_ERROR: req.caller is undefined in gatherContext');
        return next(
            new InternalError('Authentication context not properly set'));
    }

    if (!req.caller.account) {
        req.log.error({
            callerKeys: Object.keys(req.caller),
            callerType: typeof (req.caller),
            caller: req.caller
        }, 'AUTH_ERROR: req.caller.account is undefined in gatherContext');
        return next(
            new InternalError('Authentication account context missing'));
    }

    /*
     * Separate the xacct and non-xacct roles so that old systems that don't
     * support them can't get confused and authorize actions improperly.
     */
    conditions.activeRoles = [];
    conditions.activeXAcctRoles = [];
    (req.activeRoles || []).forEach(function (role) {
        if (req.caller && req.caller.roles && req.caller.roles[role] &&
            req.caller.roles[role].account === req.owner.account.uuid) {
            conditions.activeRoles.push(role);
        } else if (req.caller && req.caller.roles &&
            req.caller.roles[role]) {
            conditions.activeXAcctRoles.push(role);
        }
    });

    var t = req.date();
    conditions.date = t;
    conditions.day = t;
    conditions.time = t;
    conditions.region = req.config.region;
    var ip = req.headers['x-forwarded-for'];
    if (ip) {
        conditions.sourceip = ip.split(',')[0].trim();
    }
    conditions['user-agent'] = req.headers['user-agent'];
    conditions.fromjob = false;

    // Override conditions with ones that are provided in the token
    if (req.auth.token) {
        Object.keys(req.auth.token.conditions).forEach(function (k) {
            conditions[k] = req.auth.token.conditions[k];
        });
    }

    req.authContext.principal = req.caller;
    req.authContext.action = action.toLowerCase();
    next();
}


/*
 * Authorization is only bypassed in only two situations:
 * - A bucket is called 'public'
 * - An object inside a bucket has the 'public-read' role.
 * The internal state variables that handle these situation are the following:
 *
 * req.isAnonymousAccess: Boolean flag set to true when anonymous access is
 * validated and activated. Set by validateAnonymousAccess() for buckets named
 * exactly "public", or by validateAnonymousObjectAccess() for objects with
 * "public-read" role (or in strict mode, objects in buckets named "public").
 * Used to bypass authentication steps in the auth pipeline.
 *
 * req.caller.publicReader: Boolean flag set to true on the anonymous caller
 * object that gets created when anonymous access is granted. The caller also
 * gets roles: ['public-read'] and isAnonymousPublicAccess: true. This caller
 * object replaces any existing req.caller during anonymous access validation.
 */
function authorize(req, res, next) {
    var log = req.log;

    var sanitizedCaller = req.caller ?
        Object.assign({}, req.caller, {
            account: req.caller.account ?
                Object.assign({}, req.caller.account, {
                    accesskeys: req.caller.account.accesskeys ? '[REDACTED]' :
                        undefined
                }) : req.caller.account
        }) : req.caller;
    var sanitizedOwner = req.owner ?
        Object.assign({}, req.owner, {
            account: req.owner.account ?
                Object.assign({}, req.owner.account, {
                    accesskeys: req.owner.account.accesskeys ? '[REDACTED]' :
                        undefined
                }) : req.owner.account
        }) : req.owner;

    log.debug({caller: sanitizedCaller, owner: sanitizedOwner},
              'authorize: entered');

    // Handle public bucket access for anonymous users - bypass all Mahi
    // authorization.Also handle potential anonymous access that hasn't been
    // validated yet
    if ((req.isAnonymousAccess && req.caller && req.caller.publicReader) ||
        req.potentialAnonymousAccess) {
        var resource = req.authContext ? req.authContext.resource : null;
        var action = req.authContext ? req.authContext.action : null;

        log.debug({
            isAnonymous: req.isAnonymousAccess,
            potentialAnonymous: !!req.potentialAnonymousAccess,
            publicReader: req.caller && req.caller.publicReader,
            resourceRoles: resource ? resource.roles : null,
            callerRoles: req.caller ? req.caller.roles : 'no caller',
            action: action
        }, 'authorize: handling anonymous/potential anonymous access');

        // For potential anonymous access, we need to defer authorization until
        // after bucket metadata is loaded and validated
        if (req.potentialAnonymousAccess) {
            log.debug(
                'authorize: deferring authorization' +
                    'for potential anonymous access');
            next();
            return;
        }

        // For validated public reader anonymous access, completely bypass Mahi
        // authorization. The bucket/object public status was already verified
        // in the anonymous access handler
        if (req.isAnonymousAccess && req.caller.publicReader) {
            if ((action === 'getobject' || action === 'getdirectory' ||
                 action === 'getbucket' || !action)) {
                log.debug('authorize: allowing public access' +
                          ' - bypassing Mahi authorization completely');
                next();
                return;
            } else {
                log.debug({action: action},
                          'authorize: denying non-GET' +
                          'action for anonymous access');
                next(new AuthorizationError('anonymous',
                   req.path(),
                   'Anonymous access only allowed for GET operations'));
                return;
            }
        }

        // If we reach here with anonymous access, something is wrong
        log.warn('authorize: unexpected state' +
                 '- anonymous access not properly handled');
        next(new AuthorizationError('anonymous',
           req.path(), 'Anonymous access configuration error'));
        return;
    }

    var login;

    // Handle case where we have an anonymous caller with publicReader set
    if (req.caller.publicReader && req.isAnonymousAccess) {
        login = 'anonymous';
    } else if (!req.caller.user) {
        login = req.caller.account.login;
    } else {
        login = req.caller.account.login + '/' + req.caller.user.login;
    }

    var sanitizedAuthContext = req.authContext ?
        Object.assign({}, req.authContext, {
            conditions: req.authContext.conditions ?
                Object.assign({}, req.authContext.conditions, {
                    owner: req.authContext.conditions.owner &&
                        req.authContext.conditions.owner.accesskeys ?
                        Object.assign({}, req.authContext.conditions.owner, {
                            accesskeys: '[REDACTED]'
                        }) : req.authContext.conditions.owner
                }) : req.authContext.conditions,
            principal: req.authContext.principal ?
                Object.assign({}, req.authContext.principal, {
                    account: req.authContext.principal.account ?
                        Object.assign({}, req.authContext.principal.account, {
                            accesskeys: '[REDACTED]'
                        }) : req.authContext.principal.account
                }) : req.authContext.principal,
            resource: req.authContext.resource ?
                Object.assign({}, req.authContext.resource.owner, {
                    account: req.authContext.resource.owner.account ?
                        Object.assign({}, req.authContext.resource.owner.
                                      account, {
                            accesskeys: '[REDACTED]'
                        }) : req.authContext.resource.owner.account
                }) : req.authContext.resource
        }) : req.authContext;

    req.log.debug(sanitizedAuthContext, 'authorizing...');

    try {
        // Debug: Always log the state of assumed role for debugging
        req.log.error({
            hasAssumedRole: !!req.caller.assumedRole,
            assumedRoleData: req.caller.assumedRole,
            isTemporaryCredential: !!req.auth.isTemporaryCredential,
            authAssumedRole: req.auth.assumedRole,
            authMethod: req.auth.method
        }, 'IAM_DEBUG_ALWAYS: Checking assumed' +
           ' role state before IAM evaluation');

        // Check IAM permission policies for assumed roles BEFORE
        // standard Manta authorization
        if (req.caller.assumedRole &&
            req.caller.assumedRole.permissionPolicies) {
            req.log.debug(
                'IAM_DEBUG_ALWAYS: IAM policy evaluation is starting!');
            var iamPolicyEngine = require('./iam-policy-engine');

            // Map Manta action to IAM action
            var iamAction = mapMantaToIamAction(req.authContext.action);

            // Map Manta resource to IAM resource
            var iamResource = mapMantaToIamResource(
                req.authContext.resource.key, req.path());

            req.log.info({
                mantaAction: req.authContext.action,
                iamAction: iamAction,
                mantaResource: req.authContext.resource.key,
                requestPath: req.path(),
                iamResource: iamResource,
                permissionPoliciesCount:
                req.caller.assumedRole.permissionPolicies.length,
                permissionPolicies:
                req.caller.assumedRole.permissionPolicies.map(function (p) {
                    return ({
                        policyName: p.policyName,
                        policyDocument: typeof (p.policyDocument) === 'string' ?
                            p.policyDocument : JSON.stringify(p.policyDocument)
                    });
                })
            }, 'IAM_DEBUG: Evaluating assumed role permission policies');

            var iamAllowed = iamPolicyEngine.evaluatePermissionPolicies(
                req.caller.assumedRole.permissionPolicies, iamAction,
                iamResource, req.log);

            if (!iamAllowed) {
                req.log.debug({
                    action: iamAction,
                    resource: iamResource,
                    policies: req.caller.assumedRole.permissionPolicies
                }, 'IAM_DEBUG: Access denied by IAM permission policy');

                // Create IAM access denied error
                var iamError =
                    new Error('Access denied by IAM ' +
                              'permission policy for assumed role');
                iamError.restCode = 'AccessDenied';
                iamError.statusCode = 403;
                iamError.iamRole = req.caller.assumedRole.name;
                iamError.iamAction = iamAction;
                iamError.iamResource = iamResource;
                throw iamError;
            }

            req.log.info({
                action: iamAction,
                resource: iamResource
            }, 'IAM_INFO: Access allowed by IAM permission policy');

            // IAM allows access, skip standard Manta RBAC
            next();
            return;
        } else {
            req.log.debug({
                hasAssumedRole: !!req.caller.assumedRole,
                hasPermissionPolicies:
                !!(req.caller.assumedRole &&
                   req.caller.assumedRole.permissionPolicies)
            }, 'IAM_DEBUG_ALWAYS: Skipping IAM evaluation ' +
               '- no assumed role or policies, using standard Manta auth');
        }

        // For non-assumed roles, use standard Manta authorization
        libmantalite.authorize({
            mahi: req.mahi,
            context: req.authContext,
            log: req.log
        });
    } catch (e) {
        // Debug IAM policy errors
        if (req.caller.assumedRole &&
            req.caller.assumedRole.permissionPolicies) {
            req.log.debug({
                errorName: e.name,
                errorCode: e.code,
                errorRestCode: e.restCode,
                errorMessage: e.message,
                errorStatusCode: e.statusCode,
                allErrorProps: Object.keys(e)
            }, 'IAM_DEBUG: Authorization error details');
        }
        switch (e.restCode || e.code || e.name) {
        case 'AccountBlocked':
            next(new AccountBlockedError(req.caller.account.login));
            return;
        case 'NoMatchingRoleTag':
            /*
             * If we didn't activate any owner roles, we want to return an
             * AuthorizationError here, like we would have previously if we
             * got a CrossAccount Error before cross-account role support was
             * added.
             */
            var ownerRoles = (req.activeRoles || []).filter(function (role) {
                return (req.caller.roles[role].account ===
                    req.owner.account.uuid);
            });
            if (!ownerRoles.length) {
                next(new AuthorizationError(login, req.path(), e));
            } else {
                next(new NoMatchingRoleTagError());
            }
            return;
        case 'InvalidRole':
            next(new InvalidRoleError(e.message));
            return;
        case 'CrossAccount':
            /* This should never happen. */
            next(new AuthorizationError(login, req.path(), e));
            return;
        case 'RulesEvaluationFailed':
            next(new AuthorizationError(login, req.path(), e));
            return;
        case 'AccessDenied':
            // Handle IAM permission policy access denied errors
            if (e.iamRole) {
                // This is an IAM role-based access denial
                var iamErrorMsg = 'Access denied for assumed role \'' +
                    e.iamRole + '\' - action \'' + e.iamAction +
                    '\' not permitted for resource \'' + e.iamResource + '\'';
                next(
                    new AuthorizationError(e.iamRole, req.path(), iamErrorMsg));
            } else {
                next(new AuthorizationError(login, req.path(), e));
            }
            return;
        default:
            if (e.statusCode >= 400 && e.statusCode <= 499) {
                next(new AuthorizationError(login, req.path(), e));
                return;
            }
            return (next(new InternalError(e)));
        }
    }

    next();
}


///--- Exports

module.exports = {

    authenticationHandler: function handlers(options) {
        assert.object(options, 'options');
        assert.object(options.log, 'options.log');
        assert.object(options.mahi, 'options.mahi');
        assert.optionalObject(options.iamClient,
            'options.iamClient');

        return ([
            function _authSetup(req, res, next) {
                req.mahi = options.mahi;
                req.keyapi = options.keyapi;
                req.iamClient = options.iamClient;
                req.auth = {};
                req.authContext = {
                    conditions: {}
                };
                next();
            },
            preSignedUrl,
            checkAuthzScheme,
            parseAuthTokenHandler,
            signatureHandler,
            sigv4Handler,               // Add SigV4 authentication handler
            parseKeyId,
            loadCaller,
            verifySignature,
            parseHttpAuthToken,
            loadOwner,
            getActiveRoles
        ]);
    },

    authorizationHandler: function authz() {
        return ([
            authorize
        ]);
    },

    loadOwnerFromPath: loadOwnerFromPath,

    gatherContext: gatherContext,
    createAuthToken: createAuthToken,
    parseAuthToken: parseAuthToken,
    convertS3PresignedToManta: convertS3PresignedToManta,
    checkIfPresigned: checkIfPresigned,

    postAuthTokenHandler: function () {
        return ([createAuthTokenHandler]);
    }
};
