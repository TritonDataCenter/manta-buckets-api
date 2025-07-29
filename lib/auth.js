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
require('./errors');


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


function checkIfPresigned(req, res, next) {
    if (req.headers.authorization ||
        (!req.query.expires &&
         !req.query.signature &&
         !req.query.keyId &&
         !req.query.algorithm)) {
        next();
    } else {
        req._presigned = true;
        next();
    }
}


function preSignedUrl(req, res, next) {
    if (!req.isPresigned()) {
        next();
        return;
    }

    var expires;
    var log = req.log;
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

    log.debug({auth: req.auth}, 'preSignedUrl: done');
    next();
}


function checkAuthzScheme(req, res, next) {
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

    if (!authHeader) {
        req.log.debug('S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
        ' - Missing Authorization header');
        next(new InvalidSignatureError('Missing Authorization header'));
        return;
    }

    if (!dateHeader) {
        req.log.debug('S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
        ' - Missing date header');
        next(new InvalidSignatureError('Missing date header'));
        return;
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

    // XXX some clients rely in content-length for sigv4
    // but restify overwrites this header, an easy wayout is
    // to add a new header that mahi can read and adjust it's
    // canonical url to match with the one send by the client.
    if ('content-length' in filteredHeaders) {
        filteredHeaders['edgecast-content-length'] =
            filteredHeaders['content-length'];
    }
    var urlForVerification = req.url;
    var pathPart = urlForVerification.split('?')[0];
    var queryPart = urlForVerification.split('?')[1];

    // For virtual-hosted-style requests, the bucket name is the first
    // component of the host header.
    var hostHeader = req.headers.host || '';
    var bucketName = hostHeader.split('.')[0];

    // If the URI path is the bucket name, S3 clients sign the request with a
    // canonical URI of `/`. We must normalize the URL we send to mahi for
    // verification to match.
    if (bucketName && pathPart === '/' + bucketName) {
        req.log.debug({
            bucket: bucketName,
            originalPath: pathPart
        }, 'S3_AUTH_DEBUG: Normalizing bucket URI for SigV4 verification');
        pathPart = '/' + bucketName + '/';
    }

    // MANTA-331 removes trailing slashes, here minio requires them
    // to sign the request if pathPart is just a bucket request then add /
    // This is true for third party s3 clients, like s3cmd, where it does not
    // sends the user-agent header.
    // This is really important as this breaks sigv4 validation.
    // awscli is excluded as it does not requires pathPart to end with /.
    // For example /test5 won't match this regex and needs to be appended
    // / that manta 331 stripped from it.
    // while /test5/test1.txt won't need patching pathPart.
    var regex = /\/[^/]+\.(?:$|\/)|\/[^/]+\/[^/]+/;
    if ((!('user-agent' in req.headers) ||
       (req.headers['user-agent'] &&
       req.headers['user-agent'].toLowerCase().includes('minio'))) &&
        regex.test(pathPart) === false && pathPart !== '/') {
        pathPart += '/';
    }

    // Fix double-encoding issue in query parameters before sending to mahi
    // AWS CLI sends delimiter=%2F but when we URL-encode the whole URL for
    // mahi, it becomes delimiter=%252F which breaks signature verification
    if (queryPart) {
        // Decode query parameters once to prevent double-encoding
        try {
            var decodedQuery = decodeURIComponent(queryPart);
            urlForVerification = pathPart + '?' + decodedQuery;

            req.log.debug({
                originalUrl: req.url,
                finalUrl: urlForVerification
            }, 'S3_AUTH_DEBUG:'+
            ' Fixed query parameter encoding for SigV4 verification');
        } catch (e) {
            // If decoding fails, keep original URL
            urlForVerification = pathPart + '?' + queryPart;
            req.log.debug({
                originalUrl: req.url,
                error: e.message,
                reason: 'Query decoding failed, using original query part'
            }, 'S3_AUTH_DEBUG: Using original URL for SigV4 verification');
        }
    } else {
        urlForVerification = pathPart;
        req.log.debug({
            url: urlForVerification,
            reason: 'No query parameters'
        }, 'S3_AUTH_DEBUG: Using original URL for SigV4 verification');
    }

    var requestForVerification = {
        method: req.method,
        url: urlForVerification,
        headers: filteredHeaders
    };

    var originalHeaderKeys = Object.keys(req.headers).sort();
    var filteredHeaderKeys = Object.keys(requestForVerification.headers).
    sort();
    var skippedHeaders = originalHeaderKeys.filter(function (key) {
        return (skipHeaders.indexOf(key.toLowerCase()) !== -1);
    });

    req.log.debug({
        method: requestForVerification.method,
        url: requestForVerification.url,
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
        originalHeaders: req.rawHeaders
    }, 'S3_AUTH_DEBUG:'+
    ' Calling node-mahi verifySigV4 for signature verification'+
    ' (only skipped connection-breaking headers)');

    // Use node-mahi's verifySigV4 method
    req.mahi.verifySigV4(requestForVerification, function (err, result) {
        if (err) {
            req.log.debug({
                error: err.message || err.toString(),
                restCode: err.restCode,
                errorName: err.name,
                statusCode: err.statusCode
            }, 'S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
            ' - SigV4 verification failed');

            // Map node-mahi errors to appropriate HTTP errors
            switch (err.restCode || err.name) {
            case 'InvalidSignature':
            case 'SignatureDoesNotMatch':
                next(new InvalidSignatureError(err.message ||
                'Invalid signature'));
                break;
            case 'AccessKeyNotFound':
                next(new InvalidSignatureError('Invalid access key'));
                break;
            case 'RequestTimeTooSkewed':
                next(new InvalidSignatureError('Request timestamp too skewed'));
                break;
            default:
                next(new InvalidSignatureError('Authentication failed: '
                + (err.message || 'Unknown error')));
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
            next(new InvalidSignatureError('Authentication failed'));
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

        next();
    });
}


function parseKeyId(req, res, next) {
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
    var account = req.auth.account;
    var accountid = req.auth.accountid;
    var user = req.auth.user;
    var userid = req.auth.userid;
    var accessKeyId = req.auth.accessKeyId; // support for access key lookup

    req.log.debug('loadCaller: entered');

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

        if (req.isS3Request) {
            req.log.debug({
                callerType: info.account ? 'account' : 'user',
                accountLogin: info.account ? info.account.login : 'unknown',
                accountUuid: info.account ? info.account.uuid : 'unknown',
                isProvisioned: info.account ?
                info.account.approved_for_provisioning : false
            }, 'S3_AUTH_DEBUG: AUTHENTICATION COMPLETE'+
            ' - Caller loaded successfully');
        }

        req.log.debug({caller: req.caller}, 'loadCaller: done');
        next();
    }

    // SigV4 authentication: Get user info by UUID (from verifySigV4 result)
    if (accessKeyId && req.auth.method === 'sigv4') {
        req.log.debug({
            accessKeyId: accessKeyId,
            userUuid: req.auth.accountid,
            method: 'sigv4'
        }, 'S3_AUTH_DEBUG:'+
        ' Loading caller via userUuid from SigV4 verification');

        // Use the userUuid from SigV4 verification to get actual
        // account details
        req.mahi.getAccountById(req.auth.accountid, function (err, data) {
            if (err) {
                req.log.debug({
                    error: err.message || err.toString(),
                    userUuid: req.auth.accountid,
                    accessKeyId: accessKeyId
                }, 'S3_AUTH_DEBUG: AUTHENTICATION FAILED'+
                ' - Account lookup by UUID failed');
            } else {
                req.log.debug({
                    accessKeyId: accessKeyId,
                    userUuid: data ? data.uuid : 'unknown',
                    userLogin: data ? data.login : 'unknown'
                }, 'S3_AUTH_DEBUG: AUTHENTICATION SUCCESS'+
                ' - Account lookup by UUID successful');
            }
            gotCaller(err, data);
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
        req.log.debug({caller: req.caller}, 'loadCaller: done');
        setImmediate(next);
        return;
    }
}


function verifySignature(req, res, next) {
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
        next(new InvalidSignatureError());
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

        if (req.caller.anonymous && !owner.user) {
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

    /*
     * Separate the xacct and non-xacct roles so that old systems that don't
     * support them can't get confused and authorize actions improperly.
     */
    conditions.activeRoles = [];
    conditions.activeXAcctRoles = [];
    (req.activeRoles || []).forEach(function (role) {
        if (req.caller.roles[role].account === req.owner.account.uuid) {
            conditions.activeRoles.push(role);
        } else {
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


function authorize(req, res, next) {
    var log = req.log;

    log.debug({caller: req.caller, owner: req.owner}, 'authorize: entered');

    var login;

    if (!req.caller.user) {
        login = req.caller.account.login;
    } else {
        login = req.caller.account.login + '/' + req.caller.user.login;
    }

    req.log.debug(req.authContext, 'authorizing...');

    try {
        libmantalite.authorize({
            mahi: req.mahi,
            context: req.authContext
        });
    } catch (e) {
        switch (e.restCode || e.name) {
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

        return ([
            function _authSetup(req, res, next) {
                req.mahi = options.mahi;
                req.keyapi = options.keyapi;
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
    checkIfPresigned: checkIfPresigned,

    postAuthTokenHandler: function () {
        return ([createAuthTokenHandler]);
    }
};
