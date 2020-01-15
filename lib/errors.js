/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

var assert = require('assert-plus');
var fs = require('fs');
var path = require('path');
var util = require('util');

var restifyErrors = require('restify-errors');
var VError = require('verror');

/*
 * This file exports errors into the global namespace, for both restify
 * and new errors. In order to add a new error to muskie, you should
 * add it to this file, and edit the javascript lint config file in this
 * repo to include the new error identifier (see jsl.node.conf for
 * examples). This will define the error for the linter so your code
 * is `make check` clean.
 */


///--- Globals

var sprintf = util.format;
var RestError = restifyErrors.RestError;


///--- Errors

function BucketsApiError(obj) {
    obj.constructorOpt = this.constructor;
    RestError.call(this, obj);
}
util.inherits(BucketsApiError, RestError);

function AccountDoesNotExistError(account) {
    BucketsApiError.call(this, {
        restCode: 'AccountDoesNotExist',
        statusCode: 403,
        message: sprintf('%s does not exist', account)
    });
}
util.inherits(AccountDoesNotExistError, BucketsApiError);

function AccountBlockedError(login) {
    BucketsApiError.call(this, {
        restCode: 'AccountBlocked',
        statusCode: 403,
        message: login + ' is not an active account'
    });
}
util.inherits(AccountBlockedError, BucketsApiError);


function AuthSchemeError(scheme) {
    BucketsApiError.call(this, {
        restCode: 'AuthorizationSchemeNotAllowed',
        statusCode: 403,
        message: (scheme || 'unknown scheme') +
            ' is not allowed (use \'signature\')'
    });
}
util.inherits(AuthSchemeError, BucketsApiError);


function AuthorizationError(login, _path, reason) {
    BucketsApiError.call(this, {
        restCode: 'AuthorizationFailed',
        statusCode: 403,
        message: login + ' is not allowed to access ' + _path,
        reason: reason
    });
}
util.inherits(AuthorizationError, BucketsApiError);


function AuthorizationRequiredError(reason) {
    BucketsApiError.call(this, {
        restCode: 'AuthorizationRequired',
        statusCode: 401,
        message: reason || 'Authorization is required'
    });
}
util.inherits(AuthorizationRequiredError, BucketsApiError);


function BucketExistsError(bucket) {
    BucketsApiError.call(this, {
        restCode: 'BucketAlreadyExists',
        statusCode: 409,
        message: sprintf('%s already exists', bucket)
    });
}
util.inherits(BucketExistsError, BucketsApiError);

function BucketNotEmptyError(bucket) {
    BucketsApiError.call(this, {
        restCode: 'BucketNotEmpty',
        statusCode: 409,
        message: sprintf('%s is not empty', bucket)
    });
}
util.inherits(BucketExistsError, BucketsApiError);

function BucketNotFoundError(p) {
    BucketsApiError.call(this, {
        restCode: 'BucketNotFound',
        statusCode: 404,
        message: p + ' was not found'
    });
}
util.inherits(BucketNotFoundError, BucketsApiError);

function ChecksumError(expected, actual) {
    BucketsApiError.call(this, {
        restCode: 'ContentMD5Mismatch',
        statusCode: 400,
        message: sprintf('Content-MD5 expected %s, but was %s',
                         expected, actual)
    });
}
util.inherits(ChecksumError, BucketsApiError);


function ConcurrentRequestError(p) {
    BucketsApiError.call(this, {
        restCode: 'ConcurrentRequest',
        statusCode: 409,
        message: p + ' was being concurrently updated'
    });
}
util.inherits(ConcurrentRequestError, BucketsApiError);


function ContentLengthError() {
    BucketsApiError.call(this, {
        restCode: 'ContentLengthRequired',
        statusCode: 411,
        message: 'Content-Length must be >= 0'
    });
}
util.inherits(ContentLengthError, BucketsApiError);


function DirectoryDoesNotExistError(p) {
    BucketsApiError.call(this, {
        restCode: 'DirectoryDoesNotExist',
        statusCode: 404,
        message: sprintf('%s does not exist', path.dirname(p))
    });
}
util.inherits(DirectoryDoesNotExistError, BucketsApiError);


function DirectoryNotEmptyError(req) {
    BucketsApiError.call(this, {
        restCode: 'DirectoryNotEmpty',
        statusCode: 400,
        message: sprintf('%s is not empty', req.path())
    });
}
util.inherits(DirectoryNotEmptyError, BucketsApiError);


function EntityExistsError(req) {
    BucketsApiError.call(this, {
        restCode: 'EntityAlreadyExists',
        statusCode: 409,
        message: sprintf('%s already exists', req.path())
    });
}
util.inherits(EntityExistsError, BucketsApiError);


function ExpectedUpgradeError(req) {
    BucketsApiError.call(this, {
        restCode: 'ExpectedUpgrade',
        statusCode: 400,
        message: sprintf('%s requires a Websocket Upgrade', req.path())
    });
}
util.inherits(ExpectedUpgradeError, BucketsApiError);


function InternalError(cause) {
    assert.ok(!cause || cause instanceof Error, 'cause');
    BucketsApiError.call(this, {
        restCode: 'InternalError',
        statusCode: 500,
        message: 'an unexpected error occurred',
        cause: cause
    });
}
util.inherits(InternalError, BucketsApiError);


function InvalidAlgorithmError(alg, valid) {
    var message = sprintf(
        '%s is not a supported signing algorithm. Supported algorithms are %s',
        alg, valid);

    BucketsApiError.call(this, {
        restCode: 'InvalidAlgorithm',
        statusCode: 401,
        message: message
    });
}
util.inherits(InvalidAlgorithmError, BucketsApiError);


function InvalidAuthTokenError(reason) {
    BucketsApiError.call(this, {
        restCode: 'InvalidAuthenticationToken',
        statusCode: 403,
        message: 'the authentication token you provided is ' +
            (reason || 'malformed')
    });
}
util.inherits(InvalidAuthTokenError, BucketsApiError);


function InvalidBucketNameError(name) {
    BucketsApiError.call(this, {
        restCode: 'InvalidBucketName',
        statusCode: 422,
        message: sprintf('%j is not a valid bucket name', name)
    });
}
util.inherits(InvalidBucketNameError, BucketsApiError);


function InvalidBucketObjectNameError(name) {
    BucketsApiError.call(this, {
        restCode: 'InvalidBucketObjectName',
        statusCode: 422,
        message: sprintf('%j is not a valid bucket object name', name)
    });
}
util.inherits(InvalidBucketObjectNameError, BucketsApiError);


function InvalidHttpAuthTokenError(reason) {
    BucketsApiError.call(this, {
        restCode: 'InvalidHttpAuthenticationToken',
        statusCode: 403,
        message: (reason || 'Invalid HTTP Auth Token')
    });
}
util.inherits(InvalidHttpAuthTokenError, BucketsApiError);


function InvalidDurabilityLevelError(min, max) {
    BucketsApiError.call(this, {
        restCode: 'InvalidDurabilityLevel',
        statusCode: 400,
        message: sprintf('durability-level must be between %d and %d',
                         min, max)
    });
}
util.inherits(InvalidDurabilityLevelError, BucketsApiError);


function InvalidKeyIdError() {
    BucketsApiError.call(this, {
        restCode: 'InvalidKeyId',
        statusCode: 403,
        message: 'the KeyId token you provided is invalid'
    });
}
util.inherits(InvalidKeyIdError, BucketsApiError);


function InvalidLimitError(l) {
    BucketsApiError.call(this, {
        restCode: 'InvalidArgumentError',
        statusCode: 400,
        message: 'limit=' + l + ' is invalid: must be between [1, 1024]'
    });
}
util.inherits(InvalidLimitError, BucketsApiError);


function InvalidUpdateError(k, extra) {
    BucketsApiError.call(this, {
        restCode: 'InvalidUpdate',
        statusCode: 400,
        message: 'overwrite of "' + k + '" forbidden' + (extra || '')
    });
}
util.inherits(InvalidUpdateError, BucketsApiError);


function InvalidParameterError(k, v) {
    BucketsApiError.call(this, {
        restCode: 'InvalidParameter',
        statusCode: 400,
        message: '"' + v + '" is invalid for "' + k + '"'
    });
}
util.inherits(InvalidParameterError, BucketsApiError);


function InvalidPathError(p) {
    BucketsApiError.call(this, {
        restCode: 'InvalidResource',
        statusCode: 400,
        message: '"' + p + '" is invalid'
    });
}
util.inherits(InvalidPathError, BucketsApiError);


function InvalidRoleError(r) {
    BucketsApiError.call(this, {
        restCode: 'InvalidRole',
        statusCode: 409,
        message: 'Role "' + r + '" is invalid.'
    });
}
util.inherits(InvalidRoleError, BucketsApiError);


function InvalidRoleTagError(r) {
    BucketsApiError.call(this, {
        restCode: 'InvalidRoleTag',
        statusCode: 409,
        message: 'Role tag "' + r + '" is invalid.'
    });
}
util.inherits(InvalidRoleTagError, BucketsApiError);


function InvalidSignatureError() {
    BucketsApiError.call(this, {
        restCode: 'InvalidSignature',
        statusCode: 403,
        message: 'The signature we calculated does not match the one ' +
            'you sent'
    });
}
util.inherits(InvalidSignatureError, BucketsApiError);


function KeyDoesNotExistError(account, key, user) {
    var message = user ?
            sprintf('/%s/%s/keys/%s does not exist', account, user, key) :
            sprintf('/%s/keys/%s does not exist', account, key);
    BucketsApiError.call(this, {
        restCode: 'KeyDoesNotExist',
        statusCode: 403,
        message: message
    });
}
util.inherits(KeyDoesNotExistError, BucketsApiError);


function SharksExhaustedError(res) {
    BucketsApiError.call(this, {
        restCode: 'InternalError',
        statusCode: 503,
        message: 'No storage nodes available for this request'
    });
    if (res)
        res.setHeader('Retry-After', 30);
}
util.inherits(SharksExhaustedError, BucketsApiError);


function MaxContentLengthError(len) {
    BucketsApiError.call(this, {
        restCode: 'InvalidMaxContentLength',
        statusCode: 400,
        message: len + ' is an invalid max-content-length value'
    });
}
util.inherits(MaxContentLengthError, BucketsApiError);


function MaxSizeExceededError(max) {
    BucketsApiError.call(this, {
        restCode: 'MaxContentLengthExceeded',
        statusCode: 413,
        message: 'request has exceeded ' + max + ' bytes'
    });
}
util.inherits(MaxSizeExceededError, BucketsApiError);


function MissingPermissionError(perm) {
    BucketsApiError.call(this, {
        restCode: 'MissingPermission',
        statusCode: 403,
        message: 'missing role allowing ' + perm
    });
}
util.inherits(MissingPermissionError, BucketsApiError);


function MultipartUploadCreateError(msg) {
    BucketsApiError.call(this, {
        restCode: 'MultipartUploadInvalidArgument',
        statusCode: 409,
        message: sprintf('cannot create upload: %s', msg)
    });
}
util.inherits(MultipartUploadCreateError, BucketsApiError);


function MultipartUploadStateError(id, msg) {
    BucketsApiError.call(this, {
        restCode: 'InvalidMultipartUploadState',
        statusCode: 409,
        message: sprintf('upload %s: %s', id, msg)
    });
}
util.inherits(MultipartUploadStateError, BucketsApiError);


function MultipartUploadInvalidArgumentError(id, msg) {
    BucketsApiError.call(this, {
        restCode: 'MultipartUploadInvalidArgument',
        statusCode: 409,
        message: sprintf('upload %s: %s', id, msg)
    });
}
util.inherits(MultipartUploadInvalidArgumentError, BucketsApiError);


function NotAcceptableError(req, type) {
    BucketsApiError.call(this, {
        restCode: 'NotAcceptable',
        statusCode: 406,
        message: sprintf('%s accepts %s', req.path(), type)
    });
}
util.inherits(NotAcceptableError, BucketsApiError);


function NoMatchingRoleTagError() {
    BucketsApiError.call(this, {
        restCode: 'NoMatchingRoleTag',
        statusCode: 403,
        message: 'None of your active roles are present on the resource.'
    });
}
util.inherits(NoMatchingRoleTagError, BucketsApiError);


function NotEnoughSpaceError(size, cause) {
    var message = sprintf('not enough free space for %d MB', size);

    BucketsApiError.call(this, {
        restCode: 'NotEnoughSpace',
        statusCode: 507,
        message: message,
        cause: cause
    });
}
util.inherits(NotEnoughSpaceError, BucketsApiError);


function NotImplementedError(message) {
    BucketsApiError.call(this, {
        restCode: 'NotImplemented',
        statusCode: 501,
        message: message
    });
}
util.inherits(NotImplementedError, BucketsApiError);


/*
 * A "bucket object" path is in the form:
 * /buckets/:bucketname/objects/:objectname
 */
function ParentNotBucketError(req) {
    BucketsApiError.call(this, {
        restCode: 'ParentNotBucket',
        statusCode: 400,
        message: sprintf('bucket objects must be created in a bucket')
    });
}
util.inherits(ParentNotBucketError, BucketsApiError);


function ParentNotBucketRootError(req) {
    BucketsApiError.call(this, {
        restCode: 'ParentNotBucketRoot',
        statusCode: 400,
        message: sprintf('buckets must be created in the buckets directory')
    });
}
util.inherits(ParentNotBucketRootError, BucketsApiError);

function ObjectNotFoundError(p) {
    BucketsApiError.call(this, {
        restCode: 'ObjectNotFound',
        statusCode: 404,
        message: p + ' was not found'
    });
}
util.inherits(ObjectNotFoundError, BucketsApiError);

function PreSignedRequestError(msg) {
    BucketsApiError.call(this, {
        restCode: 'InvalidQueryStringAuthentication',
        statusCode: 403,
        message: msg
    });
}
util.inherits(PreSignedRequestError, BucketsApiError);


// We expect an array of the offending parameters.
function QueryParameterForbiddenError(params) {
    BucketsApiError.call(this, {
        restCode: 'QueryParameterForbidden',
        statusCode: 403,
        message: sprintf(
            'Use of these query parameters is restricted to operators: %s',
            params.join(', '))
    });
}
util.inherits(QueryParameterForbiddenError, BucketsApiError);


function RequestedRangeNotSatisfiableError(req, err) {
    if (err && err._result && err._result.headers) {
        this.headers = {
            'Content-Range': err._result.headers['content-range']
        };
    }
    BucketsApiError.call(this, {
        restCode: 'RequestedRangeNotSatisfiable',
        statusCode: 416,
        message: sprintf('%s is an invalid range',
                         req.headers['range'])
    });
}
util.inherits(RequestedRangeNotSatisfiableError, BucketsApiError);


function ResourceNotFoundError(p) {
    BucketsApiError.call(this, {
        restCode: 'ResourceNotFound',
        statusCode: 404,
        message: p + ' was not found'
    });
}
util.inherits(ResourceNotFoundError, BucketsApiError);


function ServiceUnavailableError(req, cause) {
    BucketsApiError.call(this, {
        restCode: 'ServiceUnavailable',
        statusCode: 503,
        message: 'manta is unable to serve this request',
        cause: cause
    });
}
util.inherits(ServiceUnavailableError, BucketsApiError);


function SSLRequiredError() {
    BucketsApiError.call(this, {
        restCode: 'SecureTransportRequired',
        statusCode: 403,
        message: 'Manta requires a secure transport (SSL/TLS)'
    });
}
util.inherits(SSLRequiredError, BucketsApiError);

function ThrottledError() {
    BucketsApiError.call(this, {
        restCode: 'ThrottledError',
        statusCode: 503,
        message: 'manta throttled this request'
    });
    this.name = this.constructor.name;
}
util.inherits(ThrottledError, BucketsApiError);

function UploadAbandonedError() {
    BucketsApiError.call(this, {
        restCode: 'UploadAbandoned',
        statusCode: 499,
        message: sprintf('request was aborted prematurely by the client')
    });
}
util.inherits(UploadAbandonedError, BucketsApiError);


function UploadTimeoutError() {
    BucketsApiError.call(this, {
        restCode: 'UploadTimeout',
        statusCode: 408,
        message: sprintf('request took too long to send data')
    });
}
util.inherits(UploadTimeoutError, BucketsApiError);


function UserDoesNotExistError(account, user) {
    var message;
    if (!account) {
        message = sprintf('%s does not exist', user);
    } else {
        message = sprintf('%s/%s does not exist', account, user);
    }
    BucketsApiError.call(this, {
        restCode: 'UserDoesNotExist',
        statusCode: 403,
        message: message
    });
}
util.inherits(UserDoesNotExistError, BucketsApiError);



///--- Translate API

function translateError(err, req) {
    if (err instanceof BucketsApiError ||
        err instanceof restifyErrors.HttpError) {

        return (err);
    }

    var cause;

    // A NoDatabasePeersError with a context object that has a 'name' and a
    // 'message' field sent from Moray indicates a transient availability error
    // due to request overload. We report these types of errors as 503s to
    // indicate to the client that it can ameliorate the situation with
    // sufficient back-off. A NoDatabasePeersError without a context object
    // of this form still indicates an internal error (500) that should be
    // investigated as a bug or other more serious problem in Manta.
    cause = VError.findCauseByName(err, 'NoDatabasePeersError');
    if (cause !== null && cause.context && cause.context.name &&
        cause.context.message && cause.context.name === 'OverloadedError') {
        return (new ServiceUnavailableError(req, new VError({
            'name': cause.context.name
        }, '%s', cause.context.message)));
    }

    cause = VError.findCauseByName(err, 'ThrottledError');
    if (cause !== null) {
        return (cause);
    }

    cause = VError.findCauseByName(err, 'ObjectNotFoundError');
    if (cause !== null) {
        return (new restifyErrors.ResourceNotFoundError(cause,
            '%s does not exist', req.path()));
    }

    cause = VError.findCauseByName(err, 'PreconditionFailedError');
    if (cause !== null) {
        return (cause);
    }

    cause = VError.findCauseByName(err, 'RequestedRangeNotSatisfiableError');
    if (cause !== null) {
        return (new RequestedRangeNotSatisfiableError(req, cause));
    }

    cause = VError.findCauseByName(err, 'EtagConflictError');
    if (cause === null) {
        cause = VError.findCauseByName(err, 'UniqueAttributeError');
    }
    if (cause !== null) {
        return (new ConcurrentRequestError(req.path()));
    }

    return (new InternalError(err));
}


///--- Exports

// Auto export all Errors defined in this file
fs.readFileSync(__filename, 'utf8').split('\n').forEach(function (l) {
    /* JSSTYLED */
    var match = /^function\s+(\w+)\(.*/.exec(l);
    if (match !== null && Array.isArray(match) && match.length > 1) {
        if (/\w+Error$/.test(match[1])) {
            module.exports[match[1]] = eval(match[1]);
        }
    }
});

Object.keys(module.exports).forEach(function (k) {
    global[k] = module.exports[k];
});
