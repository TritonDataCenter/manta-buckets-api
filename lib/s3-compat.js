/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var assert = require('assert-plus');
var url = require('url');
var crypto = require('crypto');

// Import errors
require('./errors');

///--- S3 API Operation Mapping

var S3_OPERATIONS = {
    // Bucket operations
    'GET /': 'ListBuckets',
    'PUT /{bucket}': 'CreateBucket',
    'GET /{bucket}': 'ListBucketObjects',
    'GET /{bucket}?list-type=2': 'ListBucketObjectsV2',
    'HEAD /{bucket}': 'HeadBucket',
    'DELETE /{bucket}': 'DeleteBucket',
    'POST /{bucket}?delete': 'DeleteBucketObjects',

    // Object operations
    'PUT /{bucket}/{object}': 'CreateBucketObject',
    'GET /{bucket}/{object}': 'GetBucketObject',
    'HEAD /{bucket}/{object}': 'HeadBucketObject',
    'DELETE /{bucket}/{object}': 'DeleteBucketObject'
};

/*
 * S3 AWS ACL to Manta Role mapping
 * --------------------------------
 * Currently only public-read role is used and private just means remove public
 * access. All of these roles must be created ahead of time in Manta with
 * a policy that matches the intent. For example for the public-read policy
 * we create the following in policy and role in cloudapi.
 *
 * [(cloudapi0) ~]# sdc-policy create --name=read-public --rules='CAN getobject'
 * {
 *   "name": "read-public",
 *   "id": "203c03fd-8271-472c-a5f9-cc4ab0f21e6a",
 *   "rules": [
 *     "CAN getobject"
 *   ]
 * }
 * [(cloudapi0) ~]# sdc-role create  --name=public-read   --policies=read-public
 * {
 *   "name": "public-read",
 *   "id": "c72e37a0-6a49-4660-86c4-1d6655702413",
 *   "members": [],
 *   "default_members": [],
 *   "policies": [
 *     "read-public"
 *   ]
 * }{
 *   "name": "read-public",
 *   "id": "203c03fd-8271-472c-a5f9-cc4ab0f21e6a",
 *   "rules": [
 *     "CAN getobject"
 *   ]
 * }
 */

var S3_ACL_TO_MANTA_ROLES = {
    'private': [],
    'public-read': ['public-read'],
    'public-read-write': ['public-read', 'public-writer'],
    'authenticated-read': ['authenticated-reader'],
    'bucket-owner-read': ['owner-reader'],
    'bucket-owner-full-control': ['owner-full-control'],
    'log-delivery-write': ['log-writer']
};



/*
 * Canned (XML format) Error Responses for S3 clients.
 */

var S3_ERROR_RESPONSES = {
    'NoSuchBucket': {
        code: 'NoSuchBucket',
        description: 'The specified bucket does not exist.',
        httpStatusCode: 404
    },
    'BucketAlreadyExists': {
        code: 'BucketAlreadyExists',
        description: 'The requested bucket name is not available.',
        httpStatusCode: 409
    },
    'NoSuchKey': {
        code: 'NoSuchKey',
        description: 'The specified key does not exist.',
        httpStatusCode: 404
    },
    'ObjectNotFoundError': {
        code: 'NoSuchKey',
        description: 'The specified key does not exist.',
        httpStatusCode: 404
    },
    'BucketNotFoundError': {
        code: 'NoSuchBucket',
        description: 'The specified bucket does not exist.',
        httpStatusCode: 404
    },
    'BucketExistsError': {
        code: 'BucketAlreadyExists',
        description: 'The requested bucket name is not available.',
        httpStatusCode: 409
    },
    'AccessDenied': {
        code: 'AccessDenied',
        description: 'Access Denied',
        httpStatusCode: 403
    },
    'InvalidSignature': {
        code: 'SignatureDoesNotMatch',
        description: 'The request signature we calculated does not '+
        'match the signature you provided.',
        httpStatusCode: 403
    },
    'RequestTimeTooSkewed': {
        code: 'RequestTimeTooSkewed',
        description: 'The difference between the request time and '+
        'the current time is too large.',
        httpStatusCode: 403
    },
    'NotEnoughSpaceError': {
        code: 'InternalError',
        description: 'We encountered an internal error. Please try again.',
        httpStatusCode: 500
    },
    'InvalidPart': {
        code: 'InvalidPart',
        description: 'One or more of the specified parts could not be found' +
            ' or the specified entity tag might not have matched ' +
            'the part\'s entity tag.',
        httpStatusCode: 400
    },
    'EntityTooSmall': {
        code: 'EntityTooSmall',
        description: 'Your proposed upload is smaller than' +
            ' the minimum allowed object size.',
        httpStatusCode: 400
    },
    'InsufficientStorage': {
        code: 'InsufficientStorage',
        description: 'There is insufficient storage space' +
            ' to complete the request.',
        httpStatusCode: 507
    },
    'InternalError': {
        code: 'InternalError',
        description: 'We encountered an internal error. Please try again.',
        httpStatusCode: 500
    }
};

///--- Helper Functions

/**
 * parseS3Request(req):
 * Transforms a HTTP raw request into a S3 operation with its required metadata.
 *
 * Arguments:
 *     req :  HTTP request data.
 * Returns:
 *      S3 request object, the object metadata is directly proportional to the
 *      HTTP verb and URI that determinate the S3 request operation.
 *
 *
 *  Examples of possible HTTP request and the associated S3 request operation:
 *
 *  +----+----------------+----------------+-----------+----------------------+
 *  |VERB| Path           | S3 Operation   | AddrStyle | S3 Request obj       |
 *  +----+----------------+----------------+-----------+----------------------+
 *  |PUT | /mybucket\     |CreateBucketObj | path      | { bucket:"mybucket", |
 *  |    | /file.txt      |                |           |   object:"file.txt", |
 *  |    |                |                |           |   operation:"Create",|
 *  |    |                |                |           |   isS3Request:true,  |
 *  |    |                |                |           |   mantaPath:null,    |
 *  |    |                |                |           |   addrStyle:"path" } |
 *  +----+----------------+----------------+-----------+----------------------+
 *  |DEL | /mybucket\     |DeleteBucketObj | path      | { bucket:"mybucket", |
 *  |    | /file.txt      |                |           |   object:"file.txt", |
 *  |    |                |                |           |   operation:"Delete",|
 *  |    |                |                |           |   isS3Request:true,  |
 *  |    |                |                |           |   mantaPath:null,    |
 *  |    |                |                |           |   addrStyle:"path" } |
 *  +----+----------------+----------------+-----------+----------------------+
 *  |PUT | /mybucket\     | UploadPart     | path      | { bucket:"mybucket", |
 *  |    | /large.zip\    |                |           |   object:"large.zip",|
 *  |    | ?part=1\       |                |           |   operation:"Upload",|
 *  |    | &id=abc123     |                |           |   isS3Request:true,  |
 *  |    |                |                |           |   mantaPath:null,    |
 *  |    |                |                |           |   addrStyle:"path",  |
 *  |    |                |                |           |   uploadId:"abc123", |
 *  |    |                |                |           |   partNumber:1 }     |
 *  +----+----------------+----------------+-----------+----------------------+
 *  |GET | /mybucket\     | ListObjsV2     | path      | { bucket:"mybucket", |
 *  |    | ?list-type=2   |                |           |   object:null,       |
 *  |    |                |                |           |   operation:"ListV2",|
 *  |    |                |                |           |   isS3Request:true,  |
 *  |    |                |                |           |   mantaPath:null,    |
 *  |    |                |                |           |   addrStyle:"path" } |
 *  +----+----------------+----------------+-----------+----------------------+
 *  |GET | bucket.domain\ | GetObj         | vhost     | { bucket:"bucket",   |
 *  |    | /file.txt      |                |           |   object:"file.txt", |
 *  |    |                |                |           |   operation:"GetObj",|
 *  |    |                |                |           |   isS3Request:true,  |
 *  |    |                |                |           |   mantaPath:null,    |
 *  |    |                |                |           |   addrStyle:"vhost"} |
 *  +----+----------------+----------------+-----------+----------------------+
 *
 *
 * Notes:
 *     This supports only path-style, virtual-hosted has not been tested enough,
 *     so it's disabled.
 *     One critical aspect here is that the property mantaPath is always null,
 *     this is fine as this property needs to be filled downward the stack
 *     when we are converting a s3 path style to a manta path.
 */
function parseS3Request(req) {
    req.log.debug('S3_DEBUG_CONSOLE: ===== parseS3Request CALLED ==========');
    var path = req.path();
    var method = req.method;
    var host = req.headers.host || '';

    // Parse query parameters manually since req.query isn't available yet
    var query = {};
    var requestUrl = req.url || path;
    var queryString = '';
    if (requestUrl.indexOf('?') !== -1) {
        queryString = requestUrl.split('?')[1];
        if (queryString) {
            queryString.split('&').forEach(function (param) {
                var parts = param.split('=');
                if (parts.length >= 1) {
                    var key = decodeURIComponent(parts[0]);
                    var value = parts.length === 2 ?
                        decodeURIComponent(parts[1]) : '';
                    query[key] = value;
                    req.log.debug('S3_DEBUG_QUERY_PARSE: parsed query param:',
                                 key, '=', value);
                }
            });
        }
    }

    req.log.debug('S3_DEBUG_CONSOLE: parseS3Request inputs - path:',
    path, 'method:', method, 'host:', host);
    req.log.debug('S3_DEBUG_QUERY_MAIN: req.url:', req.url);
    req.log.debug('S3_DEBUG_QUERY_MAIN: queryString extracted:', queryString);
    req.log.debug('S3_DEBUG_QUERY_MAIN: parsed query object:',
    JSON.stringify(query));

    // Remove leading slash
    var cleanPath = path.replace(/^\/+/, '');
    var pathParts = cleanPath.split('/').filter(function (part) {
    return (part.length > 0);
    });

    var hostParts = host.split('.');

    var s3Request = {
        bucket: null,
        object: null,
        operation: null,
        isS3Request: false,
        mantaPath: null,
        addressingStyle: 'path-style'
    };

    req.log.debug({
        host: host,
        path: path,
        hostParts: hostParts,
        pathParts: pathParts,
        expectedPathStyle: 'bucket from path[0] (' + (pathParts[0] || 'none') +
        '), object from path[1+] (' + (pathParts.slice(1).join('/') || 'none')
        + ')'
    }, 'S3_DEBUG: parseS3Request - analyzing request style with expectations');

    req.log.debug({path: path, host: host },
                  'S3_DEBUG_CONSOLE: parseS3Request called with path:');

    // Path-style: domain.com/bucket/object-key
    // Mark as S3 if this is a SigV4 request OR a presigned URL
    var authHeader =
        req.headers.authorization || req.headers.Authorization || '';
    var isSigV4 = authHeader.toLowerCase().indexOf('aws4-hmac-sha256') === 0;

    // Also check for S3 presigned URL parameters (must be AWS4-HMAC-SHA256)
    var isS3PresignedUrl = !!(query['X-Amz-Algorithm'] ===
                              'AWS4-HMAC-SHA256' &&
                             query['X-Amz-Signature'] &&
                             query['X-Amz-Credential'] &&
                             query['X-Amz-Date'] &&
                             query['X-Amz-Expires']);

    var isS3Request = isSigV4 || isS3PresignedUrl;

    if (pathParts.length === 0) {
        // Root path - list buckets
        s3Request.isS3Request = isS3Request;
        if (isS3Request) {
            s3Request.operation = 'ListBuckets';
        }
    } else if (pathParts.length === 1) {
        // Bucket operations
        s3Request.isS3Request = isS3Request;
        if (isS3Request) {
            s3Request.bucket = pathParts[0];

            switch (method) {
            case 'GET':
                // Check for ListObjectsV2 query parameter
                // (using manually parsed query)
                req.log.debug('S3_DEBUG_QUERY: parseS3Request'+
                              ' - query object:', JSON.stringify(query));
                req.log.debug('S3_DEBUG_QUERY: parseS3Request -'+
                              'list-type value:', query['list-type']);
                req.log.debug('S3_DEBUG_QUERY: parseS3Request -'+
                              'list-type === "2":', query['list-type'] === '2');

                if (query['list-type'] === '2') {
                    s3Request.operation = 'ListBucketObjectsV2';
                    req.log.debug('S3_DEBUG_QUERY: parseS3Request -'+
                                  ' SET OPERATION TO ListBucketObjectsV2');
                } else {
                    s3Request.operation = 'ListBucketObjects';
                    req.log.debug('S3_DEBUG_QUERY: parseS3Request'+
                                  ' - SET OPERATION TO ListBucketObjects');
                }
                req.log.debug('S3_DEBUG_FINAL_OPERATION: parseS3Request' +
                              ' - FINAL OPERATION SET TO:',
                              s3Request.operation);
                req.log.debug('S3_DEBUG_FINAL_OPERATION: parseS3Request' +
                              ' - FINAL s3Request OBJECT:',
                              JSON.stringify(s3Request, null, 2));
                break;
            case 'PUT':
                s3Request.operation = 'CreateBucket';
                break;
            case 'HEAD':
                s3Request.operation = 'HeadBucket';
                break;
            case 'DELETE':
                s3Request.operation = 'DeleteBucket';
                break;
            case 'POST':
                // Check if this is a bulk delete operation
                if (query.delete !== undefined ||
                    (typeof (queryString) === 'string' &&
                     queryString.includes('delete'))) {
                    s3Request.operation = 'DeleteBucketObjects';
                    req.log.debug('S3_DEBUG: Detected bulk'+
                                  ' delete operation');
                } else {
                    req.log.warn('S3_WARN: Unsupported POST'+
                                 ' operation for bucket:', method);
                }
                break;
            default:
                // Log unexpected method but don't fail parsing
                req.log.warn('S3_WARN: Unexpected HTTP method '+
                             'in bucket operations:', method);
                break;
            }
        }
    } else if (pathParts.length >= 2) {
        // Object operations
        s3Request.isS3Request = isS3Request;
        if (isS3Request) {
            s3Request.bucket = pathParts[0];
            s3Request.object = pathParts.slice(1).join('/');

            // Check for multipart upload operations first
            if (query.uploads !== undefined) {
                // POST /{bucket}/{key}?uploads = Initiate Multipart Upload
                s3Request.operation = 'InitiateMultipartUpload';
                req.log.debug('S3_DEBUG:' +
                              ' Detected InitiateMultipartUpload operation');
            } else if (query.uploadId && query.partNumber) {
                // PUT /{bucket}/{key}?partNumber=N&uploadId=ID = Upload Part
                s3Request.operation = 'UploadPart';
                s3Request.uploadId = query.uploadId;
                s3Request.partNumber = parseInt(query.partNumber, 10);
                req.log.debug({
                    uploadId: s3Request.uploadId,
                    partNumber: s3Request.partNumber
                }, 'S3_DEBUG: Detected UploadPart operation');
            } else if (query.uploadId && method === 'GET') {
                // GET /{bucket}/{key}?uploadId=ID = List Parts
                s3Request.operation = 'ListParts';
                s3Request.uploadId = query.uploadId;
                req.log.debug({
                    uploadId: s3Request.uploadId
                }, 'S3_DEBUG: Detected ListParts operation');
            } else if (query.uploadId && method === 'PUT' &&
                       !query.partNumber) {
                // PUT /{bucket}/{key}?uploadId=ID
                // (no partNumber) = Resume check
                s3Request.operation = 'ResumeUpload';
                s3Request.uploadId = query.uploadId;
                req.log.debug({
                    uploadId: s3Request.uploadId
                }, 'S3_DEBUG: Detected ResumeUpload operation');
            } else if (query.uploadId && method === 'POST') {
                // POST /{bucket}/{key}?uploadId=ID =
                // Complete Multipart Upload
                s3Request.operation = 'CompleteMultipartUpload';
                s3Request.uploadId = query.uploadId;
                req.log.debug({
                    uploadId: s3Request.uploadId
                }, 'S3_DEBUG: Detected CompleteMultipartUpload operation');
            } else if (query.uploadId && method === 'DELETE') {
                // DELETE /{bucket}/{key}?uploadId=ID =
                // Abort Multipart Upload
                s3Request.operation = 'AbortMultipartUpload';
                s3Request.uploadId = query.uploadId;
                req.log.debug({
                    uploadId: s3Request.uploadId
                }, 'S3_DEBUG: Detected AbortMultipartUpload operation');
            } else {
                // Regular object operations
                switch (method) {
                case 'GET':
                    s3Request.operation = 'GetBucketObject';
                    break;
                case 'PUT':
                    s3Request.operation = 'CreateBucketObject';
                    break;
                case 'HEAD':
                    s3Request.operation = 'HeadBucketObject';
                    break;
                case 'DELETE':
                    s3Request.operation = 'DeleteBucketObject';
                    break;
                case 'POST':
                    // POST without multipart query params
                    req.log.warn('S3_WARN:' +
                                 ' Unsupported POST operation for object:',
                                 method);
                    break;
                default:
                    // Log unexpected method but don't fail parsing
                    req.log.warn('S3_WARN:' +
                        ' Unexpected HTTP method in object operations:',
                                 method);
                    break;
                }
            }
        }
    }

    req.log.debug('S3_DEBUG_CONSOLE: parseS3Request final result:',
                  JSON.stringify(s3Request, null, 2));

    return (s3Request);
}

/*
 * convertS3ToMantaPath(s3Request, accountLogin)
 *
 * Arguments:
 *
 *     s3Request : s3Request object that contains the requested S3 operation and
 *                 metadata.
 *     accountLogin: Manta account for request, it's required as it is used
 *                   to construct a manta path to the resource.
 *
 *  Returns:
 *      A string that represents the Manta path to the requested resource.
 *      This should never return null.
 */
function convertS3ToMantaPath(s3Request, accountLogin) {
    assert.string(accountLogin, 'accountLogin');

    if (!s3Request.isS3Request) {
        return (null);
    }

    switch (s3Request.operation) {
        case 'ListBuckets':
            return ('/' + accountLogin + '/buckets');

        case 'CreateBucket':
        case 'HeadBucket':
        case 'DeleteBucket':
            return ('/' + accountLogin + '/buckets/' + s3Request.bucket);

        case 'ListBucketObjects':
        case 'ListBucketObjectsV2':
            return ('/' + accountLogin + '/buckets/' +
                    s3Request.bucket + '/objects');

        case 'CreateBucketObject':
        case 'GetBucketObject':
        case 'HeadBucketObject':
        case 'DeleteBucketObject':
            return ('/' + accountLogin + '/buckets/'
            + s3Request.bucket + '/objects/' + s3Request.object);

        default:
            return (null);
    }
}

/*
 * convertMantaToS3Headers(mantaHeaders, operation)
 * Arguments:
 *     mantaHeaders: Object with required manta headers.
 *     operation: S3 request operation
 *
 * Returns:
 *     Returns an object that contains the mandatory S3 headers
 *     for clients, using the supplied manta headers.
 *
 * Notes:
 *   Translates headers from a Manta response to the required S3 headers that
 *   clients expect.
 *   S3 clients expects the following AWS specific headers at a bare minimum:
 *
 *   - x-amz-request-id : Unique request ID for AWS support & tracing.
 *                        (We generate this if missing)
 *
 *   - x-amz-id-2:        Additional diagnostic token for AWS.
 *                        (We generate this if missing)
 *
 *   Manta metadata headers are passed as AWS S3 metadata headers, Manta metada-
 *   ta headers have the prefix m-, we convert whatever metadata Manta sents, to
 *   the expected metadata that S3 clients could understand.
 *
 *   - x-amz-meta-*:      Any user defined metadata
 *
 * References:
 *  - https://docs.aws.amazon.com/AmazonS3/latest/API/RESTCommonResponseHeaders\
 *      .html
 */
function convertMantaToS3Headers(mantaHeaders, operation) {
    var s3Headers = {};

    Object.keys(mantaHeaders).forEach(function (key) {
        var lowerKey = key.toLowerCase();
        var value = mantaHeaders[key];

        switch (lowerKey) {
            case 'content-type':
            case 'content-length':
            case 'etag':
            case 'last-modified':
                s3Headers[key] = value;
                break;

            // We passthrough S3-specific headers sent by S3 clients
            case 'x-amz-request-id':
            case 'x-amz-id-2':
                s3Headers[key] = value;
                break;

            // Convert Manta metadata to S3 metadata or handle other headers
            default:
                if (lowerKey.startsWith('m-')) {
                    var s3MetaKey = 'x-amz-meta-' + lowerKey.substring(2);
                    s3Headers[s3MetaKey] = value;
                }
                break;
        }
    });

    // Add S3-specific headers
    s3Headers['x-amz-request-id'] =
    s3Headers['x-amz-request-id'] || generateRequestId();
    s3Headers['x-amz-id-2'] = s3Headers['x-amz-id-2'] || generateHostId();

    return (s3Headers);
}

/*
 * convertMantaToS3Response(mantaBody, operation, s3Request, caller)
 *
 * Translates a Manta response into a S3 XML response or Bytes that s3 clients
 * could process.
 *
 * Arguments:
 *     mantaBody : Object with response data from a Manta request (Json| Bytes)
 *     operation : String with the S3 operation processed.
 *     s3Request : Object with S3 metadata.
 *     caller    : Object with account information for the Manta request.
 *
 * Returns :
 *   a XML string, an empty string or raw bytes depending on the
 *   operation argument, by default it just passes through the raw Manta
 *   response.
 *
 *  Notes :
 *     Only GetBucketObject returns Bytes
 *
 *      +------------------+-----------------+
 *      | S3 Operation     | Response Format |
 *      +------------------+-----------------+
 *      | ListBuckets      | S3 XML          |
 *      | ListBucketObjects| S3 XML          |
 *      | ListBucketObjects| S3 XML (V2)     |
 *      | CreateBucket     | Empty body      |
 *      | HeadBucket       | Empty body      |
 *      | DeleteBucket     | Empty body      |
 *      | CreateBucketObjec| Empty body      |
 *      | HeadBucketObject | Empty body      |
 *      | DeleteBucketObjec| Empty body      |
 *      | GetBucketObject  | Bytes           |
 *      +------------------+-----------------+
 *
 */
function convertMantaToS3Response(mantaBody, operation, s3Request, caller,
                                  paginationInfo) {

    switch (operation) {
        case 'ListBuckets':
            return (convertBucketListToS3(mantaBody, caller));

        case 'ListBucketObjects':
            return (convertObjectListToS3(mantaBody, s3Request.bucket,
                                          paginationInfo));

        case 'ListBucketObjectsV2':
            var v2Result = convertObjectListToS3V2(mantaBody, s3Request.bucket,
                                                   paginationInfo);
            return (v2Result);

        case 'CreateBucket':
        case 'HeadBucket':
        case 'DeleteBucket':
        case 'CreateBucketObject':
        case 'HeadBucketObject':
        case 'DeleteBucketObject':
            // AWS S3 operations that return empty bodies
            return ('');

        case 'GetBucketObject':
            // Object content passes through unchanged
            return (mantaBody);

        default:
          // return mantaBody unchanged
            return (mantaBody);
    }
}

/*
 * Helper functions that produce XML responses following AWS format.
 *
 *  +-----------------------+----------------------------------------------+
 *   | S3 Operation          | Reference Doc                                |
 *   +-----------------------+----------------------------------------------+
 *   | ListBuckets           | https://docs.aws.amazon.com/AmazonS3/latest/ |
 *   |                       | API/API_ListBuckets.html                     |
 *   | ListObjects (v1)      | https://docs.aws.amazon.com/AmazonS3/latest/ |
 *   |                       | API/API_ListObjects.html                     |
 *   | ListObjectsV2         | https://docs.aws.amazon.com/AmazonS3/latest/ |
 *   |                       | API/API_ListObjectsV2.html                   |
 *    | Error Response        | https://docs.aws.amazon.com/AmazonS3/latest/|
 *   |                       | API/ErrorResponses.html                      |
 *   +-----------------------+----------------------------------------------+
 *
 *   In the case of ListObjects, the legacy option is v1 most clients should
 *   use this one, but this has been deprecated in favour of v2, so v1 is here
 *   just for compatibility reasons.
 */

/**
 * Convert Manta bucket list to S3 XML format
 */
function convertBucketListToS3(mantaResponse, caller) {
    var buckets = Array.isArray(mantaResponse) ? mantaResponse :
    [mantaResponse];

    // Extract owner information from authenticated user
    var ownerID = 'manta-user'; // fallback
    var ownerDisplayName = 'Manta User'; // fallback

    if (caller && caller.account) {
        ownerID = caller.account.uuid || caller.account.login ||
        'manta-user';
        ownerDisplayName = caller.account.login || caller.account.cn ||
        'Manta User';
    }
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml +=
    '<ListAllMyBucketsResult'+
    ' xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n';
    xml += '  <Owner>\n';
    xml += '    <ID>' + escapeXml(ownerID) + '</ID>\n';
    xml += '    <DisplayName>' + escapeXml(ownerDisplayName) +
    '</DisplayName>\n';
    xml += '  </Owner>\n';
    xml += '  <Buckets>\n';

    buckets.forEach(function (bucket) {
        if (bucket && bucket.name) {
            xml += '    <Bucket>\n';
            xml += '      <Name>' + escapeXml(bucket.name) + '</Name>\n';
            xml += '      <CreationDate>' +
            (bucket.created || new Date().toISOString()) + '</CreationDate>\n';
            xml += '    </Bucket>\n';
        }
    });

    xml += '  </Buckets>\n';
    xml += '  <IsTruncated>false</IsTruncated>\n';
    xml += '</ListAllMyBucketsResult>\n';

    return (xml);
}

/**
 * Convert Manta object list to S3 XML format (ListObjects v1)
 */
function convertObjectListToS3(mantaResponse, bucketName, paginationInfo) {
    // Handle edge cases
    if (!bucketName) {
        throw new Error('Bucket name is required for' +
        ' ListBucketObjects conversion');
    }

    var objects = Array.isArray(mantaResponse) ?
                             mantaResponse : [mantaResponse];

    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml +=
    '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n';
    xml += '  <Name>' + escapeXml(bucketName) + '</Name>\n';
    xml += '  <Prefix></Prefix>\n';
    xml += '  <Marker></Marker>\n';
    xml += '  <MaxKeys>1000</MaxKeys>\n';

    /*
     * Every object MUST have an etag, the hardcoded hash
     * is the MD5 checksum of an empty string, this is just a fallback
     * just to mantain compatibility with S3 clients.
     */

    objects.forEach(function (obj) {
        if (obj && obj.name) {
            xml += '  <Contents>\n';
            xml += '    <Key>' + escapeXml(decodeURIComponent(obj.name)) +
                '</Key>';
            xml += '    <LastModified>' +
            (obj.mtime || new Date().toISOString())
            + '</LastModified>\n';
            xml += '    <ETag>"' + (obj.etag ||
            'd41d8cd98f00b204e9800998ecf8427e') + '"</ETag>\n';
            xml += '    <Size>' + (obj.size || 0) + '</Size>\n';
            xml += '    <StorageClass>STANDARD</StorageClass>\n';
            xml += '  </Contents>\n';
        }
    });

    // Add pagination info per AWS S3 spec
    var isTruncated = paginationInfo && paginationInfo.isTruncated ? 'true' :
        'false';
    xml += '  <IsTruncated>' + isTruncated + '</IsTruncated>\n';
    if (paginationInfo && paginationInfo.nextMarker) {
        xml += '  <NextMarker>' + escapeXml(paginationInfo.nextMarker) +
            '</NextMarker>\n';
    }
    xml += '</ListBucketResult>\n';

    return (xml);
}

/**
 * Convert Manta object list to S3 XML format (ListObjectsV2)
 */
function convertObjectListToS3V2(mantaResponse, bucketName, paginationInfo) {
    var objects = Array.isArray(mantaResponse) ?
    mantaResponse : [mantaResponse];
    // Count valid objects first
    var objectCount = 0;
    var validObjects = [];
    objects.forEach(function (obj) {
        if (obj && obj.name) {
            objectCount++;
            validObjects.push(obj);
        }
    });

    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml +=
    '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n';
    xml += '  <Name>' + escapeXml(bucketName) + '</Name>\n';
    xml += '  <Prefix></Prefix>\n';
    xml += '  <StartAfter></StartAfter>\n';
    xml += '  <MaxKeys>1000</MaxKeys>\n';
    xml += '  <KeyCount>' + objectCount + '</KeyCount>\n';
    // Add object contents
    validObjects.forEach(function (obj) {
        xml += '  <Contents>\n';
        xml += '    <Key>' + escapeXml(decodeURIComponent(obj.name)) +
            '</Key>';
        xml += '    <LastModified>' +
        (obj.mtime || new Date().toISOString()) + '</LastModified>\n';
        xml += '    <ETag>"' + (obj.etag ||
        'd41d8cd98f00b204e9800998ecf8427e') + '"</ETag>\n';
        xml += '    <Size>' + (obj.size || 0) + '</Size>\n';
        xml += '    <StorageClass>STANDARD</StorageClass>\n';
        xml += '  </Contents>\n';
    });

    // Add pagination info per AWS S3 ListObjectsV2 spec
    var isTruncated = paginationInfo && paginationInfo.isTruncated ? 'true' :
        'false';
    xml += '  <IsTruncated>' + isTruncated + '</IsTruncated>\n';
    if (paginationInfo && paginationInfo.nextMarker) {
        // ListObjectsV2 uses NextContinuationToken, not NextMarker
        xml += '  <NextContinuationToken>' +
            escapeXml(paginationInfo.nextMarker) +
            '</NextContinuationToken>\n';
    }
    xml += '</ListBucketResult>\n';

    return (xml);
}

/**
 * convertErrorToS3(error, s3Request)
 * Generates a generic XML response in case of an error.
 * Arguments:
 *     error     : Error object.
 *     s3Request : S3 metadata for the failed request.
 * Returns:
 *     XML string with error code + message for S3 clients.
 */
function convertErrorToS3(error, s3Request, req) {

    if (req && req.log) {
        req.log.warn({
            errorName: error.name,
            errorMessage: error.message,
            errorRestCode: error.restCode,
            isMultiError: error.name === 'MultiError',
            hasErrors: error.errors ? error.errors.length : 0,
            hasAres: error.ase_errors ? error.ase_errors.length : 0,
            hasCauses: error.jse_cause ? 1 : 0,
            errorProperties: Object.keys(error || {}),
            s3Operation: s3Request ? s3Request.operation : 'unknown'
        }, 'S3_DEBUG: convertErrorToS3 called ' +
           ' with detailed MultiError analysis');

        // Log the actual error structure for debugging
        if (error.name === 'MultiError') {
            req.log.warn({
                errorKeys: Object.keys(error),
                errorProto: Object.getPrototypeOf(error).constructor.name,
                errorToString: error.toString(),
                errorCause: error.jse_cause ? error.jse_cause.name : 'none',
                errorAseErrors: error.ase_errors ? error.ase_errors.length : 0
            }, 'S3_DEBUG: MultiError deep structure analysis');
        }
    }

    // If the error is already in well-formed XML, pass it on
    if (isWellFormedXML(error.message)) {
        return (error.message);
    }

    // Handle MultiError by extracting the first cause that has proper
    // error codes
    var actualError = error;
    if (error.name === 'MultiError') {
        // MultiError can store errors in different properties
        // depending on the library version
        var errorList = error.errors || error.ase_errors || [];
        var causeError = error.jse_cause;

        if (req && req.log) {
            req.log.debug({
                errorListLength: errorList.length,
                hasCause: !!causeError,
                causeName: causeError ? causeError.name : 'none',
                causeRestCode: causeError ? causeError.restCode : 'none',
                firstErrorName: errorList[0] ? errorList[0].name : 'none',
                firstErrorRestCode: errorList[0] ?
                    errorList[0].restCode : 'none'
            }, 'S3_DEBUG: Processing MultiError with multiple access paths');
        }

        // Check if there's a direct cause (jse_cause)
        if (causeError) {
            // Recursively unwrap if the cause is also a MultiError
            if (causeError.name === 'MultiError') {
                // Preserve status code before recursive call
                if (causeError.statusCode) {
                    error.statusCode = causeError.statusCode;
                }
                // Recursively process nested MultiError to find the root error
                var xmlResult = convertErrorToS3(causeError, s3Request, req);
                return (xmlResult);
            } else if (causeError.restCode ||
                       (causeError.name && causeError.name !== 'Error')) {
                actualError = causeError;
                if (req && req.log) {
                    req.log.debug({
                        selectedErrorName: actualError.name,
                        selectedErrorRestCode: actualError.restCode,
                        selectedErrorMessage: actualError.message
                    }, 'S3_DEBUG: Selected cause error from MultiError');
                }
            }
        }

        // If no cause or cause wasn't useful, check the error list
        if (actualError === error && errorList.length > 0) {
            // Look for the first error with a restCode or proper name
            for (var i = 0; i < errorList.length; i++) {
                var subError = errorList[i];
                if (subError.restCode ||
                    (subError.name && subError.name !== 'Error')) {
                    actualError = subError;
                    if (req && req.log) {
                        req.log.debug({
                            selectedErrorName: actualError.name,
                            selectedErrorRestCode: actualError.restCode,
                            selectedErrorMessage: actualError.message
                        }, 'S3_DEBUG:' +
                           ' Selected specific error from MultiError list');
                    }
                    break;
                }
            }
            // If no specific error found, use the first one
            if (actualError === error && errorList[0]) {
                actualError = errorList[0];
                if (req && req.log) {
                    req.log.debug('S3_DEBUG:' +
                       ' Using first error from MultiError list as fallback');
                }
            }
        }
    }

    var errorCode = actualError.restCode || actualError.name || 'InternalError';
    var s3Error = S3_ERROR_RESPONSES[errorCode] ||
    S3_ERROR_RESPONSES['InternalError'];

    if (req && req.log) {
        req.log.debug({
            finalErrorCode: errorCode,
            s3ErrorCode: s3Error.code,
            foundInMapping: !!S3_ERROR_RESPONSES[errorCode]
        }, 'S3_DEBUG: Final error mapping result');
    }

    // Ensure s3Request is defined
    s3Request = s3Request || {};

    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<Error>\n';
    xml += '  <Code>' + escapeXml(s3Error.code) + '</Code>\n';
    // Use the most descriptive message available
    // For MultiError, prefer the specific underlying error message
    // For regular errors, use the original message
    var errorMessage;
    if (error.name === 'MultiError' &&
        actualError !== error && actualError.message) {
        // Use specific underlying error message
        errorMessage = actualError.message;
    } else {
        // Use original message
        errorMessage = error.message || s3Error.description;
    }
    xml += '  <Message>' + escapeXml(errorMessage) + '</Message>\n';

    if (s3Request.bucket) {
        xml += '  <BucketName>' + escapeXml(s3Request.bucket) +
        '</BucketName>\n';
    }

    if (s3Request.object) {
        xml += '  <Key>' + escapeXml(s3Request.object) + '</Key>\n';
    }

    xml += '  <RequestId>' + generateRequestId() + '</RequestId>\n';
    xml += '  <HostId>' + generateHostId() + '</HostId>\n';
    xml += '</Error>\n';

    // Preserve status code from underlying error
    // (important for EntityTooSmall, etc.)
    if (actualError !== error && actualError.statusCode) {
        error.statusCode = actualError.statusCode;
        if (req && req.log) {
            req.log.debug({
                originalStatusCode: error.statusCode,
                preservedFromActualError: actualError.statusCode,
                actualErrorName: actualError.name
            }, 'S3_DEBUG: Preserved status code from underlying error');
        }
    } else if (actualError === error && error.name === 'MultiError') {
        // For MultiError cases where we couldn't extract underlying error,
        // but we know it should be a client error based on error mapping
        var s3ErrorForStatus = S3_ERROR_RESPONSES[errorCode];
        if (s3ErrorForStatus && s3ErrorForStatus.httpStatusCode &&
            s3ErrorForStatus.httpStatusCode !== 500) {
            error.statusCode = s3ErrorForStatus.httpStatusCode;
            if (req && req.log) {
                req.log.debug({
                    errorCode: errorCode,
                    mappedStatusCode: s3ErrorForStatus.httpStatusCode
                }, 'S3_DEBUG: Set status code from S3 error mapping');
            }
        }
    }

    return (xml);
}

/**
 * Utility functions
 */
/* BEGIN JSSTYLED */
function escapeXml(str) {
    if ((typeof (str)) !== 'string') {
        return (str);
    }
    return str.replace(/[<>&'"]/g, function (c) {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
            default: return c;
        }
    });
}
/* END JSSTYLED */

function generateRequestId() {
    return (crypto.randomBytes(8).toString('hex').toUpperCase());
}

function generateHostId() {
    // Generate a host ID without potentially problematic characters
    return (crypto.randomBytes(16).toString('hex').toUpperCase());
}

/*
 * isWellFormedXML(xmlString)
 * Validates if xmlString is a valid XML.
 * Arguments:
 *     xmlString : String representing a XML
 * Returns:
 *     true  if XML is valid.
 *     false if XML is not valid.
 */
function isWellFormedXML(xmlString) {
    if (!xmlString || (typeof (xmlString)) !== 'string') {
        return (false);
    }

    // Check basic XML structure
    var trimmed = xmlString.trim();

    // Must start with XML declaration or root element
    if (!trimmed.startsWith('<?xml') && !trimmed.startsWith('<')) {
        return (false);
    }

    // Must end with a closing tag
    if (!trimmed.endsWith('>')) {
        return (false);
    }

    // Check for basic tag balance (simple heuristic)
    /* BEGIN JSSTYLED */
    var openTags = (trimmed.match(/</g) || []).length;
    var closeTags = (trimmed.match(/>/g) || []).length;
    /* END JSSTYLED */
    // Should have equal number of < and > characters
    if (openTags !== closeTags) {
        return (false);
    }

    return (true);
}

/*
 * ensureWellFormedXML(xmlString)
 * Ensure XML is well-formed by fixing common issues
 * Arguments:
 *     xmlString: String representing an XML document.
 * Returns:
 *     Valid XML string
 * Notes:
 *
 *     In case xmlString is not of type string or is undefined
 *     a generic XML error response is returned.
 *
 *     By default it returns the XML document passed as input fixed if the
 *     document has an error.
 */
function ensureWellFormedXML(xmlString) {
    if (!xmlString || (typeof (xmlString)) !== 'string') {
        return ('<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>' +
                'InternalError</Code><Message>Invalid XML</Message></Error>');
    }

    var fixed = xmlString.trim();

    // Ensure proper XML declaration
    if (!fixed.startsWith('<?xml')) {
        fixed = '<?xml version="1.0" encoding="UTF-8"?>\n' + fixed;
    }

    // Ensure proper ending
    if (!fixed.endsWith('>')) {
        fixed += '\n';
    }

    // Remove any null bytes or control characters that might cause issues
    fixed = fixed.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

    return (fixed);
}

///--- Middleware Functions

/**
 * S3 Request Detection and Translation Middleware
 */
function s3RequestDetector(req, res, next) {
    req.log.debug('s3RequestDetector: checking request format');

    var s3Request = parseS3Request(req);
    req.s3Request = s3Request;

    if (s3Request.isS3Request) {
        req.log.debug({
            s3Request: s3Request
        }, 's3RequestDetector: detected S3 request');

        // Mark this as an S3 request for response formatting
        req.isS3Request = true;
        res.s3Request = s3Request;
    }

    next();
}

/**
 * S3 Path Translation Middleware
 */
function s3PathTranslator(req, res, next) {
    if (!req.s3Request || !req.s3Request.isS3Request) {
        next();
        return;
    }

    // Need account information from authentication
    if (!req.caller || !req.caller.account) {
        req.log.debug('s3PathTranslator: no account information available');
        next();
        return;
    }

    var accountLogin = req.caller.account.login;
    var mantaPath = convertS3ToMantaPath(req.s3Request, accountLogin);

    if (mantaPath) {
        req.log.debug({
            originalPath: req.path(),
            mantaPath: mantaPath,
            s3Request: req.s3Request
        }, 's3PathTranslator: converted S3 path to Manta path');

        // Store original path and rewrite to Manta format
        req.originalPath = req.path();
        req.url = mantaPath + (req.query ? '?' +
        Object.keys(req.query).map(function (k) {
            return (k + '=' + encodeURIComponent(req.query[k]));
        }).join('&') : '');

        // Update params for route matching
        req.params.account = accountLogin;
        if (req.s3Request.bucket) {
            req.params.bucket_name = req.s3Request.bucket;
        }
        if (req.s3Request.object) {
            req.params.object_name = req.s3Request.object;
        }
    }

    next();
}

/*
 * s3ResponseFormatter(req, res, next)
 * Converts Manta's JSON responses to S3's expected XML format and adds the
 * required headers that S3 clients expects.
 * Arguments:
 *     req:   HTTP request object, that contains S3 metadata.
 *     res:   HTTP response object.
 *     next:  next middleware function
 * Returns:
 *  Dependending of the S3 requested operation it can return
 *  (see convertMantaToS3Response ):
 *  - XML string representing a succesful response or an Error.
 *  - Bytes
 */

function s3ResponseFormatter(req, res, next) {

    /*
     * We need to skip non S3 requests and let the chain complete
     */
    if (!req.isS3Request) {
        req.log.debug('s3ResponseFormatter: skipping non S3 request');
        next();
        return;
    }


    // For binary operations marked to skip S3 processing,
    // completely bypass S3 formatting
    // CreateBucket error already is XML
    if (req._skipS3ResponseProcessing ||
        req.s3Request.operation === 'CreateBucket' ||
        req.s3Request.operation === 'DeleteBucket' ||
        req.s3Request.operation === 'HeadBucket' ||
        req.s3Request.operation === 'HeadBucketObject' ||
        req._binaryUpload || req._binaryOperation) {
        req.log.debug('s3ResponseFormatter: skipping '+
                      'ALL S3 processing for binary operation');
        next();
        return;
    }

    // For object operations (uploads and downloads), just add S3 headers
    // Binary data preservation is now handled by server-level formatters
    if (req.s3Request && (req.s3Request.operation === 'GetBucketObject' ||
    req.s3Request.operation === 'CreateBucketObject')) {
        req.log.debug('s3ResponseFormatter: object operation - '+
        'adding S3 headers only (binary preservation handled by server'+
        ' formatters)');

        // Store original writeHead to add S3 headers
        var originalWriteHead = res.writeHead;
        res.writeHead = function (statusCode, headers) {
            // Add S3 headers
            headers = headers || {};
            headers['x-amz-request-id'] = generateRequestId();
            headers['x-amz-id-2'] = generateHostId();
            return (originalWriteHead.call(this, statusCode, headers));
        };

        next();
        return;
    }

    req.log.debug('s3ResponseFormatter: formatting response for S3');

    // Intercept the response
    var originalSend = res.send;
    originalWriteHead = res.writeHead;
    var originalWrite = res.write;
    var originalEnd = res.end;
    var originalSet = res.set;

    res.writeHead = function (statusCode, headers) {
        if (req.isS3Request && headers) {
            // Convert headers to S3 format
            var s3Headers = convertMantaToS3Headers(headers,
            req.s3Request.operation);
            return (originalWriteHead.call(this, statusCode, s3Headers));
        }
        return (originalWriteHead.call(this, statusCode, headers));
    };

    // Intercept res.set() for HEAD operations that use it directly
    res.set = function (key, value) {
        if (req.isS3Request && typeof (key) === 'string') {
            var lowerKey = key.toLowerCase();
            // Convert Manta metadata headers to S3 format
            if (lowerKey.startsWith('m-')) {
                var s3MetaKey = 'x-amz-meta-' + lowerKey.substring(2);
                return (originalSet.call(this, s3MetaKey, value));
            }
        }
        return (originalSet.call(this, key, value));
    };

    // Also intercept streaming responses for ListObjects
    var responseData = [];

    res.write = function (chunk) {
        if (req.isS3Request && req.s3Request.operation !== 'GetBucketObject') {
            // Only collect streaming data for list operations,
            // not object downloads
            if (chunk) {
                responseData.push(chunk);
                req.log.debug({
                    chunkLength: chunk.length,
                    totalChunks: responseData.length
                }, 'S3_DEBUG: s3ResponseFormatter - collected streaming chunk');
            }
            return (true); // Pretend write was successful
        }
        return (originalWrite.call(this, chunk));
    };

    res.end = function (endChunk) {
        if (req.isS3Request && req.s3Request.operation !== 'GetBucketObject') {
            // Only process non-object responses that need XML conversion
            if (endChunk) {
                responseData.push(endChunk);
            }

            // Process streaming data OR handle empty bucket
            // case for S3 requests
            if (responseData.length > 0 || req.isS3Request) {
                req.log.debug({
                    totalChunks: responseData.length
                }, 'S3_DEBUG: s3ResponseFormatter - '+
                'processing streaming response');

                // Combine all response data
                var combinedData;
                var responseText = '';
                var jsonData = [];

                if (responseData.length > 0) {
                    combinedData = Buffer.
                        concat(responseData.map(function (chunk) {
                        return Buffer.isBuffer(chunk) ? chunk :
                        Buffer.from(chunk.toString());
                    }));
                    responseText = combinedData.toString();

                    // If the response is already a well-formed S3 error XML,
                    // send it directly without trying to parse as JSON.
                    if (isWellFormedXML(responseText) &&
                        responseText.includes('<Error>')) {
                        req.log.debug('S3_DEBUG: s3ResponseFormatter - ' +
                                      'detected pre-formatted XML error,' +
                                      ' sending directly.');
                        if (!res.headersSent) {
                            // Use existing status code or default to 400
                            var statusCode = res.statusCode >= 400 ?
                                res.statusCode : 400;
                            res.writeHead(statusCode, {
                                'Content-Type': 'application/xml',
                                'Content-Length':
                                Buffer.byteLength(responseText, 'utf8'),
                                'x-amz-request-id': generateRequestId(),
                                'x-amz-id-2': generateHostId()
                            });
                        }
                        originalWrite.call(this, responseText, 'utf8');
                        return (originalEnd.call(this));
                    }
                    // Handle newline-delimited JSON
                    // (common in Manta streaming responses)
                    var lines = responseText.trim().split('\n');
                    lines.forEach(function (line) {
                        if (line.trim()) {
                            try {
                                jsonData.push(JSON.parse(line));
                            } catch (e) {
                                req.log.warn({
                                    line: line,
                                    error: e.message
                                }, 'S3_WARN: s3ResponseFormatter'+
                                ' - failed to parse JSON line');
                            }
                        }
                    });
                } else {
                    // Empty bucket case - no streaming data
                    req.log.debug('S3_DEBUG: s3ResponseFormatter - '+
                    'handling empty bucket response');
                    jsonData = []; // Empty array for empty bucket
                }

                // Convert to S3 XML format
                var xmlResponse;
                try {
                    req.log.debug({
                        jsonObjectCount: jsonData.length,
                        operation: req.s3Request.operation,
                        bucketName: req.s3Request.bucket,
                        sampleJsonData: jsonData.length > 0 ? jsonData[0] :
                        'none',
                        s3RequestDebug: req.s3Request
                    }, 'S3_DEBUG: s3ResponseFormatter -'+
                    ' about to convert streaming JSON to S3 XML');

                    // Skip XML conversion for operations
                    // that should return empty responses
                    var emptyResponseOperations =
                        ['UploadPart', 'DeleteObject', 'PutObject',
                         'AbortMultipartUpload', 'DeleteBucketObject'];
                    if (emptyResponseOperations.
                        indexOf(req.s3Request.operation) !== -1) {
                        req.log.debug({
                            operation: req.s3Request.operation
                        }, 'S3_DEBUG: Skipping XML conversion' +
                                      ' for empty response operation');

                        // For these operations,
                        // just pass through without XML conversion
                        originalEnd.call(this);
                        return;
                    }

                    // Extract pagination info from response headers
                    var paginationInfo = null;
                    var nextMarker = this.getHeader('Next-Marker');

                    // Pagination is active if we have a marker
                    if (nextMarker !== undefined) {
                        paginationInfo = {
                            isTruncated: true,
                            nextMarker: nextMarker
                        };
                    }

                    xmlResponse = convertMantaToS3Response(jsonData,
                    req.s3Request.operation, req.s3Request, req.caller,
                                                           paginationInfo);

                    req.log.debug({
                        jsonObjectCount: jsonData.length,
                        xmlLength: xmlResponse ? xmlResponse.length : 0,
                        xmlPreview: (xmlResponse &&
                                     typeof (xmlResponse) === 'string') ?
                            xmlResponse.substring(0, 200) : 'null',
                        operation: req.s3Request.operation,
                        bucketName: req.s3Request.bucket
                    }, 'S3_DEBUG: s3ResponseFormatter -'+
                    ' converted streaming JSON to S3 XML');

                    // Validate XML response
                    if (xmlResponse === null || xmlResponse === undefined ||
                        (typeof (xmlResponse)) !== 'string') {
                        throw new Error('Invalid XML response generated: '
                        + (typeof (xmlResponse)) + ', value: '
                        + JSON.stringify(xmlResponse));
                    }

                    if (xmlResponse.length < 10) {
                        throw new Error('XML response too short: '
                        + xmlResponse.length + ' chars, content: '
                        + JSON.stringify(xmlResponse));
                    }

                    // Ensure XML is well-formed for strict parsers
                    // while maintaining compatibility with lenient
                    // parsers like AWS CLI
                    if (!isWellFormedXML(xmlResponse)) {
                        req.log.warn({
                            xmlLength: xmlResponse.length,
                            xmlPreview: (typeof (xmlResponse) === 'string') ?
                                xmlResponse.substring(0, 200) : 'not-string'
                        }, 'S3_DEBUG: XML response is not well-formed, fixing');
                        xmlResponse = ensureWellFormedXML(xmlResponse);
                    }

                } catch (conversionError) {
                    req.log.error({
                        error: conversionError.message,
                        jsonData: jsonData,
                        operation: req.s3Request.operation
                    }, 'S3_DEBUG: s3ResponseFormatter -'+
                    ' XML conversion failed, falling back to error response');

                    // Generate error XML response
                    xmlResponse = '<?xml version="1.0" encoding="UTF-8"?>\n' +
                        '<Error>\n' +
                        '  <Code>InternalError</Code>\n' +
                        '  <Message>Error converting response'+
                        ' to XML format</Message>\n' +
                        '  <RequestId>' + generateRequestId()
                        + '</RequestId>\n' +
                        '</Error>';
                }

                // Send S3 XML response
                if (!res.headersSent) {
                    res.writeHead(200, {
                        'Content-Type': 'application/xml',
                        'Content-Length': Buffer.byteLength(xmlResponse,
                        'utf8'),
                        'x-amz-request-id': generateRequestId(),
                        'x-amz-id-2': generateHostId()
                    });
                }

                try {
                    // Ensure proper content-length for the final XML
                    var xmlBuffer = Buffer.from(xmlResponse, 'utf8');
                    if (!res.headersSent) {
                        res.setHeader('Content-Length', xmlBuffer.length);
                    }

                    originalWrite.call(this, xmlBuffer);
                    originalEnd.call(this);

                    req.log.debug({
                        xmlResponseLength: xmlBuffer.length,
                        finalXmlPreview: (typeof (xmlResponse) === 'string') ?
                            (xmlResponse.substring(0, 200) +
                            (xmlResponse.length > 200 ? '...' : '')) :
                            'not-string'
                    }, 'S3_DEBUG: Successfully sent well-formed XML response');

                } catch (writeError) {
                    req.log.error({
                        error: writeError.message,
                        xmlResponseType: (typeof (xmlResponse)),
                        xmlResponseLength: xmlResponse ?
                        xmlResponse.length : 'undefined'
                    }, 'S3_DEBUG: s3ResponseFormatter -'+
                    ' failed to write XML response');
                    // Try to send a basic error response
                    originalEnd.call(this);
                }
                return;
            }
        }
        return (originalEnd.call(this, endChunk));
    };

    res.send = function (code, data) {
        if (req.isS3Request) {
            // Handle the case where error is passed
            // as first argument (code position)
            var actualCode = code;
            var actualData = data;

            // If code is an Error object, treat
            // it as an error response with 500 status
            if (code instanceof Error) {
                actualCode = code.statusCode || 500;
                actualData = code;
            }
            // If code is not a number, assume it's data with 200 status
            else if ((typeof (code)) !== 'number') {
                actualCode = 200;
                actualData = code;
            }

            req.log.debug({
                originalCode: code,
                originalData: data,
                actualCode: actualCode,
                actualDataType: (typeof (actualData)),
                isError: actualData instanceof Error,
                operation: req.s3Request ? req.s3Request.operation : 'unknown'
            }, 'S3_DEBUG: s3ResponseFormatter -'+
            ' converting response to S3 format');

            var contentType = 'application/xml';
            var responseBody;

            // Handle errors
            if (actualData instanceof Error ||
            ((typeof (actualCode)) === 'number' && actualCode >= 400)) {
                req.log.debug('S3_DEBUG: s3ResponseFormatter'+
                ' - handling error response');
                responseBody = convertErrorToS3(actualData ||
                new Error('Unknown error'), req.s3Request, req);
                res.setHeader('Content-Type', contentType);
            } else {
                // Handle successful responses
                req.log.debug('S3_DEBUG: s3ResponseFormatter -'+
                ' handling success response');

                // For GetBucketObject, the data stream has already been
                // handled by streamFromSharks
                // We should not interfere with the streaming response
                if (req.s3Request.operation === 'GetBucketObject') {
                    req.log.debug('S3_DEBUG: s3ResponseFormatter'+
                    ' - GetBucketObject response already streamed,'+
                    ' skipping XML conversion');
                    // Set appropriate S3 headers but don't interfere with
                    // the streaming response
                    if (!res.headersSent) {
                        res.setHeader('x-amz-request-id', generateRequestId());
                        res.setHeader('x-amz-id-2', generateHostId());
                    }
                    // Let the original send method handle the response
                    // as-is for object downloads
                    return (originalSend.call(this, code, data));
                }

                try {
                    // Extract pagination info from response headers
                    var paginationInfo = null;
                    var nextMarker = this.getHeader('Next-Marker');

                    // Pagination is active if we have a marker
                    if (nextMarker !== undefined) {
                        paginationInfo = {
                            isTruncated: true,
                            nextMarker: nextMarker
                        };
                    }

                    responseBody = convertMantaToS3Response(actualData,
                    req.s3Request.operation, req.s3Request, req.caller,
                                                             paginationInfo);
                    req.log.debug({
                        dataLength: Array.isArray(actualData) ?
                        actualData.length : 'not-array',
                        xmlLength: responseBody ? responseBody.length : 0
                    }, 'S3_DEBUG: XML conversion successful');
                } catch (xmlError) {
                    req.log.error({
                        error: xmlError.message,
                        data: actualData,
                        operation: req.s3Request.operation
                    }, 'S3_DEBUG: XML conversion failed');
                    responseBody = convertErrorToS3(xmlError,
                                                    req.s3Request, req);
                    res.setHeader('Content-Type', contentType);
                    return (originalSend.call(this, 500, responseBody));
                }

                // Set content type for non-object responses (XML responses)
                res.setHeader('Content-Type', contentType);
            }

            // Only process XML responses (not GetBucketObject
            // which was already handled above)
            if (responseBody) {
                // Clear any existing Content-Length that
                // might conflict with XML response
                res.removeHeader('Content-Length');
                res.removeHeader('Content-MD5');

                // Add S3-specific headers
                res.setHeader('x-amz-request-id', generateRequestId());
                res.setHeader('x-amz-id-2', generateHostId());

                // Handle both string and non-string response bodies for logging
                var logResponseBody = '';
                var responseLength = 0;

                if ((typeof (responseBody)) === 'string') {
                    logResponseBody = responseBody.substring(0, 1000) +
                    (responseBody.length > 1000 ? '...[truncated]' : '');
                    responseLength = responseBody.length;
                } else if (responseBody && (typeof (responseBody))
                === 'object') {
                    logResponseBody =
                    JSON.stringify(responseBody).substring(0, 1000) +
                    '...[object]';
                    responseLength = JSON.stringify(responseBody).length;
                } else {
                    logResponseBody = String(responseBody);
                    responseLength = String(responseBody).length;
                }

                req.log.debug({
                    httpStatusCode: actualCode,
                    responseBodyLength: responseLength,
                    responseBodyType: (typeof (responseBody)),
                    contentType: contentType,
                    operation: req.s3Request ?
                    req.s3Request.operation : 'unknown',
                    bucket: req.s3Request ? req.s3Request.bucket : 'unknown',
                    headers: {
                        'content-type': res.getHeader('content-type'),
                        'content-length': res.getHeader('content-length'),
                        'x-amz-request-id': res.getHeader('x-amz-request-id'),
                        'x-amz-id-2': res.getHeader('x-amz-id-2')
                    },
                    xmlResponse: logResponseBody
                }, 'S3_DEBUG: s3ResponseFormatter - '+
                'sending response for s3tests compatibility');

                // Ensure responseBody is a string for S3 responses
                var finalResponseBody = '';
                if ((typeof (responseBody)) === 'string') {
                    finalResponseBody = responseBody;
                } else if (responseBody && (typeof (responseBody)) ===
                'object') {
                    finalResponseBody = JSON.stringify(responseBody);
                } else {
                    finalResponseBody = String(responseBody || '');
                }

                // Bypass JSON formatting by using writeHead
                // and end directly for S3 responses
                res.writeHead(actualCode, {
                    'Content-Type': contentType,
                    'Content-Length': Buffer.byteLength(finalResponseBody,
                    'utf8'),
                    'x-amz-request-id': res.getHeader('x-amz-request-id'),
                    'x-amz-id-2': res.getHeader('x-amz-id-2')
                });
                originalWrite.call(this, finalResponseBody, 'utf8');
                originalEnd.call(this);
                return;
            }
        }

        return (originalSend.call(this, code, data));
    };

    next();
}

/*
 * s3HeaderTranslator(req, res, next)
 * Middleware to convert metadata Manta headers to S3 metadata headers.
 * Arguments :
 *     req:  HTTP request.
 *     res:  HTTP response.
 *     next: next middleware function
 * Returns:
 *     None
 */
function s3HeaderTranslator(req, res, next) {
    if (!req.isS3Request) {
        next();
        return;
    }

    req.log.debug('s3HeaderTranslator: translating S3 headers to Manta format');

    // Convert S3 metadata headers to Manta format
    Object.keys(req.headers).forEach(function (key) {
        var lowerKey = key.toLowerCase();

        if (lowerKey.startsWith('x-amz-meta-')) {
            // Convert S3 metadata to Manta metadata
            var mantaKey = 'm-' +
            lowerKey.substring(11); // Remove 'x-amz-meta-'
            req.headers[mantaKey] = req.headers[key];
            delete req.headers[key];
        }
    });

    next();
}

/*
 * s3ConditionalHeaders(req, res, next)
 * Converts S3 conditional headers to Manta conditional headers, Manta already
 * support conditional headers, so we leverage this feature by converting the
 * incoming S3 conditional headers to their equivalents in Manta.
 * Arguments:
 *     req:    HTTP request.
 *     res:    HTTP response.
 *     next:   Middleware next function.
 * Notes:
 *     Extracts S3 conditional headers and populates req.conditions
 */
function s3ConditionalHeaders(req, res, next) {
    if (!req.isS3Request) {
        next();
        return;
    }

    req.log.debug('s3ConditionalHeaders: processing S3 conditional headers');

    // Initialize conditions object if it doesn't exist
    req.conditions = req.conditions || {};

    // Extract S3 conditional headers and map to Manta format
    var conditionalHeaders = {
        'if-match': req.headers['if-match'],
        'if-none-match': req.headers['if-none-match'],
        'if-modified-since': req.headers['if-modified-since'],
        'if-unmodified-since': req.headers['if-unmodified-since']
    };

    // Populate req.conditions with non-empty values
    Object.keys(conditionalHeaders).forEach(function (header) {
        var value = conditionalHeaders[header];
        if (value) {
            req.conditions[header] = value;
            req.log.debug({
                header: header,
                value: value
            }, 's3ConditionalHeaders: mapped conditional header');
        }
    });

    req.log.debug({
        conditions: req.conditions
    }, 's3ConditionalHeaders: final conditions object');

    next();
}

/*
 * s3RoleTranslator(req, res, next)
 * Converts S3 ACL headers to Manta role-tag headers
 * Arguments:
 *     req:    HTTP request object containing S3 ACL headers.
 *     res:    HTTP response object.
 *     next:   Middleware next function.
 * Returns:
 *     None
 * Notes:
 *    This function adds the following properties to req.
 *    - _s3AclOperation : true if we are processing an ACL operation.
 *    - _s3AclRoles     : Array of Manta Roles translated from S3 ACL.
 *    - role-tag        : Comma separated string of Manta roles.
 *
 * Canned ACLs:
 * The value of the x-amz-acl header has the name of the canned ACL to enforce
 * on the resource. Today we only support the following canned ACLs that are
 * mapped to Manta roles that have the same name,through the S3_ACL_TO_MANTA_-
 * ROLES object .
 * +-------------------+--------------+-------------------------------+
 * | Canned ACL        | Applies to   | Permissions                   |
 * +-------------------+--------------+-------------------------------+
 * | private           | Bucket,Object| Owner FULL_CONTROL only.      |
 * | public-read       | Bucket,Object| Owner FULL_CONTROL, AllUsers  |
 * |                   |              | READ.                         |
 * +-------------------+--------------+-------------------------------+
 *
 * Grant Headers:
 *  if any of these headers comes, then parseS3GranToRoles will return
 *  the appropiate role.
 *  +-------------------+----------------+----------------------+--------------+
 *  | Header            | Purpose        | Scope                | Manta Role   |
 *  +-------------------+----------------+----------------------+--------------+
 *  | x-amz-grant-read  | Grant READ     | Buckets: list objs.  | public-reader|
 *  |                   | access         | Objects: read data & | auth-reader  |
 *  |                   |                | ACL                  |              |
 *  +-------------------+----------------+----------------------+--------------+
 *  | x-amz-grant-write | Grant WRITE    | Buckets only: upload | public-writer|
 *  |                   | access         | or delete objects.   | auth-writer  |
 *  +-------------------+----------------+----------------------+--------------+
 *  | x-amz-grant-full- | Grant FULL_    | Buckets: list, write,| public-reader|
 *  | control           | CONTROL (all   | ACL mgmt. Objects:   | public-writer|
 *  |                   | perms)         | read, write, ACL mgmt| auth-reader  |
 *  |                   |                |                        auth-writer  |
 *  +-------------------+----------------+----------------------+--------------+
 *
 *  WARNING:
 *      Any of this Manta roles must be created before usage, with an appropiate
 *      policy to at least resemble the intent.
 *
 *  References:
 *  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
 */
function s3RoleTranslator(req, res, next) {
    if (!req.isS3Request) {
        next();
        return;
    }

    req.log.debug({
        headers: req.headers,
        query: req.query,
        method: req.method,
        path: req.path(),
        isS3Request: req.isS3Request
    }, 's3RoleTranslator: translating S3 ACL headers to Manta roles' +
                  ' - debugging input');

    // Handle x-amz-acl header
    var s3Acl = req.headers['x-amz-acl'];
    if (s3Acl) {
        var mantaRoles = S3_ACL_TO_MANTA_ROLES[s3Acl.toLowerCase()];
        if (mantaRoles !== undefined) {
            // Mark this as an S3 ACL operation for special role handling
            req._s3AclOperation = true;
            req._s3AclRoles = mantaRoles;

            // Also set the role-tag header for backward compatibility
            if (mantaRoles.length > 0) {
                req.headers['role-tag'] = mantaRoles.join(',');
            } else {
                // For 'private' ACL, set empty role-tag to clear roles
                req.headers['role-tag'] = '';
            }

            req.log.debug({
                s3Acl: s3Acl,
                mantaRoles: mantaRoles,
                roleTag: req.headers['role-tag'],
                isAclOperation: true
            }, 's3RoleTranslator: translated S3 ACL to Manta roles');
        }
    }

    // Handle S3 grant headers (basic implementation)
    var grantHeaders = ['x-amz-grant-read',
                        'x-amz-grant-write',
                        'x-amz-grant-full-control'];
    var grantRoles = [];

    grantHeaders.forEach(function (header) {
        var grantValue = req.headers[header];
        if (grantValue) {
            // Parse grant value and convert to roles
            var roles = parseS3GrantToRoles(header, grantValue);
            grantRoles = grantRoles.concat(roles);
        }
    });

    if (grantRoles.length > 0) {
        var existingRoles = req.headers['role-tag'] ?
            req.headers['role-tag'].split(',') : [];
        var allRoles = existingRoles.concat(grantRoles);
        // Remove duplicates
        var uniqueRoles = allRoles.filter(function (role, index) {
            return (allRoles.indexOf(role) === index);
        });
        req.headers['role-tag'] = uniqueRoles.join(',');
        req.log.debug({
            grantHeaders: grantHeaders,
            grantRoles: grantRoles,
            finalRoles: uniqueRoles
        }, 's3RoleTranslator: translated S3 grants to Manta roles');
    }

    next();
}

/*
 * parseS3GrantToRoles(header, value)
 * Translates a S3 ACL grant header to the appropiate Manta role.
 * Arguments:
 *     header: S3 ACL grant header.
 *     value:  String uri to represents the user/scope to apply this ACL.
 * Returns:
 *     Array of Manta roles associated with the grant ACL header.
 * Notes:
 *    Each of this roles and their associated policies must be created ahead of
 *    time.
 */
function parseS3GrantToRoles(header, value) {
    var roles = [];

    // Simple implementation - can be extended for more complex grant parsing
    switch (header) {
        case 'x-amz-grant-read':
            if (
                value.includes(
                    'uri="http://acs.amazonaws.com/groups/global/AllUsers"')) {
                roles.push('public-reader');
            } else if (
                value.includes(
           'uri="http://acs.amazonaws.com/groups/global/AuthenticatedUsers"')) {
                roles.push('authenticated-reader');
            }
        break;
        case 'x-amz-grant-write':
            if (
                value.includes(
                    'uri="http://acs.amazonaws.com/groups/global/AllUsers"')) {
                roles.push('public-writer');
            } else if (
                value.includes(
           'uri="http://acs.amazonaws.com/groups/global/AuthenticatedUsers"')) {
                roles.push('authenticated-writer');
            }
        break;
        case 'x-amz-grant-full-control':
            if (
                value.includes(
                    'uri="http://acs.amazonaws.com/groups/global/AllUsers"')) {
                roles.push('public-reader', 'public-writer');
            } else if (
                value.includes(
           'uri="http://acs.amazonaws.com/groups/global/AuthenticatedUsers"')) {
                roles.push('authenticated-reader', 'authenticated-writer');
            }
        break;
        default:
            // need some logging here
        break;
    }
    return (roles);
}


/*
 * rolesToS3ACL(roles)
 * Converts an array of Manta roles to a canned S3 ACL
 * Arguments:
 *     roles: Array of strings representing Manta roles.
 * Returns:
 *     String representing a canned S3 ACL.
 * Notes:
 *     This is the reverse of S3_ACL_TO_MANTA_ROLES mapping
 */
function rolesToS3ACL(roles) {
    if (!roles || !Array.isArray(roles) || roles.length === 0) {
        return ('private');
    }

    // Check for specific role combinations and return matching S3 ACL
    var hasPublicReader = roles.includes('public-read');
    var hasPublicWriter = roles.includes('public-writer');
    var hasAuthenticatedReader = roles.includes('authenticated-reader');
    var hasOwnerReader = roles.includes('owner-reader');
    var hasOwnerFullControl = roles.includes('owner-full-control');
    var hasLogWriter = roles.includes('log-writer');

    // Check for specific ACL patterns
    if (hasPublicReader && hasPublicWriter) {
        return ('public-read-write');
    } else if (hasPublicReader) {
        return ('public-read');
    } else if (hasAuthenticatedReader) {
        return ('authenticated-read');
    } else if (hasOwnerReader) {
        return ('bucket-owner-read');
    } else if (hasOwnerFullControl) {
        return ('bucket-owner-full-control');
    } else if (hasLogWriter) {
        return ('log-delivery-write');
    }

    // Default to private if no recognized roles
    return ('private');
}

///--- Exports

module.exports = {
    s3RequestDetector: s3RequestDetector,
    s3PathTranslator: s3PathTranslator,
    s3ResponseFormatter: s3ResponseFormatter,
    s3HeaderTranslator: s3HeaderTranslator,
    s3ConditionalHeaders: s3ConditionalHeaders,
    s3RoleTranslator: s3RoleTranslator,
    parseS3Request: parseS3Request,
    convertS3ToMantaPath: convertS3ToMantaPath,
    convertMantaToS3Response: convertMantaToS3Response,
    convertErrorToS3: convertErrorToS3,
    parseS3GrantToRoles: parseS3GrantToRoles,
    rolesToS3ACL: rolesToS3ACL
};
