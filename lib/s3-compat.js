/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 MNX Cloud, Inc.
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
    'GET /?list-type=2': 'ListBuckets',
    'PUT /{bucket}': 'CreateBucket',
    'GET /{bucket}': 'ListBucketObjects',
    'HEAD /{bucket}': 'HeadBucket',
    'DELETE /{bucket}': 'DeleteBucket',
    
    // Object operations
    'PUT /{bucket}/{object}': 'CreateBucketObject',
    'GET /{bucket}/{object}': 'GetBucketObject',
    'HEAD /{bucket}/{object}': 'HeadBucketObject',
    'DELETE /{bucket}/{object}': 'DeleteBucketObject'
};

///--- S3 Error Responses (XML format)

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
    'AccessDenied': {
        code: 'AccessDenied',
        description: 'Access Denied',
        httpStatusCode: 403
    },
    'InvalidSignature': {
        code: 'SignatureDoesNotMatch',
        description: 'The request signature we calculated does not match the signature you provided.',
        httpStatusCode: 403
    },
    'RequestTimeTooSkewed': {
        code: 'RequestTimeTooSkewed',
        description: 'The difference between the request time and the current time is too large.',
        httpStatusCode: 403
    }
};

///--- Helper Functions

/**
 * Parse S3-style path and determine operation (supports both path-style and virtual-hosted)
 */
function parseS3Request(req) {
    var path = req.path();
    var method = req.method;
    var query = req.query || {};
    var host = req.headers.host || '';
    
    // Remove leading slash
    var cleanPath = path.replace(/^\/+/, '');
    var pathParts = cleanPath.split('/').filter(function(part) { return part.length > 0; });
    
    // Parse host to detect virtual-hosted style
    var hostParts = host.split('.');
    var isVirtualHosted = hostParts.length > 2; // e.g., bucket.domain.com
    var bucketFromHost = isVirtualHosted ? hostParts[0] : null;
    
    var s3Request = {
        bucket: null,
        object: null,
        operation: null,
        isS3Request: false,
        mantaPath: null,
        addressingStyle: isVirtualHosted ? 'virtual-hosted' : 'path-style'
    };
    
    req.log.debug({
        host: host,
        path: path,
        hostParts: hostParts,
        isVirtualHosted: isVirtualHosted,
        bucketFromHost: bucketFromHost,
        pathParts: pathParts
    }, 'S3_DEBUG: parseS3Request - analyzing request style');
    
    if (isVirtualHosted) {
        // Virtual-hosted style: bucket.domain.com/object-key
        s3Request.isS3Request = true;
        s3Request.bucket = bucketFromHost;
        
        if (pathParts.length === 0) {
            // Root path with virtual-hosted = bucket operations
            switch (method) {
                case 'GET':
                    s3Request.operation = query['list-type'] ? 'ListBuckets' : 'ListBucketObjects';
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
            }
        } else {
            // Object operations: bucket from host, object from path
            s3Request.object = pathParts.join('/');
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
            }
        }
    } else {
        // Path-style: domain.com/bucket/object-key (existing logic)
        if (pathParts.length === 0) {
            // Root path - list buckets
            s3Request.isS3Request = true;
            s3Request.operation = 'ListBuckets';
        } else if (pathParts.length === 1) {
            // Bucket operations
            s3Request.isS3Request = true;
            s3Request.bucket = pathParts[0];
            
            switch (method) {
                case 'GET':
                    s3Request.operation = query['list-type'] ? 'ListBuckets' : 'ListBucketObjects';
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
            }
        } else if (pathParts.length >= 2) {
            // Object operations
            s3Request.isS3Request = true;
            s3Request.bucket = pathParts[0];
            s3Request.object = pathParts.slice(1).join('/');
            
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
            }
        }
    }
    
    return s3Request;
}

/**
 * Convert S3 path to Manta path format
 */
function convertS3ToMantaPath(s3Request, accountLogin) {
    assert.string(accountLogin, 'accountLogin');
    
    if (!s3Request.isS3Request) {
        return null;
    }
    
    switch (s3Request.operation) {
        case 'ListBuckets':
            return '/' + accountLogin + '/buckets';
            
        case 'CreateBucket':
        case 'HeadBucket':
        case 'DeleteBucket':
            return '/' + accountLogin + '/buckets/' + s3Request.bucket;
            
        case 'ListBucketObjects':
            return '/' + accountLogin + '/buckets/' + s3Request.bucket + '/objects';
            
        case 'CreateBucketObject':
        case 'GetBucketObject':
        case 'HeadBucketObject':
        case 'DeleteBucketObject':
            return '/' + accountLogin + '/buckets/' + s3Request.bucket + '/objects/' + s3Request.object;
            
        default:
            return null;
    }
}

/**
 * Convert Manta headers to S3 headers
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
                
            // S3-specific headers
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
    s3Headers['x-amz-request-id'] = s3Headers['x-amz-request-id'] || generateRequestId();
    s3Headers['x-amz-id-2'] = s3Headers['x-amz-id-2'] || generateHostId();
    
    return s3Headers;
}

/**
 * Convert Manta response body to S3 format
 */
function convertMantaToS3Response(mantaBody, operation, s3Request) {
    switch (operation) {
        case 'ListBuckets':
            return convertBucketListToS3(mantaBody);
            
        case 'ListBucketObjects':
            return convertObjectListToS3(mantaBody, s3Request.bucket);
            
        case 'CreateBucket':
        case 'HeadBucket':
        case 'DeleteBucket':
        case 'CreateBucketObject':
        case 'HeadBucketObject':
        case 'DeleteBucketObject':
            // These operations typically return empty bodies or simple responses
            return mantaBody;
            
        case 'GetBucketObject':
            // Object content passes through unchanged
            return mantaBody;
            
        default:
            return mantaBody;
    }
}

/**
 * Convert Manta bucket list to S3 XML format
 */
function convertBucketListToS3(mantaResponse) {
    var buckets = Array.isArray(mantaResponse) ? mantaResponse : [mantaResponse];
    
    // Debug logging to understand the data structure
    console.log('S3_DEBUG: convertBucketListToS3 - input data:', JSON.stringify(mantaResponse, null, 2));
    console.log('S3_DEBUG: convertBucketListToS3 - buckets array:', JSON.stringify(buckets, null, 2));
    
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n';
    xml += '  <Owner>\n';
    xml += '    <ID>manta-user</ID>\n';
    xml += '    <DisplayName>Manta User</DisplayName>\n';
    xml += '  </Owner>\n';
    xml += '  <Buckets>\n';
    
    var bucketCount = 0;
    buckets.forEach(function (bucket) {
        console.log('S3_DEBUG: processing bucket:', JSON.stringify(bucket, null, 2));
        if (bucket && bucket.name) {
            bucketCount++;
            xml += '    <Bucket>\n';
            xml += '      <Name>' + escapeXml(bucket.name) + '</Name>\n';
            xml += '      <CreationDate>' + (bucket.created || new Date().toISOString()) + '</CreationDate>\n';
            xml += '    </Bucket>\n';
            console.log('S3_DEBUG: added bucket to XML:', bucket.name);
        } else {
            console.log('S3_DEBUG: skipping bucket (no name property):', JSON.stringify(bucket, null, 2));
        }
    });
    
    xml += '  </Buckets>\n';
    xml += '</ListAllMyBucketsResult>\n';
    
    console.log('S3_DEBUG: convertBucketListToS3 - generated XML:', xml);
    console.log('S3_DEBUG: convertBucketListToS3 - processed', bucketCount, 'buckets out of', buckets.length, 'total');
    
    return xml;
}

/**
 * Convert Manta object list to S3 XML format
 */
function convertObjectListToS3(mantaResponse, bucketName) {
    var objects = Array.isArray(mantaResponse) ? mantaResponse : [mantaResponse];
    
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n';
    xml += '  <Name>' + escapeXml(bucketName) + '</Name>\n';
    xml += '  <Prefix></Prefix>\n';
    xml += '  <Marker></Marker>\n';
    xml += '  <MaxKeys>1000</MaxKeys>\n';
    xml += '  <IsTruncated>false</IsTruncated>\n';
    
    objects.forEach(function (obj) {
        if (obj && obj.name) {
            xml += '  <Contents>\n';
            xml += '    <Key>' + escapeXml(obj.name) + '</Key>\n';
            xml += '    <LastModified>' + (obj.mtime || new Date().toISOString()) + '</LastModified>\n';
            xml += '    <ETag>"' + (obj.etag || 'd41d8cd98f00b204e9800998ecf8427e') + '"</ETag>\n';
            xml += '    <Size>' + (obj.size || 0) + '</Size>\n';
            xml += '    <StorageClass>STANDARD</StorageClass>\n';
            xml += '  </Contents>\n';
        }
    });
    
    xml += '</ListBucketResult>\n';
    
    return xml;
}

/**
 * Convert error to S3 XML format
 */
function convertErrorToS3(error, s3Request) {
    var errorCode = error.restCode || error.name || 'InternalError';
    var s3Error = S3_ERROR_RESPONSES[errorCode] || S3_ERROR_RESPONSES['InternalError'];
    
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<Error>\n';
    xml += '  <Code>' + escapeXml(s3Error.code) + '</Code>\n';
    xml += '  <Message>' + escapeXml(error.message || s3Error.description) + '</Message>\n';
    
    if (s3Request.bucket) {
        xml += '  <BucketName>' + escapeXml(s3Request.bucket) + '</BucketName>\n';
    }
    
    if (s3Request.object) {
        xml += '  <Key>' + escapeXml(s3Request.object) + '</Key>\n';
    }
    
    xml += '  <RequestId>' + generateRequestId() + '</RequestId>\n';
    xml += '  <HostId>' + generateHostId() + '</HostId>\n';
    xml += '</Error>\n';
    
    return xml;
}

/**
 * Utility functions
 */
function escapeXml(str) {
    if (typeof str !== 'string') {
        return str;
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

function generateRequestId() {
    return crypto.randomBytes(8).toString('hex').toUpperCase();
}

function generateHostId() {
    // Generate a host ID without potentially problematic characters
    return crypto.randomBytes(16).toString('hex').toUpperCase();
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
        req.url = mantaPath + (req.query ? '?' + Object.keys(req.query).map(function(k) {
            return k + '=' + encodeURIComponent(req.query[k]);
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

/**
 * S3 Response Formatter Middleware
 */
function s3ResponseFormatter(req, res, next) {
    if (!req.isS3Request) {
        next();
        return;
    }
    
    req.log.debug('s3ResponseFormatter: formatting response for S3');
    
    // Intercept the response
    var originalSend = res.send;
    var originalWriteHead = res.writeHead;
    
    res.writeHead = function(statusCode, headers) {
        if (req.isS3Request && headers) {
            // Convert headers to S3 format
            var s3Headers = convertMantaToS3Headers(headers, req.s3Request.operation);
            return originalWriteHead.call(this, statusCode, s3Headers);
        }
        return originalWriteHead.call(this, statusCode, headers);
    };
    
    res.send = function(code, data) {
        if (req.isS3Request) {
            req.log.info({
                statusCode: code,
                operation: req.s3Request ? req.s3Request.operation : 'unknown',
                dataType: typeof data,
                isError: data instanceof Error
            }, 'S3_DEBUG: s3ResponseFormatter - converting response to S3 format');
            
            var contentType = 'application/xml';
            var responseBody;
            
            // Handle errors
            if (data instanceof Error || (typeof code === 'number' && code >= 400)) {
                req.log.info('S3_DEBUG: s3ResponseFormatter - handling error response');
                responseBody = convertErrorToS3(data || new Error('Unknown error'), req.s3Request);
                res.setHeader('Content-Type', contentType);
            } else {
                // Handle successful responses
                req.log.info('S3_DEBUG: s3ResponseFormatter - handling success response');
                try {
                    responseBody = convertMantaToS3Response(data, req.s3Request.operation, req.s3Request);
                    req.log.info({
                        dataLength: Array.isArray(data) ? data.length : 'not-array',
                        xmlLength: responseBody ? responseBody.length : 0
                    }, 'S3_DEBUG: XML conversion successful');
                } catch (xmlError) {
                    req.log.error({
                        error: xmlError.message,
                        data: data,
                        operation: req.s3Request.operation
                    }, 'S3_DEBUG: XML conversion failed');
                    responseBody = convertErrorToS3(xmlError, req.s3Request);
                    res.setHeader('Content-Type', contentType);
                    return originalSend.call(this, 500, responseBody);
                }
                
                // Set appropriate content type
                if (req.s3Request.operation === 'GetBucketObject') {
                    // For object downloads, preserve original content type
                    contentType = res.getHeader('content-type') || 'application/octet-stream';
                } else {
                    res.setHeader('Content-Type', contentType);
                }
            }
            
            // Clear any existing Content-Length that might conflict with XML response
            res.removeHeader('Content-Length');
            res.removeHeader('Content-MD5');
            
            // Add S3-specific headers
            res.setHeader('x-amz-request-id', generateRequestId());
            res.setHeader('x-amz-id-2', generateHostId());
            
            req.log.info({
                httpStatusCode: code,
                responseBodyLength: responseBody ? responseBody.length : 0,
                contentType: contentType,
                headers: {
                    'content-type': res.getHeader('content-type'),
                    'content-length': res.getHeader('content-length'),
                    'x-amz-request-id': res.getHeader('x-amz-request-id'),
                    'x-amz-id-2': res.getHeader('x-amz-id-2')
                },
                xmlResponse: responseBody ? responseBody.substring(0, 1000) + (responseBody.length > 1000 ? '...[truncated]' : '') : 'null'
            }, 'S3_DEBUG: s3ResponseFormatter - sending XML response to AWS CLI');
            
            // Bypass JSON formatting by using writeHead and end directly for S3 responses
            res.writeHead(code, {
                'Content-Type': contentType,
                'Content-Length': Buffer.byteLength(responseBody, 'utf8'),
                'x-amz-request-id': res.getHeader('x-amz-request-id'),
                'x-amz-id-2': res.getHeader('x-amz-id-2')
            });
            res.write(responseBody, 'utf8');
            res.end();
            return;
        }
        
        return originalSend.call(this, code, data);
    };
    
    next();
}

/**
 * S3 Header Translation Middleware
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
            var mantaKey = 'm-' + lowerKey.substring(11); // Remove 'x-amz-meta-'
            req.headers[mantaKey] = req.headers[key];
            delete req.headers[key];
        }
    });
    
    next();
}

///--- Exports

module.exports = {
    s3RequestDetector: s3RequestDetector,
    s3PathTranslator: s3PathTranslator,
    s3ResponseFormatter: s3ResponseFormatter,
    s3HeaderTranslator: s3HeaderTranslator,
    parseS3Request: parseS3Request,
    convertS3ToMantaPath: convertS3ToMantaPath,
    convertMantaToS3Response: convertMantaToS3Response,
    convertErrorToS3: convertErrorToS3
};