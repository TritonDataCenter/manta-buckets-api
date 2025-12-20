/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/**
 * @file AWS S3-compatible CORS configuration handlers for manta-buckets-api
 * @brief Implements bucket-level CORS management operations
 * @details This module provides AWS S3 compatible CORS configuration management
 *          for buckets. It implements the standard S3 CORS API operations:
 *          PutBucketCors, GetBucketCors, and DeleteBucketCors.
 *          CORS configurations are stored as special metadata objects within
 *          buckets and support both XML (AWS CLI) and JSON formats.
 *
 * Key features:
 * - AWS S3 CORS API compatibility
 * - XML and JSON CORS configuration parsing
 * - Bucket-level CORS rule storage and retrieval
 * - CORS rule validation and error handling
 * - XML response generation for AWS CLI compatibility
 * - Support for multiple CORS rules per bucket
 *
 * CORS Configuration Storage:
 * - Stored as '.cors-configuration' object in bucket metadata
 * - JSON format in object headers for efficient access
 * - Supports AWS S3 CORS rule structure
 *
 * @see https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTcors.html
 */

var auth = require('../auth');
var buckets = require('./buckets');
var s3Compat = require('../s3-compat');
var uuidv4 = require('uuid/v4');

/**
 * CORS configuration object name in bucket storage
 */
var CORS_CONFIG_OBJECT = '.cors-configuration';

/**
 * @brief PUT Bucket CORS Handler - Create middleware chain for storing CORS
 * configuration
 * @details Returns a middleware chain that handles AWS S3 PutBucketCors
 *          requests.
 *          The chain loads the request, validates the bucket, authorizes the
 *          user,  and stores the CORS configuration as a special object.
 *
 * @return {Array} Middleware chain for PutBucketCors operation
 *
 * @note Requires bucket ownership or appropriate permissions
 * @see storeCorsConfiguration, auth.authorizationHandler
 *
 * @example
 * // AWS CLI usage:
 * // aws s3api put-bucket-cors --bucket mybucket \
 * // --cors-configuration file://cors.json
 */
function putBucketCorsHandler() {
    var chain = [
        buckets.loadRequest,
        buckets.getBucketIfExists,
        auth.authorizationHandler(),
        storeCorsConfiguration
    ];
    return (chain);
}

/**
 * @brief GET Bucket CORS Handler - Create middleware chain for retrieving
 *        CORS configuration
 * @details Returns a middleware chain that handles AWS S3 GetBucketCors
 *          requests.
 *          The chain loads the request, validates the bucket, authorizes the
 *          user, and retrieves the stored CORS configuration.
 *
 * @return {Array} Middleware chain for GetBucketCors operation
 *
 * @note Returns 404 NoSuchCORSConfiguration if no CORS config exists
 * @see retrieveCorsConfiguration, auth.authorizationHandler
 *
 * @example
 * // AWS CLI usage:
 * // aws s3api get-bucket-cors --bucket mybucket
 */
function getBucketCorsHandler() {
    var chain = [
        buckets.loadRequest,
        buckets.getBucketIfExists,
        auth.authorizationHandler(),
        retrieveCorsConfiguration
    ];
    return (chain);
}

/**
 * @brief DELETE Bucket CORS Handler - Create middleware chain for removing
 *        CORS configuration
 * @details Returns a middleware chain that handles AWS S3 DeleteBucketCors
 *          requests.
 *          The chain loads the request, validates the bucket, authorizes the
 *          user, and removes the stored CORS configuration.
 *
 * @return {Array} Middleware chain for DeleteBucketCors operation
 *
 * @note Returns 404 NoSuchCORSConfiguration if no CORS config exists to delete
 * @see deleteCorsConfiguration, auth.authorizationHandler
 *
 * @example
 * // AWS CLI usage:
 * // aws s3api delete-bucket-cors --bucket mybucket
 */
function deleteBucketCorsHandler() {
    var chain = [
        buckets.loadRequest,
        buckets.getBucketIfExists,
        auth.authorizationHandler(),
        deleteCorsConfiguration
    ];
    return (chain);
}

/**
 * @brief Store CORS configuration as a special object in bucket storage
 * @details Parses and validates CORS configuration from request body (XML or
 *          JSON), then stores it as a metadata object in the bucket for later
 *          retrieval.
 *          Supports AWS S3 XML format for CLI compatibility and JSON for
 *          internal use.
 *
 * @param req {Object} HTTP request object containing CORS configuration in body
 * @param res {Object} HTTP response object
 * @param next {Function} Next middleware function
 *
 * @return {void} Calls next(false) on completion or error
 *
 * @throws {400} MalformedXML - Invalid CORS configuration format or missing
 * required fields
 * @throws {500} InternalError - Failed to store configuration in bucket storage
 *
 * @note Validates that each CORS rule has required AllowedOrigins and
 * AllowedMethods
 * @note Stores configuration as JSON in object metadata for efficient access
 * @see parseXMLCorsConfiguration, buildCorsConfigXML
 *
 * @example
 * // Request body (XML format):
 * <?xml version="1.0" encoding="UTF-8"?>
 * <CORSConfiguration>
 *   <CORSRule>
 *     <AllowedOrigin>https://example.com</AllowedOrigin>
 *     <AllowedMethod>GET</AllowedMethod>
 *     <AllowedMethod>PUT</AllowedMethod>
 *   </CORSRule>
 * </CORSConfiguration>
 */
function storeCorsConfiguration(req, res, next) {
    var log = req.log;
    var bucket = req.bucket;
    var owner = req.owner.account.uuid;
    var requestId = req.getId();

    log.debug({
        bucket: bucket.name,
        owner: owner,
        contentLength: req.headers['content-length']
    }, 'CORS: Storing bucket CORS configuration');

    // Parse CORS configuration from request body (XML format)
    var corsConfig;
    try {
        if (!req.body || typeof (req.body) !== 'string') {
            log.error('CORS: No CORS configuration provided in request body');
            res.send(400, {
                code: 'MalformedXML',
                message: 'CORS configuration required'
            });
            return (next(false));
        }

        // Try to parse as XML first (AWS CLI format)
        if (req.body.trim().startsWith('<')) {
            log.debug('CORS: Parsing XML CORS configuration');
            corsConfig = parseXMLCorsConfiguration(req.body);
        } else {
            // Fallback to JSON for backward compatibility
            log.debug('CORS: Parsing JSON CORS configuration');
            corsConfig = JSON.parse(req.body);
        }
    } catch (parseErr) {
        log.error({
            err: parseErr,
            bodyPreview: req.body.substring(0, 200)
        }, 'CORS: Failed to parse CORS configuration');
        res.send(400, {
            code: 'MalformedXML',
            message: 'Invalid CORS configuration format: ' + parseErr.message
        });
        return (next(false));
    }

    // Validate CORS configuration structure
    if (!corsConfig.CORSRules || !Array.isArray(corsConfig.CORSRules)) {
        log.error('CORS: CORS configuration missing CORSRules array');
        res.send(400, {
            code: 'MalformedXML',
            message: 'CORS configuration must contain CORSRules array'
        });
        return (next(false));
    }

    // Validate each CORS rule
    for (var i = 0; i < corsConfig.CORSRules.length; i++) {
        var rule = corsConfig.CORSRules[i];
        if (!rule.AllowedOrigins || !rule.AllowedMethods) {
            log.error({ruleIndex: i},
                      'CORS: CORS rule missing required AllowedOrigins' +
                      ' or AllowedMethods');
            res.send(400, {
                code: 'MalformedXML',
                message: 'Each CORS rule must have AllowedOrigins' +
                    ' and AllowedMethods'
            });
            return (next(false));
        }
    }

    log.debug({
        corsRulesCount: corsConfig.CORSRules.length,
        corsConfig: corsConfig
    }, 'CORS: Validated CORS configuration');

    // Store CORS configuration as a special object
    var corsNameHash = require('crypto').createHash('md5')
        .update(CORS_CONFIG_OBJECT).digest('hex');
    var objectLocation = req.metadataPlacement.getObjectLocation(owner,
        bucket.id, corsNameHash);
    var objectClient = req.metadataPlacement.
        getBucketsMdapiClient(objectLocation);

    var objectData = {
        name: CORS_CONFIG_OBJECT,
        content_length: Buffer.byteLength(JSON.stringify(corsConfig), 'utf8'),
        content_type: 'application/json',
        content_md5: require('crypto').createHash('md5')
            .update(JSON.stringify(corsConfig)).digest('hex'),
        headers: {
            'cors-data': JSON.stringify(corsConfig),
            'object-type': 'cors-configuration'
        },
        sharks: [],
        creator: owner
    };

    objectClient.createObject(owner, bucket.id, CORS_CONFIG_OBJECT,
        uuidv4(), objectData.content_length, objectData.content_md5,
        objectData.content_type, objectData.headers, objectData.sharks, {},
        objectLocation.vnode, {}, requestId, function (putErr, _putResult) {

        if (putErr) {
            log.error({
                err: putErr,
                bucket: bucket.name
            }, 'CORS: Failed to store CORS configuration');

            res.send(500, {
                code: 'InternalError',
                message: 'Failed to store CORS configuration'
            });
            return (next(false));
        }

        log.debug({
            bucket: bucket.name,
            corsRulesCount: corsConfig.CORSRules.length
        }, 'CORS: CORS configuration stored successfully');

        // Return empty success response (per S3 API)
        res.send(200);
        return (next(false));
    });
}

/**
 * @brief Retrieve CORS configuration from bucket storage
 * @details Loads the stored CORS configuration from the special
 * '.cors-configuration'
 *          object in the bucket and returns it as XML format compatible with
 *          AWS S3 API.
 *          Used by GetBucketCors operation to provide AWS CLI compatibility.
 *
 * @param req {Object} HTTP request object
 * @param res {Object} HTTP response object
 * @param next {Function} Next middleware function
 *
 * @return {void} Calls next(false) on completion or error
 *
 * @throws {404} NoSuchCORSConfiguration - No CORS configuration found for
 * bucket
 * @throws {500} InternalError - Failed to retrieve or parse configuration
 *
 * @note Returns XML response with Content-Type: application/xml
 * @note Configuration is parsed from JSON stored in object metadata
 * @see buildCorsConfigXML, storeCorsConfiguration
 *
 * @example
 * // Response (XML format):
 * <?xml version="1.0" encoding="UTF-8"?>
 * <CORSConfiguration>
 *   <CORSRule>
 *     <AllowedOrigin>https://example.com</AllowedOrigin>
 *     <AllowedMethod>GET</AllowedMethod>
 *   </CORSRule>
 * </CORSConfiguration>
 */
function retrieveCorsConfiguration(req, res, next) {
    var log = req.log;
    var bucket = req.bucket;
    var owner = req.owner.account.uuid;
    var requestId = req.getId();

    log.debug({
        bucket: bucket.name,
        owner: owner
    }, 'CORS: Retrieving bucket CORS configuration');

    // Load CORS configuration object
    var corsNameHash = require('crypto').createHash('md5')
        .update(CORS_CONFIG_OBJECT).digest('hex');
    var objectLocation = req.metadataPlacement.getObjectLocation(owner,
        bucket.id, corsNameHash);
    var objectClient = req.metadataPlacement.
        getBucketsMdapiClient(objectLocation);

    objectClient.getObject(owner, bucket.id, CORS_CONFIG_OBJECT,
        objectLocation.vnode, {}, requestId, function (getErr, corsObjectData) {

        if (getErr) {
            if (getErr.statusCode === 404 ||
                getErr.name === 'ObjectNotFoundError' ||
                getErr.name === 'ObjectNotFound') {
                log.debug('CORS: No CORS configuration found for bucket');
                var corsError =
                    new Error('The CORS configuration does not exist');
                corsError.name = 'NoSuchCORSConfiguration';
                corsError.restCode = 'NoSuchCORSConfiguration';
                corsError.statusCode = 404;
                res.send(404, corsError);
            } else {
                log.error({
                    err: getErr,
                    bucket: bucket.name
                }, 'CORS: Failed to retrieve CORS configuration');

                res.send(500, {
                    code: 'InternalError',
                    message: 'Failed to retrieve CORS configuration'
                });
            }
            return (next(false));
        }

        try {
            var corsData = corsObjectData.headers['cors-data'];
            var corsConfig = JSON.parse(corsData);

            log.debug({
                bucket: bucket.name,
                corsRulesCount: corsConfig.CORSRules ?
                    corsConfig.CORSRules.length : 0
            }, 'CORS: Retrieved CORS configuration');

            // Convert to S3 XML response format
            var xmlResponse = buildCorsConfigXML(corsConfig);
            res.setHeader('Content-Type', 'application/xml');
            res.send(200, xmlResponse);
            return (next(false));

        } catch (parseErr) {
            log.error({
                err: parseErr,
                bucket: bucket.name
            }, 'CORS: Failed to parse stored CORS configuration');

            res.send(500, {
                code: 'InternalError',
                message: 'Failed to parse CORS configuration'
            });
            return (next(false));
        }
    });
}

/**
 * @brief Delete CORS configuration from bucket storage
 * @details Removes the stored CORS configuration by deleting the special
 *          '.cors-configuration' object from the bucket.
 *          Used by DeleteBucketCors
 *          operation to provide AWS S3 API compatibility.
 *
 * @param req {Object} HTTP request object
 * @param res {Object} HTTP response object
 * @param next {Function} Next middleware function
 *
 * @return {void} Calls next(false) on completion or error
 *
 * @throws {404} NoSuchCORSConfiguration - No CORS configuration exists to
 * delete
 * @throws {500} InternalError - Failed to delete configuration from storage
 *
 * @note Returns 204 No Content on successful deletion (per S3 API)
 * @note Bucket returns to having no CORS configuration after deletion
 * @see storeCorsConfiguration, retrieveCorsConfiguration
 *
 * @example
 * // After deletion, bucket has no CORS configuration
 * // Subsequent GetBucketCors will return 404 NoSuchCORSConfiguration
 */
function deleteCorsConfiguration(req, res, next) {
    var log = req.log;
    var bucket = req.bucket;
    var owner = req.owner.account.uuid;
    var requestId = req.getId();

    log.debug({
        bucket: bucket.name,
        owner: owner
    }, 'CORS: Deleting bucket CORS configuration');

    // Delete CORS configuration object
    var corsNameHash = require('crypto').createHash('md5')
        .update(CORS_CONFIG_OBJECT).digest('hex');
    var objectLocation = req.metadataPlacement.getObjectLocation(owner,
        bucket.id, corsNameHash);
    var objectClient = req.metadataPlacement.
        getBucketsMdapiClient(objectLocation);

    objectClient.deleteObject(owner, bucket.id, CORS_CONFIG_OBJECT,
        objectLocation.vnode, {}, requestId, function (delErr) {

        if (delErr) {
            if (delErr.statusCode === 404 ||
                delErr.name === 'ObjectNotFoundError' ||
                delErr.name === 'ObjectNotFound') {
                log.debug('CORS: No CORS configuration found to delete');
                var corsError =
                    new Error('The CORS configuration does not exist');
                corsError.name = 'NoSuchCORSConfiguration';
                corsError.restCode = 'NoSuchCORSConfiguration';
                corsError.statusCode = 404;
                res.send(404, corsError);
            } else {
                log.error({
                    err: delErr,
                    bucket: bucket.name
                }, 'CORS: Failed to delete CORS configuration');

                res.send(500, {
                    code: 'InternalError',
                    message: 'Failed to delete CORS configuration'
                });
            }
            return (next(false));
        }

        log.debug({
            bucket: bucket.name
        }, 'CORS: CORS configuration deleted successfully');

        // Return empty success response (per S3 API)
        res.send(204, '');
        return (next(false));
    });
}

/**
 * @brief Build XML response for GetBucketCors operation
 * @details Converts internal CORS configuration format to AWS S3 compatible XML
 *          response. Properly escapes XML entities and formats the response
 *          according
 *          to S3 CORS configuration schema.
 *
 * @param corsConfig {Object} Internal CORS configuration object
 * @param corsConfig.CORSRules {Array} Array of CORS rule objects
 *
 * @return {string} Formatted XML string compatible with AWS S3 CORS response
 *
 * @note Uses s3Compat.escapeXml() for proper XML entity encoding
 * @note Includes XML declaration for full S3 compatibility
 * @see retrieveCorsConfiguration, s3Compat.escapeXml
 *
 * @example
 * // Input:
 * {
 *   "CORSRules": [{
 *     "ID": "rule1",
 *     "AllowedOrigins": ["https://example.com"],
 *     "AllowedMethods": ["GET", "PUT"],
 *     "MaxAgeSeconds": 3600
 *   }]
 * }
 *
 * // Output:
 * <?xml version="1.0" encoding="UTF-8"?>
 * <CORSConfiguration>
 *   <CORSRule>
 *     <ID>rule1</ID>
 *     <AllowedOrigin>https://example.com</AllowedOrigin>
 *     <AllowedMethod>GET</AllowedMethod>
 *     <AllowedMethod>PUT</AllowedMethod>
 *     <MaxAgeSeconds>3600</MaxAgeSeconds>
 *   </CORSRule>
 * </CORSConfiguration>
 */
function buildCorsConfigXML(corsConfig) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<CORSConfiguration>\n';

    if (corsConfig.CORSRules) {
        corsConfig.CORSRules.forEach(function (rule) {
            xml += '  <CORSRule>\n';

            if (rule.ID) {
                xml += '    <ID>' + s3Compat.escapeXml(rule.ID) + '</ID>\n';
            }

            if (rule.AllowedOrigins) {
                rule.AllowedOrigins.forEach(function (origin) {
                    xml += '    <AllowedOrigin>' + s3Compat.escapeXml(origin) +
                        '</AllowedOrigin>\n';
                });
            }

            if (rule.AllowedMethods) {
                rule.AllowedMethods.forEach(function (method) {
                    xml += '    <AllowedMethod>' + s3Compat.escapeXml(method) +
                        '</AllowedMethod>\n';
                });
            }

            if (rule.AllowedHeaders) {
                rule.AllowedHeaders.forEach(function (header) {
                    xml += '    <AllowedHeader>' + s3Compat.escapeXml(header) +
                        '</AllowedHeader>\n';
                });
            }

            if (rule.ExposeHeaders) {
                rule.ExposeHeaders.forEach(function (header) {
                    xml += '    <ExposeHeader>' + s3Compat.escapeXml(header) +
                        '</ExposeHeader>\n';
                });
            }

            if (rule.MaxAgeSeconds) {
                xml += '    <MaxAgeSeconds>' +
                    s3Compat.escapeXml(rule.MaxAgeSeconds.toString()) +
                    '</MaxAgeSeconds>\n';
            }

            xml += '  </CORSRule>\n';
        });
    }
    xml += '</CORSConfiguration>\n';
    return (xml);
}

/**
 * @brief Parse XML CORS configuration into JSON format
 * @details Converts AWS S3 XML CORS configuration to internal JSON format using
 *          regex-based parsing. Handles all standard S3 CORS elements and
 *          properly decodes XML entities using s3Compat utilities.
 *
 * @param xmlString {string} Raw XML string from request body
 *
 * @return {Object} Parsed CORS configuration in internal JSON format
 * @return {Object.CORSRules} Array of CORS rule objects
 *
 * @note Uses s3Compat.decodeXMLEntities() for proper XML entity decoding
 * @note Supports all AWS S3 CORS elements: ID, AllowedOrigin, AllowedMethod,
 *       AllowedHeader, ExposeHeader, MaxAgeSeconds
 * @see storeCorsConfiguration, s3Compat.decodeXMLEntities
 *
 * @example
 * // Input XML:
 * <?xml version="1.0" encoding="UTF-8"?>
 * <CORSConfiguration>
 *   <CORSRule>
 *     <AllowedOrigin>https://example.com</AllowedOrigin>
 *     <AllowedMethod>GET</AllowedMethod>
 *   </CORSRule>
 * </CORSConfiguration>
 *
 * // Output JSON:
 * {
 *   "CORSRules": [{
 *     "AllowedOrigins": ["https://example.com"],
 *     "AllowedMethods": ["GET"]
 *   }]
 * }
 */
function parseXMLCorsConfiguration(xmlString) {
    var corsConfig = { CORSRules: [] };

    // Remove XML declaration and whitespace
    // JSSTYLED
    var cleanXml = xmlString.replace(/<\?xml[^>]*\?>/, '').trim();

    // Extract CORSRule elements using regex
    // JSSTYLED
    var corsRuleRegex = /<CORSRule>([\s\S]*?)<\/CORSRule>/g;
    var ruleMatch;

    while ((ruleMatch = corsRuleRegex.exec(cleanXml)) !== null) {
        var ruleXml = ruleMatch[1];
        var rule = {};

        // Parse ID
        // JSSTYLED
        var idMatch = /<ID>(.*?)<\/ID>/.exec(ruleXml);
        if (idMatch) {
            rule.ID = s3Compat.decodeXMLEntities(idMatch[1].trim());
        }

        // Parse AllowedOrigins
        var allowedOrigins = [];
        // JSSTYLED
        var originRegex = /<AllowedOrigin>(.*?)<\/AllowedOrigin>/g;
        var originMatch;
        while ((originMatch = originRegex.exec(ruleXml)) !== null) {
            allowedOrigins.push(s3Compat.decodeXMLEntities(
                originMatch[1].trim()));
        }
        if (allowedOrigins.length > 0) {
            rule.AllowedOrigins = allowedOrigins;
        }

        // Parse AllowedMethods
        var allowedMethods = [];
        // JSSTYLED
        var methodRegex = /<AllowedMethod>(.*?)<\/AllowedMethod>/g;
        var methodMatch;
        while ((methodMatch = methodRegex.exec(ruleXml)) !== null) {
            allowedMethods.push(s3Compat.decodeXMLEntities(
                methodMatch[1].trim()));
        }
        if (allowedMethods.length > 0) {
            rule.AllowedMethods = allowedMethods;
        }

        // Parse AllowedHeaders
        var allowedHeaders = [];
        //JSSTYLED
        var headerRegex = /<AllowedHeader>(.*?)<\/AllowedHeader>/g;
        var headerMatch;
        while ((headerMatch = headerRegex.exec(ruleXml)) !== null) {
            allowedHeaders.push(s3Compat.decodeXMLEntities(
                headerMatch[1].trim()));
        }
        if (allowedHeaders.length > 0) {
            rule.AllowedHeaders = allowedHeaders;
        }

        // Parse ExposeHeaders
        var exposeHeaders = [];
        //JSSTYLED
        var exposeRegex = /<ExposeHeader>(.*?)<\/ExposeHeader>/g;
        var exposeMatch;
        while ((exposeMatch = exposeRegex.exec(ruleXml)) !== null) {
            exposeHeaders.push(s3Compat.decodeXMLEntities(
                exposeMatch[1].trim()));
        }
        if (exposeHeaders.length > 0) {
            rule.ExposeHeaders = exposeHeaders;
        }

        // Parse MaxAgeSeconds
        //JSSTYLED
        var maxAgeMatch = /<MaxAgeSeconds>(.*?)<\/MaxAgeSeconds>/.exec(ruleXml);
        if (maxAgeMatch) {
            rule.MaxAgeSeconds = parseInt(s3Compat.decodeXMLEntities(
                maxAgeMatch[1].trim()), 10);
        }

        corsConfig.CORSRules.push(rule);
    }

    return (corsConfig);
}

// XML utility functions are imported from s3-compat module
// to avoid code duplication across the S3 compatibility layer

module.exports = {
    putBucketCorsHandler: putBucketCorsHandler,
    getBucketCorsHandler: getBucketCorsHandler,
    deleteBucketCorsHandler: deleteBucketCorsHandler
};
