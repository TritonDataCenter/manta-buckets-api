/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Application-wide constants for manta-buckets-api
 * Centralizes magic numbers and configuration values
 */

///--- Timeout Constants (milliseconds)

// Default connection timeout for HTTP clients
var DEFAULT_CONNECT_TIMEOUT = 1000;

// Default request timeout for HTTP operations
var DEFAULT_REQUEST_TIMEOUT = 10000;

// Socket timeout multiplier (converts seconds to milliseconds)
var SOCKET_TIMEOUT_MULTIPLIER = 1000;

// Data operation timeout (45 seconds)
var DEFAULT_DATA_TIMEOUT = 45000;

// Client retry timeout (5 seconds)
var CLIENT_RETRY_TIMEOUT = 5000;

///--- AWS S3 Limits

// Maximum number of parts in multipart upload
var S3_MAX_PARTS = 10000;

// Minimum part number for multipart upload
var S3_MIN_PART_NUMBER = 1;

// Maximum number of uploads to list
var S3_MAX_UPLOADS = 1000;

///--- CORS Configuration

// Default max age for CORS preflight cache (1 hour)
var CORS_DEFAULT_MAX_AGE = 3600;

///--- IAM Session Limits

// Default maximum session duration (1 hour)
var DEFAULT_MAX_SESSION_DURATION = 3600;

///--- Server Configuration

// Default development server port
var DEFAULT_DEV_PORT = 8080;

///--- HTTP Status Codes

var HTTP_STATUS = {
    OK: 200,
    CREATED: 201,
    NO_CONTENT: 204,
    FOUND: 302,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    METHOD_NOT_ALLOWED: 405,
    CONFLICT: 409,
    INTERNAL_SERVER_ERROR: 500
};

///--- AWS Authentication Constants

var AWS_AUTH = {
    SCHEME_SIGV4: 'aws4-hmac-sha256',
    SCHEME_SIGNATURE: 'signature',
    SCHEME_TOKEN: 'token',
    ALGORITHM_PARAM: 'X-Amz-Algorithm',
    ALGORITHM_PARAM_LOWER: 'x-amz-algorithm'
};

///--- AWS S3 Headers

var S3_HEADERS = {
    REQUEST_ID: 'x-amz-request-id',
    HOST_ID: 'x-amz-id-2',
    UPLOAD_ID: 'x-amz-upload-id',
    META_PREFIX: 'x-amz-meta-',
    DECODED_CONTENT_LENGTH: 'x-amz-decoded-content-length'
};

///--- Content Types

var CONTENT_TYPES = {
    XML: 'application/xml',
    JSON: 'application/json',
    OCTET_STREAM: 'application/octet-stream',
    FORM_URLENCODED: 'application/x-www-form-urlencoded'
};

///--- Debug Prefixes

var DEBUG_PREFIXES = {
    S3: 'S3_DEBUG',
    STS: 'STS_DEBUG',
    IAM: 'IAM_DEBUG',
    MANTA: 'MANTA_DEBUG',
    AUTH: 'AUTH_DEBUG'
};

///--- Default Values

var DEFAULTS = {
    COLUMN_LIMIT: 72,
    MD5_EMPTY_STRING: 'd41d8cd98f00b204e9800998ecf8427e'
};

///--- File Size Constants (in bytes)

var FILE_SIZES = {
    BYTE: 1,
    KB: 1024,
    MB: 1024 * 1024,
    GB: 1024 * 1024 * 1024
};

var SIZE_LIMITS = {
    // 1MB compression limit
    COMPRESSION_MAX: 1048576,
    // 4KB header size limit
    MAX_HEADER_SIZE: 4 * 1024,
    // 5MB minimum part size for multipart uploads
    MIN_PART_SIZE: 5 * FILE_SIZES.MB,
    // 50MB streaming buffer
    STREAMING_BUFFER: 50 * FILE_SIZES.MB,
    // 5GB default max streaming size (AWS S3 single PUT limit)
    DEFAULT_MAX_STREAMING_MB: 5120,
    // 1KB additional buffer
    BUFFER_OVERHEAD: 1024,
    // Page limits
    MAX_PAGE_LIMIT: 1024,
    MAX_VALIDATION_LIMIT: 1024
};

///--- Copy Operation Limits

var COPY_LIMITS = {
    MIN_COPIES: 1,
    MAX_COPIES: 9,
    DEFAULT_COPIES: 2
};

///--- Exports

module.exports = {
    // Timeouts
    DEFAULT_CONNECT_TIMEOUT: DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_REQUEST_TIMEOUT: DEFAULT_REQUEST_TIMEOUT,
    SOCKET_TIMEOUT_MULTIPLIER: SOCKET_TIMEOUT_MULTIPLIER,
    DEFAULT_DATA_TIMEOUT: DEFAULT_DATA_TIMEOUT,
    CLIENT_RETRY_TIMEOUT: CLIENT_RETRY_TIMEOUT,

    // AWS S3 Limits
    S3_MAX_PARTS: S3_MAX_PARTS,
    S3_MIN_PART_NUMBER: S3_MIN_PART_NUMBER,
    S3_MAX_UPLOADS: S3_MAX_UPLOADS,

    // CORS
    CORS_DEFAULT_MAX_AGE: CORS_DEFAULT_MAX_AGE,

    // IAM
    DEFAULT_MAX_SESSION_DURATION: DEFAULT_MAX_SESSION_DURATION,

    // Server
    DEFAULT_DEV_PORT: DEFAULT_DEV_PORT,

    // HTTP Status Codes
    HTTP_STATUS: HTTP_STATUS,

    // AWS Auth
    AWS_AUTH: AWS_AUTH,

    // S3 Headers
    S3_HEADERS: S3_HEADERS,

    // Content Types
    CONTENT_TYPES: CONTENT_TYPES,

    // Debug Prefixes
    DEBUG_PREFIXES: DEBUG_PREFIXES,

    // Defaults
    DEFAULTS: DEFAULTS,

    // File Sizes
    FILE_SIZES: FILE_SIZES,

    // Size Limits
    SIZE_LIMITS: SIZE_LIMITS,

    // Copy Limits
    COPY_LIMITS: COPY_LIMITS
};