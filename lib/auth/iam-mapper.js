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
 * iam-mapper.js: Utilities for mapping Manta actions
 * and resources to IAM/S3 equivalents.
 *
 * Provides conversion functions to translate Manta-style
 * action names and resource paths into AWS IAM-compatible
 * action strings and ARN resource identifiers.
 */


///--- Functions

/**
 * Map Manta action to IAM action for policy
 * evaluation.
 *
 * @param {String} mantaAction - Manta action name
 * @return {String} IAM action (e.g., 's3:GetObject')
 */
function mapMantaToIamAction(mantaAction) {
    var mapping = {
        'getdirectory': 's3:ListAllMyBuckets',
        'getbucket': 's3:ListBucket',
        'listbucketobjectsv2': 's3:ListObjectsV2',
        'listbucketobjects': 's3:ListBucket',
        'listobjects': 's3:ListBucket',
        'putbucket': 's3:CreateBucket',
        'deletebucket': 's3:DeleteBucket',
        'getobject': 's3:GetObject',
        'putobject': 's3:PutObject',
        'deleteobject': 's3:DeleteObject'
    };

    return (mapping[mantaAction] || mantaAction);
}


/**
 * Map Manta resource key to IAM ARN format for
 * policy evaluation. Uses both the resource key
 * and request path to determine the correct bucket.
 *
 * @param {String} mantaResourceKey - Manta resource
 * @param {String} requestPath - HTTP request path
 * @return {String} ARN (e.g., 'arn:aws:s3:::bucket')
 */
function mapMantaToIamResource(mantaResourceKey,
    requestPath) {
    // Extract bucket name from request path if
    // available
    if (requestPath &&
        typeof (requestPath) === 'string') {
        // Request path format: /bucket or
        // /bucket/object
        var pathParts = requestPath.split('/').filter(
            function (part) {
            return (part.length > 0);
        });

        if (pathParts.length >= 1) {
            var bucket = pathParts[0];
            var objectPath = pathParts.slice(1).join('/');

            if (objectPath) {
                return ('arn:aws:s3:::' + bucket + '/' +
                    objectPath);
            } else {
                return ('arn:aws:s3:::' + bucket);
            }
        }
    }

    // Fallback to parsing the Manta resource key
    if (mantaResourceKey &&
        typeof (mantaResourceKey) === 'string') {
        var parts = mantaResourceKey.split('/');

        // Handle case where resource is just bucket
        // name (no account prefix)
        if (parts.length === 1 && parts[0]) {
            return ('arn:aws:s3:::' + parts[0]);
        }

        // Handle case with account/bucket or
        // account/bucket/object format
        if (parts.length >= 2 && parts[1]) {
            var resourceBucket = parts[1];
            var resourceObjectPath =
                parts.slice(2).join('/');

            if (resourceObjectPath) {
                return ('arn:aws:s3:::' +
                    resourceBucket + '/' +
                    resourceObjectPath);
            } else {
                return ('arn:aws:s3:::' +
                    resourceBucket);
            }
        }
    }

    // Last resort: return wildcard (this should
    // rarely happen)
    return ('*');
}


///--- Exports

module.exports = {
    toIamAction: mapMantaToIamAction,
    toIamResource: mapMantaToIamResource
};
