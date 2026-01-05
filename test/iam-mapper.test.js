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
 * iam-mapper.test.js: Unit tests for IAM mapper
 * module
 */

var iamMapper = require('../lib/auth/iam-mapper');


///--- Tests

exports['map getobject action'] = function (t) {
    var result = iamMapper.toIamAction('getobject');
    t.equal(result, 's3:GetObject');
    t.done();
};


exports['map putobject action'] = function (t) {
    var result = iamMapper.toIamAction('putobject');
    t.equal(result, 's3:PutObject');
    t.done();
};


exports['map deleteobject action'] = function (t) {
    var result = iamMapper.toIamAction('deleteobject');
    t.equal(result, 's3:DeleteObject');
    t.done();
};


exports['map getbucket action'] = function (t) {
    var result = iamMapper.toIamAction('getbucket');
    t.equal(result, 's3:ListBucket');
    t.done();
};


exports['map putbucket action'] = function (t) {
    var result = iamMapper.toIamAction('putbucket');
    t.equal(result, 's3:CreateBucket');
    t.done();
};


exports['map deletebucket action'] = function (t) {
    var result = iamMapper.toIamAction('deletebucket');
    t.equal(result, 's3:DeleteBucket');
    t.done();
};


exports['map getdirectory action'] = function (t) {
    var result =
        iamMapper.toIamAction('getdirectory');
    t.equal(result, 's3:ListAllMyBuckets');
    t.done();
};


exports['map listbucketobjectsv2 action'] =
function (t) {
    var result =
        iamMapper.toIamAction('listbucketobjectsv2');
    t.equal(result, 's3:ListObjectsV2');
    t.done();
};


exports['map unknown action returns original'] =
function (t) {
    var result = iamMapper.toIamAction('unknownaction');
    t.equal(result, 'unknownaction');
    t.done();
};


exports['map bucket from request path'] =
function (t) {
    var result = iamMapper.toIamResource(null,
        '/mybucket');
    t.equal(result, 'arn:aws:s3:::mybucket');
    t.done();
};


exports['map bucket and object from request path'] =
function (t) {
    var result = iamMapper.toIamResource(null,
        '/mybucket/myobject');
    t.equal(result, 'arn:aws:s3:::mybucket/myobject');
    t.done();
};


exports['map bucket and nested object path'] =
function (t) {
    var result = iamMapper.toIamResource(null,
        '/mybucket/path/to/object');
    t.equal(result,
        'arn:aws:s3:::mybucket/path/to/object');
    t.done();
};


exports['map bucket from resource key only'] =
function (t) {
    var result = iamMapper.toIamResource('mybucket',
        null);
    t.equal(result, 'arn:aws:s3:::mybucket');
    t.done();
};


exports['map bucket from account/bucket format'] =
function (t) {
    var result =
        iamMapper.toIamResource('account/mybucket',
            null);
    t.equal(result, 'arn:aws:s3:::mybucket');
    t.done();
};


exports['map bucket and object from resource key'] =
function (t) {
    var result =
        iamMapper.toIamResource(
            'account/mybucket/myobject', null);
    t.equal(result, 'arn:aws:s3:::mybucket/myobject');
    t.done();
};


exports['map nested object from resource key'] =
function (t) {
    var result =
        iamMapper.toIamResource(
            'account/mybucket/path/to/object', null);
    t.equal(result,
        'arn:aws:s3:::mybucket/path/to/object');
    t.done();
};


exports['request path takes precedence'] =
function (t) {
    var result = iamMapper.toIamResource(
        'account/bucket1/obj1',
        '/bucket2/obj2');
    t.equal(result, 'arn:aws:s3:::bucket2/obj2');
    t.done();
};


exports['empty path returns wildcard'] = function (t) {
    var result = iamMapper.toIamResource('', '');
    t.equal(result, '*');
    t.done();
};


exports['null inputs return wildcard'] = function (t) {
    var result = iamMapper.toIamResource(null, null);
    t.equal(result, '*');
    t.done();
};


exports['path with leading slash handled'] =
function (t) {
    var result = iamMapper.toIamResource(null,
        '/bucket/object');
    t.equal(result, 'arn:aws:s3:::bucket/object');
    t.done();
};


exports['path with trailing slash handled'] =
function (t) {
    var result = iamMapper.toIamResource(null,
        '/bucket/');
    t.equal(result, 'arn:aws:s3:::bucket');
    t.done();
};


exports['resource key with single part'] =
function (t) {
    var result = iamMapper.toIamResource('justbucket',
        null);
    t.equal(result, 'arn:aws:s3:::justbucket');
    t.done();
};


exports['special characters in object path'] =
function (t) {
    var result = iamMapper.toIamResource(null,
        '/bucket/my-object_file.txt');
    t.equal(result,
        'arn:aws:s3:::bucket/my-object_file.txt');
    t.done();
};
