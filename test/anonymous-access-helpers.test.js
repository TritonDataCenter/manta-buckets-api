/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/**
 * Unit tests for Anonymous Access Handler helper functions in lib/server.js
 *
 * These tests exercise actual production code exported from lib/server.js.
 */

var helper = require('./s3-test-helper.js');
var server = require('../lib/server.js');

// Import production functions
var parseMantaBucketObjectPath = server.parseMantaBucketObjectPath;
var isMantaAnonymousObjectAccess = server.isMantaAnonymousObjectAccess;
var setupMantaObjectParams = server.setupMantaObjectParams;
var flattenHandlers = server.flattenHandlers;
var executeHandlerChain = server.executeHandlerChain;


// ========== parseMantaBucketObjectPath Tests ==========

helper.test('parseMantaBucketObjectPath parses path correctly', function (t) {
    var result = parseMantaBucketObjectPath(
        '/account/buckets/mybucket/objects/myfile.txt');

    t.equal(result.length, 5, 'should have 5 parts');
    t.equal(result[0], 'account', 'should extract account');
    t.equal(result[1], 'buckets', 'should extract buckets');
    t.equal(result[2], 'mybucket', 'should extract bucket name');
    t.equal(result[3], 'objects', 'should extract objects');
    t.equal(result[4], 'myfile.txt', 'should extract object name');
    t.end();
});

helper.test('parseMantaBucketObjectPath handles trailing slashes',
    function (t) {
    var result = parseMantaBucketObjectPath('/account/buckets/mybucket/');

    t.equal(result.length, 3, 'should ignore trailing slash');
    t.equal(result[0], 'account', 'should extract account');
    t.equal(result[1], 'buckets', 'should extract buckets');
    t.equal(result[2], 'mybucket', 'should extract bucket name');
    t.end();
});

helper.test('parseMantaBucketObjectPath handles nested paths', function (t) {
    var result = parseMantaBucketObjectPath(
        '/account/buckets/bucket/objects/folder/subfolder/file.txt');

    t.equal(result.length, 7, 'should have 7 parts');
    t.equal(result[0], 'account', 'should extract account');
    t.equal(result[4], 'folder', 'should extract folder');
    t.equal(result[5], 'subfolder', 'should extract subfolder');
    t.equal(result[6], 'file.txt', 'should extract file');
    t.end();
});

helper.test('parseMantaBucketObjectPath handles leading slashes', function (t) {
    var result = parseMantaBucketObjectPath('///account///buckets///');

    t.equal(result.length, 2, 'should filter empty segments');
    t.equal(result[0], 'account', 'should extract account');
    t.equal(result[1], 'buckets', 'should extract buckets');
    t.end();
});


// ========== isMantaAnonymousObjectAccess Tests ==========

helper.test('isMantaAnonymousObjectAccess returns true for valid path',
    function (t) {
    var pathParts = ['account', 'buckets', 'mybucket', 'objects', 'file.txt'];
    var req = {potentialAnonymousAccess: true};

    var result = isMantaAnonymousObjectAccess(pathParts, req);

    t.ok(result, 'should return true for valid anonymous access path');
    t.end();
});

helper.test('isMantaAnonymousObjectAccess checks potentialAnonymousAccess flag',
    function (t) {
    var pathParts = ['account', 'buckets', 'mybucket', 'objects', 'file.txt'];
    var req = {potentialAnonymousAccess: false};

    var result = isMantaAnonymousObjectAccess(pathParts, req);

    t.ok(!result, 'should return false without potentialAnonymousAccess flag');
    t.end();
});

helper.test('isMantaAnonymousObjectAccess checks path length', function (t) {
    var pathParts = ['account', 'buckets', 'mybucket'];
    var req = {potentialAnonymousAccess: true};

    var result = isMantaAnonymousObjectAccess(pathParts, req);

    t.ok(!result, 'should return false for path with less than 5 parts');
    t.end();
});

helper.test('isMantaAnonymousObjectAccess validates path format',
    function (t) {
    var pathParts = ['account', 'wrong', 'mybucket', 'format', 'file.txt'];
    var req = {potentialAnonymousAccess: true};

    var result = isMantaAnonymousObjectAccess(pathParts, req);

    t.ok(!result, 'should return false for incorrect path format');
    t.end();
});

helper.test('isMantaAnonymousObjectAccess checks objects segment',
    function (t) {
    var pathParts = ['account', 'buckets', 'mybucket', 'other', 'file.txt'];
    var req = {potentialAnonymousAccess: true};

    var result = isMantaAnonymousObjectAccess(pathParts, req);

    t.ok(!result, 'should return false when segment 3 is not objects');
    t.end();
});


// ========== setupMantaObjectParams Tests ==========

helper.test('setupMantaObjectParams extracts parameters', function (t) {
    var req = {
        params: {},
        log: {debug: function () {}}
    };
    var pathParts = ['myaccount', 'buckets', 'mybucket', 'objects',
        'myfile.txt'];

    setupMantaObjectParams(req, pathParts);

    t.equal(req.params.account, 'myaccount', 'should extract account');
    t.equal(req.params.bucket_name, 'mybucket', 'should extract bucket_name');
    t.equal(req.params.object_name, 'myfile.txt', 'should extract object_name');
    t.end();
});

helper.test('setupMantaObjectParams handles nested object paths', function (t) {
    var req = {
        params: {},
        log: {debug: function () {}}
    };
    var pathParts = ['myaccount', 'buckets', 'mybucket', 'objects',
        'folder', 'subfolder', 'file.txt'];

    setupMantaObjectParams(req, pathParts);

    t.equal(req.params.object_name, 'folder/subfolder/file.txt',
        'should join nested path with slashes');
    t.end();
});

helper.test('setupMantaObjectParams creates params object', function (t) {
    var req = {
        log: {debug: function () {}}
    };
    var pathParts = ['myaccount', 'buckets', 'mybucket', 'objects', 'file.txt'];

    setupMantaObjectParams(req, pathParts);

    t.ok(req.params, 'should create params object');
    t.equal(req.params.account, 'myaccount', 'should extract account');
    t.end();
});


// ========== flattenHandlers Tests ==========

helper.test('flattenHandlers flattens nested arrays', function (t) {
    var handler1 = function () {};
    var handler2 = function () {};
    var handler3 = function () {};
    var handler4 = function () {};

    var rawHandlers = [
        handler1,
        [handler2, handler3],
        handler4
    ];

    var result = flattenHandlers(rawHandlers);

    t.equal(result.length, 4, 'should flatten to 4 handlers');
    t.equal(result[0], handler1, 'should preserve first handler');
    t.equal(result[1], handler2, 'should flatten second handler');
    t.equal(result[2], handler3, 'should flatten third handler');
    t.equal(result[3], handler4, 'should preserve fourth handler');
    t.end();
});

helper.test('flattenHandlers handles all nested arrays', function (t) {
    var handler1 = function () {};
    var handler2 = function () {};

    var rawHandlers = [
        [handler1],
        [handler2]
    ];

    var result = flattenHandlers(rawHandlers);

    t.equal(result.length, 2, 'should flatten all arrays');
    t.end();
});

helper.test('flattenHandlers handles non-nested handlers', function (t) {
    var handler1 = function () {};
    var handler2 = function () {};

    var rawHandlers = [handler1, handler2];

    var result = flattenHandlers(rawHandlers);

    t.equal(result.length, 2, 'should preserve non-nested handlers');
    t.equal(result[0], handler1, 'should preserve first handler');
    t.equal(result[1], handler2, 'should preserve second handler');
    t.end();
});

helper.test('flattenHandlers handles empty array', function (t) {
    var result = flattenHandlers([]);

    t.equal(result.length, 0, 'should return empty array');
    t.end();
});


// ========== executeHandlerChain Tests ==========

helper.test('executeHandlerChain executes handlers sequentially', function (t) {
    var executionOrder = [];

    var handler1 = function (req, res, next) {
        executionOrder.push(1);
        next();
    };

    var handler2 = function (req, res, next) {
        executionOrder.push(2);
        next();
    };

    var handlers = [handler1, handler2];

    executeHandlerChain(handlers, {}, {}, function () {
        t.equal(executionOrder.length, 2, 'should execute 2 handlers');
        t.equal(executionOrder[0], 1, 'should execute first handler first');
        t.equal(executionOrder[1], 2, 'should execute second handler second');
        t.end();
    });
});

helper.test('executeHandlerChain stops on error', function (t) {
    var executionOrder = [];
    var testError = new Error('Test error');

    var handler1 = function (req, res, next) {
        executionOrder.push(1);
        next(testError);
    };

    var handler2 = function (req, res, next) {
        executionOrder.push(2);
        next();
    };

    var handlers = [handler1, handler2];

    executeHandlerChain(handlers, {}, {}, function (err) {
        t.equal(executionOrder.length, 1, 'should only execute first handler');
        t.equal(err, testError, 'should pass error to callback');
        t.end();
    });
});

helper.test('executeHandlerChain handles invalid handler', function (t) {
    var handlers = ['not-a-function'];
    var req = {
        log: {error: function () {}}
    };

    executeHandlerChain(handlers, req, {}, function (err) {
        t.ok(err, 'should return error');
        t.ok(err.message.indexOf('Invalid handler') !== -1,
            'should have invalid handler error message');
        t.end();
    });
});

helper.test('executeHandlerChain catches handler exceptions', function (t) {
    var thrownError = new Error('Handler threw exception');

    var handler1 = function (_req, _res, _next) {
        throw thrownError;
    };

    var handlers = [handler1];

    executeHandlerChain(handlers, {}, {}, function (err) {
        t.equal(err, thrownError, 'should catch and pass thrown exception');
        t.end();
    });
});

helper.test('executeHandlerChain handles empty handler array', function (t) {
    var handlers = [];
    var callbackCalled = false;

    executeHandlerChain(handlers, {}, {}, function (err) {
        callbackCalled = true;
        t.ok(!err, 'should not have error');
        t.ok(callbackCalled, 'should call callback');
        t.end();
    });
});
