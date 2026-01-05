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
 */

var helper = require('./s3-test-helper.js');

// Test: parseMantaBucketObjectPath - should parse path into parts
helper.test('parseMantaBucketObjectPath parses path correctly', function (t) {
    function parseMantaBucketObjectPath(requestPath) {
        var pathParts = requestPath.split('/').filter(function (part) {
            return (part.length > 0);
        });
        return (pathParts);
    }

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

// Test: parseMantaBucketObjectPath - should handle trailing slashes
helper.test('parseMantaBucketObjectPath handles trailing slashes',
    function (t) {
    function parseMantaBucketObjectPath(requestPath) {
        var pathParts = requestPath.split('/').filter(function (part) {
            return (part.length > 0);
        });
        return (pathParts);
    }

    var result = parseMantaBucketObjectPath('/account/buckets/mybucket/');

    t.equal(result.length, 3, 'should ignore trailing slash');
    t.equal(result[0], 'account', 'should extract account');
    t.equal(result[1], 'buckets', 'should extract buckets');
    t.equal(result[2], 'mybucket', 'should extract bucket name');
    t.end();
});

// Test: parseMantaBucketObjectPath - should handle nested object paths
helper.test('parseMantaBucketObjectPath handles nested paths', function (t) {
    function parseMantaBucketObjectPath(requestPath) {
        var pathParts = requestPath.split('/').filter(function (part) {
            return (part.length > 0);
        });
        return (pathParts);
    }

    var result = parseMantaBucketObjectPath(
        '/account/buckets/bucket/objects/folder/subfolder/file.txt');

    t.equal(result.length, 7, 'should have 7 parts');
    t.equal(result[0], 'account', 'should extract account');
    t.equal(result[4], 'folder', 'should extract folder');
    t.equal(result[5], 'subfolder', 'should extract subfolder');
    t.equal(result[6], 'file.txt', 'should extract file');
    t.end();
});

// Test: isMantaAnonymousObjectAccess - should return true for valid path
helper.test('isMantaAnonymousObjectAccess returns true for valid path',
    function (t) {
    function isMantaAnonymousObjectAccess(pathPartsArg, reqArg) {
        return (pathPartsArg.length >= 5 &&
                pathPartsArg[1] === 'buckets' &&
                pathPartsArg[3] === 'objects' &&
                reqArg.potentialAnonymousAccess);
    }

    var pathParts = ['account', 'buckets', 'mybucket', 'objects', 'file.txt'];
    var req = {potentialAnonymousAccess: true};

    var result = isMantaAnonymousObjectAccess(pathParts, req);

    t.ok(result, 'should return true for valid anonymous access path');
    t.end();
});

// Test: isMantaAnonymousObjectAccess - should return false without
// potentialAnonymousAccess
helper.test('isMantaAnonymousObjectAccess checks potentialAnonymousAccess flag',
    function (t) {
    function isMantaAnonymousObjectAccess(pathPartsArg, reqArg) {
        return (pathPartsArg.length >= 5 &&
                pathPartsArg[1] === 'buckets' &&
                pathPartsArg[3] === 'objects' &&
                reqArg.potentialAnonymousAccess);
    }

    var pathParts = ['account', 'buckets', 'mybucket', 'objects', 'file.txt'];
    var req = {potentialAnonymousAccess: false};

    var result = isMantaAnonymousObjectAccess(pathParts, req);

    t.ok(!result, 'should return false without potentialAnonymousAccess flag');
    t.end();
});

// Test: isMantaAnonymousObjectAccess - should return false for short path
helper.test('isMantaAnonymousObjectAccess checks path length', function (t) {
    function isMantaAnonymousObjectAccess(pathPartsArg, reqArg) {
        return (pathPartsArg.length >= 5 &&
                pathPartsArg[1] === 'buckets' &&
                pathPartsArg[3] === 'objects' &&
                reqArg.potentialAnonymousAccess);
    }

    var pathParts = ['account', 'buckets', 'mybucket'];
    var req = {potentialAnonymousAccess: true};

    var result = isMantaAnonymousObjectAccess(pathParts, req);

    t.ok(!result, 'should return false for path with less than 5 parts');
    t.end();
});

// Test: isMantaAnonymousObjectAccess - should return false for wrong
// path format
helper.test('isMantaAnonymousObjectAccess validates path format',
    function (t) {
    function isMantaAnonymousObjectAccess(pathPartsArg, reqArg) {
        return (pathPartsArg.length >= 5 &&
                pathPartsArg[1] === 'buckets' &&
                pathPartsArg[3] === 'objects' &&
                reqArg.potentialAnonymousAccess);
    }

    var pathParts = ['account', 'wrong', 'mybucket', 'format', 'file.txt'];
    var req = {potentialAnonymousAccess: true};

    var result = isMantaAnonymousObjectAccess(pathParts, req);

    t.ok(!result, 'should return false for incorrect path format');
    t.end();
});

// Test: setupMantaObjectParams - should extract parameters correctly
helper.test('setupMantaObjectParams extracts parameters', function (t) {
    function setupMantaObjectParams(reqArg, pathPartsArg) {
        reqArg.params = reqArg.params || {};
        reqArg.params.account = pathPartsArg[0];
        reqArg.params.bucket_name = pathPartsArg[2];
        reqArg.params.object_name = pathPartsArg.slice(4).join('/');

        reqArg.log.debug({
            account: reqArg.params.account,
            bucket_name: reqArg.params.bucket_name,
            object_name: reqArg.params.object_name
        }, 'Set up Manta route parameters');
    }

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

// Test: setupMantaObjectParams - should handle nested object paths
helper.test('setupMantaObjectParams handles nested object paths', function (t) {
    function setupMantaObjectParams(reqArg, pathPartsArg) {
        reqArg.params = reqArg.params || {};
        reqArg.params.account = pathPartsArg[0];
        reqArg.params.bucket_name = pathPartsArg[2];
        reqArg.params.object_name = pathPartsArg.slice(4).join('/');

        reqArg.log.debug({
            account: reqArg.params.account,
            bucket_name: reqArg.params.bucket_name,
            object_name: reqArg.params.object_name
        }, 'Set up Manta route parameters');
    }

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

// Test: setupMantaObjectParams - should create params object if missing
helper.test('setupMantaObjectParams creates params object', function (t) {
    function setupMantaObjectParams(reqArg, pathPartsArg) {
        reqArg.params = reqArg.params || {};
        reqArg.params.account = pathPartsArg[0];
        reqArg.params.bucket_name = pathPartsArg[2];
        reqArg.params.object_name = pathPartsArg.slice(4).join('/');

        reqArg.log.debug({
            account: reqArg.params.account,
            bucket_name: reqArg.params.bucket_name,
            object_name: reqArg.params.object_name
        }, 'Set up Manta route parameters');
    }

    var req = {
        log: {debug: function () {}}
    };

    var pathParts = ['myaccount', 'buckets', 'mybucket', 'objects', 'file.txt'];

    setupMantaObjectParams(req, pathParts);

    t.ok(req.params, 'should create params object');
    t.equal(req.params.account, 'myaccount', 'should extract account');
    t.end();
});

// Test: flattenHandlers - should flatten nested handler arrays
helper.test('flattenHandlers flattens nested arrays', function (t) {
    function flattenHandlers(rawHandlersArg) {
        var handlers = [];
        rawHandlersArg.forEach(function (handler) {
            if (Array.isArray(handler)) {
                handlers = handlers.concat(handler);
            } else {
                handlers.push(handler);
            }
        });
        return (handlers);
    }

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

// Test: flattenHandlers - should handle all nested arrays
helper.test('flattenHandlers handles all nested arrays', function (t) {
    function flattenHandlers(rawHandlersArg) {
        var handlers = [];
        rawHandlersArg.forEach(function (handler) {
            if (Array.isArray(handler)) {
                handlers = handlers.concat(handler);
            } else {
                handlers.push(handler);
            }
        });
        return (handlers);
    }

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

// Test: flattenHandlers - should handle no nesting
helper.test('flattenHandlers handles non-nested handlers', function (t) {
    function flattenHandlers(rawHandlersArg) {
        var handlers = [];
        rawHandlersArg.forEach(function (handler) {
            if (Array.isArray(handler)) {
                handlers = handlers.concat(handler);
            } else {
                handlers.push(handler);
            }
        });
        return (handlers);
    }

    var handler1 = function () {};
    var handler2 = function () {};

    var rawHandlers = [handler1, handler2];

    var result = flattenHandlers(rawHandlers);

    t.equal(result.length, 2, 'should preserve non-nested handlers');
    t.equal(result[0], handler1, 'should preserve first handler');
    t.equal(result[1], handler2, 'should preserve second handler');
    t.end();
});

// Test: executeHandlerChain - should execute all handlers in sequence
helper.test('executeHandlerChain executes handlers sequentially', function (t) {
    function executeHandlerChain(handlersArg, reqArg, res, next) {
        var index = 0;

        function executeNext(err) {
            if (err) {
                return (next(err));
            }

            if (index >= handlersArg.length) {
                return (next());
            }

            var currentHandler = handlersArg[index++];

            if (typeof (currentHandler) === 'function') {
                try {
                    currentHandler(reqArg, res, executeNext);
                } catch (e) {
                    next(e);
                }
            } else {
                reqArg.log.error({
                    handlerIndex: index - 1,
                    handlerType: typeof (currentHandler),
                    handler: currentHandler
                }, 'Invalid handler in bucket object chain');

                next(new Error('Invalid handler in bucket object chain' +
                    ' at index ' + (index - 1)));
            }
        }

        executeNext();
    }

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

// Test: executeHandlerChain - should stop on error
helper.test('executeHandlerChain stops on error', function (t) {
    function executeHandlerChain(handlersArg, reqArg, res, next) {
        var index = 0;

        function executeNext(err) {
            if (err) {
                return (next(err));
            }

            if (index >= handlersArg.length) {
                return (next());
            }

            var currentHandler = handlersArg[index++];

            if (typeof (currentHandler) === 'function') {
                try {
                    currentHandler(reqArg, res, executeNext);
                } catch (e) {
                    next(e);
                }
            } else {
                reqArg.log.error({
                    handlerIndex: index - 1,
                    handlerType: typeof (currentHandler),
                    handler: currentHandler
                }, 'Invalid handler in bucket object chain');

                next(new Error('Invalid handler in bucket object chain' +
                    ' at index ' + (index - 1)));
            }
        }

        executeNext();
    }

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

// Test: executeHandlerChain - should handle invalid handler
helper.test('executeHandlerChain handles invalid handler', function (t) {
    function executeHandlerChain(handlersArg, reqArg, res, next) {
        var index = 0;

        function executeNext(err) {
            if (err) {
                return (next(err));
            }

            if (index >= handlersArg.length) {
                return (next());
            }

            var currentHandler = handlersArg[index++];

            if (typeof (currentHandler) === 'function') {
                try {
                    currentHandler(reqArg, res, executeNext);
                } catch (e) {
                    next(e);
                }
            } else {
                reqArg.log.error({
                    handlerIndex: index - 1,
                    handlerType: typeof (currentHandler),
                    handler: currentHandler
                }, 'Invalid handler in bucket object chain');

                next(new Error('Invalid handler in bucket object chain' +
                    ' at index ' + (index - 1)));
            }
        }

        executeNext();
    }

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

// Test: executeHandlerChain - should catch handler exceptions
helper.test('executeHandlerChain catches handler exceptions', function (t) {
    function executeHandlerChain(handlersArg, reqArg, res, next) {
        var index = 0;

        function executeNext(err) {
            if (err) {
                return (next(err));
            }

            if (index >= handlersArg.length) {
                return (next());
            }

            var currentHandler = handlersArg[index++];

            if (typeof (currentHandler) === 'function') {
                try {
                    currentHandler(reqArg, res, executeNext);
                } catch (e) {
                    next(e);
                }
            } else {
                reqArg.log.error({
                    handlerIndex: index - 1,
                    handlerType: typeof (currentHandler),
                    handler: currentHandler
                }, 'Invalid handler in bucket object chain');

                next(new Error('Invalid handler in bucket object chain' +
                    ' at index ' + (index - 1)));
            }
        }

        executeNext();
    }

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
