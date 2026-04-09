/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Unit tests for MANTA-5517: CORS preflight handler no longer sets
 * overly permissive defaults.
 *
 * Verifies the corsPreflightHandler distinguishes service-level ("/")
 * from bucket-scoped ("/bucket/...") requests and sets appropriate
 * CORS headers for each.
 *
 * NOTE: We load corsPreflightHandler by extracting it from the source
 * file to avoid pulling in native module dependencies (bignum) that
 * don't compile on all platforms. The function under test has no
 * external dependencies beyond req/res/next.
 */

var fs = require('fs');
var path = require('path');
var vm = require('vm');


///--- Load corsPreflightHandler in isolation

/*
 * Extract corsPreflightHandler from middleware.js without requiring
 * the full module (which pulls in bignum via s3-compat -> common).
 */
var middlewareSrc = fs.readFileSync(
    path.join(__dirname, '..', 'lib', 'server', 'middleware.js'), 'utf8');

// Build a minimal sandbox that provides just enough for the function
var exportedHandler;
var sandbox = {
    module: { exports: {} },
    exports: {},
    require: function () {
        // Return empty stubs for all requires — we only need
        // corsPreflightHandler which has no external deps
        return ({});
    },
    console: console
};
sandbox.exports = sandbox.module.exports;

// We only need the corsPreflightHandler function. Extract it plus
// its setup from the source using a focused eval approach.
// Pull the function source directly.
var fnMatch = middlewareSrc.match(
    /* JSSTYLED */
    /function corsPreflightHandler\(req, res, next\) \{[\s\S]*?\n\}/);
if (!fnMatch) {
    throw new Error('Could not extract corsPreflightHandler from source');
}

/*jsl:ignore*/
var corsPreflightHandler = new Function(
    'return ' + fnMatch[0])();
/*jsl:end*/


///--- Helpers

function createMockRequest(options) {
    options = options || {};
    var headers = options.headers || {};

    return {
        method: options.method || 'OPTIONS',
        url: options.url || '/',
        headers: headers,
        path: function () {
            return (options.path || '/');
        },
        log: {
            debug: function () {}
        }
    };
}

function createMockResponse() {
    var hdrs = {};
    var statusCode = null;

    return {
        setHeader: function (k, v) {
            hdrs[k] = v;
        },
        getHeader: function (k) {
            return (hdrs[k]);
        },
        send: function (code) {
            statusCode = code;
        },
        _getHeaders: function () { return (hdrs); },
        _getStatusCode: function () { return (statusCode); }
    };
}

function createMockNext() {
    var called = false;
    var arg = undefined;

    function next(a) {
        called = true;
        arg = a;
    }

    next.wasCalled = function () { return (called); };
    next.getArg = function () { return (arg); };

    return (next);
}


///--- Tests: non-preflight pass-through

exports['non-preflight request calls next() directly'] = function (t) {
    var req = createMockRequest({
        headers: {}  // no access-control-request-method
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    t.ok(next.wasCalled(), 'next() should be called');
    t.strictEqual(next.getArg(), undefined,
        'next() should be called without arguments');
    t.strictEqual(res._getStatusCode(), null,
        'should not send a response');
    t.done();
};


///--- Tests: service-level preflight (path = "/")

exports['MANTA-5517: service-level preflight returns wildcard origin'] =
function (t) {
    var req = createMockRequest({
        path: '/',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'POST'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    var hdrs = res._getHeaders();
    t.equal(hdrs['Access-Control-Allow-Origin'], '*',
        'service-level should use wildcard origin');
    t.done();
};

exports['MANTA-5517: service-level preflight allows GET,POST,OPTIONS'] =
function (t) {
    var req = createMockRequest({
        path: '/',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'POST'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    var hdrs = res._getHeaders();
    t.equal(hdrs['Access-Control-Allow-Methods'], 'GET,POST,OPTIONS',
        'service-level should only allow GET,POST,OPTIONS');
    t.done();
};

exports['MANTA-5517: service-level preflight has no credentials header'] =
function (t) {
    var req = createMockRequest({
        path: '/',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'GET'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    var hdrs = res._getHeaders();
    t.strictEqual(hdrs['Access-Control-Allow-Credentials'], undefined,
        'service-level must NOT set Allow-Credentials');
    t.done();
};

exports['MANTA-5517: service-level preflight sends 200 and stops'] =
function (t) {
    var req = createMockRequest({
        path: '/',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'GET'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    t.equal(res._getStatusCode(), 200, 'should send 200');
    t.ok(next.wasCalled(), 'next() should be called');
    t.strictEqual(next.getArg(), false,
        'next(false) should stop the handler chain');
    t.done();
};

exports['MANTA-5517: service-level preflight sets Max-Age'] =
function (t) {
    var req = createMockRequest({
        path: '/',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'GET'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    var hdrs = res._getHeaders();
    t.equal(hdrs['Access-Control-Max-Age'], '3600');
    t.done();
};


///--- Tests: bucket-scoped preflight (path = "/bucket/...")

exports['MANTA-5517: bucket preflight returns wildcard origin'] =
function (t) {
    var req = createMockRequest({
        path: '/mybucket/object.txt',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'GET'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    var hdrs = res._getHeaders();
    t.equal(hdrs['Access-Control-Allow-Origin'], '*',
        'bucket-scoped should use wildcard origin (not echo origin)');
    t.done();
};

exports['MANTA-5517: bucket preflight has no credentials header'] =
function (t) {
    var req = createMockRequest({
        path: '/mybucket/object.txt',
        headers: {
            'origin': 'https://evil.example.com',
            'access-control-request-method': 'GET'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    var hdrs = res._getHeaders();
    t.strictEqual(hdrs['Access-Control-Allow-Credentials'], undefined,
        'bucket-scoped must NOT set Allow-Credentials');
    t.done();
};

exports['MANTA-5517: bucket preflight allows full method set'] =
function (t) {
    var req = createMockRequest({
        path: '/mybucket/object.txt',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'PUT'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    var hdrs = res._getHeaders();
    t.equal(hdrs['Access-Control-Allow-Methods'],
        'GET,PUT,POST,DELETE,HEAD,OPTIONS',
        'bucket-scoped should allow full S3 method set');
    t.done();
};

exports['MANTA-5517: bucket preflight includes x-amz-user-agent'] =
function (t) {
    var req = createMockRequest({
        path: '/mybucket',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'GET'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    var hdrs = res._getHeaders();
    t.ok(hdrs['Access-Control-Allow-Headers'].indexOf(
        'x-amz-user-agent') !== -1,
        'bucket-scoped should include x-amz-user-agent header');
    t.done();
};

exports['MANTA-5517: bucket preflight sets Vary: Origin'] =
function (t) {
    var req = createMockRequest({
        path: '/mybucket/object.txt',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'GET'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    var hdrs = res._getHeaders();
    t.equal(hdrs['Vary'], 'Origin',
        'bucket-scoped should set Vary: Origin');
    t.done();
};

exports['MANTA-5517: bucket preflight sends 200 and stops chain'] =
function (t) {
    var req = createMockRequest({
        path: '/mybucket/deep/path/object.txt',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'DELETE'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    t.equal(res._getStatusCode(), 200, 'should send 200');
    t.strictEqual(next.getArg(), false,
        'next(false) should stop the handler chain');
    t.done();
};


///--- Tests: service vs bucket distinction

exports['MANTA-5517: service-level excludes PUT,DELETE,HEAD methods'] =
function (t) {
    var req = createMockRequest({
        path: '/',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'PUT'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    var methods = res._getHeaders()['Access-Control-Allow-Methods'];
    t.equal(methods.indexOf('PUT'), -1,
        'service-level should not include PUT');
    t.equal(methods.indexOf('DELETE'), -1,
        'service-level should not include DELETE');
    t.done();
};

exports['MANTA-5517: bucket-only path "/mybucket" is bucket-scoped'] =
function (t) {
    var req = createMockRequest({
        path: '/mybucket',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'GET'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    var methods = res._getHeaders()['Access-Control-Allow-Methods'];
    t.ok(methods.indexOf('DELETE') !== -1,
        '/mybucket should be treated as bucket-scoped');
    t.done();
};

exports['MANTA-5517: service-level excludes x-amz-user-agent'] =
function (t) {
    var req = createMockRequest({
        path: '/',
        headers: {
            'origin': 'https://app.example.com',
            'access-control-request-method': 'GET'
        }
    });
    var res = createMockResponse();
    var next = createMockNext();

    corsPreflightHandler(req, res, next);

    var allowHeaders = res._getHeaders()['Access-Control-Allow-Headers'];
    t.equal(allowHeaders.indexOf('x-amz-user-agent'), -1,
        'service-level should not include x-amz-user-agent');
    t.done();
};
