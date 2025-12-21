/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * Standalone middleware tests (no heavy dependencies)
 */

var middleware = require('../lib/server/middleware');

// Mock request helper
function createMockRequest(options) {
    options = options || {};
    var headers = options.headers || {};
    var debugLogs = [];

    var mockReq = {
        method: options.method || 'GET',
        url: options.url || '/',
        headers: headers,
        query: options.query || {},
        path: function () {
            return (options.path || '/');
        },
        isChunked: function () {
            return (options.isChunked || false);
        },
        log: {
            debug: function (obj, msg) {
                debugLogs.push({ obj: obj, msg: msg });
            }
        },
        _debugLogs: debugLogs,
        setEncoding: function (encoding) {
            mockReq._encoding = encoding;
        },
        _readableState: {
            encoding: 'utf8',
            decoder: {},
            objectMode: false
        },
        readable: {
            setEncoding: function (encoding) {
                mockReq.readable._encoding = encoding;
            }
        },
        connection: {
            setEncoding: function (encoding) {
                mockReq.connection._encoding = encoding;
            },
            parser: {
                incoming: null
            }
        }
    };

    return (mockReq);
}

function createMockNext() {
    var called = false;
    var error = null;

    function next(err) {
        called = true;
        error = err;
    }

    next.wasCalled = function () { return (called); };
    next.getError = function () { return (error); };

    return (next);
}

exports['logAllRequests logs request details'] = function (t) {
    var req = createMockRequest({
        method: 'GET',
        url: '/bucket/object.txt',
        headers: { 'host': 's3.example.com' }
    });
    var next = createMockNext();

    middleware.logAllRequests(req, {}, next);

    t.ok(next.wasCalled(), 'should call next()');
    t.equal(req._debugLogs.length, 1);
    t.equal(req._debugLogs[0].obj.method, 'GET');
    t.done();
};

exports['logAllRequests does not modify request'] = function (t) {
    var req = createMockRequest({
        method: 'PUT',
        headers: { 'authorization': 'AWS4-HMAC-SHA256 ...' }
    });
    var next = createMockNext();

    middleware.logAllRequests(req, {}, next);

    t.ok(next.wasCalled());
    t.ok(!req._isS3Upload, 'should not set _isS3Upload');
    t.ok(!req._binaryMode, 'should not set _binaryMode');
    t.done();
};

exports['detectS3Uploads detects PUT with SigV4'] = function (t) {
    var req = createMockRequest({
        method: 'PUT',
        headers: { 'authorization': 'AWS4-HMAC-SHA256 Credential=...' }
    });
    var next = createMockNext();

    middleware.detectS3Uploads(req, {}, next);

    t.ok(next.wasCalled());
    t.ok(req._isS3Upload, 'should set _isS3Upload flag');
    t.done();
};

exports['detectS3Uploads detects POST with SigV4'] = function (t) {
    var req = createMockRequest({
        method: 'POST',
        headers: { 'authorization': 'aws4-hmac-sha256 Credential=...' }
    });
    var next = createMockNext();

    middleware.detectS3Uploads(req, {}, next);

    t.ok(next.wasCalled());
    t.ok(req._isS3Upload);
    t.done();
};

exports['detectS3Uploads ignores GET requests'] = function (t) {
    var req = createMockRequest({
        method: 'GET',
        headers: { 'authorization': 'AWS4-HMAC-SHA256 Credential=...' }
    });
    var next = createMockNext();

    middleware.detectS3Uploads(req, {}, next);

    t.ok(next.wasCalled());
    t.ok(!req._isS3Upload, 'should not set flag for GET');
    t.done();
};

exports['detectS3Uploads ignores non-SigV4'] = function (t) {
    var req = createMockRequest({
        method: 'PUT',
        headers: { 'authorization': 'Signature keyId="..."' }
    });
    var next = createMockNext();

    middleware.detectS3Uploads(req, {}, next);

    t.ok(next.wasCalled());
    t.ok(!req._isS3Upload);
    t.done();
};

exports['configureBinaryMode configures for S3 uploads'] = function (t) {
    var req = createMockRequest({ method: 'PUT' });
    req._isS3Upload = true;
    var next = createMockNext();

    middleware.configureBinaryMode(req, {}, next);

    t.ok(next.wasCalled());
    t.ok(req._binaryMode, 'should set _binaryMode');
    t.ok(req._forceRawData, 'should set _forceRawData');
    t.equal(req._encoding, null, 'should set encoding to null');
    t.equal(req._readableState.encoding, null);
    t.done();
};

exports['configureBinaryMode skips non-S3 requests'] = function (t) {
    var req = createMockRequest({ method: 'GET' });
    var next = createMockNext();

    middleware.configureBinaryMode(req, {}, next);

    t.ok(next.wasCalled());
    t.ok(!req._binaryMode, 'should not set _binaryMode');
    t.done();
};

exports['full pipeline - S3 upload flow'] = function (t) {
    var req = createMockRequest({
        method: 'PUT',
        url: '/bucket/object.txt',
        headers: { 'authorization': 'AWS4-HMAC-SHA256 Credential=...' }
    });

    var next1 = createMockNext();
    var next2 = createMockNext();
    var next3 = createMockNext();

    middleware.logAllRequests(req, {}, next1);
    middleware.detectS3Uploads(req, {}, next2);
    middleware.configureBinaryMode(req, {}, next3);

    t.ok(next1.wasCalled() && next2.wasCalled() && next3.wasCalled());
    t.ok(req._isS3Upload, 'should detect S3 upload');
    t.ok(req._binaryMode, 'should enable binary mode');
    t.done();
};

exports['full pipeline - non-S3 request'] = function (t) {
    var req = createMockRequest({
        method: 'GET',
        headers: { 'authorization': 'Signature keyId="..."' }
    });

    var next1 = createMockNext();
    var next2 = createMockNext();
    var next3 = createMockNext();

    middleware.logAllRequests(req, {}, next1);
    middleware.detectS3Uploads(req, {}, next2);
    middleware.configureBinaryMode(req, {}, next3);

    t.ok(next1.wasCalled() && next2.wasCalled() && next3.wasCalled());
    t.ok(!req._isS3Upload, 'should not detect as S3 upload');
    t.ok(!req._binaryMode, 'should not enable binary mode');
    t.done();
};

// Helper to create event emitter mock for stream testing
function createStreamMockRequest(options) {
    var req = createMockRequest(options);
    var listeners = {
        data: [],
        end: [],
        error: []
    };
    var paused = false;
    var resumed = false;

    req.pause = function () {
        paused = true;
    };

    req.resume = function () {
        resumed = true;
    };

    req.on = function (event, callback) {
        if (listeners[event]) {
            listeners[event].push(callback);
        }
    };

    req._isPaused = function () { return paused; };
    req._isResumed = function () { return resumed; };
    req._emit = function (event, data) {
        if (listeners[event]) {
            listeners[event].forEach(function (cb) {
                cb(data);
            });
        }
    };

    return (req);
}

exports['preserveRawBody detects CompleteMultipartUpload with uploadId'] =
function (t) {
    var req = createStreamMockRequest({
        method: 'POST',
        url: '/bucket/object.txt?uploadId=abc123',
        headers: {
            'authorization': 'AWS4-HMAC-SHA256 Credential=...',
            'content-type': 'application/xml',
            'content-length': '100'
        }
    });

    var next = createMockNext();
    middleware.preserveRawBodyPreMiddleware(req, {}, next);

    // Verify stream was paused and resumed
    t.ok(req._isPaused(), 'should pause stream');
    t.ok(req._isResumed(), 'should resume stream');

    // Emit end event to trigger next()
    req._emit('end');

    t.ok(next.wasCalled(), 'should call next()');
    t.done();
};

exports['preserveRawBody excludes InitiateMultipartUpload with ' +
    'uploads param'] = function (t) {
    var req = createStreamMockRequest({
        method: 'POST',
        url: '/bucket/object.txt?uploads',
        headers: {
            'authorization': 'AWS4-HMAC-SHA256 Credential=...',
            'content-type': 'text/plain',
            'content-length': '100'
        }
    });

    var next = createMockNext();
    middleware.preserveRawBodyPreMiddleware(req, {}, next);

    // Should not pause/resume because uploads param means
    // InitiateMultipartUpload and content-type is not XML
    t.ok(!req._isPaused(), 'should not pause for InitiateMultipartUpload');

    // Since it's not detected as a raw body operation, next() is
    // called immediately
    t.ok(next.wasCalled(), 'should call next()');
    t.done();
};

exports['preserveRawBody handles object path containing uploads'] =
function (t) {
    var req = createStreamMockRequest({
        method: 'POST',
        url: '/bucket/my-uploads-file.txt?uploadId=xyz789',
        headers: {
            'authorization': 'AWS4-HMAC-SHA256 Credential=...',
            'content-type': 'application/xml',
            'content-length': '100'
        }
    });

    var next = createMockNext();
    middleware.preserveRawBodyPreMiddleware(req, {}, next);

    // Verify stream was paused (CompleteMultipartUpload detected)
    t.ok(req._isPaused(),
        'should pause stream even when path contains uploads');
    t.ok(req._isResumed(), 'should resume stream');

    // Emit end event to trigger next()
    req._emit('end');

    t.ok(next.wasCalled(), 'should call next()');
    t.done();
};

exports['preserveRawBody handles nested path with uploads'] =
function (t) {
    var req = createStreamMockRequest({
        method: 'POST',
        url: '/bucket/data/uploads/document.pdf?uploadId=def456',
        headers: {
            'authorization': 'AWS4-HMAC-SHA256 Credential=...',
            'content-type': 'application/xml',
            'content-length': '100'
        }
    });

    var next = createMockNext();
    middleware.preserveRawBodyPreMiddleware(req, {}, next);

    t.ok(req._isPaused(),
        'should detect CompleteMultipartUpload for nested path');
    t.ok(req._isResumed(), 'should resume stream');

    req._emit('end');
    t.ok(next.wasCalled(), 'should call next()');
    t.done();
};

exports['preserveRawBody differentiates uploadId vs uploads param'] =
function (t) {
    // Test case 1: uploadId only (CompleteMultipartUpload)
    var req1 = createStreamMockRequest({
        method: 'POST',
        url: '/bucket/file.txt?uploadId=123',
        headers: {
            'authorization': 'AWS4-HMAC-SHA256 Credential=...',
            'content-type': 'application/xml',
            'content-length': '100'
        }
    });

    middleware.preserveRawBodyPreMiddleware(req1, {}, createMockNext());
    t.ok(req1._isPaused(), 'uploadId param should be detected');

    // Test case 2: uploads only (InitiateMultipartUpload)
    // Use non-XML content-type to isolate CompleteMultipartUpload detection
    var req2 = createStreamMockRequest({
        method: 'POST',
        url: '/bucket/file.txt?uploads',
        headers: {
            'authorization': 'AWS4-HMAC-SHA256 Credential=...',
            'content-type': 'text/plain',
            'content-length': '100'
        }
    });

    middleware.preserveRawBodyPreMiddleware(req2, {}, createMockNext());
    t.ok(!req2._isPaused(), 'uploads param should not be detected as Complete');

    // Test case 3: both params (should not happen in practice, but test
    // precedence) - Use non-XML content-type
    var req3 = createStreamMockRequest({
        method: 'POST',
        url: '/bucket/file.txt?uploads&uploadId=456',
        headers: {
            'authorization': 'AWS4-HMAC-SHA256 Credential=...',
            'content-type': 'text/plain',
            'content-length': '100'
        }
    });

    middleware.preserveRawBodyPreMiddleware(req3, {}, createMockNext());
    t.ok(!req3._isPaused(),
        'both params should exclude (uploads takes precedence)');

    t.done();
};

exports['preserveRawBody detects CORS configuration request'] =
function (t) {
    var req = createStreamMockRequest({
        method: 'PUT',
        url: '/bucket?cors',
        headers: {
            'authorization': 'AWS4-HMAC-SHA256 Credential=...',
            'content-type': 'application/xml',
            'content-length': '100'
        }
    });

    var next = createMockNext();
    middleware.preserveRawBodyPreMiddleware(req, {}, next);

    t.ok(req._isPaused(), 'should pause stream for CORS request');
    t.ok(req._isResumed(), 'should resume stream');

    req._emit('end');
    t.ok(next.wasCalled(), 'should call next()');
    t.done();
};

exports['preserveRawBody handles object path containing cors'] =
function (t) {
    var req = createStreamMockRequest({
        method: 'PUT',
        url: '/bucket/mycorsfile.txt',
        headers: {
            'authorization': 'AWS4-HMAC-SHA256 Credential=...',
            'content-type': 'text/plain',
            'content-length': '100'
        }
    });

    var next = createMockNext();
    middleware.preserveRawBodyPreMiddleware(req, {}, next);

    // Should not pause because 'cors' is in path, not query param
    t.ok(!req._isPaused(),
        'should not pause for object path containing cors');
    t.ok(next.wasCalled(), 'should call next()');
    t.done();
};

exports['preserveRawBody detects bulk delete request'] = function (t) {
    var req = createStreamMockRequest({
        method: 'POST',
        url: '/bucket?delete',
        headers: {
            'authorization': 'AWS4-HMAC-SHA256 Credential=...',
            'content-type': 'application/xml',
            'content-length': '100'
        }
    });

    var next = createMockNext();
    middleware.preserveRawBodyPreMiddleware(req, {}, next);

    t.ok(req._isPaused(), 'should pause stream for bulk delete');
    t.ok(req._isResumed(), 'should resume stream');

    req._emit('end');
    t.ok(next.wasCalled(), 'should call next()');
    t.done();
};

exports['preserveRawBody handles object path containing delete'] =
function (t) {
    var req = createStreamMockRequest({
        method: 'POST',
        url: '/bucket/delete-this-file.txt',
        headers: {
            'authorization': 'AWS4-HMAC-SHA256 Credential=...',
            'content-type': 'text/plain',
            'content-length': '100'
        }
    });

    var next = createMockNext();
    middleware.preserveRawBodyPreMiddleware(req, {}, next);

    // Should not pause because 'delete' is in path, not query param
    t.ok(!req._isPaused(),
        'should not pause for object path containing delete');
    t.ok(next.wasCalled(), 'should call next()');
    t.done();
};
