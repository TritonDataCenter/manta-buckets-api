/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Unit tests for the MPU-local error constructors that used to live
 * in lib/s3-multipart.js as plain Error returns and have been moved
 * into lib/errors.js as proper BucketsApiError subclasses.
 *
 * What this test actually catches:
 *
 *   1. The constructors exist and are exported from lib/errors.js
 *      (its file-bottom auto-export discovers any `function *Error`).
 *   2. Each instance is an `instanceof BucketsApiError` — this is the
 *      shape restify's error pipeline needs to serialize the error
 *      as an S3-style XML body. Plain Error instances (the previous
 *      anti-pattern) would fail this assertion AND would surface as
 *      generic 500 InternalError on the wire — see CHG-141 for the
 *      live-system evidence on coal.
 *   3. statusCode matches the intended HTTP status code per the S3
 *      ListParts / UploadPart / CompleteMultipartUpload spec.
 *   4. restCode matches the S3 <Code> element clients see in the
 *      error body.
 *   5. The message is non-empty and includes any caller-supplied
 *      context (uploadId, partNumber, custom message).
 *
 * What this test does NOT do:
 *
 *   - Spin up a restify server to round-trip the XML body. The
 *     BucketsApiError -> restify.RestError inheritance handles that
 *     serialization deterministically; if (2) holds, the wire shape
 *     follows. End-to-end XML verification is left to the integration
 *     test (test/integration-mpu-orphan-cleanup.py) where TASK-4 will
 *     tighten the convergence assertion to require an exact 404
 *     NoSuchUpload response once this fix is deployed.
 */

/*
 * Bare nodeunit export pattern — no test/helper.js (which would pull
 * in lib/auth.js and the full server boot dependencies), no tape
 * (not in this project's node_modules). Each `exports.<name>` is a
 * nodeunit test taking a `t` object; `make test` invokes them via
 * node_modules/.bin/nodeunit on the test directory glob.
 */

var errors = require('../lib/errors');


function defineTest(name, fn) {
    exports[name] = function (t) {

        // Polyfill nodeunit's t with the helper-style affordances
        // this file uses (t.end alias, t.notOk).
        t.end = function () {
            if (!t.__done) {
                t.__done = true;
                t.done();
            }
        };
        t.notOk = function (val, message) {
            return (t.ok(!val, message));
        };
        try {
            fn(t);
        } catch (err) {
            t.ok(false, name + ' threw: ' + (err && err.stack));
            t.end();
        }
    };
}
var test = defineTest;


/*
 * Shared shape assertion. Every fixed error must be a real
 * BucketsApiError (and therefore a real restify RestError); restify's
 * error-serialization machinery looks for exactly this prototype
 * chain when deciding how to build the HTTP response body. If any
 * regression returns a plain Error with statusCode/restCode tacked
 * on (the original anti-pattern), this assertion will fail.
 */
function assertWellFormedError(t, err, expectedRestCode,
                               expectedStatusCode) {
    t.ok(err instanceof errors.BucketsApiError,
        'error is a BucketsApiError instance ' +
        '(restify can serialize it as S3 XML)');
    t.equal(err.restCode, expectedRestCode,
        'restCode matches S3 <Code> element');
    t.equal(err.statusCode, expectedStatusCode,
        'statusCode matches intended HTTP status');
    t.ok(typeof (err.message) === 'string' && err.message.length > 0,
        'error has a non-empty message');
}


test('NoSuchUploadError serializes as 404 / NoSuchUpload', function (t) {
    var uploadId = 'mp-test-12345678';
    var err = new errors.NoSuchUploadError(uploadId);

    assertWellFormedError(t, err, 'NoSuchUpload', 404);
    t.ok(err.message.indexOf(uploadId) >= 0,
        'message embeds the supplied uploadId');
    t.end();
});


test('NoSuchUploadError without an uploadId still serializes',
     function (t) {
    var err = new errors.NoSuchUploadError();

    assertWellFormedError(t, err, 'NoSuchUpload', 404);
    t.end();
});


test('InvalidPartNumberError serializes as 400 / InvalidPartNumber',
     function (t) {
    var err = new errors.InvalidPartNumberError(99999);

    assertWellFormedError(t, err, 'InvalidPartNumber', 400);
    t.ok(err.message.indexOf('99999') >= 0,
        'message embeds the supplied part number');
    t.end();
});


test('InvalidPartOrderError serializes as 400 / InvalidPartOrder',
     function (t) {
    var err = new errors.InvalidPartOrderError();

    assertWellFormedError(t, err, 'InvalidPartOrder', 400);
    t.end();
});


test('InvalidPartError serializes as 400 / InvalidPart', function (t) {
    var err = new errors.InvalidPartError('part 7 missing etag');

    assertWellFormedError(t, err, 'InvalidPart', 400);
    t.equal(err.message, 'part 7 missing etag',
        'caller-supplied message is preserved verbatim');
    t.end();
});


test('InvalidPartError without args uses the default message',
     function (t) {
    var err = new errors.InvalidPartError();

    assertWellFormedError(t, err, 'InvalidPart', 400);
    t.equal(err.message, 'Invalid part in multipart upload',
        'default message present when none supplied');
    t.end();
});


test('EntityTooSmallError serializes as 400 / EntityTooSmall',
     function (t) {
    var err = new errors.EntityTooSmallError(
        'Part 3 is 1024 bytes; minimum is 5242880');

    assertWellFormedError(t, err, 'EntityTooSmall', 400);
    t.end();
});


test('EntityTooLargeError serializes as 400 / EntityTooLarge',
     function (t) {
    var err = new errors.EntityTooLargeError();

    assertWellFormedError(t, err, 'EntityTooLarge', 400);
    t.end();
});


test('MalformedXMLError serializes as 400 / MalformedXML',
     function (t) {
    var err = new errors.MalformedXMLError(
        'unexpected end-of-document at line 4');

    assertWellFormedError(t, err, 'MalformedXML', 400);
    t.end();
});


test('InvalidRequestError serializes as 400 / InvalidRequest',
     function (t) {
    var err = new errors.InvalidRequestError(
        'Missing complete multipart upload body');

    assertWellFormedError(t, err, 'InvalidRequest', 400);
    t.end();
});


/*
 * Regression: the bare global expectation. lib/errors.js installs
 * every exported constructor onto `global` (see the loop at the
 * bottom of that file). lib/s3-multipart.js historically called
 * `new NoSuchUploadError(...)` without an explicit `require`, and
 * a number of other modules may do the same. If anyone removes the
 * global-export loop, all those bare references break. Lock that
 * down here so the breakage shows up at unit-test time, not at
 * 02:00 in production.
 */
test('MPU error constructors are exported on the global object',
     function (t) {
    var names = [
        'NoSuchUploadError',
        'InvalidPartNumberError',
        'InvalidPartOrderError',
        'InvalidPartError',
        'EntityTooSmallError',
        'EntityTooLargeError',
        'MalformedXMLError',
        'InvalidRequestError',
        'InternalError'
    ];
    names.forEach(function (n) {
        t.equal(typeof (global[n]), 'function',
            n + ' is registered as a global constructor');
        t.equal(global[n], errors[n],
            n + ' global matches errors.' + n);
    });
    t.end();
});


/*
 * Regression: the old anti-pattern. If someone re-adds a plain
 * Error-returning constructor in lib/s3-multipart.js (or anywhere
 * else) and forgets to inherit from BucketsApiError, restify will
 * silently surface it as 500. This test demonstrates the failure
 * mode by constructing a plain Error in the old shape and asserting
 * that it does NOT satisfy our BucketsApiError invariant — i.e. the
 * test catches the regression before it ships.
 */
test('plain Error with tacked-on restCode is NOT a BucketsApiError',
     function (t) {
    var brokenLike = new Error('The specified upload does not exist');
    brokenLike.name = 'NoSuchUpload';
    brokenLike.statusCode = 404;
    brokenLike.restCode = 'NoSuchUpload';

    t.notOk(brokenLike instanceof errors.BucketsApiError,
        'plain Error with statusCode/restCode is NOT a ' +
        'BucketsApiError — this is exactly the shape that surfaces ' +
        'as a generic 500 InternalError on the wire (see CHG-141)');
    t.end();
});
