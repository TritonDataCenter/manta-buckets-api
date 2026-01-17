/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * STS Body Precedence Integration Tests
 *
 * Tests that STS handlers correctly give request body parameters precedence
 * over query parameters, per AWS Query API specification.
 *
 * These tests exercise the actual production handlers in lib/sts-handlers.js
 * by creating mock clients and verifying which parameters are passed through.
 */

var helper = require('./s3-test-helper.js');
var stsHandlers = require('../lib/sts-handlers.js');
var bunyan = require('bunyan');

// Test logger (silent)
var LOG = bunyan.createLogger({
    name: 'sts-body-precedence-test',
    level: 'fatal'
});

/**
 * Create a mock STS client that captures parameters passed to it.
 * This allows us to verify which parameter values the handler used.
 */
function createMockSTSClient(capturedParams) {
    return {
        assumeRole: function (opts, callback) {
            capturedParams.roleArn = opts.roleArn;
            capturedParams.roleSessionName = opts.roleSessionName;
            capturedParams.durationSeconds = opts.durationSeconds;

            // Return success with mock credentials
            callback(null, {
                Credentials: {
                    AccessKeyId: 'MOCK_ACCESS_KEY',
                    SecretAccessKey: 'MOCK_SECRET_KEY',
                    SessionToken: 'MOCK_SESSION_TOKEN',
                    Expiration: new Date().toISOString()
                },
                AssumedRoleUser: {
                    AssumedRoleId: 'MOCK_ROLE_ID:test-session',
                    Arn: opts.roleArn
                }
            });
        },
        getSessionToken: function (opts, callback) {
            capturedParams.durationSeconds = opts.durationSeconds;

            // Return success with mock credentials
            callback(null, {
                Credentials: {
                    AccessKeyId: 'MOCK_ACCESS_KEY',
                    SecretAccessKey: 'MOCK_SECRET_KEY',
                    SessionToken: 'MOCK_SESSION_TOKEN',
                    Expiration: new Date().toISOString()
                }
            });
        }
    };
}

/**
 * Create a mock request object for testing.
 */
function createMockRequest(body, query) {
    return {
        body: body,
        query: query,
        headers: {
            'content-type': 'application/x-www-form-urlencoded'
        },
        log: LOG,
        caller: {
            account: {
                uuid: 'test-account-uuid',
                login: 'testuser'
            }
        },
        auth: {
            isTemporaryCredential: false
        }
    };
}

/**
 * Create a mock response object for testing.
 */
function createMockResponse(capturedResponse) {
    return {
        setHeader: function (name, value) {
            capturedResponse.headers = capturedResponse.headers || {};
            capturedResponse.headers[name] = value;
        },
        writeHead: function (statusCode) {
            capturedResponse.statusCode = statusCode;
        },
        end: function (body) {
            capturedResponse.body = body;
        }
    };
}


// ========== AssumeRole Body Precedence Tests ==========

helper.test('AssumeRole: body RoleArn takes precedence over query',
            function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockSTSClient(capturedParams);
    var handler = stsHandlers.assumeRoleHandler(mockClient);

    var bodyParams = {
        RoleArn: 'arn:manta:iam::123:role/body-role',
        RoleSessionName: 'test-session'
    };
    var queryParams = {
        RoleArn: 'arn:manta:iam::123:role/query-role',
        RoleSessionName: 'query-session'
    };
    var req = createMockRequest(bodyParams, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.roleArn, 'arn:manta:iam::123:role/body-role',
                'body RoleArn should take precedence over query');
        t.equal(capturedParams.roleSessionName, 'test-session',
                'body RoleSessionName should take precedence');
        t.end();
    });
});

helper.test('AssumeRole: query RoleArn used when body empty', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockSTSClient(capturedParams);
    var handler = stsHandlers.assumeRoleHandler(mockClient);

    var queryParams = {
        RoleArn: 'arn:manta:iam::123:role/query-role',
        RoleSessionName: 'query-session'
    };
    var req = createMockRequest({}, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.roleArn, 'arn:manta:iam::123:role/query-role',
                'query RoleArn should be used when body empty');
        t.equal(capturedParams.roleSessionName, 'query-session',
                'query RoleSessionName should be used when body empty');
        t.end();
    });
});

helper.test('AssumeRole: body DurationSeconds takes precedence', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockSTSClient(capturedParams);
    var handler = stsHandlers.assumeRoleHandler(mockClient);

    var bodyParams = {
        RoleArn: 'arn:manta:iam::123:role/test-role',
        RoleSessionName: 'test-session',
        DurationSeconds: '7200'
    };
    var queryParams = {DurationSeconds: '3600'};
    var req = createMockRequest(bodyParams, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.durationSeconds, 7200,
                'body DurationSeconds should take precedence (parsed as int)');
        t.end();
    });
});

helper.test('AssumeRole: query DurationSeconds used when body empty',
            function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockSTSClient(capturedParams);
    var handler = stsHandlers.assumeRoleHandler(mockClient);

    var bodyParams = {
        RoleArn: 'arn:manta:iam::123:role/test-role',
        RoleSessionName: 'test-session'
    };
    var queryParams = {DurationSeconds: '3600'};
    var req = createMockRequest(bodyParams, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.durationSeconds, 3600,
                'query DurationSeconds should be used as fallback');
        t.end();
    });
});

helper.test('AssumeRole: mixed body and query params', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockSTSClient(capturedParams);
    var handler = stsHandlers.assumeRoleHandler(mockClient);

    var bodyParams = {
        RoleArn: 'arn:manta:iam::123:role/body-role',
        DurationSeconds: '7200'
    };
    var queryParams = {
        RoleArn: 'arn:manta:iam::123:role/query-role',
        RoleSessionName: 'query-session',
        DurationSeconds: '3600'
    };
    var req = createMockRequest(bodyParams, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.roleArn, 'arn:manta:iam::123:role/body-role',
                'body RoleArn should take precedence');
        t.equal(capturedParams.roleSessionName, 'query-session',
                'query RoleSessionName should be used (not in body)');
        t.equal(capturedParams.durationSeconds, 7200,
                'body DurationSeconds should take precedence');
        t.end();
    });
});


// ========== GetSessionToken Body Precedence Tests ==========

helper.test('GetSessionToken: body DurationSeconds takes precedence',
            function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockSTSClient(capturedParams);
    var handler = stsHandlers.getSessionTokenHandler(mockClient);

    var req = createMockRequest({DurationSeconds: '43200'},
                                {DurationSeconds: '3600'});
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.durationSeconds, 43200,
                'body DurationSeconds should take precedence');
        t.end();
    });
});

helper.test('GetSessionToken: query DurationSeconds used when body empty',
            function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockSTSClient(capturedParams);
    var handler = stsHandlers.getSessionTokenHandler(mockClient);

    var req = createMockRequest({}, {DurationSeconds: '3600'});
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.durationSeconds, 3600,
                'query DurationSeconds should be used as fallback');
        t.end();
    });
});


// ========== Edge Cases ==========

helper.test('AssumeRole: body param is empty string falls back to query',
            function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockSTSClient(capturedParams);
    var handler = stsHandlers.assumeRoleHandler(mockClient);

    var bodyParams = {RoleArn: '', RoleSessionName: 'test-session'};
    var queryParams = {RoleArn: 'arn:manta:iam::123:role/query-role'};
    var req = createMockRequest(bodyParams, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        // Empty string is falsy, so query should be used
        t.equal(capturedParams.roleArn, 'arn:manta:iam::123:role/query-role',
                'query RoleArn should be used when body is empty string');
        t.end();
    });
});

helper.test('AssumeRole: returns error when RoleArn missing', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockSTSClient(capturedParams);
    var handler = stsHandlers.assumeRoleHandler(mockClient);

    var req = createMockRequest({}, {});
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedResponse.statusCode, 400,
                'should return 400 when RoleArn is missing');
        t.ok(capturedResponse.body.indexOf('RoleArn') > -1,
             'error should mention RoleArn');
        t.end();
    });
});
