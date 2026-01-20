/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * IAM Body Precedence Integration Tests
 *
 * Tests that IAM handlers correctly give request body parameters precedence
 * over query parameters, per AWS Query API specification.
 *
 * These tests exercise the actual production handlers in lib/iam-handlers.js
 * by creating mock clients and verifying which parameters are passed through.
 */

var helper = require('./s3-test-helper.js');
var iamHandlers = require('../lib/iam-handlers.js');
var bunyan = require('bunyan');

// Test logger (silent)
var LOG = bunyan.createLogger({
    name: 'iam-body-precedence-test',
    level: 'fatal'
});

/**
 * Create a mock IAM client that captures parameters passed to it.
 * This allows us to verify which parameter values the handler used.
 */
function createMockIAMClient(capturedParams) {
    return {
        createRole: function (opts, callback) {
            capturedParams.roleName = opts.roleName;
            capturedParams.assumeRolePolicyDocument =
                opts.assumeRolePolicyDocument;
            capturedParams.description = opts.description;
            capturedParams.path = opts.path;

            callback(null, {
                Role: {
                    RoleName: opts.roleName,
                    Arn: 'arn:manta:iam::123:role/' + opts.roleName,
                    CreateDate: new Date().toISOString(),
                    Path: opts.path || '/',
                    RoleId: 'MOCK_ROLE_ID'
                }
            });
        },
        getRole: function (opts, callback) {
            capturedParams.roleName = opts.roleName;

            callback(null, {
                Role: {
                    RoleName: opts.roleName,
                    Arn: 'arn:manta:iam::123:role/' + opts.roleName,
                    CreateDate: new Date().toISOString(),
                    Path: '/',
                    RoleId: 'MOCK_ROLE_ID'
                }
            });
        },
        putRolePolicy: function (opts, callback) {
            capturedParams.roleName = opts.roleName;
            capturedParams.policyName = opts.policyName;
            capturedParams.policyDocument = opts.policyDocument;

            callback(null, {});
        },
        deleteRolePolicy: function (opts, callback) {
            capturedParams.roleName = opts.roleName;
            capturedParams.policyName = opts.policyName;

            callback(null, {});
        },
        listRoles: function (opts, callback) {
            capturedParams.maxItems = opts.maxItems;
            capturedParams.marker = opts.marker;

            callback(null, {
                Roles: [],
                IsTruncated: false
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
        },
        getId: function () {
            return ('test-request-id');
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
        getHeader: function (name) {
            capturedResponse.headers = capturedResponse.headers || {};
            return (capturedResponse.headers[name]);
        },
        writeHead: function (statusCode) {
            capturedResponse.statusCode = statusCode;
        },
        end: function (body) {
            capturedResponse.body = body;
        }
    };
}


// ========== CreateRole Body Precedence Tests ==========

helper.test('CreateRole: body RoleName takes precedence over query',
            function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.createRoleHandler(mockClient);

    var bodyParams = {
        RoleName: 'body-role',
        AssumeRolePolicyDocument: '{"Version":"2012-10-17","Statement":[]}'
    };
    var queryParams = {RoleName: 'query-role'};
    var req = createMockRequest(bodyParams, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.roleName, 'body-role',
                'body RoleName should take precedence over query');
        t.end();
    });
});

helper.test('CreateRole: query RoleName used when body empty', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.createRoleHandler(mockClient);

    var bodyParams = {
        AssumeRolePolicyDocument: '{"Version":"2012-10-17","Statement":[]}'
    };
    var queryParams = {RoleName: 'query-role'};
    var req = createMockRequest(bodyParams, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.roleName, 'query-role',
                'query RoleName should be used when body empty');
        t.end();
    });
});

helper.test('CreateRole: body Description and Path take precedence',
            function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.createRoleHandler(mockClient);

    var bodyParams = {
        RoleName: 'test-role',
        Description: 'body description',
        Path: '/body/',
        AssumeRolePolicyDocument: '{"Version":"2012-10-17","Statement":[]}'
    };
    var queryParams = {Description: 'query description', Path: '/query/'};
    var req = createMockRequest(bodyParams, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.description, 'body description',
                'body Description should take precedence');
        t.equal(capturedParams.path, '/body/',
                'body Path should take precedence');
        t.end();
    });
});


// ========== GetRole Body Precedence Tests ==========

helper.test('GetRole: body RoleName takes precedence over query', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.getRoleHandler(mockClient);

    var req = createMockRequest({RoleName: 'body-role'},
                                {RoleName: 'query-role'});
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.roleName, 'body-role',
                'body RoleName should take precedence over query');
        t.end();
    });
});

helper.test('GetRole: query RoleName used when body empty', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.getRoleHandler(mockClient);

    var req = createMockRequest({}, {RoleName: 'query-role'});
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.roleName, 'query-role',
                'query RoleName should be used when body empty');
        t.end();
    });
});


// ========== PutRolePolicy Body Precedence Tests ==========

helper.test('PutRolePolicy: body parameters take precedence', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.putRolePolicyHandler(mockClient);

    var bodyPolicy = '{"Version":"2012-10-17","Statement":[]}';
    var queryPolicy =
        '{"Version":"2012-10-17","Statement":[{"Effect":"Deny"}]}';

    var bodyParams = {
        RoleName: 'body-role',
        PolicyName: 'body-policy',
        PolicyDocument: bodyPolicy
    };
    var queryParams = {
        RoleName: 'query-role',
        PolicyName: 'query-policy',
        PolicyDocument: queryPolicy
    };
    var req = createMockRequest(bodyParams, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.roleName, 'body-role',
                'body RoleName should take precedence');
        t.equal(capturedParams.policyName, 'body-policy',
                'body PolicyName should take precedence');
        t.end();
    });
});

helper.test('PutRolePolicy: query params used when body empty', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.putRolePolicyHandler(mockClient);

    var queryPolicy = '{"Version":"2012-10-17","Statement":[]}';
    var queryParams = {
        RoleName: 'query-role',
        PolicyName: 'query-policy',
        PolicyDocument: queryPolicy
    };
    var req = createMockRequest({}, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.roleName, 'query-role',
                'query RoleName should be used as fallback');
        t.equal(capturedParams.policyName, 'query-policy',
                'query PolicyName should be used as fallback');
        t.end();
    });
});


// ========== DeleteRolePolicy Body Precedence Tests ==========

helper.test('DeleteRolePolicy: body parameters take precedence', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.deleteRolePolicyHandler(mockClient);

    var bodyParams = {RoleName: 'body-role', PolicyName: 'body-policy'};
    var queryParams = {RoleName: 'query-role', PolicyName: 'query-policy'};
    var req = createMockRequest(bodyParams, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.roleName, 'body-role',
                'body RoleName should take precedence');
        t.equal(capturedParams.policyName, 'body-policy',
                'body PolicyName should take precedence');
        t.end();
    });
});

helper.test('DeleteRolePolicy: query params used when body empty',
            function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.deleteRolePolicyHandler(mockClient);

    var queryParams = {RoleName: 'query-role', PolicyName: 'query-policy'};
    var req = createMockRequest({}, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.roleName, 'query-role',
                'query RoleName should be used as fallback');
        t.equal(capturedParams.policyName, 'query-policy',
                'query PolicyName should be used as fallback');
        t.end();
    });
});


// ========== ListRoles Body Precedence Tests ==========

helper.test('ListRoles: body MaxItems/Marker take precedence', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.listRolesHandler(mockClient);

    var bodyParams = {MaxItems: '50', Marker: 'body-marker'};
    var queryParams = {MaxItems: '100', Marker: 'query-marker'};
    var req = createMockRequest(bodyParams, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.maxItems, 50,
                'body MaxItems should take precedence (parsed as int)');
        t.equal(capturedParams.marker, 'body-marker',
                'body Marker should take precedence');
        t.end();
    });
});

helper.test('ListRoles: query MaxItems/Marker used when body empty',
            function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.listRolesHandler(mockClient);

    var queryParams = {MaxItems: '100', Marker: 'query-marker'};
    var req = createMockRequest({}, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.maxItems, 100,
                'query MaxItems should be used as fallback');
        t.equal(capturedParams.marker, 'query-marker',
                'query Marker should be used as fallback');
        t.end();
    });
});


// ========== Edge Cases ==========

helper.test('CreateRole: returns error when RoleName missing', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.createRoleHandler(mockClient);

    var req = createMockRequest({}, {});
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedResponse.statusCode, 400,
                'should return 400 when RoleName is missing');
        t.ok(capturedResponse.body.indexOf('RoleName') > -1,
             'error should mention RoleName');
        t.end();
    });
});

helper.test('GetRole: body param is empty string falls back to query',
            function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.getRoleHandler(mockClient);

    var req = createMockRequest({RoleName: ''}, {RoleName: 'query-role'});
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        // Empty string is falsy, so query should be used
        t.equal(capturedParams.roleName, 'query-role',
                'query RoleName should be used when body is empty string');
        t.end();
    });
});

helper.test('PutRolePolicy: mixed body and query params', function (t) {
    var capturedParams = {};
    var capturedResponse = {};
    var mockClient = createMockIAMClient(capturedParams);
    var handler = iamHandlers.putRolePolicyHandler(mockClient);

    var queryPolicy = '{"Version":"2012-10-17","Statement":[]}';
    var bodyParams = {RoleName: 'body-role', PolicyName: 'body-policy'};
    var queryParams = {RoleName: 'query-role', PolicyDocument: queryPolicy};
    var req = createMockRequest(bodyParams, queryParams);
    var res = createMockResponse(capturedResponse);

    handler(req, res, function () {
        t.equal(capturedParams.roleName, 'body-role',
                'body RoleName should take precedence');
        t.equal(capturedParams.policyName, 'body-policy',
                'body PolicyName should take precedence');
        // PolicyDocument from query since not in body
        t.end();
    });
});
