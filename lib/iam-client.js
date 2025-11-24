/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * IAM client for communicating with Mahi's IAM endpoints
 */

var assert = require('assert-plus');
var restifyClients = require('restify-clients');

function IAMClient(options) {
    assert.object(options, 'options');
    assert.string(options.url, 'options.url');
    assert.object(options.log, 'options.log');

    this.url = options.url;
    this.log = options.log;

    this.client = restifyClients.createJsonClient({
        url: options.url,
        connectTimeout: options.connectTimeout || 1000,
        requestTimeout: options.requestTimeout || 10000,
        retry: false
    });
}

IAMClient.prototype.createRole = function createRole(opts, callback) {
    assert.object(opts, 'opts');
    assert.string(opts.roleName, 'opts.roleName');
    assert.object(opts.caller, 'opts.caller');
    assert.func(callback, 'callback');

    var log = this.log;
    var path = '/iam/create-role';

    var requestData = {
        roleName: opts.roleName,
        assumeRolePolicyDocument: opts.assumeRolePolicyDocument,
        mantaPolicy: opts.mantaPolicy, // Include converted Manta policy
        description: opts.description,
        path: opts.path || '/',
        accountUuid: opts.caller.account.uuid
    };

    log.debug({
        path: path,
        roleName: opts.roleName,
        callerUuid: opts.caller.account.uuid
    }, 'IAMClient: Creating role via Mahi');

    this.client.post(path, requestData, function (err, req, res, data) {
        if (err) {
            log.error({
                err: err,
                roleName: opts.roleName,
                statusCode: res ? res.statusCode : 'unknown',
                errorCode: err.code,
                errorMessage: err.message
            }, 'IAMClient: CreateRole request to Mahi failed');
            return (callback(err));
        }

        log.info({
            roleName: opts.roleName,
            roleArn: data.Role ? data.Role.Arn : 'unknown',
            statusCode: res.statusCode
        }, 'IAMClient: CreateRole request completed successfully');

        callback(null, data);
    });
};

IAMClient.prototype.getRole = function getRole(opts, callback) {
    assert.object(opts, 'opts');
    assert.string(opts.roleName, 'opts.roleName');
    assert.object(opts.caller, 'opts.caller');
    assert.func(callback, 'callback');

    var log = this.log;
    var path = '/iam/get-role/' + encodeURIComponent(opts.roleName);

    var query = {
        accountUuid: opts.caller.account.uuid
    };

    log.debug({
        path: path,
        roleName: opts.roleName,
        query: query
    }, 'IAMClient: Getting role via Mahi');

    this.client.get({
        path: path,
        query: query
    }, function (err, req, res, data) {
        if (err) {
            log.error({
                err: err,
                roleName: opts.roleName,
                statusCode: res ? res.statusCode : 'unknown',
                errorCode: err.code,
                errorMessage: err.message
            }, 'IAMClient: GetRole request failed');
            return (callback(err));
        }

        log.debug({
            roleName: opts.roleName,
            roleArn: data.Role ? data.Role.Arn : 'unknown',
            statusCode: res.statusCode
        }, 'IAMClient: GetRole request completed successfully');

        callback(null, data);
    });
};

IAMClient.prototype.putRolePolicy = function putRolePolicy(opts, callback) {
    assert.object(opts, 'opts');
    assert.string(opts.roleName, 'opts.roleName');
    assert.string(opts.policyName, 'opts.policyName');
    assert.string(opts.policyDocument, 'opts.policyDocument');
    assert.object(opts.mantaPolicy, 'opts.mantaPolicy');
    assert.object(opts.caller, 'opts.caller');
    assert.func(callback, 'callback');

    var log = this.log;
    var path = '/iam/put-role-policy';

    var requestData = {
        roleName: opts.roleName,
        policyName: opts.policyName,
        policyDocument: opts.policyDocument,
        mantaPolicy: opts.mantaPolicy,
        accountUuid: opts.caller.account.uuid
    };

    log.debug({
        path: path,
        roleName: opts.roleName,
        policyName: opts.policyName,
        mantaPolicyName: opts.mantaPolicy.name
    }, 'IAMClient: Putting role policy via Mahi');

    this.client.post(path, requestData, function (err, req, res, data) {
        if (err) {
            log.error({
                err: err,
                roleName: opts.roleName,
                policyName: opts.policyName,
                statusCode: res ? res.statusCode : 'unknown',
                errorCode: err.code,
                errorMessage: err.message
            }, 'IAMClient: PutRolePolicy request failed');
            return (callback(err));
        }

        log.info({
            roleName: opts.roleName,
            policyName: opts.policyName,
            statusCode: res.statusCode
        }, 'IAMClient: PutRolePolicy request completed successfully');

        callback(null, data);
    });
};

IAMClient.prototype.deleteRolePolicy =
    function deleteRolePolicy(opts, callback) {
    assert.object(opts, 'opts');
    assert.string(opts.roleName, 'opts.roleName');
    assert.string(opts.policyName, 'opts.policyName');
    assert.object(opts.caller, 'opts.caller');
    assert.func(callback, 'callback');

    var log = this.log;
    var path = '/iam/delete-role-policy';

    var requestData = {
        roleName: opts.roleName,
        policyName: opts.policyName,
        accountUuid: opts.caller.account.uuid
    };

    log.debug({
        path: path,
        roleName: opts.roleName,
        policyName: opts.policyName,
        callerUuid: opts.caller.account.uuid
    }, 'IAMClient: Deleting role policy via Mahi');

    this.client.del({
        path: path,
        query: requestData
    }, function (err, req, res, data) {
        if (err) {
            // Use debug level for 4xx errors (expected test scenarios)
            var logLevel = (res && res.statusCode >= 400 &&
                            res.statusCode < 500) ? 'debug' : 'error';
            log[logLevel]({
                err: err,
                roleName: opts.roleName,
                policyName: opts.policyName,
                statusCode: res ? res.statusCode : 'unknown',
                errorCode: err.code,
                errorMessage: err.message
            }, 'IAMClient: DeleteRolePolicy request failed');
            return (callback(err));
        }

        log.info({
            roleName: opts.roleName,
            policyName: opts.policyName,
            statusCode: res.statusCode
        }, 'IAMClient: DeleteRolePolicy request completed successfully');

        callback(null, data);
    });
};

IAMClient.prototype.deleteRole = function deleteRole(opts, callback) {
    assert.object(opts, 'opts');
    assert.string(opts.roleName, 'opts.roleName');
    assert.object(opts.caller, 'opts.caller');
    assert.func(callback, 'callback');

    var log = this.log;
    var path = '/iam/delete-role/' + encodeURIComponent(opts.roleName);

    var requestData = {
        roleName: opts.roleName,
        accountUuid: opts.caller.account.uuid
    };

    log.debug({
        path: path,
        roleName: opts.roleName,
        callerUuid: opts.caller.account.uuid
    }, 'IAMClient: Deleting role via Mahi');

    this.client.del({
        path: path,
        query: requestData
    }, function (err, req, res, data) {
        if (err) {
            // Use debug level for 4xx errors (expected test scenarios)
            var logLevel = (res && res.statusCode >= 400 &&
                            res.statusCode < 500) ? 'debug' : 'error';
            log[logLevel]({
                err: err,
                roleName: opts.roleName,
                statusCode: res ? res.statusCode : 'unknown',
                errorCode: err.code,
                errorMessage: err.message
            }, 'IAMClient: DeleteRole request failed');
            return (callback(err));
        }

        log.info({
            roleName: opts.roleName,
            statusCode: res.statusCode
        }, 'IAMClient: DeleteRole request completed successfully');

        callback(null, data);
    });
};

IAMClient.prototype.listRoles = function listRoles(opts, callback) {
    assert.object(opts, 'opts');
    assert.object(opts.caller, 'opts.caller');
    assert.func(callback, 'callback');

    var log = this.log;
    var path = '/iam/list-roles';

    var requestData = {
        accountUuid: opts.caller.account.uuid,
        maxItems: opts.maxItems || 100,
        marker: opts.marker || null
    };

    log.debug({
        path: path,
        callerUuid: opts.caller.account.uuid,
        maxItems: requestData.maxItems
    }, 'IAMClient: Listing roles via Mahi');

    this.client.get({
        path: path,
        query: requestData
    }, function (err, req, res, data) {
        if (err) {
            log.error({
                err: err,
                callerUuid: opts.caller.account.uuid,
                statusCode: res ? res.statusCode : 'unknown',
                errorCode: err.code,
                errorMessage: err.message
            }, 'IAMClient: ListRoles request failed');
            return (callback(err));
        }

        log.info({
            callerUuid: opts.caller.account.uuid,
            statusCode: res.statusCode,
            roleCount: data && data.roles ? data.roles.length : 0
        }, 'IAMClient: ListRoles request completed successfully');

        callback(null, data);
    });
};

/**
 * ListRolePolicies IAM operation - list inline policies attached to a role
 */
IAMClient.prototype.listRolePolicies =
    function listRolePolicies(opts, callback) {
    assert.object(opts, 'opts');
    assert.string(opts.roleName, 'opts.roleName');
    assert.object(opts.caller, 'opts.caller');
    assert.func(callback, 'callback');

    var self = this;
    var log = self.log.child({
        operation: 'ListRolePolicies',
        roleName: opts.roleName,
        callerUuid: opts.caller.account.uuid
    });

    var reqOpts = {
        path: '/iam/list-role-policies/' + encodeURIComponent(opts.roleName),
        query: {
            accountUuid: opts.caller.account.uuid
        }
    };

    // Add optional parameters
    if (opts.marker) {
        reqOpts.query.marker = opts.marker;
    }
    if (opts.maxItems) {
        reqOpts.query.maxitems = opts.maxItems;
    }

    log.debug({
        path: reqOpts.path,
        query: reqOpts.query,
        marker: opts.marker,
        maxItems: opts.maxItems
    }, 'IAMClient: Making ListRolePolicies request to mahi');

    self.client.get(reqOpts, function (err, req, res, data) {
        if (err) {
            log.error({
                err: err,
                statusCode: res ? res.statusCode : null,
                errorCode: err.code,
                errorMessage: err.message
            }, 'IAMClient: ListRolePolicies request failed');
            return (callback(err));
        }

        log.info({
            callerUuid: opts.caller.account.uuid,
            statusCode: res.statusCode,
            policyCount: data && data.PolicyNames ? data.PolicyNames.length : 0
        }, 'IAMClient: ListRolePolicies request completed successfully');

        callback(null, data);
    });
};

/**
 * GetRolePolicy IAM operation - retrieve a specific inline policy document
 */
IAMClient.prototype.getRolePolicy = function getRolePolicy(opts, callback) {
    assert.object(opts, 'opts');
    assert.string(opts.roleName, 'opts.roleName');
    assert.string(opts.policyName, 'opts.policyName');
    assert.object(opts.caller, 'opts.caller');
    assert.func(callback, 'callback');

    var self = this;
    var log = self.log.child({
        operation: 'GetRolePolicy',
        roleName: opts.roleName,
        policyName: opts.policyName,
        callerUuid: opts.caller.account.uuid
    });

    var reqOpts = {
        path: '/iam/get-role-policy/' + encodeURIComponent(opts.roleName) +
            '/' + encodeURIComponent(opts.policyName),
        query: {
            accountUuid: opts.caller.account.uuid
        }
    };

    log.debug({
        path: reqOpts.path,
        roleName: opts.roleName,
        policyName: opts.policyName
    }, 'IAMClient: Making GetRolePolicy request to mahi');

    self.client.get(reqOpts, function (err, req, res, data) {
        if (err) {
            log.error({
                err: err,
                statusCode: res ? res.statusCode : null,
                errorCode: err.code,
                errorMessage: err.message
            }, 'IAMClient: GetRolePolicy request failed');
            return (callback(err));
        }

        log.info({
            callerUuid: opts.caller.account.uuid,
            statusCode: res.statusCode,
            roleName: data ? data.RoleName : null,
            policyName: data ? data.PolicyName : null,
            hasPolicyDocument: !!(data && data.PolicyDocument)
        }, 'IAMClient: GetRolePolicy request completed successfully');

        callback(null, data);
    });
};

module.exports = IAMClient;
