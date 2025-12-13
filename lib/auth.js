/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
 */

//
// Generate keys for the muskie config with:
//
// $ openssl enc -aes-128-cbc -k $(uuid) -P
// salt=C93A670ACC05C166
// key=5163205CA0C7F2752FD3A574E30F64DD
// iv=6B11F0F0B786F96812D5A0799D5B217A
//

var assert = require('assert-plus');
var httpSignature = require('http-signature');
var path = require('path');
var querystring = require('querystring');
var sprintf = require('util').format;
var vasync = require('vasync');

var libmantalite = require('./libmantalite');
var common = require('./common');
var s3Compat = require('./s3-compat');
var constants = require('./constants');
var tokenManager = require('./auth/token-manager');
var iamMapper = require('./auth/iam-mapper');
var roleManager = require('./auth/role-manager');
var signatureVerifier = require('./auth/signature-verifier');
var credentialProvider = require('./auth/credential-provider');
var authorizationHandler = require('./auth/authorization-handler');
require('./errors');


///--- Exports

module.exports = {

    authenticationHandler: function handlers(options) {
        assert.object(options, 'options');
        assert.object(options.log, 'options.log');
        assert.object(options.mahi, 'options.mahi');
        assert.optionalObject(options.iamClient,
            'options.iamClient');

        return ([
            function _authSetup(req, res, next) {
                req.mahi = options.mahi;
                req.keyapi = options.keyapi;
                req.iamClient = options.iamClient;
                req.auth = {};
                req.authContext = {
                    conditions: {}
                };
                next();
            },
            signatureVerifier.preSignedUrl,
            signatureVerifier.checkAuthzScheme,
            tokenManager.parseHandler,
            signatureVerifier.signatureHandler,
            // Add SigV4 authentication handler
            signatureVerifier.sigv4Handler,
            credentialProvider.parseKeyId,
            credentialProvider.loadCaller,
            signatureVerifier.verifySignature,
            credentialProvider.parseHttpAuthToken,
            authorizationHandler.loadOwner,
            roleManager.getActiveRoles
        ]);
    },

    authorizationHandler: function authz() {
        return ([
            authorizationHandler.authorize
        ]);
    },

    loadOwnerFromPath: authorizationHandler.loadOwnerFromPath,

    gatherContext: authorizationHandler.gatherContext,
    createAuthToken: tokenManager.create,
    parseAuthToken: tokenManager.parse,
    convertS3PresignedToManta: signatureVerifier.convertS3PresignedToManta,
    checkIfPresigned: signatureVerifier.checkIfPresigned,

    postAuthTokenHandler: function () {
        return ([tokenManager.createHandler]);
    }
};
