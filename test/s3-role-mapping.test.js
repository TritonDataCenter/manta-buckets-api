/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 * Test S3 ACL to Manta Role Mapping
 */

var helper = require('./s3-test-helper.js');
var s3Compat = require('../lib/s3-compat');

helper.test('S3 ACL to Manta Role Translation', function (t) {
    // Mock request object
    var req = {
        isS3Request: true,
        headers: {
            'x-amz-acl': 'public-read'
        },
        log: {
            debug: function () {}
        }
    };

    // Mock response object
    var res = {};

    // Test the role translator
    s3Compat.s3RoleTranslator(req, res, function (err) {
        t.error(err, 'No error in role translation');
        t.equal(req.headers['role-tag'], 'public-reader',
                'public-read ACL should map to public-reader role');
        t.end();
    });
});

helper.test('S3 Grant Headers to Manta Role Translation', function (t) {
    // Mock request object
    var req = {
        isS3Request: true,
        headers: {
            'x-amz-grant-read':
            'uri="http://acs.amazonaws.com/groups/global/AllUsers"'
        },
        log: {
            debug: function () {}
        }
    };

    // Mock response object
    var res = {};

    // Test the role translator
    s3Compat.s3RoleTranslator(req, res, function (err) {
        t.error(err, 'No error in role translation');
        t.equal(req.headers['role-tag'], 'public-reader',
                'grant-read AllUsers should map to public-reader role');
        t.end();
    });
});

helper.test('Non-S3 Request Passes Through', function (t) {
    // Mock request object
    var req = {
        isS3Request: false,
        headers: {
            'x-amz-acl': 'public-read'
        },
        log: {
            debug: function () {}
        }
    };

    // Mock response object
    var res = {};

    // Test the role translator
    s3Compat.s3RoleTranslator(req, res, function (err) {
        t.error(err, 'No error in role translation');
        t.notOk(req.headers['role-tag'],
                'Non-S3 requests should not have role-tag added');
        t.end();
    });
});
