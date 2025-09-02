/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var test = require('tape');
var uuid = require('uuid');

var helper = require('./helper');

if (helper.config.enableMPU !== true) {
    console.error('MPU tests require enableMPU: true in config');
    process.exit(1);
}

var server;

test('setup', function (t) {
    helper.createServer(null, function (s) {
        server = s;
        t.end();
    });
});

test('v2 commit configuration check', function (t) {
    t.ok(server.config, 'server has config');
    t.ok(server.config.multipartUpload, 'multipartUpload config exists');
    
    // Test can work with or without v2 commit enabled
    if (server.config.multipartUpload.useNativeV2Commit) {
        t.pass('Native v2 commit is enabled');
    } else {
        t.pass('Native v2 commit is disabled, will use streaming');
    }
    
    t.end();
});

test('v2 commit module loading', function (t) {
    var v2Module;
    
    try {
        v2Module = require('../lib/s3-multipart-v2');
        t.ok(v2Module, 'v2 multipart module loaded');
        t.ok(typeof v2Module.tryMakoV2Commit === 'function', 
             'tryMakoV2Commit function exists');
    } catch (err) {
        t.fail('Failed to load v2 multipart module: ' + err.message);
    }
    
    t.end();
});

test('integration with existing MPU', function (t) {
    var bucketName = 'test-bucket-' + uuid.v4();
    var objectName = 'test-object-' + uuid.v4();
    
    // This test verifies the integration doesn't break existing functionality
    helper.createBucket(server, bucketName, function (err) {
        t.error(err, 'bucket creation should succeed');
        
        helper.initiateMPU(server, bucketName, objectName, function (err, uploadId) {
            t.error(err, 'MPU initiation should succeed');
            t.ok(uploadId, 'upload ID should be returned');
            
            // Clean up
            helper.abortMPU(server, bucketName, objectName, uploadId, function (abortErr) {
                t.error(abortErr, 'abort MPU should succeed');
                
                helper.deleteBucket(server, bucketName, function (deleteErr) {
                    t.error(deleteErr, 'bucket deletion should succeed');
                    t.end();
                });
            });
        });
    });
});

test('cleanup', function (t) {
    server.close(function () {
        t.end();
    });
});