/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

var crypto = require('crypto');
var uuidv4 = require('uuid/v4');
var jsc = require('jsverify');

var shark_client = require('../lib/shark_client.js');

///--- Tests

/**
 * storagePathTest is a property test for the storagePath helper function in the
 * shark_client module. jsverify generates 100 random strings, and checks that
 * the property defined always holds. The property this tests is that the
 * storagePath function properly forms a object storage path by breaking long
 * object names into a series of subdirectories.
 */
exports.storagePathTest = function (t) {
    function propStoragePath(objectNameLen) {
        var objectName = 'a'.repeat(objectNameLen);
        var objectNameHash =
            crypto.createHash('md5').update(objectName).digest('hex');

        var storagePathOpts = {
            owner: uuidv4(),
            bucketId: uuidv4(),
            objectName: objectName,
            objectNameHash: objectNameHash,
            objectId: uuidv4(),
            storageLayoutVersion: shark_client.STORAGE_LAYOUT_V2
        };

        var storagePath = shark_client.storagePath(storagePathOpts);

        var actualPathParts = storagePath.substr(1).split('/');
        var actualPathPartCount = actualPathParts.length;
        var expectedObjectIdPrefix =
            storagePathOpts.objectId.substr(0,
                shark_client.STORAGE_LAYOUT_PREFIX_LEN);

        return (actualPathPartCount === 5 &&
                actualPathParts[0] === 'v2' &&
                actualPathParts[1] === storagePathOpts.owner &&
                actualPathParts[2] === storagePathOpts.bucketId &&
                actualPathParts[3] === expectedObjectIdPrefix &&
                actualPathParts[4] === storagePathOpts.objectId + ',' +
                    storagePathOpts.objectNameHash);
    }

    var propRes =
        jsc.checkForall(jsc.integer(1, 1024), propStoragePath);

    // use equals, as propRes is a report object on property failure,
    // but it's contents are logged by jsverify
    t.ok(propRes === true, 'Property:: storagePath parts match');
    t.done();
};
