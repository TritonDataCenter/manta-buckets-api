/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/**
 * Lightweight test helper for S3 unit tests.
 * This helper provides only the basic testing functionality needed for S3 tests
 * without requiring Manta environment variables or external dependencies.
 */

var bunyan = require('bunyan');

// Create a simple logger for S3 tests
function createLogger(name) {
    return bunyan.createLogger({
        name: name || 's3-test',
        level: process.env.LOG_LEVEL || 'fatal', // Keep quiet during tests
        stream: process.stderr
    });
}

// Simple test function wrapper (compatible with nodeunit)
function test(name, testFn) {
    // Get the calling module's exports and add the test
    var caller = module.parent;
    if (caller && caller.exports) {
        // Wrap the test function to add missing assertion methods
        caller.exports[name] = function (t) {
            // Add missing nodeunit assertion methods
            t.notOk = t.notOk || function (value, message) {
                t.ok(!value, message);
            };

            t.end = t.end || function () {
                t.done();
            };

            // Call the original test function
            testFn(t);
        };
    }
}

// Export test utilities
module.exports = {
    test: test,
    createLogger: createLogger
};