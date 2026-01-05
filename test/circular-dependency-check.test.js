/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Test to catch circular dependency bugs between s3-mako-v2-commit
 * and s3-multipart modules.
 *
 * This test validates that require() statements are properly structured
 * to avoid circular dependency issues where module exports are incomplete.
 *
 * Background: In January 2026, hoisting require('./s3-multipart') to the
 * top of s3-mako-v2-commit.js created a circular dependency that caused
 * production failures when s3Multipart.createFinalObjectMetadata() was
 * called - it was undefined due to incomplete module.exports.
 *
 * This test ensures that both modules load correctly and have complete
 * exports, preventing similar issues in the future.
 */

var fs = require('fs');
var path = require('path');

///--- Tests

module.exports = {
    's3-mako-v2-commit module loads without circular dependency': function (t) {
        var v2Module;

        try {
            v2Module = require('../lib/s3-mako-v2-commit');
            t.ok(v2Module, 's3-mako-v2-commit module loaded');
            t.ok(typeof (v2Module.tryMakoV2Commit) === 'function',
                 'tryMakoV2Commit function exists');
        } catch (err) {
            t.fail('Failed to load s3-mako-v2-commit module: ' + err.message);
        }

        t.done();
    },

    's3-multipart exports are complete (circular dependency check)':
        function (t) {
        var s3Multipart;

        try {
            // First load s3-mako-v2-commit to trigger potential
            // circular dependency
            require('../lib/s3-mako-v2-commit');

            // Now load s3-multipart and verify its exports are complete
            s3Multipart = require('../lib/s3-multipart');

            // Critical exports that must exist
            var requiredExports = [
                'createFinalObjectMetadata',
                'handleCompleteMultipartUpload',
                'createMultipartUpload',
                'uploadPart',
                'listParts',
                'abortMultipartUpload'
            ];

            requiredExports.forEach(function (exportName) {
                t.ok(typeof (s3Multipart[exportName]) === 'function',
                     exportName + ' is a function');
            });

            // This is the specific function that failed in production
            t.ok(typeof (s3Multipart.createFinalObjectMetadata) === 'function',
                 'createFinalObjectMetadata must be a function (was ' +
                 'undefined in circular dependency bug)');

        } catch (err) {
            // Skip if this is a pre-existing infrastructure issue (bignum, etc)
            if (err.code === 'MODULE_NOT_FOUND' &&
                err.message.indexOf('bignum') !== -1) {
                // Skip this test - bignum dependency not available
                t.done();
                return;
            } else {
                t.fail('Error loading modules: ' + err.message);
            }
        }

        t.done();
    },


    'verify lazy-loading pattern in proceedWithV2Commit': function (t) {
        /*
         * This test documents the expected pattern: s3-multipart should be
         * required INSIDE proceedWithV2Commit function, not at module
         * top-level.
         *
         * We verify this by checking that the require is not at the top of
         * the file, which would create a circular dependency.
         */
        var filePath = path.join(__dirname, '../lib/s3-mako-v2-commit.js');
        var content = fs.readFileSync(filePath, 'utf8');
        var lines = content.split('\n');

        // Check first 50 lines for top-level requires
        var topLevelRequiresMultipart = false;
        var patternStr = '^(?:var|const|let)\\s+\\w+\\s*=\\s*' +
            'require\\([\'\"]\\.\\/s3-multipart[\'\"]\\)';
        var requirePattern = new RegExp(patternStr);

        for (var i = 0; i < Math.min(50, lines.length); i++) {
            var match = lines[i].match(requirePattern);
            if (match) {
                topLevelRequiresMultipart = true;
                t.fail('Found top-level require of s3-multipart at line ' +
                       (i + 1) + ': ' + lines[i].trim());
                break;
            }
        }

        if (!topLevelRequiresMultipart) {
            t.ok(true, 's3-multipart is not required at module top-level ' +
                 '(good!)');
        }

        // Verify that s3-multipart IS required somewhere (lazy-loaded)
        var hasLazyRequire =
            content.indexOf('require(\'./s3-multipart\')') !== -1;
        t.ok(hasLazyRequire,
             's3-multipart is required somewhere in the file (lazy-loaded)');

        t.done();
    }
};
