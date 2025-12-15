/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/**
 * End-to-End tests for S3 object operations using hybrid mock approach
 * Tests complete workflows: upload → storage → retrieval
 */

var helper = require('./s3-test-helper.js');
var mocks = require('./mock-infrastructure.js');
var stream = require('stream');

// Test: E2E object upload with streaming and MD5 computation
helper.test('E2E: Upload object to shark cluster with streaming', function (t) {
    // Setup E2E infrastructure
    var storinfo = mocks.createMockStorinfoClient();
    var sharkCluster = storinfo.getSharkCluster();
    var metadataClient = mocks.createMockMetadataClientE2E();

    // Create test data
    var testData = 'Hello, Manta! This is test object data.';
    var dataStream = new stream.PassThrough();
    dataStream.end(testData);

    var objectId = 'test-object-123';
    var owner = 'test-owner-uuid';
    var bucketId = 'test-bucket';
    var objectName = 'test-file.txt';

    // Select sharks
    storinfo.choose({replicas: 2}, function (err, sharks) {
        t.ok(!err, 'should select sharks without error');
        t.equal(sharks.length, 2, 'should select 2 sharks');

        var sharkIds = sharks.map(function (s) {
            return (s.manta_storage_id);
        });

        // Stream to sharks
        sharkCluster.streamToSharks(objectId, dataStream, sharkIds,
            function (err, result) {
                t.ok(!err, 'should stream to sharks without error');
                t.ok(result.md5, 'should compute MD5');
                t.equal(result.size, testData.length,
                    'should track correct size');
                t.equal(result.replicas, 2, 'should store 2 replicas');

                // Store metadata
                metadataClient.createObject(
                    owner,
                    bucketId,
                    objectName,
                    objectId,
                    result.size,
                    result.md5,
                    'text/plain',
                    {},
                    sharkIds,
                    {},
                    null,
                    {},
                    'test-request',
                    function (err, metadata) {
                        t.ok(!err, 'should create metadata without error');
                        t.equal(metadata.id, objectId, 'should set object ID');
                        t.equal(metadata.content_length, testData.length,
                            'should store size');
                        t.equal(metadata.type, 'bucketobject',
                            'should set type');
                        t.end();
                    });
            });
    });
});

// Test: E2E object retrieval with streaming
helper.test('E2E: Retrieve object from shark cluster', function (t) {
    // Setup infrastructure
    var storinfo = mocks.createMockStorinfoClient();
    var sharkCluster = storinfo.getSharkCluster();
    var metadataClient = mocks.createMockMetadataClientE2E();

    var testData = 'Retrieved object data';
    var objectId = 'retrieve-test-123';
    var owner = 'test-owner';
    var bucketId = 'test-bucket';
    var objectName = 'retrieve-test.txt';

    // First upload object
    var uploadStream = new stream.PassThrough();
    uploadStream.end(testData);

    storinfo.choose({replicas: 2}, function (err, sharks) {
        var sharkIds = sharks.map(function (s) {
            return (s.manta_storage_id);
        });

        sharkCluster.streamToSharks(objectId, uploadStream, sharkIds,
            function (err, uploadResult) {
                t.ok(!err, 'should upload without error');

                // Store metadata
                metadataClient.createObject(
                    owner, bucketId, objectName, objectId,
                    uploadResult.size, uploadResult.md5, 'text/plain',
                    {}, sharkIds, {}, null, {}, 'test',
                    function (err, metadata) {
                        t.ok(!err, 'should store metadata');

                        // Now retrieve
                        metadataClient.getObject(owner, bucketId,
                            objectName, null, {}, 'test',
                            function (err, obj) {
                                t.ok(!err, 'should get metadata');
                                t.equal(obj.id, objectId,
                                    'should return correct object ID');

                                // Stream from sharks
                                sharkCluster.streamFromSharks(objectId,
                                    obj.sharks,
                                    function (err, dataStream, meta) {
                                        t.ok(!err,
                                            'should retrieve stream');
                                        t.equal(meta.size, testData.length,
                                            'should have correct size');

                                        // Read stream
                                        var chunks = [];
                                        dataStream.on('data', function (chunk) {
                                            chunks.push(chunk);
                                        });

                                        dataStream.on('end', function () {
                                            var buf = Buffer.concat(chunks);
                                            var retrieved = buf.toString();
                                            t.equal(retrieved, testData,
                                                'should retrieve correct data');
                                            t.end();
                                        });
                                    });
                            });
                    });
            });
    });
});

// Test: E2E multipart upload workflow
helper.test('E2E: Complete multipart upload workflow', function (t) {
    // Setup infrastructure
    var storinfo = mocks.createMockStorinfoClient();
    var sharkCluster = storinfo.getSharkCluster();
    var metadataClient = mocks.createMockMetadataClientE2E();
    var mpuManager = mocks.createMockMultipartManager(metadataClient,
        sharkCluster);

    var bucketId = 'test-bucket';
    var objectKey = 'large-file.bin';
    var owner = 'test-owner';

    // Select sharks for this upload
    storinfo.choose({replicas: 2}, function (err, sharks) {
        t.ok(!err, 'should select sharks');

        // Initiate upload
        mpuManager.initiateUpload(bucketId, objectKey, {
            owner: owner,
            sharks: sharks,
            durabilityLevel: 2
        }, function (err, uploadId, uploadRecord) {
            t.ok(!err, 'should initiate upload');
            t.ok(uploadId, 'should return upload ID');
            t.equal(uploadRecord.durabilityLevel, 2,
                'should set durability level');

            // Upload part 1
            var part1Data = 'Part 1 data content';
            var part1Stream = new stream.PassThrough();
            part1Stream.end(part1Data);

            mpuManager.uploadPart(uploadId, 1, part1Stream,
                function (err, part1Result) {
                    t.ok(!err, 'should upload part 1');
                    t.ok(part1Result.etag, 'should return part 1 ETag');

                    // Upload part 2
                    var part2Data = 'Part 2 data content';
                    var part2Stream = new stream.PassThrough();
                    part2Stream.end(part2Data);

                    mpuManager.uploadPart(uploadId, 2, part2Stream,
                        function (err, part2Result) {
                            t.ok(!err, 'should upload part 2');
                            t.ok(part2Result.etag,
                                'should return part 2 ETag');

                            // Complete upload
                            var partsXML = [
                                {partNumber: 1, etag: part1Result.etag},
                                {partNumber: 2, etag: part2Result.etag}
                            ];

                            mpuManager.completeUpload(uploadId, partsXML,
                                function (err, completeResult) {
                                    t.ok(!err, 'should complete upload');
                                    t.ok(completeResult.etag,
                                        'should return final ETag');
                                    var expectedSize = part1Data.length +
                                        part2Data.length;
                                    t.equal(completeResult.size, expectedSize,
                                        'should calculate total size');

                                    // Verify upload record cleaned up
                                    var uploadAfter = mpuManager.getUpload(
                                        uploadId);
                                    t.ok(!uploadAfter,
                                        'should cleanup upload record');

                                    t.end();
                                });
                        });
                });
        });
    });
});

// Test: E2E conditional headers (If-None-Match)
helper.test('E2E: Conditional object creation with If-None-Match',
    function (t) {
    var metadataClient = mocks.createMockMetadataClientE2E();

    var owner = 'test-owner';
    var bucketId = 'test-bucket';
    var objectName = 'conditional-test.txt';
    var objectId1 = 'object-1';

    // Create object first time
    metadataClient.createObject(
        owner, bucketId, objectName, objectId1, 100, 'md5-1',
        'text/plain', {}, ['shark-1'], {}, null,
        {'if-none-match': '*'}, 'test',
        function (err, obj1) {
            t.ok(!err, 'should create object first time');
            t.equal(obj1.id, objectId1, 'should return object');

            // Try to create same object again with If-None-Match: *
            metadataClient.createObject(
                owner, bucketId, objectName, 'object-2', 100, 'md5-2',
                'text/plain', {}, ['shark-1'], {}, null,
                {'if-none-match': '*'}, 'test',
                function (err, obj2) {
                    t.ok(err, 'should fail on duplicate');
                    t.equal(err.name, 'ObjectExistsError',
                        'should return ObjectExistsError');
                    t.equal(err.statusCode, 412,
                        'should return 412 status');
                    t.end();
                });
        });
});

// Test: E2E shark failover during retrieval
helper.test('E2E: Shark failover when first shark fails', function (t) {
    var storinfo = mocks.createMockStorinfoClient();
    var sharkCluster = storinfo.getSharkCluster();

    var testData = 'Failover test data';
    var objectId = 'failover-test-123';

    // Upload to multiple sharks
    var uploadStream = new stream.PassThrough();
    uploadStream.end(testData);

    var sharkIds = ['mock-shark-1', 'mock-shark-2'];

    sharkCluster.streamToSharks(objectId, uploadStream, sharkIds,
        function (err, result) {
            t.ok(!err, 'should upload to both sharks');

            // Delete from first shark to simulate failure
            var shark1 = sharkCluster.getShark('mock-shark-1');
            shark1.deleteObject(objectId, function (err) {
                t.ok(!err, 'should delete from shark 1');

                // Try to retrieve - should failover to shark 2
                sharkCluster.streamFromSharks(objectId, sharkIds,
                    function (err, dataStream, metadata) {
                        t.ok(!err, 'should retrieve from shark 2');
                        t.equal(metadata.shark, 'mock-shark-2',
                            'should use second shark');

                        var chunks = [];
                        dataStream.on('data', function (chunk) {
                            chunks.push(chunk);
                        });

                        dataStream.on('end', function () {
                            var retrieved = Buffer.concat(chunks).toString();
                            t.equal(retrieved, testData,
                                'should retrieve correct data');
                            t.end();
                        });
                    });
            });
        });
});

// Test: E2E abort multipart upload
helper.test('E2E: Abort multipart upload cleans up parts', function (t) {
    var storinfo = mocks.createMockStorinfoClient();
    var sharkCluster = storinfo.getSharkCluster();
    var metadataClient = mocks.createMockMetadataClientE2E();
    var mpuManager = mocks.createMockMultipartManager(metadataClient,
        sharkCluster);

    var bucketId = 'test-bucket';
    var objectKey = 'aborted-file.bin';
    var owner = 'test-owner';

    storinfo.choose({replicas: 2}, function (err, sharks) {
        mpuManager.initiateUpload(bucketId, objectKey, {
            owner: owner,
            sharks: sharks
        }, function (err, uploadId) {
            t.ok(!err, 'should initiate upload');

            // Upload some parts
            var part1Stream = new stream.PassThrough();
            part1Stream.end('Part 1');

            mpuManager.uploadPart(uploadId, 1, part1Stream, function (err) {
                t.ok(!err, 'should upload part');

                // Verify part exists
                var parts = mpuManager.listParts(uploadId);
                t.equal(parts.length, 1, 'should have 1 part');

                // Abort upload
                mpuManager.abortUpload(uploadId, function (err) {
                    t.ok(!err, 'should abort upload');

                    // Verify cleanup
                    var upload = mpuManager.getUpload(uploadId);
                    t.ok(!upload, 'should cleanup upload record');

                    var partsAfter = mpuManager.listParts(uploadId);
                    t.equal(partsAfter.length, 0, 'should cleanup parts');

                    t.end();
                });
            });
        });
    });
});
