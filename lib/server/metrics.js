/*
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * metrics.js: Metrics collection and audit logging for Restify server.
 *
 * Provides functions for:
 * - Metrics collector initialization (artedi counters and histograms)
 * - Audit logging setup with request completion handling
 */

var audit = require('../audit');
var common = require('../common');


///--- Functions

/**
 * Initialize metric collectors for HTTP requests, latency, and data throughput.
 * Sets up artedi collectors for tracking request counts, time-to-first-byte,
 * and data transfer metrics.
 *
 * @param {Object} collector - Artedi metric collector instance
 */
function initializeMetrics(collector) {
    // A counter to track the number of HTTP requests serviced.
    collector.counter({
        name: common.METRIC_REQUEST_COUNTER,
        help: 'count of Muskie requests completed'
    });

    /*
     * A mostly log-linear histogram to track the time to first byte.
     * Track values between 2 and 60000 ms (2ms to 1 minute).
     */
    collector.histogram({
        name: common.METRIC_LATENCY_HISTOGRAM,
        help: 'time-to-first-byte of Muskie requests',
        // These were generated with artedi.logLinearBuckets(10, 1, 3, 10); and
        // then some manual tweaking. Slightly different from muskie, but if
        // you're interested in the reasoning also see MANTA-5268 and MANTA-4388
        // for details.
        buckets: [
            2,
            4,
            6,
            8,
            10,
            12,
            14,
            16,
            18,
            20,
            25,
            30,
            35,
            40,
            45,
            50,
            60,
            70,
            80,
            90,
            100,
            200,
            300,
            400,
            500,
            600,
            700,
            800,
            900,
            1000,
            2000,
            4000,
            6000,
            8000,
            10000,
            30000,
            60000
        ]
    });

    // A pair of counters to track inbound and outbound throughput.
    collector.counter({
        name: common.METRIC_INBOUND_DATA_COUNTER,
        help: 'count of object bytes streamed from client to storage'
    });
    collector.counter({
        name: common.METRIC_OUTBOUND_DATA_COUNTER,
        help: 'count of object bytes streamed from storage to client'
    });
    collector.counter({
        name: common.METRIC_DELETED_DATA_COUNTER,
        help: 'count of deleted object bytes'
    });
}


/**
 * Create audit logger and 'after' handler for request completion.
 * Handles audit logging and request stream cleanup on errors.
 *
 * @param {Object} options - Options object containing collector
 * @param {Object} log - Bunyan logger instance
 * @param {Object} server - Restify server instance
 */
function setupAuditLogging(options, log, server) {
    var _audit = audit.auditLogger({
        collector: options.collector,
        log: log
    });

    server.on('after', function (req, res, route, err) {
        _audit(req, res, route, err);

        if ((req.method === 'PUT' || req.method === 'POST') &&
            res.statusCode >= 400) {
            /*
             * An error occurred on a PUT or POST request, but there may still
             * be incoming data on the request stream. Call resume() in order to
             * dump any remaining request data so the stream emits an 'end' and
             * the socket resources are not leaked.
             */
            req.resume();
        }
    });
}


///--- Exports

module.exports = {
    initializeMetrics: initializeMetrics,
    setupAuditLogging: setupAuditLogging
};
