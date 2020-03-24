/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

// var parseUri = require('parseUri');

'use strict';

///--- Helpers

//TODO: Pull this from npm
// parseUri 1.2.2
// (c) Steven Levithan <stevenlevithan.com>
// MIT License

function parseUri (str) {
    var o   = parseUri.options,
        m   = o.parser[o.strictMode ? "strict" : "loose"].exec(str),
        uri = {},
        i   = 14;

    while (i--) uri[o.key[i]] = m[i] || "";

    uri[o.q.name] = {};
    uri[o.key[12]].replace(o.q.parser, function ($0, $1, $2) {
        if ($1) uri[o.q.name][$1] = $2;
    });

    return uri;
};

parseUri.options = {
    strictMode: false,
    key: ["source","protocol","authority","userInfo","user","password","host","port","relative","path","directory","file","query","anchor"],
    q:   {
        name:   "queryKey",
        parser: /(?:^|&)([^&=]*)=?([^&]*)/g
    },
    parser: {
        strict: /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?))?((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/,
        loose:  /^(?:(?![^:@]+:[^:@\/]*@)([^:\/?#.]+):)?(?:\/\/)?((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?)(((\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/
    }
};


/**
 * Rewrite S3 url to manta buckets API URL
 *
 * @private
 * @function rewrite
 * @param    {Object} method - The HTTP verb
 * @param    {Object} headers - The request headers
 * @param    {Object} path - The URL request path
 * @returns  {String} rewritten path
 */
function rewrite(method, headers, path) {
    var rewrittenPath = '/';

    // Parse the URL into its component pieces
    // var parsedUri = parseUri.parseUri(path);
    var parsedUri = parseUri(path);

    console.log('ParsedURI: ' + JSON.stringify(parsedUri));

    // Extract the buckets name from the Host header value
    console.log("Headers present: " + Object.keys(headers));
    if (headers !== undefined && headers['host'] !== undefined) {
        var hostParts = headers['host'].split('.');
        var bucket = hostParts.slice(0,1);

        console.log('Bucket: ' + bucket);

        rewrittenPath = rewrittenPath + bucket;
    }

    console.log('Rewritten path: ' + rewrittenPath);

    return rewrittenPath;
}

/**
 * Translate S3 API URL to buckets API URL
 *
 * @public
 * @function urlRewrite
 * @returns  {Function} Handler
 */
function urlRewrite() {
    function _urlRewrite(req, res, next) {
        // TODO: Rewrite actual url key. For now we want requests to just pass
        // through to test the rewrite process.
        // req.url = rewrite(req.method, req.headers, req.url);
        req.newurl = rewrite(req.method, req.headers, req.url);
        next();
    }

    return _urlRewrite;
}

///--- Exports

module.exports = {
    urlRewrite: urlRewrite
};
