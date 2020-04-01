/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

// var parseUri = require('parseUri');

//'use strict';

///--- Helpers

const SUBRESOURCES = ['acl', 'location', 'logging', 'notification', 'partNumber',
                      'policy', 'requestPayment', 'torrent', 'uploadId', 'uploads',
                      'versionId', 'versioning', 'versions', 'website',
                      'delete', 'lifecycle'];

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
}

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
 * @param    {String} method - The HTTP verb
 * @param    {Object} headers - The request headers
 * @param    {String} path - The URL request path
 * @param    {String} root_host - The root host name (e.g. manta.joyent.us)
 * @returns  {String} rewritten path
 */
function rewrite(method, headers, path, root_host) {
    // TODO: We have to determine a way to map the notion of S3 account onto our
    // accounts. I hacked this to work by disabling the auth checks in
    // buckets-api and hardcoding my account into the path.
    var rewritten_path = '/kelly';

    // Parse the URL into its component pieces
    // var parsedUri = parseUri.parseUri(path);

    /* Parsed URI has the following structure:

     > parseUri('/buckets/bucket/objects/object?name=test');
    { anchor: '',
      query: 'name=test',
      file: '',
      directory: '/buckets/bucket/objects/object',
      path: '/buckets/bucket/objects/object',
      relative: '/buckets/bucket/objects/object?name=test',
      port: '',
      host: '',
      password: '',
      user: '',
      userInfo: '',
      authority: '',
      protocol: '',
      source: '/buckets/bucket/objects/object?name=test',
      queryKey: { name: 'test' } }
    */

    var parsedUri = parseUri(path);
    var query_params = parsedUri.queryKey;

    console.log('ParsedURI: ' + JSON.stringify(parsedUri));

    // Extract the buckets name from the Host header value
    console.log('Headers present: ' + Object.keys(headers));
    if (headers !== undefined && headers['host'] !== undefined) {
        var host = headers['host'];

        // S3 API requests prepend the bucket name to the host name as the Host
        // header value. Therefore the bucket name is found by removing the host
        // suffix along with the preceding '.'
        var bucket;

        if (host.indexOf(root_host) > 0) {
            bucket = host.substring(0, host.indexOf(root_host)-1);
        }

        console.log('Bucket: ' + bucket);
        if (bucket === undefined) {
            if (path === '/') {
                rewritten_path += '/buckets';
            } else {
                // The bucket name is part of the path
                console.log('Bucket name is part of the path');
                rewritten_path += handle_bucket_in_path(method, parsedUri.path, query_params);
            }
        } else {
            if (method == 'GET' && parsedUri.path === '/') {
                rewritten_path += '/buckets/' + bucket;
            } else {
                var subresource_result = get_subresources(query_params);
                if (path == '/') {
                    var bucket_resource_and_query_path = format_bucket_subresources_and_query(method, subresource_result.subresources, subresource_result.query_params);
                    rewritten_path += '/buckets/' + bucket + bucket_resource_and_query_path;
                } else {
                    var object_resource_and_query_path = format_object_subresources_and_query(method, subresource_result.subresources, subresource_result.query_params);
                    rewritten_path += '/buckets/' + bucket + '/objects' + path + object_resource_and_query_path;
                }
            }
        }
    }

    console.log('Rewritten path: ' + rewritten_path);

    return (rewritten_path);
}

function format_bucket_subresources_and_query(method, subresources, query_params) {
    console.log('Formatting bucket subresources');
    if (method === 'POST' && ('delete' in subresources)) {
        return ('delete');
    } else if (method === 'GET' || method === 'POST') {
        return ('objects');
    } else {
        return ('');
    }
}

function format_object_subresources_and_query(method, subresources, query_params) {
    return ('');
}

/**
 * Extract the S3 subresources from the request query string
 *
 * @private
 * @function get_subresources
 * @param    {Object} query_params - An object with key-value pairs of the request query parameters.
 * @returns  {Object} An object with a subresources key and a query_params key.
 */
function get_subresources(query_params) {
    var result = {
        subresources: {},
        query_params: {}
    };

    for (var key in Object.keys(query_params)) {
        if (SUBRESOURCES.includes(key)) {
            result.subresources[key] = query_params[key];
        } else {
            result.query_params[key] = query_params[key];
        }
    }

    return (result);
}

/**
 * Deal with the case where the S3 request has the bucket name as part of the path
 *
 * @private
 * @function handle_bucket_in_path
 * @param    {String} method - The HTTP verb
 * @param    {String} path - The URL request path
 * @param    {Object} query_params - The request query parameters
 * @returns  {String} rewritten path fragment
 */
function handle_bucket_in_path(method, fullPath, query_params) {
    console.log('handle_bucket_in_path');
    var firstSlashIndex = fullPath.indexOf('/', 1);


    var rewritten_path = '/';
    var bucket;
    var path;
    if (firstSlashIndex === -1) {
        bucket = fullPath.substring(1);
        path = '/';
    } else {
        bucket = fullPath.substring(1, firstSlashIndex);
        path = fullPath.substring(firstSlashIndex, fullPath.length);
    }

    console.log('Bucket: ' + bucket);
    console.log('Path: ' + path);

    if (method !== 'GET' && path === '/') {
        rewritten_path += 'buckets/' + bucket;
    } else {
        var subresource_result = get_subresources(query_params);
        if (path == '/') {
            var bucket_resource_and_query_path = format_bucket_subresources_and_query(method, subresource_result.subresources, subresource_result.query_params);
            rewritten_path += 'buckets/' + bucket + '/' + bucket_resource_and_query_path;
        } else {
            var object_resource_and_query_path = format_object_subresources_and_query(method, subresource_result.subresources, subresource_result.query_params);
            rewritten_path += 'buckets/' + bucket + '/objects' + path + object_resource_and_query_path;
        }
    }

    return (rewritten_path);
}

/**
 * Translate S3 API URL to buckets API URL
 *
 * @public
 * @function urlRewrite
 * @param    {String} root host name for S3-style requests
 * @returns  {Function} Handler
 */
function urlRewrite(root_host) {
    function _urlRewrite(req, res, next) {
        console.log('Initial url: ' + req.url);
        // Ignore ping requests
        if (req.url === '/ping') {
            return (next());
        }
        req.url = rewrite(req.method, req.headers, req.url, root_host);
        next();
    }

    return _urlRewrite;
}

///--- Exports

module.exports = {
    urlRewrite: urlRewrite
};
