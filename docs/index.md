---
title: Joyent Manta Service REST API
markdown2extras: wiki-tables, code-friendly
apisections: Directories, Objects, Jobs, SnapLinks, Multipart Uploads
---
<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright 2019 Joyent, Inc.
-->

# REST API

This is the API reference documentation for the Joyent Manta Storage
Service, which enables you to store data in the cloud and process that data
using the built-in compute facility.

This document covers only the HTTP interface and all examples are given in curl.

Before you do the examples in this section, it's important to go through the
examples using the CLI and setting up your environment.

* [Getting Started](index.html)

There are also detailed reference materials:

* [Object Storage Reference](storage-reference.html)
* [Compute Jobs Reference](jobs-reference.html)
* [Multipart Uploads Reference](mpu-reference.html)

## Conventions

Any content formatted like this:

    $ curl -is https://us-east.manta.joyent.com

is a command-line example that you can run from a shell. All other examples and
information are formatted like this:

    GET /my/stor/foo HTTP/1.1


# Authentication

There are a few access methodologies. The predominant means of
authenticating requests to the service is to use the
[HTTP Signature](http://tools.ietf.org/html/draft-cavage-http-signatures-00)
over TLS.

In most situations, you will only need to sign the lowercase `date: ` and value
of the HTTP `Date` header using your SSH private key; doing this allows you to
create interactive shell functions (see below).  All requests require an HTTP
Authorization header where the scheme is `Signature`.

Full details are available in the `http signatures` specification, but a simple
form is:

    Authorization: Signature keyId="/:login/keys/:fp",algorithm="rsa-sha256",signature="$base64_signature"

The `keyId` for the service is always
`/$your_joyent_login/keys/$ssh_fingerprint`, and the supported algorithms are:
`rsa-sha1`, `rsa-sha256` and `dsa-sha`. The ssh key fingerprint must be a MD5
fingerprint (ex. `a1:b2:c3:d4:e5:f6:a7:b8:c9:d0:e1:f2:a3:b4:c5:d6`)

To make a request for an RBAC subuser, change the `keyId` for the signature to
`/$your_joyent_login/$subuser_login/keys/$ssh_fingerprint`. To make a request
using a RBAC role, include the HTTP header `Role`.

## Interacting with the Joyent Manta Storage Service from the shell (bash)

Most things in the service are easy to interact with via [cURL](http://curl.haxx.se/),
but note that all requests to the service must be authenticated.  You can string
together [OpenSSL](http://www.openssl.org/) and [cURL](http://curl.haxx.se/)
with a bash function.

Copy all of below:

``` bash
function manta {
    local alg=rsa-sha256
    local keyId=/$MANTA_USER/keys/$MANTA_KEY_ID
    local now=$(date -u "+%a, %d %h %Y %H:%M:%S GMT")
    local sig=$(echo "date:" $now | \
                tr -d '\n' | \
                openssl dgst -sha256 -sign $HOME/.ssh/id_rsa | \
                openssl enc -e -a | tr -d '\n')

    curl -sS $MANTA_URL"$@" -H "date: $now"  \
        -H "Authorization: Signature keyId=\"$keyId\",algorithm=\"$alg\",signature=\"$sig\""
}
```

Paste into `~/.bash_profile` or `~/.bashrc` and restart your terminal to pick up the changes.

    pbpaste > ~/.bash_profile

And edit the file, replacing `$JOYENT_CLOUD_USER_NAME` with your actual cloud username.

This all is setup correctly you will be able to:

    $ manta /$MANTA_USER/stor
    $ manta /$MANTA_USER/stor/moved -X PUT -H "content-type: application/json; type=file"
    $ manta /$MANTA_USER/stor/foo -X PUT -H "content-type: application/json; type=directory"
    $ manta /$MANTA_USER/stor -X GET
    {"name":"foo","type":"directory","mtime":"2013-06-16T05:42:56.515Z"}
      {"name":"moved","etag":"bfaa3227-3abb-4ed6-915a-a2179f623172","size":0,"type":"object","mtime":"2013-06-16T05:42:45.460Z"}

All sample "curl" requests in the rest of this document use the
function above.  Throughout the rest of the document, the value of the
Authorization header is simply represented as `$Authorization`.

# Errors

All HTTP requests can return user or server errors (HTTP status codes >= 400).
In these cases, you can usually expect a JSON body to come along that has the following
structure:

``` json
{
  "code": "ProgrammaticCode",
  "message": "human consumable message"
}
```

The complete list of codes that will be sent are:

- AuthSchemeError
- AuthorizationError
- BadRequestError
- BucketAlreadyExistsError
- BucketNotEmptyError
- BucketNotFoundError
- ChecksumError
- ConcurrentRequestError
- ContentLengthError
- ContentMD5MismatchError
- DirectoryDoesNotExistError
- DirectoryExistsError
- DirectoryNotEmptyError
- DirectoryOperationError
- EntityExistsError
- InternalError
- InvalidArgumentError
- InvalidAuthTokenError
- InvalidCredentialsError
- InvalidDurabilityLevelError
- InvalidJobError
- InvalidKeyIdError
- InvalidLimitError
- InvalidLinkError
- InvalidMultipartUploadStateError
- InvalidSignatureError
- InvalidUpdateError
- JobNotFoundError
- JobStateError
- KeyDoesNotExistError
- LinkNotFoundError
- LinkNotObjectError
- LinkRequiredError
- MultipartUploadInvalidArgumentError
- NotAcceptableError
- NotEnoughSpaceError
- ObjectNotFoundError
- ParentNotBucketError
- ParentNotBucketRootError
- ParentNotDirectoryError
- PreSignedRequestError
- PreconditionFailedError
- RequestEntityTooLargeError
- ResourceNotFoundError
- RootDirectoryError
- SSLRequiredError
- ServiceUnavailableError
- UploadTimeoutError
- UserDoesNotExistError

Additionally, jobs may emit the above errors, or:

|| **Error name** || **Reason** ||
|| TaskInitError  || Failed to initialize a task (usually a failure to load assets). ||
|| UserTaskError  || User's script returned a non-zero status or one of its processes dumped core. ||

# Buckets

## OptionsBuckets (OPTIONS /:login/buckets)

Returns success if buckets is supported.  This is a way to determine if a manta
setup supports buckets (i.e.: is using `manta-buckets-api` and not
`manta-muskie`).

### Return Data

On success this will return a `204` status code with no data.

## ListBuckets (GET /:login/buckets)

Lists the buckets owned by a user.

### Return Data

On success this will return newline (`\n`) separated stream of JSON objects,
where each object represents a single bucket.  Each object will have the
following properties:

- `name` [string] bucket name
- `type` [string] entry type (will `"bucket"` or `"group"`)
- `mtime` [string] bucket modified time in ISO 8601 format

Note that `"group"` objects (described below) will only contain the `name` and
`type` properties.

An example listing would look like (newlines added for clarity):

```
{
  "name": "bucket-1",
  "type": "bucket",
  "mtime": "2019-09-10T19:19:09.495Z"
}
{
  "name": "bucket-2",
  "type": "bucket",
  "mtime": "2019-09-10T20:15:26.436Z"
}
{
  "name": "bucket-3",
  "type": "bucket",
  "mtime": "2019-09-10T20:15:31.038Z"
}
{
  "name": "test-bucket",
  "type": "bucket",
  "mtime": "2019-09-10T20:15:35.238Z"
}
```

### Query Parameters

This will return entries in blocks of `1024` (you can opt for less, or more by
setting the `limit` parameter on the query string).  You can choose where to
start the next listing by using the `marker` query parameter. The service lists
objects in alphabetical order (UTF-8 collation).

All query parameters are optional.

- `limit` the maximum number of results to return, max 1024, defaults to 1024
- `marker` a string to start the listing, this is used for pagination (explained below)
- `prefix` a string to match against the beginning of the bucket names to limit results
- `delimiter` a single character to separate entries into a logical unit when listing

### Pagination

An optional header of `Next-Marker` will be returned if there are more entries
than the current limit allows.  This should be used in subsequent `ListBuckets`
requests as the `marker` header until there is no `Next-Marker` header returned.

Note that the `limit` parameter is just a maximum, and it is possible for a
smaller number of results than the limit to be returned, even though there may
be more records to request.  Because of this, always check for the presence of
the `Next-Marker` header to determine if there are more records to get.

An example of this is (some headers removed for brevity):

```
$ manta /$MANTA_USER/buckets?prefix=bucket\&limit=2 -i
HTTP/1.1 200 OK
Connection: close
Next-Marker: bucket-2
Date: Wed, 16 Oct 2019 18:10:22 GMT
Server: Manta

{"name":"bucket-1","type":"bucket","mtime":"2019-10-16T18:04:38.270Z"}
{"name":"bucket-2","type":"bucket","mtime":"2019-10-16T18:05:26.831Z"}
$ manta /$MANTA_USER/buckets?prefix=bucket\&limit=2\&marker=bucket-2 -i
HTTP/1.1 200 OK
Connection: close
Date: Wed, 16 Oct 2019 18:10:43 GMT
Server: Manta

{"name":"bucket-3","type":"bucket","mtime":"2019-10-16T18:05:33.562Z"}
```

#### Delimiter

The delimiter parameter can be used as a token to separate an entry when
listing.  For example, the 3 buckets above are all named `bucket-N` where `N`
is a number, we can set the delimiter to `-` to get back a single result for
all 3 buckets.

```
$ manta /$MANTA_USER/buckets?prefix=bucket\&delimiter=- -i
HTTP/1.1 200 OK
Connection: close
Date: Wed, 16 Oct 2019 18:12:17 GMT
Server: Manta

{"name":"bucket-","type":"group"}
```

This single entry will only count as 1 entry against the limit you set.  This
also helps the backend service by being able to skip multiple entries that
match the same delimiter.  Whether the `bucket-` group encompasses 5,000
entries, or 50,000 entries, the work for the server should be similar.

## CreateBucket (PUT /:login/buckets/:bucket_name)

Create a new bucket.

### Headers

The following header(s) must be supplied with each request:

- `Content-Type` must be set to `application/json; type=bucket`

### Return Data

On success this will return a `204` status code with no data.

## HeadBucket (HEAD /:login/buckets/:bucket_name)

Checks for the existence of a bucket by name.

### Return Data

On success this will return a status code of `200`. The only failure mode is if
the bucket was not found, in which case will be a `BucketNotFoundError` with a
status code of 404.

## DeleteBucket (DELETE /:login/buckets/:bucket_name)

Delete a bucket by name.

### Return Data

On success this will return a `204` status code with no data.  This can fail
with a `BucketNotFoundError` or a `BucketNotEmptyError`.

---

## ListBucketObjects (GET /:login/buckets/:bucket_name/objects)

Lists the objects of a bucket.

### Return Data

On success this will return newline (`\n`) separated stream of JSON objects,
where each object represents a single object. Each object will have the
following properties:

- `name` [string] bucket name
- `type` [string] entry type (will `"bucketobject"` or `"group"`)
- `etag` [string] a UUID etag that can be used by the client
- `size` [number] object size (in bytes)
- `contentType` [string] `Content-Type` of the object when it was created
- `contentMD5` [string] md5 checksum of the objects data (calculated when uploaded)
- `mtime` [string] bucket modified time in ISO 8601 format

Note that any `"group"` objects (described in `ListBuckets`) will only contain the
`name` and `type` properties.

An example listing would look like (newlines added for clarity):

```
{
  "name": "dir1/a.txt",
  "type": "bucketobject",
  "etag": "ef351164-65b2-c1cb-e9a6-b2eca9e04813",
  "size": 11,
  "contentType": "application/json",
  "contentMD5": "puh9hLJiq0smQ3Xk6c+wdg==",
  "mtime": "2019-10-16T20:35:11.259Z"
}
{
  "name": "dir1/b.txt",
  "type": "bucketobject",
  "etag": "c2326453-286b-40bf-ece9-f77fb5528be1",
  "size": 11,
  "contentType": "application/json",
  "contentMD5": "puh9hLJiq0smQ3Xk6c+wdg==",
  "mtime": "2019-10-16T20:35:17.768Z"
}
{
  "name": "dir1/c.txt",
  "type": "bucketobject",
  "etag": "07507f42-92ab-e7bb-871b-c869fe14f143",
  "size": 11,
  "contentType": "application/json",
  "contentMD5": "puh9hLJiq0smQ3Xk6c+wdg==",
  "mtime": "2019-10-16T20:35:24.675Z"
}
{
  "name": "foo",
  "type": "bucketobject",
  "etag": "4d2fcc0e-9c17-692a-8eb3-cc5a421e4963",
  "size": 11,
  "contentType": "application/json",
  "contentMD5": "puh9hLJiq0smQ3Xk6c+wdg==",
  "mtime": "2019-10-16T20:34:50.375Z"
}
```

Note that the `/` character is valid in the objects name - it must be URL
encoded when it is created.

### Query Parameters / Pagination

The logic for this is identical to `ListBuckets` - see above for more
documentation.

### Delimiter

The logic for this is also identical to `ListBuckets` though it is worth
showing an example here using the `/` character.  With this, a directory
structure can be emulated.

`prefix=dir1`

```
$ manta /$MANTA_USER/buckets/bucket-1/objects?prefix=dir1\&delimiter=%2f
{"name":"dir1/","type":"group"}
```

`prefix=dir1%2f`

```
$ manta /$MANTA_USER/buckets/bucket-1/objects?prefix=dir1%2f\&delimiter=%2f
{"name":"dir1/a.txt","type":"bucketobject","etag":"ef351164-65b2-c1cb-e9a6-b2eca9e04813","size":11,"contentType":"application/json","contentMD5":"puh9hLJiq0smQ3Xk6c+wdg==","mtime":"2019-10-16T20:35:11.259Z"}
{"name":"dir1/b.txt","type":"bucketobject","etag":"c2326453-286b-40bf-ece9-f77fb5528be1","size":11,"contentType":"application/json","contentMD5":"puh9hLJiq0smQ3Xk6c+wdg==","mtime":"2019-10-16T20:35:17.768Z"}
{"name":"dir1/c.txt","type":"bucketobject","etag":"07507f42-92ab-e7bb-871b-c869fe14f143","size":11,"contentType":"application/json","contentMD5":"puh9hLJiq0smQ3Xk6c+wdg==","mtime":"2019-10-16T20:35:24.675Z"}
```

## CreateBucketObject (PUT /:login/buckets/:bucket_name/objects/:object_name)

Create a new object in a bucket.

### Headers

The following header(s) must be supplied with each request:

- `Content-Type` set to anything, this will be used by the server when this
object is requested

### Return Data

On success this will return a `204` status code with no data.

Also, it will include the following headers:

- `Etag` the etag generated for the object
- `Computed-MD5` the generated md5 checksum for the object

## GetBucketObject (GET /:login/buckets/:bucket_name/objects/:object_name)

Get an objects data.

### Return Data

On success this will return with a `200` status code and the data from the
objects data itself.

Also, it will include the following headers:

- `Content-Type` the content type header supplied during object creation
- `Etag` the etag generated for the object
- `Content-MD5` the generated md5 checksum for the object
- `Last-Modified` the last modified time of the object
- `Content-Length` the size of the data being returned
- `Durability-Level` the durability level of the object

This request can fail with a `BucketNotFoundError` if the bucket does not
exist.

## HeadBucketObject (HEAD /:login/buckets/:bucket_name/objects/:object_name)

Get an objects metadata.

### Return Data

On success this will return a status code of `200` and all of the same headers
as the `GetBucketObject` request.

This request can fail with a `BucketNotFoundError` if the bucket does not
exist, or an `ObjectNotFoundError` if the object does not exist.

## DeleteBucketObject (DELETE /:login/buckets/:bucket_name/objects/:object_name)

Delete an object.

### Return Data

On success this will return a `204` status code with no data.  This can fail
with a `BucketNotFoundError` or an `ObjectNotFoundError`).

## UpdateBucketObjectMetadata (PUT /:login/buckets/:bucket_name/objects/:object_name/metadata)

Update an objects metadata (headers).

### Return Data

On success this will return a `204` status code with no data.  This can fail
with a `BucketNotFoundError` or an `ObjectNotFoundError`).

### Headers

The following headers can be updated:

- `Content-Type` the content type header to use when serving the object
