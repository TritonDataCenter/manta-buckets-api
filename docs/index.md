---
title: Joyent Manta Service REST API
markdown2extras: wiki-tables, code-friendly
---
<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright 2019 Joyent, Inc.
-->

# Manta Buckets Storage Service

This is the API reference documentation for the Joyent Manta Buckets Storage
Service, which enables you to store data in the cloud using a buckets and
objects abstraction.

This document covers only the HTTP interface and all examples are given in curl.

## Authentication

Authentication will be handled in the same manner as it is currently with Manta
as described [here](https://apidocs.joyent.com/manta/api.html#authentication).

## Interacting from the shell (Bash)

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

Paste into `~/.bash_profile` or `~/.bashrc` and restart your terminal to pick
up the changes.

The following environmental variables will need to be set (see
[Authentication](#authentication) above for more details):

    export MANTA_USER=<username>
    export MANTA_KEY_ID=<ssh-key-finger-print>
    export MANTA_URL=<url-to-manta>

This all is setup correctly you will be able to:

    $ manta /$MANTA_USER/buckets -i -X OPTIONS
    HTTP/1.1 204 No Content
    Server: Manta/2
    allow: OPTIONS, GET
    date: Tue, 26 Nov 2019 19:34:48 GMT
    x-request-id: 84178b7a-9f0a-44b9-8f24-67f07c93c3e3
    x-response-time: 86
    x-server-name: 1caf2114-99a7-4731-acd9-4541dd007ef7

All sample "curl" requests in the rest of this document use the
function above.

# Errors

All HTTP requests can return user or server errors (HTTP status codes >= 400).
In these cases, you can expect a JSON body to come along that has the following
structure:

``` json
{
  "code": "ProgrammaticCode",
  "message": "human consumable message"
}
```

The complete list of codes that will be sent are:

- `AuthSchemeError`
- `AuthorizationError`
- `BadRequestError`
- `BucketAlreadyExistsError`
- `BucketNotEmptyError`
- `BucketNotFoundError`
- `ChecksumError`
- `ConcurrentRequestError`
- `ContentLengthError`
- `ContentMD5MismatchError`
- `DirectoryDoesNotExistError`
- `DirectoryNotEmptyError`
- `EntityExistsError`
- `InternalError`
- `InvalidArgumentError`
- `InvalidAuthTokenError`
- `InvalidCredentialsError`
- `InvalidDurabilityLevelError`
- `InvalidKeyIdError`
- `InvalidLimitError`
- `InvalidMultipartUploadStateError`
- `InvalidSignatureError`
- `InvalidUpdateError`
- `KeyDoesNotExistError`
- `MultipartUploadInvalidArgumentError`
- `NotAcceptableError`
- `NotEnoughSpaceError`
- `ObjectNotFoundError`
- `ParentNotBucketError`
- `ParentNotBucketRootError`
- `PreSignedRequestError`
- `PreconditionFailedError`
- `RequestEntityTooLargeError`
- `ResourceNotFoundError`
- `SSLRequiredError`
- `ServiceUnavailableError`
- `UploadTimeoutError`
- `UserDoesNotExistError`

# Endpoints

| name | endpoint |
| --- | --- |
| [OptionsBuckets](#optionsbuckets) | `OPTIONS /:login/buckets` |
| [ListBuckets](#listbuckets) | `GET /:login/buckets` |
| [CreateBucket](#createbucket) | `PUT /:login/buckets/:bucket_name` |
| [HeadBucket](#headbucket) | `HEAD /:login/buckets/:bucket_name` |
| [DeleteBucket](#deletebucket) | `DELETE /:login/buckets/:bucket_name` |
| [ListBucketObjects](#listbucketobjects) | `GET /:login/buckets/:bucket_name/objects` |
| [CreateBucketObject](#createbucketobject) | `PUT /:login/buckets/:bucket_name/objects/:object_name` |
| [GetBucketObject](#getbucketobject) | `GET /:login/buckets/:bucket_name/objects/:object_name` |
| [HeadBucketObject](#headbucketobject) | `HEAD /:login/buckets/:bucket_name/objects/:object_name` |
| [DeleteBucketObject](#deletebucketobject) | `DELETE /:login/buckets/:bucket_name/objects/:object_name` |
| [UpdateBucketObjectMetadata](#updatebucketobjectmetadata) | `PUT /:login/buckets/:bucket_name/objects/:object_name/metadata` |

## OptionsBuckets

    OPTIONS /:login/buckets

Returns success if buckets is supported.  This is a way to determine if a manta
setup supports buckets (i.e.: is using `manta-buckets-api` and not
`manta-muskie`).

### Return Data

On success this will return a `204` status code with no data.

---

## ListBuckets

    GET /:login/buckets

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
Server: Manta/2

{"name":"bucket-1","type":"bucket","mtime":"2019-10-16T18:04:38.270Z"}
{"name":"bucket-2","type":"bucket","mtime":"2019-10-16T18:05:26.831Z"}
$ manta /$MANTA_USER/buckets?prefix=bucket\&limit=2\&marker=bucket-2 -i
HTTP/1.1 200 OK
Connection: close
Date: Wed, 16 Oct 2019 18:10:43 GMT
Server: Manta/2

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
Server: Manta/2

{"name":"bucket-","type":"group"}
```

This single entry will only count as 1 entry against the limit you set.  This
also helps the backend service by being able to skip multiple entries that
match the same delimiter.  Whether the `bucket-` group encompasses 5,000
entries, or 50,000 entries, the work for the server should be similar.

---

## CreateBucket

    PUT /:login/buckets/:bucket_name

Create a new bucket.

### Return Data

On success this will return a `204` status code with no data.

### Restrictions

Bucket names must be between 3 and 63 characters long, and must not
"resemble an IP address" as defined below.

A valid bucket name is composed of one or more "labels" separated by periods.

A label is defined as a string that meets the following criteria:
- Contains only lowercase letters, numbers, and hyphens.
- Does not start or end with a hyphen.

"resembling an IP address" is to mean four groups of between one and three
digits each, separated by periods. This includes strings that are not actually
valid IP addresses. For example:

- 1.1.1.1 resembles an IP address
- 999.999.999.999 also resembles an IP address
- 172.25.1234.1 does not, because there is a section with more than three
  digits. This is thus a valid bucket name.

---

## HeadBucket

    HEAD /:login/buckets/:bucket_name

Checks for the existence of a bucket by name.

### Return Data

On success this will return a status code of `200`. The only failure mode is if
the bucket was not found, in which case will be a `BucketNotFoundError` with a
status code of 404.

---

## DeleteBucket

    DELETE /:login/buckets/:bucket_name

Delete a bucket by name.

### Return Data

On success this will return a `204` status code with no data.  This can fail
with a `BucketNotFoundError` or a `BucketNotEmptyError`.

---

## ListBucketObjects

    GET /:login/buckets/:bucket_name/objects

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

---

## CreateBucketObject

    PUT /:login/buckets/:bucket_name/objects/:object_name

Create a new object in a bucket.

### Headers

The following header(s) must be supplied with each request:

- `Content-Type` set to anything, this will be used by the server when this
object is requested

The following headers may optionally be sent with the request:

- `Durability-Level`
- `If-Unmodified-Since`
- `If-Match`
- `If-None-Match`

### Return Data

On success this will return a `204` status code with no data.

Also, it will include the following headers:

- `Etag` the etag generated for the object
- `Computed-MD5` the generated md5 checksum for the object

### Restrictions

There are very few limitations imposed on object names. Object names must
contain only valid UTF-8 characters and may be a maximum of 1024 characters in
length. Object names may include forward slash characters (or any other valid
UTF-8 character) to create the suggestion of a directory hierarchy for a set of
object even though the buckets system uses a flat namespace. Care must be
taken, however, to properly URL encode all object names to avoid problems when
interacting with the server.

---

## GetBucketObject

    GET /:login/buckets/:bucket_name/objects/:object_name

Get an objects data.

### Headers

The following headers may optionally be sent with the request:

- `If-Modified-Since`
- `If-Unmodified-Since`
- `If-Match`
- `If-None-Match`

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

---

## HeadBucketObject

    HEAD /:login/buckets/:bucket_name/objects/:object_name

Get an objects metadata.

### Headers

The following headers may optionally be sent with the request:

- `If-Modified-Since`
- `If-Unmodified-Since`
- `If-Match`
- `If-None-Match`

### Return Data

On success this will return a status code of `200` and all of the same headers
as the `GetBucketObject` request.

This request can fail with a `BucketNotFoundError` if the bucket does not
exist, or an `ObjectNotFoundError` if the object does not exist.

---

## DeleteBucketObject

    DELETE /:login/buckets/:bucket_name/objects/:object_name

Delete an object.

### Headers

The following headers may optionally be sent with the request:

- `If-Unmodified-Since`
- `If-Match`
- `If-None-Match`

### Return Data

On success this will return a `204` status code with no data.  This can fail
with a `BucketNotFoundError` or an `ObjectNotFoundError`).

---

## UpdateBucketObjectMetadata

    PUT /:login/buckets/:bucket_name/objects/:object_name/metadata

Update an objects metadata (headers).

### Return Data

On success this will return a `204` status code with no data.  This can fail
with a `BucketNotFoundError` or an `ObjectNotFoundError`).

### Headers

The following headers can be updated:

- `Content-Type` the content type header to use when serving the object
