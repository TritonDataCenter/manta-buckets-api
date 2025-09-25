<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright 2020 Joyent, Inc.
    Copyright 2025 Edgecast Cloud LLC.
-->

# manta-buckets-api: The Manta Web API

This repository is part of the Joyent Manta project.  For contribution
guidelines, issues, and general documentation, visit the main
[Manta](http://github.com/TritonDataCenter/manta) project page.

manta-buckets-api holds the source code for the Manta API, otherwise known as
"the front door".  It is analogous to CloudAPI for SDC.  See the restdown
docs for API information, but effectively this is where you go to call
PUT/GET/DEL on your stuff, as well as to submit and control compute jobs.

API documentation is in [docs/index.md](./docs/index.md).  Some design
documentation (possibly quite dated) is in [docs/internal](./docs/internal).
Developer notes are in this README.

## Browser-Friendly URLs

For improved user experience, the buckets API provides automatic URL redirection for web browser users. This feature allows users to access objects using shorter, more intuitive URLs without affecting S3 API functionality.

### URL Shortcut

Web browsers can access objects using the simplified URL pattern:

```
https://host/username/buckets/bucketname/filename
```

This automatically redirects to the full Manta path:

```
https://host/username/buckets/bucketname/objects/filename
```

### Examples

```bash
# Browser users can type this shorter URL:
https://manta.example.com/jdoe/buckets/documents/report.pdf

# Which automatically redirects to:
https://manta.example.com/jdoe/buckets/documents/objects/report.pdf
```

### Important Notes

- **Browser-only**: This redirection only applies to web browser requests (detected via `Accept: text/html` headers)
- **API compatibility**: S3 API calls, s3cmd operations, and direct API access are completely unaffected
- **Backward compatibility**: All existing URLs continue to work as before
- **Smart detection**: Redirection won't occur if the URL already contains the `/objects/` segment

This feature makes it easier for users to bookmark, share, and manually type URLs to access their stored objects while maintaining full compatibility with all programmatic access methods.

## Testing

### S3 Compatibility Testing

The Manta Buckets API includes comprehensive test scripts for validating S3 compatibility and ACL functionality.

#### S3 Compatibility Test Script

The main S3 compatibility test script validates core S3 operations using AWS CLI:

```bash
# Run with default configuration
./test/s3-compat-test.sh

# Run with custom endpoint and credentials  
S3_ENDPOINT="https://manta.example.com:8080" \
AWS_ACCESS_KEY_ID="your-key" \
AWS_SECRET_ACCESS_KEY="your-secret" \
./test/s3-compat-test.sh

# View available options
./test/s3-compat-test.sh --help
```

**Test Coverage:**
- Bucket operations (create, list, delete)
- Object operations (upload, download, metadata)
- Data integrity validation (MD5/SHA256 checksums)
- Error handling for non-existent resources
- Authentication and authorization

#### S3cmd ACL Test Script

The ACL-specific test script validates Access Control List operations using s3cmd:

```bash
# Prerequisites: Install s3cmd
# Ubuntu/Debian: sudo apt-get install s3cmd
# CentOS/RHEL: sudo yum install s3cmd  
# pip: pip install s3cmd

# Run ACL tests with default configuration
./test/s3cmd-acl-test.sh

# Run with custom endpoint and credentials
S3_ENDPOINT="https://manta.example.com:8080" \
AWS_ACCESS_KEY_ID="your-key" \
AWS_SECRET_ACCESS_KEY="your-secret" \
./test/s3cmd-acl-test.sh

# View available options
./test/s3cmd-acl-test.sh --help
```

**ACL Test Coverage:**
- s3cmd connectivity and configuration
- Bucket ACL operations (get, set)
- Object ACL operations (get, set)
- Canned ACL testing (private removes public-read role, public-read adds role)
- ACL policy verification
- Object listing with ACL information

**Environment Variables:**
- `AWS_ACCESS_KEY_ID` - Your Manta access key
- `AWS_SECRET_ACCESS_KEY` - Your Manta secret key  
- `S3_ENDPOINT` - Manta endpoint URL (default: https://localhost:8080)
- `AWS_REGION` - AWS region (default: us-east-1)

**Example Output:**
```
[2024-01-01 12:00:00] Starting S3cmd ACL Compatibility Tests for manta-buckets-api
============================================================
[2024-01-01 12:00:01] Testing: s3cmd Connectivity
✅ s3cmd connectivity - Successfully connected to S3 endpoint
[2024-01-01 12:00:02] Testing: Create Bucket with s3cmd  
✅ Create bucket - s3cmd-acl-test-1234567890 created successfully
[2024-01-01 12:00:03] Testing: Put Object with Default ACL
✅ Put object - test-object.txt uploaded successfully
...
============================================================
Tests Passed: 12
Tests Failed: 0
🎉 All ACL tests passed! s3cmd ACL compatibility is working correctly.
```

Both test scripts provide:
- **Automated setup/cleanup** of test resources
- **Detailed logging** with timestamps and color-coded output
- **Comprehensive validation** of responses and data integrity
- **Error recovery** to continue testing after failures
- **Summary reporting** with pass/fail statistics

## Deploying a buckets-api image

If you're changing anything about the way buckets-api is deployed, configured, or
started, you should definitely test creating a buckets-api image and deploying that
into your Manta.  This is always a good idea anyway.  To run tests against an
image, your configuration will be a bit different.  Your `MANTA_URL` will be the
manta network IP of a buckets-api instance, with a port number of a buckets-api process
inside a buckets-api zone (8081).  Your `SDC_URL` will be the external network IP of
the cloudapi0 zone.  You can find both of these IPs with the commands:

    $ vmadm get <buckets-api_zone_uuid> | json -a nics | json -a nic_tag ip
    $ vmadm lookup -j alias=cloudapi0 | json -a nics | json -a ip

There are various documents about deploying/updating a buckets-api image in
Manta. If you're doing this for the first time, and not sure what to
do, I had success with `make buildimage` which leaves you with an
image and manifest in `./bits`. You can then import this image and
follow this guide to upgrading manta components:
https://github.com/TritonDataCenter/manta/blob/master/docs/operator-guide/maintenance.md#upgrading-manta-components

## Metrics

Buckets-Api exposes metrics via [node-artedi](https://github.com/TritonDataCenter/node-artedi).
See the [design](./docs/internal/design.md) document for more information about
the metrics that are exposed, and how to access them. For development, it is
probably easiest to use `curl` to scrape metrics:

```
$ curl http://localhost:8881/metrics
```

Notably, some metadata labels are not being collected due to their potential
for high cardinality.  Specifically, remote IP address, object owner, and caller
username are not collected.  Metadata labels that have a large number of unique
values cause memory strain on metric client processes (buckets-api) as well as
metric servers (Prometheus).  It's important to understand what kind of an
effect on the entire system the addition of metrics and metadata labels can have
before adding them. This is an issue that would likely not appear in a
development or staging environment.

## Service registration

Like most other components in Triton and Manta, this service is configured to
use [Registrar](https://github.com/TritonDataCenter/registrar/). Each of the API server
ports are registered under a `SRV` record as described in the Registrar
documentation, and the registration type is `load\_balancer`.

The general mechanism is [documented in detail in the Registrar
README](https://github.com/TritonDataCenter/registrar/blob/master/README.md).

As with other services providing multiple ports per zone instance, the registrar
template is itself modified during setup via `boot/setup.sh` to populate the
list of ports. Consequently, querying DNS for `SRV` entries will show something
like (if we have two instances each with four API servers):

```
$ dig +nocmd +nocomments +noquestion +nostats -t SRV _http._tcp.buckets-api.manta.example.com
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8081 243844f9-8cc1-497d-99a0-627263524e7a.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8082 243844f9-8cc1-497d-99a0-627263524e7a.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8083 243844f9-8cc1-497d-99a0-627263524e7a.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8084 243844f9-8cc1-497d-99a0-627263524e7a.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8081 4a1af359-a671-47d1-bc8b-70e4ea81af7c.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8082 4a1af359-a671-47d1-bc8b-70e4ea81af7c.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8083 4a1af359-a671-47d1-bc8b-70e4ea81af7c.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8084 4a1af359-a671-47d1-bc8b-70e4ea81af7c.buckets-api.manta.example.com.
243844f9-8cc1-497d-99a0-627263524e7a.buckets-api.manta.example.com. 30 IN A 192.168.0.39
4a1af359-a671-47d1-bc8b-70e4ea81af7c.buckets-api.manta.example.com. 30 IN A 192.168.0.38
```

The `buckets-api` client, [muppet](https://github.com/TritonDataCenter/muppet), doesn't
directly use DNS lookups: instead the corresponding Zookeeper nodes are watched
for changes, updating its `haproxy` configuration as needed. This is partly for
historical reasons (both muppet and the old webapi registered themselves with a
service name of "manta"), and to reduce load on
[binder](https://github.com/TritonDataCenter/binder/).

## S3 Compatibility

Manta Buckets API provides S3-compatible endpoints that translate S3 API requests into Manta bucket operations. This compatibility layer enables S3 clients and tools to work with Manta's bucket storage.
[!NOTE]
Only Path-Style URL is supported, Virtual-Hosted style is in development.


### Supported Operations

#### Bucket Operations
- **ListBuckets**: `GET /` → Lists all buckets for the authenticated account
- **CreateBucket**: `PUT /:bucket` → Creates a new bucket
- **ListBucketObjects**: `GET /:bucket` → Lists objects in a bucket (S3 API v1)
- **ListBucketObjectsV2**: `GET /:bucket?list-type=2` → Lists objects in a bucket (S3 API v2)
- **HeadBucket**: `HEAD /:bucket` → Checks if bucket exists
- **DeleteBucket**: `DELETE /:bucket` → Deletes an empty bucket

#### Object Operations
- **CreateBucketObject**: `PUT /:bucket/:object` → Uploads an object to a bucket
- **GetBucketObject**: `GET /:bucket/:object` → Downloads an object from a bucket
- **HeadBucketObject**: `HEAD /:bucket/:object` → Gets object metadata
- **DeleteBucketObject**: `DELETE /:bucket/:object` → Deletes an object from a bucket

### Addressing Styles

Currently only S3 Path-style addressing is supported:

- **Path-style**: `https://domain.com/bucket/object`
- **Virtual-hosted**: `https://bucket.domain.com/object`

The system automatically detects the addressing style based on the Host header and request path,
but currently virtual-hosted style is disabled.

### AWS CLI Compatibility

The S3 compatibility layer is fully compatible with the AWS CLI, enabling seamless integration with existing S3 workflows and tools.

#### Configuration

To use AWS CLI with Manta Buckets API, configure your endpoint and credentials:

```bash
# Set environment variables
export AWS_ACCESS_KEY_ID="your-manta-access-key"
export AWS_SECRET_ACCESS_KEY="your-manta-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Sample credentials file 

``` shell
[default]
aws_access_key_id = "your-manta-access-key"
aws_secret_access_key = "your-manta-secret-key"
region = us-east-1
s3=
         addressing_style = path
```

# Use AWS CLI with custom endpoint
aws s3 --endpoint-url="https://your-manta-endpoint:8080" \
    --region="us-east-1" \
    --no-verify-ssl  ls

aws s3  ls s3://yourbucketname \
    --endpoint-url="https://your-manta-endpoint" \
    --region=us-east-1 --no-verify-ssl
 
# Or use s3api commands
         
aws --no-verify-ssl s3api list-objects-v2 \
    --bucket test5  --region us-east-1 \ 
    --endpoint-url=https://your-manta-endpoint:8080 --output json

```

#### Supported AWS CLI Commands

**Bucket Operations:**
```bash
# List all buckets
aws s3api list-buckets

# Create a bucket
aws s3api create-bucket --bucket my-bucket

# Check if bucket exists
aws s3api head-bucket --bucket my-bucket

# Delete bucket
aws s3api delete-bucket --bucket my-bucket
```

**Object Operations:**
```bash
# Upload object
aws s3api put-object --bucket my-bucket --key my-file.txt --body local-file.txt

# Download object
aws s3api get-object --bucket my-bucket --key my-file.txt downloaded-file.txt

# Get object metadata
aws s3api head-object --bucket my-bucket --key my-file.txt

# List objects
aws s3api list-objects-v2 --bucket my-bucket

# Delete object
aws s3api delete-object --bucket my-bucket --key my-file.txt
```

**High-level S3 Commands:**
```bash
# Copy files
aws s3 cp local-file.txt s3://my-bucket/remote-file.txt
aws s3 cp s3://my-bucket/remote-file.txt local-copy.txt

# Sync directories
aws s3 sync ./local-dir s3://my-bucket/remote-dir/

# List bucket contents
aws s3 ls s3://my-bucket/
```
### S3 Clients configuration

#### Minio mc 

``` shell
export S3_ENDPOINT_URL=https://your-manta-endpoint
export MC_REGION=us-east-1
mc alias set local  https://your-manta-endpoint\
    AWS_ACCESS_KEY AWS_ACCESS_SECRET_KEY --insecure --api S3v4 --path=off
```

Minio mc example alias configuration

``` shell
{
	"version": "10",
	"aliases": {
	"local": {
			"url": "https://your-manta-endpoint-bucket",
			"accessKey": "your-manta-access-key",
			"secretKey": "your-manta-secret-key",
			"api": "S3v4",
			"path": "on"
		}
  }
}

```

List objects in bucket test5

``` shell
mc  ls local/test5  --insecure
[2025-07-17 14:40:52 -04] 1.4KiB STANDARD Jenkinsfile
[2025-07-15 19:28:02 -04] 1.9KiB STANDARD package.json
```
#### s3cmd 

A sample configuration to start using s3cmd is the following 

``` sh
[default]
access_key = your-access-key
secret_key = your-secret-key
host_base = your-manta-endpoint
host_bucket = your-manta-endpoint
use_https = True
signature_v2 = False

```
The reason that host_base and host_bucket has the same value is to force
path-style buckets instead of virtual buckets. 


[!NOTE]
The only supported clients today are awscli and s3cmd as testing
is done using this clients.

### S3 to Manta Object Property Mapping

The following table shows how S3 object properties are translated to Manta object properties during upload operations:

| **S3 Property** | **S3 Example** | **Manta Property** | **Manta Example** | **Transformation** | **Default Value** |
|---|---|---|---|---|---|
| **Object Key** | `my-folder/file.txt` | `name` | `my-folder/file.txt` | Direct mapping | N/A |
| **Content-Type** | `image/jpeg` | `contentType` | `image/jpeg` | Direct mapping | `application/octet-stream` |
| **Content-Length** | `1024` | `contentLength` | `1024` | Direct mapping | Calculated from stream |
| **Content-MD5** | `"d41d8cd98f00b204e9800998ecf8427e"` | `contentMD5` | `"d41d8cd98f00b204e9800998ecf8427e"` | Direct mapping or computed | Computed during upload |
| **x-amz-meta-author** | `"John Doe"` | `m-author` | `"John Doe"` | Prefix conversion (`x-amz-meta-*` → `m-*`) | N/A |
| **x-amz-meta-category** | `"documents"` | `m-category` | `"documents"` | Prefix conversion | N/A |
| **ETag** | `"abc123def456"` | `objectId` (used as ETag) | `"550e8400-e29b-41d4-a716-446655440000"` | Generated UUID v4 | Generated UUID |
| **LastModified** | `2023-01-01T12:00:00Z` | `mtime` | `2023-01-01T12:00:00Z` | Set during creation | Current timestamp |
| **StorageClass** | `STANDARD` | N/A (implicit) | N/A | Always "STANDARD" | `STANDARD` |
| **Cache-Control** | `max-age=3600` | `headers['Cache-Control']` | `max-age=3600` | Direct mapping | N/A |
| **Surrogate-Key** | `cache-key-123` | `headers['Surrogate-Key']` | `cache-key-123` | Direct mapping | N/A |
| **durability-level** | `3` | `req._copies` | `3` | Direct mapping | `2` |
| **role-tag** | `admin,user` | `roles` | `[uuid1, uuid2]` | Converted to role UUIDs | `[]` |
| **x-amz-decoded-content-length** | `2048` | `contentLength` | `2048` | Used for chunked uploads | N/A |

#### Limitations

- **StorageClass**: Only "STANDARD" supported (hardcoded)
- **ETag**: Uses Manta object ID instead of MD5 hash for performance
- **Metadata Size**: User metadata limited to 4KB total for all `x-amz-meta-*` headers
- **Custom Headers**: Only `m-*` pattern headers preserved as user metadata

#### Properties Added by Manta (Not Present in S3)

| **Manta Property** | **Example** | **Purpose** | **How Generated** |
|---|---|---|---|
| `sharks` | `["1.stor.domain.com", "2.stor.domain.com"]` | Storage node locations | Computed by storage info service |
| `type` | `"bucketobject"` | Object type identifier | Fixed value |
| `objectId` | `"550e8400-e29b-41d4-a716-446655440000"` | Unique object identifier | Generated UUID v4 |
| `storageLayoutVersion` | `2` | Storage layout version | Current version (default: 2) |
| `name_hash` | `"d41d8cd98f00b204e9800998ecf8427e"` | MD5 of object name | Computed for metadata placement |
| `owner` | `"550e8400-e29b-41d4-a716-446655440001"` | Account UUID | From authenticated user |
| `bucketId` | `"550e8400-e29b-41d4-a716-446655440002"` | Bucket UUID | From bucket lookup |


#### Key Transformation Rules

1. **Metadata Headers**: `x-amz-meta-*` → `m-*` (prefix change)
2. **ETag Handling**: S3 ETag becomes Manta `objectId` (UUID instead of MD5)
3. **Size Limits**: Custom metadata limited to 4KB total
4. **Durability**: S3 doesn't specify, Manta defaults to 2 copies
5. **Storage Class**: S3 supports multiple classes, Manta always uses "STANDARD"

#### Example: S3 PUT Object Request → Manta Object

**S3 Request:**
```http
PUT /my-bucket/documents/report.pdf HTTP/1.1
Content-Type: application/pdf
Content-Length: 2048
Content-MD5: d41d8cd98f00b204e9800998ecf8427e
x-amz-meta-author: John Doe
x-amz-meta-department: Engineering
durability-level: 3
```

**Resulting Manta Object:**
```javascript
{
  name: "documents/report.pdf",
  contentType: "application/pdf",
  contentLength: 2048,
  contentMD5: "d41d8cd98f00b204e9800998ecf8427e",
  objectId: "550e8400-e29b-41d4-a716-446655440000",
  mtime: "2023-01-01T12:00:00.000Z",
  type: "bucketobject",
  sharks: ["1.stor.domain.com", "2.stor.domain.com", "3.stor.domain.com"],
  headers: {
    "m-author": "John Doe",
    "m-department": "Engineering"
  },
  owner: "550e8400-e29b-41d4-a716-446655440001",
  bucketId: "550e8400-e29b-41d4-a716-446655440002"
}
```


This mapping enables seamless S3 API compatibility while leveraging Manta's distributed storage architecture and metadata system.

## Documentation

| **Document** | **Location** | **Description** |
|---|---|---|
| **S3 Documentation Index** | [docs/s3.md](./docs/s3.md) | Complete navigation guide for all S3 documentation with user, developer, and operations guides |
| **S3 Compatibility Matrix** | [docs/divergences.md](./docs/divergences.md) | AWS S3 vs Manta feature comparison, supported/unsupported operations, migration considerations |
| **S3 Quick Start Guide** | [docs/quickstart.md](./docs/quickstart.md) | Getting started with S3 clients, access key creation, basic operations, troubleshooting |
| **S3-to-Manta Architecture** | [docs/architecture.md](./docs/architecture.md) | System architecture, request flow, header translation, ACL system, SigV4 authentication |
| **S3 Multipart Upload Design** | [docs/mpu.md](./docs/mpu.md) | Multipart upload implementation with native v2 commit and distributed locking |
| **S3 Compatibility Testing** | [docs/testing.md](./docs/testing.md) | Testing procedures, AWS CLI test suites, s3cmd testing, debugging |
| **Anonymous S3 Access** | [docs/anonymous-access.md](./docs/anonymous-access.md) | Public bucket access implementation and security model |
| **S3 Error Codes Reference** | [docs/error-codes.md](./docs/error-codes.md) | Complete S3 error documentation with HTTP status codes and conditions |
| **S3 Troubleshooting FAQ** | [docs/faq.md](./docs/faq.md) | Common issues and solutions for S3 compatibility |
| **S3 Layer Deployment** | [docs/deployment.md](./docs/deployment.md) | Production setup instructions and service dependencies |

## Dtrace Probes

Buckets-Api has two dtrace providers. The first, `buckets-api`, has the following probes:
* `client_close`: `json`. Fires if a client uploading an object or part closes
  before data has been streamed to mako. Also fires if the client closes the
  connection while the stream is in progress. The argument json object has the
  following format:
  ```
  {
      id: restify uuid, or x-request-id/request-id http header (string)
      method: request http method (string)
      headers: http headers specified by the client (object)
      url: http request url (string)
      bytes_sent: number of bytes streamed to mako before client close (int)
      bytes_expected: number of bytes that should have been streamed (int)
  }
  ```
* `socket_timeout`: `json`. Fires when the timeout limit is reached on a
  connection to a client. This timeout can be configured either by setting the
  `SOCKET_TIMEOUT` environment variable. The default is 120 seconds. The object
  passed has the same fields to the `client_close` dtrace probe, except for the
  `bytes_sent` and `bytes_expected`. These parameters are only present if buckets-api
  is able to determine the last request sent on this socket.

The second provider, `buckets-api-throttle`, has the following probes, which will not
fire if the throttle is disabled:
* `request_throttled`: `int`, `int`, `char *`, `char *` - slots occupied, queued
  requests, url, method. Fires when a request has been throttled.
* `request_handled`: `int`, `int`, `char *`, `char *` - slots occupied, queued
  requests, url, method. Fires after a request has been handled.
Internally, the buckets-api throttle is implemented with a vasync-queue. A "slot"
in the above description refers to one of `concurrency` possible spaces
allotted for concurrently scheduled request-handling callbacks. If all slots are
occupied, incoming requests will be "queued", which indicates that they are
waiting for slots to free up.
* `queue_enter`: `char *` - restify request uuid. This probe fires as a request
enters the queue.
* `queue_leave`: `char *` - restify request uuid. This probe fires as a request
is dequeued, before it is handled. The purpose of these probes is to make it
easy to write d scripts that measure the latency impact the throttle has on
individual requests.

The script `bin/throttlestat.d` is implemented as an analog to `moraystat.d`
with the `queue_enter` and `queue_leave` probes. It is a good starting point for
gaining insight into both how actively a buckets-api process is being throttled and
how much stress it is under.

The throttle probes are provided in a separate provider to prevent coupling the
throttle implementation with buckets-api itself. Future work may involve making the
throttle a generic module that can be included in any service with minimal code
modification.
