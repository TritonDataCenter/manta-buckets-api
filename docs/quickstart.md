# Manta Buckets API - S3 Layer Quick Start Guide

This guide will help you get started with using the S3-compatible layer of the Manta Buckets API. You'll learn how to create access keys and configure your S3 clients to work with Manta storage.

## Prerequisites

Before you begin, ensure you have:
- A Manta account 
- An S3 client (AWS CLI, s3cmd)

## Creating Access Keys

### Step 1: Create Access Key and Secret

The S3 layer uses your Manta your access keys and secret access key from your account.
To create the access key and secret, we need to use [cloudapi](https://docs.mnx.io/cloudapi/api-introduction).

```bash
# Call cloudapi to generate access keys and secret
cloudapi /your-manta-account/accesskeys | json
HTTP/1.1 200 OK
content-type: application/json
content-length: 2
access-control-allow-origin: *
access-control-allow-headers: Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, Api-Version, Response-Time
access-control-allow-methods: POST, GET, HEAD
access-control-expose-headers: Api-Version, Request-Id, Response-Time
content-md5: 11FxOYiYfpMxmANj4kGJzg==
date: Mon, 28 Jul 2025 14:38:39 GMT
server: cloudapi/9.20.0
api-version: 9.0.0
request-id: 6bf0b965-d49b-40c0-8619-675c02afa305
response-time: 320

[]
# as expected your account those not have access keys, so let's generate them.
cloudapi /your-manta-account/accesskeys -X POST
HTTP/1.1 201 Created
location: /neirac/accesskeys/91f41250ffff1bb1472611dd3b0bde50
content-type: application/json
content-length: 346
access-control-allow-origin: *
access-control-allow-headers: Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, Api-Version, Response-Time
access-control-allow-methods: POST, GET, HEAD
access-control-expose-headers: Api-Version, Request-Id, Response-Time
content-md5: IWO6EvVxPH542Zv+Q9fAAA==
date: Mon, 28 Jul 2025 14:38:51 GMT
server: cloudapi/9.20.0
api-version: 9.0.0
request-id: 9fd136ad-1021-4d55-a257-aeeffdac2071
response-time: 373

{"dn":"accesskeyid=your-access-key-id, uuid=your-manta-account-uuid, ou=users, o=smartdc","controls":[],"accesskeyid":"your-access-key-id","accesskeysecret":"your-access-key-secret","created":"2025-07-28T14:38:51.900Z","objectclass":"accesskey","status":"Active"}

```

### Step 2: Configure Your S3 Client

#### AWS CLI Configuration

```ini
[default]
aws_access_key_id = "your-manta-access-key"
aws_secret_access_key = "your-manta-secret-key"
region = us-east-1
s3=
         addressing_style = path
```

#### s3cmd Configuration

Create or edit `~/.s3cfg`:

```ini
[default]
access_key = your-access-key
secret_key = your-secret-key
host_base = your-manta-endpoint
host_bucket = your-manta-endpoint
use_https = True
signature_v2 = False

```

#### Environment Variables

You can also use environment variables:

```bash
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-access-key
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=https://your-manta-endpoint
```

## Testing Your Configuration

### Test Basic Operations

```bash
# List buckets
aws s3 ls --endpoint-url https://your-manta-endpoint

# Create a bucket
aws s3 mb s3://test-bucket --endpoint-url https://your-manta-endpoint

# Upload a file
aws s3 cp local-file.txt s3://test-bucket/ --endpoint-url https://your-manta-endpoint

# List objects in bucket
aws s3 ls s3://test-bucket/ --endpoint-url https://your-manta-endpoint

# Download a file
aws s3 cp s3://test-bucket/local-file.txt downloaded-file.txt --endpoint-url https://your-manta-endpoint
```

### Test with ACLs
ACLs are not applied to objects within a bucket, not to the bucket itself.

```bash
# Upload with public-read ACL
aws s3 cp local-file.txt s3://test-bucket/ --acl public-read --endpoint-url https://your-manta-endpoint

```

## S3 Presigned URLs

Manta Buckets API supports S3 presigned URLs, which allow you to grant temporary access to objects without requiring AWS credentials. This is useful for sharing files securely or integrating with web applications.

### How S3 Presigned URLs Work

S3 presigned URLs provide secure, time-limited access to objects by embedding authentication information directly in the URL. Here's how the process works:

1. **URL Generation**: A user with valid access keys generates a presigned URL using AWS CLI or SDK
2. **Cryptographic Signing**: The URL contains AWS SigV4 signature that validates the request 
3. **Request Validation**: Manta validates the signature against the original request parameters
4. **Secure Access**: If valid, the request is processed using the signer's permissions

### Security Features

- **Time-bound**: URLs expire after the specified duration (1 hour to 7 days)
- **Method-specific**: URLs are tied to specific HTTP operations (GET, PUT, etc.)
- **Tamper-proof**: Any modification to the URL invalidates the signature
- **Permission-scoped**: Access is limited to the signer's actual permissions

### Generating Presigned URLs

#### For Object Downloads (GET)

```bash
# Generate a presigned URL for downloading (valid for 1 hour)
aws s3 presign s3://test-bucket/file.txt \
    --endpoint-url https://your-manta-endpoint \
    --expires-in 3600

# Output: 
# https://your-manta-endpoint/test-bucket/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=your-access-key%2F20250926%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250926T220000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=...
```

#### For Object Uploads (PUT)

```bash
# Generate a presigned URL for uploading (valid for 2 hours)
aws s3 presign s3://test-bucket/new-file.txt \
    --endpoint-url https://your-manta-endpoint \
    --expires-in 7200

# Use the URL with curl to upload
curl -X PUT -T local-file.txt "https://your-manta-endpoint/test-bucket/new-file.txt?X-Amz-Algorithm=..."
```

### Using Presigned URLs

#### Simple Download

```bash
# Anyone with the URL can download the file (no AWS credentials needed)
curl "https://your-manta-endpoint/test-bucket/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=..." \
    -o downloaded-file.txt
```

#### Browser Access

Presigned URLs work directly in web browsers:

```html
<!-- Direct link for downloads -->
<a href="https://your-manta-endpoint/test-bucket/file.txt?X-Amz-Algorithm=...">Download File</a>

<!-- Image display -->
<img src="https://your-manta-endpoint/test-bucket/image.jpg?X-Amz-Algorithm=..." />
```

#### Web Application Integration

```javascript
// Example: Generate download links in a web app
const downloadUrl = generatePresignedUrl('test-bucket', 'document.pdf', 3600);

// Users can access the file without backend authentication
fetch(downloadUrl)
    .then(response => response.blob())
    .then(blob => {
        // Handle file download
    });
```

### Advanced Options

#### Custom Expiration Times

```bash
# Short-lived URL (15 minutes)
aws s3 presign s3://bucket/file.txt --expires-in 900 --endpoint-url https://your-manta-endpoint

# Long-lived URL (7 days - maximum)
aws s3 presign s3://bucket/file.txt --expires-in 604800 --endpoint-url https://your-manta-endpoint
```

#### Content-Type Specification

```bash
# For uploads with specific content type
aws s3 presign s3://bucket/image.jpg \
    --endpoint-url https://your-manta-endpoint \
    --expires-in 3600 \
    --content-type "image/jpeg"
```

### Implementation Details

#### Signature Validation Process

1. **Parameter Extraction**: Manta extracts signature components from query parameters
2. **Request Reconstruction**: The original signed request is reconstructed for validation
3. **Cryptographic Verification**: AWS SigV4 signature is validated using Mahi's authentication service
4. **Authorization Check**: User permissions are verified against Manta's RBAC system
5. **Request Processing**: If valid, the request proceeds through normal Manta authorization

#### Supported Operations

| Operation | Method | Description | Example Use Case |
|-----------|--------|-------------|------------------|
| **GetObject** | GET | Download files | File sharing, web content delivery |
| **PutObject** | PUT | Upload files | Web form uploads, direct browser uploads |
| **HeadObject** | HEAD | Get metadata | File existence checks, size validation |

### Troubleshooting Presigned URLs

#### Common Issues

**Invalid Signature Error (403)**
```
Error: Invalid signature
```
- **Cause**: URL parameters were modified or URL has expired
- **Solution**: Generate a new presigned URL

**Missing Authorization Header Error (403)**
```
Error: Missing Authorization header  
```
- **Cause**: Legacy client or malformed URL
- **Solution**: Verify URL was generated correctly with AWS CLI v2

**Access Denied Error (403)**
```
Error: Access Denied
```
- **Cause**: Signer lacks permissions for the requested operation
- **Solution**: Verify the access key has appropriate bucket/object permissions

#### Debugging Tips

```bash
# Validate URL structure
echo "URL components:"
echo "X-Amz-Algorithm: AWS4-HMAC-SHA256"
echo "X-Amz-Credential: Contains access key and scope"
echo "X-Amz-Date: Request timestamp" 
echo "X-Amz-Expires: Expiration time in seconds"
echo "X-Amz-SignedHeaders: Headers included in signature"
echo "X-Amz-Signature: Cryptographic signature"

# Test with curl for detailed error information
curl -v "https://your-manta-endpoint/bucket/file.txt?X-Amz-Algorithm=..."
```

### Security Best Practices

1. **Minimize Expiration Time**: Use the shortest reasonable expiration time
2. **Secure Distribution**: Share URLs over HTTPS only
3. **Monitor Access**: Log and monitor presigned URL usage
4. **Rotate Access Keys**: Regularly rotate AWS access keys used for signing
5. **Validate Permissions**: Ensure signers have only necessary permissions

## Service Dependencies

The following table shows the services that the Manta Buckets API S3 layer depends on:

| Service Name | Service Type | UUID/Identifier | Needs Extra Steps? |
|--------------|--------------|-----------------|-------------------|
| `authcache` | Authentication & Authorization |  2d6c9916-2bc3-40d7-ad3c-4f76fb5fbc05 | Yes - Requires cache rebuild |
| `buckets-api`| Core Bucket Operations |  684049e8-9b78-49b3-8e09-8744f7df3698  | No - Direct integration |
| `storage`  | Storage Nodes |  5735eba4-746c-4f93-b275-8d739e53f1e4| No - Backend dependency |
| `loadbalancer` | Traffic Distribution | f9f32770-14fa-4f85-a7cc-a1b8b62ede07| No -  direct integration  |

### Services Requiring Extra Steps

Required steps after the required services from the service dependencies table
are specified in https://github.com/TritonDataCenter/manta-buckets-api/blob/MANTA-5471/docs/deployment.md
