# Manta Buckets API - S3 Layer Quick Start Guide

This guide will help you get started with using the S3-compatible layer of the Manta Buckets API. You'll learn how to create access keys and configure your S3 clients to work with Manta storage.

## Prerequisites

Before you begin, ensure you have:
- A Manta account 
- An S3 client (AWS CLI, s3cmd)

## Creating Access Keys

### Step 1: Create Access Key and Secret

The S3 layer uses your Manta your access keys and secret access key from your account.
To create the access key and secret, we need to use cloudapi.

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

## Troubleshooting


### Mahi is not picking up changes

Authcache must be rebuild to pickup the new structure for accesskeys 
https://github.com/TritonDataCenter/mahi/blob/master/docs/index.md


### Where is my bucket object stored? 
https://github.com/TritonDataCenter/manta/blob/master/docs/operator-guide/maintenance.md#pickerstorinfo-toggle

For manta-buckets-api there is /opt/smartdc/buckets-api/bin/mlocate 

```
[root@c7aaf162 (buckets-api) /opt/smartdc/buckets-api]$ ./bin/mlocate neirac/test5/sopa.txt  | json
{"name":"mlocate","hostname":"c7aaf162-6a9b-4873-b82e-19b8cb35490e","pid":26684,"component":"CueBallDNSResolver","domain":"nameservice.coal.joyent.us","level":30,"removed":["10.99.99.11"],"msg":"removed 1 resolvers from bootstrap","time":"2025-07-30T16:30:08.560Z","v":0}
{"name":"mlocate","hostname":"c7aaf162-6a9b-4873-b82e-19b8cb35490e","pid":26684,"component":"BucketsMdapiClient","domain":"buckets-mdplacement.coal.joyent.us","local":"10.77.77.22:44521","remote":"10.77.77.25:2021","key":"R4yi9i8ue6tXRAS1Z41aOM6BhFE=.1","level":30,"msg":"new connection","time":"2025-07-30T16:30:08.580Z","v":0}
{"name":"mlocate","hostname":"c7aaf162-6a9b-4873-b82e-19b8cb35490e","pid":26684,"component":"BucketsMdapiClient","domain":"1.buckets-mdapi.coal.joyent.us","local":"10.77.77.22:43654","remote":"10.77.77.26:2030","key":"YxCC9C7ibWSuMQh7MiERHMTSHB8=.1","level":30,"msg":"new connection","time":"2025-07-30T16:30:08.615Z","v":0}
{"name":"mlocate","hostname":"c7aaf162-6a9b-4873-b82e-19b8cb35490e","pid":26684,"component":"BucketsMdapiClient","domain":"1.buckets-mdapi.coal.joyent.us","local":"10.77.77.22:46025","remote":"10.77.77.26:2030","key":"YxCC9C7ibWSuMQh7MiERHMTSHB8=.1","level":30,"msg":"new connection","time":"2025-07-30T16:30:08.626Z","v":0}
{
  "bucket_id": "afc19bda-99de-461c-81f5-8b0633c88259",
  "content_length": 6,
  "content_md5": "R4EsbxCWGllPX3vFgGxy4Q==",
  "content_type": "text/plain",
  "created": "2025-07-30T16:15:14.559859Z",
  "headers": {
    "m-s3cmd-attrs": "atime:1753892103/ctime:1753892103/gid:0/gname:wheel/md5:47812c6f10961a594f5f7bc5806c72e1/mode:33188/mtime:1753892103/uid:501/uname:carlosneira"
  },
  "id": "56ccac05-c9c6-4e6b-8a8e-5daad7d4e44f",
  "modified": "2025-07-30T16:15:14.559859Z",
  "name": "sopa.txt",
  "owner": "c116efce-086f-455e-9ae4-26d49551428d",
  "properties": {},
  "sharks": [
    {
      "datacenter": "coal",
      "manta_storage_id": "1.stor.coal.joyent.us"
    },
    {
      "datacenter": "coal",
      "manta_storage_id": "3.stor.coal.joyent.us"
    }
  ],
  "_key": "c116efce-086f-455e-9ae4-26d49551428d:afc19bda-99de-461c-81f5-8b0633c88259:4116ddb8d538f4db68253ca6a6fb9bee",
  "_node": {
    "pnode": "tcp://1.buckets-mdapi.coal.joyent.us:2030",
    "vnode": 3,
    "data": 1
  },
  "_bucket_name": "test5",
  "_buckets_mdplacement": "buckets-mdplacement.coal.joyent.us"
}

```

The important part here is the _key_  and id , the file name that contains the data is a concatenation of id and the last element from _key_ (we split by  ':' ) . For example to obtain the file we just concatenate these values adding ',' between them: 
```
id : 56ccac05-c9c6-4e6b-8a8e-5daad7d4e44f
last element from key: 4116ddb8d538f4db68253ca6a6fb9bee

So the filename is called 
56ccac05-c9c6-4e6b-8a8e-5daad7d4e44f,4116ddb8d538f4db68253ca6a6fb9bee

```

The file is should be located in storage node 3, under directory
```
/manta/v2/<owneruuid>/<second element from _key>/<2 first bytes of id>/
```

For example 

```
[root@b948d68a (storage) /manta/v2/c116efce-086f-455e-9ae4-26d49551428d/afc19bda-99de-461c-81f5-8b0633c88259/56]$ ls -lrt
total 1
-rw-r--r-- 1 nobody nobody 6 Jul 30 16:15 56ccac05-c9c6-4e6b-8a8e-5daad7d4e44f,4116ddb8d538f4db68253ca6a6fb9bee
[root@b948d68a (storage) /manta/v2/c116efce-086f-455e-9ae4-26d49551428d/afc19bda-99de-461c-81f5-8b0633c88259/56]$ cat 56ccac05-c9c6-4e6b-8a8e-5daad7d4e44f,4116ddb8d538f4db68253ca6a6fb9bee
sopa1

```

## User Access Control for Buckets and Objects

This section explains how to create subusers and grant them specific access to buckets and objects using Manta's Role-Based Access Control (RBAC) system.

**⚠️ Important Note**: Role and policy changes take a few seconds to become effective. After creating or modifying roles and policies, wait 5-10 seconds before testing access.

### Creating Subusers with Bucket-Specific Access

#### Step 1: Create a Subuser

```bash
# Create a subuser for S3 access
sdc-user create --login s3qa --email s3qa@example.com --password temp-password

# Example response:
{
  "login": "s3qa",
  "uuid": "04a54897-82c0-4ab9-a77a-bbf800ff371a",
  "email": "s3qa@example.com"
}
```

#### Step 2: Generate Access Keys for the Subuser

```bash
# Generate S3 access keys for the subuser
cloudapi /your-account/users/s3qa/accesskeys -X POST

# Example response:
{
  "accesskeyid": "b6856fbd3d5a3645e1347931fe8e9226",
  "accesskeysecret": "77a041b549e8170fba994022c762a9e9e5be986454ef770d0f9e213082ecede4"
}
```

#### Step 3: Create Policies for Bucket Access

```bash
# Policy for reading objects from a specific bucket
sdc-policy create --name=bucket-reader --rules='CAN getbucket test-bucket' 'CAN getobject test-bucket/*'

# Policy for full access to a specific bucket
sdc-policy create --name=bucket-admin --rules='CAN getbucket test-bucket' 'CAN getobject test-bucket/*' 'CAN putobject test-bucket/*' 'CAN deleteobject test-bucket/*'

# Policy for read-only access to multiple buckets
sdc-policy create --name=multi-bucket-reader --rules='CAN getbucket dev-bucket' 'CAN getobject dev-bucket/*' 'CAN getbucket prod-bucket' 'CAN getobject prod-bucket/*'
```

#### Step 4: Create Roles and Assign to Subuser

**Critical for S3 clients**: Subusers must be in both `members` AND `default_members` arrays for S3 compatibility, as S3 clients cannot send role headers.

```bash
# Create role for bucket reading access
sdc-role create --name=storage-reader --members=s3qa --default_members=s3qa --policies=bucket-reader

# Create role for full bucket access
sdc-role create --name=storage-admin --members=s3qa --default_members=s3qa --policies=bucket-admin
```

### Common Access Patterns

#### Read-Only Access to Specific Bucket

```bash
# Create policy
sdc-policy create --name=readonly-mybucket --rules='CAN getbucket mybucket' 'CAN getobject mybucket/*'

# Create role with default activation
sdc-role create --name=mybucket-reader --members=s3qa --default_members=s3qa --policies=readonly-mybucket
```

#### Upload and Download Access to Specific Bucket

```bash
# Create policy
sdc-policy create --name=readwrite-uploads --rules='CAN getbucket uploads' 'CAN getobject uploads/*' 'CAN putobject uploads/*'

# Create role with default activation
sdc-role create --name=uploads-user --members=s3qa --default_members=s3qa --policies=readwrite-uploads
```

#### Multiple Bucket Access with Different Permissions

```bash
# Policy for development environment (full access)
sdc-policy create --name=dev-full-access --rules='CAN getbucket dev-*' 'CAN getobject dev-*/*' 'CAN putobject dev-*/*' 'CAN deleteobject dev-*/*'

# Policy for production environment (read-only)
sdc-policy create --name=prod-readonly --rules='CAN getbucket prod-*' 'CAN getobject prod-*/*'

# Combined role
sdc-role create --name=developer --members=s3qa --default_members=s3qa --policies=dev-full-access,prod-readonly
```

### Testing Subuser Access

#### Configure S3 Client with Subuser Credentials

```bash
# Configure AWS CLI with subuser credentials
aws configure set aws_access_key_id b6856fbd3d5a3645e1347931fe8e9226
aws configure set aws_secret_access_key 77a041b549e8170fba994022c762a9e9e5be986454ef770d0f9e213082ecede4

# Test access
aws s3 ls s3://test-bucket/ --endpoint-url https://your-manta-endpoint
aws s3 cp localfile.txt s3://test-bucket/ --endpoint-url https://your-manta-endpoint
```

#### Verify Permissions

```bash
# Should succeed (if user has getbucket permission)
aws s3 ls s3://test-bucket/ --endpoint-url https://your-manta-endpoint

# Should succeed (if user has getobject permission)  
aws s3 cp s3://test-bucket/file.txt downloaded.txt --endpoint-url https://your-manta-endpoint

# Should fail (if user lacks permission for different bucket)
aws s3 ls s3://other-bucket/ --endpoint-url https://your-manta-endpoint
```

### Troubleshooting Access Issues

#### Common Issues

1. **403 Forbidden Errors**
   - Verify user is in both `members` and `default_members` of role
   - Check that policy includes required permissions (`getbucket`, `getobject`, `putobject`)
   - Wait 5-10 seconds after role/policy changes

2. **Empty activeRoles**
   - User must be in `default_members` for automatic role activation
   - S3 clients cannot send Role headers, so default activation is required

3. **Bucket-scoped permissions not working**
   - Use bucket-scoped patterns: `bucketname/*` for objects
   - Ensure bucket name in policy matches exactly

#### Debugging Commands

```bash
# Check user's roles and permissions
sdc-user get s3qa

# List all roles for account
sdc-role list

# View specific role details
sdc-role get storage-reader

# Check policy rules
sdc-policy get bucket-reader
```

### Security Best Practices

1. **Principle of Least Privilege**: Grant minimum required permissions
2. **Bucket-Specific Access**: Use bucket-scoped permissions rather than wildcards
3. **Regular Audit**: Periodically review user permissions and active roles
4. **Access Key Rotation**: Regularly rotate subuser access keys
5. **Default Role Management**: Only add users to `default_members` when necessary for S3 compatibility

### Permission Reference

| Operation | Required Permission | Example |
|-----------|-------------------|---------|
| List bucket contents | `CAN getbucket bucket-name` | `CAN getbucket uploads` |
| Download objects | `CAN getobject bucket-name/*` | `CAN getobject uploads/*` |
| Upload objects | `CAN putobject bucket-name/*` | `CAN putobject uploads/*` |
| Delete objects | `CAN deleteobject bucket-name/*` | `CAN deleteobject uploads/*` |
| Bucket metadata | `CAN getbucket bucket-name` | `CAN getbucket uploads` |

**Note**: `getbucket` permission is required for both bucket listing and bucket metadata operations in S3 compatibility mode.

## Advanced Configuration

### Custom Role Management

If you need custom roles beyond the standard S3 ACLs, zlogin into the cloudapi
instance from the headnode and create the policy and role required.
For example here we create the required public-read role and read-public policy
used by the canned acl 'public-read'

```bash
# Create custom roles using Manta CLI
manta-create-role --name custom-readers --members user1,user2

[root@1d812d88-6e82-4b6d-8300-c7e5816f353a (us-central-a:cloudapi0) ~]#  sdc-policy create --name=read-public --rules='CAN getobject'
{
  "name": "read-public",
  "id": "48617132-dd3d-4a87-ab7d-1f125db1512f",
  "rules": [
    "CAN getobject"
  ]
}
[root@1d812d88-6e82-4b6d-8300-c7e5816f353a (us-central-a:cloudapi0) ~]# sdc-role create   --name=public-read        --policies=read-public
{
  "name": "public-read",
  "id": "cdc6c74c-9c75-4200-bfc8-fdbe9fd94a22",
  "members": [],
  "default_members": [],
  "policies": [
    "read-public"
  ]
}

# test the policy/role
aws s3 cp file.txt s3://bucket/ --acl=public-read --endpoint-url https://your-manta-endpoint
```
