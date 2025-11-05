# S3-Manta API Divergences

This document describes the differences between AWS S3 API and the Manta Buckets API implementation.

## Overview

Manta Buckets API provides S3-compatible storage functionality backed by Manta's object storage system. While maintaining compatibility with common S3 operations, there are several key differences due to architectural and design choices.

## Bucket Operations

| Operation | AWS S3 | Manta Buckets API | Status | Notes |
|-----------|--------|------------------|--------|-------|
| **LIST BUCKETS** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Full S3 XML response format |
| **CREATE BUCKET** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Creates bucket in Manta metadata |
| **DELETE BUCKET** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Requires bucket to be empty |
| **HEAD BUCKET** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Returns bucket existence/access |
| **GET BUCKET ACL** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Converts Manta roles to S3 ACL XML |
| **PUT BUCKET ACL** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Supports canned ACLs (public-read, etc.) |
| **GET BUCKET LOCATION** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | Manta doesn't have regions concept |
| **GET BUCKET VERSIONING** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | Manta doesn't support object versioning |
| **PUT BUCKET VERSIONING** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | Manta doesn't support object versioning |
| **GET BUCKET NOTIFICATION** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | No notification system |
| **PUT BUCKET NOTIFICATION** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | No notification system |
| **GET BUCKET LIFECYCLE** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | No lifecycle management |
| **PUT BUCKET LIFECYCLE** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | No lifecycle management |
| **GET BUCKET POLICY** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | Uses Manta roles instead |
| **PUT BUCKET POLICY** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | Uses Manta roles instead |
| **GET BUCKET CORS** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | CORS handled at HTTP level |
| **PUT BUCKET CORS** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | CORS handled at HTTP level |
| **GET BUCKET WEBSITE** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | No static website hosting |
| **PUT BUCKET WEBSITE** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | No static website hosting |
| **GET BUCKET LOGGING** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | Manta has built-in audit logging |
| **PUT BUCKET LOGGING** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | Manta has built-in audit logging |

## Object Operations

| Operation | AWS S3 | Manta Buckets API | Status | Notes |
|-----------|--------|------------------|--------|-------|
| **GET OBJECT** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Full object retrieval with conditional headers |
| **PUT OBJECT** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Supports aws-chunked encoding and metadata |
| **DELETE OBJECT** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Single object deletion |
| **DELETE OBJECTS** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Bulk delete with XML response |
| **HEAD OBJECT** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Object metadata without body |
| **LIST OBJECTS** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Both v1 and v2 API versions |
| **LIST OBJECTS V2** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Preferred S3 listing API |
| **GET OBJECT ACL** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Converts Manta roles to S3 ACL XML |
| **PUT OBJECT ACL** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Supports canned ACLs and role mapping |
| **COPY OBJECT** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Copy object between buckets |
| **GET OBJECT TORRENT** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | BitTorrent not supported |

## Presigned URL Operations

| Operation | AWS S3 | Manta Buckets API | Status | Notes |
|-----------|--------|------------------|--------|-------|
| **PRESIGNED GET URL** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Time-limited download URLs with AWS SigV4 |
| **PRESIGNED PUT URL** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Time-limited upload URLs with AWS SigV4 |
| **PRESIGNED POST** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | HTML form-based uploads not supported |
| **PRESIGNED DELETE URL** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | Presigned DELETE operations not supported |

### Presigned URL Implementation Details

**✅ Supported Features:**
- **AWS Signature Version 4** - Full SigV4 signature validation using Mahi
- **GET Operations** - Time-limited download URLs for object retrieval
- **PUT Operations** - Time-limited upload URLs for object creation
- **Configurable Expiry** - URLs expire after specified time period
- **Authentication Bypass** - Valid presigned URLs work without additional credentials
- **Security Validation** - Signature verification, expiry checking, and access control

**Usage Examples:**
```bash
# AWS CLI presigned URL generation (works with manta-buckets-api)
aws s3 presign s3://my-bucket/my-file.txt --expires-in 3600 --endpoint-url https://manta.example.com

# Boto3 presigned URL generation
import boto3
s3 = boto3.client('s3', endpoint_url='https://manta.example.com')
url = s3.generate_presigned_url('get_object', Params={'Bucket': 'my-bucket', 'Key': 'my-file.txt'}, ExpiresIn=3600)
```

**❌ Not Supported:**
- **Presigned POST** - HTML form-based uploads with policy documents
- **Presigned DELETE** - Time-limited deletion URLs  
- **Advanced Conditions** - Complex policy conditions beyond basic expiry
- **Custom Query Parameters** - Additional non-AWS query parameters in presigned URLs

## Multipart Upload Operations

| Operation | AWS S3 | Manta Buckets API | Status | Notes |
|-----------|--------|------------------|--------|-------|
| **INITIATE MULTIPART UPLOAD** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Creates upload session with durability tracking |
| **UPLOAD PART** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Streams parts to Mako storage nodes |
| **COMPLETE MULTIPART UPLOAD** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Uses Mako /mpu/v2/commit for assembly |
| **ABORT MULTIPART UPLOAD** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Cleans up partial upload state |
| **LIST PARTS** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Lists uploaded parts for an upload |
| **LIST MULTIPART UPLOADS** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | No cross-upload listing |
| **UPLOAD PART COPY** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | No server-side copy functionality |

## Key Architectural Differences

### Authentication & Authorization
- **S3**: Uses AWS IAM policies and Access Control Lists
- **Manta**: Uses Manta roles and RBAC system
- **Impact**: ACL operations translate between S3 canned ACLs and Manta roles

### Storage Architecture
- **S3**: Object versioning, storage classes, lifecycle policies
- **Manta**: Single version objects with durability levels (replica count)
- **Impact**: No versioning or storage class management

### Metadata Handling
- **S3**: Uses `x-amz-meta-*` headers for user metadata
- **Manta**: Uses `m-*` headers, automatically translated for S3 clients
- **Impact**: Transparent metadata conversion for S3 compatibility

### Durability & Replication
- **S3**: Regional replication with storage classes
- **Manta**: Configurable replica count per object (durability-level)
- **Impact**: Durability specified as number of copies rather than storage class

### Multipart Uploads
- **S3**: Native multipart upload support in storage layer
- **Manta**: Implemented using Mako's `/mpu/v2/commit` assembly process
- **Impact**: Parts must be uploaded to consistent set of storage nodes for assembly

### Regional Concepts
- **S3**: Buckets exist in specific regions
- **Manta**: No region concept, single deployment
- **Impact**: Region-related operations not applicable

## Compatibility Matrix

### High Compatibility ✅
- Basic CRUD operations (GET, PUT, DELETE, HEAD)
- Multipart uploads for large objects
- **Presigned URLs for GET and PUT operations**
- ACL management with role translation
- Conditional headers and ETags
- Standard S3 error responses

### Partial Compatibility ⚠️
- Metadata headers (automatically translated)
- Durability via replica count vs storage classes
- Authentication (uses Manta roles vs IAM)

### Not Supported ❌
- Object versioning
- Lifecycle management
- Cross-region replication
- Static website hosting
- BitTorrent distribution
- Notification services
- Server-side copy operations
- Bucket policies (use Manta roles)

## Migration Considerations

When migrating from AWS S3 or implementing S3-compatible applications:

1. **No Object Versioning**: Applications relying on S3 versioning must implement their own versioning logic
2. **Durability Levels**: Use `durability-level` header instead of storage classes
3. **Role Mapping**: Understand how S3 ACLs map to Manta roles
4. **Metadata Translation**: User metadata automatically converted between `x-amz-meta-*` and `m-*` formats
5. **Strong Consistency**: Can rely on immediate consistency for all operations
6. **No Regional Concepts**: All buckets exist in the same Manta deployment


## STS IAM Operations

| Operation | AWS S3 | Manta Buckets API | Status | Notes |
|-----------|--------|------------------|--------|-------|
| **STS OPERATIONS** | | | | |
| **ASSUME ROLE** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Full trust policy validation with conditions |
| **GET SESSION TOKEN** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | Use AssumeRole for temporary credentials |
| **GET CALLER IDENTITY** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Returns user/role identity information |
| **DECODE AUTHORIZATION MESSAGE** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | No authorization message encoding |
| **IAM ROLE MANAGEMENT** | | | | |
| **CREATE ROLE** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Creates role with trust policy |
| **DELETE ROLE** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Removes role and associated policies |
| **GET ROLE** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Returns role metadata (excludes policies) |
| **LIST ROLES** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Lists all roles in account |
| **UPDATE ROLE** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | No role description/policy updates |
| **IAM POLICY MANAGEMENT** | | | | |
| **PUT ROLE POLICY** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Attaches inline policy to role |
| **DELETE ROLE POLICY** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Removes inline policy from role |
| **GET ROLE POLICY** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Retrieves specific policy document |
| **LIST ROLE POLICIES** | ✅ Supported | ✅ Supported | **IMPLEMENTED** | Lists policy names attached to role |
| **ATTACH ROLE POLICY** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | Only inline policies supported |
| **DETACH ROLE POLICY** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | Only inline policies supported |
| **LIST ATTACHED ROLE POLICIES** | ✅ Supported | ❌ Not Implemented | **NOT IMPLEMENTED** | Only inline policies supported |

### STS IAM Implementation Details

**✅ Fully Supported Features:**
- **Trust Policy Validation** - Complete condition evaluation engine
- **Principal Matching** - User, role, root, and wildcard principals  
- **Condition Operators** - StringEquals, DateGreaterThan, IpAddress, Bool, etc.
- **External ID Support** - Secure cross-account-style access patterns
- **Time-Based Access** - Business hours restrictions and time windows
- **IP Address Restrictions** - Network-based access control
- **Role Chaining** - Roles can assume other roles
- **JWT Session Tokens** - HMAC-SHA256 signed tokens with key rotation
- **Multi-Cloud ARNs** - Support for aws/manta/triton ARN prefixes
- **Permission Policy Evaluation** - Action/Resource matching for S3 operations

**⚠️ Partial Support:**
- **Trust Policies Only** - Conditions only work in trust policies, not permission policies
- **S3 Actions Only** - Permission policies limited to S3 actions
- **Single Account Model** - No cross-account access (inherent Manta limitation)

**❌ Not Supported:**
- **Managed Policies** - Only inline policies supported
- **Service Principals** - Not applicable to Manta architecture
- **SAML/OIDC Federation** - No federated identity support
- **Policy Conditions in Permissions** - Conditions only work in trust policies
- **S3 Condition Keys** - No s3:prefix, s3:max-keys, etc. support
- **User Management** - No IAM user CRUD operations (use Manta users)
- **Group Management** - No IAM groups (use Manta roles)

**Session Token Security Features:**
- **JWT with HMAC-SHA256** - Cryptographically signed, tamper-proof tokens
- **Key Rotation Support** - Seamless secret rotation with keyId tracking
- **Auto-Expiration** - Default 1-hour expiration (configurable up to 12 hours)
- **Standard JWT Claims** - iss, aud, iat, exp, nbf for comprehensive validation
- **Version Support** - Token versioning for backward compatibility

### Trust Policy Migration

**AWS Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {"sts:ExternalId": "secret-key"},
      "IpAddress": {"aws:SourceIp": "192.168.1.0/24"}
    }
  }]
}
```

**Manta Trust Policy (Direct Migration):**
```json
{
  "Version": "2012-10-17", 
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:manta:iam::123456789012:user/alice"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {"sts:ExternalId": "secret-key"},
      "IpAddress": {"aws:SourceIp": "192.168.1.0/24"}  
    }
  }]
}
```

**Key Changes for Migration:**
1. **ARN Prefix**: Change `arn:aws:` to `arn:manta:` (or keep aws for compatibility)
2. **Remove Cross-Account**: Remove references to other AWS accounts
3. **Remove Service Principals**: Replace with user principals
4. **Keep All Conditions**: Trust policy conditions work identically

### Permission Policy Migration

**AWS Permission Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow", 
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::bucket/*"],
    "Condition": {
      "StringLike": {"s3:prefix": "user-data/*"}
    }
  }]
}
```

**Manta Permission Policy (Adapted):**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:*", 
    "Resource": ["arn:manta:s3:::bucket/user-data/*"]
  }]
}
```

**Key Changes for Migration:**
1. **ARN Prefix**: Change `arn:aws:s3:` to `arn:manta:s3:`
2. **Remove Conditions**: Move condition logic into Resource ARN patterns
3. **Specific Resources**: Use explicit resource paths instead of condition keys
4. **S3 Actions Only**: Only S3 actions supported in permission policies

## AWS SDK Compatibility

While Manta Buckets API maintains high compatibility with standard S3 operations, certain SDK-specific behaviors require adjustments for optimal functionality.

### Supported S3 Operations by SDK

| S3 Operation | Python boto3 | PHP AWS SDK v3 | Notes |
|--------------|---------------|-----------------|-------|
| **Basic Operations** |  |  |  |
| `list_buckets()` / `listBuckets()` | ✅ Supported | ✅ Supported | Full compatibility |
| `create_bucket()` / `createBucket()` | ✅ Supported | ✅ Supported | Full compatibility |
| `delete_bucket()` / `deleteBucket()` | ✅ Supported | ✅ Supported | Must be empty |
| `head_bucket()` / `headBucket()` | ✅ Supported | ✅ Supported | Full compatibility |
| **Object Operations** |  |  |  |
| `put_object()` / `putObject()` | ✅ Supported | ✅ Supported | Full compatibility |
| `get_object()` / `getObject()` | ✅ Supported | ✅ Supported | Full compatibility |
| `head_object()` / `headObject()` | ✅ Supported | ✅ Supported | Full compatibility |
| `delete_object()` / `deleteObject()` | ✅ Supported | ✅ Supported | Full compatibility |
| `delete_objects()` / `deleteObjects()` | ✅ Supported | ✅ Supported | Bulk delete with XML |
| `copy_object()` / `copyObject()` | ✅ Supported | ✅ Supported | Server-side copy |
| **Listing Operations** |  |  |  |
| `list_objects()` / `listObjects()` | ✅ Supported | ✅ Supported | V1 API |
| `list_objects_v2()` / `listObjectsV2()` | ✅ Supported | ✅ Supported | V2 API with pagination |
| **Multipart Upload** |  |  |  |
| `create_multipart_upload()` / `createMultipartUpload()` | ✅ Supported | ✅ Supported | Initialize MPU |
| `upload_part()` / `uploadPart()` | ✅ Supported | ✅ Supported | Upload individual parts |
| `complete_multipart_upload()` / `completeMultipartUpload()` | ✅ Supported | ⚠️ ETag issues | Use server ETags from listParts |
| `abort_multipart_upload()` / `abortMultipartUpload()` | ✅ Supported | ✅ Supported | Cleanup partial uploads |
| `list_parts()` / `listParts()` | ✅ Supported | ✅ Supported | List uploaded parts |
| `upload_file()` | ✅ Supported | N/A | High-level API |
| `putObject()` with `@multipart_upload_threshold` | N/A | ✅ Supported | High-level API |
| **Presigned URLs** |  |  |  |
| `generate_presigned_url()` | ✅ Supported | N/A | Works seamlessly |
| `createPresignedRequest()` | N/A | ❌ Signature issues | Use manual implementation |
| **ACL Operations** |  |  |  |
| `get_bucket_acl()` / `getBucketAcl()` | ✅ Supported | ✅ Supported | Maps to Manta roles |
| `put_bucket_acl()` / `putBucketAcl()` | ✅ Supported | ✅ Supported | Canned ACLs supported |
| `get_object_acl()` / `getObjectAcl()` | ✅ Supported | ✅ Supported | Maps to Manta roles |
| `put_object_acl()` / `putObjectAcl()` | ✅ Supported | ✅ Supported | Canned ACLs supported |
| **Unsupported Operations** |  |  |  |
| `list_multipart_uploads()` / `listMultipartUploads()` | ❌ Not Implemented | ❌ Not Implemented | No cross-upload listing |
| `upload_part_copy()` / `uploadPartCopy()` | ❌ Not Implemented | ❌ Not Implemented | No server-side copy for parts |
| `get_bucket_versioning()` / `getBucketVersioning()` | ❌ Not Implemented | ❌ Not Implemented | No versioning support |
| `put_bucket_versioning()` / `putBucketVersioning()` | ❌ Not Implemented | ❌ Not Implemented | No versioning support |
| `get_bucket_location()` / `getBucketLocation()` | ❌ Not Implemented | ❌ Not Implemented | No region concept |
| `get_bucket_policy()` / `getBucketPolicy()` | ❌ Not Implemented | ❌ Not Implemented | Use Manta roles |
| `put_bucket_policy()` / `putBucketPolicy()` | ❌ Not Implemented | ❌ Not Implemented | Use Manta roles |
| `get_bucket_lifecycle()` / `getBucketLifecycle()` | ❌ Not Implemented | ❌ Not Implemented | No lifecycle management |
| `put_bucket_lifecycle()` / `putBucketLifecycle()` | ❌ Not Implemented | ❌ Not Implemented | No lifecycle management |
| `get_bucket_cors()` / `getBucketCors()` | ❌ Not Implemented | ❌ Not Implemented | CORS at HTTP level |
| `put_bucket_cors()` / `putBucketCors()` | ❌ Not Implemented | ❌ Not Implemented | CORS at HTTP level |
| `get_bucket_notification()` / `getBucketNotification()` | ❌ Not Implemented | ❌ Not Implemented | No notification system |
| `put_bucket_notification()` / `putBucketNotification()` | ❌ Not Implemented | ❌ Not Implemented | No notification system |

**Legend:**
- ✅ **Supported**: Full compatibility, works as expected
- ⚠️ **Partial**: Works with limitations or workarounds needed  
- ❌ **Not Implemented**: Operation not supported by Manta Buckets API
- **N/A**: SDK doesn't provide this specific method

## Error Handling

Manta Buckets API returns S3-compatible error responses with proper HTTP status codes and XML error bodies. Common S3 client libraries should work without modification for supported operations.
