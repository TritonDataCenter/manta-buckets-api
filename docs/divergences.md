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


## Error Handling

Manta Buckets API returns S3-compatible error responses with proper HTTP status codes and XML error bodies. Common S3 client libraries should work without modification for supported operations.
