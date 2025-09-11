# S3-to-Manta Architecture

This document explains how S3 requests are processed and translated to Manta operations in the manta-buckets-api.

## Overview

The manta-buckets-api serves as a bridge between S3 clients and Manta storage, translating S3 API calls into equivalent Manta bucket operations. The system handles authentication, request routing, header translation, and response formatting to provide S3 compatibility.

## High-Level Architecture

```mermaid
graph TB
    S3Client[S3 Client<br/>aws-cli, s3cmd, boto3] --> API[manta-buckets-api]
    API --> Auth[Authentication<br/>Mahi]
    API --> Routes[S3 Route Handlers<br/>s3-routes.js]
    Routes --> Compat[S3 Compatibility<br/>s3-compat.js]
    Routes --> Buckets[Manta Buckets<br/>buckets/]
    Buckets --> Storage[Manta Storage<br/>Sharks/Metadata]
    
    Auth --> Mahi[(Mahi<br/>Auth Service)]
    Storage --> Sharks[(Shark Nodes<br/>Object Storage)]
    Storage --> Metadata[(Metadata API<br/>Bucket/Object Metadata)]
```

## Request Processing Flow

### 1. S3 Request Lifecycle

```mermaid
sequenceDiagram
    participant Client as S3 Client
    participant API as manta-buckets-api
    participant Auth as Authentication
    participant S3Routes as S3 Route Handler
    participant S3Compat as S3 Compatibility
    participant Buckets as Manta Buckets
    participant Storage as Manta Storage
    
    Client->>API: HTTP Request (S3 API)
    API->>Auth: Authenticate request
    Auth-->>API: Authentication context
    API->>S3Routes: Route to S3 handler
    S3Routes->>S3Routes: Parse S3 parameters
    S3Routes->>S3Compat: Translate S3 headers/ACLs
    S3Compat-->>S3Routes: Manta-compatible headers
    S3Routes->>Buckets: Execute Manta operation
    Buckets->>Storage: Store/retrieve data
    Storage-->>Buckets: Operation result
    Buckets-->>S3Routes: Manta response
    S3Routes->>S3Routes: Format S3 response
    S3Routes-->>API: S3-compatible response
    API-->>Client: HTTP Response (S3 format)
```

### 2. Detailed Request Processing Steps

#### Step 1: Request Routing
- Incoming HTTP requests are routed based on method and path
- S3-specific routes are handled by functions in `s3-routes.js`
- Each S3 operation has a dedicated handler function

#### Step 2: Parameter Translation
S3 parameters are converted to Manta format:
```javascript
// S3 format
req.params.bucket -> req.params.bucket_name
req.params['*'] -> req.params.object_name
req.caller.account.login -> req.params.account
```

#### Step 3: Header Translation
S3 headers are translated to Manta equivalents:
- `x-amz-acl` → `role-tag` (via s3RoleTranslator)
- `x-amz-meta-*` → `m-*` (metadata headers)

#### Step 4: Middleware Chain Execution
Each operation executes a chain of middleware functions:

```mermaid
graph LR
    Load[loadRequest] --> Auth[authorizationHandler]
    Auth --> Validate[validateHandler]
    Validate --> Execute[executeHandler]
    Execute --> Success[successHandler]
```

## Component Details

### S3 Route Handlers (`s3-routes.js`)

The main S3 route handlers include:

#### Bucket Operations
- `s3ListBucketsHandler()` - List all buckets
- `s3CreateBucketHandler()` - Create bucket
- `s3HeadBucketHandler()` - Get bucket metadata  
- `s3DeleteBucketHandler()` - Delete bucket
- `s3ListBucketObjectsHandler()` - List objects in bucket
- `s3ListBucketObjectsV2Handler()` - List objects (API v2)

#### Object Operations
- `s3CreateBucketObjectHandler()` - Upload object
- `s3GetBucketObjectHandler()` - Download object
- `s3HeadBucketObjectHandler()` - Get object metadata
- `s3DeleteBucketObjectHandler()` - Delete object
- `s3DeleteBucketObjectsHandler()` - Bulk delete objects

#### ACL Operations
- `s3SetBucketACLHandler()` - Set bucket ACL
- `s3GetBucketACLHandler()` - Get bucket ACL
- `s3SetObjectACLHandler()` - Set object ACL
- `s3GetObjectACLHandler()` - Get object ACL

### S3 Compatibility Layer (`s3-compat.js`)

Handles translation between S3 and Manta concepts:

#### Role Translation
```mermaid
graph TB
    S3ACL[S3 ACL Headers<br/>x-amz-acl] --> Translator[s3RoleTranslator]
    Translator --> MantaRoles[Manta Role Tags<br/>role-tag]
    
    subgraph "Supported ACLs"
        Private[private]
        PublicRead[public-read] 
        PublicWrite[public-read-write]
        AuthRead[authenticated-read]
    end
    
    Private --> EmptyRoles["[]"]
    PublicRead --> PublicReadRole["['public-read']"]
    PublicWrite --> PublicWriteRoles["['public-read', 'public-writer']"]
    AuthRead --> AuthRoles["['authenticated-reader']"]
```

#### Metadata Translation
- S3 `x-amz-meta-*` headers ↔ Manta `m-*` headers
- Content-Type preservation
- ETag generation

### ACL Processing Flow

```mermaid
sequenceDiagram
    participant Client as S3 Client
    participant Handler as S3 Handler
    participant Parser as ACL Parser
    participant Translator as Role Translator
    participant Mahi as Mahi Service
    participant Storage as Metadata Storage
    
    Client->>Handler: Request with x-amz-acl header
    Handler->>Parser: parseS3ACLFromXML()
    Parser->>Parser: Extract ACL from XML/headers
    Parser-->>Handler: Parsed ACL (e.g., "public-read")
    
    Handler->>Translator: s3RoleTranslator()
    Translator->>Translator: Convert S3 ACL to role names
    Translator-->>Handler: role-tag header set
    
    Handler->>Handler: updateObjectRoles()
    Handler->>Handler: Separate system vs user roles
    
    alt User-defined roles exist
        Handler->>Mahi: getUuid() for role names
        Mahi-->>Handler: Role UUIDs
    end
    
    Handler->>Storage: updateObject() with roles
    Storage-->>Handler: Success
    Handler-->>Client: 200 OK
```

## Data Flow Examples

### Example 1: S3 Object Upload with Public Read ACL

```mermaid
sequenceDiagram
    participant AWS as aws s3 cp
    participant API as manta-buckets-api
    participant S3Handler as s3CreateBucketObjectHandler
    participant S3Compat as s3RoleTranslator
    participant Buckets as Manta Buckets
    
    AWS->>API: PUT /bucket/object<br/>x-amz-acl: public-read
    API->>S3Handler: Route request
    
    S3Handler->>S3Handler: Extract bucket/object names
    S3Handler->>S3Handler: Set req.isS3Request = true
    S3Handler->>S3Handler: Convert to Manta params
    
    S3Handler->>S3Compat: s3RoleTranslator(req, res, callback)
    S3Compat->>S3Compat: x-amz-acl: "public-read"<br/>→ role-tag: "public-read"
    S3Compat-->>S3Handler: Headers translated
    
    S3Handler->>Buckets: executeMiddlewareChain(createBucketObjectHandler)
    Buckets->>Buckets: Store object with roles: ["public-read"]
    Buckets-->>S3Handler: Object stored
    
    S3Handler-->>API: Success
    API-->>AWS: 200 OK
```

### Example 2: S3 Bulk Delete Objects

```mermaid
sequenceDiagram
    participant Client as S3 Client
    participant API as manta-buckets-api
    participant Handler as s3DeleteBucketObjectsHandler
    participant Parser as XML Parser
    participant Buckets as bucketHelpers
    participant Storage as Manta Storage
    
    Client->>API: POST /bucket?delete<br/>XML body with object list
    API->>Handler: Route to bulk delete
    
    Handler->>Parser: Parse XML body
    Parser->>Parser: Extract <Key>object1</Key><br/><Key>object2</Key>
    Parser-->>Handler: objectKeys array
    
    loop For each object
        Handler->>Buckets: loadRequest(deleteReq)
        Buckets-->>Handler: Object metadata
        Handler->>Buckets: getBucketIfExists(deleteReq)
        Buckets-->>Handler: Bucket context
        Handler->>Storage: deleteObject()
        
        alt Object found
            Storage-->>Handler: Deleted successfully
            Handler->>Handler: Add to deleted array
        else Object not found
            Handler->>Handler: Try URL-encoded version
            alt Encoded version found
                Storage-->>Handler: Deleted successfully
                Handler->>Handler: Add to deleted array
            else Still not found
                Handler->>Handler: Add to errors array
            end
        end
    end
    
    Handler->>Handler: Generate XML response
    Handler-->>API: XML with deleted/error results
    API-->>Client: 200 OK + XML response
```

## Error Handling

### Authentication Errors
- Missing or invalid authentication → 401 Unauthorized
- Insufficient permissions → 403 Forbidden

### S3-specific Error Handling
- Invalid bucket names → InvalidBucketName error
- Object not found → NoSuchKey error (with encoding fallbacks)
- Bucket already exists → BucketAlreadyExists (handled specially for ACL updates)

### Error Response Format
Errors are converted to S3-compatible XML format:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <RequestId>...</RequestId>
</Error>
```

## Key Features

### 1. Header Translation
- Bidirectional conversion between S3 and Manta headers
- Metadata preservation and format conversion
- Content-Type handling

### 2. ACL System Integration
- S3 canned ACLs mapped to Manta roles
- Support for both system and user-defined roles
- XML ACL parsing for complex permissions

### 3. Encoding Handling
- Multiple encoding attempts for object keys
- URL encoding/decoding for special characters
- Space and parentheses handling

### 4. Response Formatting
- XML response generation for S3 compatibility
- Proper HTTP status codes
- S3-compatible error messages
