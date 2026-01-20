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

#### CORS Operations
- `s3GetBucketCorsHandler()` - Get bucket CORS configuration
- `s3PutBucketCorsHandler()` - Set bucket CORS configuration
- `s3DeleteBucketCorsHandler()` - Delete bucket CORS configuration

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
    end
    
    Private --> EmptyRoles["[]"]
    PublicRead --> PublicReadRole["['public-read']"]
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

## CORS (Cross-Origin Resource Sharing) Architecture

The manta-buckets-api implements comprehensive CORS support to enable web browsers to make cross-origin requests to Manta storage. This is essential for web applications that need to upload or download files directly from browsers without going through backend proxies.

### CORS Architecture Overview

```mermaid
graph TB
    Browser[Web Browser] --> CORS[CORS Middleware]
    CORS --> Preflight{OPTIONS Request?}
    Preflight -->|Yes| PreflightHandler[Handle Preflight]
    Preflight -->|No| RequestProcessor[Process Regular Request]
    
    PreflightHandler --> BucketCORS[Get Bucket CORS Config]
    RequestProcessor --> BucketCORS
    BucketCORS --> ObjectCORS[Check Object CORS Headers]
    ObjectCORS --> Validation[Validate Origin/Method/Headers]
    Validation --> Response[Add CORS Response Headers]
    
    subgraph "CORS Configuration Sources"
        BucketLevel[Bucket-Level CORS<br/>.cors-configuration metadata]
        ObjectLevel[Object-Level CORS<br/>m-access-control-* headers]
    end
    
    BucketCORS --> BucketLevel
    ObjectCORS --> ObjectLevel
```

### CORS Request Processing Flow

#### 1. Preflight Request Processing (OPTIONS)

```mermaid
sequenceDiagram
    participant Browser as Web Browser
    participant API as manta-buckets-api
    participant CORS as CORS Middleware
    participant Bucket as Bucket Storage
    participant Object as Object Metadata
    
    Browser->>API: OPTIONS /bucket/object<br/>Origin: https://app.example.com<br/>Access-Control-Request-Method: PUT
    API->>CORS: handleCorsOptions()
    CORS->>Bucket: Get bucket CORS configuration
    Bucket-->>CORS: CORS rules (if any)
    CORS->>Object: Check object CORS headers
    Object-->>CORS: Object CORS metadata (if any)
    CORS->>CORS: Validate origin against rules
    CORS->>CORS: Check allowed methods
    CORS->>CORS: Validate requested headers
    CORS-->>API: CORS response headers
    API-->>Browser: 200 OK<br/>Access-Control-Allow-Origin: https://app.example.com<br/>Access-Control-Allow-Methods: PUT<br/>Access-Control-Allow-Headers: Content-Type
```

#### 2. Actual Request Processing (GET/PUT/DELETE)

```mermaid
sequenceDiagram
    participant Browser as Web Browser
    participant API as manta-buckets-api
    participant CORS as CORS Middleware
    participant S3Routes as S3 Route Handler
    participant Storage as Manta Storage
    
    Browser->>API: PUT /bucket/object<br/>Origin: https://app.example.com<br/>Content-Type: image/jpeg
    API->>CORS: addCustomHeaders()
    CORS->>CORS: Validate origin and method
    CORS-->>API: Add CORS response headers
    API->>S3Routes: Process S3 request
    S3Routes->>Storage: Store object with metadata
    Storage-->>S3Routes: Object stored successfully
    S3Routes-->>API: Success response
    API-->>Browser: 200 OK<br/>Access-Control-Allow-Origin: https://app.example.com<br/>ETag: "abc123"
```

### CORS Configuration Storage

#### Bucket-Level CORS Configuration
Bucket CORS rules are stored as metadata objects with empty sharks arrays:

```javascript
// Bucket CORS configuration object
{
    sharks: [],  // Empty - metadata only
    headers: {
        'cors-configuration': JSON.stringify({
            CORSRules: [
                {
                    ID: 'rule1',
                    AllowedOrigins: ['https://app.example.com'],
                    AllowedMethods: ['GET', 'PUT'],
                    AllowedHeaders: ['Content-Type'],
                    ExposeHeaders: ['ETag'],
                    MaxAgeSeconds: 3600
                }
            ]
        })
    }
}
```

#### Object-Level CORS Headers
Individual objects can have CORS metadata that overrides bucket-level configuration:

```javascript
// Object metadata headers
{
    'm-access-control-allow-origin': 'https://specific.example.com',
    'm-access-control-allow-methods': 'GET,HEAD',
    'm-access-control-expose-headers': 'ETag,Last-Modified',
    'm-access-control-max-age': '7200'
}
```

### CORS Integration Points

#### 1. Server Middleware Chain
CORS is integrated into the main server middleware chain:

```javascript
// In server.js
app.use(corsMiddleware.handleCorsOptions);      // Handle OPTIONS requests
app.use(corsMiddleware.addCustomHeaders);       // Add CORS headers to responses
```

#### 2. S3 Route Integration
S3 routes automatically include CORS processing:

```javascript
// In s3-routes.js
function s3CreateBucketObjectHandler() {
    return [
        buckets.loadRequest,
        corsMiddleware.addCustomHeaders,  // CORS headers added here
        buckets.authorizationHandler,
        // ... other middleware
    ];
}
```

### Presigned URL CORS Support

The CORS implementation fully supports presigned URL uploads from browsers:

#### Browser Upload Flow with Presigned URLs

```javascript
// 1. Backend generates presigned URL
const presignedUrl = await s3.getSignedUrl('putObject', {
    Bucket: 'uploads',
    Key: 'photo.jpg',
    Expires: 3600,
    ContentType: 'image/jpeg'
});

// 2. Browser uploads directly to Manta
const response = await fetch(presignedUrl, {
    method: 'PUT',
    mode: 'cors',  // Enable CORS
    body: fileInput.files[0],
    headers: {
        'Content-Type': 'image/jpeg'
    }
});

// 3. CORS middleware processes request
// - Handles missing Origin header (presigned URLs)
// - Applies bucket or object-level CORS rules
// - Returns proper Access-Control-* headers
```

#### Presigned URL CORS Handling

```mermaid
sequenceDiagram
    participant Browser as Web Browser
    participant Backend as Application Backend
    participant API as manta-buckets-api
    participant Storage as Manta Storage
    
    Browser->>Backend: Request upload URL
    Backend->>Backend: Generate presigned URL
    Backend-->>Browser: Presigned PUT URL
    
    Browser->>API: PUT presigned-url<br/>Origin: null (or missing)<br/>Body: file data
    API->>API: Detect presigned URL request
    API->>API: Apply CORS rules (origin-agnostic)
    API->>Storage: Store object
    Storage-->>API: Success
    API-->>Browser: 200 OK<br/>Access-Control-Allow-Origin: *<br/>(or specific origin if configured)
```

### CORS Security Model

#### Origin Validation
- **Wildcard Support**: Both `*` and `star` formats supported for compatibility
- **Exact Match**: Specific origins matched exactly (case-sensitive)
- **Protocol Enforcement**: Origins must include protocol (https://)
- **Port Handling**: Origins with ports are matched including port number

#### Method Validation
- **Preflight Methods**: OPTIONS requests validate Access-Control-Request-Method
- **Actual Methods**: Regular requests validate HTTP method against allowed methods
- **Default Methods**: GET and HEAD typically allowed by default

#### Header Validation
- **Simple Headers**: Content-Type, Accept, etc. typically allowed
- **Custom Headers**: Must be explicitly listed in AllowedHeaders
- **Response Headers**: ExposeHeaders controls which response headers browsers can access

### AWS S3 Compatibility

The CORS implementation provides full compatibility with AWS S3 CORS API:

| AWS S3 Feature | Manta Implementation | Status |
|----------------|---------------------|---------|
| PutBucketCors | s3PutBucketCorsHandler | ✅ Implemented |
| GetBucketCors | s3GetBucketCorsHandler | ✅ Implemented |
| DeleteBucketCors | s3DeleteBucketCorsHandler | ✅ Implemented |
| CORSRule.ID | Unique rule identifier | ✅ Implemented |
| AllowedOrigins | Origin whitelist | ✅ Implemented |
| AllowedMethods | HTTP method whitelist | ✅ Implemented |
| AllowedHeaders | Request header whitelist | ✅ Implemented |
| ExposeHeaders | Response header exposure | ✅ Implemented |
| MaxAgeSeconds | Preflight cache duration | ✅ Implemented |

### Manta-Specific CORS Extensions

Beyond AWS S3 compatibility, Manta provides additional CORS features:

#### Object-Level CORS Override
Objects can specify individual CORS policies that take precedence over bucket settings:

```bash
# Set object-specific CORS during upload
mput -H 'm-access-control-allow-origin: https://myapp.com' \
     -H 'm-access-control-allow-methods: GET' \
     photo.jpg ~~/uploads/photo.jpg
```

#### Enhanced Wildcard Support
Supports both AWS standard (`*`) and legacy (`star`) wildcard formats:

```xml
<CORSRule>
    <AllowedOrigin>*</AllowedOrigin>          <!-- AWS standard -->
    <AllowedOrigin>star</AllowedOrigin>       <!-- Legacy support -->
</CORSRule>
```

#### Flexible Origin Matching
- Case-insensitive domain matching
- Automatic protocol inference for local development
- Support for `origin: null` (file:// and data: URLs)

This CORS architecture enables seamless browser integration while maintaining security and AWS S3 compatibility, making it ideal for modern web applications that need direct browser-to-storage file operations.

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

Only S3 Path-style addressing is supported:

- **Path-style**: `https://domain.com/bucket/object`
- **Virtual-hosted**: `https://bucket.domain.com/object`

The system automatically detects the addressing style based on the Host header and request path,
but currently virtual-hosted style is disabled.

### Response Format Translation

#### Bucket Listings
Manta's JSON streaming format is converted to S3's XML format:
```xml
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
    <ID>account-uuid</ID>
    <DisplayName>account-login</DisplayName>
  </Owner>
  <Buckets>
    <Bucket>
      <Name>bucket-name</Name>
      <CreationDate>2023-01-01T00:00:00.000Z</CreationDate>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>
```

#### Object Listings
Object lists are converted to S3 XML format with support for both v1 and v2 APIs:
```xml
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket-name</Name>
  <KeyCount>1</KeyCount>
  <Contents>
    <Key>object-key</Key>
    <LastModified>2023-01-01T00:00:00.000Z</LastModified>
    <ETag>"etag-value"</ETag>
    <Size>1024</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
</ListBucketResult>
```

#### Error Responses
Manta errors are translated to S3 XML error format:
```xml
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist.</Message>
  <RequestId>request-id</RequestId>
</Error>
```

### Header Translation

- **Metadata headers**: `m-*` → `x-amz-meta-*`
- **Standard headers**: `content-type`, `content-length`, `etag`, `last-modified` are preserved
- **S3-specific headers**: `x-amz-request-id`, `x-amz-id-2` are added automatically

### Authentication

S3 compatibility requires AWS Signature Version 4 (SigV4) authentication. Traditional Manta authentication methods are not supported for S3 endpoints.

#### AWS Signature Version 4 (SigV4) Authentication

The Manta Buckets API implements full AWS SigV4 authentication compatibility through integration with the Mahi authentication service. This enables standard AWS tools and SDKs to authenticate seamlessly with Manta's bucket storage.

##### SigV4 Authentication Flow

```mermaid
graph TD
    A[S3 Client Request with SigV4 Headers] --> B[Authentication Middleware]
    B --> C{Authorization Header Check}
    C -->|AWS4-HMAC-SHA256| D[SigV4 Handler]
    C -->|Other| E[Traditional Manta Auth]
    
    D --> F[Parse SigV4 Headers]
    F --> G[Extract Authorization Components]
    G --> H{Required Headers Present?}
    
    H -->|Missing| I[Return 400 Bad Request]
    H -->|Present| J[Prepare Request for Verification]
    
    J --> K[Filter Problematic Headers]
    K --> L[Handle URL Encoding]
    L --> M[Call Mahi SigV4 Verification]
    
    M --> N[Mahi /aws-verify Endpoint]
    N --> O[Access Key Lookup]
    O --> P[Signature Calculation]
    P --> Q[Signature Comparison]
    
    Q -->|Invalid| R[Return 403 Forbidden]
    Q -->|Valid| S[Return User Context]
    
    S --> T[Set Authentication Context]
    T --> U[Load User Account Information]
    U --> V[Set req.caller with Account Details]
    V --> W[Continue to S3 Handler]
    
    R --> X[Map to S3 Error Format]
    I --> X
    X --> Y[Send S3 XML Error Response]
    
    classDef clientNode fill:#F8FBFF,stroke:#90CAF9,stroke-width:1px,color:#1565C0
    classDef authNode fill:#FFFAF0,stroke:#FFCC80,stroke-width:1px,color:#F57C00
    classDef processNode fill:#FCF8FF,stroke:#CE93D8,stroke-width:1px,color:#8E24AA
    classDef mahiNode fill:#F8FFF8,stroke:#A5D6A7,stroke-width:1px,color:#43A047
    classDef errorNode fill:#FFF8F8,stroke:#FFAB91,stroke-width:1px,color:#F4511E
    classDef successNode fill:#F8FFF8,stroke:#A5D6A7,stroke-width:1px,color:#43A047
    
    class A clientNode
    class B,C,D authNode
    class F,G,H,J,K,L processNode
    class M,N,O,P,Q,S mahiNode
    class I,R,X,Y errorNode
    class T,U,V,W successNode
```

##### Implementation Details

**Key Components:**

1. **SigV4 Detection** (`lib/auth.js:sigv4Handler`)
   - Identifies requests with `AWS4-HMAC-SHA256` authorization scheme
   - Validates presence of required headers (`Authorization`, `x-amz-date`)
   - Filters problematic headers that cause verification issues

2. **Mahi Integration** (`node_modules/mahi/lib/client.js`)
   - **Signature Verification**: `verifySigV4()` calls `/aws-verify` endpoint
   - **Access Key Lookup**: `getUserByAccessKey()` retrieves user credentials
   - **Account Resolution**: Maps AWS access keys to Manta accounts

3. **Authentication Context** (`lib/auth.js:loadCaller`)
   ```javascript
   req.auth = {
       accountid: result.userUuid,
       accessKeyId: result.accessKeyId,
       method: 'sigv4',
       signature: {
           verified: true,
           keyId: result.accessKeyId
       }
   };
   ```

**Required SigV4 Headers:**
- `Authorization: AWS4-HMAC-SHA256 Credential=...`
- `x-amz-date: 20231201T120000Z` (or standard `Date` header)
- `x-amz-content-sha256: <payload-hash>` (for POST/PUT requests)
- `Host: <endpoint-hostname>`

**Signature Calculation Process:**
1. **Canonical Request**: Normalize HTTP method, URI, query parameters, headers, and payload
2. **String to Sign**: Create standardized string with algorithm, timestamp, scope, and canonical request hash
3. **Signing Key**: Derive signing key from secret access key, date, region, and service
4. **Signature**: Calculate HMAC-SHA256 of string-to-sign using signing key

**Error Handling:**
- `InvalidSignature` → 403 Forbidden with S3 XML error format
- `AccessKeyNotFound` → 403 Forbidden (mapped to InvalidSignature for security)
- `RequestTimeTooSkewed` → 403 Forbidden with time skew error
- `MissingHeaders` → 400 Bad Request

**Security Features:**
- **Time-based Validation**: Requests must be within acceptable time window
- **Replay Protection**: Signatures include timestamp and are single-use
- **Secure Key Storage**: Access keys managed through Mahi service
- **Audit Logging**: All authentication attempts are logged for security monitoring

##### Configuration

SigV4 authentication is configured through the Mahi client setup:

```javascript
// main.js - Mahi client configuration
var mahiClient = mahi.createClient({
    url: 'http://mahi.service.consul:8080',
    log: bunyan.createLogger({name: 'mahi'}),
    typeTable: apertureConfig.typeTable
});
```

**Environment Variables:**
- `MAHI_URL` - Mahi authentication service endpoint
- `APERTURE_URL` - Aperture authorization service endpoint  
- `KEYAPI_URL` - Key management service endpoint

##### Testing SigV4 Authentication

The test suite (`test/s3-compat-test.sh`) validates SigV4 authentication with:
- **AWS CLI Integration**: Standard AWS CLI commands with custom endpoint
- **Credential Validation**: Access key and secret key verification
- **Error Scenarios**: Invalid signatures, missing headers, time skew
- **Multi-operation Flows**: End-to-end workflows with authentication

## S3 Presigned URLs

The Manta Buckets API supports S3 presigned URLs, providing secure, time-limited access to objects without requiring AWS credentials in the client. This feature enables use cases like temporary file sharing, web browser uploads/downloads, and serverless application integrations.

### Overview

S3 presigned URLs embed authentication information directly in the URL query parameters, allowing temporary access to specific objects. The system validates these URLs by reconstructing the original signed request and verifying the cryptographic signature against the embedded credentials.

### Architecture

```mermaid
graph TB
    subgraph "Client Side"
        User[User/Application]
        AWSCLI[AWS CLI<br/>aws s3 presign]
        SDK[AWS SDK<br/>boto3, etc.]
    end
    
    subgraph "URL Generation"
        User --> AWSCLI
        User --> SDK
        AWSCLI --> PresignedURL[Presigned URL<br/>X-Amz-Algorithm=AWS4-HMAC-SHA256<br/>X-Amz-Credential=AKIATEST.../20250926/us-east-1/s3/aws4_request<br/>X-Amz-Date=20250926T120000Z<br/>X-Amz-Expires=3600<br/>X-Amz-SignedHeaders=host<br/>X-Amz-Signature=abc123...]
        SDK --> PresignedURL
    end
    
    subgraph "URL Usage"
        Browser[Web Browser]
        CURL[curl/wget]
        WebApp[Web Application]
        PresignedURL --> Browser
        PresignedURL --> CURL
        PresignedURL --> WebApp
    end
    
    subgraph "Manta Infrastructure"
        HAProxy[HAProxy<br/>Request Routing]
        BucketsAPI[manta-buckets-api<br/>S3 Compatibility]
        MahiAuth[Mahi<br/>Authentication Service]
        MantaStorage[Manta Storage<br/>Sharks/Metadata]
    end
    
    Browser --> HAProxy
    CURL --> HAProxy
    WebApp --> HAProxy
    
    HAProxy --> BucketsAPI
    BucketsAPI --> MahiAuth
    BucketsAPI --> MantaStorage
    
    classDef clientNode fill:#E3F2FD,stroke:#1976D2,stroke-width:2px
    classDef urlNode fill:#FFF3E0,stroke:#F57C00,stroke-width:2px
    classDef infraNode fill:#E8F5E8,stroke:#388E3C,stroke-width:2px
    
    class User,AWSCLI,SDK,Browser,CURL,WebApp clientNode
    class PresignedURL urlNode
    class HAProxy,BucketsAPI,MahiAuth,MantaStorage infraNode
```

### Request Flow

#### 1. Presigned URL Detection and Routing

```mermaid
sequenceDiagram
    participant Client as Client<br/>(Browser/curl)
    participant HAProxy as HAProxy<br/>Load Balancer
    participant BucketsAPI as manta-buckets-api
    participant Auth as Authentication<br/>Middleware
    
    Note over Client: User accesses presigned URL:<br/>GET /bucket/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&...
    
    Client->>HAProxy: HTTP Request with S3 query parameters
    
    Note over HAProxy: Route Selection Logic:<br/>✓ acl_s3_presigned: urlp(X-Amz-Algorithm) -m found<br/>✓ acl_s3_presigned_alt: urlp(X-Amz-Signature) -m found<br/>✓ acl_s3_credential: urlp(X-Amz-Credential) -m found
    
    HAProxy->>HAProxy: Detect S3 presigned URL parameters
    HAProxy->>BucketsAPI: Route to buckets_api backend
    
    BucketsAPI->>Auth: Process S3 presigned URL
    Auth-->>BucketsAPI: Authentication context established
    BucketsAPI-->>HAProxy: Response (file content or error)
    HAProxy-->>Client: HTTP Response
```

#### 2. S3 Presigned URL Processing Pipeline

```mermaid
sequenceDiagram
    participant Request as Incoming Request
    participant Converter as convertS3PresignedToManta()
    participant Checker as checkIfPresigned()
    participant Validator as preSignedUrl()
    participant Mahi as Mahi SigV4 Verification
    participant Handler as S3 Route Handler
    
    Request->>Converter: URL with X-Amz-* parameters
    
    Note over Converter: Parameter Preservation:<br/>• _originalS3Credential<br/>• _originalS3Date<br/>• _originalS3Expires<br/>• _originalS3SignedHeaders<br/>• _originalS3Signature
    
    Converter->>Converter: Extract access key from X-Amz-Credential
    Converter->>Converter: Parse X-Amz-Date (ISO8601 format)
    Converter->>Converter: Calculate absolute expiration timestamp
    
    Note over Converter: Manta Format Conversion:<br/>keyId → access key<br/>algorithm → 'rsa-sha256'<br/>expires → Unix timestamp<br/>signature → X-Amz-Signature<br/>method → HTTP method
    
    Converter->>Converter: Mark req._s3PresignedConverted = true
    Converter->>Checker: Continue to presigned check
    
    Checker->>Checker: Detect presigned URL (S3 or Manta format)
    Checker->>Checker: Set req._presigned = true
    Checker->>Validator: Continue to validation
    
    Note over Validator: Signature Validation Process
    
    Validator->>Validator: Reconstruct Authorization header:<br/>AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
    
    Validator->>Validator: Rebuild original S3 URL with query parameters:<br/>X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date, etc.
    
    Validator->>Validator: Create verification request object:<br/>{method, url, headers}
    
    Validator->>Mahi: verifySigV4(reconstructedRequest)
    
    Note over Mahi: Mahi Verification:<br/>1. Parse Authorization header<br/>2. Extract signing components<br/>3. Calculate canonical request<br/>4. Generate string-to-sign<br/>5. Compute expected signature<br/>6. Compare signatures
    
    alt Signature Valid
        Mahi-->>Validator: {userUuid, accessKeyId}
        Validator->>Validator: Set authentication context:<br/>req.auth.accountid = userUuid<br/>req.auth.method = 'presigned-s3'<br/>req._s3PresignedAuthComplete = true
        Validator->>Handler: Continue to S3 operation
    else Signature Invalid
        Mahi-->>Validator: Error (Invalid signature)
        Validator-->>Request: 403 Forbidden<br/>PreSignedRequestError
    end
```

### Implementation Details

#### Query Parameter Conversion

```mermaid
graph LR
    subgraph "S3 Presigned URL Format"
        S3Algo["X-Amz-Algorithm<br/>AWS4-HMAC-SHA256"]
        S3Cred["X-Amz-Credential<br/>AKIATEST.../20250926/us-east-1/s3/aws4_request"]
        S3Date["X-Amz-Date<br/>20250926T120000Z"]
        S3Expires["X-Amz-Expires<br/>3600"]
        S3Headers["X-Amz-SignedHeaders<br/>host"]
        S3Sig["X-Amz-Signature<br/>abc123..."]
    end
    
    subgraph "Manta Presigned Format"
        MantaKeyId["keyId<br/>AKIATEST..."]
        MantaAlgo["algorithm<br/>rsa-sha256"]
        MantaExpires["expires<br/>1758927600"]
        MantaSig["signature<br/>abc123..."]
        MantaMethod["method<br/>GET"]
    end
    
    S3Cred --> MantaKeyId
    S3Algo --> MantaAlgo
    S3Date --> MantaExpires
    S3Expires --> MantaExpires
    S3Sig --> MantaSig
    
    classDef s3Style fill:#FFE082,stroke:#F57C00,stroke-width:2px
    classDef mantaStyle fill:#A5D6A7,stroke:#388E3C,stroke-width:2px
    
    class S3Algo,S3Cred,S3Date,S3Expires,S3Headers,S3Sig s3Style
    class MantaKeyId,MantaAlgo,MantaExpires,MantaSig,MantaMethod mantaStyle
```

#### Signature Verification Process

The signature verification reconstructs the exact request that was signed by the client:

```javascript
// 1. Reconstruct Authorization header
var authHeader = 'AWS4-HMAC-SHA256 Credential=' + credential + 
               ', SignedHeaders=' + signedHeaders + 
               ', Signature=' + signature;

// 2. Rebuild original URL with S3 query parameters  
var originalQueryParams = [
    'X-Amz-Algorithm=AWS4-HMAC-SHA256',
    'X-Amz-Credential=' + encodeURIComponent(credential),
    'X-Amz-Date=' + amzDate,
    'X-Amz-Expires=' + expires,
    'X-Amz-SignedHeaders=' + signedHeaders
];

// 3. Create verification request
var requestForVerification = {
    method: req.method,
    url: pathPart + '?' + originalQueryParams.join('&'),
    headers: {
        'authorization': authHeader,
        'x-amz-date': amzDate,
        'host': req.headers.host
    }
};

// 4. Verify with Mahi
req.mahi.verifySigV4(requestForVerification, callback);
```

### Security Model

#### Time-based Validation
```mermaid
graph TD
    A[X-Amz-Date] --> B[Parse ISO8601 Timestamp<br/>20250926T120000Z]
    C[X-Amz-Expires] --> D[Expiration Duration<br/>3600 seconds]
    
    B --> E[Request Time<br/>2025-09-26 12:00:00 UTC]
    D --> E
    E --> F[Calculated Expiry<br/>2025-09-26 13:00:00 UTC]
    
    G[Current Time] --> H{Within Valid Window?}
    F --> H
    
    H -->|Yes| I[✅ Allow Request]
    H -->|No| J[❌ Deny - URL Expired]
    
    classDef timeNode fill:#E1F5FE,stroke:#0277BD,stroke-width:2px
    classDef checkNode fill:#FFF9C4,stroke:#F9A825,stroke-width:2px
    classDef successNode fill:#E8F5E8,stroke:#388E3C,stroke-width:2px
    classDef errorNode fill:#FFEBEE,stroke:#D32F2F,stroke-width:2px
    
    class A,B,C,D,E,F,G timeNode
    class H checkNode
    class I successNode
    class J errorNode
```

#### Cryptographic Validation
- **Algorithm**: AWS SigV4 (HMAC-SHA256)
- **Signature Scope**: Method + URL + Headers + Timestamp
- **Tamper Detection**: Any URL modification invalidates signature
- **Replay Protection**: Time window limits reuse

#### Permission Model
```mermaid
graph TB
    subgraph "Access Control Flow"
        A[Presigned URL Request] --> B[Signature Validation]
        B --> C[Extract Access Key]
        C --> D[Mahi User Lookup]
        D --> E[Manta Authorization]
        E --> F[Resource Access Check]
        
        F --> G{Permission Check}
        G -->|Authorized| H[✅ Grant Access]
        G -->|Denied| I[❌ Access Denied]
    end
    
    subgraph "Permission Inheritance"
        J[Signer's Permissions] --> K[URL Access Level]
        K --> L[Scoped to Specific Object]
        L --> M[Limited by Expiration Time]
    end
    
    classDef processNode fill:#E3F2FD,stroke:#1976D2,stroke-width:2px
    classDef permNode fill:#F3E5F5,stroke:#7B1FA2,stroke-width:2px
    classDef successNode fill:#E8F5E8,stroke:#388E3C,stroke-width:2px
    classDef errorNode fill:#FFEBEE,stroke:#D32F2F,stroke-width:2px
    
    class A,B,C,D,E,F,G processNode
    class J,K,L,M permNode
    class H successNode
    class I errorNode
```


### Error Handling and Diagnostics

#### Common Error Scenarios

```mermaid
graph TD
    A[Presigned URL Request] --> B{URL Format Valid?}
    B -->|No| C[400 Bad Request<br/>Invalid S3 presigned URL format]
    
    B -->|Yes| D{Required Parameters Present?}
    D -->|No| E[403 Forbidden<br/>Missing required S3 presigned URL parameters]
    
    D -->|Yes| F{URL Expired?}
    F -->|Yes| G[403 Forbidden<br/>URL has expired]
    
    F -->|No| H{Signature Valid?}
    H -->|No| I[403 Forbidden<br/>Invalid signature]
    
    H -->|Yes| J{User Has Permission?}
    J -->|No| K[403 Forbidden<br/>Access denied]
    
    J -->|Yes| L[✅ Process Request Successfully]
    
    classDef errorNode fill:#FFEBEE,stroke:#D32F2F,stroke-width:2px
    classDef checkNode fill:#FFF9C4,stroke:#F9A825,stroke-width:2px
    classDef successNode fill:#E8F5E8,stroke:#388E3C,stroke-width:2px
    
    class C,E,G,I,K errorNode
    class B,D,F,H,J checkNode
    class L successNode
```

#### Debugging Information

The system provides detailed logging for troubleshooting presigned URL issues:

```javascript
// Authentication flow logging
log.debug({
    originalUrl: req.url,
    verificationUrl: urlForVerification,
    authHeader: authHeader.substring(0, 100) + '...',
    signedHeaders: signedHeaders
}, 'S3_PRESIGNED_DEBUG: Constructed verification request');

// Signature validation results
log.debug({
    accessKeyId: result.accessKeyId,
    userUuid: result.userUuid
}, 'S3_PRESIGNED_DEBUG: Signature validation successful');
```

### Performance Considerations

#### HAProxy Routing Efficiency
- **Parameter Detection**: Fast ACL checks on query parameters
- **Minimal Overhead**: Direct routing without complex pattern matching
- **Load Balancing**: Distributes presigned URL requests across buckets-api instances

#### Signature Validation Optimization
- **Cached Results**: Mahi may cache signature validation results
- **Connection Pooling**: Reuse connections to Mahi service
- **Parallel Processing**: Multiple presigned URL requests processed concurrently

#### Monitoring and Metrics
- **Request Latency**: Track time from URL request to signature validation
- **Error Rates**: Monitor signature validation failures and expiration errors
- **Usage Patterns**: Analyze presigned URL generation and access patterns

### Configuration

#### HAProxy Rules
```haproxy
# S3 presigned URL detection in /home/build/S3-MANTA/muppet/etc/haproxy.cfg.in
acl acl_s3_presigned urlp(X-Amz-Algorithm) -m found
acl acl_s3_presigned_alt urlp(X-Amz-Signature) -m found  
acl acl_s3_credential urlp(X-Amz-Credential) -m found

# Route presigned URLs to buckets-api
use_backend buckets_api if acl_s3_presigned
use_backend buckets_api if acl_s3_presigned_alt
use_backend buckets_api if acl_s3_credential
```

#### Manta Buckets API Middleware
```javascript
// Authentication pipeline in lib/server.js
server.use(auth.convertS3PresignedToManta);  // Convert S3 to Manta format
server.use(auth.checkIfPresigned);           // Detect presigned requests  
server.use(auth.preSignedUrl);               // Validate signatures
```

#### Security Settings
- **Maximum Expiration**: URLs can be valid for up to 7 days (604800 seconds)
- **Minimum Expiration**: URLs must be valid for at least 1 second
- **Time Skew Tolerance**: Configurable time window for clock differences
- **Algorithm Support**: Only AWS4-HMAC-SHA256 is supported

## Role-Based Access Control (RBAC) for S3 Compatibility

The Manta Buckets API implements Role-Based Access Control (RBAC) to provide fine-grained access control for S3 operations. This system allows administrators to create subusers with specific permissions for individual buckets and objects.

### RBAC Architecture Overview

```mermaid
graph TB
    subgraph "Account Structure"
        Account["Account Owner<br/>your_account_owner"]
        Subuser1["Subuser<br/>s3qa"]
        Subuser2["Subuser<br/>app-user"]
        Account --> Subuser1
        Account --> Subuser2
    end
    
    subgraph "Policy Definitions"
        Policy1["bucket-reader<br/>CAN getbucket test-bucket<br/>CAN getobject test-bucket/*"]
        Policy2["bucket-admin<br/>CAN getbucket uploads<br/>CAN getobject uploads/*<br/>CAN putobject uploads/*<br/>CAN deleteobject uploads/*"]
        Policy3["multi-bucket<br/>CAN getbucket dev-*<br/>CAN getobject dev-*/*"]
    end
    
    subgraph "Role Assignment"
        Role1["storage-reader<br/>members: s3qa<br/>default_members: s3qa<br/>policies: bucket-reader"]
        Role2["uploader<br/>members: app-user<br/>default_members: app-user<br/>policies: bucket-admin"]
    end
    
    subgraph "S3 Authorization Flow"
        S3Request["S3 Request<br/>GET /test-bucket/file.txt"]
        AuthCheck["Authorization Check<br/>Resource: test-bucket/file.txt<br/>Action: getobject"]
        PolicyEval["Policy Evaluation<br/>test-bucket/* matches<br/>test-bucket/file.txt"]
        Decision["✅ Allow Access"]
    end
    
    Policy1 --> Role1
    Policy2 --> Role2
    Policy3 --> Role1
    
    Role1 --> Subuser1
    Role2 --> Subuser2
    
    Subuser1 --> S3Request
    S3Request --> AuthCheck
    AuthCheck --> PolicyEval
    PolicyEval --> Decision
    
    classDef accountNode fill:#E3F2FD,stroke:#1976D2,stroke-width:2px
    classDef policyNode fill:#FFF3E0,stroke:#F57C00,stroke-width:2px
    classDef roleNode fill:#E8F5E8,stroke:#388E3C,stroke-width:2px
    classDef authNode fill:#F3E5F5,stroke:#7B1FA2,stroke-width:2px
    
    class Account,Subuser1,Subuser2 accountNode
    class Policy1,Policy2,Policy3 policyNode
    class Role1,Role2 roleNode
    class S3Request,AuthCheck,PolicyEval,Decision authNode
```

### Default Role Activation for S3 Compatibility

A critical requirement for S3 compatibility is that subusers must be in the `default_members` array of their roles. This ensures automatic role activation since S3 clients cannot send explicit role headers.

#### Authentication Flow with Default Roles

```mermaid
sequenceDiagram
    participant S3Client as S3 Client<br/>(AWS CLI)
    participant Auth as Authentication<br/>Middleware
    participant Mahi as Mahi Service
    participant RBAC as RBAC Evaluation
    participant Storage as Manta Storage
    
    Note over S3Client: S3 clients cannot send<br/>Role headers
    
    S3Client->>Auth: GET /test-bucket/file.txt<br/>Authorization: AWS4-HMAC-SHA256...
    Auth->>Mahi: Verify SigV4 signature
    Mahi-->>Auth: Valid user: s3qa
    
    Auth->>Auth: loadCaller(s3qa)
    Note over Auth: Mahi returns:<br/>user.roles: ["role-uuid"]<br/>user.defaultRoles: ["role-uuid"]
    
    Auth->>Auth: getActiveRoles()
    Note over Auth: No Role header provided<br/>Use defaultRoles for activation
    
    Auth->>Auth: activeRoles = user.defaultRoles
    Auth->>RBAC: Authorize with active roles
    
    RBAC->>RBAC: Check policy rules<br/>Resource: test-bucket/file.txt<br/>Action: getobject
    
    alt User in default_members
        RBAC->>RBAC: Evaluate: CAN getobject test-bucket/*<br/>Matches: test-bucket/file.txt ✅
        RBAC-->>Auth: ✅ Access Granted
        Auth->>Storage: Retrieve object
        Storage-->>S3Client: Object content
    else User NOT in default_members
        RBAC->>RBAC: activeRoles = [] (empty)<br/>No permissions active ❌
        RBAC-->>Auth: ❌ Access Denied
        Auth-->>S3Client: 403 Forbidden
    end
```

### Resource Naming and Bucket-Scoped Permissions

The system supports bucket-scoped object permissions using hierarchical resource names. This enables fine-grained access control at the bucket level.

#### Resource Name Resolution

```mermaid
graph TB
    subgraph "S3 Request Processing"
        Request[S3 Request<br/>GET /test-bucket/photos/image.jpg]
        RouteHandler[S3 Route Handler<br/>Extract bucket and object]
        BucketName[Bucket: test-bucket]
        ObjectName[Object: photos/image.jpg]
    end
    
    subgraph "Authorization Resource Construction"
        LoadRequest[loadRequest Function<br/>lib/buckets/buckets.js]
        ResourceKey[resource.key Construction]
        FullPath[Full Resource Path<br/>test-bucket/photos/image.jpg]
    end
    
    subgraph "Policy Evaluation"
        PolicyRule[Policy Rule<br/>CAN getobject test-bucket/*]
        RegexMatch[Regex Pattern Match<br/>/test\-bucket\/.*/]
        MatchResult[✅ test-bucket/photos/image.jpg<br/>matches test-bucket/*]
    end
    
    Request --> RouteHandler
    RouteHandler --> BucketName
    RouteHandler --> ObjectName
    
    BucketName --> LoadRequest
    ObjectName --> LoadRequest
    LoadRequest --> ResourceKey
    ResourceKey --> FullPath
    
    FullPath --> PolicyRule
    PolicyRule --> RegexMatch
    RegexMatch --> MatchResult
    
    classDef requestNode fill:#E3F2FD,stroke:#1976D2,stroke-width:2px
    classDef processNode fill:#FFF9C4,stroke:#F9A825,stroke-width:2px
    classDef policyNode fill:#E8F5E8,stroke:#388E3C,stroke-width:2px
    
    class Request,RouteHandler,BucketName,ObjectName requestNode
    class LoadRequest,ResourceKey,FullPath processNode
    class PolicyRule,RegexMatch,MatchResult policyNode
```

### Policy Examples and Use Cases

#### Granular Bucket Access Policies

```javascript
// Read-only access to specific bucket
{
  "name": "bucket-reader",
  "rules": [
    "CAN getbucket test-bucket",      // List bucket contents
    "CAN getobject test-bucket/*"     // Download any object in bucket
  ]
}

// Full access to specific bucket
{
  "name": "bucket-admin", 
  "rules": [
    "CAN getbucket uploads",          // List bucket contents
    "CAN getobject uploads/*",        // Download objects
    "CAN putobject uploads/*",        // Upload objects
    "CAN deleteobject uploads/*"      // Delete objects
  ]
}

// Multi-bucket access with patterns
{
  "name": "dev-environment",
  "rules": [
    "CAN getbucket dev-*",            // Access all dev buckets
    "CAN getobject dev-*/*",          // Download from dev buckets
    "CAN putobject dev-*/*"           // Upload to dev buckets
  ]
}

// Environment-based access
{
  "name": "developer-access",
  "rules": [
    "CAN getbucket dev-*",            // Full dev access
    "CAN getobject dev-*/*",
    "CAN putobject dev-*/*", 
    "CAN deleteobject dev-*/*",
    "CAN getbucket prod-*",           // Read-only prod access
    "CAN getobject prod-*/*"
  ]
}
```

#### Role Configuration for S3 Compatibility

```javascript
// Critical: User must be in BOTH members and default_members
{
  "name": "storage-reader",
  "members": ["s3qa"],                // User can assume this role
  "default_members": ["s3qa"],        // Role activates automatically
  "policies": ["bucket-reader"]       // Policy provides permissions
}

// Multiple users with automatic activation
{
  "name": "uploader-team",
  "members": ["user1", "user2", "user3"],
  "default_members": ["user1", "user2", "user3"],  // All get auto-activation
  "policies": ["bucket-admin"]
}

// Mixed activation (some users auto, others manual)
{
  "name": "developer-role",
  "members": ["dev1", "dev2", "admin1"],
  "default_members": ["dev1", "dev2"],             // Only devs get auto-activation
  "policies": ["dev-environment"]                   // admin1 must send Role header
}
```

### Authorization Action Mapping

S3 operations map to specific authorization actions that must be granted in policies:

| S3 Operation | Authorization Action | Required Permission Example |
|--------------|---------------------|----------------------------|
| **List Bucket** | `getbucket` | `CAN getbucket test-bucket` |
| **Get Object** | `getobject` | `CAN getobject test-bucket/*` |
| **Put Object** | `putobject` | `CAN putobject test-bucket/*` |
| **Delete Object** | `deleteobject` | `CAN deleteobject test-bucket/*` |
| **Head Bucket** | `getbucket` | `CAN getbucket test-bucket` |
| **Head Object** | `getobject` | `CAN getobject test-bucket/file.txt` |
| **Create Bucket** | `putbucket` | `CAN putbucket *` |

**Important Note**: Unlike traditional Manta routes that use separate `listbucket` permissions, S3 routes consolidate bucket operations under `getbucket` to align with AWS S3's permission model.


### Permission Scope and Wildcards

#### Bucket-Level Permissions

```javascript
// Specific bucket access
"CAN getbucket mybucket"              // Only mybucket
"CAN getobject mybucket/*"            // All objects in mybucket

// Pattern-based bucket access  
"CAN getbucket dev-*"                 // All buckets starting with dev-
"CAN getobject dev-*/*"               // All objects in dev-* buckets
// Can create buckets 
"CAN putbucket *"

// Multiple specific buckets
"CAN getbucket bucket1"               // Access bucket1
"CAN getbucket bucket2"               // Access bucket2
"CAN getobject bucket1/*"             // Objects in bucket1
"CAN getobject bucket2/*"             // Objects in bucket2
```

#### Object-Level Permissions

```javascript
// Specific object access
"CAN getobject mybucket/file.txt"     // Only specific file
"CAN getobject mybucket/folder/*"     // All files in folder

// Path-based restrictions
"CAN getobject uploads/public/*"      // Public files only
"CAN putobject uploads/user-123/*"    // User's folder only

// File type restrictions
"CAN getobject assets/*.jpg"          // Only JPEG files
"CAN getobject docs/*.pdf"            // Only PDF files
```

## STS IAM Implementation

The manta-buckets-api provides AWS STS (Security Token Service) IAM compatibility, enabling temporary credential workflows for S3 operations. This implementation bridges AWS IAM concepts with Manta's authentication system.

### STS IAM Architecture

```mermaid
sequenceDiagram
    participant CLI as AWS CLI
    participant API as manta-buckets-api
    participant Mahi as Mahi Auth Service  
    participant Redis as Redis Store
    participant UFDS as UFDS
    participant Buckets as Manta Buckets

    Note over CLI,Buckets: STS AssumeRole Flow with Trust Policy Validation
    CLI->>API: AssumeRole(RoleArn, SessionName, ExternalId?)
    API->>Mahi: POST /sts/assume-role
    Mahi->>Redis: GET /role/:uuid
    Redis-->>Mahi: Role + Trust Policy Document
    
    Note over Mahi: Trust Policy Validation Engine
    Mahi->>Mahi: Parse Trust Policy JSON
    Mahi->>Mahi: Validate Principal ARN Match
    Mahi->>Mahi: Evaluate Conditions (StringEquals, IpAddress, etc.)
    Mahi->>Mahi: Check Action Authorization (sts:AssumeRole)
    
    alt Trust Policy Validation Passes
        Mahi->>UFDS: Generate Temporary Credentials
        UFDS-->>Mahi: Access Key + Secret (tdc_ prefix)
        Mahi->>Mahi: Generate JWT Session Token (HMAC-SHA256)
        Mahi->>Redis: Store Session + Role Mapping
        Mahi-->>API: Credentials + JWT Session Token
        API-->>CLI: STS XML Response
    else Trust Policy Validation Fails
        Mahi-->>API: 403 AccessDenied
        API-->>CLI: Error: Access denied by trust policy
    end

    Note over CLI,Buckets: S3 Operations with JWT Session Tokens
    CLI->>API: S3 Request (AccessKey + SecretKey + SessionToken)
    API->>API: Extract JWT Session Token from Headers
    API->>Mahi: Validate JWT + Load Role Permissions
    
    Note over Mahi: JWT Token Validation
    Mahi->>Mahi: Verify HMAC-SHA256 Signature
    Mahi->>Mahi: Check Token Expiration (exp claim)
    Mahi->>Mahi: Validate Issuer/Audience (iss/aud claims)
    Mahi->>Redis: GET Role Permission Policies
    Redis-->>Mahi: S3 Permission Policies
    
    Mahi-->>API: Auth Context + S3 Permissions
    API->>API: Evaluate S3 Action + Resource Match
    API->>Buckets: S3 Operation (authorized)
    Buckets-->>API: Operation Result
    API-->>CLI: S3 Response
```

### AWS vs Manta STS IAM Comparison

| Component | AWS STS IAM | Manta STS IAM |
|-----------|-------------|---------------|
| **Role Storage** | DynamoDB/Internal | Redis with `/role/:uuid` keys |
| **Policy Storage** | IAM Service | Redis with `/role-permissions/:uuid` keys |
| **Session Management** | AWS STS | Redis with `/session-token/:token` keys |
| **Credential Format** | AWS Access Keys | TRITON-2513 format (`tdc_` prefix) |
| **Principal Support** | Full ARN support | Complete ARN support (aws/manta/triton) |
| **Trust Policies** | Rich policy language | Complete condition evaluation engine |
| **Session Tokens** | JWT-based | JWT with HMAC-SHA256 + key rotation |
| **Condition Operators** | Full set | StringEquals, IpAddress, DateGreaterThan, Bool, etc. |
| **External ID** | Supported | Fully supported with StringEquals conditions |
| **Time-based Access** | Supported | Fully supported with Date conditions |
| **IP Restrictions** | Supported | Fully supported with IpAddress conditions |
| **Expiration** | AWS managed | Auto-expiration with JWT exp claim |

### IAM Operations

The system implements core AWS IAM operations for role and policy management:

#### Role Management
- **CreateRole** - Creates IAM role with trust policy
  ```bash
  aws iam create-role --role-name MyRole --assume-role-policy-document file://trust.json
  ```

- **DeleteRole** - Removes IAM role
  ```bash
  aws iam delete-role --role-name MyRole
  ```

- **GetRole** - Retrieves role metadata (excludes permission policies per AWS standard)
  ```bash
  aws iam get-role --role-name MyRole
  ```

- **ListRoles** - Lists all roles in account
  ```bash
  aws iam list-roles
  ```

#### Permission Policy Management  
- **PutRolePolicy** - Attaches inline policy to role
  ```bash
  aws iam put-role-policy --role-name MyRole --policy-name S3Access --policy-document file://policy.json
  ```

- **DeleteRolePolicy** - Removes inline policy from role
  ```bash
  aws iam delete-role-policy --role-name MyRole --policy-name S3Access
  ```

- **ListRolePolicies** - Lists policy names attached to role
  ```bash
  aws iam list-role-policies --role-name MyRole
  ```

- **GetRolePolicy** - Retrieves specific policy document
  ```bash
  aws iam get-role-policy --role-name MyRole --policy-name S3Access
  ```

### STS Operations

#### AssumeRole
Generates temporary credentials for role-based access:
```bash
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/MyRole --role-session-name session1
```

**Response Structure:**
```json
{
  "Credentials": {
    "AccessKeyId": "tdc_SU4xWXL-HzrMIDM_A8GH94sl-uc-aX8mqsEMiK4JSVdAGyjH",
    "SecretAccessKey": "tdc_9k3jF8mN2pL5qR7sT1vY6zA8bC4eG7iJ0mP3rU5xW9yB2dF",
    "SessionToken": "eyJ1dWlkIjoiYWJjZC0xMjM0LWVmZ2gtNTY3OCIsImV4cGlyZXMiOjE2OTg0NTM2MDB9",
    "Expiration": "2023-10-28T10:00:00Z"
  },
  "AssumedRoleUser": {
    "AssumedRoleId": "AROA123EXAMPLE123:session1",
    "Arn": "arn:aws:sts::123456789012:assumed-role/MyRole/session1"
  }
}
```

### Session Token Structure

Session tokens use Base64-encoded JSON (not JWT):
```json
{
  "uuid": "abcd-1234-efgh-5678",
  "expires": 1698453600,
  "sessionName": "session1",
  "roleArn": "arn:aws:iam::123456789012:role/MyRole"
}
```

### STS IAM Implementation in Manta S3

Manta S3 provides a complete STS IAM implementation that enables temporary credential workflows and role-based access control for S3 operations.

#### Understanding Core STS IAM Concepts

##### What is a Principal?

A **Principal** is an entity that can make requests to Manta S3 resources. Think of it as "who is making the request."

**Principal vs User vs Role:**

| Concept | Description | Lifetime | Example |
|---------|-------------|----------|---------|
| **User** | Permanent identity with long-term access keys | Permanent until deleted | `alice` - a developer account |
| **Role** | Temporary identity that can be "assumed" | Temporary (1 hour default) | `DeploymentRole` - for deployments only |
| **Principal** | Generic term for any entity (user, role, service) in policies | Defined in policy | Used in trust policy Principal field |

##### Why Use STS Instead of Direct User Access?

**Traditional Approach (Direct User Access):**
```bash
# Alice uses her permanent credentials
AWS_ACCESS_KEY_ID=EXAMPLE-ACCESS-KEY-ID
AWS_SECRET_ACCESS_KEY=ExampleSecretAccessKey1234567890

# Alice can access everything her user account allows
aws s3 ls --endpoint-url https://manta.example.com
aws s3 cp file.txt s3://production-data/ --endpoint-url https://manta.example.com
```

**Problems:**
- Credentials don't expire (security risk)
- Hard to audit specific operations
- Difficult to limit permissions per task

**STS Approach (Role-Based Access):**
```bash
# Step 1: Alice assumes a specific role
aws sts assume-role \
  --role-arn arn:manta:iam::123456789012:role/ReadOnlyAccess \
  --role-session-name alice-data-analysis \
  --endpoint-url https://manta.example.com

# Step 2: Get temporary credentials (expire in 1 hour)
AWS_ACCESS_KEY_ID=EXAMPLE-TEMP-ACCESS-KEY-ID
AWS_SECRET_ACCESS_KEY=ExampleTempSecretKey7890123456
AWS_SESSION_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiZXhhbXBsZS0xMjM0LWVmZ2gtNTY3OCIsInJvbGVBcm4iOiJhcm46bWFudGE6aWFtOjoxMjM0NTY3ODkwMTI6cm9sZS9SZWFkT25seUFjY2VzcyIsInNlc3Npb25OYW1lIjoiYWxpY2UtZGF0YS1hbmFseXNpcyIsInRva2VuVHlwZSI6InN0cy1zZXNzaW9uIiwidG9rZW5WZXJzaW9uIjoiMS4xIiwia2V5SWQiOiJrZXktMjAyNTAxMjAtYTFiMmMzZDQiLCJpc3MiOiJtYW50YS1tYWhpIiwiYXVkIjoibWFudGEtczMiLCJpYXQiOjE3MDUzMTU4MDAsImV4cCI6MTcwNTMxOTQwMCwibmJmIjoxNzA1MzE1ODAwfQ.ExampleSignatureHash1234567890

# Step 3: Use limited permissions
aws s3 ls s3://analytics-data/ --endpoint-url https://manta.example.com  # ✅ Allowed
aws s3 cp s3://analytics-data/report.csv ./ --endpoint-url https://manta.example.com  # ✅ Allowed
aws s3 rm s3://production-data/critical.db --endpoint-url https://manta.example.com  # ❌ Denied
```

**Benefits:**
- Credentials auto-expire (default 1 hour)
- Granular permissions per role
- Complete audit trail
- Secure credential sharing

#### Manta ARN Format and Construction

##### ARN Structure in Manta S3

Amazon Resource Names (ARNs) in Manta follow AWS format but with important differences:

**General Format:**
```
arn:partition:service:region:account-id:resource-type/resource-name
```

##### Supported Partitions

| Partition | Purpose | Example |
|-----------|---------|---------|
| `aws` | AWS compatibility | `arn:aws:iam::123456789012:user/alice` |
| `manta` | Manta native | `arn:manta:iam::123456789012:user/alice` |
| `triton` | Triton compatibility | `arn:triton:iam::123456789012:user/alice` |

**All three partitions work identically** - choose based on your preference and migration needs.

##### IAM Resource ARNs

**Format:** `arn:partition:iam::account-id:resource-type/resource-name`

**Key Points:**
- **No region field** (empty between colons: `iam::account`)
- **Account ID required** (your 12-digit Manta account number)
- **Resource type** can be `user`, `role`, or `root`

**Examples:**
```bash
# User ARNs
arn:manta:iam::123456789012:user/alice
arn:manta:iam::123456789012:user/bob-developer  
arn:manta:iam::123456789012:user/service-account
arn:manta:iam::123456789012:user/github-runner

# Role ARNs
arn:manta:iam::123456789012:role/S3ReadOnly
arn:manta:iam::123456789012:role/DeploymentRole
arn:manta:iam::123456789012:role/ProductionAccess

# Root ARN (account owner)
arn:manta:iam::123456789012:root
```

##### S3 Resource ARNs

**Format:** `arn:partition:s3:::bucket-name[/object-path]`

**Key Points:**
- **No region field at all** (three colons after s3: `s3:::bucket`)
- **No account field** (buckets are globally unique)
- **Object paths** support wildcards

**Examples:**
```bash
# Bucket ARNs
arn:manta:s3:::my-application-bucket
arn:manta:s3:::dev-environment-data
arn:manta:s3:::production-backups

# Object ARNs  
arn:manta:s3:::my-app/config/settings.json
arn:manta:s3:::user-data/alice/documents/report.pdf
arn:manta:s3:::logs/2024/01/15/application.log

# Wildcard patterns
arn:manta:s3:::my-app/*                    # All objects in bucket
arn:manta:s3:::my-app/config/*             # All config files
arn:manta:s3:::user-data/*/profile.json    # All user profiles
arn:manta:s3:::logs/2024/*/*               # All 2024 logs
arn:manta:s3:::images/*.jpg                # All JPEG images
```

##### ARN Construction Rules

**Getting Your Account ID:**
```bash
# Method 1: Check caller identity
aws sts get-caller-identity --endpoint-url https://manta.example.com

# Response shows your account ID
{
  "UserId": "example-1234-efgh-5678",
  "Account": "123456789012",
  "Arn": "arn:manta:iam::123456789012:user/alice"
}
```

**Building ARNs:**
```bash
# Set your account ID
ACCOUNT_ID="123456789012"

# Build user ARNs
USER_ALICE="arn:manta:iam::${ACCOUNT_ID}:user/alice"
USER_BOB="arn:manta:iam::${ACCOUNT_ID}:user/bob"

# Build role ARNs  
ROLE_DEPLOY="arn:manta:iam::${ACCOUNT_ID}:role/DeploymentRole"
ROLE_READONLY="arn:manta:iam::${ACCOUNT_ID}:role/ReadOnlyAccess"

# Build bucket ARNs
BUCKET_APP="arn:manta:s3:::my-application"
OBJECTS_APP="arn:manta:s3:::my-application/*"
```

#### Trust Policies (Who Can Assume Roles)

Trust policies control **who can assume a role** and **under what conditions**.

##### Basic Trust Policy Structure

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:manta:iam::123456789012:user/alice"
    },
    "Action": "sts:AssumeRole"
  }]
}
```

**Translation:** "Allow user alice to assume this role"

##### Principal Types in Trust Policies

**1. User Principals**

Single user:
```json
{
  "Principal": {
    "AWS": "arn:manta:iam::123456789012:user/alice"
  }
}
```

Multiple users:
```json
{
  "Principal": {
    "AWS": [
      "arn:manta:iam::123456789012:user/alice",
      "arn:manta:iam::123456789012:user/bob",
      "arn:manta:iam::123456789012:user/charlie"
    ]
  }
}
```

**2. Role Principals (Role Chaining)**

```json
{
  "Principal": {
    "AWS": "arn:manta:iam::123456789012:role/BaseRole"
  }
}
```

**Use Case:** One role assumes another role for escalated permissions.

**3. Root Principal (Account Owner)**

```json
{
  "Principal": {
    "AWS": "arn:manta:iam::123456789012:root"
  }
}
```

**Use Case:** Administrative access, emergency scenarios.

**4. Wildcard Principal**

```json
{
  "Principal": {"AWS": "*"}
}
```

**Use Case:** Public access (always use with strict conditions).

##### Trust Policy Conditions (Fully Supported)

**Supported Condition Operators:**

| Operator | Description | Example |
|----------|-------------|---------|
| `StringEquals` | Exact string match | External ID validation |
| `StringNotEquals` | String inequality | Exclude specific values |
| `StringLike` | Wildcard patterns (* ?) | Session name patterns |
| `StringNotLike` | Negative wildcard | Exclude patterns |
| `Bool` | Boolean comparison | MFA requirements |
| `DateGreaterThan` | After timestamp | Business hours only |
| `DateLessThan` | Before timestamp | Time-limited access |
| `IpAddress` | IP/CIDR matching | Office network only |
| `NotIpAddress` | IP exclusion | Block specific IPs |

**Available Context Keys:**

| Context Key | Description | Example Value |
|-------------|-------------|---------------|
| `aws:SourceIp` | Client IP address | "192.168.1.100" |
| `aws:username` | Username | "alice" |
| `aws:userid` | User UUID | "example-1234-efgh-5678" |
| `aws:RequestTime` | Request timestamp | "2024-01-15T10:30:00Z" |
| `sts:ExternalId` | External identifier | "github-actions-12345" |
| `aws:MultiFactorAuthPresent` | MFA presence | "true" / "false" |

#### Complete STS IAM Examples

##### Example 1: Development Team Role

**Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": [
        "arn:manta:iam::123456789012:user/alice",
        "arn:manta:iam::123456789012:user/bob",
        "arn:manta:iam::123456789012:user/charlie"
      ]
    },
    "Action": "sts:AssumeRole"
  }]
}
```

**Permission Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": [
        "arn:manta:s3:::dev-*",
        "arn:manta:s3:::dev-*/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:manta:s3:::prod-data",
        "arn:manta:s3:::prod-data/*"
      ]
    }
  ]
}
```

**Creating the Role:**
```bash
# Step 1: Create role with trust policy
aws iam create-role --role-name DevelopmentAccess \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:manta:iam::123456789012:user/alice",
          "arn:manta:iam::123456789012:user/bob",
          "arn:manta:iam::123456789012:user/charlie"
        ]
      },
      "Action": "sts:AssumeRole"
    }]
  }' --endpoint-url https://manta.example.com

# Step 2: Attach permission policy
aws iam put-role-policy --role-name DevelopmentAccess \
  --policy-name S3DevAccess --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "s3:*",
        "Resource": [
          "arn:manta:s3:::dev-*",
          "arn:manta:s3:::dev-*/*"
        ]
      },
      {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Resource": [
          "arn:manta:s3:::prod-data",
          "arn:manta:s3:::prod-data/*"
        ]
      }
    ]
  }' --endpoint-url https://manta.example.com
```

**Using the Role:**
```bash
# Alice assumes the role
CREDS=$(aws sts assume-role \
  --role-arn arn:manta:iam::123456789012:role/DevelopmentAccess \
  --role-session-name alice-dev-work \
  --endpoint-url https://manta.example.com)

# Extract credentials from response
export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Credentials.SessionToken')

# Now Alice can use S3 with role permissions
aws s3 ls s3://dev-project/ --endpoint-url https://manta.example.com      # ✅ Full access
aws s3 cp file.txt s3://dev-project/ --endpoint-url https://manta.example.com  # ✅ Upload allowed
aws s3 ls s3://prod-data/ --endpoint-url https://manta.example.com        # ✅ Read-only access
aws s3 rm s3://prod-data/critical.db --endpoint-url https://manta.example.com  # ❌ Delete denied
```

##### Example 2: CI/CD with External ID Security

**Trust Policy with External ID:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:manta:iam::123456789012:user/github-runner"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "myproject-deployment-secret"
      }
    }
  }]
}
```

**Permission Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
    "Resource": [
      "arn:manta:s3:::production-app",
      "arn:manta:s3:::production-app/*"
    ]
  }]
}
```

**Creating and Using:**
```bash
# Create deployment role
aws iam create-role --role-name DeploymentRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:manta:iam::123456789012:user/github-runner"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "myproject-deployment-secret"
        }
      }
    }]
  }' --endpoint-url https://manta.example.com

# Assume role WITH correct external ID (succeeds)
aws sts assume-role \
  --role-arn arn:manta:iam::123456789012:role/DeploymentRole \
  --role-session-name deploy-session \
  --external-id "myproject-deployment-secret" \
  --endpoint-url https://manta.example.com

# Assume role WITHOUT external ID (fails)
aws sts assume-role \
  --role-arn arn:manta:iam::123456789012:role/DeploymentRole \
  --role-session-name deploy-session \
  --endpoint-url https://manta.example.com
# Error: Access denied by trust policy condition
```

##### Example 3: Time-Based Access Control

**Trust Policy with Time Restrictions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:manta:iam::123456789012:user/admin"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "DateGreaterThan": {
        "aws:CurrentTime": "09:00:00Z"
      },
      "DateLessThan": {
        "aws:CurrentTime": "17:00:00Z"
      }
    }
  }]
}
```

**Usage:**
```bash
# Works during business hours (9 AM - 5 PM UTC)
aws sts assume-role \
  --role-arn arn:manta:iam::123456789012:role/BusinessHoursRole \
  --role-session-name admin-work \
  --endpoint-url https://manta.example.com

# Fails outside business hours
# Error: Access denied by trust policy condition
```

##### Example 4: IP Address Restrictions

**Trust Policy with Network Controls:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:manta:iam::123456789012:user/sensitive-ops"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "IpAddress": {
        "aws:SourceIp": [
          "192.168.1.0/24",    // Office network
          "10.0.0.100/32"      // VPN gateway
        ]
      }
    }
  }]
}
```

##### Example 5: Role Chaining

**BaseRole Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:manta:iam::123456789012:user/application"
    },
    "Action": "sts:AssumeRole"
  }]
}
```

**ElevatedRole Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:manta:iam::123456789012:role/BaseRole"
    },
    "Action": "sts:AssumeRole"
  }]
}
```

**Usage:**
```bash
# Step 1: Application assumes BaseRole
aws sts assume-role \
  --role-arn arn:manta:iam::123456789012:role/BaseRole \
  --role-session-name app-base \
  --endpoint-url https://manta.example.com

# Step 2: BaseRole assumes ElevatedRole for sensitive operation
aws sts assume-role \
  --role-arn arn:manta:iam::123456789012:role/ElevatedRole \
  --role-session-name elevated-ops \
  --endpoint-url https://manta.example.com
```

#### Permission Policies (What Roles Can Do)

Permission policies define what actions a role can perform on which resources.

**Basic Structure:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": [
      "arn:manta:s3:::my-bucket",
      "arn:manta:s3:::my-bucket/*"
    ]
  }]
}
```

**Supported S3 Actions:**
- `s3:ListAllMyBuckets` - List all buckets
- `s3:ListBucket` - List objects in specific bucket
- `s3:GetObject` - Download objects
- `s3:PutObject` - Upload objects  
- `s3:DeleteObject` - Delete objects
- `s3:GetBucketLocation` - Get bucket information
- `s3:CreateBucket` - Create new buckets
- `s3:DeleteBucket` - Delete empty buckets

**Important:** Conditions in permission policies are **not implemented** - only Action/Resource matching works.

#### Session Token Format (JWT Implementation)

STS returns temporary credentials with cryptographically signed JWT session tokens:

```json
{
  "Credentials": {
    "AccessKeyId": "EXAMPLE-TEMP-ACCESS-KEY-ID",
    "SecretAccessKey": "ExampleTempSecretKey7890123456",
    "SessionToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiZXhhbXBsZS0xMjM0LWVmZ2gtNTY3OCIsInJvbGVBcm4iOiJhcm46bWFudGE6aWFtOjoxMjM0NTY3ODkwMTI6cm9sZS9SZWFkT25seUFjY2VzcyIsInNlc3Npb25OYW1lIjoiYWxpY2UtZGF0YS1hbmFseXNpcyIsInRva2VuVHlwZSI6InN0cy1zZXNzaW9uIiwidG9rZW5WZXJzaW9uIjoiMS4xIiwia2V5SWQiOiJrZXktMjAyNTAxMjAtYTFiMmMzZDQiLCJpc3MiOiJtYW50YS1tYWhpIiwiYXVkIjoibWFudGEtczMiLCJpYXQiOjE3MDUzMTU4MDAsImV4cCI6MTcwNTMxOTQwMCwibmJmIjoxNzA1MzE1ODAwfQ.ExampleSignatureHash1234567890",
    "Expiration": "2024-01-15T11:30:00Z"
  },
  "AssumedRoleUser": {
    "AssumedRoleId": "AROA123EXAMPLE123:session-name",
    "Arn": "arn:manta:sts::123456789012:assumed-role/RoleName/session-name"
  }
}
```

**JWT Session Token Structure:**

The session token is a cryptographically signed JWT (JSON Web Token) with HMAC-SHA256 signature containing:

```json
{
  "uuid": "example-1234-efgh-5678",
  "roleArn": "arn:manta:iam::123456789012:role/ReadOnlyAccess", 
  "sessionName": "alice-data-analysis",
  "tokenType": "sts-session",
  "tokenVersion": "1.1",
  "keyId": "key-20250120-a1b2c3d4",
  "iss": "manta-mahi",
  "aud": "manta-s3",
  "iat": 1705315800,
  "exp": 1705319400,
  "nbf": 1705315800
}
```

**JWT Security Features:**
- **HMAC-SHA256 Signature** - Cryptographically signed, tamper-proof
- **Key Rotation Support** - `keyId` field enables seamless secret rotation
- **Standard JWT Claims** - `iss`, `aud`, `iat`, `exp`, `nbf` for validation
- **Token Versioning** - Version 1.1 with enhanced security features
- **Auto-Expiration** - Tokens expire automatically (default 1 hour)

#### Tested Implementation Status

**✅ Fully Implemented and Tested:**
- Trust policy evaluation with all condition operators
- Principal matching (user, role, root, wildcard)
- External ID validation
- Time-based access control
- IP address restrictions
- Role chaining
- Multi-cloud ARN support (aws/manta/triton)
- JWT session tokens with HMAC-SHA256 signatures
- Key rotation for session tokens
- Basic permission policy evaluation

**❌ Not Implemented:**
- Conditions in permission policies
- S3-specific condition keys
- Service principals (not applicable to Manta)
- Cross-account access (single account model)

### Permission Policy Support

**Supported S3 Actions:**
```json
{
  "Version": "2012-10-17", 
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:PutObject", 
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "s3:CreateBucket",
      "s3:DeleteBucket"
    ],
    "Resource": [
      "arn:aws:s3:::my-bucket",
      "arn:aws:s3:::my-bucket/*"  
    ]
  }]
}
```

### AWS CLI Workflow Examples

#### 1. Read-Only S3 Access
```bash
# Create read-only role
aws iam create-role --role-name S3ReadOnly \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow", 
      "Principal": {"AWS": "arn:aws:iam::123456789012:user/developer"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach read-only policy
aws iam put-role-policy --role-name S3ReadOnly --policy-name ReadPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::data-bucket", "arn:aws:s3:::data-bucket/*"]
    }]
  }'

# Assume role and get credentials  
CREDS=$(aws sts assume-role --role-arn arn:aws:iam::123456789012:role/S3ReadOnly \
  --role-session-name read-session --output json)

# Extract and export credentials
export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.Credentials.SecretAccessKey') 
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Credentials.SessionToken')

# Use temporary credentials for S3 operations
aws s3 ls s3://data-bucket/
aws s3 cp s3://data-bucket/file.txt ./
```

#### 2. Deployment Role with Time Limits
```bash
# Create deployment role (expires in 1 hour)
aws iam create-role --role-name DeploymentRole \
  --assume-role-policy-document file://deployment-trust.json

aws iam put-role-policy --role-name DeploymentRole --policy-name DeployPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow", 
      "Action": ["s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::deploy-bucket/*"]
    }]
  }'

# Get temporary credentials with custom duration
DEPLOY_CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/DeploymentRole \
  --role-session-name deploy-$(date +%s) \
  --duration-seconds 3600)

# Deploy using temporary credentials
export AWS_ACCESS_KEY_ID=$(echo $DEPLOY_CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $DEPLOY_CREDS | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $DEPLOY_CREDS | jq -r '.Credentials.SessionToken')

aws s3 sync ./build/ s3://deploy-bucket/releases/v1.2.3/
```

#### 3. Environment-Specific Access
```bash
# Production access role
aws iam create-role --role-name ProductionAccess \
  --assume-role-policy-document file://prod-trust.json

aws iam put-role-policy --role-name ProductionAccess --policy-name ProdPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::prod-data",
        "arn:aws:s3:::prod-data/*",
        "arn:aws:s3:::prod-backups", 
        "arn:aws:s3:::prod-backups/*"
      ]
    }]
  }'

# Staging access role  
aws iam create-role --role-name StagingAccess \
  --assume-role-policy-document file://staging-trust.json

aws iam put-role-policy --role-name StagingAccess --policy-name StagingPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow", 
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::staging-data",
        "arn:aws:s3:::staging-data/*"
      ]
    }]
  }'

# Switch between environments
function assume_env_role() {
  local env=$1
  local role_arn="arn:aws:iam::123456789012:role/${env}Access"
  
  echo "Assuming role for $env environment..."
  CREDS=$(aws sts assume-role --role-arn $role_arn \
    --role-session-name ${env}-session-$(whoami))
  
  export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.Credentials.AccessKeyId')
  export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.Credentials.SecretAccessKey')
  export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Credentials.SessionToken')
  
  echo "Switched to $env environment"
}

# Usage
assume_env_role "Production" 
aws s3 ls s3://prod-data/

assume_env_role "Staging"
aws s3 ls s3://staging-data/
```

#### 4. Automated Credential Management
```bash
#!/bin/bash
# auto-assume-role.sh - Automatic credential refresh script

ROLE_ARN="arn:aws:iam::123456789012:role/AutomationRole"
SESSION_NAME="automation-$(date +%s)"
CREDENTIALS_FILE="/tmp/aws-temp-creds"

# Function to get fresh credentials
get_credentials() {
  echo "Getting fresh STS credentials..."
  aws sts assume-role \
    --role-arn $ROLE_ARN \
    --role-session-name $SESSION_NAME \
    --duration-seconds 3600 > $CREDENTIALS_FILE
    
  if [ $? -eq 0 ]; then
    export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' < $CREDENTIALS_FILE)
    export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' < $CREDENTIALS_FILE) 
    export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' < $CREDENTIALS_FILE)
    echo "Credentials updated successfully"
  else
    echo "Failed to get credentials"
    exit 1
  fi
}

# Function to check if credentials are expired
check_credentials() {
  if [ ! -f $CREDENTIALS_FILE ]; then
    return 1
  fi
  
  EXPIRATION=$(jq -r '.Credentials.Expiration' < $CREDENTIALS_FILE)
  EXPIRATION_EPOCH=$(date -d "$EXPIRATION" +%s)
  CURRENT_EPOCH=$(date +%s)
  
  # Refresh if less than 5 minutes remaining
  if [ $((EXPIRATION_EPOCH - CURRENT_EPOCH)) -lt 300 ]; then
    return 1
  fi
  
  return 0
}

# Main automation loop
while true; do
  if ! check_credentials; then
    get_credentials
  fi
  
  # Perform S3 operations
  aws s3 sync s3://source-bucket/ ./local-data/
  aws s3 sync ./processed-data/ s3://destination-bucket/
  
  sleep 600  # Wait 10 minutes before next sync
done
```

### Migration from AWS to Manta

#### Pattern 1: Direct Credential Migration
**AWS Workflow:**
```bash
# AWS - Using permanent credentials
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
aws s3 cp file.txt s3://my-bucket/
```

**Manta Equivalent:**  
```bash
# Manta - Using permanent credentials
export AWS_ACCESS_KEY_ID="tdc_permanent_access_key_example"
export AWS_SECRET_ACCESS_KEY="tdc_permanent_secret_key_example"
aws s3 cp file.txt s3://my-bucket/ --endpoint-url https://manta.example.com
```

#### Pattern 2: Role-Based Access Migration
**AWS Workflow:**
```bash
# AWS - Assume role workflow
aws sts assume-role --role-arn arn:aws:iam::123:role/S3Access \
  --role-session-name session1

# Use returned temporary credentials...
```

**Manta Equivalent:**
```bash  
# Manta - Same assume role workflow
aws sts assume-role --role-arn arn:aws:iam::123:role/S3Access \
  --role-session-name session1 --endpoint-url https://manta.example.com

# Use returned temporary credentials with Manta endpoint...
export AWS_ACCESS_KEY_ID="tdc_SU4xWXL-HzrMIDM_A8GH94sl-uc-aX8mqsEMiK4JSVdAGyjH"
export AWS_SECRET_ACCESS_KEY="tdc_9k3jF8mN2pL5qR7sT1vY6zA8bC4eG7iJ0mP3rU5xW9yB2dF"
export AWS_SESSION_TOKEN="eyJ1dWlkIjoiYWJjZC0xMjM0LWVmZ2gtNTY3OCIsImV4cGlyZXMiOjE2OTg0NTM2MDB9"

aws s3 ls --endpoint-url https://manta.example.com
```

#### Pattern 3: Policy Translation
**AWS Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:PutObject", 
      "s3:ListBucket"
    ],
    "Resource": [
      "arn:aws:s3:::production-bucket",
      "arn:aws:s3:::production-bucket/*"
    ]
  }]
}
```

**Manta Policy (identical):**
```json
{
  "Version": "2012-10-17", 
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket"
    ],
    "Resource": [
      "arn:aws:s3:::production-bucket", 
      "arn:aws:s3:::production-bucket/*"
    ]
  }]
}
```

#### Pattern 4: Multi-Environment Migration
**Migration Strategy:**
```bash
# 1. Create equivalent roles in Manta
aws iam create-role --role-name DevRole \
  --assume-role-policy-document file://trust.json \
  --endpoint-url https://manta.example.com

# 2. Migrate policies exactly as-is  
aws iam put-role-policy --role-name DevRole \
  --policy-name DevS3Access --policy-document file://dev-policy.json \
  --endpoint-url https://manta.example.com

# 3. Update scripts to use Manta endpoint
sed -i 's/aws s3/aws s3 --endpoint-url https:\/\/manta.example.com/g' deploy.sh
sed -i 's/aws sts/aws sts --endpoint-url https:\/\/manta.example.com/g' deploy.sh

# 4. Test with same role assumption workflow
aws sts assume-role --role-arn arn:aws:iam::123:role/DevRole \
  --role-session-name migration-test \
  --endpoint-url https://manta.example.com
```

### Error Handling

Common STS IAM errors mapped to S3-compatible responses:

| Error Condition | HTTP Code | Error Code | Message |
|-----------------|-----------|------------|---------|
| Role not found | 404 | NoSuchEntity | Role does not exist |
| Invalid policy JSON | 400 | MalformedPolicyDocument | Policy document is malformed |
| Duplicate role name | 409 | EntityAlreadyExists | Role already exists |
| Session token expired | 403 | TokenRefreshRequired | Session token has expired |
| Invalid session token | 403 | InvalidToken | Session token is invalid |

### Configuration

**Required Environment Variables:**
```bash
# Mahi endpoint for IAM operations
MAHI_URL=https://mahi.example.com

# Redis configuration for session storage  
REDIS_HOST=redis.example.com
REDIS_PORT=6379

# UFDS integration for credential generation
UFDS_URL=ldaps://ufds.example.com
UFDS_BIND_DN=cn=root
UFDS_BIND_PASSWORD=secret
```

**Session Configuration:**
```javascript
{
  "sts": {
    "sessionDuration": 3600,        // 1 hour default
    "maxSessionDuration": 43200,    // 12 hour maximum  
    "cleanupInterval": 300,         // 5 minute cleanup
    "sessionTokenPrefix": "session_"
  }
}
```

### Security Considerations

#### Least Privilege Principle

- Grant minimum required permissions for specific use cases
- Use bucket-scoped patterns instead of global wildcards
- Regularly audit and review user permissions

#### Access Key Management

- Generate separate access keys for each subuser
- Rotate access keys regularly
- Monitor access key usage and deactivate unused keys

#### Role Inheritance and Conflicts

- Users can have multiple roles with overlapping permissions
- Permission evaluation follows allow-first policy
- More specific permissions take precedence over wildcards

### Troubleshooting RBAC Issues

#### Common Permission Problems

1. **Empty activeRoles**
   ```
   Problem: User not in default_members
   Solution: Add user to role's default_members array
   ```

2. **Bucket-scoped permissions not working**
   ```
   Problem: Resource name mismatch
   Solution: Ensure patterns use bucket/object format
   ```

3. **403 Forbidden despite correct permissions**
   ```
   Problem: Role/policy propagation delay
   Solution: Wait 5-10 seconds after changes
   ```

#### Debugging Authorization

The system provides detailed logging for authorization decisions:

```javascript
// Example authorization log output
{
  "activeRoles": ["100db4d0-67e3-44ba-a104-db53081d9b61"],
  "action": "getobject", 
  "resource": "test-bucket/file.txt",
  "caller": "s3qa",
  "decision": "allow",
  "matchedRule": "CAN getobject test-bucket/*"
}
```
