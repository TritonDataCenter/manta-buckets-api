# Anonymous Access to Public Buckets

This document explains the production-ready anonymous access system in manta-buckets-api, which allows secure browser access to explicitly public buckets without authentication.

## Overview

The anonymous access system is **enabled by default** and provides secure access to public content while maintaining strict security controls. It supports:

- Direct browser access to public bucket content
- Static website hosting from Manta buckets
- Public CDN-style content distribution
- API access without authentication for public resources
- Production-grade security and audit logging

## Architecture

The anonymous access system works by:

1. **Pre-Authentication Check**: Before authentication runs, check if the request targets a public bucket
2. **Anonymous User Context**: Create a temporary user context with `public-reader` role
3. **Bypass Authentication**: Skip signature verification for anonymous public access
4. **Role-Based Authorization**: Still enforce RBAC using the anonymous user's roles
5. **Secure Access**: Only buckets explicitly marked as public are accessible

## Implementation Components

### 1. Anonymous Authentication Module (`lib/anonymous-auth.js`)

This module provides the core functionality for handling anonymous requests:

```javascript
// Key functions:
anonymousAccessHandler()     // Middleware for pre-auth anonymous handling
isPublicResourceRequest()    // Checks if bucket allows public access
createAnonymousUser()        // Creates anonymous user context
extractBucketName()          // Parses bucket name from various URL formats
```

**Anonymous User Context**:
```javascript
{
    account: { uuid: 'anonymous', login: 'anonymous', isAdmin: false },
    user: { uuid: 'anonymous', login: 'anonymous' },
    roles: ['public-reader']  // Has public-reader role for authorization
}
```

### 2. Authentication Handler Modifications (`lib/auth.js`)

The existing authentication pipeline is modified to handle anonymous users:

```javascript
// Skip authentication steps for anonymous access
function checkAuthzScheme(req, res, next) {
    if (req.isAnonymousAccess) {
        next(); // Skip auth scheme validation
        return;
    }
    // ... existing authentication logic
}

function verifySignature(req, res, next) {
    if (req.isAnonymousAccess) {
        next(); // Skip signature verification
        return;
    }
    // ... existing signature verification
}
```

### 3. Server Integration (`lib/server.js`)

The anonymous access handler is integrated into the middleware chain:

```javascript
// Anonymous access handler runs BEFORE authentication
server.use(anonymousAuth.anonymousAccessHandler);

server.use(auth.authenticationHandler({
    log: log,
    mahi: clients.mahi,
    keyapi: clients.keyapi
}));
```

## Request Flow

### Authenticated Request (Existing)
```
Browser → Authentication → Authorization → Bucket Access
```

### Anonymous Public Request (New)
```
Browser → Anonymous Check → Skip Auth → Authorization → Bucket Access
          ↓
    (if public bucket)
```

### Detailed Anonymous Flow

1. **Request Received**: Browser sends `GET /user/buckets/public-docs/objects/readme.txt`
2. **Anonymous Handler**: Checks for authentication headers
   - No auth headers found
   - Extracts bucket name: `public-docs`
3. **Public Bucket Check**: Queries bucket metadata for roles
   - Finds `public-reader` role on bucket
   - Marks request as `req.isAnonymousAccess = true`
4. **Anonymous Context**: Creates anonymous user with `public-reader` role  
5. **Skip Authentication**: Authentication steps detect anonymous flag and skip
6. **Authorization**: RBAC checks if `public-reader` role can access resource
7. **Serve Content**: If authorized, content is returned to browser

## Security Model

### What's Protected
- **Authentication Bypass**: Only for requests to buckets with `public-reader` role
- **Method Restrictions**: Only GET and HEAD methods allowed for anonymous access
- **Role Enforcement**: Authorization still uses RBAC to validate access
- **Audit Logging**: All anonymous access attempts are logged

### What's NOT Changed
- **Private Buckets**: Still require full authentication
- **Write Operations**: Anonymous users cannot modify content
- **Administrative Operations**: Bucket creation, deletion still require auth
- **User Management**: Account operations still require authentication

### Security Considerations

1. **Bucket Role Verification**: The system must verify bucket roles before granting anonymous access
2. **Method Restrictions**: Only safe HTTP methods (GET, HEAD) are allowed
3. **No Privilege Escalation**: Anonymous users cannot gain additional permissions
4. **Audit Trail**: All anonymous access is logged for security monitoring

## Security Model

### Production Security Features

The system includes comprehensive security controls:

#### **1. Strict Bucket Matching**
- Only buckets named exactly `"public"` are accessible by default
- No substring matching (prevents accidental exposure of `my-public-test` buckets)
- Case-sensitive exact matching for maximum security

#### **2. Configuration-Based Controls**
```bash
# Environment variables for production control
MANTA_ANONYMOUS_ACCESS_ENABLED=true           # Anonymous access enabled by default
MANTA_ANONYMOUS_BUCKETS=public                # Allowed bucket names (comma-separated)
MANTA_ANONYMOUS_STRICT_MODE=true              # Strict security mode (default: enabled)
MANTA_ANONYMOUS_RATE_LIMIT=100                # Requests per minute limit (Not implemented)
MANTA_ANONYMOUS_AUDIT_ALL=false               # Audit all attempts (default: disabled)
```

#### **3. Method Restrictions**
- **Allowed**: GET, HEAD operations only
- **Blocked**: POST, PUT, DELETE, and all modification operations
- **Read-Only**: Anonymous users cannot modify any content

#### **4. Audit and Monitoring**
- All anonymous access attempts are logged
- Configurable audit trail with IP addresses and user agents
- Production monitoring integration ready

#### **5. Role-Based Access Control**
- Authorization still enforced through RBAC
- Anonymous users have limited `public-reader` role only
- No privilege escalation possible

### What's Protected

- **Private Buckets**: All non-public buckets require full authentication
- **Write Operations**: Anonymous users cannot modify any content
- **Administrative Operations**: Bucket management still requires authentication
- **Account Operations**: User management requires authentication
- **Metadata Access**: Only explicitly public objects accessible

## Configuration

### System Configuration

#### **Default Configuration** 
```bash
# Anonymous access is enabled by default with secure settings
MANTA_ANONYMOUS_ACCESS_ENABLED=true           # Feature enabled
MANTA_ANONYMOUS_BUCKETS=public                # Only "public" bucket allowed
MANTA_ANONYMOUS_STRICT_MODE=true              # Maximum security
MANTA_ANONYMOUS_RATE_LIMIT=100                # Rate limiting active
MANTA_ANONYMOUS_AUDIT_ALL=false               # Basic audit logging
```

### Public buckets

A Bucket become publicly accessible when it's name public.

```bash
# Create a bucket named exactly "public" 
s3cmd --no-check-certificate mb s3://public

# Upload content to the public bucket
s3cmd --no-check-certificate put document.pdf s3://public/

# Access directly from browser
curl https://manta.example.com/user/buckets/public/objects/document.pdf
```


#### Using Canned ACLs to allow access to objects within buckets.

By default all buckets are private (except a buckets named 'public'), but it is 
possible to allow anonymous access to specific objects inside a bucket.

```bash
# Share an object within a bucket 
s3cmd --no-check-certificate --acl=public-read  s3://mybucket/shareobject.txt
```

### Removing Public Access

To make a public bucket private again, you need to remove the `public-reader` role:

#### Method 1: Using s3cmd (Recommended)

```bash
# Set bucket to private
s3cmd --no-check-certificate --acl-private setacl s3://mybucket/myobject.txt

# Alternative: recreate bucket without public access
s3cmd --no-check-certificate del s3://public-bucket
s3cmd --no-check-certificate mb s3://public-bucket  # Private by default
```

### Verifying Bucket Access Status

#### Check if the Bucket object is public 

```bash
# Method 1: Check bucket headers for role-tag
curl -JOL   https://{manta_endpoint}/{your account}\
    /buckets/{bucket}/objects/myobject.txt
```

#### Test Browser Access

```bash
# Public bucket: Should return JSON or content
curl https://manta.example.com/user/buckets/public

# Private bucket: Should return 403 Forbidden
curl https://manta.example.com/user/buckets/private-bucket
```

#### Check Debug Logs

Enable debug logging to see bucket status:

```bash
# Look for these log messages
grep "Bucket role lookup result" /var/log/buckets-api.log
grep "Anonymous access check result" /var/log/buckets-api.log

# Public bucket logs:
# Bucket role lookup result (bucket=public-bucket, isPublicByNaming=true, roles=["public-reader"])
# Anonymous access check result (isPublic=true)

# Private bucket logs:  
# Bucket role lookup result (bucket=private-bucket, isPublicByNaming=false, roles=[])
# Anonymous access check result (isPublic=false)
```

### Environment Variables

#### **Production Environment Variables**

```bash
# Core Configuration
MANTA_ANONYMOUS_ACCESS_ENABLED=true           # Enable/disable anonymous access (default: true)
MANTA_ANONYMOUS_BUCKETS=public                # Comma-separated list of allowed bucket names
MANTA_ANONYMOUS_STRICT_MODE=true              # Enable strict security mode (default: true)

# Security Controls  
MANTA_ANONYMOUS_RATE_LIMIT=100                # Rate limit per minute (default: 100)
MANTA_ANONYMOUS_AUDIT_ALL=false               # Audit all attempts (default: false)

# Example: Multiple public buckets
MANTA_ANONYMOUS_BUCKETS=public,cdn,assets

# Example: Disable anonymous access entirely
MANTA_ANONYMOUS_ACCESS_ENABLED=false
```

#### **Configuration Validation**

The system logs its configuration on startup:

```
MANTA ANONYMOUS ACCESS ENABLED - Configuration: {
  "enabled": true,
  "allowedBuckets": ["public"],
  "strictMode": true,
  "maxRequestsPerMinute": 100,
  "auditAll": false
}
```

### Browser Access Examples

Once a bucket is marked as public, browsers can access content directly:

```html
<!-- Direct image access -->
<img src="https://manta.example.com/user/buckets/public-images/objects/logo.png">

<!-- Static website hosting -->
<iframe src="https://manta.example.com/user/buckets/public-site/objects/index.html"></iframe>

<!-- Direct download links -->
<a href="https://manta.example.com/user/buckets/public-docs/objects/manual.pdf">
    Download Manual
</a>
```

## CORS Support

For browser-based applications, CORS headers are automatically added:

```javascript
// Automatically added to public bucket responses
'Access-Control-Allow-Origin': '*'
'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS'
'Access-Control-Allow-Headers': 'Content-Type, Range'
```

### Performance Considerations

- **Bucket Role Caching**: Consider caching bucket public status to reduce metadata lookups
- **CDN Integration**: Use with CDN for better performance of public content
- **Load Balancing**: Distribute anonymous requests across multiple buckets-api instances

## Troubleshooting

### Common Issues

1. **Access Denied on Public Bucket**
   - Verify bucket has `public-reader` role
   - Check bucket name extraction in logs
   - Ensure anonymous user context is created
   - Confirm bucket name contains "public" (current simplified implementation)

2. **Can't Remove Public Access**
   - Use `--acl-private` flag with s3cmd: `s3cmd --acl-private setacl s3://bucket`
   - Verify the role-tag header is empty after removal
   - Test browser access returns 403 Forbidden
   - Check debug logs show `roles=[]` and `isPublic=false`

3. **Public Access Not Working After Setup**
   - Restart buckets-api service after code changes
   - Verify anonymous access handler is loaded before authentication
   - Check that bucket name contains "public" (current naming-based detection)
   - Ensure browser is not sending authentication headers (clear cookies/auth)

4. **CORS Errors in Browser**
   - Verify CORS headers are being set
   - Check browser developer tools for CORS policy errors
   - Ensure OPTIONS requests are handled

5. **Bucket is named Public But Browser Access Fails**
   - Check if bucket name is "public" (required for current implementation)
   - Verify the anonymous access middleware chain is complete
   - Look for authorization bypass logs: `authorize: allowing public access - bypassing Mahi authorization`
   - Ensure no authentication headers are being sent by the browser

### Debug Logging

Enable debug logging to troubleshoot anonymous access issues:

```bash
# Enable debug logging
svccfg -s buckets-api setenv LOG_LEVEL debug
svcadm refresh buckets-api

# Check logs for anonymous access
grep "anonymous" /var/log/buckets-api.log
grep "public-reader" /var/log/buckets-api.log
```

### Log Messages to Monitor

```
anonymousAccessHandler: checking for anonymous access
isPublicResourceRequest: bucket has public-reader role
checkAuthzScheme: skipping for anonymous access  
verifySignature: skipping for anonymous access
```
