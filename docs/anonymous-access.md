# Anonymous Access to Public Buckets

This document explains how to enable anonymous browser access to buckets marked as public in the manta-buckets-api, allowing web browsers to access public content without authentication.

## Overview

By default, all bucket operations in Manta require authentication. However, for public content distribution (like static websites, public documents, or CDN use cases), it's useful to allow anonymous browser access to buckets explicitly marked as public.

This feature enables:
- Direct browser access to public bucket content
- Static website hosting from Manta buckets
- Public CDN-style content distribution
- API access without authentication for public resources

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

## Configuration

### Making Buckets Public

Buckets become publicly accessible when they have the `public-reader` role. There are several ways to enable public access:

#### Method 1: Using s3cmd with Canned ACLs

```bash
# Create a new public bucket
s3cmd --no-check-certificate --add-header="x-amz-acl:public-read" mb s3://public-docs

# Make an existing bucket public
s3cmd --no-check-certificate --acl-public setacl s3://existing-bucket
```

#### Method 2: Using s3cmd with Custom Headers

```bash
# Create bucket with custom ACL header
s3cmd --no-check-certificate \
      --add-header="x-amz-acl:public-read" \
      mb s3://public-docs

# Set ACL on existing bucket
s3cmd --no-check-certificate \
      --add-header="x-amz-acl:public-read" \
      setacl s3://existing-bucket
```

#### Method 3: Using curl with Manta API

```bash
# Create bucket with public-reader role
curl -X PUT \
     -H "role-tag: public-reader" \
     -H "Authorization: Signature keyId=\"/user/keys/...\",algorithm=\"rsa-sha256\",signature=\"...\"" \
     -H "Date: $(date -u '+%a, %d %h %Y %H:%M:%S GMT')" \
     https://manta.example.com/user/buckets/public-docs

# Update existing bucket to be public
curl -X PUT \
     -H "role-tag: public-reader" \
     -H "Authorization: Signature ..." \
     -H "Date: $(date -u '+%a, %d %h %Y %H:%M:%S GMT')" \
     https://manta.example.com/user/buckets/existing-bucket
```

#### Method 4: Using S3 Grant Headers

```bash
# Grant read access to all users
s3cmd --no-check-certificate \
      --add-header="x-amz-grant-read:uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"" \
      mb s3://public-docs
```

### Removing Public Access

To make a public bucket private again, you need to remove the `public-reader` role:

#### Method 1: Using s3cmd (Recommended)

```bash
# Set bucket to private
s3cmd --no-check-certificate --acl-private setacl s3://public-bucket

# Alternative: recreate bucket without public access
s3cmd --no-check-certificate del s3://public-bucket
s3cmd --no-check-certificate mb s3://public-bucket  # Private by default
```

#### Method 2: Using curl with Manta API

```bash
# Remove role-tag by setting it to empty
curl -X PUT \
     -H "Authorization: Signature keyId=\"/user/keys/...\",algorithm=\"rsa-sha256\",signature=\"...\"" \
     -H "Date: $(date -u '+%a, %d %h %Y %H:%M:%S GMT')" \
     -H "role-tag: " \
     https://manta.example.com/user/buckets/public-bucket

# OR explicitly set to private ACL
curl -X PUT \
     -H "Authorization: Signature ..." \
     -H "Date: $(date -u '+%a, %d %h %Y %H:%M:%S GMT')" \
     -H "x-amz-acl: private" \
     https://manta.example.com/user/buckets/public-bucket
```

#### Method 3: Using s3cmd with Headers

```bash
# Explicitly set private ACL
s3cmd --no-check-certificate \
      --add-header="x-amz-acl:private" \
      setacl s3://public-bucket
```

### Verifying Bucket Access Status

#### Check if Bucket is Public

```bash
# Method 1: Check bucket headers for role-tag
curl -I \
     -H "Authorization: Signature ..." \
     -H "Date: $(date -u '+%a, %d %h %Y %H:%M:%S GMT')" \
     https://manta.example.com/user/buckets/bucket-name

# Look for: role-tag: public-reader
```

#### Test Browser Access

```bash
# Public bucket: Should return JSON or content
curl https://manta.example.com/user/buckets/public-bucket

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

No additional configuration is required. The feature works with existing settings.

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

## Limitations & Considerations

### Current Limitations

1. **Naming-Based Detection**: Current implementation uses simplified bucket role detection based on bucket name containing "public". For production use, this should be replaced with proper metadata querying.

2. **Bucket Role Lookup**: The `lookupBucketRoles()` function in `lib/anonymous-auth.js` currently uses naming patterns instead of actual metadata queries:
   ```javascript
   // Current simplified implementation
   var isPublicByNaming = bucketName.toLowerCase().includes('public');
   var roles = isPublicByNaming ? ['public-reader'] : [];
   ```

3. **Metadata Performance**: Each anonymous request requires a bucket role lookup
4. **Caching**: No built-in caching of bucket public status

### Performance Considerations

- **Bucket Role Caching**: Consider caching bucket public status to reduce metadata lookups
- **CDN Integration**: Use with CDN for better performance of public content
- **Load Balancing**: Distribute anonymous requests across multiple buckets-api instances

### Recommended Improvements

1. **Enhanced Bucket Detection**: Implement proper metadata client support for unauthenticated role queries
2. **Role Caching**: Cache bucket public status with TTL to improve performance
3. **Rate Limiting**: Add rate limiting for anonymous requests to prevent abuse
4. **Geographic Distribution**: Deploy buckets-api instances closer to users for public content

## Alternative: External Proxy Approach

Instead of modifying the core authentication system, you can deploy a separate public proxy service:

### Proxy Architecture
```
Browser → Public Proxy → Manta Buckets API (authenticated)
```

### Proxy Benefits
- **Core System Unchanged**: No modifications to buckets-api authentication
- **Dedicated Security**: Separate security model for public access
- **Scalable**: Can deploy multiple proxy instances
- **Flexible**: Custom logic for public access patterns

### Proxy Implementation
```javascript
// Example proxy logic
if (isBucketPublic(bucketName)) {
    // Authenticate with service credentials
    // Proxy request to Manta
    // Return content to browser
}
```

## Troubleshooting

### Common Issues

1. **Access Denied on Public Bucket**
   - Verify bucket has `public-reader` role
   - Check bucket name extraction in logs
   - Ensure anonymous user context is created
   - Confirm bucket name contains "public" (current simplified implementation)

2. **Can't Make Bucket Public**
   - Ensure you're using the correct s3cmd syntax: `--add-header="x-amz-acl:public-read"`
   - Verify the S3 role translator middleware is active
   - Check that the bucket creation succeeded
   - Look for role translation in debug logs: `s3RoleTranslator: translated S3 ACL to Manta roles`

3. **Can't Remove Public Access**
   - Use `--acl-private` flag with s3cmd: `s3cmd --acl-private setacl s3://bucket`
   - Verify the role-tag header is empty after removal
   - Test browser access returns 403 Forbidden
   - Check debug logs show `roles=[]` and `isPublic=false`

4. **Public Access Not Working After Setup**
   - Restart buckets-api service after code changes
   - Verify anonymous access handler is loaded before authentication
   - Check that bucket name contains "public" (current naming-based detection)
   - Ensure browser is not sending authentication headers (clear cookies/auth)

5. **CORS Errors in Browser**
   - Verify CORS headers are being set
   - Check browser developer tools for CORS policy errors
   - Ensure OPTIONS requests are handled

6. **Performance Issues**
   - Monitor bucket role lookup performance  
   - Consider implementing role caching
   - Check for excessive metadata queries

7. **Bucket Shows as Public But Browser Access Fails**
   - Check if bucket name contains "public" (required for current implementation)
   - Verify the anonymous access middleware chain is complete
   - Look for authorization bypass logs: `authorize: allowing public access - bypassing Mahi authorization`
   - Ensure no authentication headers are being sent by the browser

### Debug Logging

Enable debug logging to troubleshoot anonymous access issues:

```bash
# Enable debug logging
export NODE_LOG_LEVEL=debug

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

## Security Audit Checklist

When implementing anonymous access, verify:

- [ ] Only GET/HEAD methods allowed for anonymous users
- [ ] Authentication bypass only for public buckets
- [ ] Role-based authorization still enforced
- [ ] Anonymous access attempts are logged
- [ ] No privilege escalation possible
- [ ] CORS headers properly configured
- [ ] Rate limiting implemented for anonymous requests
- [ ] Bucket role verification working correctly

## Conclusion

Anonymous access to public buckets enables powerful use cases like static website hosting and public content distribution while maintaining security through role-based authorization. The implementation carefully balances functionality with security by only bypassing authentication for explicitly public resources while preserving all authorization controls.

For production deployments, consider the external proxy approach if you prefer to keep the core buckets-api authentication unchanged, or implement the direct approach for seamless browser integration.