# Manta S3 Presigned URLS

Manta Buckets API supports S3 presigned URLs, which allow you to grant temporary access to objects without requiring AWS credentials. This is useful for sharing files securely or integrating with web applications.

## How S3 Presigned URLs Work

S3 presigned URLs provide secure, time-limited access to objects by embedding authentication information directly in the URL. Here's how the process works:

1. **URL Generation**: A user with valid access keys generates a presigned URL using AWS CLI or SDK
2. **Cryptographic Signing**: The URL contains AWS SigV4 signature that validates the request 
3. **Request Validation**: Manta validates the signature against the original request parameters
4. **Secure Access**: If valid, the request is processed using the signer's permissions

## Security Features

- **Time-bound**: URLs expire after the specified duration (1 hour to 7 days)
- **Method-specific**: URLs are tied to specific HTTP operations (GET, PUT, etc.)
- **Tamper-proof**: Any modification to the URL invalidates the signature
- **Permission-scoped**: Access is limited to the signer's actual permissions

## Generating Presigned URLs

### For Object Downloads (GET)

```bash
# Generate a presigned URL for downloading (valid for 1 hour)
aws s3 presign s3://test-bucket/file.txt \
    --endpoint-url https://your-manta-endpoint \
    --expires-in 3600

# Output: 
# https://your-manta-endpoint/test-bucket/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=your-access-key%2F20250926%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250926T220000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=...
```

### For Object Uploads (PUT)

```bash
# Generate a presigned URL for uploading (valid for 2 hours)
aws s3 presign s3://test-bucket/new-file.txt \
    --endpoint-url https://your-manta-endpoint \
    --expires-in 7200

# Use the URL with curl to upload
curl -X PUT -T local-file.txt "https://your-manta-endpoint/test-bucket/new-file.txt?X-Amz-Algorithm=..."
```

## Using Presigned URLs

### Simple Download

```bash
# Anyone with the URL can download the file (no AWS credentials needed)
curl "https://your-manta-endpoint/test-bucket/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=..." \
    -o downloaded-file.txt
```

### Browser Access

Presigned URLs work directly in web browsers:

```html
<!-- Direct link for downloads -->
<a href="https://your-manta-endpoint/test-bucket/file.txt?X-Amz-Algorithm=...">Download File</a>

<!-- Image display -->
<img src="https://your-manta-endpoint/test-bucket/image.jpg?X-Amz-Algorithm=..." />
```

### Web Application Integration

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

## Advanced Options

### Custom Expiration Times

```bash
# Short-lived URL (15 minutes)
aws s3 presign s3://bucket/file.txt --expires-in 900 --endpoint-url https://your-manta-endpoint

# Long-lived URL (7 days - maximum)
aws s3 presign s3://bucket/file.txt --expires-in 604800 --endpoint-url https://your-manta-endpoint
```

### Content-Type Specification

```bash
# For uploads with specific content type
aws s3 presign s3://bucket/image.jpg \
    --endpoint-url https://your-manta-endpoint \
    --expires-in 3600 \
    --content-type "image/jpeg"
```

## Implementation Details

### Signature Validation Process

1. **Parameter Extraction**: Manta extracts signature components from query parameters
2. **Request Reconstruction**: The original signed request is reconstructed for validation
3. **Cryptographic Verification**: AWS SigV4 signature is validated using Mahi's authentication service
4. **Authorization Check**: User permissions are verified against Manta's RBAC system
5. **Request Processing**: If valid, the request proceeds through normal Manta authorization

### Supported Operations

| Operation | Method | Description | Example Use Case |
|-----------|--------|-------------|------------------|
| **GetObject** | GET | Download files | File sharing, web content delivery |
| **PutObject** | PUT | Upload files | Web form uploads, direct browser uploads |
| **HeadObject** | HEAD | Get metadata | File existence checks, size validation |

## Troubleshooting Presigned URLs

### Common Issues

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

### Debugging Tips

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

## Security Best Practices

1. **Minimize Expiration Time**: Use the shortest reasonable expiration time
2. **Secure Distribution**: Share URLs over HTTPS only
3. **Monitor Access**: Log and monitor presigned URL usage
4. **Rotate Access Keys**: Regularly rotate AWS access keys used for signing
5. **Validate Permissions**: Ensure signers have only necessary permissions
