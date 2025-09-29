# S3 Compatibility Testing Guide

This guide explains how to run the comprehensive S3 compatibility test suites for manta-buckets-api, covering both AWS CLI and s3cmd client compatibility.

## Overview

The test suites validate S3 API compatibility across multiple clients and scenarios:
- **Basic CRUD operations** (Create, Read, Update, Delete)
- **Multipart upload functionality** including resume scenarios
- **Error handling and edge cases**
- **Performance and reliability testing**

## Test Suites

### Unit Test Suite (`make test-s3`)

Pure unit tests with mocks that validate S3 functionality without external dependencies.

**Key Features:**
- **Multipart Upload Tests** (`test/s3-multipart.test.js`) - Core MPU functionality
- **Enhanced S3 Compatibility** (`test/s3-compat-enhanced.test.js`) - Advanced S3 operations  
- **Route Handling** (`test/s3-routes.test.js`) - S3 request routing and middleware
- **Role Mapping** (`test/s3-role-mapping.test.js`) - S3 ACL to Manta role translation
- **AWS Chunked Decoding** (`test/aws-chunked-decoder.test.js`) - AWS chunked transfer encoding

**Run Unit Tests:**
```bash
# Run all S3 unit tests
make test-s3

# Or run individual test files
./node_modules/.bin/nodeunit test/s3-multipart.test.js
```

### AWS CLI Test Suite (`test/s3-compat-awscli-test.sh`)

Comprehensive testing using AWS CLI (aws s3api commands) for low-level S3 API operations.

**Key Features:**
- Raw S3 API testing using `aws s3api` commands
- Manual multipart upload part management
- ETag extraction and validation
- Resume functionality testing
- Conditional header testing (If-Match, If-None-Match, etc.)
- Error scenario validation (EntityTooSmall, etc.)
- **S3 Presigned URL testing** (GET operations and expiry validation)

### s3cmd Test Suite (`test/s3-compat-s3cmd-test.sh`)

High-level testing using s3cmd client for real-world usage scenarios.

**Key Features:**
- S3cmd client compatibility testing
- Automatic multipart upload handling
- Resume capability validation
- Error handling verification
- Performance optimization testing

## Environment Variables

Both test suites support the same environment variables for configuration:

### Required Variables
None - all variables have sensible defaults for local testing.

### Optional Configuration Variables

| Variable | Default Value | Description |
|----------|---------------|-------------|
| `AWS_ACCESS_KEY_ID` | `AKIA123456789EXAMPLE` | AWS access key for authentication |
| `AWS_SECRET_ACCESS_KEY` | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | AWS secret key for authentication |
| `S3_ENDPOINT` | `https://localhost:8080` | S3 endpoint URL |
| `AWS_REGION` | `us-east-1` | AWS region |
| `AWS_DEFAULT_REGION` | `us-east-1` | Default AWS region |

### Example Custom Configuration
```bash
# Test against remote manta-buckets-api instance
export S3_ENDPOINT="https://manta.example.com:8080"
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"

# Run tests
./test/s3-compat-awscli-test.sh
```

## Prerequisites

### System Requirements
- **AWS CLI**: Version 2.0+ with JSON output support
- **s3cmd**: Version 2.0+ for s3cmd tests
- **jq**: JSON processor for parsing responses
- **json**: Node.js json tool (`npm install -g json`)
- **curl**: For HTTP requests
- **Basic Unix tools**: grep, sed, awk, dd, md5sum

### Install Dependencies

#### macOS (Homebrew)
```bash
brew install awscli s3cmd jq
npm install -g json
```

#### Ubuntu/Debian
```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscli.zip"
unzip awscli.zip && sudo ./aws/install

# Other tools
sudo apt-get update
sudo apt-get install s3cmd jq nodejs npm
sudo npm install -g json
```

#### RHEL/CentOS
```bash
# AWS CLI (same as Ubuntu)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscli.zip"
unzip awscli.zip && sudo ./aws/install

# Other tools
sudo yum install epel-release
sudo yum install s3cmd jq nodejs npm
sudo npm install -g json
```

## Running Tests

### AWS CLI Test Suite

#### Run All Tests
```bash
cd /path/to/manta-buckets-api
./test/s3-compat-awscli-test.sh
```

#### Run Specific Test Categories
```bash
# Run only multipart upload tests
./test/s3-compat-awscli-test.sh mpu

# Run only basic CRUD tests  
./test/s3-compat-awscli-test.sh basic

# Run only error handling tests
./test/s3-compat-awscli-test.sh errors

# Run only presigned URL tests
./test/s3-compat-awscli-test.sh presigned

# Run only ACL tests
./test/s3-compat-awscli-test.sh acl

# Run all tests (explicit)
./test/s3-compat-awscli-test.sh all
```

#### Help and Options
```bash
# Show help and usage
./test/s3-compat-awscli-test.sh --help
```

### s3cmd Test Suite

#### Run All Tests
```bash
cd /path/to/manta-buckets-api
./test/s3-compat-s3cmd-test.sh
```

#### Help and Options
```bash
# Show help and usage  
./test/s3-compat-s3cmd-test.sh --help
```

## Test Scenarios Covered

### AWS CLI Test Suite

#### Basic Operations
- ✅ **List Buckets**: Validate bucket listing functionality
- ✅ **Create Bucket**: Test bucket creation with proper error handling
- ✅ **Put Object**: Upload objects with content validation
- ✅ **List Objects**: Verify object listing within buckets
- ✅ **Get Object**: Download and content verification
- ✅ **Delete Object**: Object removal with confirmation
- ✅ **Delete Bucket**: Bucket cleanup validation

#### Multipart Upload Tests
- ✅ **Basic MPU**: Complete multipart upload flow with ETag extraction
- ✅ **MPU Resume**: Interrupt and resume multipart uploads
- ✅ **Error Handling**: EntityTooSmall validation for undersized parts

#### Advanced Features
- ✅ **Conditional Headers**: If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since
- ✅ **Error Scenarios**: Non-existent bucket/object handling
- ✅ **ETag Validation**: Content integrity verification
- ✅ **S3 Presigned URLs**: GET presigned URL generation and usage validation
- ✅ **ACL Operations**: Bucket and object ACL management and canned ACL support

### s3cmd Test Suite

#### Basic Operations
- ✅ **List Buckets**: s3cmd ls functionality
- ✅ **Create Bucket**: s3cmd mb command
- ✅ **Put Object**: s3cmd put with content verification
- ✅ **List Objects**: s3cmd ls bucket contents
- ✅ **Get Object**: s3cmd get with integrity checks
- ✅ **Delete Object**: s3cmd rm functionality
- ✅ **Delete Bucket**: s3cmd rb command

#### Multipart Upload Tests
- ✅ **Basic MPU**: Large file upload with automatic multipart chunking
- ✅ **MPU Resume**: Simulated interruption and resume testing
- ✅ **Error Handling**: Part size validation and error detection

#### Error Scenarios
- ✅ **Non-existent Resources**: Bucket and object error handling
- ✅ **Access Permissions**: Authentication and authorization testing

## Expected Test Results

### Successful Test Run
```
=================================================================
S3 Compatibility Test Results Summary
=================================================================
Tests Passed: 18
Tests Failed: 0

🎉 All tests passed! S3 compatibility is working correctly.
```

### Common Test Failures and Solutions

#### 1. Connection Refused
```
ERROR: Connection to localhost:8080 refused
```
**Solution**: Ensure manta-buckets-api is running on the configured endpoint.

#### 2. Authentication Failures
```
ERROR: Access Denied
```  
**Solution**: Verify AWS credentials are correctly configured in the server.

#### 3. Tool Missing
```
ERROR: jq not found
ERROR: json command not found
```
**Solution**: Install missing dependencies as shown in Prerequisites section.

#### 4. SSL Certificate Issues
```
ERROR: SSL certificate verify failed
```
**Solution**: Tests use `--no-verify-ssl` and `--no-check-certificate` flags for localhost testing.

## S3 Presigned URL Testing

The test suites include comprehensive validation of S3 presigned URL functionality, which allows generating time-limited URLs for S3 operations without requiring AWS credentials in the request.

### AWS CLI Presigned URL Tests (`presigned` test category)

#### Features Tested
- ✅ **GET Presigned URLs**: Generated using `aws s3 presign` command
- ✅ **URL Validation**: Verify presigned URLs work with curl/HTTP clients
- ✅ **Content Integrity**: Downloaded content matches uploaded content
- ✅ **Expiry Handling**: Expired URLs are properly rejected with 403/400 status
- ✅ **Authentication Bypass**: Presigned URLs work without additional credentials

#### Running Presigned URL Tests
```bash
# Run only presigned URL tests
./test/s3-compat-awscli-test.sh presigned

# Example output for successful presigned URL test
✅ AWS CLI presigned URL - Generated GET presigned URL
✅ AWS CLI presigned GET - Successfully downloaded using presigned URL  
✅ AWS CLI presigned GET - Downloaded content matches original
✅ Presigned URL expiry - Expired URL properly rejected
```

#### Test Workflow
1. **Upload Test Object**: Create object using standard authenticated API
2. **Generate Presigned URL**: Use `aws s3 presign` with configurable expiry
3. **Test Valid URL**: Download object using presigned URL with curl
4. **Verify Content**: Ensure downloaded content matches original
5. **Test Expiry**: Generate short-lived URL and verify rejection after expiry
6. **Cleanup**: Remove test objects and validate cleanup

### Manual S3v4 Presigned URL Tests (`test/manual-presigned-url-test.sh`)

For comprehensive presigned URL testing including PUT operations (which AWS CLI doesn't support natively), use the manual test script.

#### Features Tested
- ✅ **PUT Presigned URLs**: Manual S3v4 signature generation for uploads
- ✅ **GET Presigned URLs**: Manual S3v4 signature generation for downloads
- ✅ **Signature Validation**: Proper AWS Signature v4 implementation
- ✅ **Expiry Validation**: Invalid and expired URL rejection
- ✅ **Content Upload/Download**: Full round-trip testing via presigned URLs

#### Running Manual Presigned URL Tests
```bash
# Run complete manual presigned URL test suite
./test/manual-presigned-url-test.sh

# Example output for successful tests
✅ S3v4 presigned PUT - Object uploaded successfully
✅ S3v4 presigned GET - Downloaded content matches uploaded content
✅ Expired presigned URL - Properly rejected expired URL
✅ Invalid signature URL - Properly rejected invalid signature
```

#### Manual Test Workflow
1. **Create Test Bucket**: Set up isolated test environment
2. **Generate PUT Presigned URL**: Manual AWS SigV4 signature calculation
3. **Upload via Presigned URL**: Use curl to upload content
4. **Generate GET Presigned URL**: Create download URL with fresh signature
5. **Download and Verify**: Ensure content integrity through full cycle
6. **Test Edge Cases**: Invalid signatures, expired URLs, malformed requests
7. **Cleanup**: Remove all test artifacts

### Presigned URL Security Validation

Both test suites validate critical security aspects:

#### Signature Validation
- ✅ **Valid Signatures**: Properly constructed URLs succeed
- ✅ **Invalid Signatures**: Malformed or incorrect signatures fail with 403
- ✅ **Tampered URLs**: Modified query parameters are rejected

#### Expiry Handling  
- ✅ **Valid Time Window**: URLs within expiry time succeed
- ✅ **Expired URLs**: Past expiry time results in 403/400 errors
- ✅ **Future Expiry**: Long-lived URLs work within time bounds

#### Authentication Bypass
- ✅ **No Credentials Required**: Presigned URLs work without AWS headers
- ✅ **Proper Authorization**: Valid signatures grant appropriate access
- ✅ **Access Control**: Invalid/expired URLs properly deny access

### Troubleshooting Presigned URL Tests

#### Common Issues and Solutions

**1. Signature Mismatch Errors**
```
ERROR: Invalid signature: Signature mismatch
```
- Verify system clock is synchronized (signature includes timestamp)
- Check AWS credentials match between client and server
- Ensure proper URL encoding of query parameters

**2. Expired URL Errors** 
```
ERROR: Request has expired
```
- Verify system time is correct on both client and server
- Check if URL expiry time is reasonable for test execution
- Ensure no delays between URL generation and usage

**3. SSL/TLS Issues with Presigned URLs**
```
ERROR: SSL certificate verify failed
```
- Tests use `--insecure` flag for localhost testing
- For production testing, ensure proper SSL certificates
- Verify endpoint URL matches SSL certificate

**4. Content Integrity Failures**
```
ERROR: Downloaded content doesn't match uploaded content
```
- Check for encoding issues (binary vs text handling)
- Verify no proxy/gateway modifications to content
- Ensure proper content-type handling

## Test Data and Cleanup

### Temporary Files
Tests create temporary files and buckets:
- **Test buckets**: `s3-compat-test-*`, `mpu-test-*`, `mpu-resume-test-*`
- **Test files**: Generated in `/tmp/s3-compat-test/` directory
- **Multipart files**: 4MB-15MB test files for multipart scenarios

### Automatic Cleanup
Both test suites include comprehensive cleanup:
- **Trap handlers**: Clean up on script exit or interruption
- **Failed test cleanup**: Remove partial resources on test failures  
- **Temporary file removal**: Clean up local test files
- **Bucket cleanup**: Remove test buckets and contents

### Manual Cleanup (if needed)
```bash
# List any remaining test buckets
aws s3 ls --endpoint-url=https://localhost:8080

# Remove test buckets manually
aws s3 rb s3://test-bucket-name --force --endpoint-url=https://localhost:8080

# Clean temporary directory
rm -rf /tmp/s3-compat-test /tmp/s3cmd-compat-test
```

## Performance Expectations

### AWS CLI Test Suite
- **Total runtime**: 30-60 seconds for all tests
- **Individual operations**: 1-3 seconds each
- **Large file tests**: 5-15 seconds depending on file size

### s3cmd Test Suite  
- **Total runtime**: 45-90 seconds for all tests
- **Individual operations**: 2-5 seconds each
- **Multipart uploads**: 10-30 seconds depending on file size

## Debugging Test Failures

### Enable Debug Output
```bash
# For AWS CLI tests (verbose AWS CLI output)
AWS_DEBUG=1 ./test/s3-compat-awscli-test.sh

# For s3cmd tests (verbose s3cmd output)
./test/s3-compat-s3cmd-test.sh --debug
```

### Check Server Logs
```bash
# Monitor manta-buckets-api logs during test execution
tail -f $(svcs -L buckets-api) | grep -E "(S3_MPU|ERROR|WARN)"
```

### Common Debug Steps
1. **Verify endpoint connectivity**: `curl -k https://localhost:8080/`
2. **Check credentials**: Ensure AWS credentials are properly configured
3. **Validate dependencies**: Confirm all required tools are installed
4. **Review test output**: Look for specific error messages in test logs
5. **Check server logs**: Review server-side errors and warnings

