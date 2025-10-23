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
- **S3 Compatibility** (`test/s3-compat-enhanced.test.js`) - Advanced S3 operations  
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

### Python Boto3 Test Suite (`test/boto3-tests.py`)

Comprehensive testing using Python's official AWS SDK (boto3) for advanced S3 operations and validation.

**Key Features:**
- Official AWS SDK testing for maximum compatibility validation
- Advanced S3 operations (server-side copy, object tagging, presigned URLs)
- Multipart upload with resume simulation
- Pagination testing with large object sets
- Content integrity verification with MD5 validation
- Error handling and edge case testing

### PHP AWS SDK Test Suite (`test/php-s3-tests.php`)

Complete S3 compatibility testing using PHP's AWS SDK for PHP, providing equivalent functionality to the Python boto3 tests.

**Key Features:**
- PHP AWS SDK v3 compatibility testing
- Full CRUD operations with content verification
- Server-side copy operations with metadata handling
- Multipart upload testing with configurable part sizes
- Presigned URL generation and validation (GET/PUT)
- Pagination testing with continuation tokens
- Error handling and authentication testing

## Environment Variables

All test suites support the same environment variables for configuration:

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
brew install awscli s3cmd jq python3 php composer
npm install -g json
```

#### Ubuntu/Debian
```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscli.zip"
unzip awscli.zip && sudo ./aws/install

# Other tools
sudo apt-get update
sudo apt-get install s3cmd jq nodejs npm python3 python3-pip php php-curl php-json composer
sudo npm install -g json

# Python dependencies
pip3 install boto3 requests

# PHP dependencies (for PHP tests)
cd test && composer install
```

#### RHEL/CentOS
```bash
# AWS CLI (same as Ubuntu)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscli.zip"
unzip awscli.zip && sudo ./aws/install

# Other tools
sudo yum install epel-release
sudo yum install s3cmd jq nodejs npm python3 python3-pip php php-curl php-json composer
sudo npm install -g json

# Python dependencies
pip3 install boto3 requests

# PHP dependencies (for PHP tests)
cd test && composer install
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

### Python Boto3 Test Suite

#### Run All Tests
```bash
cd /path/to/manta-buckets-api
python3 test/boto3-tests.py --endpoint-url https://localhost:8080 --bucket test-bucket
```

#### Specific Test Scenarios
```bash
# Test with custom configuration
python3 test/boto3-tests.py \
    --endpoint-url https://manta.example.com \
    --bucket my-test-bucket \
    --region us-west-2 \
    --profile manta-profile \
    --insecure \
    --cleanup

# Test with different object keys
python3 test/boto3-tests.py \
    --endpoint-url https://localhost:8080 \
    --bucket test-bucket \
    --key custom-test-object.txt \
    --mpu-key custom-mpu-test.bin
```

#### Help and Options
```bash
# Show help and usage
python3 test/boto3-tests.py --help
```

### PHP AWS SDK Test Suite

#### Prerequisites
```bash
# Install Composer dependencies (one-time setup)
cd test
composer install
```

#### Run All Tests
```bash
cd /path/to/manta-buckets-api
./test/php-s3-tests.php --endpoint-url https://localhost:8080 --bucket test-bucket
```

#### Specific Test Scenarios
```bash
# Test with custom configuration
./test/php-s3-tests.php \
    --endpoint-url https://manta.example.com \
    --bucket my-test-bucket \
    --region us-west-2 \
    --profile manta-profile \
    --insecure \
    --cleanup

# Test with different object keys
./test/php-s3-tests.php \
    --endpoint-url https://localhost:8080 \
    --bucket test-bucket \
    --key custom-test-object.txt \
    --mpu-key custom-mpu-test.bin
```

#### Help and Options
```bash
# Show help and usage
./test/php-s3-tests.php --help
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

### Python Boto3 Test Suite

#### Basic Operations
- ✅ **List Buckets**: Validate bucket listing functionality with boto3
- ✅ **Create Bucket**: Test bucket creation with region constraints
- ✅ **Put Object**: Upload objects with metadata and content validation
- ✅ **Head Object**: Object metadata retrieval and validation
- ✅ **Get Object**: Download and content integrity verification
- ✅ **Delete Object**: Object removal with confirmation

#### Server-Side Copy Operations
- ✅ **Basic Copy**: Copy objects within bucket with content verification
- ✅ **Preserve Metadata**: Copy with COPY metadata directive
- ✅ **Replace Metadata**: Copy with REPLACE metadata directive and new metadata
- ✅ **Nested Path Copy**: Copy to nested object paths
- ✅ **Large Object Copy**: Performance testing with larger objects
- ✅ **Error Handling**: Copy non-existent objects and error validation

#### Multipart Upload Tests
- ✅ **Basic MPU**: Complete multipart upload flow with MD5 verification
- ✅ **MPU Resume**: Interrupt and resume multipart uploads with part validation
- ✅ **Part Management**: Upload part validation and assembly

#### Advanced Features
- ✅ **List Objects Pagination**: Comprehensive pagination testing with continuation tokens
- ✅ **Presigned URLs**: GET and PUT presigned URL generation and validation
- ✅ **Object Tagging**: Complete object tagging operations (PUT/GET/DELETE tags)
- ✅ **Content Integrity**: MD5 verification for uploads and downloads
- ✅ **Error Scenarios**: Comprehensive error handling and edge cases

### PHP AWS SDK Test Suite

#### Basic Operations
- ✅ **List Buckets**: Validate bucket listing with AWS SDK for PHP
- ✅ **Create Bucket**: Test bucket creation with region support
- ✅ **Put Object**: Upload objects with content verification
- ✅ **Head Object**: Object metadata retrieval and size validation
- ✅ **Get Object**: Download and content integrity verification
- ✅ **Delete Object**: Object removal with confirmation

#### Server-Side Copy Operations
- ✅ **Basic Copy**: Copy objects within bucket with content verification
- ✅ **Preserve Metadata**: Copy with COPY metadata directive validation
- ✅ **Replace Metadata**: Copy with REPLACE metadata directive and new metadata
- ✅ **Error Handling**: Copy non-existent objects and proper error handling

#### Multipart Upload Tests
- ✅ **Basic MPU**: Complete multipart upload using PHP SDK upload() method
- ✅ **Part Size Configuration**: Configurable part sizes and concurrency settings
- ✅ **Large File Handling**: Test with 16MB+ files using random data generation

#### Advanced Features
- ✅ **List Objects Pagination**: Comprehensive pagination with continuation tokens
- ✅ **Presigned URLs**: GET and PUT presigned URL generation and validation
- ✅ **Content Integrity**: Content verification through upload/download cycles
- ✅ **Error Scenarios**: Comprehensive error handling and authentication testing

## Expected Test Results

### Successful Test Run

#### AWS CLI / s3cmd Test Results
```
=================================================================
S3 Compatibility Test Results Summary
=================================================================
Tests Passed: 18
Tests Failed: 0

🎉 All tests passed! S3 compatibility is working correctly.
```

#### Python Boto3 Test Results
```
[ok] All 21 tests passed
```

#### PHP AWS SDK Test Results
```
[ok] All 15 tests passed
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

#### 5. Python Dependencies Missing
```
ERROR: No module named 'boto3'
ERROR: No module named 'requests'
```
**Solution**: Install Python dependencies: `pip3 install boto3 requests`

#### 6. PHP Dependencies Missing
```
ERROR: Class 'Aws\S3\S3Client' not found
ERROR: require_once 'vendor/autoload.php' failed
```
**Solution**: Install PHP Composer dependencies:
```bash
cd test
composer install
```

#### 7. PHP Extensions Missing
```
ERROR: Call to undefined function curl_init()
ERROR: Call to undefined function random_bytes()
```
**Solution**: Install required PHP extensions:
```bash
# Ubuntu/Debian
sudo apt-get install php-curl php-json php-mbstring

# RHEL/CentOS
sudo yum install php-curl php-json php-mbstring
```

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

### Presigned URL Security Validation

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

## Presigned URL Test Scripts

For more comprehensive and flexible presigned URL testing, two additional test scripts are available that provide manual presigned URL generation and testing capabilities.

### Boto3-Compatible Presigned URL Generator (`test/boto3-compatible-presigned.sh`)

A bash script that implements the exact AWS SigV4 algorithm used by boto3, allowing manual generation and testing of presigned URLs with full control over parameters.

#### Features
- ✅ **Exact boto3 Algorithm**: Replicates boto3's canonical request construction
- ✅ **Flexible Parameters**: Configurable method, bucket, object, and expiry time
- ✅ **Generate-Only Mode**: Create URLs without testing for external use
- ✅ **Debug Output**: Shows canonical request, string-to-sign, and HMAC chain
- ✅ **Both Methods**: Supports GET and PUT presigned URL generation

#### Usage
```bash
# Basic usage with defaults
./test/boto3-compatible-presigned.sh

# Specify method, bucket, object, and expiry
./test/boto3-compatible-presigned.sh PUT my-bucket upload.txt 600

# Generate URL only (no testing)
./test/boto3-compatible-presigned.sh --generate-only GET my-bucket file.txt 300
./test/boto3-compatible-presigned.sh -g PUT test-bucket data.bin 1800

# Show help and usage
./test/boto3-compatible-presigned.sh --help
```

#### Parameters
| Parameter | Description | Default |
|-----------|-------------|---------|
| `METHOD` | HTTP method (GET or PUT) | `GET` |
| `BUCKET` | S3 bucket name | `test-bucket` |
| `OBJECT` | S3 object key | `test-object.txt` |
| `EXPIRES` | Expiration time in seconds | `300` |

#### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_ACCESS_KEY_ID` | `AKIA123456789EXAMPLE` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | AWS secret key |
| `S3_ENDPOINT` | `https://localhost:8080` | S3 endpoint URL |
| `AWS_REGION` | `us-east-1` | AWS region |

#### Example Output
```bash
$ ./test/boto3-compatible-presigned.sh GET my-bucket file.txt 600

Building presigned URL with timestamp: 20251001T120000Z
Method: GET
Bucket: my-bucket
Object: file.txt
Expires: 600 seconds
Credential: AKIA123456789EXAMPLE/20251001/us-east-1/s3/aws4_request
Host: localhost:8080

=== CANONICAL REQUEST ===
GET
/my-bucket/file.txt
X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA123456789EXAMPLE%2F20251001%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20251001T120000Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host
host:localhost:8080

host
UNSIGNED-PAYLOAD
=========================

=== FINAL URL ===
https://localhost:8080/my-bucket/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA123456789EXAMPLE%2F20251001%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20251001T120000Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=abc123...
=================

Testing the GET URL...
HTTP response code: 200
✅ SUCCESS: Presigned GET URL works!
```

### Python Boto3 Presigned URL Tester (`test/test-presigned-boto3.py`)

A Python script that uses the official boto3 library to generate and test presigned URLs, providing a reference implementation for comparison.

#### Features
- ✅ **Official boto3 Library**: Uses AWS's official Python SDK
- ✅ **PUT and GET URLs**: Tests both upload and download presigned URLs
- ✅ **Signature Extraction**: Shows generated signatures for comparison
- ✅ **Content Validation**: Verifies upload/download content integrity
- ✅ **Error Handling**: Proper error reporting and status codes

#### Usage
```bash
# Set credentials and endpoint
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export S3_ENDPOINT="https://localhost:8080"

# Run the test
python3 test/test-presigned-boto3.py
```

#### Example Output
```bash
$ python3 test/test-presigned-boto3.py

Testing presigned URLs with boto3
Endpoint: https://localhost:8080
Region: us-east-1
Access Key: your-acces...

✓ Created bucket test-bucket

=== Testing PUT presigned URL ===
PUT URL: https://localhost:8080/test-bucket/test-object.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...
PUT Signature: a1b2c3d4e5f6789...
PUT Response: 200
✓ PUT presigned URL works!

=== Testing GET presigned URL ===
GET URL: https://localhost:8080/test-bucket/test-object.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...
GET Signature: f6e5d4c3b2a1987...
GET Response: 200
✓ GET presigned URL works and content matches!
```

### How Boto3 Python Script Tests Presigned URLs

The Python boto3 script provides a comprehensive testing methodology that validates presigned URL functionality using AWS's official SDK as the reference implementation.

#### Test Methodology

**1. Bucket Creation and Validation**
```python
# Create bucket if needed
try:
    s3.head_bucket(Bucket=BUCKET)
    print(f"✓ Bucket {BUCKET} exists")
except:
    s3.create_bucket(Bucket=BUCKET)
    print(f"✓ Created bucket {BUCKET}")
```

**2. PUT Presigned URL Testing**
```python
# Generate PUT presigned URL using boto3
put_url = s3.generate_presigned_url(
    'put_object',
    Params={'Bucket': BUCKET, 'Key': OBJECT},
    ExpiresIn=300
)

# Test upload using requests library (not boto3)
response = requests.put(put_url, data=TEST_CONTENT, verify=False)
```

**3. GET Presigned URL Testing**
```python
# Generate GET presigned URL using boto3
get_url = s3.generate_presigned_url(
    'get_object', 
    Params={'Bucket': BUCKET, 'Key': OBJECT},
    ExpiresIn=300
)

# Test download and verify content integrity
response = requests.get(get_url, verify=False)
if response.content == TEST_CONTENT:
    print("✓ GET presigned URL works and content matches!")
```

#### Key Testing Principles

**Separation of URL Generation and Usage**
- Uses boto3 to generate presigned URLs (trusted reference)
- Uses requests library to test URLs (simulates external client)
- Validates that presigned URLs work independently of AWS SDKs

**Content Integrity Validation**
- Uploads known test content via PUT presigned URL
- Downloads content via GET presigned URL  
- Verifies downloaded content exactly matches uploaded content
- Ensures no data corruption through the presigned URL workflow

**Signature Extraction and Comparison**
```python
# Extract signature for debugging/comparison
if 'X-Amz-Signature=' in put_url:
    sig_start = put_url.find('X-Amz-Signature=') + len('X-Amz-Signature=')
    sig_end = put_url.find('&', sig_start) if put_url.find('&', sig_start) != -1 else len(put_url)
    signature = put_url[sig_start:sig_end]
    print(f"PUT Signature: {signature}")
```

**Real-World Client Simulation**
- Uses standard HTTP clients (requests) rather than AWS SDKs
- Tests presigned URLs as external applications would use them
- Validates compatibility with non-AWS HTTP clients

#### Validation Benefits

**Reference Implementation Guarantee**
- boto3 is AWS's official SDK with canonical SigV4 implementation
- Any presigned URL that works with boto3 should work with AWS S3
- Provides gold standard for signature validation

**Cross-Implementation Testing**
- Compare signatures between boto3 (Python) and manual bash implementation
- Identify discrepancies in canonical request construction
- Validate that manta-buckets-api matches AWS behavior exactly

**End-to-End Workflow Verification**
- Tests complete upload/download cycle via presigned URLs
- Verifies both URL generation and actual usage work correctly
- Ensures presigned URLs integrate properly with manta-buckets-api authentication

### Use Cases for Manual Presigned URL Scripts

#### 1. External Application Testing
```bash
# Generate a PUT URL for external application to upload to
./test/boto3-compatible-presigned.sh --generate-only PUT uploads my-file.pdf 3600

# Use the generated URL in external application
curl -X PUT "https://endpoint/uploads/my-file.pdf?X-Amz-..." --data-binary @my-file.pdf
```

#### 2. Signature Algorithm Debugging
```bash
# Compare signatures between bash and boto3 implementations
./test/boto3-compatible-presigned.sh GET test-bucket file.txt 300
python3 test/test-presigned-boto3.py
```

#### 3. Performance Testing
```bash
# Generate multiple URLs with different expiry times
for expiry in 300 600 1800 3600; do
    ./test/boto3-compatible-presigned.sh -g PUT load-test file-$expiry.bin $expiry
done
```

#### 4. Integration Testing
```bash
# Test presigned URLs work across different clients and implementations
./test/boto3-compatible-presigned.sh PUT integration-test upload.bin 600
python3 test/test-presigned-boto3.py  # Verify compatibility
```

### Troubleshooting Manual Presigned URL Scripts

#### Common Issues

**1. Signature Mismatch Between Scripts**
```bash
# Compare canonical requests and signatures
./test/boto3-compatible-presigned.sh GET test-bucket file.txt 300 | grep "Canonical request hash"
python3 test/test-presigned-boto3.py  # Check signature output
```

**2. URL Generation vs Testing**
- Use `--generate-only` flag to separate URL generation from testing
- Test generated URLs with external tools (curl, Postman, etc.)
- Verify signatures match between different implementations

**3. Environment Variable Issues**
```bash
# Verify credentials are set correctly
echo "Access Key: ${AWS_ACCESS_KEY_ID:0:10}..."
echo "Endpoint: $S3_ENDPOINT"

# Test with explicit values
AWS_ACCESS_KEY_ID="key" AWS_SECRET_ACCESS_KEY="secret" ./test/boto3-compatible-presigned.sh
```

