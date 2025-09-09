# S3 Compatibility Testing Guide

This guide explains how to run the comprehensive S3 compatibility test suites for manta-buckets-api, covering both AWS CLI and s3cmd client compatibility.

## Overview

The test suites validate S3 API compatibility across multiple clients and scenarios:
- **Basic CRUD operations** (Create, Read, Update, Delete)
- **Multipart upload functionality** including resume scenarios
- **Error handling and edge cases**
- **Performance and reliability testing**

## Test Suites

### AWS CLI Test Suite (`test/s3-compat-awscli-test.sh`)

Comprehensive testing using AWS CLI (aws s3api commands) for low-level S3 API operations.

**Key Features:**
- Raw S3 API testing using `aws s3api` commands
- Manual multipart upload part management
- ETag extraction and validation
- Resume functionality testing
- Conditional header testing (If-Match, If-None-Match, etc.)
- Error scenario validation (EntityTooSmall, etc.)

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
tail -f /var/log/manta-buckets-api.log | grep -E "(S3_MPU|ERROR|WARN)"
```

### Common Debug Steps
1. **Verify endpoint connectivity**: `curl -k https://localhost:8080/`
2. **Check credentials**: Ensure AWS credentials are properly configured
3. **Validate dependencies**: Confirm all required tools are installed
4. **Review test output**: Look for specific error messages in test logs
5. **Check server logs**: Review server-side errors and warnings

## Integration with CI/CD

### Example GitHub Actions
```yaml
name: S3 Compatibility Tests
on: [push, pull_request]

jobs:
  s3-compatibility:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install dependencies
        run: |
          curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscli.zip"
          unzip awscli.zip && sudo ./aws/install
          sudo apt-get install s3cmd jq nodejs npm
          sudo npm install -g json
          
      - name: Start manta-buckets-api
        run: |
          # Start your manta-buckets-api server here
          npm start &
          sleep 10
          
      - name: Run AWS CLI tests
        run: ./test/s3-compat-awscli-test.sh
        
      - name: Run s3cmd tests  
        run: ./test/s3-compat-s3cmd-test.sh
```

## Contributing Test Cases

### Adding New Test Scenarios
1. **Follow naming convention**: `test_category_specific_scenario()`
2. **Include proper logging**: Use `log()`, `success()`, `error()` functions
3. **Handle cleanup**: Ensure resources are cleaned up on success/failure
4. **Add to test runner**: Include in the main `run_tests()` function

### Test Function Template
```bash
test_new_scenario() {
    log "Testing: New Scenario Description"
    
    # Setup
    local test_bucket="test-bucket-$(date +%s)"
    
    # Test execution with error handling
    set +e
    local result=$(aws_s3api create-bucket --bucket "$test_bucket" 2>&1)
    local exit_code=$?
    set -e
    
    # Validation and cleanup
    if [ $exit_code -eq 0 ]; then
        success "New scenario - Test passed"
        aws_s3api delete-bucket --bucket "$test_bucket" 2>/dev/null || true
    else
        error "New scenario - Test failed: $result"
    fi
}
```

## Best Practices

### Test Environment
- **Use dedicated test credentials** separate from production
- **Run against local instances** for development testing
- **Validate cleanup** after each test run
- **Monitor resource usage** during large file tests

### Test Development
- **Write atomic tests** that don't depend on other test state
- **Include negative testing** for error scenarios  
- **Validate both success and failure cases**
- **Use descriptive test names** and log messages

### Performance Testing
- **Test with various file sizes** (small, medium, large)
- **Validate multipart thresholds** (5MB parts, etc.)
- **Test concurrent operations** when applicable
- **Monitor memory usage** during large uploads

## Troubleshooting

### Common Issues

| Issue | Symptoms | Solution |
|-------|----------|----------|
| **Server not running** | Connection refused errors | Start manta-buckets-api service |
| **Port conflicts** | Address already in use | Change S3_ENDPOINT port or stop conflicting service |
| **Permission issues** | Access denied errors | Verify AWS credentials configuration |
| **Missing tools** | Command not found errors | Install required dependencies |
| **SSL issues** | Certificate validation errors | Tests handle this automatically with --no-verify-ssl |
| **Memory issues** | Large file test failures | Increase available memory or reduce test file sizes |

### Support and Issues
- **GitHub Issues**: Report test failures and bugs
- **Server logs**: Always include relevant server logs with issue reports
- **Test output**: Include full test output for debugging
- **Environment details**: Specify OS, tool versions, and configuration

---

*This testing guide is maintained as part of the manta-buckets-api project. For the latest updates and additional information, refer to the project repository.*