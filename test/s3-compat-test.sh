#!/bin/bash
# Copyright 2025 Edgecast Cloud LLC.
# S3 Compatibility Test Script for manta-buckets-api
# Tests basic S3 functionality using AWS CLI
#
# Fixed: Properly handles AWS CLI command failures by temporarily disabling
# 'set -e' around commands that are expected to potentially fail, preventing
# premature script termination while preserving error detection.

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration variables (can be overridden via environment)
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-"AKIA123456789EXAMPLE"}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
S3_ENDPOINT=${S3_ENDPOINT:-"https://localhost:8080"}
AWS_REGION=${AWS_REGION:-"us-east-1"}

# Test configuration
TEST_BUCKET="s3-compat-test-$(date +%s)"
TEST_OBJECT="test-object.txt"
TEST_CONTENT="Hello, S3 World! This is a test file for manta-buckets-api compatibility."
TEMP_DIR="/tmp/s3-compat-test"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

# Utility functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
    ((TESTS_PASSED++))
}

error() {
    echo -e "${RED}❌ $1${NC}"
    ((TESTS_FAILED++))
    FAILED_TESTS+=("$1")
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# AWS CLI wrapper with our endpoint
aws_s3() {
    aws s3 --endpoint-url="$S3_ENDPOINT" \
           --region="$AWS_REGION" \
           --no-verify-ssl \
           "$@"
}

aws_s3api() {
    aws s3api --endpoint-url="$S3_ENDPOINT" \
              --region="$AWS_REGION" \
              --no-verify-ssl \
              "$@"
}

# Setup test environment
setup() {
    log "Setting up test environment..."
    
    # Export AWS credentials
    export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
    export AWS_DEFAULT_REGION="$AWS_REGION"
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    # Create test file
    echo "$TEST_CONTENT" > "$TEST_OBJECT"
    
    log "Test configuration:"
    log "  Endpoint: $S3_ENDPOINT"
    log "  Access Key: ${AWS_ACCESS_KEY_ID:0:10}..."
    log "  Region: $AWS_REGION"
    log "  Test Bucket: $TEST_BUCKET"
    log "  Test Object: $TEST_OBJECT"
}

# Cleanup test environment
cleanup() {
    log "Cleaning up test environment..."
    
    set +e  # Disable exit on error for cleanup
    
    # Try to delete test objects and bucket
    if aws_s3api head-bucket --bucket "$TEST_BUCKET" 2>/dev/null; then
        log "Deleting test objects from bucket $TEST_BUCKET..."
        aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
        
        log "Deleting test bucket $TEST_BUCKET..."
        aws_s3api delete-bucket --bucket "$TEST_BUCKET" 2>/dev/null || true
    fi
    
    # Remove temp directory
    rm -rf "$TEMP_DIR"
    
    set -e  # Re-enable exit on error
}

# Test functions
test_list_buckets() {
    log "Testing: List Buckets"
    
    set +e  # Temporarily disable exit on error
    result=$(aws_s3api list-buckets 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        if echo "$result" | grep -q '"Buckets"'; then
            success "List buckets - JSON response contains Buckets array"
        else
            error "List buckets - Response missing Buckets array"
            echo "Response: $result"
        fi
        
        if echo "$result" | grep -q '"Owner"'; then
            success "List buckets - JSON response contains Owner information"
        else
            error "List buckets - Response missing Owner information"
        fi
    else
        error "List buckets - Command failed: $result"
    fi
}

test_create_bucket() {
    log "Testing: Create Bucket"
    
    set +e  # Temporarily disable exit on error
    result=$(aws_s3api create-bucket --bucket "$TEST_BUCKET" 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        success "Create bucket - $TEST_BUCKET created successfully"
    else
        error "Create bucket - Failed to create $TEST_BUCKET: $result"
        return 1
    fi
}

test_head_bucket() {
    log "Testing: Head Bucket"
    
    set +e  # Temporarily disable exit on error
    aws_s3api head-bucket --bucket "$TEST_BUCKET" 2>/dev/null
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        success "Head bucket - $TEST_BUCKET exists and is accessible"
    else
        error "Head bucket - Failed to access $TEST_BUCKET"
    fi
}

test_list_bucket_objects() {
    log "Testing: List Bucket Objects (empty bucket)"
    
    set +e  # Temporarily disable exit on error
    result=$(aws_s3api list-objects-v2 --bucket "$TEST_BUCKET" 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        if echo "$result" | grep -q '"KeyCount": 0' || echo "$result" | grep -q '"Contents": \[\]' || ! echo "$result" | grep -q '"Contents"'; then
            success "List objects - Empty bucket returns correct response"
        else
            error "List objects - Empty bucket response unexpected: $result"
        fi
    else
        error "List objects - Command failed: $result"
    fi
}

test_put_object() {
    log "Testing: Put Object"
    
    set +e  # Temporarily disable exit on error
    result=$(aws_s3api put-object --bucket "$TEST_BUCKET" --key "$TEST_OBJECT" --body "$TEST_OBJECT" 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        if echo "$result" | grep -q '"ETag"'; then
            success "Put object - $TEST_OBJECT uploaded successfully"
        else
            error "Put object - Response missing ETag: $result"
        fi
    else
        error "Put object - Failed to upload $TEST_OBJECT: $result"
        return 1
    fi
}

test_head_object() {
    log "Testing: Head Object"
    
    if aws_s3api head-object --bucket "$TEST_BUCKET" --key "$TEST_OBJECT" 2>/dev/null; then
        success "Head object - $TEST_OBJECT exists and metadata accessible"
    else
        error "Head object - Failed to access $TEST_OBJECT metadata"
    fi
}

test_get_object() {
    log "Testing: Get Object"
    
    local download_file="downloaded-$TEST_OBJECT"
    
    if aws_s3api get-object --bucket "$TEST_BUCKET" --key "$TEST_OBJECT" "$download_file" 2>/dev/null; then
        if [ -f "$download_file" ]; then
            local downloaded_content=$(cat "$download_file")
            if [ "$downloaded_content" = "$TEST_CONTENT" ]; then
                success "Get object - Downloaded content matches uploaded content"
            else
                error "Get object - Content mismatch. Expected: '$TEST_CONTENT', Got: '$downloaded_content'"
            fi
        else
            error "Get object - Downloaded file not found"
        fi
    else
        error "Get object - Failed to download $TEST_OBJECT"
    fi
}

test_object_checksum_integrity() {
    log "Testing: Object Upload/Download Checksum Integrity"
    
    local checksum_test_file="checksum-test.bin"
    local downloaded_checksum_file="downloaded-$checksum_test_file"
    
    # Create a test file with known content for checksum verification
    # Using a mix of text and binary-like content to ensure integrity
    local test_data="S3 Checksum Test Data - $(date +%s)$(printf '\x00\x01\x02\x03\xFF\xFE\xFD\xFC')"
    printf "%s" "$test_data" > "$checksum_test_file"
    
    # Calculate original checksum
    local original_md5=$(md5sum "$checksum_test_file" | cut -d' ' -f1)
    local original_sha256=$(sha256sum "$checksum_test_file" | cut -d' ' -f1)
    
    log "  Original file MD5: $original_md5"
    log "  Original file SHA256: $original_sha256"
    
    set +e  # Temporarily disable exit on error
    
    # Upload the file
    upload_result=$(aws_s3api put-object --bucket "$TEST_BUCKET" --key "$checksum_test_file" --body "$checksum_test_file" 2>&1)
    local upload_exit_code=$?
    
    if [ $upload_exit_code -ne 0 ]; then
        error "Checksum test - Failed to upload $checksum_test_file: $upload_result"
        set -e
        return 1
    fi
    
    # Download the file
    download_result=$(aws_s3api get-object --bucket "$TEST_BUCKET" --key "$checksum_test_file" "$downloaded_checksum_file" 2>&1)
    local download_exit_code=$?
    
    set -e  # Re-enable exit on error
    
    if [ $download_exit_code -ne 0 ]; then
        error "Checksum test - Failed to download $checksum_test_file: $download_result"
        return 1
    fi
    
    if [ ! -f "$downloaded_checksum_file" ]; then
        error "Checksum test - Downloaded file $downloaded_checksum_file not found"
        return 1
    fi
    
    # Calculate downloaded file checksums
    local downloaded_md5=$(md5sum "$downloaded_checksum_file" | cut -d' ' -f1)
    local downloaded_sha256=$(sha256sum "$downloaded_checksum_file" | cut -d' ' -f1)
    
    log "  Downloaded file MD5: $downloaded_md5"
    log "  Downloaded file SHA256: $downloaded_sha256"
    
    # Verify MD5 checksums match
    if [ "$original_md5" = "$downloaded_md5" ]; then
        success "Checksum test - MD5 checksums match ($original_md5)"
    else
        error "Checksum test - MD5 checksum mismatch! Original: $original_md5, Downloaded: $downloaded_md5"
    fi
    
    # Verify SHA256 checksums match
    if [ "$original_sha256" = "$downloaded_sha256" ]; then
        success "Checksum test - SHA256 checksums match ($original_sha256)"
    else
        error "Checksum test - SHA256 checksum mismatch! Original: $original_sha256, Downloaded: $downloaded_sha256"
    fi
    
    # Verify file sizes match
    local original_size=$(wc -c < "$checksum_test_file")
    local downloaded_size=$(wc -c < "$downloaded_checksum_file")
    
    if [ "$original_size" = "$downloaded_size" ]; then
        success "Checksum test - File sizes match ($original_size bytes)"
    else
        error "Checksum test - File size mismatch! Original: $original_size bytes, Downloaded: $downloaded_size bytes"
    fi
    
    # Cleanup test files
    rm -f "$checksum_test_file" "$downloaded_checksum_file"
    
    # Cleanup S3 object
    set +e
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$checksum_test_file" 2>/dev/null || true
    set -e
}

test_list_bucket_objects_with_content() {
    log "Testing: List Bucket Objects (with content)"
    
    if result=$(aws_s3api list-objects-v2 --bucket "$TEST_BUCKET" 2>&1); then
        if echo "$result" | grep -q "\"Key\": \"$TEST_OBJECT\""; then
            success "List objects - Object $TEST_OBJECT found in listing"
        else
            error "List objects - Object $TEST_OBJECT not found in listing: $result"
        fi
        
        if echo "$result" | grep -q '"KeyCount": 1'; then
            success "List objects - KeyCount correctly shows 1 object"
        else
            warning "List objects - KeyCount may be incorrect"
        fi
    else
        error "List objects - Command failed: $result"
    fi
}

test_delete_object() {
    log "Testing: Delete Object"
    
    if aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$TEST_OBJECT" 2>/dev/null; then
        success "Delete object - $TEST_OBJECT deleted successfully"
        
        # Verify object is gone
        if ! aws_s3api head-object --bucket "$TEST_BUCKET" --key "$TEST_OBJECT" 2>/dev/null; then
            success "Delete object - Object no longer exists after deletion"
        else
            error "Delete object - Object still exists after deletion"
        fi
    else
        error "Delete object - Failed to delete $TEST_OBJECT"
    fi
}

test_delete_bucket() {
    log "Testing: Delete Bucket"
    
    if aws_s3api delete-bucket --bucket "$TEST_BUCKET" 2>/dev/null; then
        success "Delete bucket - $TEST_BUCKET deleted successfully"
        
        # Verify bucket is gone
        if ! aws_s3api head-bucket --bucket "$TEST_BUCKET" 2>/dev/null; then
            success "Delete bucket - Bucket no longer exists after deletion"
        else
            error "Delete bucket - Bucket still exists after deletion"
        fi
    else
        error "Delete bucket - Failed to delete $TEST_BUCKET"
    fi
}

# Error handling tests
test_nonexistent_bucket() {
    log "Testing: Access Non-existent Bucket"
    
    local fake_bucket="nonexistent-bucket-$(date +%s)"
    
    if ! aws_s3api head-bucket --bucket "$fake_bucket" 2>/dev/null; then
        success "Error handling - Non-existent bucket returns proper error"
    else
        error "Error handling - Non-existent bucket should return error"
    fi
}

test_nonexistent_object() {
    log "Testing: Access Non-existent Object"
    
    # First create a bucket for this test
    local test_bucket="error-test-$(date +%s)"
    aws_s3api create-bucket --bucket "$test_bucket" 2>/dev/null
    
    if ! aws_s3api head-object --bucket "$test_bucket" --key "nonexistent-object" 2>/dev/null; then
        success "Error handling - Non-existent object returns proper error"
    else
        error "Error handling - Non-existent object should return error"
    fi
    
    # Cleanup
    aws_s3api delete-bucket --bucket "$test_bucket" 2>/dev/null
}

# Main test execution
run_tests() {
    log "Starting S3 Compatibility Tests for manta-buckets-api"
    log "=================================================="
    
    set +e  # Disable exit on error for test execution
    
    # Basic functionality tests
    test_list_buckets || true
    test_create_bucket || true
    test_head_bucket || true
    test_list_bucket_objects || true
    test_put_object || true
    test_head_object || true
    test_get_object || true
    test_object_checksum_integrity || true
    test_list_bucket_objects_with_content || true
    test_delete_object || true
    test_delete_bucket || true
    
    # Error handling tests
    test_nonexistent_bucket || true
    test_nonexistent_object || true
    
    set -e  # Re-enable exit on error
}

# Print test results
print_results() {
    log "=================================================="
    log "Test Results Summary"
    log "=================================================="
    
    echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
    
    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "\n${RED}Failed Tests:${NC}"
        for test in "${FAILED_TESTS[@]}"; do
            echo -e "${RED}  - $test${NC}"
        done
        echo
        exit 1
    else
        echo -e "\n${GREEN}🎉 All tests passed! S3 compatibility is working correctly.${NC}"
        exit 0
    fi
}

# Main execution
main() {
    # Handle command line arguments
    case "${1:-}" in
        -h|--help)
            echo "S3 Compatibility Test Script for manta-buckets-api"
            echo
            echo "Usage: $0 [options]"
            echo
            echo "Environment variables:"
            echo "  AWS_ACCESS_KEY_ID     - AWS access key (default: AKIA123456789EXAMPLE)"
            echo "  AWS_SECRET_ACCESS_KEY - AWS secret key (default: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)"
            echo "  S3_ENDPOINT          - S3 endpoint URL (default: http://localhost:8080)"
            echo "  AWS_REGION           - AWS region (default: us-east-1)"
            echo
            echo "Examples:"
            echo "  $0"
            echo "  AWS_ACCESS_KEY_ID=mykey AWS_SECRET_ACCESS_KEY=mysecret $0"
            echo "  S3_ENDPOINT=https://manta.example.com:8080 $0"
            exit 0
            ;;
        *)
            ;;
    esac
    
    # Set up trap for cleanup
    trap cleanup EXIT
    
    # Run the tests
    setup
    run_tests
    print_results
}

# Execute main function
main "$@"
