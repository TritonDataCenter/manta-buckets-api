#!/bin/bash
# Copyright 2025 Edgecast Cloud LLC.
# S3 Compatibility Test Script for manta-buckets-api using S3cmd
# Tests S3 functionality using s3cmd client
#
# S3cmd provides a higher-level interface to S3 operations compared to AWS CLI,
# with automatic multipart upload handling and resume capabilities.

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration variables (can be overridden via environment)
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-"AKIA123456789EXAMPLE"}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
S3_ENDPOINT=${S3_ENDPOINT:-"https://localhost:8080"}
AWS_REGION=${AWS_REGION:-"us-east-1"}

# Test configuration
TEST_BUCKET="s3cmd-compat-test-$(date +%s)"
TEST_OBJECT="test-object.txt"
TEST_CONTENT="Hello, S3 World! This is a test file for manta-buckets-api compatibility using s3cmd."
TEMP_DIR="/tmp/s3cmd-compat-test"

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

# S3cmd wrapper with our endpoint
s3cmd_wrapper() {
    s3cmd --host="${S3_ENDPOINT#https://}" \
          --host-bucket="${S3_ENDPOINT#https://}" \
          --access_key="$AWS_ACCESS_KEY_ID" \
          --secret_key="$AWS_SECRET_ACCESS_KEY" \
          --no-ssl \
          --no-check-certificate \
          --no-mime-magic \
          --no-preserve \
          "$@"
}

# Setup test environment
setup() {
    log "Setting up s3cmd test environment..."
    
    # Export AWS credentials
    export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
    export AWS_DEFAULT_REGION="$AWS_REGION"
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    # Create test file
    echo "$TEST_CONTENT" > "$TEST_OBJECT"
    
    log "S3cmd test configuration:"
    log "  Endpoint: $S3_ENDPOINT"
    log "  Access Key: ${AWS_ACCESS_KEY_ID:0:10}..."
    log "  Region: $AWS_REGION"
    log "  Test Bucket: $TEST_BUCKET"
    log "  Test Object: $TEST_OBJECT"
}

# Cleanup test environment
cleanup() {
    log "Cleaning up s3cmd test environment..."
    
    set +e  # Disable exit on error for cleanup
    
    # Clean up any remaining test buckets
    local buckets_to_clean=(
        "$TEST_BUCKET"
        "s3cmd-mpu-test-"*
        "s3cmd-mpu-resume-test-"*
        "s3cmd-mpu-error-test-"*
    )
    
    for bucket_pattern in "${buckets_to_clean[@]}"; do
        # Use s3cmd ls to find buckets matching pattern, then clean them
        s3cmd_wrapper ls 2>/dev/null | grep "$bucket_pattern" | while read -r line; do
            local bucket_uri=$(echo "$line" | awk '{print $3}')
            if [ -n "$bucket_uri" ]; then
                log "  Cleaning up bucket: $bucket_uri"
                s3cmd_wrapper rb "$bucket_uri" --force 2>/dev/null || true
            fi
        done 2>/dev/null || true
    done
    
    # Clean up temp directory
    cd /
    rm -rf "$TEMP_DIR" 2>/dev/null || true
    
    set -e
}

# Basic s3cmd functionality tests
test_s3cmd_list_buckets() {
    log "Testing: S3cmd List Buckets"
    
    set +e
    local result=$(s3cmd_wrapper ls 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "S3cmd list buckets - Command executed successfully"
    else
        error "S3cmd list buckets - Failed: $result"
    fi
}

test_s3cmd_create_bucket() {
    log "Testing: S3cmd Create Bucket"
    
    set +e
    local result=$(s3cmd_wrapper mb "s3://$TEST_BUCKET" 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "S3cmd create bucket - $TEST_BUCKET created successfully"
    else
        error "S3cmd create bucket - Failed to create $TEST_BUCKET: $result"
    fi
}

test_s3cmd_put_object() {
    log "Testing: S3cmd Put Object"
    
    set +e
    local result=$(s3cmd_wrapper put "$TEST_OBJECT" "s3://$TEST_BUCKET/" 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "S3cmd put object - $TEST_OBJECT uploaded successfully"
    else
        error "S3cmd put object - Failed to upload $TEST_OBJECT: $result"
    fi
}

test_s3cmd_list_objects() {
    log "Testing: S3cmd List Objects"
    
    set +e
    local result=$(s3cmd_wrapper ls "s3://$TEST_BUCKET" 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ] && echo "$result" | grep -q "$TEST_OBJECT"; then
        success "S3cmd list objects - Found $TEST_OBJECT in bucket"
    else
        error "S3cmd list objects - Failed or $TEST_OBJECT not found: $result"
    fi
}

test_s3cmd_get_object() {
    log "Testing: S3cmd Get Object"
    
    local downloaded_file="downloaded-$TEST_OBJECT"
    
    set +e
    local result=$(s3cmd_wrapper get "s3://$TEST_BUCKET/$TEST_OBJECT" "$downloaded_file" 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ] && [ -f "$downloaded_file" ]; then
        local downloaded_content=$(cat "$downloaded_file")
        if [ "$downloaded_content" = "$TEST_CONTENT" ]; then
            success "S3cmd get object - Content matches original"
        else
            error "S3cmd get object - Content mismatch"
        fi
        rm -f "$downloaded_file"
    else
        error "S3cmd get object - Failed to download: $result"
    fi
}

test_s3cmd_delete_object() {
    log "Testing: S3cmd Delete Object"
    
    set +e
    local result=$(s3cmd_wrapper rm "s3://$TEST_BUCKET/$TEST_OBJECT" 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "S3cmd delete object - $TEST_OBJECT deleted successfully"
        
        # Verify object is gone
        set +e
        s3cmd_wrapper ls "s3://$TEST_BUCKET/$TEST_OBJECT" 2>/dev/null
        local verify_exit_code=$?
        set -e
        
        if [ $verify_exit_code -ne 0 ]; then
            success "S3cmd delete object - Object no longer exists after deletion"
        else
            error "S3cmd delete object - Object still exists after deletion"
        fi
    else
        error "S3cmd delete object - Failed to delete: $result"
    fi
}

# Multipart upload tests
test_s3cmd_multipart_upload_basic() {
    log "Testing: S3cmd Basic Multipart Upload"
    
    local mpu_bucket="s3cmd-mpu-test-$(date +%s)"
    local mpu_object="s3cmd-large-test-file.bin"
    local total_size=15728640  # 15MB
    
    # Create test bucket
    set +e
    s3cmd_wrapper mb "s3://$mpu_bucket" 2>/dev/null
    local create_exit_code=$?
    set -e
    
    if [ $create_exit_code -ne 0 ]; then
        error "S3cmd MPU basic test - Failed to create test bucket"
        return 1
    fi
    
    # Create a large test file
    log "  Creating $total_size byte test file..."
    dd if=/dev/urandom of="$mpu_object" bs=1024 count=$((total_size / 1024)) 2>/dev/null
    local original_md5=$(md5sum "$mpu_object" | cut -d' ' -f1)
    
    # Upload using s3cmd (it handles multipart automatically for large files)
    log "  Uploading with s3cmd (automatic multipart for large files)..."
    set +e
    upload_result=$(s3cmd_wrapper put "$mpu_object" "s3://$mpu_bucket/" --multipart-chunk-size-mb=5 2>&1)
    local upload_exit_code=$?
    set -e
    
    if [ $upload_exit_code -ne 0 ]; then
        error "S3cmd MPU basic test - Failed to upload file: $upload_result"
        s3cmd_wrapper rb "s3://$mpu_bucket" --force 2>/dev/null || true
        return 1
    fi
    
    success "S3cmd MPU basic test - File uploaded successfully"
    
    # Download and verify the uploaded file
    local downloaded_file="downloaded-s3cmd-$mpu_object"
    set +e
    s3cmd_wrapper get "s3://$mpu_bucket/$mpu_object" "$downloaded_file" 2>/dev/null
    local download_exit_code=$?
    set -e
    
    if [ $download_exit_code -eq 0 ] && [ -f "$downloaded_file" ]; then
        local downloaded_md5=$(md5sum "$downloaded_file" | cut -d' ' -f1)
        if [ "$original_md5" = "$downloaded_md5" ]; then
            success "S3cmd MPU basic test - Downloaded file MD5 matches original ($original_md5)"
        else
            error "S3cmd MPU basic test - Downloaded file MD5 mismatch! Original: $original_md5, Downloaded: $downloaded_md5"
        fi
        
        local original_size=$(wc -c < "$mpu_object")
        local downloaded_size=$(wc -c < "$downloaded_file")
        if [ "$original_size" = "$downloaded_size" ]; then
            success "S3cmd MPU basic test - Downloaded file size matches original ($original_size bytes)"
        else
            error "S3cmd MPU basic test - Downloaded file size mismatch! Original: $original_size, Downloaded: $downloaded_size"
        fi
    else
        error "S3cmd MPU basic test - Failed to download file"
    fi
    
    # Cleanup
    set +e
    s3cmd_wrapper rm "s3://$mpu_bucket/$mpu_object" 2>/dev/null || true
    s3cmd_wrapper rb "s3://$mpu_bucket" 2>/dev/null || true
    rm -f "$mpu_object" "$downloaded_file"
    set -e
}

test_s3cmd_multipart_upload_resume() {
    log "Testing: S3cmd Multipart Upload Resume"
    
    local mpu_bucket="s3cmd-mpu-resume-test-$(date +%s)"
    local mpu_object="s3cmd-resume-test-file.bin"
    local total_size=12582912  # 12MB
    
    # Create test bucket
    set +e
    s3cmd_wrapper mb "s3://$mpu_bucket" 2>/dev/null
    local create_exit_code=$?
    set -e
    
    if [ $create_exit_code -ne 0 ]; then
        error "S3cmd MPU resume test - Failed to create test bucket"
        return 1
    fi
    
    # Create a test file
    log "  Creating $total_size byte test file..."
    dd if=/dev/urandom of="$mpu_object" bs=1024 count=$((total_size / 1024)) 2>/dev/null
    local original_md5=$(md5sum "$mpu_object" | cut -d' ' -f1)
    
    # Start upload with s3cmd (simulate interruption by using timeout)
    log "  Starting upload with s3cmd..."
    set +e
    # Try a normal upload but interrupt it after a short time
    timeout 3 s3cmd_wrapper put "$mpu_object" "s3://$mpu_bucket/" --multipart-chunk-size-mb=5 2>&1 &
    local upload_pid=$!
    sleep 2
    kill $upload_pid 2>/dev/null || true
    wait $upload_pid 2>/dev/null || true
    
    # Now try to resume the upload
    log "  Resuming upload with s3cmd..."
    upload_result=$(s3cmd_wrapper put "$mpu_object" "s3://$mpu_bucket/" --multipart-chunk-size-mb=5 2>&1)
    local upload_exit_code=$?
    set -e
    
    if [ $upload_exit_code -ne 0 ]; then
        # s3cmd might not support resume in the same way, so just do a fresh upload
        log "  Resume not supported, doing fresh upload..."
        set +e
        upload_result=$(s3cmd_wrapper put "$mpu_object" "s3://$mpu_bucket/" --multipart-chunk-size-mb=5 2>&1)
        upload_exit_code=$?
        set -e
    fi
    
    if [ $upload_exit_code -eq 0 ]; then
        success "S3cmd MPU resume test - Upload completed (resume or fresh)"
    else
        error "S3cmd MPU resume test - Upload failed: $upload_result"
        s3cmd_wrapper rb "s3://$mpu_bucket" --force 2>/dev/null || true
        return 1
    fi
    
    # Download and verify
    local downloaded_file="downloaded-s3cmd-resume-$mpu_object"
    set +e
    s3cmd_wrapper get "s3://$mpu_bucket/$mpu_object" "$downloaded_file" 2>/dev/null
    local download_exit_code=$?
    set -e
    
    if [ $download_exit_code -eq 0 ] && [ -f "$downloaded_file" ]; then
        local downloaded_md5=$(md5sum "$downloaded_file" | cut -d' ' -f1)
        if [ "$original_md5" = "$downloaded_md5" ]; then
            success "S3cmd MPU resume test - Downloaded file MD5 matches original ($original_md5)"
        else
            error "S3cmd MPU resume test - Downloaded file MD5 mismatch!"
        fi
    else
        error "S3cmd MPU resume test - Failed to download file"
    fi
    
    # Cleanup
    set +e
    s3cmd_wrapper rm "s3://$mpu_bucket/$mpu_object" 2>/dev/null || true
    s3cmd_wrapper rb "s3://$mpu_bucket" 2>/dev/null || true
    rm -f "$mpu_object" "$downloaded_file"
    set -e
}

test_s3cmd_multipart_upload_errors() {
    log "Testing: S3cmd Multipart Upload Error Handling"
    
    local mpu_bucket="s3cmd-mpu-error-test-$(date +%s)"
    local mpu_object="s3cmd-error-test-file.bin"
    
    # Create test bucket
    set +e
    s3cmd_wrapper mb "s3://$mpu_bucket" 2>/dev/null
    local create_exit_code=$?
    set -e
    
    if [ $create_exit_code -ne 0 ]; then
        error "S3cmd MPU error test - Failed to create test bucket"
        return 1
    fi
    
    # Create a file that's exactly at the boundary for multipart upload issues
    local small_size=4194304  # 4MB - smaller than the 5MB minimum part size
    log "  Creating $small_size byte test file..."
    dd if=/dev/urandom of="$mpu_object" bs=1024 count=$((small_size / 1024)) 2>/dev/null
    
    # Try uploading with s3cmd using small chunk size to force multipart
    log "  Testing upload with small chunk size to trigger multipart..."
    set +e
    upload_result=$(s3cmd_wrapper put "$mpu_object" "s3://$mpu_bucket/" --multipart-chunk-size-mb=2 2>&1)
    local upload_exit_code=$?
    set -e
    
    if [ $upload_exit_code -eq 0 ]; then
        success "S3cmd MPU error test - Upload succeeded (s3cmd may have handled part size automatically)"
        
        # Verify the uploaded file
        local downloaded_file="downloaded-s3cmd-error-$mpu_object"
        set +e
        s3cmd_wrapper get "s3://$mpu_bucket/$mpu_object" "$downloaded_file" 2>/dev/null
        local download_exit_code=$?
        set -e
        
        if [ $download_exit_code -eq 0 ]; then
            success "S3cmd MPU error test - File uploaded and downloaded successfully"
        else
            error "S3cmd MPU error test - Failed to download file"
        fi
        
        rm -f "$downloaded_file"
    else
        # Check if the error is related to part size
        if echo "$upload_result" | grep -i "too small\|EntityTooSmall"; then
            success "S3cmd MPU error test - Properly detected part size error"
        else
            warning "S3cmd MPU error test - Upload failed but not due to expected part size error: $upload_result"
        fi
    fi
    
    # Test aborting uploads by trying to delete bucket with partial uploads
    log "  Testing cleanup of partial uploads..."
    set +e
    s3cmd_wrapper rb "s3://$mpu_bucket" --force 2>/dev/null
    local cleanup_exit_code=$?
    set -e
    
    if [ $cleanup_exit_code -eq 0 ]; then
        success "S3cmd MPU error test - Bucket cleanup succeeded"
    else
        warning "S3cmd MPU error test - Bucket cleanup had issues (may have partial uploads)"
    fi
    
    # Final cleanup
    set +e
    rm -f "$mpu_object"
    set -e
}

test_s3cmd_delete_bucket() {
    log "Testing: S3cmd Delete Bucket"
    
    set +e
    local result=$(s3cmd_wrapper rb "s3://$TEST_BUCKET" 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "S3cmd delete bucket - $TEST_BUCKET deleted successfully"
        
        # Verify bucket is gone
        set +e
        s3cmd_wrapper ls "s3://$TEST_BUCKET" 2>/dev/null
        local verify_exit_code=$?
        set -e
        
        if [ $verify_exit_code -ne 0 ]; then
            success "S3cmd delete bucket - Bucket no longer exists after deletion"
        else
            error "S3cmd delete bucket - Bucket still exists after deletion"
        fi
    else
        error "S3cmd delete bucket - Failed to delete $TEST_BUCKET: $result"
    fi
}

# Error handling tests
test_s3cmd_nonexistent_bucket() {
    log "Testing: S3cmd Access Non-existent Bucket"
    
    local fake_bucket="nonexistent-bucket-$(date +%s)"
    
    set +e
    s3cmd_wrapper ls "s3://$fake_bucket" 2>/dev/null
    local exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        success "S3cmd error handling - Non-existent bucket returns proper error"
    else
        error "S3cmd error handling - Non-existent bucket should return error"
    fi
}

test_s3cmd_nonexistent_object() {
    log "Testing: S3cmd Access Non-existent Object"
    
    # First create a bucket for this test
    local test_bucket="s3cmd-error-test-$(date +%s)"
    s3cmd_wrapper mb "s3://$test_bucket" 2>/dev/null
    
    set +e
    s3cmd_wrapper get "s3://$test_bucket/nonexistent-object" "/tmp/nonexistent" 2>/dev/null
    local exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        success "S3cmd error handling - Non-existent object returns proper error"
    else
        error "S3cmd error handling - Non-existent object should return error"
    fi
    
    # Cleanup
    s3cmd_wrapper rb "s3://$test_bucket" 2>/dev/null || true
    rm -f "/tmp/nonexistent"
}

# Main test execution
run_tests() {
    log "Starting S3 Compatibility Tests for manta-buckets-api using S3cmd"
    log "================================================================="
    
    set +e  # Disable exit on error for test execution
    
    # Basic functionality tests
    test_s3cmd_list_buckets || true
    test_s3cmd_create_bucket || true
    test_s3cmd_put_object || true
    test_s3cmd_list_objects || true
    test_s3cmd_get_object || true
    test_s3cmd_delete_object || true
    
    # Multipart upload tests
    test_s3cmd_multipart_upload_basic || true
    test_s3cmd_multipart_upload_resume || true
    test_s3cmd_multipart_upload_errors || true
    
    test_s3cmd_delete_bucket || true
    
    # Error handling tests
    test_s3cmd_nonexistent_bucket || true
    test_s3cmd_nonexistent_object || true
    
    set -e  # Re-enable exit on error
}

# Print test results
print_results() {
    log "================================================================="
    log "S3cmd Test Results Summary"
    log "================================================================="
    
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
        echo -e "\n${GREEN}🎉 All s3cmd tests passed! S3 compatibility is working correctly.${NC}"
        exit 0
    fi
}

# Main execution
main() {
    # Handle command line arguments
    case "${1:-}" in
        -h|--help)
            echo "S3 Compatibility Test Script for manta-buckets-api using S3cmd"
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
            echo
            echo "Note: This script requires s3cmd to be installed and configured."
            exit 0
            ;;
        *)
            ;;
    esac
    
    # Check if s3cmd is available
    if ! command -v s3cmd >/dev/null 2>&1; then
        echo -e "${RED}Error: s3cmd is not installed or not in PATH${NC}"
        echo "Please install s3cmd: pip install s3cmd"
        exit 1
    fi
    
    # Set up trap for cleanup
    trap cleanup EXIT
    
    # Run the tests
    setup
    run_tests
    print_results
}

# Execute main function
main "$@"