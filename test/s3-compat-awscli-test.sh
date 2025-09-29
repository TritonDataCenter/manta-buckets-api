#!/bin/bash
# Copyright 2025 Edgecast Cloud LLC.
# S3 Compatibility Test Script for manta-buckets-api using AWS CLI
# Tests S3 functionality using AWS CLI (raw S3 API operations)
#
# This script tests low-level S3 API operations using aws s3api commands,
# including manual multipart upload part management and ETag extraction.
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
           --no-cli-pager \
           --no-paginate \
           --color off \
           "$@"
}

aws_s3api() {
    aws s3api --endpoint-url="$S3_ENDPOINT" \
              --region="$AWS_REGION" \
              --no-verify-ssl \
              --no-cli-pager \
              --no-paginate \
              --color off \
              --output json \
              "$@"
}

# Setup test environment
setup() {
    log "Setting up test environment..."
    
    # Export AWS credentials
    export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
    export AWS_DEFAULT_REGION="$AWS_REGION"
    
    # Suppress urllib3 SSL warnings for localhost testing
    export PYTHONWARNINGS="ignore:Unverified HTTPS request"
    
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
        if echo "$result" | jq -e '.Buckets' >/dev/null 2>&1; then
            success "List buckets - JSON response contains Buckets array"
        else
            error "List buckets - Response missing Buckets array"
            echo "Response: $result"
        fi
        
        if echo "$result" | jq -e '.Owner' >/dev/null 2>&1; then
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
        if echo "$result" | jq -e '.KeyCount == 0 or (.Contents | length == 0) or (.Contents | not)' >/dev/null 2>&1; then
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
        if echo "$result" | jq -e '.ETag' >/dev/null 2>&1; then
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
        if echo "$result" | jq -e --arg key "$TEST_OBJECT" '.Contents[]? | select(.Key == $key)' >/dev/null 2>&1; then
            success "List objects - Object $TEST_OBJECT found in listing"
        else
            error "List objects - Object $TEST_OBJECT not found in listing: $result"
        fi
        
        if echo "$result" | jq -e '.KeyCount == 1' >/dev/null 2>&1; then
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

test_conditional_headers() {
    log "Testing: Conditional Headers (If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since)"
    
    local conditional_test_bucket="conditional-test-$(date +%s)"
    local conditional_test_object="conditional-test.txt"
    local conditional_content="Test content for conditional headers - $(date +%s)"
    
    # Create test bucket
    set +e
    aws_s3api create-bucket --bucket "$conditional_test_bucket" 2>/dev/null
    local create_exit_code=$?
    set -e
    
    if [ $create_exit_code -ne 0 ]; then
        error "Conditional headers test - Failed to create test bucket"
        return 1
    fi
    
    # Create test file
    echo "$conditional_content" > "$conditional_test_object"
    
    # Upload object to get ETag and Last-Modified
    set +e
    put_result=$(aws_s3api put-object --bucket "$conditional_test_bucket" --key "$conditional_test_object" --body "$conditional_test_object" 2>&1)
    local put_exit_code=$?
    set -e
    
    if [ $put_exit_code -ne 0 ]; then
        error "Conditional headers test - Failed to upload test object: $put_result"
        aws_s3api delete-bucket --bucket "$conditional_test_bucket" 2>/dev/null || true
        return 1
    fi
    
    # Extract ETag from put response
    local etag=$(echo "$put_result" | jq -r '.ETag // empty')
    log "  Object ETag: $etag"
    
    # Get object metadata to extract Last-Modified
    set +e
    head_result=$(aws_s3api head-object --bucket "$conditional_test_bucket" --key "$conditional_test_object" 2>&1)
    local head_exit_code=$?
    set -e
    
    if [ $head_exit_code -ne 0 ]; then
        error "Conditional headers test - Failed to get object metadata: $head_result"
        aws_s3api delete-bucket --bucket "$conditional_test_bucket" 2>/dev/null || true
        return 1
    fi
    
    # Test If-Match (should succeed)
    log "  Testing If-Match header (should succeed)..."
    set +e
    if aws_s3api head-object --bucket "$conditional_test_bucket" --key "$conditional_test_object" --if-match "$etag" 2>/dev/null; then
        success "Conditional headers - If-Match with correct ETag succeeds"
    else
        error "Conditional headers - If-Match with correct ETag failed"
    fi
    set -e
    
    # Test If-Match with wrong ETag (should fail with 412)
    log "  Testing If-Match header with wrong ETag (should fail)..."
    set +e
    aws_s3api head-object --bucket "$conditional_test_bucket" --key "$conditional_test_object" --if-match "\"wrong-etag\"" 2>/dev/null
    local wrong_match_exit_code=$?
    set -e
    
    if [ $wrong_match_exit_code -ne 0 ]; then
        success "Conditional headers - If-Match with wrong ETag properly fails"
    else
        error "Conditional headers - If-Match with wrong ETag should fail but didn't"
    fi
    
    # Test If-None-Match with wrong ETag (should succeed)
    log "  Testing If-None-Match header with different ETag (should succeed)..."
    set +e
    if aws_s3api head-object --bucket "$conditional_test_bucket" --key "$conditional_test_object" --if-none-match "\"different-etag\"" 2>/dev/null; then
        success "Conditional headers - If-None-Match with different ETag succeeds"
    else
        error "Conditional headers - If-None-Match with different ETag failed"
    fi
    set -e
    
    # Test If-None-Match with same ETag (should fail with 304)
    log "  Testing If-None-Match header with same ETag (should fail)..."
    set +e
    aws_s3api head-object --bucket "$conditional_test_bucket" --key "$conditional_test_object" --if-none-match "$etag" 2>/dev/null
    local same_none_match_exit_code=$?
    set -e
    
    if [ $same_none_match_exit_code -ne 0 ]; then
        success "Conditional headers - If-None-Match with same ETag properly fails"
    else
        error "Conditional headers - If-None-Match with same ETag should fail but didn't"
    fi
    
    # Test If-Modified-Since with past date (should succeed)
    log "  Testing If-Modified-Since header with past date (should succeed)..."
    local past_date="Wed, 01 Jan 2020 00:00:00 GMT"
    set +e
    if aws_s3api head-object --bucket "$conditional_test_bucket" --key "$conditional_test_object" --if-modified-since "$past_date" 2>/dev/null; then
        success "Conditional headers - If-Modified-Since with past date succeeds"
    else
        error "Conditional headers - If-Modified-Since with past date failed"
    fi
    set -e
    
    # Test If-Unmodified-Since with future date (should succeed)
    log "  Testing If-Unmodified-Since header with future date (should succeed)..."
    local future_date="Wed, 01 Jan 2030 00:00:00 GMT"
    set +e
    if aws_s3api head-object --bucket "$conditional_test_bucket" --key "$conditional_test_object" --if-unmodified-since "$future_date" 2>/dev/null; then
        success "Conditional headers - If-Unmodified-Since with future date succeeds"
    else
        error "Conditional headers - If-Unmodified-Since with future date failed"
    fi
    set -e
    
    # Test If-Unmodified-Since with past date (should fail with 412)
    log "  Testing If-Unmodified-Since header with past date (should fail)..."
    set +e
    aws_s3api head-object --bucket "$conditional_test_bucket" --key "$conditional_test_object" --if-unmodified-since "$past_date" 2>/dev/null
    local past_unmodified_exit_code=$?
    set -e
    
    if [ $past_unmodified_exit_code -ne 0 ]; then
        success "Conditional headers - If-Unmodified-Since with past date properly fails"
    else
        error "Conditional headers - If-Unmodified-Since with past date should fail but didn't"
    fi
    
    # Test conditional headers with GET operations
    log "  Testing conditional headers with GET operations..."
    local download_file="conditional-download.txt"
    
    # Test If-Match with GET (should succeed)
    set +e
    if aws_s3api get-object --bucket "$conditional_test_bucket" --key "$conditional_test_object" --if-match "$etag" "$download_file" 2>/dev/null; then
        success "Conditional headers - GET with If-Match succeeds"
        rm -f "$download_file"
    else
        error "Conditional headers - GET with If-Match failed"
    fi
    set -e
    
    # Test If-None-Match with GET (should fail with 304)
    set +e
    aws_s3api get-object --bucket "$conditional_test_bucket" --key "$conditional_test_object" --if-none-match "$etag" "$download_file" 2>/dev/null
    local get_none_match_exit_code=$?
    set -e
    
    if [ $get_none_match_exit_code -ne 0 ]; then
        success "Conditional headers - GET with If-None-Match (same ETag) properly fails"
    else
        error "Conditional headers - GET with If-None-Match (same ETag) should fail but didn't"
    fi
    
    # Cleanup
    set +e
    aws_s3api delete-object --bucket "$conditional_test_bucket" --key "$conditional_test_object" 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$conditional_test_bucket" 2>/dev/null || true
    rm -f "$conditional_test_object" "$download_file"
    set -e
}

test_multipart_upload_basic() {
    log "Testing: Basic Multipart Upload"
    
    local mpu_bucket="mpu-test-$(date +%s)"
    local mpu_object="large-test-file.bin"
    local part_size=8388608  # 8MB - ensures parts stay above 5MB minimum even with aws-chunked
    local total_size=16777216  # 16MB (exactly 2 parts: 8MB + 8MB final)
    
    # Create test bucket
    set +e
    aws_s3api create-bucket --bucket "$mpu_bucket" 2>/dev/null
    local create_exit_code=$?
    set -e
    
    if [ $create_exit_code -ne 0 ]; then
        error "MPU basic test - Failed to create test bucket"
        return 1
    fi
    
    # Create a large test file
    log "  Creating $total_size byte test file..."
    dd if=/dev/urandom of="$mpu_object" bs=1024 count=$((total_size / 1024)) 2>/dev/null
    local original_md5=$(md5sum "$mpu_object" | cut -d' ' -f1)
    
    # Initiate multipart upload
    set +e
    initiate_result=$(aws_s3api create-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" 2>&1)
    local initiate_exit_code=$?
    set -e
    
    if [ $initiate_exit_code -ne 0 ]; then
        error "MPU basic test - Failed to initiate multipart upload: $initiate_result"
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    local upload_id=$(echo "$initiate_result" | jq -r '.UploadId // empty')
    log "  Upload ID: $upload_id"
    
    if [ -z "$upload_id" ]; then
        error "MPU basic test - Failed to extract upload ID from response"
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    # Upload parts - boto3 approach: use server-reported sizes for everything
    local part_number=1
    local uploaded_parts=()
    local bytes_uploaded=0  # Track server-reported total size (authoritative)
    local file_offset=0     # Track position in original file
    
    # Upload parts until file is fully consumed (aws-chunked may compress data)
    while [ $file_offset -lt $total_size ]; do
        local file_remaining=$((total_size - file_offset))
        # Use standard part size, or remaining file data for final part
        local current_part_size=$part_size
        if [ $file_remaining -lt $current_part_size ]; then
            current_part_size=$file_remaining
        fi
        
        # Safety check: if no file data remaining, stop immediately
        if [ $current_part_size -le 0 ]; then
            log "  DEBUG: No more file data to upload (current_part_size=$current_part_size), stopping"
            break
        fi
        
        log "  Uploading part $part_number ($current_part_size bytes from file)..."
        log "  DEBUG: file_offset=$file_offset, bytes_uploaded=$bytes_uploaded, file_remaining=$file_remaining"
        
        # Extract part from original file using file_offset
        local part_file="part$part_number.bin"
        dd if="$mpu_object" of="$part_file" bs=1 skip=$file_offset count=$current_part_size 2>/dev/null
        
        local actual_part_size=$(wc -c < "$part_file")
        log "  DEBUG: Created part file size: $actual_part_size bytes"
        
        set +e
        # AWS CLI upload-part doesn't output anything by default, so we need to capture the ETag differently
        part_result=$(aws_s3api upload-part --bucket "$mpu_bucket" --key "$mpu_object" --part-number $part_number --upload-id "$upload_id" --body "$part_file" 2>&1)
        local part_exit_code=$?
        set -e
        
        # If the command succeeded but returned no output, that's normal for upload-part
        if [ $part_exit_code -eq 0 ] && [ -z "$part_result" ]; then
            log "  Part $part_number uploaded successfully (no output is normal for upload-part)"
        fi
        
        if [ $part_exit_code -ne 0 ]; then
            error "MPU basic test - Failed to upload part $part_number: $part_result"
            aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
            aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
            return 1
        fi
        
        # AWS CLI upload-part doesn't return ETag in output, so we need to get it via list-parts
        # This is actually more realistic as it's what real MPU clients do
        log "  Getting ETag via list-parts (upload-part doesn't output ETags)..."
        
        set +e
        list_result=$(aws_s3api list-parts --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" --part-number-marker $((part_number - 1)) --max-parts 1 2>&1)
        local list_exit_code=$?
        set -e
        
        if [ $list_exit_code -eq 0 ]; then
            echo "=== DEBUG: list-parts response for part $part_number ==="
            echo "$list_result"
            echo "=== END DEBUG ==="
            
            # Extract ETag and Size for specific part using json tool
            part_etag=$(echo "$list_result" | json Parts | json -a -c "this.PartNumber === $part_number" ETag)
            part_size=$(echo "$list_result" | json Parts | json -a -c "this.PartNumber === $part_number" Size)
            echo "DEBUG: part $part_number json tool result: ETag='$part_etag', Size='$part_size'"
        else
            echo "DEBUG: list-parts failed with exit code $list_exit_code"
            echo "DEBUG: list-parts error: $list_result"
            log "  Warning: list-parts failed, using placeholder ETag and calculated size"
            part_etag="placeholder-etag-$part_number"
            part_size=""  # Initialize part_size when list-parts fails
        fi
        
        log "  Part $part_number ETag: '$part_etag'"
        
        # Safety check for empty ETag
        if [ -z "$part_etag" ]; then
            error "MPU basic test - Failed to extract ETag for part $part_number from response: $part_result"
            aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
            aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
            return 1
        fi
        
        # IMPORTANT: The ETag from list-parts is the content MD5, but manta-buckets-api
        # stores object UUIDs. We need to get the stored object IDs for completion.
        # For now, we'll work with the list-parts ETags and handle any validation
        # differences on the server side.
        log "  Part $part_number: Using list-parts ETag '$part_etag' (content MD5 format)"
        
        uploaded_parts+=("ETag=$part_etag,PartNumber=$part_number,Size=$part_size")
        
        # CRITICAL: Always use server-reported size from ListParts API
        # This is the only correct approach for S3 MPU - server is source of truth
        #
        # NOTE: AWS CLI uses 'Content-Encoding: aws-chunked' which adds encoding overhead
        # to the data stream. The client sends 8MB (data + chunked metadata) but the 
        # server stores only the actual decoded data (~6-7MB). This size discrepancy causes
        # v2 commit failures if clients calculate based on what they sent rather than
        # what was actually stored. boto3-resume-mpu.py works because it always uses
        # ListParts sizes. This is the correct S3-compatible behavior.
        echo "DEBUG: Basic MPU Part $part_number - file size: $current_part_size, server size: '$part_size'"
        if [ -n "$part_size" ] && [ "$part_size" -gt 0 ] 2>/dev/null; then
            bytes_uploaded=$((bytes_uploaded + part_size))
            echo "DEBUG: Using server-reported size $part_size (from ListParts) - this is correct S3 behavior"
            echo "DEBUG: Server total: $bytes_uploaded, File offset will be: $((file_offset + current_part_size))"
        else
            # Fallback only if ListParts failed completely
            bytes_uploaded=$((bytes_uploaded + current_part_size))
            echo "WARNING: Server size unavailable, falling back to calculated size $current_part_size"
            echo "WARNING: This may cause completion failures due to size mismatches"
        fi
        
        # Always advance file offset by the actual bytes read from file
        file_offset=$((file_offset + current_part_size))
        part_number=$((part_number + 1))
        rm -f "$part_file"
    done
    
    log "  DEBUG: Upload loop completed - original file size=$total_size, server reported total=$bytes_uploaded"
    log "  DEBUG: File offset reached: $file_offset, Parts created: $((part_number - 1))"
    success "MPU basic test - Uploaded $((part_number - 1)) parts successfully"
    
    # Complete multipart upload
    local parts_json="{"
    parts_json+="\"Parts\": ["
    for i in "${!uploaded_parts[@]}"; do
        if [ $i -gt 0 ]; then
            parts_json+=","
        fi
        local part_info="${uploaded_parts[$i]}"
        local etag=$(echo "$part_info" | cut -d',' -f1 | cut -d'=' -f2)
        local part_num=$(echo "$part_info" | cut -d',' -f2 | cut -d'=' -f2)
        local part_size=$(echo "$part_info" | cut -d',' -f3 | cut -d'=' -f2)
        # Ensure ETag is properly quoted - remove any existing quotes first
        etag=$(echo "$etag" | sed 's/^"//;s/"$//')
        if [ -n "$etag" ]; then
            etag="\"$etag\""
        else
            etag='""'
        fi
        parts_json+="{\"ETag\": $etag, \"PartNumber\": $part_num}"
    done
    parts_json+="]}"
    
    log "  Generated JSON: $parts_json"
    echo "$parts_json" > multipart-complete.json
    
    # Debug: Show the exact JSON being sent to complete-multipart-upload
    log "  DEBUG: JSON content being sent to complete-multipart-upload:"
    cat multipart-complete.json
    log "  DEBUG: Number of parts in JSON: $(echo "$parts_json" | jq '.Parts | length' 2>/dev/null || echo 'jq-failed')"
    
    set +e
    complete_result=$(aws_s3api complete-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" --multipart-upload file://multipart-complete.json 2>&1)
    local complete_exit_code=$?
    set -e
    
    if [ $complete_exit_code -ne 0 ]; then
        error "MPU basic test - Failed to complete multipart upload: $complete_result"
        aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    success "MPU basic test - Multipart upload completed successfully"
    
    # Verify the uploaded object
    local downloaded_file="downloaded-$mpu_object"
    set +e
    aws_s3api get-object --bucket "$mpu_bucket" --key "$mpu_object" "$downloaded_file" 2>/dev/null
    local download_exit_code=$?
    set -e
    
    if [ $download_exit_code -eq 0 ] && [ -f "$downloaded_file" ]; then
        local downloaded_md5=$(md5sum "$downloaded_file" | cut -d' ' -f1)
        if [ "$original_md5" = "$downloaded_md5" ]; then
            success "MPU basic test - Downloaded file MD5 matches original ($original_md5)"
        else
            error "MPU basic test - Downloaded file MD5 mismatch! Original: $original_md5, Downloaded: $downloaded_md5"
        fi
        
        local original_size=$(wc -c < "$mpu_object")
        local downloaded_size=$(wc -c < "$downloaded_file")
        if [ "$original_size" = "$downloaded_size" ]; then
            success "MPU basic test - Downloaded file size matches original ($original_size bytes)"
        else
            error "MPU basic test - Downloaded file size mismatch! Original: $original_size, Downloaded: $downloaded_size"
        fi
    else
        error "MPU basic test - Failed to download completed multipart upload"
    fi
    
    # Cleanup
    set +e
    aws_s3api delete-object --bucket "$mpu_bucket" --key "$mpu_object" 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
    rm -f "$mpu_object" "$downloaded_file" multipart-complete.json
    set -e
}

test_multipart_upload_resume() {
    log "Testing: Multipart Upload Resume"
    
    local mpu_bucket="mpu-resume-test-$(date +%s)"
    local mpu_object="resume-test-file.bin"
    local part_size=6291456  # 6MB (above minimum part size)
    local total_size=15728640  # 15MB (exactly 2.5 parts)
    
    # Create test bucket
    set +e
    aws_s3api create-bucket --bucket "$mpu_bucket" 2>/dev/null
    local create_exit_code=$?
    set -e
    
    if [ $create_exit_code -ne 0 ]; then
        error "MPU resume test - Failed to create test bucket"
        return 1
    fi
    
    # Create a test file
    log "  Creating $total_size byte test file..."
    dd if=/dev/urandom of="$mpu_object" bs=1024 count=$((total_size / 1024)) 2>/dev/null
    local original_md5=$(md5sum "$mpu_object" | cut -d' ' -f1)
    
    # Initiate multipart upload
    set +e
    initiate_result=$(aws_s3api create-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" 2>&1)
    local initiate_exit_code=$?
    set -e
    
    if [ $initiate_exit_code -ne 0 ]; then
        error "MPU resume test - Failed to initiate multipart upload: $initiate_result"
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    local upload_id=$(echo "$initiate_result" | jq -r '.UploadId // empty')
    log "  Upload ID: $upload_id"
    
    # Upload first part only
    log "  Uploading part 1..."
    local part1_file="part1.bin"
    dd if="$mpu_object" of="$part1_file" bs=1 count=$part_size 2>/dev/null
    
    set +e
    part1_result=$(aws_s3api upload-part --bucket "$mpu_bucket" --key "$mpu_object" --part-number 1 --upload-id "$upload_id" --body "$part1_file" 2>&1)
    local part1_exit_code=$?
    set -e
    
    if [ $part1_exit_code -ne 0 ]; then
        error "MPU resume test - Failed to upload part 1: $part1_result"
        aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    # Get ETag via list-parts since upload-part doesn't output ETags
    log "  Getting part 1 ETag via list-parts..."
    
    set +e
    list_result=$(aws_s3api list-parts --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" --max-parts 1 2>&1)
    local list_exit_code=$?
    set -e
    
    if [ $list_exit_code -eq 0 ]; then
        echo "=== DEBUG: list-parts response for part 1 (resume test) ==="
        echo "$list_result"
        echo "=== END DEBUG ==="
        
        # Extract ETag and Size from list-parts response - simplified robust approach
        # Try the most straightforward jq approach first
        part1_etag=$(echo "$list_result" | jq -r '.Parts[0].ETag' 2>/dev/null)
        part1_size=$(echo "$list_result" | jq -r '.Parts[0].Size' 2>/dev/null)
        echo "DEBUG: part1 jq direct array access result: ETag='$part1_etag', Size='$part1_size'"
        
        # If jq fails completely, use a robust sed approach that handles escaped quotes
        if [ -z "$part1_etag" ] || [ "$part1_etag" = "null" ]; then
            # Extract the full ETag value including any escaped quotes
            part1_etag=$(echo "$list_result" | sed -n 's/.*"ETag": *"\(.*\)".*/\1/p' | head -1)
            # Remove escaped quotes from the ETag value
            part1_etag=$(echo "$part1_etag" | sed 's/\\\"//g')
            echo "DEBUG: part1 sed extraction result: '$part1_etag'"
        fi
        
        # If sed fails, try jq as a fallback
        if [ -z "$part1_etag" ]; then
            part1_etag=$(echo "$list_result" | jq -r '.Parts[0].ETag // empty')
            echo "DEBUG: part1 jq fallback extraction result: '$part1_etag'"
        fi
    else
        echo "DEBUG: part1 list-parts failed with exit code $list_exit_code"
        echo "DEBUG: part1 list-parts error: $list_result"
        log "  Warning: list-parts failed, using placeholder ETag"
        part1_etag="placeholder-etag-1"
    fi
    
    log "  Part 1 uploaded with ETag: '$part1_etag'"
    
    # Safety check for empty ETag
    if [ -z "$part1_etag" ] || [ "$part1_etag" = "null" ]; then
        error "MPU resume test - Failed to extract ETag for part 1 from response. List result: $list_result"
        aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    # Simulate interruption - now "resume" by listing existing parts
    log "  Simulating interruption and resuming..."
    
    set +e
    list_parts_result=$(aws_s3api list-parts --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>&1)
    local list_exit_code=$?
    set -e
    
    if [ $list_exit_code -ne 0 ]; then
        error "MPU resume test - Failed to list existing parts: $list_parts_result"
        aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    # Verify part 1 is listed
    if echo "$list_parts_result" | jq -e '.Parts[]? | select(.PartNumber == 1)' >/dev/null 2>&1; then
        success "MPU resume test - ListParts correctly shows existing part 1"
    else
        error "MPU resume test - ListParts does not show existing part 1"
        echo "ListParts response: $list_parts_result"
    fi
    
    # Verify ListParts returns size information
    if echo "$list_parts_result" | jq -e '.Parts[]?.Size' >/dev/null 2>&1; then
        success "MPU resume test - ListParts includes part size information"
    else
        error "MPU resume test - ListParts missing size information (required for resume)"
    fi
    
    # Continue with remaining parts - separate file position from server totals
    local bytes_uploaded=$part1_size  # Server-reported total (for tracking completion)
    local file_offset=$part_size      # File position (for dd operations)
    local part_number=2
    local uploaded_parts=("ETag=$part1_etag,PartNumber=1,Size=$part1_size")
    
    while [ $file_offset -lt $total_size ]; do
        local file_remaining=$((total_size - file_offset))
        # Use standard part size, or remaining file data for final part
        local current_part_size=$part_size
        if [ $file_remaining -lt $current_part_size ]; then
            current_part_size=$file_remaining
        fi
        
        # Safety check: if no file data remaining, stop immediately
        if [ $current_part_size -le 0 ]; then
            log "  DEBUG: No more file data to upload (current_part_size=$current_part_size), stopping resume"
            break
        fi
        
        log "  Uploading part $part_number ($current_part_size bytes)..."
        log "  DEBUG: file_offset=$file_offset, bytes_uploaded=$bytes_uploaded, file_remaining=$file_remaining"
        
        local part_file="part$part_number.bin"
        dd if="$mpu_object" of="$part_file" bs=1 skip=$file_offset count=$current_part_size 2>/dev/null
        
        set +e
        part_result=$(aws_s3api upload-part --bucket "$mpu_bucket" --key "$mpu_object" --part-number $part_number --upload-id "$upload_id" --body "$part_file" 2>&1)
        local part_exit_code=$?
        set -e
        
        if [ $part_exit_code -ne 0 ]; then
            error "MPU resume test - Failed to upload part $part_number: $part_result"
            aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
            aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
            return 1
        fi
        
        # Get ETag via list-parts since upload-part doesn't output ETags
        log "  Getting part $part_number ETag via list-parts..."
        
        set +e
        list_result=$(aws_s3api list-parts --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" --part-number-marker $((part_number - 1)) --max-parts 1 2>&1)
        local list_exit_code=$?
        set -e
        
        echo "=== DEBUG: list-parts response for part $part_number (resume continuation) ==="
        echo "Command: aws_s3api list-parts --part-number-marker $((part_number - 1)) --max-parts 1"
        echo "$list_result"
        echo "=== END DEBUG ==="
        
        if [ $list_exit_code -eq 0 ]; then
            # Extract ETag and Size for specific part using json tool
            part_etag=$(echo "$list_result" | json Parts | json -a -c "this.PartNumber === $part_number" ETag)
            part_size=$(echo "$list_result" | json Parts | json -a -c "this.PartNumber === $part_number" Size)
            echo "DEBUG: part $part_number json tool result: ETag='$part_etag', Size='$part_size'"
        else
            log "  Warning: list-parts failed, using placeholder ETag"
            part_etag="placeholder-etag-$part_number"
        fi
        
        log "  Part $part_number ETag: '$part_etag'"
        uploaded_parts+=("ETag=$part_etag,PartNumber=$part_number,Size=$part_size")
        
        # Use actual part size from server - this is the correct approach for S3 MPU
        if [ -n "$part_size" ] && [ "$part_size" -gt 0 ] 2>/dev/null; then
            bytes_uploaded=$((bytes_uploaded + part_size))
            echo "DEBUG: Resume MPU Part $part_number - using server size $part_size for bytes_uploaded calculation"
        else
            bytes_uploaded=$((bytes_uploaded + current_part_size))
            echo "DEBUG: Resume MPU Part $part_number - server size empty/zero, falling back to calculated size $current_part_size"
        fi
        
        # Always advance file offset by the actual bytes read from file
        file_offset=$((file_offset + current_part_size))
        part_number=$((part_number + 1))
        rm -f "$part_file"
    done
    
    success "MPU resume test - Resumed and completed upload with $((part_number - 1)) total parts"
    
    # Complete multipart upload
    local parts_json="{"
    parts_json+="\"Parts\": ["
    for i in "${!uploaded_parts[@]}"; do
        if [ $i -gt 0 ]; then
            parts_json+=","
        fi
        local part_info="${uploaded_parts[$i]}"
        local etag=$(echo "$part_info" | cut -d',' -f1 | cut -d'=' -f2)
        local part_num=$(echo "$part_info" | cut -d',' -f2 | cut -d'=' -f2)
        local part_size=$(echo "$part_info" | cut -d',' -f3 | cut -d'=' -f2)
        # Ensure ETag is properly quoted - remove any existing quotes first
        etag=$(echo "$etag" | sed 's/^"//;s/"$//')
        if [ -n "$etag" ]; then
            etag="\"$etag\""
        else
            etag='""'
        fi
        parts_json+="{\"ETag\": $etag, \"PartNumber\": $part_num}"
    done
    parts_json+="]}"
    
    log "  Generated resume JSON: $parts_json"
    echo "$parts_json" > multipart-resume-complete.json
    
    # Debug: Show the exact JSON being sent to complete-multipart-upload
    log "  DEBUG: Resume JSON content being sent to complete-multipart-upload:"
    cat multipart-resume-complete.json
    
    set +e
    complete_result=$(aws_s3api complete-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" --multipart-upload file://multipart-resume-complete.json 2>&1)
    local complete_exit_code=$?
    set -e
    
    if [ $complete_exit_code -ne 0 ]; then
        error "MPU resume test - Failed to complete multipart upload: $complete_result"
        aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    success "MPU resume test - Resumed multipart upload completed successfully"
    
    # Verify the uploaded object
    local downloaded_file="downloaded-resume-$mpu_object"
    set +e
    aws_s3api get-object --bucket "$mpu_bucket" --key "$mpu_object" "$downloaded_file" 2>/dev/null
    local download_exit_code=$?
    set -e
    
    if [ $download_exit_code -eq 0 ] && [ -f "$downloaded_file" ]; then
        local downloaded_md5=$(md5sum "$downloaded_file" | cut -d' ' -f1)
        if [ "$original_md5" = "$downloaded_md5" ]; then
            success "MPU resume test - Downloaded file MD5 matches original ($original_md5)"
        else
            error "MPU resume test - Downloaded file MD5 mismatch! Original: $original_md5, Downloaded: $downloaded_md5"
        fi
    else
        error "MPU resume test - Failed to download completed resumed multipart upload"
    fi
    
    # Cleanup
    set +e
    aws_s3api delete-object --bucket "$mpu_bucket" --key "$mpu_object" 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
    rm -f "$mpu_object" "$downloaded_file" "$part1_file" multipart-resume-complete.json
    set -e
}

test_multipart_upload_errors() {
    log "Testing: Multipart Upload Error Handling"
    
    local mpu_bucket="mpu-error-test-$(date +%s)"
    local mpu_object="error-test-file.bin"
    
    # Create test bucket
    set +e
    aws_s3api create-bucket --bucket "$mpu_bucket" 2>/dev/null
    local create_exit_code=$?
    set -e
    
    if [ $create_exit_code -ne 0 ]; then
        error "MPU error test - Failed to create test bucket"
        return 1
    fi
    
    # Create a small test file (< 5MB)
    local small_size=4194304  # 4MB
    log "  Creating $small_size byte test file..."
    dd if=/dev/urandom of="$mpu_object" bs=1024 count=$((small_size / 1024)) 2>/dev/null
    
    # Initiate multipart upload
    set +e
    initiate_result=$(aws_s3api create-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" 2>&1)
    local initiate_exit_code=$?
    set -e
    
    if [ $initiate_exit_code -ne 0 ]; then
        error "MPU error test - Failed to initiate multipart upload: $initiate_result"
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    local upload_id=$(echo "$initiate_result" | jq -r '.UploadId // empty')
    
    # Upload a small part (should fail with EntityTooSmall if not final part)
    log "  Testing EntityTooSmall error for 4MB non-final part..."
    
    # Create two 4MB parts to test EntityTooSmall error
    local part1_file="small-part1.bin"
    local part2_file="small-part2.bin"
    dd if="$mpu_object" of="$part1_file" bs=1 count=4194304 2>/dev/null
    dd if="$mpu_object" of="$part2_file" bs=1 count=4194304 2>/dev/null
    
    # Upload part 1 (4MB - should fail as it's not final)
    set +e
    part1_result=$(aws_s3api upload-part --bucket "$mpu_bucket" --key "$mpu_object" --part-number 1 --upload-id "$upload_id" --body "$part1_file" 2>&1)
    local part1_exit_code=$?
    set -e
    
    # Upload part 2 to make part 1 non-final, then complete to trigger EntityTooSmall
    set +e
    part2_result=$(aws_s3api upload-part --bucket "$mpu_bucket" --key "$mpu_object" --part-number 2 --upload-id "$upload_id" --body "$part2_file" 2>&1)
    local part2_exit_code=$?
    set -e
    
    if [ $part1_exit_code -eq 0 ] && [ $part2_exit_code -eq 0 ]; then
        log "  Parts uploaded, now testing complete with EntityTooSmall validation..."
        
        # Get ETags via list-parts since upload-part doesn't output ETags
        log "  Getting ETags via list-parts..."
        
        set +e
        list_result=$(aws_s3api list-parts --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>&1)
        local list_exit_code=$?
        set -e
        
        if [ $list_exit_code -eq 0 ]; then
            echo "=== DEBUG: list-parts response for error test ==="
            echo "$list_result"
            echo "=== END DEBUG ==="
            
            # Extract ETags from list-parts response - simplified robust approach
            # Try direct array access for both parts
            part1_etag=$(echo "$list_result" | jq -r '.Parts[0].ETag' 2>/dev/null)
            part2_etag=$(echo "$list_result" | jq -r '.Parts[1].ETag' 2>/dev/null)
            echo "DEBUG: error test part1 jq direct access result: '$part1_etag'"
            echo "DEBUG: error test part2 jq direct access result: '$part2_etag'"
            
            # If jq fails, use robust sed approach that handles escaped quotes
            if [ -z "$part1_etag" ] || [ "$part1_etag" = "null" ]; then
                all_etags=$(echo "$list_result" | sed -n 's/.*"ETag": *"\(.*\)".*/\1/p')
                part1_etag=$(echo "$all_etags" | head -1 | sed 's/\\\"//g')
                echo "DEBUG: error test part1 sed result: '$part1_etag'"
            fi
            if [ -z "$part2_etag" ] || [ "$part2_etag" = "null" ]; then
                all_etags=$(echo "$list_result" | sed -n 's/.*"ETag": *"\(.*\)".*/\1/p')
                part2_etag=$(echo "$all_etags" | tail -1 | sed 's/\\\"//g')
                echo "DEBUG: error test part2 sed result: '$part2_etag'"
            fi
            
            # Final fallback - awk approach
            if [ -z "$part1_etag" ]; then
                part1_etag=$(echo "$list_result" | jq -r '.Parts[0].ETag // empty')
                echo "DEBUG: error test part1 jq result: '$part1_etag'"
            fi
            if [ -z "$part2_etag" ]; then
                part2_etag=$(echo "$list_result" | jq -r '.Parts[1].ETag // empty')
                echo "DEBUG: error test part2 jq result: '$part2_etag'"
            fi
        else
            log "  Warning: list-parts failed, using placeholder ETags"
            part1_etag="placeholder-etag-1"
            part2_etag="placeholder-etag-2"
        fi
        
        # Ensure ETags are properly quoted - remove any existing quotes first
        part1_etag=$(echo "$part1_etag" | sed 's/^"//;s/"$//')
        part2_etag=$(echo "$part2_etag" | sed 's/^"//;s/"$//')
        if [ -n "$part1_etag" ]; then
            part1_etag="\"$part1_etag\""
        else
            part1_etag='""'
        fi
        if [ -n "$part2_etag" ]; then
            part2_etag="\"$part2_etag\""
        else
            part2_etag='""'
        fi
        local parts_json="{\"Parts\": [{\"ETag\": $part1_etag, \"PartNumber\": 1}, {\"ETag\": $part2_etag, \"PartNumber\": 2}]}"
        log "  Generated error test JSON: $parts_json"
        echo "$parts_json" > multipart-error-complete.json
        
        set +e
        complete_result=$(aws_s3api complete-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" --multipart-upload file://multipart-error-complete.json 2>&1)
        local complete_exit_code=$?
        set -e
        
        if [ $complete_exit_code -ne 0 ]; then
            if echo "$complete_result" | grep -q "EntityTooSmall"; then
                success "MPU error test - EntityTooSmall error properly returned for 4MB non-final part"
            elif echo "$complete_result" | grep -q "Part.*too small"; then
                success "MPU error test - Part too small error properly returned for 4MB non-final part"
            else
                error "MPU error test - Expected EntityTooSmall error but got: $complete_result"
            fi
        else
            error "MPU error test - Complete should have failed with EntityTooSmall for 4MB parts"
        fi
    else
        warning "MPU error test - Could not upload parts to test EntityTooSmall (parts may have been rejected earlier)"
    fi
    
    # Test aborting multipart upload
    log "  Testing abort multipart upload..."
    set +e
    abort_result=$(aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>&1)
    local abort_exit_code=$?
    set -e
    
    if [ $abort_exit_code -eq 0 ]; then
        success "MPU error test - Multipart upload aborted successfully"
    else
        error "MPU error test - Failed to abort multipart upload: $abort_result"
    fi
    
    # Cleanup
    set +e
    aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
    rm -f "$mpu_object" "$part1_file" "$part2_file" multipart-error-complete.json
    set -e
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

# AWS CLI ACL tests
test_aws_get_bucket_acl() {
    log "Testing: AWS CLI Get Bucket ACL"
    
    set +e
    local result=$(aws_s3api get-bucket-acl --bucket "$TEST_BUCKET" 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "AWS CLI get bucket ACL - Retrieved bucket ACL successfully"
    else
        error "AWS CLI get bucket ACL - Failed to get bucket ACL: $result"
    fi
}

test_aws_get_object_acl() {
    log "Testing: AWS CLI Get Object ACL"
    
    # First upload a test object
    echo "ACL test content" > "acl-test-object.txt"
    set +e
    aws_s3api put-object --bucket "$TEST_BUCKET" --key "acl-test-object.txt" --body "acl-test-object.txt" 2>/dev/null
    local put_exit_code=$?
    set -e
    
    if [ $put_exit_code -eq 0 ]; then
        set +e
        local result=$(aws_s3api get-object-acl --bucket "$TEST_BUCKET" --key "acl-test-object.txt" 2>&1)
        local exit_code=$?
        set -e
        
        if [ $exit_code -eq 0 ]; then
            success "AWS CLI get object ACL - Retrieved object ACL successfully"
        else
            error "AWS CLI get object ACL - Failed to get object ACL: $result"
        fi
    else
        error "AWS CLI get object ACL - Failed to upload test object"
    fi
    
    rm -f "acl-test-object.txt"
}

test_aws_put_object_with_canned_acl() {
    local acl_type="$1"
    local test_file="acl-test-$acl_type.txt"
    
    log "Testing: AWS CLI Put Object with Canned ACL ($acl_type)"
    
    echo "Test content for $acl_type ACL" > "$test_file"
    
    set +e
    local result=$(aws_s3api put-object --bucket "$TEST_BUCKET" --key "$test_file" --body "$test_file" --acl "$acl_type" 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "AWS CLI put object with $acl_type ACL - Upload successful"
        
        # Try to get ACL of the object to verify it was set
        set +e
        local acl_result=$(aws_s3api get-object-acl --bucket "$TEST_BUCKET" --key "$test_file" 2>&1)
        local acl_exit_code=$?
        set -e
        
        if [ $acl_exit_code -eq 0 ]; then
            success "AWS CLI put object with $acl_type ACL - Object ACL retrieved"
        else
            warning "AWS CLI put object with $acl_type ACL - Could not retrieve object ACL: $acl_result"
        fi
    else
        error "AWS CLI put object with $acl_type ACL - Failed to upload: $result"
    fi
    
    rm -f "$test_file"
}

test_aws_put_bucket_acl() {
    log "Testing: AWS CLI Put Bucket ACL"
    
    set +e
    local result=$(aws_s3api put-bucket-acl --bucket "$TEST_BUCKET" --acl "private" 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "AWS CLI put bucket ACL - Successfully set private ACL on bucket"
    else
        error "AWS CLI put bucket ACL - Failed to set private ACL: $result"
    fi
}

test_aws_put_object_acl() {
    log "Testing: AWS CLI Put Object ACL"
    
    # First upload a test object
    echo "ACL set test content" > "acl-set-test-object.txt"
    set +e
    aws_s3api put-object --bucket "$TEST_BUCKET" --key "acl-set-test-object.txt" --body "acl-set-test-object.txt" 2>/dev/null
    local put_exit_code=$?
    set -e
    
    if [ $put_exit_code -eq 0 ]; then
        set +e
        local result=$(aws_s3api put-object-acl --bucket "$TEST_BUCKET" --key "acl-set-test-object.txt" --acl "private" 2>&1)
        local exit_code=$?
        set -e
        
        if [ $exit_code -eq 0 ]; then
            success "AWS CLI put object ACL - Successfully set private ACL on object"
        else
            error "AWS CLI put object ACL - Failed to set private ACL: $result"
        fi
    else
        error "AWS CLI put object ACL - Failed to upload test object"
    fi
    
    rm -f "acl-set-test-object.txt"
}

test_aws_canned_acls() {
    log "Testing: AWS CLI Various Canned ACLs"
    
    # Test different canned ACL types that are supported
    local acl_types=("private" "public-read" "public-read-write")
    
    for acl in "${acl_types[@]}"; do
        test_aws_put_object_with_canned_acl "$acl"
    done
}

test_aws_bucket_acl_policy() {
    log "Testing: AWS CLI Bucket ACL Policy Operations"
    
    # Try to set bucket to public-read
    set +e
    local result=$(aws_s3api put-bucket-acl --bucket "$TEST_BUCKET" --acl "public-read" 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "AWS CLI bucket ACL policy - Successfully set public-read ACL on bucket"
        
        # Verify the ACL was set by getting bucket ACL
        set +e
        local acl_result=$(aws_s3api get-bucket-acl --bucket "$TEST_BUCKET" 2>&1)
        local acl_exit_code=$?
        set -e
        
        if [ $acl_exit_code -eq 0 ]; then
            success "AWS CLI bucket ACL policy - Retrieved bucket ACL after change"
        else
            warning "AWS CLI bucket ACL policy - Could not retrieve bucket ACL: $acl_result"
        fi
        
        # Set back to private
        set +e
        aws_s3api put-bucket-acl --bucket "$TEST_BUCKET" --acl "private" 2>/dev/null || true
        set -e
    else
        error "AWS CLI bucket ACL policy - Failed to set public-read ACL: $result"
    fi
}

test_aws_list_objects_with_metadata() {
    log "Testing: AWS CLI List Objects with Metadata"
    
    set +e
    local result=$(aws_s3api list-objects-v2 --bucket "$TEST_BUCKET" 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "AWS CLI list with metadata - Object listing successful"
    else
        error "AWS CLI list with metadata - Failed to list objects: $result"
    fi
}

# Test AWS CLI presigned URL generation and usage
test_aws_cli_presigned_urls() {
    log "Testing: AWS CLI Presigned URL Generation and Usage"
    
    local presigned_test_object="presigned-test-object.txt"
    local presigned_content="Test content for presigned URL - $(date +%s)"
    local presigned_download_file="downloaded-presigned.txt"
    
    # Create test file
    echo "$presigned_content" > "$presigned_test_object"
    
    # Upload object first using regular API
    set +e
    aws_s3api put-object --bucket "$TEST_BUCKET" --key "$presigned_test_object" --body "$presigned_test_object" 2>/dev/null
    local put_exit_code=$?
    set -e
    
    if [ $put_exit_code -ne 0 ]; then
        error "Presigned URL test - Failed to upload test object"
        rm -f "$presigned_test_object"
        return 1
    fi
    
    # Generate presigned URL for GET operation (1 hour expiry)
    set +e
    local presigned_get_url=$(aws s3 presign "s3://$TEST_BUCKET/$presigned_test_object" --expires-in 3600 2>&1)
    local presign_exit_code=$?
    set -e
    
    if [ $presign_exit_code -eq 0 ]; then
        success "AWS CLI presigned URL - Generated GET presigned URL"
        log "  Presigned URL: ${presigned_get_url:0:100}..."
        
        # Test the presigned URL with curl
        set +e
        local curl_response=$(curl -s -w "%{http_code}" --insecure "$presigned_get_url" -o "$presigned_download_file" 2>&1)
        local curl_exit_code=$?
        local http_code="${curl_response: -3}"
        set -e
        
        if [ $curl_exit_code -eq 0 ] && [ "$http_code" = "200" ]; then
            success "AWS CLI presigned GET - Successfully downloaded using presigned URL"
            
            # Verify content
            if [ -f "$presigned_download_file" ]; then
                local downloaded_content=$(cat "$presigned_download_file")
                if [ "$downloaded_content" = "$presigned_content" ]; then
                    success "AWS CLI presigned GET - Downloaded content matches original"
                else
                    error "AWS CLI presigned GET - Content mismatch via presigned URL"
                fi
            else
                error "AWS CLI presigned GET - Download file not created"
            fi
        else
            error "AWS CLI presigned GET - Failed to download via presigned URL (HTTP $http_code)"
        fi
        
    else
        error "AWS CLI presigned URL - Failed to generate GET presigned URL: $presigned_get_url"
    fi
    
    # Cleanup
    set +e
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$presigned_test_object" 2>/dev/null || true
    rm -f "$presigned_test_object" "$presigned_download_file"
    set -e
}

# Test presigned URL PUT operations using manual signature calculation
test_presigned_url_put_operations() {
    log "Testing: Presigned URL PUT Operations"
    
    local put_test_object="presigned-put-test.txt"
    local put_test_content="PUT test via presigned URL - $(date +%s)"
    echo "$put_test_content" > "$put_test_object"
    
    # Use our manual presigned URL script to generate a proper PUT URL
    # Since AWS CLI doesn't support generating PUT presigned URLs directly
    local temp_bucket="put-presigned-$(date +%s)"
    
    # Create temporary bucket for PUT test
    set +e
    aws_s3api create-bucket --bucket "$temp_bucket" 2>/dev/null
    local bucket_exit_code=$?
    set -e
    
    if [ $bucket_exit_code -ne 0 ]; then
        error "Presigned PUT test - Failed to create temporary bucket"
        rm -f "$put_test_object"
        return 1
    fi
    
    # Generate presigned PUT URL using embedded signature calculation
    log "  Generating PUT presigned URL using embedded signature calculation..."
    
    # HMAC helper functions (embedded in AWS CLI test)
    hmac_sha256() {
        local key="$1"
        local data="$2"
        echo -n "$data" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$key" -binary | xxd -p -c 256
    }

    hmac_sha256_string() {
        local key="$1"
        local data="$2"
        echo -n "$data" | openssl dgst -sha256 -mac HMAC -macopt key:"$key" -binary | xxd -p -c 256
    }
    
    # Create a PUT presigned URL generator
    local now=$(date -u +"%Y%m%dT%H%M%SZ")
    local date_stamp=$(echo "$now" | cut -c1-8)
    local credential="${AWS_ACCESS_KEY_ID}/${date_stamp}/${AWS_REGION}/s3/aws4_request"
    local host=$(echo "$S3_ENDPOINT" | sed 's|^https://||' | sed 's|^http://||' | sed 's|/.*$||')
    
    # Build canonical request for PUT
    local canonical_uri="/${temp_bucket}/${put_test_object}"
    local canonical_querystring="X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=${credential}&X-Amz-Date=${now}&X-Amz-Expires=300&X-Amz-SignedHeaders=host"
    canonical_querystring=$(echo "$canonical_querystring" | sed 's|/|%2F|g')
    
    local canonical_headers="host:${host}
"
    local canonical_request="PUT
${canonical_uri}
${canonical_querystring}
${canonical_headers}
host
UNSIGNED-PAYLOAD"
    
    # Create string to sign
    local algorithm="AWS4-HMAC-SHA256"
    local credential_scope="${date_stamp}/${AWS_REGION}/s3/aws4_request"
    local canonical_request_hash=$(echo -n "$canonical_request" | openssl dgst -sha256 -hex | cut -d' ' -f2)
    
    local string_to_sign="${algorithm}
${now}
${credential_scope}
${canonical_request_hash}"
    
    # Calculate signature using embedded HMAC functions
    local kDate=$(hmac_sha256_string "AWS4${AWS_SECRET_ACCESS_KEY}" "$date_stamp")
    local kRegion=$(hmac_sha256 "$kDate" "$AWS_REGION")
    local kService=$(hmac_sha256 "$kRegion" "s3")
    local kSigning=$(hmac_sha256 "$kService" "aws4_request")
    local signature=$(echo -n "$string_to_sign" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$kSigning" -hex | cut -d' ' -f2)
    
    local put_presigned_url="${S3_ENDPOINT}/${temp_bucket}/${put_test_object}?${canonical_querystring}&X-Amz-Signature=${signature}"
    
    log "  Generated PUT presigned URL: ${put_presigned_url:0:100}..."
    
    # Test PUT with curl
    set +e
    local put_curl_response=$(curl -s -w "%{http_code}" -X PUT --data-binary "@$put_test_object" --insecure "$put_presigned_url" 2>&1)
    local put_curl_exit_code=$?
    local put_http_code="${put_curl_response: -3}"
    set -e
    
    if [ $put_curl_exit_code -eq 0 ] && [ "$put_http_code" -ge 200 ] && [ "$put_http_code" -lt 300 ]; then
        success "Presigned PUT - Successfully uploaded using presigned PUT URL"
        
        # Verify the object was uploaded by downloading it
        set +e
        local verify_download="verify-put-download.txt"
        aws_s3api get-object --bucket "$temp_bucket" --key "$put_test_object" "$verify_download" 2>/dev/null
        local verify_exit_code=$?
        set -e
        
        if [ $verify_exit_code -eq 0 ] && [ -f "$verify_download" ]; then
            local verify_content=$(cat "$verify_download")
            if [ "$verify_content" = "$put_test_content" ]; then
                success "Presigned PUT - PUT via presigned URL verified"
            else
                error "Presigned PUT - PUT content verification failed"
            fi
            rm -f "$verify_download"
        else
            error "Presigned PUT - Could not verify PUT operation"
        fi
    else
        error "Presigned PUT - Failed to upload via presigned PUT URL (HTTP $put_http_code)"
    fi
    
    # Cleanup
    set +e
    aws s3 rm "s3://$temp_bucket" --recursive 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$temp_bucket" 2>/dev/null || true
    rm -f "$put_test_object"
    set -e
}

# Test presigned URL expiry
test_presigned_url_expiry() {
    log "Testing: Presigned URL Expiry Validation"
    
    local expiry_test_object="expiry-test-object.txt"
    echo "Expiry test content" > "$expiry_test_object"
    
    # Upload test object
    set +e
    aws_s3api put-object --bucket "$TEST_BUCKET" --key "$expiry_test_object" --body "$expiry_test_object" 2>/dev/null
    local put_exit_code=$?
    set -e
    
    if [ $put_exit_code -eq 0 ]; then
        # Generate presigned URL with very short expiry (1 second)
        set +e
        local short_expiry_url=$(aws s3 presign "s3://$TEST_BUCKET/$expiry_test_object" --expires-in 1 2>&1)
        local presign_exit_code=$?
        set -e
        
        if [ $presign_exit_code -eq 0 ]; then
            # Wait for URL to expire
            log "  Waiting for presigned URL to expire..."
            sleep 2
            
            # Test expired URL
            set +e
            local curl_response=$(curl -s -w "%{http_code}" --insecure "$short_expiry_url" 2>&1)
            local curl_exit_code=$?
            local http_code="${curl_response: -3}"
            set -e
            
            if [ "$http_code" = "403" ] || [ "$http_code" = "400" ]; then
                success "Presigned URL expiry - Expired URL properly rejected"
            else
                error "Presigned URL expiry - Expected 400/403 for expired URL, got $http_code"
            fi
        else
            error "Presigned URL expiry - Failed to generate short-expiry URL: $short_expiry_url"
        fi
    else
        error "Presigned URL expiry - Failed to upload test object"
    fi
    
    # Cleanup
    set +e
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$expiry_test_object" 2>/dev/null || true
    rm -f "$expiry_test_object"
    set -e
}

# Main test execution
run_tests() {
    local test_filter="${1:-all}"
    
    case "$test_filter" in
        "mpu"|"multipart")
            log "Starting S3 Multipart Upload Tests for manta-buckets-api using AWS CLI"
            log "================================================================="
            
            set +e  # Disable exit on error for test execution
            
            # Create bucket for MPU tests
            test_create_bucket || true
            
            # Multipart upload tests only
            test_multipart_upload_basic || true
            test_multipart_upload_resume || true
            test_multipart_upload_errors || true
            
            # Clean up any objects before deleting bucket
            log "Cleaning up test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            # Cleanup bucket
            test_delete_bucket || true
            
            set -e  # Re-enable exit on error
            ;;
        "basic")
            log "Starting S3 Basic Functionality Tests for manta-buckets-api using AWS CLI"
            log "================================================================="
            
            set +e  # Disable exit on error for test execution
            
            # Basic functionality tests only
            test_list_buckets || true
            test_create_bucket || true
            test_head_bucket || true
            test_list_bucket_objects || true
            test_put_object || true
            test_head_object || true
            test_get_object || true
            test_object_checksum_integrity || true
            test_list_bucket_objects_with_content || true
            test_conditional_headers || true
            test_delete_object || true
            
            # Clean up any objects before deleting bucket
            log "Cleaning up test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            test_delete_bucket || true
            
            set -e  # Re-enable exit on error
            ;;
        "errors")
            log "Starting S3 Error Handling Tests for manta-buckets-api using AWS CLI"
            log "================================================================="
            
            set +e  # Disable exit on error for test execution
            
            # Error handling tests only
            test_nonexistent_bucket || true
            test_nonexistent_object || true
            
            set -e  # Re-enable exit on error
            ;;
        "acl")
            log "Starting S3 ACL Tests for manta-buckets-api using AWS CLI"
            log "========================================================="
            
            set +e  # Disable exit on error for test execution
            
            # Create bucket for ACL tests
            test_create_bucket || true
            
            # ACL tests only
            test_aws_get_bucket_acl || true
            test_aws_get_object_acl || true
            test_aws_put_bucket_acl || true
            test_aws_put_object_acl || true
            test_aws_canned_acls || true
            test_aws_bucket_acl_policy || true
            test_aws_list_objects_with_metadata || true
            
            # Clean up ACL test objects before deleting bucket
            log "Cleaning up ACL test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            # Cleanup bucket
            test_delete_bucket || true
            
            set -e  # Re-enable exit on error
            ;;
        "presigned")
            log "Starting S3 Presigned URL Tests for manta-buckets-api using AWS CLI"
            log "================================================================"
            
            set +e  # Disable exit on error for test execution
            
            # Create bucket for presigned URL tests
            test_create_bucket || true
            
            # Presigned URL tests only
            test_aws_cli_presigned_urls || true
            test_presigned_url_put_operations || true
            test_presigned_url_expiry || true
            
            # Clean up test objects before deleting bucket
            log "Cleaning up presigned URL test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            # Cleanup bucket
            test_delete_bucket || true
            
            set -e  # Re-enable exit on error
            ;;
        "all"|*)
            log "Starting S3 Compatibility Tests (including ACL) for manta-buckets-api using AWS CLI"
            log "================================================================================="
            
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
            test_conditional_headers || true
            test_delete_object || true
            
            # Multipart upload tests
            test_multipart_upload_basic || true
            test_multipart_upload_resume || true
            test_multipart_upload_errors || true
            
            # ACL tests (run before deleting the main test bucket)
            test_aws_get_bucket_acl || true
            test_aws_get_object_acl || true
            test_aws_put_bucket_acl || true
            test_aws_put_object_acl || true
            test_aws_canned_acls || true
            test_aws_bucket_acl_policy || true
            test_aws_list_objects_with_metadata || true
            
            # Presigned URL tests
            test_aws_cli_presigned_urls || true
            test_presigned_url_put_operations || true
            test_presigned_url_expiry || true
            
            # Clean up any test objects before deleting bucket
            log "Cleaning up ACL test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            test_delete_bucket || true
            
            # Error handling tests (run after main bucket is deleted)
            test_nonexistent_bucket || true
            test_nonexistent_object || true
            
            set -e  # Re-enable exit on error
            ;;
    esac
    
    set -e  # Re-enable exit on error
}

# Print test results
print_results() {
    log "===================================================================="
    log "AWS CLI Test Results Summary"
    log "===================================================================="
    
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
        echo -e "\n${GREEN}🎉 All AWS CLI tests passed! S3 compatibility is working correctly.${NC}"
        exit 0
    fi
}

# Main execution
main() {
    # Handle command line arguments
    local test_type="all"
    
    case "${1:-}" in
        -h|--help)
            echo "S3 Compatibility Test Script for manta-buckets-api using AWS CLI"
            echo
            echo "Usage: $0 [test_type] [options]"
            echo
            echo "Test Types:"
            echo "  all        - Run all tests including ACL (default)"
            echo "  basic      - Run basic S3 functionality tests only"
            echo "  mpu        - Run multipart upload tests only"
            echo "  multipart  - Alias for mpu"
            echo "  acl        - Run ACL tests only"
            echo "  errors     - Run error handling tests only"
            echo "  presigned  - Run presigned URL tests only"
            echo
            echo "Environment variables:"
            echo "  AWS_ACCESS_KEY_ID     - AWS access key (default: AKIA123456789EXAMPLE)"
            echo "  AWS_SECRET_ACCESS_KEY - AWS secret key (default: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)"
            echo "  S3_ENDPOINT          - S3 endpoint URL (default: https://localhost:8080)"
            echo "  AWS_REGION           - AWS region (default: us-east-1)"
            echo
            echo "Examples:"
            echo "  $0                    # Run all tests including ACL"
            echo "  $0 mpu                # Run only multipart upload tests"
            echo "  $0 basic              # Run only basic functionality tests"
            echo "  $0 acl                # Run only ACL tests"
            echo "  $0 errors             # Run only error handling tests"
            echo "  $0 presigned          # Run only presigned URL tests"
            echo "  AWS_ACCESS_KEY_ID=mykey AWS_SECRET_ACCESS_KEY=mysecret $0 mpu"
            echo "  S3_ENDPOINT=https://manta.example.com:8080 $0 basic"
            echo
            echo "Note: This script requires AWS CLI to be installed and configured."
            exit 0
            ;;
        "mpu"|"multipart"|"basic"|"errors"|"presigned"|"acl"|"all")
            test_type="$1"
            ;;
        "")
            test_type="all"
            ;;
        *)
            echo "Unknown test type: $1"
            echo "Use -h or --help for usage information."
            exit 1
            ;;
    esac
    
    # Set up trap for cleanup
    trap cleanup EXIT
    
    # Run the tests
    setup
    run_tests "$test_type"
    print_results
}

# Execute main function
main "$@"
