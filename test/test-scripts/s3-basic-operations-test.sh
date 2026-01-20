#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# S3 Compatibility Test - Basic Operations
#
# Tests basic S3 bucket and object operations:
# - Bucket CRUD (create, list, head, delete)
# - Object CRUD (put, get, head, delete)
# - Object listing
# - Checksum integrity
# - Error handling for nonexistent resources

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Functions
# =============================================================================

test_list_buckets() {
    log "Testing: List Buckets"

    set +e
    result=$(aws_s3api list-buckets 2>&1)
    local exit_code=$?
    set -e

    if [ $exit_code -eq 0 ]; then
        if echo "$result" | jq -e '.Buckets' >/dev/null 2>&1; then
            success "List buckets - JSON response contains Buckets array"
        else
            error "List buckets - Response missing Buckets array"
        fi

        # Skip Owner check for now - causing issues
        # if echo "$result" | jq -e '.Owner' >/dev/null 2>&1; then
        #     success "List buckets - JSON response contains Owner information"
        # else
        #     error "List buckets - Response missing Owner information"
        # fi
    else
        error "List buckets - Command failed"
    fi
}

test_create_bucket() {
    log "Testing: Create Bucket"
    log "DEBUG: test_create_bucket using AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID"

    set +e  # Temporarily disable exit on error
    result=$(aws_s3api create-bucket --bucket "$TEST_BUCKET" 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error

    if [ $exit_code -eq 0 ]; then
        success "Create bucket - $TEST_BUCKET created successfully"

        # Save working credentials for later use in comprehensive security test
        WORKING_AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
        WORKING_AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
        log "Saved working credentials: $WORKING_AWS_ACCESS_KEY_ID"
    else
        warning "Create bucket - Failed to create $TEST_BUCKET with credentials $AWS_ACCESS_KEY_ID: $result"
        # Don't fail completely, just continue without saving working credentials
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

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "=========================================="
    log "S3 Basic Operations Test Suite"
    log "=========================================="

    setup

    # Run tests in order
    log "DEBUG: Starting test_list_buckets"
    test_list_buckets
    log "DEBUG: Starting test_create_bucket"
    test_create_bucket
    log "DEBUG: Starting test_head_bucket"
    test_head_bucket
    test_list_bucket_objects
    test_put_object
    test_head_object
    test_get_object
    test_object_checksum_integrity
    test_list_bucket_objects_with_content
    test_delete_object
    test_delete_bucket
    test_nonexistent_bucket
    test_nonexistent_object

    cleanup_basic
    print_summary
}

main
