#!/bin/bash
# Copyright 2025 Edgecast Cloud LLC.
# S3 Compatibility Test - Server-Side Copy and Conditional Headers
#
# Tests S3 server-side copy operations and conditional request headers:
# - Basic server-side copy
# - Metadata directives (COPY, REPLACE)
# - Copy with special characters
# - Conditional headers (If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since)

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Functions
# =============================================================================

test_server_side_copy() {
    log "Testing: Server-Side Copy Object"

    # Create source objects for copy tests
    local source_object="source-object.txt"
    local dest_object="dest-object.txt"
    local copy_content="Content for server-side copy test - $(date +%s)"

    # Create source file and upload
    echo "$copy_content" > "$source_object"

    set +e
    result=$(aws_s3api put-object --bucket "$TEST_BUCKET" --key "$source_object" --body "$source_object" 2>&1)
    local put_exit_code=$?
    set -e

    if [ $put_exit_code -ne 0 ]; then
        error "Server-side copy - Failed to upload source object: $result"
        return 1
    fi

    # Test 1: Basic server-side copy
    log "  Testing basic server-side copy..."
    set +e
    result=$(aws_s3api copy-object \
        --bucket "$TEST_BUCKET" \
        --key "$dest_object" \
        --copy-source "$TEST_BUCKET/$source_object" 2>&1)
    local copy_exit_code=$?
    set -e

    if [ $copy_exit_code -eq 0 ]; then
        if echo "$result" | jq -e '.CopyObjectResult.ETag' >/dev/null 2>&1; then
            success "Server-side copy - Basic copy successful with ETag"

            # Verify copied object exists and has correct content
            local downloaded_copy="downloaded-$dest_object"
            if aws_s3api get-object --bucket "$TEST_BUCKET" --key "$dest_object" "$downloaded_copy" 2>/dev/null; then
                local copied_content=$(cat "$downloaded_copy")
                if [ "$copied_content" = "$copy_content" ]; then
                    success "Server-side copy - Copied content matches source"
                else
                    error "Server-side copy - Content mismatch. Expected: '$copy_content', Got: '$copied_content'"
                fi
                rm -f "$downloaded_copy"
            else
                error "Server-side copy - Failed to download copied object"
            fi
        else
            error "Server-side copy - Response missing ETag: $result"
        fi
    else
        error "Server-side copy - Failed to copy object: $result"
        return 1
    fi

    # Test 2: Server-side copy with metadata directive COPY (default)
    log "  Testing server-side copy with metadata directive COPY..."
    local dest_object_copy="dest-object-copy.txt"

    set +e
    result=$(aws_s3api copy-object \
        --bucket "$TEST_BUCKET" \
        --key "$dest_object_copy" \
        --copy-source "$TEST_BUCKET/$source_object" \
        --metadata-directive COPY 2>&1)
    local copy_directive_exit_code=$?
    set -e

    if [ $copy_directive_exit_code -eq 0 ]; then
        success "Server-side copy - Copy with COPY metadata directive successful"
    else
        error "Server-side copy - Failed with COPY metadata directive: $result"
    fi

    # Test 3: Server-side copy with metadata directive REPLACE
    log "  Testing server-side copy with metadata directive REPLACE..."
    local dest_object_replace="dest-object-replace.txt"

    set +e
    result=$(aws_s3api copy-object \
        --bucket "$TEST_BUCKET" \
        --key "$dest_object_replace" \
        --copy-source "$TEST_BUCKET/$source_object" \
        --metadata-directive REPLACE \
        --content-type "text/plain" \
        --metadata "test-key=test-value,copy-test=replaced" 2>&1)
    local replace_exit_code=$?
    set -e

    if [ $replace_exit_code -eq 0 ]; then
        success "Server-side copy - Copy with REPLACE metadata directive successful"

        # Verify new metadata was applied
        set +e
        metadata_result=$(aws_s3api head-object --bucket "$TEST_BUCKET" --key "$dest_object_replace" 2>&1)
        local head_exit_code=$?
        set -e

        if [ $head_exit_code -eq 0 ]; then
            if echo "$metadata_result" | jq -e '.Metadata."test-key"' | grep -q "test-value" && \
               echo "$metadata_result" | jq -e '.Metadata."copy-test"' | grep -q "replaced"; then
                success "Server-side copy - Custom metadata applied correctly"
            else
                warning "Server-side copy - Custom metadata might not be applied as expected: $metadata_result"
            fi
        else
            error "Server-side copy - Failed to retrieve metadata for replaced object: $metadata_result"
        fi
    else
        error "Server-side copy - Failed with REPLACE metadata directive: $result"
    fi

    # Test 4: Cross-object copy (same bucket, different paths)
    log "  Testing server-side copy to different path..."
    local dest_nested_object="nested/path/dest-object.txt"

    set +e
    result=$(aws_s3api copy-object \
        --bucket "$TEST_BUCKET" \
        --key "$dest_nested_object" \
        --copy-source "$TEST_BUCKET/$source_object" 2>&1)
    local nested_copy_exit_code=$?
    set -e

    if [ $nested_copy_exit_code -eq 0 ]; then
        success "Server-side copy - Copy to nested path successful"

        # Verify object exists at nested path
        if aws_s3api head-object --bucket "$TEST_BUCKET" --key "$dest_nested_object" 2>/dev/null; then
            success "Server-side copy - Object exists at nested path"
        else
            error "Server-side copy - Object not found at nested path"
        fi
    else
        error "Server-side copy - Failed to copy to nested path: $result"
    fi

    # Test 5: Copy with special characters in object name
    log "  Testing server-side copy with special characters..."
    local special_source="special source with spaces & symbols!.txt"
    local special_dest="special dest with spaces & symbols!.txt"

    # Create source object with special characters
    echo "Special character test content" > "special-temp.txt"

    set +e
    aws_s3api put-object --bucket "$TEST_BUCKET" --key "$special_source" --body "special-temp.txt" 2>/dev/null
    local special_put_exit_code=$?
    set -e

    if [ $special_put_exit_code -eq 0 ]; then
        set +e
        result=$(aws_s3api copy-object \
            --bucket "$TEST_BUCKET" \
            --key "$special_dest" \
            --copy-source "$TEST_BUCKET/$special_source" 2>&1)
        local special_copy_exit_code=$?
        set -e

        if [ $special_copy_exit_code -eq 0 ]; then
            success "Server-side copy - Copy with special characters successful"
        else
            warning "Server-side copy - Copy with special characters failed (may be expected): $result"
        fi
    else
        warning "Server-side copy - Failed to create source object with special characters"
    fi

    # Cleanup test files
    rm -f "$source_object" "special-temp.txt"

    # Clean up test objects (ignore errors for cleanup)
    set +e
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$source_object" 2>/dev/null
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$dest_object" 2>/dev/null
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$dest_object_copy" 2>/dev/null
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$dest_object_replace" 2>/dev/null
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$dest_nested_object" 2>/dev/null
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$special_source" 2>/dev/null
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$special_dest" 2>/dev/null
    set -e
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

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "=========================================="
    log "S3 Server-Side Copy and Conditional Headers Test Suite"
    log "=========================================="

    setup

    # Create test bucket
    log "Creating test bucket: $TEST_BUCKET"
    set +e
    aws_s3api create-bucket --bucket "$TEST_BUCKET" >/dev/null 2>&1
    local create_exit=$?
    set -e

    if [ $create_exit -ne 0 ]; then
        log "Note: Bucket creation returned non-zero, may already exist"
    fi

    # Run tests in order
    test_server_side_copy
    test_conditional_headers

    cleanup_basic
    print_summary
}

main
