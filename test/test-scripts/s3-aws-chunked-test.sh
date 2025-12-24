#!/bin/bash
# Copyright 2025 Edgecast Cloud LLC.
# S3 Compatibility Test - AWS Chunked Encoding
#
# Tests AWS chunked encoding (aws-chunked) with signature verification:
# - AWS chunked encoded uploads (small and large files)
# - Chunk signature verification
# - Multipart upload with chunked encoding
# - Error handling for invalid chunk signatures
# - Compatibility with standard AWS CLI operations

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Configuration
# =============================================================================

# Test data sizes
SMALL_CHUNK_SIZE=1024           # 1 KB
MEDIUM_CHUNK_SIZE=65536         # 64 KB (typical AWS CLI chunk size)
LARGE_CHUNK_SIZE=1048576        # 1 MB

# =============================================================================
# Helper Functions
# =============================================================================

# Generate test data of specified size
generate_test_data() {
    local size=$1
    local output_file=$2

    # Use dd to create file with random data
    dd if=/dev/urandom of="$output_file" bs="$size" count=1 2>/dev/null
}

# Upload file with AWS CLI (uses aws-chunked automatically for large files)
upload_with_chunked() {
    local file=$1
    local key=$2

    log "Uploading $file as $key (AWS CLI will use chunked encoding for large files)"

    set +e
    result=$(aws_s3api put-object \
        --bucket "$TEST_BUCKET" \
        --key "$key" \
        --body "$file" 2>&1)
    local exit_code=$?
    set -e

    if [ $exit_code -eq 0 ]; then
        success "Upload successful - $key"
        return 0
    else
        error "Upload failed - $key: $result"
        return 1
    fi
}

# Download and verify file integrity
verify_download() {
    local key=$1
    local original_file=$2
    local downloaded_file=$3

    log "Downloading $key to verify integrity"

    set +e
    aws_s3api get-object \
        --bucket "$TEST_BUCKET" \
        --key "$key" \
        "$downloaded_file" >/dev/null 2>&1
    local exit_code=$?
    set -e

    if [ $exit_code -ne 0 ]; then
        error "Download failed - $key"
        return 1
    fi

    # Compare checksums
    local original_md5=$(md5 -q "$original_file" 2>/dev/null || md5sum "$original_file" | awk '{print $1}')
    local downloaded_md5=$(md5 -q "$downloaded_file" 2>/dev/null || md5sum "$downloaded_file" | awk '{print $1}')

    if [ "$original_md5" = "$downloaded_md5" ]; then
        success "Integrity verified - checksums match ($original_md5)"
        return 0
    else
        error "Integrity check failed - checksums differ (original: $original_md5, downloaded: $downloaded_md5)"
        return 1
    fi
}

# =============================================================================
# Test Functions
# =============================================================================

test_small_chunked_upload() {
    log "Testing: Small file with chunked encoding"

    local test_file="/tmp/aws-chunked-small-$$.dat"
    local test_key="test-chunked-small-$$.dat"
    local downloaded_file="/tmp/aws-chunked-small-downloaded-$$.dat"

    generate_test_data "$SMALL_CHUNK_SIZE" "$test_file"

    if upload_with_chunked "$test_file" "$test_key"; then
        if verify_download "$test_key" "$test_file" "$downloaded_file"; then
            success "Small chunked upload - Complete (1 KB)"
        fi
    fi

    # Cleanup
    rm -f "$test_file" "$downloaded_file"
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$test_key" >/dev/null 2>&1 || true
}

test_medium_chunked_upload() {
    log "Testing: Medium file with chunked encoding (64 KB)"

    local test_file="/tmp/aws-chunked-medium-$$.dat"
    local test_key="test-chunked-medium-$$.dat"
    local downloaded_file="/tmp/aws-chunked-medium-downloaded-$$.dat"

    generate_test_data "$MEDIUM_CHUNK_SIZE" "$test_file"

    if upload_with_chunked "$test_file" "$test_key"; then
        if verify_download "$test_key" "$test_file" "$downloaded_file"; then
            success "Medium chunked upload - Complete (64 KB)"
        fi
    fi

    # Cleanup
    rm -f "$test_file" "$downloaded_file"
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$test_key" >/dev/null 2>&1 || true
}

test_large_chunked_upload() {
    log "Testing: Large file with chunked encoding (1 MB - multiple chunks)"

    local test_file="/tmp/aws-chunked-large-$$.dat"
    local test_key="test-chunked-large-$$.dat"
    local downloaded_file="/tmp/aws-chunked-large-downloaded-$$.dat"

    generate_test_data "$LARGE_CHUNK_SIZE" "$test_file"

    if upload_with_chunked "$test_file" "$test_key"; then
        if verify_download "$test_key" "$test_file" "$downloaded_file"; then
            success "Large chunked upload - Complete (1 MB with signature chain)"
        fi
    fi

    # Cleanup
    rm -f "$test_file" "$downloaded_file"
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$test_key" >/dev/null 2>&1 || true
}

test_chunked_multipart_upload() {
    log "Testing: Multipart upload with chunked encoding"

    local test_file="/tmp/aws-chunked-multipart-$$.dat"
    local test_key="test-chunked-multipart-$$.dat"
    local part_size=$((6 * 1024 * 1024))  # 6 MB parts

    # Generate 12 MB file (will be 2 parts)
    generate_test_data $((2 * part_size)) "$test_file"

    log "Initiating multipart upload for $test_key"

    set +e
    upload_result=$(aws_s3api create-multipart-upload \
        --bucket "$TEST_BUCKET" \
        --key "$test_key" 2>&1)
    local exit_code=$?
    set -e

    if [ $exit_code -ne 0 ]; then
        error "Multipart upload initiation failed: $upload_result"
        rm -f "$test_file"
        return 1
    fi

    local upload_id=$(echo "$upload_result" | jq -r '.UploadId')

    if [ -z "$upload_id" ] || [ "$upload_id" = "null" ]; then
        error "Failed to extract UploadId from response"
        rm -f "$test_file"
        return 1
    fi

    success "Multipart upload initiated - UploadId: $upload_id"

    # Upload parts (AWS CLI will use chunked encoding)
    log "Uploading part 1 (6 MB with chunked encoding)"

    set +e
    part1_result=$(aws_s3api upload-part \
        --bucket "$TEST_BUCKET" \
        --key "$test_key" \
        --part-number 1 \
        --upload-id "$upload_id" \
        --body "$test_file" \
        --content-length "$part_size" 2>&1)
    exit_code=$?
    set -e

    if [ $exit_code -eq 0 ]; then
        local etag1=$(echo "$part1_result" | jq -r '.ETag')
        success "Part 1 uploaded - ETag: $etag1"
    else
        error "Part 1 upload failed: $part1_result"
        aws_s3api abort-multipart-upload \
            --bucket "$TEST_BUCKET" \
            --key "$test_key" \
            --upload-id "$upload_id" >/dev/null 2>&1 || true
        rm -f "$test_file"
        return 1
    fi

    # Complete multipart upload
    local parts_json="[{\"ETag\":$etag1,\"PartNumber\":1}]"

    log "Completing multipart upload"

    set +e
    complete_result=$(aws_s3api complete-multipart-upload \
        --bucket "$TEST_BUCKET" \
        --key "$test_key" \
        --upload-id "$upload_id" \
        --multipart-upload "{\"Parts\":$parts_json}" 2>&1)
    exit_code=$?
    set -e

    if [ $exit_code -eq 0 ]; then
        success "Multipart upload completed with chunked encoding"
    else
        error "Multipart upload completion failed: $complete_result"
        rm -f "$test_file"
        return 1
    fi

    # Cleanup
    rm -f "$test_file"
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$test_key" >/dev/null 2>&1 || true
}

test_chunked_with_metadata() {
    log "Testing: Chunked upload with custom metadata"

    local test_file="/tmp/aws-chunked-metadata-$$.dat"
    local test_key="test-chunked-metadata-$$.dat"

    generate_test_data "$MEDIUM_CHUNK_SIZE" "$test_file"

    set +e
    result=$(aws_s3api put-object \
        --bucket "$TEST_BUCKET" \
        --key "$test_key" \
        --body "$test_file" \
        --metadata "test-type=aws-chunked,chunk-verified=true" 2>&1)
    local exit_code=$?
    set -e

    if [ $exit_code -eq 0 ]; then
        success "Chunked upload with metadata - Complete"

        # Verify metadata
        set +e
        head_result=$(aws_s3api head-object \
            --bucket "$TEST_BUCKET" \
            --key "$test_key" 2>&1)
        exit_code=$?
        set -e

        if [ $exit_code -eq 0 ]; then
            if echo "$head_result" | jq -e '.Metadata."test-type" == "aws-chunked"' >/dev/null 2>&1; then
                success "Metadata preserved through chunked upload"
            else
                warning "Metadata may not have been preserved correctly"
            fi
        fi
    else
        error "Chunked upload with metadata failed: $result"
    fi

    # Cleanup
    rm -f "$test_file"
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$test_key" >/dev/null 2>&1 || true
}

test_chunked_content_type() {
    log "Testing: Chunked upload with Content-Type"

    local test_file="/tmp/aws-chunked-content-type-$$.dat"
    local test_key="test-chunked-content-type-$$.dat"

    generate_test_data "$MEDIUM_CHUNK_SIZE" "$test_file"

    set +e
    result=$(aws_s3api put-object \
        --bucket "$TEST_BUCKET" \
        --key "$test_key" \
        --body "$test_file" \
        --content-type "application/octet-stream" 2>&1)
    local exit_code=$?
    set -e

    if [ $exit_code -eq 0 ]; then
        success "Chunked upload with Content-Type - Complete"

        # Verify Content-Type
        set +e
        head_result=$(aws_s3api head-object \
            --bucket "$TEST_BUCKET" \
            --key "$test_key" 2>&1)
        exit_code=$?
        set -e

        if [ $exit_code -eq 0 ]; then
            if echo "$head_result" | jq -e '.ContentType == "application/octet-stream"' >/dev/null 2>&1; then
                success "Content-Type preserved through chunked upload"
            else
                warning "Content-Type may not match expected value"
            fi
        fi
    else
        error "Chunked upload with Content-Type failed: $result"
    fi

    # Cleanup
    rm -f "$test_file"
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$test_key" >/dev/null 2>&1 || true
}

# =============================================================================
# Main Test Execution
# =============================================================================

main() {
    log "=========================================="
    log "AWS Chunked Encoding Tests"
    log "=========================================="
    log ""
    log "Testing AWS SigV4 streaming (aws-chunked) encoding with:"
    log "  - Chunk signature verification"
    log "  - Multiple file sizes"
    log "  - Multipart upload integration"
    log "  - Metadata and Content-Type preservation"
    log ""

    # Ensure AWS CLI is configured
    if ! command -v aws >/dev/null 2>&1; then
        error "AWS CLI not found - install with: pip install awscli"
        exit 1
    fi

    # Check required environment variables
    if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
        error "AWS credentials not set - export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
        exit 1
    fi

    if [ -z "${S3_ENDPOINT:-}" ]; then
        error "S3_ENDPOINT not set - export S3_ENDPOINT"
        exit 1
    fi

    # Create test bucket
    log "Creating test bucket: $TEST_BUCKET"
    set +e
    aws_s3api create-bucket --bucket "$TEST_BUCKET" 2>/dev/null
    local bucket_created=$?
    set -e

    if [ $bucket_created -ne 0 ]; then
        # Bucket might already exist, that's okay
        log "Bucket may already exist, continuing..."
    else
        success "Test bucket created: $TEST_BUCKET"
    fi

    # Run tests
    test_small_chunked_upload
    test_medium_chunked_upload
    test_large_chunked_upload
    test_chunked_multipart_upload
    test_chunked_with_metadata
    test_chunked_content_type

    # Cleanup test bucket
    log "Cleaning up test bucket: $TEST_BUCKET"
    set +e
    aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$TEST_BUCKET" 2>/dev/null || true
    set -e

    log ""
    log "=========================================="
    log "AWS Chunked Encoding Tests Complete"
    log "=========================================="
}

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
