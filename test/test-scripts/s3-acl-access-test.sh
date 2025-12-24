#!/bin/bash
# Copyright 2025 Edgecast Cloud LLC.
# S3 Compatibility Test - ACL and Access Control
#
# Tests S3 access control list (ACL) functionality:
# - Bucket and object ACL operations (GET/PUT)
# - Canned ACLs (private, public-read, etc.)
# - ACL policy enforcement
# - Anonymous access scenarios
# - ACL validation and error handling

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Functions
# =============================================================================

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

# Test anonymous access to objects in public bucket
test_anonymous_access_public_bucket() {
    log "Testing: Anonymous Access to Objects in 'public' Bucket"
    
    local public_bucket="public"
    local test_object="anonymous-test-object.txt"
    local test_content="Test content for anonymous access - $(date +%s)"
    local download_file="anonymous-download.txt"
    
    # Create test file
    echo "$test_content" > "$test_object"
    
    # Create public bucket
    set +e
    aws_s3api create-bucket --bucket "$public_bucket" 2>/dev/null
    local bucket_exit_code=$?
    set -e
    
    if [ $bucket_exit_code -ne 0 ]; then
        warning "Anonymous access test - Failed to create public bucket (may already exist)"
    fi
    
    # Upload object to public bucket
    set +e
    aws_s3api put-object --bucket "$public_bucket" --key "$test_object" --body "$test_object" 2>/dev/null
    local put_exit_code=$?
    set -e
    
    if [ $put_exit_code -ne 0 ]; then
        error "Anonymous access test - Failed to upload object to public bucket"
        rm -f "$test_object"
        return 1
    fi
    
    # Test anonymous access using curl (no AWS credentials) - use Manta URL format
    set +e
    local anonymous_url="${S3_ENDPOINT}/${MANTA_USER}/buckets/${public_bucket}/objects/${test_object}"
    local curl_response=$(curl -s -w "%{http_code}" --insecure "$anonymous_url" -o "$download_file" 2>&1)
    local curl_exit_code=$?
    local http_code="${curl_response: -3}"
    set -e
    
    if [ $curl_exit_code -eq 0 ] && [ "$http_code" = "200" ]; then
        # Verify content matches
        if [ -f "$download_file" ] && cmp -s "$test_object" "$download_file"; then
            success "Anonymous access - Successfully accessed object in 'public' bucket"
        else
            error "Anonymous access - Downloaded content doesn't match original"
        fi
    else
        error "Anonymous access - Failed to access object in 'public' bucket (HTTP: $http_code)"
    fi
    
    # Clean up
    rm -f "$test_object" "$download_file"
    set +e
    aws_s3api delete-object --bucket "$public_bucket" --key "$test_object" 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$public_bucket" 2>/dev/null || true
    set -e
}

# Test anonymous access to objects with public-read ACL in private bucket
test_anonymous_access_public_acl() {
    log "Testing: Anonymous Access to Objects with public-read ACL in Private Bucket"
    
    local test_object="public-acl-test-object.txt"
    local test_content="Test content for public ACL anonymous access - $(date +%s)"
    local download_file="public-acl-download.txt"
    
    # Create test file
    echo "$test_content" > "$test_object"
    
    # Upload object with public-read ACL to regular (private) bucket
    set +e
    aws_s3api put-object --bucket "$TEST_BUCKET" --key "$test_object" --body "$test_object" --acl "public-read" 2>/dev/null
    local put_exit_code=$?
    set -e
    
    if [ $put_exit_code -ne 0 ]; then
        error "Public ACL anonymous access test - Failed to upload object with public-read ACL"
        rm -f "$test_object"
        return 1
    fi
    
    # Verify the ACL was set correctly
    set +e
    local acl_result=$(aws_s3api get-object-acl --bucket "$TEST_BUCKET" --key "$test_object" 2>&1)
    local acl_exit_code=$?
    set -e
    
    if [ $acl_exit_code -eq 0 ]; then
        log "  Object ACL set successfully"
    else
        warning "Public ACL anonymous access test - Could not verify ACL: $acl_result"
    fi
    
    # Test anonymous access using curl (no AWS credentials) - use Manta URL format
    set +e
    local anonymous_url="${S3_ENDPOINT}/${MANTA_USER}/buckets/${TEST_BUCKET}/objects/${test_object}"
    local curl_response=$(curl -s -w "%{http_code}" --insecure "$anonymous_url" -o "$download_file" 2>&1)
    local curl_exit_code=$?
    local http_code="${curl_response: -3}"
    set -e
    
    if [ $curl_exit_code -eq 0 ] && [ "$http_code" = "200" ]; then
        # Verify content matches
        if [ -f "$download_file" ] && cmp -s "$test_object" "$download_file"; then
            success "Public ACL anonymous access - Successfully accessed object with public-read ACL"
        else
            error "Public ACL anonymous access - Downloaded content doesn't match original"
        fi
    else
        error "Public ACL anonymous access - Failed to access object with public-read ACL (HTTP: $http_code)"
    fi
    
    # Clean up
    rm -f "$test_object" "$download_file"
    set +e
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$test_object" 2>/dev/null || true
    set -e
}

# Test that anonymous access is denied for private objects
test_anonymous_access_denied() {
    log "Testing: Anonymous Access Denied for Private Objects"
    
    local test_object="private-test-object.txt"
    local test_content="Private test content - $(date +%s)"
    local download_file="private-download.txt"
    
    # Create test file
    echo "$test_content" > "$test_object"
    
    # Upload object without public ACL to regular (private) bucket
    set +e
    aws_s3api put-object --bucket "$TEST_BUCKET" --key "$test_object" --body "$test_object" 2>/dev/null
    local put_exit_code=$?
    set -e
    
    if [ $put_exit_code -ne 0 ]; then
        error "Private access test - Failed to upload private object"
        rm -f "$test_object"
        return 1
    fi
    
    # Test anonymous access using curl (no AWS credentials) - should fail - use Manta URL format
    set +e
    local anonymous_url="${S3_ENDPOINT}/${MANTA_USER}/buckets/${TEST_BUCKET}/objects/${test_object}"
    local curl_response=$(curl -s -w "%{http_code}" --insecure "$anonymous_url" -o "$download_file" 2>&1)
    local curl_exit_code=$?
    local http_code="${curl_response: -3}"
    set -e
    
    # We expect this to fail (403 or 401)
    if [ "$http_code" = "403" ] || [ "$http_code" = "401" ]; then
        success "Anonymous access denied - Correctly denied access to private object (HTTP: $http_code)"
    else
        error "Anonymous access denied - Expected 403/401 but got HTTP: $http_code"
    fi
    
    # Clean up
    rm -f "$test_object" "$download_file"
    set +e
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$test_object" 2>/dev/null || true
    set -e
}

# Test AWS CLI presigned URL generation and usage

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "=========================================="
    log "S3 ACL and Access Control Test Suite"
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
    test_aws_get_bucket_acl
    test_aws_get_object_acl
    test_aws_put_object_with_canned_acl
    test_aws_put_bucket_acl
    test_aws_put_object_acl
    test_aws_canned_acls
    test_aws_bucket_acl_policy
    test_aws_list_objects_with_metadata
    test_anonymous_access_public_bucket
    test_anonymous_access_public_acl
    test_anonymous_access_denied

    cleanup_basic
    print_summary
}

main
