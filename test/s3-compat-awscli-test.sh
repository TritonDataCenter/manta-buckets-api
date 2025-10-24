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
MANTA_USER=${MANTA_USER:-""}

# Check required environment variables
if [ -z "$MANTA_USER" ]; then
    echo "ERROR: MANTA_USER environment variable is required for anonymous access tests"
    exit 1
fi

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

test_bulk_delete_objects() {
    log "Testing: Bulk Delete Objects"
    
    # Create multiple test objects for bulk deletion
    local bulk_objects=("bulk-test-1.txt" "bulk-test-2.txt" "bulk-test-3.txt")
    local bulk_content="Bulk delete test content - $(date +%s)"
    
    # Create and upload test objects
    log "Creating objects for bulk delete test..."
    for obj in "${bulk_objects[@]}"; do
        echo "$bulk_content" > "$TEMP_DIR/$obj"
        
        set +e
        result=$(aws_s3api put-object --bucket "$TEST_BUCKET" --key "$obj" --body "$TEMP_DIR/$obj" 2>&1)
        exit_code=$?
        set -e
        
        if [ $exit_code -ne 0 ]; then
            error "Bulk delete - Failed to create test object $obj: $result"
            return
        fi
    done
    
    # Verify objects exist before deletion
    log "Verifying objects exist before bulk deletion..."
    for obj in "${bulk_objects[@]}"; do
        if ! aws_s3api head-object --bucket "$TEST_BUCKET" --key "$obj" 2>/dev/null; then
            error "Bulk delete - Test object $obj does not exist before deletion"
            return
        fi
    done
    success "Bulk delete - All test objects created successfully"
    
    # Create delete request JSON
    local delete_json="$TEMP_DIR/bulk-delete.json"
    cat > "$delete_json" << EOF
{
    "Objects": [
        {"Key": "${bulk_objects[0]}"},
        {"Key": "${bulk_objects[1]}"},
        {"Key": "${bulk_objects[2]}"}
    ],
    "Quiet": false
}
EOF
    
    # Perform bulk delete
    log "Performing bulk delete operation..."
    set +e
    result=$(aws_s3api delete-objects --bucket "$TEST_BUCKET" --delete "file://$delete_json" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "Bulk delete - delete-objects command executed successfully"
        
        # Parse response to check for deleted objects
        if echo "$result" | grep -q "Deleted"; then
            success "Bulk delete - Response indicates objects were deleted"
        else
            error "Bulk delete - Response does not indicate successful deletion: $result"
        fi
        
        # Verify objects are actually deleted
        log "Verifying objects were deleted..."
        all_deleted=true
        for obj in "${bulk_objects[@]}"; do
            if aws_s3api head-object --bucket "$TEST_BUCKET" --key "$obj" 2>/dev/null; then
                error "Bulk delete - Object $obj still exists after bulk deletion"
                all_deleted=false
            fi
        done
        
        if $all_deleted; then
            success "Bulk delete - All objects successfully deleted"
        fi
    else
        error "Bulk delete - delete-objects command failed: $result"
    fi
    
    # Cleanup
    rm -f "$delete_json"
    for obj in "${bulk_objects[@]}"; do
        rm -f "$TEMP_DIR/$obj"
        # Try to delete in case bulk delete failed
        aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$obj" 2>/dev/null || true
    done
}

test_bulk_delete_with_errors() {
    log "Testing: Bulk Delete with Mixed Success/Errors"
    
    # Create some test objects and include non-existent ones
    local existing_objects=("bulk-error-1.txt" "bulk-error-2.txt")
    local nonexistent_objects=("nonexistent-1.txt" "nonexistent-2.txt")
    local bulk_content="Bulk delete error test - $(date +%s)"
    
    # Create and upload existing objects
    log "Creating objects for bulk delete error test..."
    for obj in "${existing_objects[@]}"; do
        echo "$bulk_content" > "$TEMP_DIR/$obj"
        
        set +e
        result=$(aws_s3api put-object --bucket "$TEST_BUCKET" --key "$obj" --body "$TEMP_DIR/$obj" 2>&1)
        exit_code=$?
        set -e
        
        if [ $exit_code -ne 0 ]; then
            error "Bulk delete errors - Failed to create test object $obj: $result"
            return
        fi
    done
    
    # Create delete request JSON with mix of existing and non-existing objects
    local delete_json="$TEMP_DIR/bulk-delete-errors.json"
    cat > "$delete_json" << EOF
{
    "Objects": [
        {"Key": "${existing_objects[0]}"},
        {"Key": "${nonexistent_objects[0]}"},
        {"Key": "${existing_objects[1]}"},
        {"Key": "${nonexistent_objects[1]}"}
    ],
    "Quiet": false
}
EOF
    
    # Perform bulk delete
    log "Performing bulk delete with mixed existing/non-existing objects..."
    set +e
    result=$(aws_s3api delete-objects --bucket "$TEST_BUCKET" --delete "file://$delete_json" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "Bulk delete errors - delete-objects command completed"
        
        # Check response contains both deleted objects and errors
        if echo "$result" | grep -q "Deleted"; then
            success "Bulk delete errors - Response contains deleted objects"
        else
            warning "Bulk delete errors - Response does not show deleted objects"
        fi
        
        if echo "$result" | grep -q "Errors\|Error"; then
            success "Bulk delete errors - Response contains expected errors for non-existent objects"
        else
            warning "Bulk delete errors - Response does not show errors for non-existent objects"
        fi
        
        # Verify existing objects were deleted
        for obj in "${existing_objects[@]}"; do
            if ! aws_s3api head-object --bucket "$TEST_BUCKET" --key "$obj" 2>/dev/null; then
                success "Bulk delete errors - Existing object $obj was successfully deleted"
            else
                error "Bulk delete errors - Existing object $obj still exists"
            fi
        done
    else
        error "Bulk delete errors - delete-objects command failed: $result"
    fi
    
    # Cleanup
    rm -f "$delete_json"
    for obj in "${existing_objects[@]}"; do
        rm -f "$TEMP_DIR/$obj"
        # Try to delete in case bulk delete failed
        aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$obj" 2>/dev/null || true
    done
}

test_bulk_delete_special_chars() {
    log "Testing: Bulk Delete with Special Characters in Object Names"
    
    # Create objects with special characters (URL encoding test)
    local special_objects=("object with spaces.txt" "object(with)parentheses.txt" "object+with+plus.txt")
    local bulk_content="Special chars bulk delete test - $(date +%s)"
    local actual_stored_keys=()
    
    # Create and upload test objects
    log "Creating objects with special characters for bulk delete test..."
    for obj in "${special_objects[@]}"; do
        echo "$bulk_content" > "$TEMP_DIR/special-temp.txt"
        
        set +e
        result=$(aws_s3api put-object --bucket "$TEST_BUCKET" --key "$obj" --body "$TEMP_DIR/special-temp.txt" 2>&1)
        exit_code=$?
        set -e
        
        if [ $exit_code -ne 0 ]; then
            error "Bulk delete special chars - Failed to create test object '$obj': $result"
            continue
        fi
        
        # Verify object was created and discover how it's actually stored
        if aws_s3api head-object --bucket "$TEST_BUCKET" --key "$obj" 2>/dev/null; then
            success "Bulk delete special chars - Object '$obj' created successfully"
            actual_stored_keys+=("$obj")
        else
            error "Bulk delete special chars - Object '$obj' not found after upload"
        fi
    done
    
    # List objects to see how they're actually stored
    log "Discovering actual stored object keys..."
    set +e
    list_result=$(aws_s3api list-objects --bucket "$TEST_BUCKET" 2>&1)
    list_exit_code=$?
    set -e
    
    if [ $list_exit_code -eq 0 ]; then
        log "Current objects in bucket:"
        echo "$list_result" | grep '"Key"' || echo "No objects with Key field found"
    else
        warning "Could not list objects to verify storage format: $list_result"
    fi
    
    # Use the keys exactly as we created them for the delete operation
    # This tests whether the simplified bulk delete approach works with special characters
    local delete_json="$TEMP_DIR/bulk-delete-special.json"
    
    if [ ${#actual_stored_keys[@]} -gt 0 ]; then
        # Build JSON dynamically based on successfully created objects
        echo '{' > "$delete_json"
        echo '    "Objects": [' >> "$delete_json"
        for i in "${!actual_stored_keys[@]}"; do
            if [ $i -gt 0 ]; then
                echo ',' >> "$delete_json"
            fi
            echo "        {\"Key\": \"${actual_stored_keys[$i]}\"}" >> "$delete_json"
        done
        echo '' >> "$delete_json"
        echo '    ],' >> "$delete_json"
        echo '    "Quiet": false' >> "$delete_json"
        echo '}' >> "$delete_json"
        
        # Perform bulk delete
        log "Performing bulk delete with special character object names..."
        set +e
        result=$(aws_s3api delete-objects --bucket "$TEST_BUCKET" --delete "file://$delete_json" 2>&1)
        exit_code=$?
        set -e
        
        if [ $exit_code -eq 0 ]; then
            success "Bulk delete special chars - delete-objects command completed"
            
            # Check if response indicates success
            if echo "$result" | grep -q "Deleted"; then
                success "Bulk delete special chars - Response indicates successful deletions"
            else
                warning "Bulk delete special chars - Response does not show 'Deleted' status: $result"
            fi
            
            # Verify objects are deleted
            log "Verifying special character objects were deleted..."
            all_deleted=true
            for obj in "${actual_stored_keys[@]}"; do
                if aws_s3api head-object --bucket "$TEST_BUCKET" --key "$obj" 2>/dev/null; then
                    error "Bulk delete special chars - Object '$obj' still exists after deletion"
                    all_deleted=false
                else
                    success "Bulk delete special chars - Object '$obj' successfully deleted"
                fi
            done
            
            if $all_deleted; then
                success "Bulk delete special chars - All special character objects deleted successfully"
            else
                error "Bulk delete special chars - Some objects were not deleted (expected with simplified approach if encoding mismatch)"
            fi
        else
            error "Bulk delete special chars - delete-objects command failed: $result"
        fi
    else
        warning "Bulk delete special chars - No objects were successfully created, skipping delete test"
    fi
    
    # Cleanup
    rm -f "$delete_json" "$TEMP_DIR/special-temp.txt"
    for obj in "${special_objects[@]}"; do
        # Try to delete in case bulk delete failed - try both original and encoded versions
        aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$obj" 2>/dev/null || true
        # Also try URL-encoded versions
        encoded_obj=$(echo "$obj" | sed 's/ /%20/g; s/(/%28/g; s/)/%29/g; s/+/%2B/g')
        if [ "$encoded_obj" != "$obj" ]; then
            aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$encoded_obj" 2>/dev/null || true
        fi
    done
}

test_bulk_delete_empty_request() {
    log "Testing: Bulk Delete with Empty Object List"
    
    # Create delete request JSON with empty object list
    local delete_json="$TEMP_DIR/bulk-delete-empty.json"
    cat > "$delete_json" << EOF
{
    "Objects": [],
    "Quiet": false
}
EOF
    
    # Perform bulk delete with empty list
    log "Performing bulk delete with empty object list..."
    set +e
    result=$(aws_s3api delete-objects --bucket "$TEST_BUCKET" --delete "file://$delete_json" 2>&1)
    exit_code=$?
    set -e
    
    # This should either succeed with empty response or fail with appropriate error
    if [ $exit_code -eq 0 ]; then
        success "Bulk delete empty - Empty delete request completed without error"
    else
        # Check if it's an expected error about empty object list
        if echo "$result" | grep -i "empty\|no.*object\|invalid"; then
            success "Bulk delete empty - Appropriate error returned for empty object list"
        else
            error "Bulk delete empty - Unexpected error for empty object list: $result"
        fi
    fi
    
    # Cleanup
    rm -f "$delete_json"
}

test_bulk_delete_encoded_chars() {
    log "Testing: Bulk Delete with encodeURIComponent Special Characters"
    
    # Create objects with characters that are encoded by encodeURIComponent
    # This tests the full range of characters that require URL encoding
    local encoded_objects=(
        "object with spaces.txt"           # %20
        "object(with)parentheses.txt"      # %28 %29
        "object+with+plus.txt"             # %2B
        "object[with]brackets.txt"         # %5B %5D
        "object{with}braces.txt"           # %7B %7D
        "object@with@at.txt"               # %40
        "object#with#hash.txt"             # %23
        "object\$with\$dollar.txt"         # %24
        "object%with%percent.txt"          # %25
        "object&with&ampersand.txt"        # %26
        "object=with=equals.txt"           # %3D
        "object?with?question.txt"         # %3F
        "object/with/slash.txt"            # %2F
        "object:with:colon.txt"            # %3A
        "object;with;semicolon.txt"        # %3B
        "object,with,comma.txt"            # %2C
        "object'with'apostrophe.txt"       # %27
        "object\"with\"quote.txt"          # %22
        "object<with>angles.txt"           # %3C %3E
        "object|with|pipe.txt"             # %7C
        "object\\with\\backslash.txt"      # %5C
        "object^with^caret.txt"            # %5E
        "object\`with\`backtick.txt"       # %60
        "object~with~tilde.txt"            # %7E
    )
    
    local bulk_content="Encoded chars bulk delete test - $(date +%s)"
    local actual_stored_keys=()
    
    # Create and upload test objects
    log "Creating objects with encodeURIComponent special characters for bulk delete test..."
    for obj in "${encoded_objects[@]}"; do
        echo "$bulk_content" > "$TEMP_DIR/encoded-temp.txt"
        
        set +e
        result=$(aws_s3api put-object --bucket "$TEST_BUCKET" --key "$obj" --body "$TEMP_DIR/encoded-temp.txt" 2>&1)
        exit_code=$?
        set -e
        
        if [ $exit_code -ne 0 ]; then
            warning "Bulk delete encoded chars - Failed to create test object '$obj': $result"
            continue
        else
            success "Bulk delete encoded chars - Created object: '$obj'"
            actual_stored_keys+=("$obj")
        fi
    done
    
    if [ ${#actual_stored_keys[@]} -gt 0 ]; then
        log "Successfully created ${#actual_stored_keys[@]} objects with encoded characters"
        
        # Verify objects exist before deletion
        log "Verifying objects exist before bulk delete..."
        for obj in "${actual_stored_keys[@]}"; do
            if aws_s3api head-object --bucket "$TEST_BUCKET" --key "$obj" 2>/dev/null; then
                success "Bulk delete encoded chars - Object '$obj' confirmed to exist"
            else
                warning "Bulk delete encoded chars - Object '$obj' not found before deletion"
            fi
        done
        
        # Create delete request JSON dynamically
        local delete_json="$TEMP_DIR/bulk-delete-encoded.json"
        cat > "$delete_json" << 'EOF'
{
    "Objects": [
EOF
        
        for i in "${!actual_stored_keys[@]}"; do
            # Escape quotes and backslashes for JSON
            local escaped_key="${actual_stored_keys[i]}"
            escaped_key="${escaped_key//\\/\\\\}"  # Escape backslashes
            escaped_key="${escaped_key//\"/\\\"}"  # Escape quotes
            
            printf "        {\"Key\": \"%s\"}" "$escaped_key" >> "$delete_json"
            if [ $i -lt $((${#actual_stored_keys[@]} - 1)) ]; then
                echo ',' >> "$delete_json"
            else
                echo '' >> "$delete_json"
            fi
        done
        
        cat >> "$delete_json" << 'EOF'
    ],
    "Quiet": false
}
EOF
        
        # Perform bulk delete
        log "Performing bulk delete with encoded character object names..."
        set +e
        result=$(aws_s3api delete-objects --bucket "$TEST_BUCKET" --delete "file://$delete_json" 2>&1)
        exit_code=$?
        set -e
        
        if [ $exit_code -eq 0 ]; then
            success "Bulk delete encoded chars - delete-objects command completed"
            
            # Check if response indicates success
            if echo "$result" | grep -q "Deleted"; then
                success "Bulk delete encoded chars - Response indicates successful deletions"
                
                # Count successful deletions
                local deleted_count=$(echo "$result" | grep -o '"Key"' | wc -l | tr -d ' ')
                log "Bulk delete encoded chars - $deleted_count objects reported as deleted"
            else
                warning "Bulk delete encoded chars - Response does not show 'Deleted' status: $result"
            fi
            
            # Verify objects are deleted
            log "Verifying encoded character objects were deleted..."
            local all_deleted=true
            local successfully_deleted=0
            for obj in "${actual_stored_keys[@]}"; do
                if aws_s3api head-object --bucket "$TEST_BUCKET" --key "$obj" 2>/dev/null; then
                    error "Bulk delete encoded chars - Object '$obj' still exists after deletion"
                    all_deleted=false
                else
                    success "Bulk delete encoded chars - Object '$obj' successfully deleted"
                    ((successfully_deleted++))
                fi
            done
            
            log "Bulk delete encoded chars - Successfully deleted $successfully_deleted out of ${#actual_stored_keys[@]} objects"
            
            if $all_deleted; then
                success "Bulk delete encoded chars - All encoded character objects deleted successfully"
            else
                error "Bulk delete encoded chars - Some objects with encoded characters were not deleted"
            fi
        else
            error "Bulk delete encoded chars - delete-objects command failed: $result"
        fi
    else
        warning "Bulk delete encoded chars - No objects with encoded characters were successfully created, skipping delete test"
    fi
    
    # Cleanup
    rm -f "$delete_json" "$TEMP_DIR/encoded-temp.txt"
    for obj in "${encoded_objects[@]}"; do
        # Try to delete in case bulk delete failed
        aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$obj" 2>/dev/null || true
    done
}

test_server_side_copy() {
    log "Testing: Server-Side Copy Object"
    
    # Create source objects for copy tests
    local source_object="source-object.txt"
    local dest_object="dest-object.txt"
    local copy_content="Content for server-side copy test - $(date +%s)"
    
    # Create source file and upload
    echo "$copy_content" > "$source_object"
    
    set +e  # Temporarily disable exit on error
    result=$(aws_s3api put-object --bucket "$TEST_BUCKET" --key "$source_object" --body "$source_object" 2>&1)
    local put_exit_code=$?
    set -e  # Re-enable exit on error
    
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
    local presigned_get_url=$(aws s3 presign "s3://$TEST_BUCKET/$presigned_test_object" --expires-in 3600 --endpoint-url="$S3_ENDPOINT" 2>&1)
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
        local short_expiry_url=$(aws s3 presign "s3://$TEST_BUCKET/$expiry_test_object" --expires-in 1 --endpoint-url="$S3_ENDPOINT" 2>&1)
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

# Test invalid X-Amz-Date format validation
test_presigned_invalid_date_format() {
    log "Testing: Presigned URL Invalid X-Amz-Date Format Validation"
    
    local invalid_date_object="invalid-date-test.txt"
    echo "Invalid date test content" > "$invalid_date_object"
    
    # Upload test object
    set +e
    aws_s3api put-object --bucket "$TEST_BUCKET" --key "$invalid_date_object" --body "$invalid_date_object" 2>/dev/null
    local put_exit_code=$?
    set -e
    
    if [ $put_exit_code -eq 0 ]; then
        # Generate a valid presigned URL first to get the base URL structure
        set +e
        local valid_url=$(aws s3 presign "s3://$TEST_BUCKET/$invalid_date_object" --expires-in 3600 --endpoint-url="$S3_ENDPOINT" 2>&1)
        local presign_exit_code=$?
        set -e
        
        if [ $presign_exit_code -eq 0 ]; then
            # Test various invalid X-Amz-Date formats by manually crafting URLs
            local base_url="${valid_url%%\?*}"
            local query_params="${valid_url#*\?}"
            
            # Test cases for invalid X-Amz-Date formats
            local test_cases=(
                "invaliddate"                    # Completely invalid format
                "2023-01-01T12:00:00Z"          # ISO format with dashes (should be compact)
                "20230101T120000"               # Missing Z suffix
                "20230101T120000Y"              # Wrong suffix
                "2023010T120000Z"               # Too short
                "202301011T120000Z"             # Too long
                "20230230T120000Z"              # Invalid date (Feb 30)
                "20230101T250000Z"              # Invalid hour
                "20230101T126000Z"              # Invalid minute
                "20230101T120060Z"              # Invalid second
                ""                              # Empty date
            )
            
            local invalid_format_count=0
            
            for invalid_date in "${test_cases[@]}"; do
                # Replace X-Amz-Date parameter in the URL
                local modified_query=$(echo "$query_params" | sed "s/X-Amz-Date=[^&]*/X-Amz-Date=$invalid_date/")
                local test_url="$base_url?$modified_query"
                
                log "  Testing invalid X-Amz-Date: '$invalid_date'"
                
                # Test the modified URL
                set +e
                local curl_response=$(curl -s -w "%{http_code}" --insecure "$test_url" 2>&1)
                local curl_exit_code=$?
                local http_code="${curl_response: -3}"
                set -e
                
                # Should get 400 or 403 for invalid date format
                if [ "$http_code" = "400" ] || [ "$http_code" = "403" ]; then
                    success "Presigned URL validation - Invalid X-Amz-Date '$invalid_date' properly rejected (HTTP $http_code)"
                    ((invalid_format_count++))
                else
                    error "Presigned URL validation - Invalid X-Amz-Date '$invalid_date' should be rejected, got HTTP $http_code"
                fi
            done
            
            log "  Successfully tested $invalid_format_count invalid X-Amz-Date formats"
            
        else
            error "Presigned URL invalid date - Failed to generate base URL: $valid_url"
        fi
    else
        error "Presigned URL invalid date - Failed to upload test object"
    fi
    
    # Cleanup
    set +e
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$invalid_date_object" 2>/dev/null || true
    rm -f "$invalid_date_object"
    set -e
}

# Test invalid X-Amz-Expires validation
test_presigned_invalid_expires() {
    log "Testing: Presigned URL Invalid X-Amz-Expires Validation"
    
    local invalid_expires_object="invalid-expires-test.txt"
    echo "Invalid expires test content" > "$invalid_expires_object"
    
    # Upload test object
    set +e
    aws_s3api put-object --bucket "$TEST_BUCKET" --key "$invalid_expires_object" --body "$invalid_expires_object" 2>/dev/null
    local put_exit_code=$?
    set -e
    
    if [ $put_exit_code -eq 0 ]; then
        # Generate a valid presigned URL first to get the base URL structure
        set +e
        local valid_url=$(aws s3 presign "s3://$TEST_BUCKET/$invalid_expires_object" --expires-in 3600 --endpoint-url="$S3_ENDPOINT" 2>&1)
        local presign_exit_code=$?
        set -e
        
        if [ $presign_exit_code -eq 0 ]; then
            local base_url="${valid_url%%\?*}"
            local query_params="${valid_url#*\?}"
            
            # Test cases for invalid X-Amz-Expires values
            local test_cases=(
                "-1"                            # Negative value
                "0"                             # Zero value
                "604801"                        # Over 7-day limit
                "999999"                        # Way over limit
                "abc"                           # Non-numeric
                "3600.5"                        # Decimal (should be integer)
                ""                              # Empty value
                "3600abc"                       # Mixed numeric/text
            )
            
            local invalid_expires_count=0
            
            for invalid_expires in "${test_cases[@]}"; do
                # Replace X-Amz-Expires parameter in the URL
                local modified_query=$(echo "$query_params" | sed "s/X-Amz-Expires=[^&]*/X-Amz-Expires=$invalid_expires/")
                local test_url="$base_url?$modified_query"
                
                log "  Testing invalid X-Amz-Expires: '$invalid_expires'"
                
                # Test the modified URL
                set +e
                local curl_response=$(curl -s -w "%{http_code}" --insecure "$test_url" 2>&1)
                local curl_exit_code=$?
                local http_code="${curl_response: -3}"
                set -e
                
                # Should get 400 or 403 for invalid expires value
                if [ "$http_code" = "400" ] || [ "$http_code" = "403" ]; then
                    success "Presigned URL validation - Invalid X-Amz-Expires '$invalid_expires' properly rejected (HTTP $http_code)"
                    ((invalid_expires_count++))
                else
                    error "Presigned URL validation - Invalid X-Amz-Expires '$invalid_expires' should be rejected, got HTTP $http_code"
                fi
            done
            
            log "  Successfully tested $invalid_expires_count invalid X-Amz-Expires values"
            
        else
            error "Presigned URL invalid expires - Failed to generate base URL: $valid_url"
        fi
    else
        error "Presigned URL invalid expires - Failed to upload test object"
    fi
    
    # Cleanup
    set +e
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$invalid_expires_object" 2>/dev/null || true
    rm -f "$invalid_expires_object"
    set -e
}

# Test specific SigV4 authentication error cases
test_sigv4_auth_errors() {
    log "Testing: SigV4 Authentication Error Handling "
    
    local auth_test_bucket="auth-test-$(date +%s)"
    
    # Test 1: Missing Authorization header 
    # Maps to: sendInvalidSignatureError(req, res, next, 'Missing Authorization header')
    log "  Testing missing Authorization header..."
    set +e
    local missing_auth_response=$(curl -s -w "%{http_code}" --insecure \
        -X GET \
        "$S3_ENDPOINT/$auth_test_bucket" 2>&1)
    local missing_auth_exit_code=$?
    local missing_auth_http_code="${missing_auth_response: -3}"
    set -e
    
    if [ "$missing_auth_http_code" = "403" ]; then
        success "SigV4 auth errors - Missing Authorization header returns 403"
        
        # Check if response contains proper S3 XML error format
        local response_body="${missing_auth_response%???}"
        if echo "$response_body" | grep -q "InvalidSignature\|Missing Authorization header"; then
            success "SigV4 auth errors - Missing Authorization header returns proper S3 XML error"
        else
            warning "SigV4 auth errors - Missing Authorization header response format: $response_body"
        fi
    else
        error "SigV4 auth errors - Expected 403 for missing Authorization header, got $missing_auth_http_code"
    fi
    
    # Test 2: Missing date header
    # Maps to: sendInvalidSignatureError(req, res, next, 'Missing date header')
    log "  Testing missing date header..."
    set +e
    local missing_date_response=$(curl -s -w "%{http_code}" --insecure \
        -X GET \
        -H "Authorization: AWS4-HMAC-SHA256 Credential=test/20230101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=invalid" \
        "$S3_ENDPOINT/$auth_test_bucket" 2>&1)
    local missing_date_exit_code=$?
    local missing_date_http_code="${missing_date_response: -3}"
    set -e
    
    if [ "$missing_date_http_code" = "403" ]; then
        success "SigV4 auth errors - Missing date header returns 403"
        
        local response_body="${missing_date_response%???}"
        if echo "$response_body" | grep -q "InvalidSignature\|Missing date header"; then
            success "SigV4 auth errors - Missing date header returns proper S3 XML error"
        else
            warning "SigV4 auth errors - Missing date header response format: $response_body"
        fi
    else
        error "SigV4 auth errors - Expected 403 for missing date header, got $missing_date_http_code"
    fi
    
    # Test 3: InvalidSignature/SignatureDoesNotMatch error case
    # Maps to: case 'InvalidSignature': case 'SignatureDoesNotMatch': sendInvalidSignatureError(req, res, next, 'Invalid Signature')
    log "  Testing invalid signature (SignatureDoesNotMatch) - using curl with forged signature..."
    
    # Use curl with manually crafted invalid signature (AWS CLI always generates valid format signatures)
    set +e
    local invalid_sig_response=$(curl -s -w "%{http_code}" --insecure \
        -X PUT \
        -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/20230101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=INVALID_SIGNATURE_THAT_WILL_NEVER_MATCH_ANYTHING" \
        -H "x-amz-date: 20230101T000000Z" \
        "$S3_ENDPOINT/$auth_test_bucket-invalid-sig/" 2>&1)
    local invalid_sig_exit_code=$?
    local invalid_sig_http_code="${invalid_sig_response: -3}"
    set -e
    
    if [ "$invalid_sig_http_code" = "403" ]; then
        success "SigV4 auth errors - Invalid signature properly rejected"
        
        local response_body="${invalid_sig_response%???}"
        if echo "$response_body" | grep -q "InvalidSignature\|SignatureDoesNotMatch"; then
            success "SigV4 auth errors - Invalid signature returns proper error response"
        else
            warning "SigV4 auth errors - Invalid signature error format: $response_body"
        fi
    else
        error "SigV4 auth errors - Invalid signature should be rejected but wasn't"
        log "  Debug: HTTP code: $invalid_sig_http_code, Response: $invalid_sig_response"
    fi
    
    # Test 4: AccessKeyNotFound error case
    # Maps to: case 'AccessKeyNotFound': sendInvalidSignatureError(req, res, next, 'Invalid access key')
    log "  Testing invalid access key (AccessKeyNotFound) - using curl with invalid access key..."
    
    # Use curl with definitely invalid access key (not the format the system expects)
    set +e
    local invalid_key_response=$(curl -s -w "%{http_code}" --insecure \
        -X PUT \
        -H "Authorization: AWS4-HMAC-SHA256 Credential=INVALID_ACCESS_KEY_NOT_FOUND/20230101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=somesignature" \
        -H "x-amz-date: 20230101T000000Z" \
        "$S3_ENDPOINT/$auth_test_bucket-invalid-key/" 2>&1)
    local invalid_key_exit_code=$?
    local invalid_key_http_code="${invalid_key_response: -3}"
    set -e
    
    if [ "$invalid_key_http_code" = "403" ]; then
        success "SigV4 auth errors - Invalid access key properly rejected"
        
        local response_body="${invalid_key_response%???}"
        if echo "$response_body" | grep -q "InvalidSignature\|AccessKeyNotFound\|Invalid access key"; then
            success "SigV4 auth errors - Invalid access key returns proper error response"
        else
            warning "SigV4 auth errors - Invalid access key error format: $response_body"
        fi
    else
        error "SigV4 auth errors - Invalid access key should be rejected but wasn't"
        log "  Debug: HTTP code: $invalid_key_http_code, Response: $invalid_key_response"
    fi
    
    # Test 5: RequestTimeTooSkewed error case  
    # Maps to: case 'RequestTimeTooSkewed': sendInvalidSignatureError(req, res, next, 'Request timestamp too skewed')
    log "  Testing request time too skewed..."
    set +e
    local skewed_time_response=$(curl -s -w "%{http_code}" --insecure \
        -X GET \
        -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/19700101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=invalid" \
        -H "x-amz-date: 19700101T000000Z" \
        "$S3_ENDPOINT/$auth_test_bucket" 2>&1)
    local skewed_time_exit_code=$?
    local skewed_time_http_code="${skewed_time_response: -3}"
    set -e
    
    if [ "$skewed_time_http_code" = "403" ]; then
        success "SigV4 auth errors - Request time too skewed returns 403"
        
        local response_body="${skewed_time_response%???}"
        if echo "$response_body" | grep -q "InvalidSignature\|RequestTimeTooSkewed\|timestamp too skewed"; then
            success "SigV4 auth errors - Request time too skewed returns proper S3 XML error"
        else
            warning "SigV4 auth errors - Request time too skewed response format: $response_body"
        fi
    else
        error "SigV4 auth errors - Expected 403 for request time too skewed, got $skewed_time_http_code"
    fi
    
    # Test 6: Default authentication failure case
    # Maps to: default: sendInvalidSignatureError(req, res, next, 'Authentication failed: ' + ...)
    log "  Testing general authentication failure..."
    set +e
    local auth_fail_response=$(curl -s -w "%{http_code}" --insecure \
        -X GET \
        -H "Authorization: AWS4-HMAC-SHA256 Credential=malformed-credential-format, SignedHeaders=host, Signature=invalid" \
        -H "x-amz-date: 20230101T000000Z" \
        "$S3_ENDPOINT/$auth_test_bucket" 2>&1)
    local auth_fail_exit_code=$?
    local auth_fail_http_code="${auth_fail_response: -3}"
    set -e
    
    if [ "$auth_fail_http_code" = "403" ]; then
        success "SigV4 auth errors - General authentication failure returns 403"
        
        local response_body="${auth_fail_response%???}"
        if echo "$response_body" | grep -q "InvalidSignature\|Authentication failed"; then
            success "SigV4 auth errors - General authentication failure returns proper S3 XML error"
        else
            warning "SigV4 auth errors - General authentication failure response format: $response_body"
        fi
    else
        error "SigV4 auth errors - Expected 403 for general authentication failure, got $auth_fail_http_code"
    fi
    
    # Test 7: HTTP signature verification failure (from verifySignature function)
    # Maps to: sendInvalidSignatureError(req, res, next, 'Signature verification failed')
    log "  Testing HTTP signature verification failure..."
    # This is harder to trigger with pure curl, so we'll test it via malformed signature format
    set +e
    local sig_verify_response=$(curl -s -w "%{http_code}" --insecure \
        -X GET \
        -H "Authorization: Signature keyId=\"invalid\",algorithm=\"rsa-sha256\",signature=\"invalid\"" \
        -H "Date: $(date -u '+%a, %d %b %Y %H:%M:%S GMT')" \
        "$S3_ENDPOINT/$auth_test_bucket" 2>&1)
    local sig_verify_exit_code=$?
    local sig_verify_http_code="${sig_verify_response: -3}"
    set -e
    
    if [ "$sig_verify_http_code" = "403" ]; then
        success "SigV4 auth errors - HTTP signature verification failure returns 403"
        
        local response_body="${sig_verify_response%???}"
        if echo "$response_body" | grep -q "InvalidSignature\|Signature verification failed"; then
            success "SigV4 auth errors - HTTP signature verification failure returns proper S3 XML error"
        else
            warning "SigV4 auth errors - HTTP signature verification failure response format: $response_body"
        fi
    else
        error "SigV4 auth errors - Expected 403 for HTTP signature verification failure, got $sig_verify_http_code"
    fi
    
    # Test 8: PUT request with application/x-directory content-type and invalid auth
    # Maps to: Tests that error handling works correctly for directory creation requests
    log "  Testing PUT request with application/x-directory content-type and invalid auth..."
    
    # Test PUT request with directory content type and invalid authentication
    set +e
    local directory_put_response=$(curl -s -w "%{http_code}" --insecure \
        -X PUT \
        -H "Content-Type: application/x-directory" \
        -H "Authorization: AWS4-HMAC-SHA256 Credential=invalid/20230101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=invalid" \
        -H "x-amz-date: 20230101T000000Z" \
        "$S3_ENDPOINT/$auth_test_bucket/testfolder/" 2>&1)
    local directory_put_exit_code=$?
    local directory_put_http_code="${directory_put_response: -3}"
    set -e
    
    if [ "$directory_put_http_code" = "403" ]; then
        success "SigV4 auth errors - PUT request with application/x-directory content-type returns 403"
        
        local response_body="${directory_put_response%???}"
        if echo "$response_body" | grep -q "InvalidSignature"; then
            success "SigV4 auth errors - PUT request with application/x-directory returns proper S3 XML error"
        else
            warning "SigV4 auth errors - PUT request with application/x-directory response format: $response_body"
        fi
    else
        error "SigV4 auth errors - Expected 403 for PUT request with application/x-directory and invalid auth, got $directory_put_http_code"
    fi
    
    log "  All specific SigV4 authentication error cases were tested successfully"
}

# S3 Object Tagging Tests
test_object_tagging_basic() {
    log "Testing: Basic Object Tagging (PUT/GET/DELETE)"
    
    local tagging_test_object="tagging-test-object.txt"
    
    # First upload an object to tag
    log "  Uploading object for tagging tests..."
    set +e
    result=$(aws_s3api put-object --bucket "$TEST_BUCKET" --key "$tagging_test_object" --body "$TEST_OBJECT" 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        error "Object tagging - Failed to upload test object: $result"
        return 1
    fi
    
    # Test PUT object tagging
    log "  Testing PUT object tagging..."
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$tagging_test_object" --tagging 'TagSet=[{Key=Environment,Value=Test},{Key=Owner,Value=DevTeam}]' 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "Object tagging - PUT tagging succeeded"
    else
        error "Object tagging - PUT tagging failed: $result"
        return 1
    fi
    
    # Test GET object tagging
    log "  Testing GET object tagging..."
    set +e
    result=$(aws_s3api get-object-tagging --bucket "$TEST_BUCKET" --key "$tagging_test_object" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        if echo "$result" | jq -e '.TagSet' >/dev/null 2>&1; then
            local tag_count=$(echo "$result" | jq '.TagSet | length' 2>/dev/null || echo "0")
            if [ "$tag_count" -eq 2 ]; then
                success "Object tagging - GET tagging returned correct number of tags ($tag_count)"
                
                # Verify specific tags
                local env_tag=$(echo "$result" | jq -r '.TagSet[] | select(.Key=="Environment") | .Value' 2>/dev/null || echo "")
                local owner_tag=$(echo "$result" | jq -r '.TagSet[] | select(.Key=="Owner") | .Value' 2>/dev/null || echo "")
                
                if [ "$env_tag" = "Test" ] && [ "$owner_tag" = "DevTeam" ]; then
                    success "Object tagging - Tag values match expected values"
                else
                    error "Object tagging - Tag values don't match (Environment: '$env_tag', Owner: '$owner_tag')"
                fi
            else
                error "Object tagging - Expected 2 tags, got $tag_count"
            fi
        else
            error "Object tagging - GET tagging response missing TagSet: $result"
        fi
    else
        error "Object tagging - GET tagging failed: $result"
        return 1
    fi
    
    # Test DELETE object tagging
    log "  Testing DELETE object tagging..."
    set +e
    result=$(aws_s3api delete-object-tagging --bucket "$TEST_BUCKET" --key "$tagging_test_object" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "Object tagging - DELETE tagging succeeded"
        
        # Verify tags are deleted
        log "  Verifying tags are deleted..."
        set +e
        result=$(aws_s3api get-object-tagging --bucket "$TEST_BUCKET" --key "$tagging_test_object" 2>&1)
        exit_code=$?
        set -e
        
        if [ $exit_code -eq 0 ]; then
            local tag_count=$(echo "$result" | jq '.TagSet | length' 2>/dev/null || echo "0")
            if [ "$tag_count" -eq 0 ]; then
                success "Object tagging - Tags successfully deleted (TagSet empty)"
            else
                error "Object tagging - Expected 0 tags after delete, got $tag_count"
            fi
        else
            error "Object tagging - GET tagging after DELETE failed: $result"
        fi
    else
        error "Object tagging - DELETE tagging failed: $result"
        return 1
    fi
    
    # Cleanup test object
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$tagging_test_object" 2>/dev/null || true
}

test_object_tagging_edge_cases() {
    log "Testing: Object Tagging Edge Cases"
    
    local edge_case_object="tagging-edge-case-object.txt"
    
    # Upload test object
    set +e
    aws_s3api put-object --bucket "$TEST_BUCKET" --key "$edge_case_object" --body "$TEST_OBJECT" >/dev/null 2>&1
    local exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        error "Object tagging edge cases - Failed to upload test object"
        return 1
    fi
    
    # Test tagging with special characters and spaces
    log "  Testing tags with special characters..."
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$edge_case_object" --tagging 'TagSet=[{Key=Special-Key_123,Value=Value with spaces & symbols!}]' 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "Object tagging - Special characters in tags accepted"
        
        # Verify the special character tag
        set +e
        result=$(aws_s3api get-object-tagging --bucket "$TEST_BUCKET" --key "$edge_case_object" 2>&1)
        exit_code=$?
        set -e
        
        if [ $exit_code -eq 0 ]; then
            local special_value=$(echo "$result" | jq -r '.TagSet[0].Value' 2>/dev/null || echo "")
            if [ "$special_value" = "Value with spaces & symbols!" ]; then
                success "Object tagging - Special character tag value preserved correctly"
            else
                error "Object tagging - Special character tag value corrupted: '$special_value'"
            fi
        fi
    else
        error "Object tagging - Special characters in tags rejected: $result"
    fi
    
    # Test maximum number of tags (S3 limit is 10)
    log "  Testing maximum number of tags (10)..."
    local max_tags='TagSet=['
    for i in {1..10}; do
        if [ $i -gt 1 ]; then
            max_tags+=','
        fi
        max_tags+="{Key=Key$i,Value=Value$i}"
    done
    max_tags+=']'
    
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$edge_case_object" --tagging "$max_tags" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "Object tagging - Maximum tags (10) accepted"
        
        # Verify tag count
        set +e
        result=$(aws_s3api get-object-tagging --bucket "$TEST_BUCKET" --key "$edge_case_object" 2>&1)
        exit_code=$?
        set -e
        
        if [ $exit_code -eq 0 ]; then
            local tag_count=$(echo "$result" | jq '.TagSet | length' 2>/dev/null || echo "0")
            if [ "$tag_count" -eq 10 ]; then
                success "Object tagging - All 10 tags stored correctly"
            else
                error "Object tagging - Expected 10 tags, got $tag_count"
            fi
        fi
    else
        error "Object tagging - Maximum tags (10) rejected: $result"
    fi
    
    # Test empty TagSet (should remove all tags)
    log "  Testing empty TagSet..."
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$edge_case_object" --tagging 'TagSet=[]' 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "Object tagging - Empty TagSet accepted"
        
        # Verify tags are removed
        set +e
        result=$(aws_s3api get-object-tagging --bucket "$TEST_BUCKET" --key "$edge_case_object" 2>&1)
        exit_code=$?
        set -e
        
        if [ $exit_code -eq 0 ]; then
            local tag_count=$(echo "$result" | jq '.TagSet | length' 2>/dev/null || echo "0")
            if [ "$tag_count" -eq 0 ]; then
                success "Object tagging - Empty TagSet removed all tags"
            else
                error "Object tagging - Empty TagSet didn't remove tags, count: $tag_count"
            fi
        fi
    else
        error "Object tagging - Empty TagSet rejected: $result"
    fi
    
    # Cleanup test object
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$edge_case_object" 2>/dev/null || true
}

test_object_tagging_invalid_formats() {
    log "Testing: Object Tagging Invalid Formats and Error Handling"
    
    local invalid_format_object="tagging-invalid-format-object.txt"
    
    # Upload test object
    set +e
    aws_s3api put-object --bucket "$TEST_BUCKET" --key "$invalid_format_object" --body "$TEST_OBJECT" >/dev/null 2>&1
    local exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        error "Object tagging invalid formats - Failed to upload test object"
        return 1
    fi
    
    # Test invalid JSON format using file with invalid content (should be rejected)
    log "  Testing invalid JSON format in tagging..."
    
    # Create a file with invalid JSON/XML content
    local invalid_format_file="$TEMP_DIR/invalid_format_tagging.xml"
    mkdir -p "$TEMP_DIR"
    cat > "$invalid_format_file" << 'EOF'
TagSet=[Key=Invalid,Value=Format]
EOF
    
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$invalid_format_object" --tagging "file://$invalid_format_file" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        if echo "$result" | grep -i "MalformedXML\|InvalidRequest\|BadRequest\|Invalid\|Malformed" >/dev/null 2>&1; then
            success "Object tagging - Invalid format properly rejected"
        else
            error "Object tagging - Invalid format rejection with unexpected error: $result"
        fi
    else
        error "Object tagging - Invalid format should have been rejected but was accepted"
    fi
    
    # Clean up the invalid format file
    rm -f "$invalid_format_file" 2>/dev/null || true
    
    # Test malformed XML (missing closing tags)
    log "  Testing malformed XML format..."
    
    # Create a temporary file with malformed XML
    local malformed_xml_file="$TEMP_DIR/malformed_tagging.xml"
    mkdir -p "$TEMP_DIR"
    cat > "$malformed_xml_file" << 'EOF'
<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <TagSet>
    <Tag>
      <Key>TestKey</Key>
      <Value>TestValue
    </Tag>
  </TagSet>
</Tagging>
EOF
    
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$invalid_format_object" --tagging "file://$malformed_xml_file" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        if echo "$result" | grep -i "MalformedXML\|InvalidRequest\|XML" >/dev/null 2>&1; then
            success "Object tagging - Malformed XML properly rejected"
        else
            error "Object tagging - Malformed XML rejection with unexpected error: $result"
        fi
    else
        error "Object tagging - Malformed XML should have been rejected but was accepted"
    fi
    
    # Test tag key too long (>128 characters)
    log "  Testing tag key too long (>128 characters)..."
    local long_key=$(printf 'A%.0s' {1..130})  # 130 character key
    
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$invalid_format_object" --tagging "TagSet=[{Key=$long_key,Value=ValidValue}]" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        if echo "$result" | grep -i "InvalidTag\|BadRequest\|InvalidRequest" >/dev/null 2>&1; then
            success "Object tagging - Tag key too long properly rejected"
        else
            warning "Object tagging - Tag key too long rejection (may depend on server validation): $result"
        fi
    else
        error "Object tagging - Tag key too long should have been rejected but was accepted"
    fi
    
    # Test tag value too long (>256 characters)  
    log "  Testing tag value too long (>256 characters)..."
    local long_value=$(printf 'B%.0s' {1..260})  # 260 character value
    
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$invalid_format_object" --tagging "TagSet=[{Key=ValidKey,Value=$long_value}]" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        if echo "$result" | grep -i "InvalidTag\|BadRequest\|InvalidRequest" >/dev/null 2>&1; then
            success "Object tagging - Tag value too long properly rejected"
        else
            warning "Object tagging - Tag value too long rejection (may depend on server validation): $result"
        fi
    else
        error "Object tagging - Tag value too long should have been rejected but was accepted"
    fi
    
    # Test too many tags (>10)
    log "  Testing too many tags (>10)..."
    local too_many_tags='TagSet=['
    for i in {1..12}; do
        if [ $i -gt 1 ]; then
            too_many_tags+=','
        fi
        too_many_tags+="{Key=Key$i,Value=Value$i}"
    done
    too_many_tags+=']'
    
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$invalid_format_object" --tagging "$too_many_tags" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        if echo "$result" | grep -i "BadRequest\|InvalidRequest\|TooManyTags" >/dev/null 2>&1; then
            success "Object tagging - Too many tags properly rejected"
        else
            warning "Object tagging - Too many tags rejection (may depend on server validation): $result"
        fi
    else
        error "Object tagging - Too many tags should have been rejected but was accepted"
    fi
    
    # Test empty key
    log "  Testing empty tag key..."
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$invalid_format_object" --tagging 'TagSet=[{Key=,Value=ValidValue}]' 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        if echo "$result" | grep -i "InvalidTag\|BadRequest\|InvalidRequest" >/dev/null 2>&1; then
            success "Object tagging - Empty tag key properly rejected"
        else
            warning "Object tagging - Empty tag key rejection (may depend on client/server validation): $result"
        fi
    else
        error "Object tagging - Empty tag key should have been rejected but was accepted"
    fi
    
    # Test duplicate keys
    log "  Testing duplicate tag keys..."
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$invalid_format_object" --tagging 'TagSet=[{Key=DuplicateKey,Value=Value1},{Key=DuplicateKey,Value=Value2}]' 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        if echo "$result" | grep -i "InvalidTag\|BadRequest\|Duplicate" >/dev/null 2>&1; then
            success "Object tagging - Duplicate tag keys properly rejected"
        else
            warning "Object tagging - Duplicate keys rejection (behavior may vary): $result"
        fi
    else
        # AWS S3 actually allows duplicate keys and takes the last value
        log "  Note: Duplicate keys were accepted (AWS behavior - last value wins)"
        
        # Verify which value was stored
        set +e
        get_result=$(aws_s3api get-object-tagging --bucket "$TEST_BUCKET" --key "$invalid_format_object" 2>&1)
        get_exit_code=$?
        set -e
        
        if [ $get_exit_code -eq 0 ]; then
            local duplicate_value=$(echo "$get_result" | jq -r '.TagSet[] | select(.Key=="DuplicateKey") | .Value' 2>/dev/null || echo "")
            if [ "$duplicate_value" = "Value2" ]; then
                success "Object tagging - Duplicate keys: last value wins (Value2)"
            else
                warning "Object tagging - Duplicate keys: unexpected value '$duplicate_value'"
            fi
        fi
    fi
    
    # Test completely invalid XML
    log "  Testing completely invalid XML..."
    local invalid_xml_file="$TEMP_DIR/invalid_tagging.xml"
    echo "This is not XML at all!" > "$invalid_xml_file"
    
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$invalid_format_object" --tagging "file://$invalid_xml_file" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        if echo "$result" | grep -i "MalformedXML\|InvalidRequest\|XML" >/dev/null 2>&1; then
            success "Object tagging - Invalid XML properly rejected"
        else
            error "Object tagging - Invalid XML rejection with unexpected error: $result"
        fi
    else
        error "Object tagging - Invalid XML should have been rejected but was accepted"
    fi
    
    # Cleanup
    rm -f "$malformed_xml_file" "$invalid_xml_file" 2>/dev/null || true
    aws_s3api delete-object --bucket "$TEST_BUCKET" --key "$invalid_format_object" 2>/dev/null || true
}

test_object_tagging_nonexistent_object() {
    log "Testing: Object Tagging on Non-existent Object"
    
    local nonexistent_object="nonexistent-tagging-object.txt"
    
    # Test GET tagging on non-existent object (should return 404 NoSuchKey)
    log "  Testing GET tagging on non-existent object..."
    set +e
    result=$(aws_s3api get-object-tagging --bucket "$TEST_BUCKET" --key "$nonexistent_object" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        if echo "$result" | grep -i "NoSuchKey\|Not Found" >/dev/null 2>&1; then
            success "Object tagging - GET on non-existent object returns proper NoSuchKey error"
        else
            error "Object tagging - GET on non-existent object returned unexpected error: $result"
        fi
    else
        error "Object tagging - GET on non-existent object should have failed but succeeded"
    fi
    
    # Test PUT tagging on non-existent object (should return 404 NoSuchKey)
    log "  Testing PUT tagging on non-existent object..."
    set +e
    result=$(aws_s3api put-object-tagging --bucket "$TEST_BUCKET" --key "$nonexistent_object" --tagging 'TagSet=[{Key=Test,Value=Value}]' 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        if echo "$result" | grep -i "NoSuchKey\|Not Found" >/dev/null 2>&1; then
            success "Object tagging - PUT on non-existent object returns proper NoSuchKey error"
        else
            error "Object tagging - PUT on non-existent object returned unexpected error: $result"
        fi
    else
        error "Object tagging - PUT on non-existent object should have failed but succeeded"
    fi
    
    # Test DELETE tagging on non-existent object (should return 404 NoSuchKey)
    log "  Testing DELETE tagging on non-existent object..."
    set +e
    result=$(aws_s3api delete-object-tagging --bucket "$TEST_BUCKET" --key "$nonexistent_object" 2>&1)
    exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        if echo "$result" | grep -i "NoSuchKey\|Not Found" >/dev/null 2>&1; then
            success "Object tagging - DELETE on non-existent object returns proper NoSuchKey error"
        else
            error "Object tagging - DELETE on non-existent object returned unexpected error: $result"
        fi
    else
        error "Object tagging - DELETE on non-existent object should have failed but succeeded"
    fi
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
        "mpu-resume")
            log "Starting S3 Multipart Upload Resume Tests for manta-buckets-api using AWS CLI"
            log "================================================================="
            
            set +e  # Disable exit on error for test execution
            
            # Create bucket for MPU resume tests
            test_create_bucket || true
            
            # Multipart upload resume tests only
            test_multipart_upload_resume || true
            
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
            test_server_side_copy || true
            test_conditional_headers || true
            test_delete_object || true
            test_bulk_delete_objects || true
            test_bulk_delete_with_errors || true
            test_bulk_delete_special_chars || true
            test_bulk_delete_encoded_chars || true
            test_bulk_delete_empty_request || true
            
            # Clean up any objects before deleting bucket
            log "Cleaning up test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            test_delete_bucket || true
            
            set -e  # Re-enable exit on error
            ;;
        "copy")
            log "Starting S3 Server-Side Copy Tests for manta-buckets-api using AWS CLI"
            log "====================================================================="
            
            set +e  # Disable exit on error for test execution
            
            # Create bucket for copy tests
            test_create_bucket || true
            
            # Server-side copy tests only
            test_server_side_copy || true
            
            # Clean up copy test objects before deleting bucket
            log "Cleaning up copy test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            # Cleanup bucket
            test_delete_bucket || true
            
            set -e  # Re-enable exit on error
            ;;
        "errors")
            log "Starting S3 Error Handling Tests for manta-buckets-api using AWS CLI"
            log "================================================================="
            
            set +e  # Disable exit on error for test execution
            
            # Create bucket for error tests that need it
            test_create_bucket || true
            
            # Error handling tests only
            test_nonexistent_bucket || true
            test_nonexistent_object || true
            test_sigv4_auth_errors || true
            
            # Clean up error test objects before deleting bucket
            log "Cleaning up error test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            # Cleanup bucket
            test_delete_bucket || true
            
            set -e  # Re-enable exit on error
            ;;
        "bulk-delete")
            log "Starting S3 Bulk Delete Tests for manta-buckets-api using AWS CLI"
            log "================================================================="
            
            set +e  # Disable exit on error for test execution
            
            # Create bucket for bulk delete tests
            test_create_bucket || true
            
            # Create a test object first (required for some bulk delete tests)
            test_put_object || true
            
            # Bulk delete tests only
            test_bulk_delete_objects || true
            test_bulk_delete_with_errors || true
            test_bulk_delete_special_chars || true
            test_bulk_delete_encoded_chars || true
            test_bulk_delete_empty_request || true
            
            # Clean up bulk delete test objects before deleting bucket
            log "Cleaning up bulk delete test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            # Cleanup bucket
            test_delete_bucket || true
            
            set -e  # Re-enable exit on error
            ;;
        "auth")
            log "Starting S3 Authentication Error Tests for manta-buckets-api using AWS CLI"
            log "======================================================================"
            
            set +e  # Disable exit on error for test execution
            
            # Create bucket for auth error tests
            test_create_bucket || true
            
            # Authentication error tests only
            test_sigv4_auth_errors || true
            
            # Clean up auth error test objects before deleting bucket
            log "Cleaning up auth error test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            # Cleanup bucket
            test_delete_bucket || true
            
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
            
            # Anonymous access tests
            test_anonymous_access_public_bucket || true
            test_anonymous_access_public_acl || true
            test_anonymous_access_denied || true
            
            # Clean up ACL test objects before deleting bucket
            log "Cleaning up ACL test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            # Cleanup bucket
            test_delete_bucket || true
            
            set -e  # Re-enable exit on error
            ;;
        "anonymous")
            log "Starting S3 Anonymous Access Tests for manta-buckets-api using AWS CLI"
            log "======================================================================="
            
            set +e  # Disable exit on error for test execution
            
            # Create bucket for anonymous access tests
            test_create_bucket || true
            
            # Anonymous access tests only
            test_anonymous_access_public_bucket || true
            test_anonymous_access_public_acl || true
            test_anonymous_access_denied || true
            
            # Clean up anonymous test objects before deleting bucket
            log "Cleaning up anonymous test objects before bucket deletion..."
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
            test_presigned_url_expiry || true
            test_presigned_invalid_date_format || true
            test_presigned_invalid_expires || true
            
            # Clean up test objects before deleting bucket
            log "Cleaning up presigned URL test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            # Cleanup bucket
            test_delete_bucket || true
            
            set -e  # Re-enable exit on error
            ;;
        "tagging")
            log "Starting S3 Object Tagging Tests for manta-buckets-api using AWS CLI"
            log "=================================================================="
            
            set +e  # Disable exit on error for test execution
            
            # Create bucket for tagging tests
            test_create_bucket || true
            
            # Object tagging tests only
            test_object_tagging_basic || true
            test_object_tagging_edge_cases || true
            test_object_tagging_invalid_formats || true
            test_object_tagging_nonexistent_object || true
            
            # Clean up test objects before deleting bucket
            log "Cleaning up tagging test objects before bucket deletion..."
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
            test_server_side_copy || true
            test_conditional_headers || true
            test_delete_object || true
            test_bulk_delete_objects || true
            test_bulk_delete_with_errors || true
            test_bulk_delete_special_chars || true
            test_bulk_delete_encoded_chars || true
            test_bulk_delete_empty_request || true
            
            # Multipart upload tests
            test_multipart_upload_basic || true
            test_multipart_upload_resume || true
            test_multipart_upload_errors || true
            
            # Object tagging tests
            test_object_tagging_basic || true
            test_object_tagging_edge_cases || true
            test_object_tagging_invalid_formats || true
            test_object_tagging_nonexistent_object || true
            
            # ACL tests (run before deleting the main test bucket)
            test_aws_get_bucket_acl || true
            test_aws_get_object_acl || true
            test_aws_put_bucket_acl || true
            test_aws_put_object_acl || true
            test_aws_canned_acls || true
            test_aws_bucket_acl_policy || true
            test_aws_list_objects_with_metadata || true
            
            # Anonymous access tests
            test_anonymous_access_public_bucket || true
            test_anonymous_access_public_acl || true
            test_anonymous_access_denied || true
            
            # Presigned URL tests
            test_aws_cli_presigned_urls || true
            test_presigned_url_expiry || true
            test_presigned_invalid_date_format || true
            test_presigned_invalid_expires || true
            
            # Clean up any test objects before deleting bucket
            log "Cleaning up ACL test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            test_delete_bucket || true
            
            # Error handling tests (run after main bucket is deleted)
            test_nonexistent_bucket || true
            test_nonexistent_object || true
            
            # Create bucket for SigV4 auth error tests
            test_create_bucket || true
            test_sigv4_auth_errors || true
            
            # Clean up auth error test objects before deleting bucket
            log "Cleaning up auth error test objects before bucket deletion..."
            set +e
            aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
            set -e
            
            test_delete_bucket || true
            
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
            echo "  copy       - Run server-side copy tests only"
            echo "  mpu        - Run multipart upload tests only"
            echo "  multipart  - Alias for mpu"
            echo "  mpu-resume - Run only multipart upload resume tests"
            echo "  tagging    - Run object tagging tests only"
            echo "  acl        - Run ACL tests only"
            echo "  anonymous  - Run anonymous access tests only"
            echo "  bulk-delete - Run bulk delete object tests only"
            echo "  errors     - Run error handling tests only"
            echo "  auth       - Run SigV4 authentication error tests only"
            echo "  presigned  - Run presigned URL tests only"
            echo
            echo "Environment variables:"
            echo "  AWS_ACCESS_KEY_ID     - AWS access key (default: AKIA123456789EXAMPLE)"
            echo "  AWS_SECRET_ACCESS_KEY - AWS secret key (default: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)"
            echo "  S3_ENDPOINT          - S3 endpoint URL (default: https://localhost:8080)"
            echo "  AWS_REGION           - AWS region (default: us-east-1)"
            echo "  MANTA_USER           - Manta account name (required for anonymous access tests)"
            echo
            echo "Examples:"
            echo "  $0                    # Run all tests including ACL"
            echo "  $0 mpu                # Run only multipart upload tests"
            echo "  $0 mpu-resume         # Run only multipart upload resume tests"
            echo "  $0 basic              # Run only basic functionality tests"
            echo "  $0 copy               # Run only server-side copy tests"
            echo "  $0 tagging            # Run only object tagging tests"
            echo "  $0 acl                # Run only ACL tests"
            echo "  $0 anonymous          # Run only anonymous access tests"
            echo "  $0 bulk-delete        # Run only bulk delete tests"
            echo "  $0 errors             # Run only error handling tests"
            echo "  $0 auth               # Run only SigV4 authentication error tests"
            echo "  $0 presigned          # Run only presigned URL tests"
            echo "  AWS_ACCESS_KEY_ID=mykey AWS_SECRET_ACCESS_KEY=mysecret $0 mpu"
            echo "  S3_ENDPOINT=https://manta.example.com:8080 $0 basic"
            echo
            echo "Note: This script requires AWS CLI to be installed and configured."
            exit 0
            ;;
        "mpu"|"multipart"|"mpu-resume"|"basic"|"copy"|"errors"|"auth"|"presigned"|"acl"|"anonymous"|"tagging"|"bulk-delete"|"all")
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
