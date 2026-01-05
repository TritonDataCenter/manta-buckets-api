#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# S3 Compatibility Test - Object Tagging Operations
#
# Tests S3 object tagging functionality:
# - Basic tagging operations (put/get/delete)
# - Edge cases and limits
# - Invalid format handling
# - Tagging nonexistent objects

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Functions
# =============================================================================

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

# =============================================================================
# CORS (Cross-Origin Resource Sharing) Tests
# =============================================================================

# Function to create a minimal PNG image file
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

# =============================================================================
# IAM (Identity and Access Management) Tests
# =============================================================================

# AWS IAM wrapper with our endpoint
aws_iam() {
    run_with_timeout 30 aws iam --endpoint-url="$S3_ENDPOINT" \
            --region="$AWS_REGION" \
            --no-verify-ssl \
            --no-cli-pager \
            --no-paginate \
            --color off \
            --output json \
            "$@"
}


# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "=========================================="
    log "S3 Object Tagging Test Suite"
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
    test_object_tagging_basic
    test_object_tagging_edge_cases
    test_object_tagging_invalid_formats
    test_object_tagging_nonexistent_object

    cleanup_basic
    print_summary
}

main
