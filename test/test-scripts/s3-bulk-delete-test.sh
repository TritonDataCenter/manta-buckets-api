#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# S3 Compatibility Test - Bulk Delete Operations
#
# Tests S3 bulk delete operations:
# - Basic bulk delete of multiple objects
# - Bulk delete with mixed success/errors
# - Special characters in object names
# - Empty delete requests
# - Comprehensive encoded character handling

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Functions
# =============================================================================

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
        "object with spaces.txt"
        "object(with)parentheses.txt"
        "object+with+plus.txt"
        "object[with]brackets.txt"
        "object{with}braces.txt"
        "object@with@at.txt"
        "object#with#hash.txt"
        "object\$with\$dollar.txt"
        "object%with%percent.txt"
        "object&with&ampersand.txt"
        "object=with=equals.txt"
        "object?with?question.txt"
        "object/with/slash.txt"
        "object:with:colon.txt"
        "object;with;semicolon.txt"
        "object,with,comma.txt"
        "object'with'apostrophe.txt"
        "object\"with\"quote.txt"
        "object<with>angles.txt"
        "object|with|pipe.txt"
        "object\\with\\backslash.txt"
        "object^with^caret.txt"
        "object\`with\`backtick.txt"
        "object~with~tilde.txt"
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
            escaped_key="${escaped_key//\\/\\\\}"
            escaped_key="${escaped_key//\"/\\\"}"

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

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "=========================================="
    log "S3 Bulk Delete Test Suite"
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
    test_bulk_delete_objects
    test_bulk_delete_with_errors
    test_bulk_delete_special_chars
    test_bulk_delete_empty_request
    test_bulk_delete_encoded_chars

    cleanup_basic
    print_summary
}

main
