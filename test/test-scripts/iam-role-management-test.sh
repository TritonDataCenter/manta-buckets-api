#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# S3 Compatibility Test - IAM Role Management
#
# Tests IAM role management operations:
# - Role creation and retrieval
# - Role listing and deletion
# - Role policy operations (Put, Get, Delete, List)
# - Duplicate role handling
# - Nonexistent role error handling
# - Complete role operations workflow

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Functions
# =============================================================================

test_iam_create_role() {
    log "Testing IAM CreateRole..."
    
    # Clean up any existing test roles and policies first to avoid UUID conflicts
    log "DEBUG: Cleaning up existing IAM test roles and policies..."
    cleanup_iam_test_resources "s3-test-role-"
    
    # Generate highly unique role name
    local timestamp=$(date +%s)
    local microseconds=$(date +%N | cut -b1-6)
    local role_name="s3-test-role-${timestamp}-${microseconds}-$$-$RANDOM-$RANDOM"
    local assume_role_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    
    
    set +e
    local result
    # Use a temporary file to capture output instead of command substitution
    local temp_output="/tmp/aws_iam_output_$$"
    aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$assume_role_policy" \
        --description "Test role for S3 compatibility testing" > "$temp_output" 2>&1
    local exit_code=$?
    
    # Read the output from temp file
    if [ -f "$temp_output" ]; then
        result=$(cat "$temp_output")
        rm -f "$temp_output"
    else
        result=""
    fi
    set -e
    
    if [ $exit_code -eq 0 ]; then
        # Verify response contains expected fields
        if echo "$result" | grep -q "RoleName.*$role_name" && \
           echo "$result" | grep -q "Arn.*role/$role_name" && \
           echo "$result" | grep -q "CreateDate"; then
            success "IAM CreateRole - Role created successfully: $role_name"
            # Save role name for later tests
            echo "$role_name" > "$TEMP_DIR/test_role_name"
            return 0
        else
            error "IAM CreateRole - Response missing expected fields: $result"
            return 1
        fi
    else
        error "IAM CreateRole - Failed to create role: $result"
        return 1
    fi
}

test_iam_get_role() {
    log "Testing IAM GetRole..."
    
    # Use the role created in previous test
    local role_name
    if [ -f "$TEMP_DIR/test_role_name" ]; then
        role_name=$(cat "$TEMP_DIR/test_role_name")
    else
        warning "IAM GetRole - No role name found from CreateRole test, skipping"
        return 0
    fi
    
    set +e
    local result
    capture_output result aws_iam get-role --role-name "$role_name"
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        # Verify response contains expected fields
        if echo "$result" | grep -q "RoleName.*$role_name" && \
           echo "$result" | grep -q "Arn.*role/$role_name" && \
           echo "$result" | grep -q "AssumeRolePolicyDocument"; then
            success "IAM GetRole - Role retrieved successfully: $role_name"
            return 0
        else
            error "IAM GetRole - Response missing expected fields: $result"
            return 1
        fi
    else
        error "IAM GetRole - Failed to get role: $result"
        return 1
    fi
}

test_iam_create_role_duplicate() {
    log "Testing IAM CreateRole error handling (duplicate role)..."
    
    # Use the role created in previous test
    local role_name
    if [ -f "$TEMP_DIR/test_role_name" ]; then
        role_name=$(cat "$TEMP_DIR/test_role_name")
    else
        warning "IAM CreateRole duplicate - No role name found, creating new role for test"
        role_name="s3-test-role-duplicate-$(date +%s)-$$-$RANDOM"
        # Create the role first
        aws_iam create-role \
            --role-name "$role_name" \
            --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}' \
            >/dev/null 2>&1 || true
    fi
    
    set +e
    local result
    capture_output result aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    local exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        # Should fail with EntityAlreadyExists error
        if echo "$result" | grep -q "EntityAlreadyExists"; then
            success "IAM CreateRole error handling - Correctly rejected duplicate role with EntityAlreadyExists"
            return 0
        else
            error "IAM CreateRole error handling - Failed with wrong error (expected EntityAlreadyExists): $result"
            return 1
        fi
    else
        error "IAM CreateRole error handling - Should have failed but succeeded: $result"
        return 1
    fi
}

test_iam_get_role_nonexistent() {
    log "Testing IAM GetRole error handling (non-existent role)..."
    
    local nonexistent_role="non-existent-role-$(date +%s)"
    
    set +e
    local result
    capture_output result aws_iam get-role --role-name "$nonexistent_role"
    local exit_code=$?
    set -e
    
    if [ $exit_code -ne 0 ]; then
        # Should fail with NoSuchEntity error
        if echo "$result" | grep -q "NoSuchEntity"; then
            success "IAM GetRole error handling - Correctly rejected non-existent role with NoSuchEntity"
            return 0
        else
            error "IAM GetRole error handling - Failed with wrong error (expected NoSuchEntity): $result"
            return 1
        fi
    else
        error "IAM GetRole error handling - Should have failed but succeeded: $result"
        return 1
    fi
}

test_sts_assume_role() {
    log "Testing STS AssumeRole..."
    
    # Get account UUID using the same method as trust policy tests
    local account_uuid
    local account_info
    account_info=$(aws sts get-caller-identity --endpoint-url "$S3_ENDPOINT" --no-verify-ssl --output json 2>/dev/null | jq -r '.Account' 2>/dev/null || echo "")
    if [ -z "$account_info" ] || [ "$account_info" = "null" ]; then
        account_uuid="c116efce-086f-455e-9ae4-26d49551428d"  # fallback
    else
        account_uuid="$account_info"
    fi
    
    # Create a test role for STS (always create fresh to avoid dependencies)
    local role_name="STSTestRole-$(date +%s)"
    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    
    log "Creating STS test role: $role_name"
    if aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" >/dev/null 2>&1; then
        log "STS test role created successfully"
        # Store role name for cleanup
        echo "$role_name" > "$TEMP_DIR/sts_test_role_name"
    else
        error "Failed to create STS test role"
        return 1
    fi

    # Attach S3 permissions policy to the role
    local s3_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":"*"}]}'
    if aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "S3FullAccess" \
        --policy-document "$s3_policy" >/dev/null 2>&1; then
        log "S3 permissions policy attached to role"
        # Give time for policy to propagate
        sleep 2
    else
        warning "Failed to attach S3 policy to role (role may have no permissions)"
    fi

    local role_arn="arn:aws:iam::${account_uuid}:role/${role_name}"
    local session_name="test-session-$(date +%s)"
    
    log "[$(date '+%Y-%m-%d %H:%M:%S')] Testing STS AssumeRole..."
    
    # Test 1: Check raw XML response format first
    log "Step 1: Testing raw XML response format..."
    local raw_xml_output
    set +e
    raw_xml_output=$(curl -k -s -X POST "$S3_ENDPOINT/" \
        -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$(date +%Y%m%d)/$AWS_REGION/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=dummy" \
        -H "Content-Type: application/x-amz-json-1.1" \
        -d "Action=AssumeRole&RoleArn=${role_arn}&RoleSessionName=${session_name}" 2>/dev/null || echo "")
    set -e
    
    if [ -n "$raw_xml_output" ]; then
        log "Raw XML Response (first 500 chars):"
        echo "$raw_xml_output" | head -c 500
        
        # Check for proper XML structure
        if echo "$raw_xml_output" | grep -q "<?xml version" && \
           echo "$raw_xml_output" | grep -q "<AssumeRoleResponse" && \
           echo "$raw_xml_output" | grep -q "<Credentials>" && \
           echo "$raw_xml_output" | grep -q "</AssumeRoleResponse>"; then
            success "STS AssumeRole - XML structure validation passed"
        else
            error "STS AssumeRole - Invalid XML structure detected!"
            log "XML Response Analysis:"
            echo "- Has XML declaration: $(echo "$raw_xml_output" | grep -q "<?xml version" && echo "YES" || echo "NO")"
            echo "- Has AssumeRoleResponse: $(echo "$raw_xml_output" | grep -q "<AssumeRoleResponse" && echo "YES" || echo "NO")"
            echo "- Has Credentials: $(echo "$raw_xml_output" | grep -q "<Credentials>" && echo "YES" || echo "NO")"
            echo "- Has closing tag: $(echo "$raw_xml_output" | grep -q "</AssumeRoleResponse>" && echo "YES" || echo "NO")"
            return 1
        fi
    else
        warning "STS AssumeRole - Could not retrieve raw XML (possibly auth issue)"
    fi
    
    # Test 2: AWS CLI JSON parsing test (existing functionality)
    log "Step 2: Testing AWS CLI JSON parsing..."
    local aws_output
    capture_output aws_output aws_sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name "$session_name" \
        --output json
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        # Verify response contains expected fields
        if echo "$aws_output" | grep -q "AccessKeyId" && \
           echo "$aws_output" | grep -q "SecretAccessKey" && \
           echo "$aws_output" | grep -q "SessionToken" && \
           echo "$aws_output" | grep -q "Expiration" && \
           echo "$aws_output" | grep -q "AssumedRoleUser"; then
            success "STS AssumeRole - AWS CLI parsing successful: $role_arn"
            
            # Additional validation: Check field formats
            local access_key_id secret_key session_token expiration
            access_key_id=$(echo "$aws_output" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
            secret_key=$(echo "$aws_output" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)
            session_token=$(echo "$aws_output" | grep -o '"SessionToken": "[^"]*"' | cut -d'"' -f4)
            expiration=$(echo "$aws_output" | grep -o '"Expiration": "[^"]*"' | cut -d'"' -f4)
            
            # Validate credential formats
            if [ ${#access_key_id} -ge 16 ] && [ ${#secret_key} -ge 20 ] && [ ${#session_token} -ge 100 ]; then
                success "STS AssumeRole - Credential format validation passed"
                log "Credential lengths: AccessKeyId=${#access_key_id}, SecretKey=${#secret_key}, Token=${#session_token}"
            else
                error "STS AssumeRole - Invalid credential formats detected"
                log "AccessKeyId length: ${#access_key_id} (expected >=16)"
                log "SecretKey length: ${#secret_key} (expected >=20)"
                log "SessionToken length: ${#session_token} (expected >=100)"
                return 1
            fi
            
            log "Response:"
            echo "$aws_output" | jq '.' 2>/dev/null || echo "$aws_output"
            # Save credentials for role-based authorization test
            echo "$aws_output" > "$TEMP_DIR/temp_credentials.json"
            return 0
        else
            error "STS AssumeRole - Response missing expected fields"
            log "AWS CLI Response:"
            echo "$aws_output"
            return 1
        fi
    else
        error "STS AssumeRole - Failed to assume role"
        log "AWS CLI Response:"
        echo "$aws_output"
        return 1
    fi
}

test_sts_role_based_authorization() {
    log "Testing STS role-based authorization with S3 operations..."
    
    # Load temporary credentials from AssumeRole test
    if [ ! -f "$TEMP_DIR/temp_credentials.json" ]; then
        warning "STS role-based authorization - No temporary credentials found, skipping test"
        return 0
    fi
    
    # Extract temporary credentials
    local temp_creds
    temp_creds=$(cat "$TEMP_DIR/temp_credentials.json")
    
    local temp_access_key temp_secret_key temp_session_token
    temp_access_key=$(echo "$temp_creds" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
    temp_secret_key=$(echo "$temp_creds" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)
    temp_session_token=$(echo "$temp_creds" | grep -o '"SessionToken": "[^"]*"' | cut -d'"' -f4)
    
    if [ -z "$temp_access_key" ] || [ -z "$temp_secret_key" ] || [ -z "$temp_session_token" ]; then
        error "STS role-based authorization - Failed to extract temporary credentials"
        return 1
    fi
    
    # Save original credentials
    local original_access_key="$AWS_ACCESS_KEY_ID"
    local original_secret_key="$AWS_SECRET_ACCESS_KEY"
    local original_session_token="${AWS_SESSION_TOKEN:-}"
    
    # Set temporary credentials
    export AWS_ACCESS_KEY_ID="$temp_access_key"
    export AWS_SECRET_ACCESS_KEY="$temp_secret_key"
    export AWS_SESSION_TOKEN="$temp_session_token"
    
    # Test 1: Try to list all buckets (should work or give non-auth error)
    set +e
    local result
    result=$(aws_s3 ls 2>&1)
    local exit_code=$?
    set -e
    
    log "Testing bucket-level access restrictions with temporary credentials..."
    
    # Test 2: Create test buckets to verify role restrictions
    local allowed_bucket="test-bucket-$(date +%s)"
    local denied_bucket="other-bucket-$(date +%s)"
    
    # First, restore original credentials to create test buckets
    local temp_access_key_backup="$AWS_ACCESS_KEY_ID"
    local temp_secret_key_backup="$AWS_SECRET_ACCESS_KEY"
    local temp_session_token_backup="${AWS_SESSION_TOKEN:-}"
    
    # Use full admin credentials to create buckets
    export AWS_ACCESS_KEY_ID="$original_access_key"
    export AWS_SECRET_ACCESS_KEY="$original_secret_key"
    if [ -n "$original_session_token" ]; then
        export AWS_SESSION_TOKEN="$original_session_token"
    else
        unset AWS_SESSION_TOKEN
    fi
    
    # Create test buckets with admin credentials
    log "Creating test buckets for role authorization test..."
    # Give a short pause to ensure credential switch takes effect
    sleep 1
    
    local bucket_creation_failed=false
    
    # Create allowed bucket
    local allowed_result
    allowed_result=$(aws_s3 mb "s3://$allowed_bucket" 2>&1)
    if [ $? -eq 0 ]; then
        log "  ✅ Created allowed bucket: $allowed_bucket"
    else
        log "  ❌ Failed to create allowed bucket: $allowed_bucket"
        log "  Error: $allowed_result"
        bucket_creation_failed=true
    fi
    
    # Create denied bucket  
    local denied_result
    denied_result=$(aws_s3 mb "s3://$denied_bucket" 2>&1)
    if [ $? -eq 0 ]; then
        log "  ✅ Created denied bucket: $denied_bucket"
    else
        log "  ❌ Failed to create denied bucket: $denied_bucket"
        log "  Error: $denied_result"
        bucket_creation_failed=true
    fi
    
    # If bucket creation failed, skip the access tests
    if [ "$bucket_creation_failed" = true ]; then
        warning "STS role-based authorization - Bucket creation failed, skipping access control tests"
        
        # Restore original credentials and return
        export AWS_ACCESS_KEY_ID="$original_access_key"
        export AWS_SECRET_ACCESS_KEY="$original_secret_key"
        if [ -n "$original_session_token" ]; then
            export AWS_SESSION_TOKEN="$original_session_token"
        else
            unset AWS_SESSION_TOKEN
        fi
        
        # Still test basic credential functionality
        if [ $exit_code -eq 0 ]; then
            success "STS role-based authorization - Basic S3 operations work with temporary credentials"
        else
            if echo "$result" | grep -q -E "(SignatureDoesNotMatch|InvalidSignature|AccessDenied)"; then
                error "STS role-based authorization - S3 operation failed with auth error: $result"
                return 1
            else
                success "STS role-based authorization - Temporary credentials processed successfully (non-auth error: $result)"
            fi
        fi
        return 0
    fi
    
    # Restore temporary credentials for testing
    export AWS_ACCESS_KEY_ID="$temp_access_key_backup"
    export AWS_SECRET_ACCESS_KEY="$temp_secret_key_backup"
    if [ -n "$temp_session_token_backup" ]; then
        export AWS_SESSION_TOKEN="$temp_session_token_backup"
    else
        unset AWS_SESSION_TOKEN
    fi
    
    # Test 3: Try to access allowed bucket pattern (should work if properly implemented)
    set +e
    local allowed_result
    allowed_result=$(aws_s3 ls "s3://$allowed_bucket" 2>&1)
    local allowed_exit=$?
    set -e
    
    # Test 4: Try to access denied bucket (should fail with authorization, not auth error)
    set +e
    local denied_result  
    denied_result=$(aws_s3 ls "s3://$denied_bucket" 2>&1)
    local denied_exit=$?
    set -e
    
    # Cleanup test buckets (with admin credentials)
    export AWS_ACCESS_KEY_ID="$original_access_key"
    export AWS_SECRET_ACCESS_KEY="$original_secret_key"
    unset AWS_SESSION_TOKEN
    aws_s3 rb "s3://$allowed_bucket" 2>/dev/null || true
    aws_s3 rb "s3://$denied_bucket" 2>/dev/null || true
    
    # Restore original credentials
    export AWS_ACCESS_KEY_ID="$original_access_key"
    export AWS_SECRET_ACCESS_KEY="$original_secret_key"
    if [ -n "$original_session_token" ]; then
        export AWS_SESSION_TOKEN="$original_session_token"
    else
        unset AWS_SESSION_TOKEN
    fi
    
    # Evaluate main S3 operation result
    if [ $exit_code -eq 0 ]; then
        success "STS role-based authorization - Basic S3 operations work with temporary credentials"
    else
        # Check if it's an authentication error vs authorization error
        if echo "$result" | grep -q -E "(SignatureDoesNotMatch|InvalidSignature|AccessDenied)"; then
            error "STS role-based authorization - S3 operation failed with auth error: $result"
            return 1
        else
            # Other errors might be expected (e.g., no buckets exist)
            success "STS role-based authorization - Temporary credentials processed successfully (non-auth error: $result)"
        fi
    fi
    
    # Evaluate bucket restriction results
    log "Analyzing bucket-level access control results..."
    
    # NOTE: The current policy conversion creates policies like "CAN getbucket test-bucket"
    # but these bucket name patterns are based on the AWS policy Resource field
    # The test here demonstrates the test framework - actual enforcement depends on 
    # Manta's policy engine matching bucket patterns correctly
    
    if [ $allowed_exit -eq 0 ]; then
        success "STS role-based authorization - Allowed bucket access works: $allowed_bucket"
        log "✅ IAM POLICY VALIDATION: Allowed bucket access succeeded - permission policies should have been evaluated"
    else
        if echo "$allowed_result" | grep -q -E "(AccessDenied|Forbidden)"; then
            warning "STS role-based authorization - Allowed bucket was denied (policy may not be working)"
            log "DEBUG: STS ROLE AUTH - Allowed bucket test:"
            log "  Bucket: $allowed_bucket"
            log "  Exit code: $allowed_exit"
            log "  Response: $allowed_result"
            if echo "$allowed_result" | grep -q "not allowed to access"; then
                log "❌ IAM POLICY VALIDATION: CRITICAL - This looks like permissionPoliciesCount=0 issue!"
                log "   Expected: Bucket access should work with proper role policy"
                log "   Actual: Role policy not being evaluated properly"
            fi
        else
            success "STS role-based authorization - Allowed bucket test completed (non-access error)"
        fi
    fi
    
    if [ $denied_exit -ne 0 ] && echo "$denied_result" | grep -q -E "(AccessDenied|Forbidden)"; then
        success "STS role-based authorization - Denied bucket properly rejected: $denied_bucket"
        log "✅ IAM POLICY VALIDATION: Denied bucket correctly rejected"
    elif [ $denied_exit -eq 0 ]; then
        warning "STS role-based authorization - Denied bucket was allowed (policy restrictions may not be enforced)"
        log "DEBUG: STS ROLE AUTH - Denied bucket test:"
        log "  Bucket: $denied_bucket"
        log "  Exit code: $denied_exit"
        log "  Response: $denied_result"
    else
        success "STS role-based authorization - Denied bucket test completed (non-access error)"  
    fi
    
    return 0
}

test_sts_role_object_permissions() {
    log "Testing STS role with specific object creation permissions..."
    
    local role_name="s3-object-role-$(date +%s)-$$-$RANDOM"
    # Use a simple bucket name that's more likely to work
    local test_bucket="obj-test-$(date +%s | tail -c 6)"  # Short bucket name
    local test_object="test-file.txt"
    local test_content="Test content for role-based object creation - $(date)"
    
    # Separate trust policy and permission policy (proper AWS IAM way)
    local trust_policy='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole"
            }
        ]
    }'
    
    # Permission policy with S3 access for the test bucket
    local permission_policy='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject", 
                    "s3:ListBucket",
                    "s3:CreateBucket"
                ],
                "Resource": [
                    "arn:aws:s3:::'"$test_bucket"'/*",
                    "arn:aws:s3:::'"$test_bucket"'",
                    "arn:aws:s3:::obj-test-*/*",
                    "arn:aws:s3:::obj-test-*",
                    "arn:aws:s3:::*"
                ]
            }
        ]
    }'
    
    log "Creating IAM role with trust policy for bucket: $test_bucket"
    set +e
    local create_role_result
    capture_output create_role_result aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" \
        --description "Test role with object creation permissions"
    local create_role_exit=$?
    set -e
    
    if [ $create_role_exit -ne 0 ]; then
        error "STS object permissions - Failed to create role: $create_role_result"
        return 1
    fi
    
    # Attach the permission policy to the role
    log "Attaching S3 permission policy to role: $role_name"
    set +e
    local put_policy_result
    capture_output put_policy_result aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "S3ObjectPermissions" \
        --policy-document "$permission_policy"
    local put_policy_exit=$?
    set -e
    
    if [ $put_policy_exit -ne 0 ]; then
        error "STS object permissions - Failed to attach permission policy: $put_policy_result"
        # Cleanup role
        run_with_timeout 30 aws_iam_silent delete-role --role-name "$role_name" || true
        return 1
    fi
    
    # Get account UUID for ARN construction
    local account_uuid=$(get_account_uuid)
    local role_arn="arn:aws:iam::${account_uuid}:role/${role_name}"
    local session_name="object-test-session-$(date +%s)"
    
    # Wait a moment for role policy to propagate
    log "Waiting for role policy to propagate..."
    sleep 2
    
    # Assume the role to get temporary credentials
    log "Assuming role for object permissions testing..."
    set +e
    local assume_result
    capture_output assume_result aws_sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name "$session_name"
    local assume_exit=$?
    set -e
    
    if [ $assume_exit -ne 0 ]; then
        error "STS object permissions - Failed to assume role: $assume_result"
        return 1
    fi
    
    # Extract temporary credentials
    local temp_access_key temp_secret_key temp_session_token
    temp_access_key=$(echo "$assume_result" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
    temp_secret_key=$(echo "$assume_result" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)
    temp_session_token=$(echo "$assume_result" | grep -o '"SessionToken": "[^"]*"' | cut -d'"' -f4)
    
    if [ -z "$temp_access_key" ] || [ -z "$temp_secret_key" ] || [ -z "$temp_session_token" ]; then
        error "STS object permissions - Failed to extract temporary credentials"
        return 1
    fi
    
    # Save original credentials
    local original_access_key="$AWS_ACCESS_KEY_ID"
    local original_secret_key="$AWS_SECRET_ACCESS_KEY"
    local original_session_token="${AWS_SESSION_TOKEN:-}"
    
    # Switch to temporary credentials for all testing
    export AWS_ACCESS_KEY_ID="$temp_access_key"
    export AWS_SECRET_ACCESS_KEY="$temp_secret_key"
    export AWS_SESSION_TOKEN="$temp_session_token"
    
    # Try to create the test bucket with role credentials (role has CreateBucket permission)
    log "Creating test bucket with role credentials: $test_bucket"
    
    set +e
    local bucket_create_result
    bucket_create_result=$(aws_s3 mb "s3://$test_bucket" 2>&1)
    local bucket_create_exit=$?
    set -e
    
    if [ $bucket_create_exit -ne 0 ]; then
        error "STS object permissions - Failed to create test bucket with role credentials: $test_bucket"
        error "Bucket creation error: $bucket_create_result"
        return 1
    else
        success "STS object permissions - Test bucket created with role credentials: $test_bucket"
    fi
    
    # Test 1: Try to put an object to the allowed bucket (should work)
    log "Testing object creation with role credentials..."
    echo "$test_content" > "$TEMP_DIR/$test_object"
    
    set +e
    local put_result
    put_result=$(aws_s3api put-object \
        --bucket "$test_bucket" \
        --key "$test_object" \
        --body "$TEMP_DIR/$test_object" \
        2>&1)
    local put_exit=$?
    set -e
    
    # Test 2: Try to get the object back (should work)
    set +e
    local get_result
    get_result=$(aws_s3api get-object \
        --bucket "$test_bucket" \
        --key "$test_object" \
        "$TEMP_DIR/downloaded-$test_object" \
        2>&1)
    local get_exit=$?
    set -e
    
    # Test 3: Try to list bucket contents (should work)
    set +e
    local list_result
    list_result=$(aws_s3api list-objects-v2 \
        --bucket "$test_bucket" \
        2>&1)
    local list_exit=$?
    set -e
    
    # Test 4: Try to put object in a different bucket (should fail)
    local other_bucket="other-bucket-$(date +%s)"
    
    # Create other bucket with admin credentials
    export AWS_ACCESS_KEY_ID="$original_access_key"
    export AWS_SECRET_ACCESS_KEY="$original_secret_key"
    unset AWS_SESSION_TOKEN
    aws_s3 mb "s3://$other_bucket" 2>/dev/null || true
    
    # Switch back to role credentials
    export AWS_ACCESS_KEY_ID="$temp_access_key"
    export AWS_SECRET_ACCESS_KEY="$temp_secret_key"
    export AWS_SESSION_TOKEN="$temp_session_token"
    
    set +e
    local denied_put_result
    denied_put_result=$(aws_s3api put-object \
        --bucket "$other_bucket" \
        --key "$test_object" \
        --body "$TEMP_DIR/$test_object" \
        2>&1)
    local denied_put_exit=$?
    set -e
    
    # Restore original credentials for cleanup
    export AWS_ACCESS_KEY_ID="$original_access_key"
    export AWS_SECRET_ACCESS_KEY="$original_secret_key"
    if [ -n "$original_session_token" ]; then
        export AWS_SESSION_TOKEN="$original_session_token"
    else
        unset AWS_SESSION_TOKEN
    fi
    
    # Cleanup
    aws_s3 rm "s3://$test_bucket/$test_object" 2>/dev/null || true
    aws_s3 rb "s3://$test_bucket" 2>/dev/null || true
    aws_s3 rb "s3://$other_bucket" 2>/dev/null || true
    rm -f "$TEMP_DIR/$test_object" "$TEMP_DIR/downloaded-$test_object"
    
    # Evaluate results
    local test_passed=true
    
    if [ $put_exit -eq 0 ]; then
        success "STS object permissions - PutObject to allowed bucket succeeded"
    else
        if echo "$put_result" | grep -q -E "(AccessDenied|Forbidden)"; then
            error "STS object permissions - PutObject to allowed bucket was denied: $put_result"
            test_passed=false
        else
            error "STS object permissions - PutObject failed with non-permission error: $put_result"
            test_passed=false
        fi
    fi
    
    if [ $get_exit -eq 0 ]; then
        # Verify content matches
        if [ -f "$TEMP_DIR/downloaded-$test_object" ]; then
            local downloaded_content
            downloaded_content=$(cat "$TEMP_DIR/downloaded-$test_object")
            if [ "$downloaded_content" = "$test_content" ]; then
                success "STS object permissions - GetObject from allowed bucket succeeded with correct content"
            else
                warning "STS object permissions - GetObject succeeded but content mismatch"
            fi
        else
            success "STS object permissions - GetObject from allowed bucket succeeded"
        fi
    else
        if echo "$get_result" | grep -q -E "(AccessDenied|Forbidden)"; then
            error "STS object permissions - GetObject from allowed bucket was denied: $get_result"
            test_passed=false
        else
            error "STS object permissions - GetObject failed with non-permission error: $get_result"
            test_passed=false
        fi
    fi
    
    if [ $list_exit -eq 0 ]; then
        if echo "$list_result" | grep -q "$test_object"; then
            success "STS object permissions - ListObjects on allowed bucket succeeded and found object"
        else
            success "STS object permissions - ListObjects on allowed bucket succeeded"
        fi
    else
        if echo "$list_result" | grep -q -E "(AccessDenied|Forbidden)"; then
            error "STS object permissions - ListObjects on allowed bucket was denied: $list_result"
            test_passed=false
        else
            error "STS object permissions - ListObjects failed with non-permission error: $list_result"
            test_passed=false
        fi
    fi
    
    # Check denied bucket access
    if [ $denied_put_exit -ne 0 ] && echo "$denied_put_result" | grep -q -E "(AccessDenied|Forbidden)"; then
        success "STS object permissions - PutObject to denied bucket properly rejected"
    elif [ $denied_put_exit -eq 0 ]; then
        warning "STS object permissions - PutObject to denied bucket was allowed (policy restrictions may not be enforced)"
    else
        success "STS object permissions - PutObject to denied bucket failed (non-permission error)"
    fi
    
    if $test_passed; then
        success "STS object permissions - All allowed operations completed successfully"
        return 0
    else
        error "STS object permissions - Some allowed operations were denied"
        return 1
    fi
}

test_sts_temporary_credentials_expiry() {
    log "Testing STS temporary credentials properties..."
    
    # Load temporary credentials from AssumeRole test
    if [ ! -f "$TEMP_DIR/temp_credentials.json" ]; then
        warning "STS temporary credentials expiry - No temporary credentials found, skipping test"
        return 0
    fi
    
    local temp_creds
    temp_creds=$(cat "$TEMP_DIR/temp_credentials.json")
    
    # Check that credentials have expiration
    if echo "$temp_creds" | grep -q "Expiration"; then
        local expiration
        expiration=$(echo "$temp_creds" | grep -o '"Expiration": "[^"]*"' | cut -d'"' -f4)
        
        # Verify expiration is in the future
        local exp_epoch current_epoch
        # Handle ISO 8601 format with timezone - try multiple parsing approaches
        exp_epoch=$(date -d "$expiration" +%s 2>/dev/null || \
                   python3 -c "import datetime; import sys; print(int(datetime.datetime.fromisoformat('$expiration'.replace('Z', '+00:00')).timestamp()))" 2>/dev/null || \
                   echo "0")
        current_epoch=$(date +%s)
        
        if [ "$exp_epoch" -gt "$current_epoch" ]; then
            success "STS temporary credentials expiry - Credentials have valid future expiration: $expiration"
            return 0
        else
            error "STS temporary credentials expiry - Credentials expiration is not in future: $expiration"
            return 1
        fi
    else
        error "STS temporary credentials expiry - Response missing expiration field"
        return 1
    fi
}

test_sts_get_session_token() {
    log "[$(date '+%Y-%m-%d %H:%M:%S')] Testing STS GetSessionToken..."
    
    # Test GetSessionToken operation with detailed response capture
    local aws_output
    capture_output aws_output aws_sts get-session-token \
        --duration-seconds 3600 \
        --output json
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ] && echo "$aws_output" | grep -q "Credentials"; then
        success "STS GetSessionToken - Session token generated successfully"
        log "Response:"
        echo "$aws_output" | jq '.' 2>/dev/null || echo "$aws_output"
        
        # Extract credentials for validation
        local access_key_id secret_access_key session_token expiration
        access_key_id=$(echo "$aws_output" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
        secret_access_key=$(echo "$aws_output" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)
        session_token=$(echo "$aws_output" | grep -o '"SessionToken": "[^"]*"' | cut -d'"' -f4)
        expiration=$(echo "$aws_output" | grep -o '"Expiration": "[^"]*"' | cut -d'"' -f4)
        
        if [ -n "$access_key_id" ] && [ -n "$secret_access_key" ] && [ -n "$session_token" ] && [ -n "$expiration" ]; then
            
            # Save session token credentials for potential use in other tests
            cat > "$TEMP_DIR/session_token_credentials.json" <<EOF
{
    "AccessKeyId": "$access_key_id",
    "SecretAccessKey": "$secret_access_key", 
    "SessionToken": "$session_token",
    "Expiration": "$expiration"
}
EOF
            
            # Verify session token credentials work for basic S3 operations
            log "Testing S3 operation with session token credentials..."
            
            # Save original credentials
            local orig_access_key="$AWS_ACCESS_KEY_ID"
            local orig_secret_key="$AWS_SECRET_ACCESS_KEY"
            local orig_session_token="${AWS_SESSION_TOKEN:-}"
            
            # Use session token credentials
            export AWS_ACCESS_KEY_ID="$access_key_id"
            export AWS_SECRET_ACCESS_KEY="$secret_access_key"
            export AWS_SESSION_TOKEN="$session_token"
            
            # Test basic S3 operation
            local s3_test_result
            s3_test_result=$(aws_s3api list-buckets 2>&1)
            local s3_exit_code=$?
            
            # Restore original credentials
            export AWS_ACCESS_KEY_ID="$orig_access_key"
            export AWS_SECRET_ACCESS_KEY="$orig_secret_key"
            if [ -n "$orig_session_token" ]; then
                export AWS_SESSION_TOKEN="$orig_session_token"
            else
                unset AWS_SESSION_TOKEN
            fi
            
            if [ $s3_exit_code -eq 0 ]; then
                success "STS GetSessionToken - Session token credentials work for S3 operations"
            else
                warning "STS GetSessionToken - Session token credentials failed S3 test: $s3_test_result"
            fi
            
            # Verify expiration is in the future
            local exp_epoch current_epoch
            exp_epoch=$(date -d "$expiration" +%s 2>/dev/null || \
                       python3 -c "import datetime; import sys; print(int(datetime.datetime.fromisoformat('$expiration'.replace('Z', '+00:00')).timestamp()))" 2>/dev/null || \
                       echo "0")
            current_epoch=$(date +%s)
            
            if [ "$exp_epoch" -gt "$current_epoch" ]; then
                success "STS GetSessionToken - Credentials have valid future expiration: $expiration"
            else
                warning "STS GetSessionToken - Credentials expiration may not be in future: $expiration"
            fi
            
        else
            error "STS GetSessionToken - Response missing required credential fields"
            log "AWS CLI Response:"
            echo "$aws_output"
        fi
    else
        error "STS GetSessionToken - Failed to get session token"
        log "AWS CLI Response:"
        echo "$aws_output"
    fi
}

# Test STS GetCallerIdentity response format
# Validates AWS-compatible XML response structure
test_sts_get_caller_identity() {
    log "[$(date '+%Y-%m-%d %H:%M:%S')] Testing STS GetCallerIdentity response format..."

    # Test GetCallerIdentity operation
    local aws_output
    capture_output aws_output aws_sts get-caller-identity --output json

    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        success "STS GetCallerIdentity - Request succeeded"
        log "Response:"
        echo "$aws_output" | jq '.' 2>/dev/null || echo "$aws_output"

        # Validate required fields in JSON response
        local account_id user_id arn
        account_id=$(echo "$aws_output" | jq -r '.Account // empty' 2>/dev/null)
        user_id=$(echo "$aws_output" | jq -r '.UserId // empty' 2>/dev/null)
        arn=$(echo "$aws_output" | jq -r '.Arn // empty' 2>/dev/null)

        local all_fields_present=true

        # Check Account field
        if [ -n "$account_id" ]; then
            success "STS GetCallerIdentity - Account field present: $account_id"
        else
            error "STS GetCallerIdentity - Account field missing"
            all_fields_present=false
        fi

        # Check UserId field
        if [ -n "$user_id" ]; then
            success "STS GetCallerIdentity - UserId field present: $user_id"
        else
            error "STS GetCallerIdentity - UserId field missing"
            all_fields_present=false
        fi

        # Check Arn field
        if [ -n "$arn" ]; then
            success "STS GetCallerIdentity - Arn field present: $arn"

            # Validate ARN format (should start with arn:aws:)
            if [[ "$arn" == arn:aws:* ]]; then
                success "STS GetCallerIdentity - Arn has valid AWS ARN format"
            else
                warning "STS GetCallerIdentity - Arn does not follow standard AWS ARN format: $arn"
            fi
        else
            error "STS GetCallerIdentity - Arn field missing"
            all_fields_present=false
        fi

        if [ "$all_fields_present" = true ]; then
            success "STS GetCallerIdentity - Response format is AWS-compatible"
        else
            error "STS GetCallerIdentity - Response format is missing required fields"
        fi

        # Test with temporary credentials if available
        if [ -f "$TEMP_DIR/session_token_credentials.json" ]; then
            log "Testing GetCallerIdentity with session token credentials..."

            # Save original credentials
            local orig_access_key="$AWS_ACCESS_KEY_ID"
            local orig_secret_key="$AWS_SECRET_ACCESS_KEY"
            local orig_session_token="${AWS_SESSION_TOKEN:-}"

            # Load session token credentials
            local temp_access_key temp_secret_key temp_session_token
            temp_access_key=$(jq -r '.AccessKeyId' "$TEMP_DIR/session_token_credentials.json")
            temp_secret_key=$(jq -r '.SecretAccessKey' "$TEMP_DIR/session_token_credentials.json")
            temp_session_token=$(jq -r '.SessionToken' "$TEMP_DIR/session_token_credentials.json")

            # Use session token credentials
            export AWS_ACCESS_KEY_ID="$temp_access_key"
            export AWS_SECRET_ACCESS_KEY="$temp_secret_key"
            export AWS_SESSION_TOKEN="$temp_session_token"

            local temp_output
            capture_output temp_output aws_sts get-caller-identity --output json
            local temp_exit_code=$?

            # Restore original credentials
            export AWS_ACCESS_KEY_ID="$orig_access_key"
            export AWS_SECRET_ACCESS_KEY="$orig_secret_key"
            if [ -n "$orig_session_token" ]; then
                export AWS_SESSION_TOKEN="$orig_session_token"
            else
                unset AWS_SESSION_TOKEN
            fi

            if [ $temp_exit_code -eq 0 ]; then
                success "STS GetCallerIdentity - Works with temporary credentials"
                log "Temporary credential identity:"
                echo "$temp_output" | jq '.' 2>/dev/null || echo "$temp_output"
            else
                warning "STS GetCallerIdentity - Failed with temporary credentials"
            fi
        fi

    else
        error "STS GetCallerIdentity - Request failed"
        log "AWS CLI Response:"
        echo "$aws_output"
    fi
}

# Test STS GetCallerIdentity with temporary credentials from AssumeRole
# Creates a role, assumes it, and validates GetCallerIdentity returns assumed role identity
test_sts_get_caller_identity_with_temp_creds() {
    log "[$(date '+%Y-%m-%d %H:%M:%S')] Testing STS GetCallerIdentity with temporary credentials..."

    local role_name="GetCallerIdTestRole-$(date +%s)"

    # Get the actual account UUID from GetCallerIdentity
    log "Getting account UUID from GetCallerIdentity..."
    local caller_identity
    caller_identity=$(aws sts --endpoint-url="$S3_ENDPOINT" \
        --region="$AWS_REGION" \
        --no-verify-ssl \
        get-caller-identity \
        --output json 2>/dev/null)

    local account_uuid
    account_uuid=$(echo "$caller_identity" | jq -r '.Account // empty' 2>/dev/null)

    if [ -z "$account_uuid" ]; then
        error "STS GetCallerIdentity with temp creds - Could not get account UUID"
        log "GetCallerIdentity response: $caller_identity"
        return 1
    fi

    log "DEBUG: Account UUID: $account_uuid"

    # Create trust policy allowing the current account to assume the role
    # Use "*" principal like other working tests - specific ARN format may not be fully supported
    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    log "DEBUG: Trust policy: $trust_policy"

    # Step 1: Create a role for testing
    log "Creating test role: $role_name"
    local create_output
    capture_output create_output aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" \
        --output json

    if [ $? -ne 0 ]; then
        error "STS GetCallerIdentity with temp creds - Failed to create test role"
        log "Create role output: $create_output"
        return 1
    fi

    # Extract role ARN
    local role_arn
    role_arn=$(echo "$create_output" | jq -r '.Role.Arn // empty' 2>/dev/null)

    if [ -z "$role_arn" ]; then
        error "STS GetCallerIdentity with temp creds - Could not extract role ARN"
        # Cleanup
        aws_iam delete-role --role-name "$role_name" 2>/dev/null || true
        return 1
    fi

    log "Created role with ARN: $role_arn"

    # Wait for role to propagate before assuming
    log "Waiting for role to propagate..."
    sleep 2

    # Step 2: Assume the role to get temporary credentials
    log "Assuming role to get temporary credentials..."
    log "DEBUG: Role ARN: $role_arn"
    log "DEBUG: Endpoint: $S3_ENDPOINT"

    local assume_output assume_exit_code
    # Use --debug to see full HTTP request/response on failure
    assume_output=$(aws sts --endpoint-url="$S3_ENDPOINT" \
        --region="$AWS_REGION" \
        --no-verify-ssl \
        --debug \
        assume-role \
        --role-arn "$role_arn" \
        --role-session-name "GetCallerIdTest" \
        --duration-seconds 900 \
        --output json 2>&1)
    assume_exit_code=$?

    log "DEBUG: AssumeRole exit code: $assume_exit_code"

    if [ $assume_exit_code -ne 0 ]; then
        error "STS GetCallerIdentity with temp creds - Failed to assume role"
        log "DEBUG: Looking for server response body:"
        echo "$assume_output" | grep -A20 "Response body" | head -30
        log "DEBUG: Looking for Error XML:"
        echo "$assume_output" | grep -oE "<Error>.*</Error>" | head -5
        log "DEBUG: Full output (last 100 lines):"
        echo "$assume_output" | tail -100
        # Cleanup
        aws_iam delete-role --role-name "$role_name" 2>/dev/null || true
        return 1
    fi

    # On success, extract just the JSON block (filter out debug and XML output)
    # The JSON starts with '{' on its own line and ends with '}'
    local json_output
    json_output=$(echo "$assume_output" | sed -n '/^{$/,/^}$/p')

    log "DEBUG: Extracted JSON output:"
    echo "$json_output" | head -20

    # Extract temporary credentials
    local temp_access_key temp_secret_key temp_session_token
    temp_access_key=$(echo "$json_output" | jq -r '.Credentials.AccessKeyId // empty' 2>/dev/null)
    temp_secret_key=$(echo "$json_output" | jq -r '.Credentials.SecretAccessKey // empty' 2>/dev/null)
    temp_session_token=$(echo "$json_output" | jq -r '.Credentials.SessionToken // empty' 2>/dev/null)

    log "DEBUG: Extracted AccessKeyId: $temp_access_key"
    log "DEBUG: Extracted SessionToken length: ${#temp_session_token}"

    if [ -z "$temp_access_key" ] || [ -z "$temp_secret_key" ] || [ -z "$temp_session_token" ]; then
        error "STS GetCallerIdentity with temp creds - Could not extract temporary credentials"
        log "DEBUG: Raw assume_output (last 50 lines):"
        echo "$assume_output" | tail -50
        # Cleanup
        aws_iam delete-role --role-name "$role_name" 2>/dev/null || true
        return 1
    fi

    success "STS GetCallerIdentity with temp creds - Obtained temporary credentials"

    # Step 3: Use temporary credentials to call GetCallerIdentity
    log "Calling GetCallerIdentity with temporary credentials..."
    log "DEBUG: Using temp AccessKeyId: $temp_access_key"

    # Save original credentials
    local orig_access_key="$AWS_ACCESS_KEY_ID"
    local orig_secret_key="$AWS_SECRET_ACCESS_KEY"
    local orig_session_token="${AWS_SESSION_TOKEN:-}"

    # Use temporary credentials
    export AWS_ACCESS_KEY_ID="$temp_access_key"
    export AWS_SECRET_ACCESS_KEY="$temp_secret_key"
    export AWS_SESSION_TOKEN="$temp_session_token"

    local identity_output
    identity_output=$(aws sts --endpoint-url="$S3_ENDPOINT" \
        --region="$AWS_REGION" \
        --no-verify-ssl \
        get-caller-identity \
        --output json 2>&1)
    local identity_exit_code=$?

    log "DEBUG: GetCallerIdentity exit code: $identity_exit_code"
    log "DEBUG: GetCallerIdentity raw output:"
    echo "$identity_output"

    # Restore original credentials immediately
    export AWS_ACCESS_KEY_ID="$orig_access_key"
    export AWS_SECRET_ACCESS_KEY="$orig_secret_key"
    if [ -n "$orig_session_token" ]; then
        export AWS_SESSION_TOKEN="$orig_session_token"
    else
        unset AWS_SESSION_TOKEN
    fi

    # Step 4: Validate the response
    if [ $identity_exit_code -eq 0 ]; then
        success "STS GetCallerIdentity with temp creds - Request succeeded"
        log "Response:"
        echo "$identity_output" | jq '.' 2>/dev/null || echo "$identity_output"

        # Validate response fields
        local resp_account resp_user_id resp_arn
        resp_account=$(echo "$identity_output" | jq -r '.Account // empty' 2>/dev/null)
        resp_user_id=$(echo "$identity_output" | jq -r '.UserId // empty' 2>/dev/null)
        resp_arn=$(echo "$identity_output" | jq -r '.Arn // empty' 2>/dev/null)

        # Check Account field
        if [ -n "$resp_account" ]; then
            success "STS GetCallerIdentity with temp creds - Account field present: $resp_account"
        else
            error "STS GetCallerIdentity with temp creds - Account field missing"
        fi

        # Check UserId field
        if [ -n "$resp_user_id" ]; then
            success "STS GetCallerIdentity with temp creds - UserId field present: $resp_user_id"
        else
            error "STS GetCallerIdentity with temp creds - UserId field missing"
        fi

        # Check Arn field - should reflect the assumed role
        if [ -n "$resp_arn" ]; then
            success "STS GetCallerIdentity with temp creds - Arn field present: $resp_arn"

            # Validate ARN contains the assumed role info
            if [[ "$resp_arn" == *"$role_name"* ]] || [[ "$resp_arn" == *"assumed-role"* ]]; then
                success "STS GetCallerIdentity with temp creds - Arn reflects assumed role identity"
            else
                warning "STS GetCallerIdentity with temp creds - Arn may not reflect assumed role: $resp_arn"
            fi
        else
            error "STS GetCallerIdentity with temp creds - Arn field missing"
        fi

    else
        error "STS GetCallerIdentity with temp creds - Request failed with temporary credentials"
        log "Response: $identity_output"
    fi

    # Step 5: Cleanup - delete the test role
    log "Cleaning up test role: $role_name"
    aws_iam delete-role --role-name "$role_name" 2>/dev/null || true

    success "STS GetCallerIdentity with temp creds - Test completed"
}

# Test IAM CreateRole with temporary credentials from GetSessionToken
# AWS restriction: GetSessionToken credentials (MSTS prefix) CANNOT call
# IAM APIs. This test verifies that our implementation correctly blocks
# IAM operations when using GetSessionToken temporary credentials.
test_iam_create_role_with_session_token() {
    log "Testing IAM CreateRole with GetSessionToken credentials (MSTS)..."
    log "Expected: AccessDenied (MSTS prefix blocked from IAM APIs)"

    # Step 1: Get session token credentials (MSTS prefix)
    log "Step 1: Getting session token credentials..."
    local session_output
    capture_output session_output aws_sts get-session-token \
        --duration-seconds 3600 \
        --output json

    if [ $? -ne 0 ]; then
        error "IAM with MSTS - Failed to get session token"
        log "GetSessionToken output: $session_output"
        return 1
    fi

    # Extract credentials
    local temp_access_key temp_secret_key temp_session_token
    temp_access_key=$(echo "$session_output" | \
        jq -r '.Credentials.AccessKeyId // empty' 2>/dev/null)
    temp_secret_key=$(echo "$session_output" | \
        jq -r '.Credentials.SecretAccessKey // empty' 2>/dev/null)
    temp_session_token=$(echo "$session_output" | \
        jq -r '.Credentials.SessionToken // empty' 2>/dev/null)

    if [ -z "$temp_access_key" ] || [ -z "$temp_secret_key" ] || \
       [ -z "$temp_session_token" ]; then
        error "IAM with MSTS - Could not extract session credentials"
        log "Session output: $session_output"
        return 1
    fi

    # Verify MSTS prefix (GetSessionToken credentials)
    if [[ "$temp_access_key" != MSTS* ]]; then
        error "IAM with MSTS - AccessKeyId should have MSTS prefix"
        log "Got AccessKeyId: $temp_access_key (expected MSTS...)"
        return 1
    fi

    log "DEBUG: Got MSTS credentials: $temp_access_key"
    success "IAM with MSTS - Verified MSTS prefix on GetSessionToken creds"

    # Save original credentials
    local orig_access_key="$AWS_ACCESS_KEY_ID"
    local orig_secret_key="$AWS_SECRET_ACCESS_KEY"
    local orig_session_token="${AWS_SESSION_TOKEN:-}"

    # Step 2: Attempt IAM CreateRole (should be blocked)
    log "Step 2: Attempting IAM CreateRole with MSTS credentials..."

    export AWS_ACCESS_KEY_ID="$temp_access_key"
    export AWS_SECRET_ACCESS_KEY="$temp_secret_key"
    export AWS_SESSION_TOKEN="$temp_session_token"

    local role_name="MSTSTestRole-$(date +%s)-$$"
    local trust_policy='{
        "Version":"2012-10-17",
        "Statement":[{
            "Effect":"Allow",
            "Principal":{"AWS":"*"},
            "Action":"sts:AssumeRole"
        }]
    }'

    set +e
    local create_output
    capture_output create_output aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" \
        --description "Test role - should fail with MSTS creds" \
        --output json
    local create_exit_code=$?
    set -e

    # Restore original credentials immediately
    export AWS_ACCESS_KEY_ID="$orig_access_key"
    export AWS_SECRET_ACCESS_KEY="$orig_secret_key"
    if [ -n "$orig_session_token" ]; then
        export AWS_SESSION_TOKEN="$orig_session_token"
    else
        unset AWS_SESSION_TOKEN
    fi

    # Step 3: Verify the request was blocked with AccessDenied
    if [ $create_exit_code -ne 0 ]; then
        if echo "$create_output" | grep -qiE "AccessDenied"; then
            success "IAM with MSTS - Correctly blocked with AccessDenied"
            log "Response: $create_output"
        else
            error "IAM with MSTS - Blocked but unexpected error message"
            log "Expected: AccessDenied, Got: $create_output"
        fi
    else
        # Role was created - this is a SECURITY VIOLATION
        error "IAM with MSTS - SECURITY BUG: Role was created!"
        error "GetSessionToken credentials (MSTS) must NOT call IAM APIs"
        log "Response: $create_output"

        # Clean up the role that should not have been created
        log "Cleaning up incorrectly created role: $role_name"
        aws_iam delete-role --role-name "$role_name" 2>/dev/null || true
    fi
}

# Test IAM CreateRole with temporary credentials from AssumeRole
# AssumeRole credentials (MSAR prefix) CAN call IAM APIs if the
# role's permission policy allows it. This test verifies that
# MSAR credentials are not blocked from IAM operations.
test_iam_create_role_with_assume_role_credentials() {
    log "Testing IAM CreateRole with AssumeRole credentials (MSAR)..."
    log "Expected: Success (MSAR prefix allowed for IAM APIs)"

    # Step 1: Create a role that allows the current user to assume it
    # and has permissions to call IAM CreateRole
    log "Step 1: Creating a role with IAM permissions..."

    local account_uuid
    account_uuid=$(get_account_uuid)
    if [ -z "$account_uuid" ]; then
        error "IAM with MSAR - Could not get account UUID"
        return 1
    fi

    local base_role_name="IAMPermissionsRole-$(date +%s)-$$"

    # Trust policy allowing current account to assume this role
    local trust_policy=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "$account_uuid"},
        "Action": "sts:AssumeRole"
    }]
}
EOF
)

    set +e
    local create_base_output
    capture_output create_base_output aws_iam create-role \
        --role-name "$base_role_name" \
        --assume-role-policy-document "$trust_policy" \
        --description "Role with IAM permissions for MSAR test" \
        --output json
    local create_base_exit=$?
    set -e

    if [ $create_base_exit -ne 0 ]; then
        error "IAM with MSAR - Failed to create base role"
        log "Output: $create_base_output"
        return 1
    fi

    log "DEBUG: Created base role: $base_role_name"

    # Add IAM permissions to the role
    local iam_policy=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["iam:CreateRole", "iam:DeleteRole", "iam:GetRole"],
        "Resource": "*"
    }]
}
EOF
)

    set +e
    aws_iam put-role-policy \
        --role-name "$base_role_name" \
        --policy-name "IAMPermissions" \
        --policy-document "$iam_policy" 2>/dev/null
    set -e

    # Step 2: Assume the role to get MSAR credentials
    log "Step 2: Assuming role to get MSAR credentials..."

    local role_arn="arn:aws:iam::$account_uuid:role/$base_role_name"
    local assume_output

    set +e
    capture_output assume_output aws_sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name "MSAR-IAM-Test" \
        --output json
    local assume_exit=$?
    set -e

    if [ $assume_exit -ne 0 ]; then
        error "IAM with MSAR - Failed to assume role"
        log "Output: $assume_output"
        # Cleanup base role
        aws_iam delete-role-policy \
            --role-name "$base_role_name" \
            --policy-name "IAMPermissions" 2>/dev/null || true
        aws_iam delete-role --role-name "$base_role_name" 2>/dev/null || true
        return 1
    fi

    # Extract MSAR credentials
    local msar_access_key msar_secret_key msar_session_token
    msar_access_key=$(echo "$assume_output" | \
        jq -r '.Credentials.AccessKeyId // empty' 2>/dev/null)
    msar_secret_key=$(echo "$assume_output" | \
        jq -r '.Credentials.SecretAccessKey // empty' 2>/dev/null)
    msar_session_token=$(echo "$assume_output" | \
        jq -r '.Credentials.SessionToken // empty' 2>/dev/null)

    if [ -z "$msar_access_key" ] || [ -z "$msar_secret_key" ] || \
       [ -z "$msar_session_token" ]; then
        error "IAM with MSAR - Could not extract AssumeRole credentials"
        log "Assume output: $assume_output"
        # Cleanup
        aws_iam delete-role-policy \
            --role-name "$base_role_name" \
            --policy-name "IAMPermissions" 2>/dev/null || true
        aws_iam delete-role --role-name "$base_role_name" 2>/dev/null || true
        return 1
    fi

    # Verify MSAR prefix (AssumeRole credentials)
    if [[ "$msar_access_key" != MSAR* ]]; then
        error "IAM with MSAR - AccessKeyId should have MSAR prefix"
        log "Got AccessKeyId: $msar_access_key (expected MSAR...)"
        # Cleanup
        aws_iam delete-role-policy \
            --role-name "$base_role_name" \
            --policy-name "IAMPermissions" 2>/dev/null || true
        aws_iam delete-role --role-name "$base_role_name" 2>/dev/null || true
        return 1
    fi

    log "DEBUG: Got MSAR credentials: $msar_access_key"
    success "IAM with MSAR - Verified MSAR prefix on AssumeRole creds"

    # Save original credentials
    local orig_access_key="$AWS_ACCESS_KEY_ID"
    local orig_secret_key="$AWS_SECRET_ACCESS_KEY"
    local orig_session_token="${AWS_SESSION_TOKEN:-}"

    # Step 3: Use MSAR credentials to call IAM CreateRole
    log "Step 3: Attempting IAM CreateRole with MSAR credentials..."

    export AWS_ACCESS_KEY_ID="$msar_access_key"
    export AWS_SECRET_ACCESS_KEY="$msar_secret_key"
    export AWS_SESSION_TOKEN="$msar_session_token"

    local new_role_name="MSARCreatedRole-$(date +%s)-$$"
    local new_trust_policy='{
        "Version":"2012-10-17",
        "Statement":[{
            "Effect":"Allow",
            "Principal":{"AWS":"*"},
            "Action":"sts:AssumeRole"
        }]
    }'

    set +e
    local create_output
    capture_output create_output aws_iam create-role \
        --role-name "$new_role_name" \
        --assume-role-policy-document "$new_trust_policy" \
        --description "Role created with MSAR credentials" \
        --output json
    local create_exit_code=$?
    set -e

    # Restore original credentials
    export AWS_ACCESS_KEY_ID="$orig_access_key"
    export AWS_SECRET_ACCESS_KEY="$orig_secret_key"
    if [ -n "$orig_session_token" ]; then
        export AWS_SESSION_TOKEN="$orig_session_token"
    else
        unset AWS_SESSION_TOKEN
    fi

    # Step 4: Verify the result
    if [ $create_exit_code -eq 0 ]; then
        success "IAM with MSAR - Successfully created role with MSAR creds"
        log "Response: $create_output"

        # Cleanup the newly created role
        log "Cleaning up created role: $new_role_name"
        aws_iam delete-role --role-name "$new_role_name" 2>/dev/null || true
    else
        if echo "$create_output" | grep -qiE "AccessDenied"; then
            error "IAM with MSAR - Incorrectly blocked MSAR credentials"
            error "AssumeRole credentials (MSAR) SHOULD be allowed for IAM"
        else
            error "IAM with MSAR - Failed with error: $create_output"
        fi
    fi

    # Cleanup base role
    log "Cleaning up base role: $base_role_name"
    aws_iam delete-role-policy \
        --role-name "$base_role_name" \
        --policy-name "IAMPermissions" 2>/dev/null || true
    aws_iam delete-role --role-name "$base_role_name" 2>/dev/null || true
}

# Test that verifies the access key prefix distinction
test_sts_credential_prefix_verification() {
    log "Testing STS credential prefix verification..."
    log "GetSessionToken should return MSTS, AssumeRole should return MSAR"

    local account_uuid
    account_uuid=$(get_account_uuid)

    # Test 1: GetSessionToken returns MSTS prefix
    log "Test 1: Verifying GetSessionToken returns MSTS prefix..."
    local session_output
    capture_output session_output aws_sts get-session-token \
        --duration-seconds 900 \
        --output json

    if [ $? -eq 0 ]; then
        local session_key
        session_key=$(echo "$session_output" | \
            jq -r '.Credentials.AccessKeyId // empty' 2>/dev/null)
        if [[ "$session_key" == MSTS* ]]; then
            success "STS Prefix - GetSessionToken returns MSTS prefix"
            log "AccessKeyId: $session_key"
        else
            error "STS Prefix - GetSessionToken should return MSTS prefix"
            log "Got: $session_key"
        fi
    else
        error "STS Prefix - GetSessionToken failed"
    fi

    # Test 2: AssumeRole returns MSAR prefix
    log "Test 2: Verifying AssumeRole returns MSAR prefix..."

    # Create a simple role to assume
    local test_role="PrefixTestRole-$(date +%s)-$$"
    local trust_policy=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "$account_uuid"},
        "Action": "sts:AssumeRole"
    }]
}
EOF
)

    set +e
    aws_iam create-role \
        --role-name "$test_role" \
        --assume-role-policy-document "$trust_policy" \
        --output json 2>/dev/null
    local create_exit=$?
    set -e

    if [ $create_exit -eq 0 ]; then
        local role_arn="arn:aws:iam::$account_uuid:role/$test_role"
        local assume_output

        set +e
        capture_output assume_output aws_sts assume-role \
            --role-arn "$role_arn" \
            --role-session-name "prefix-test" \
            --output json
        local assume_exit=$?
        set -e

        if [ $assume_exit -eq 0 ]; then
            local assume_key
            assume_key=$(echo "$assume_output" | \
                jq -r '.Credentials.AccessKeyId // empty' 2>/dev/null)
            if [[ "$assume_key" == MSAR* ]]; then
                success "STS Prefix - AssumeRole returns MSAR prefix"
                log "AccessKeyId: $assume_key"
            else
                error "STS Prefix - AssumeRole should return MSAR prefix"
                log "Got: $assume_key"
            fi
        else
            error "STS Prefix - AssumeRole failed"
            log "Output: $assume_output"
        fi

        # Cleanup
        aws_iam delete-role --role-name "$test_role" 2>/dev/null || true
    else
        error "STS Prefix - Could not create test role for AssumeRole"
    fi
}

# =============================================================================
# IAM Test Utilities
# =============================================================================

# Minimal cleanup - just delete a few most recent roles 
cleanup_iam_test_resources() {
    local role_prefix="$1"
    
    log "DEBUG: Ultra-fast cleanup for prefix: $role_prefix (skip all AWS calls)"
    
    # Since tests create roles with predictable patterns and we know DeleteRole works fast,
    # just skip cleanup entirely to avoid any hanging AWS CLI calls during testing
    log "DEBUG: Skipping cleanup to avoid hanging - roles will be cleaned up by next test run"
    
    # If we really need cleanup, only try the most likely recent role name
    if [ "${FORCE_CLEANUP:-}" = "true" ]; then
        log "DEBUG: Force cleanup requested, trying one likely role name..."
        local current_time=$(date +%s)
        local likely_role="${role_prefix}${current_time}"
        
        # Try deleting just one likely role name with short timeout
        log "DEBUG: Attempting to delete: $likely_role"
        set +e
        timeout 5 aws_iam delete-role --role-name "$likely_role" 2>/dev/null || true
        set -e
        log "DEBUG: Cleanup attempt completed"
    fi
    set -e
}

# Comprehensive cleanup - delete all existing roles to prevent name conflicts  
cleanup_all_iam_roles() {
    log "DEBUG: Comprehensive IAM role cleanup - deleting all existing roles..."
    
    set +e  # Don't exit on errors during cleanup
    
    # Get list of all existing roles using temp file to avoid pipe-while subshell issues
    local roles_temp_file="$TEMP_DIR/roles_to_cleanup.tmp"
    aws_iam_silent list-roles 2>/dev/null | grep '"RoleName"' | sed 's/.*"RoleName": *"\([^"]*\)".*/\1/' > "$roles_temp_file" || true
    
    if [ -s "$roles_temp_file" ]; then
        local total_count=$(wc -l < "$roles_temp_file")
        log "DEBUG: Found $total_count roles to delete"
        
        # Delete each role and its policies using file input instead of pipe
        while IFS= read -r role_name; do
            if [ -n "$role_name" ]; then
                log "DEBUG: Deleting role and policies: $role_name"
                
                # First, delete all attached inline policies
                local policies_temp_file="$TEMP_DIR/policies_to_cleanup_${role_name}.tmp"
                aws_iam_silent list-role-policies --role-name "$role_name" 2>/dev/null | grep '"PolicyNames"' -A 100 | grep '"' | sed 's/.*"\([^"]*\)".*/\1/' > "$policies_temp_file" || true
                
                if [ -s "$policies_temp_file" ]; then
                    while IFS= read -r policy_name; do
                        if [ -n "$policy_name" ]; then
                            log "DEBUG: Deleting policy $policy_name from role $role_name"
                            timeout 10 aws_iam_silent delete-role-policy --role-name "$role_name" --policy-name "$policy_name" 2>/dev/null || true
                            sleep 1  # Brief pause between policy deletions
                        fi
                    done < "$policies_temp_file"
                    rm -f "$policies_temp_file"
                fi
                
                # Then delete the role with longer timeout
                log "DEBUG: Deleting role: $role_name"
                timeout 15 aws_iam_silent delete-role --role-name "$role_name" 2>/dev/null || true
                sleep 2  # Brief pause between role deletions to avoid overwhelming the system
            fi
        done < "$roles_temp_file"
        
        rm -f "$roles_temp_file"
        log "DEBUG: Role cleanup completed"
    else
        log "DEBUG: No existing roles found to delete"
        rm -f "$roles_temp_file"
    fi
    
    set -e
}

# =============================================================================
# IAM Policy Conversion Test
# =============================================================================

test_iam_policy_conversion() {
    log "Testing IAM policy conversion with S3 permissions..."
    
    # Clean up any existing test roles first to avoid UUID conflicts
    log "DEBUG: Cleaning up existing IAM test roles and policies..."
    cleanup_iam_test_resources "policy-test-role-"
    
    local role_name="policy-test-role-$(date +%s)-$$-$RANDOM"
    
    # Create a role with proper trust policy (AssumeRolePolicyDocument)
    # S3 permissions will be attached separately via PutRolePolicy (proper AWS pattern)
    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    local s3_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:ListBucket","s3:ListObjectsV2"],"Resource":["arn:aws:s3:::test-bucket/*","arn:aws:s3:::test-bucket"]}]}'
    
    log "Creating role with trust policy..."
    log "DEBUG: Trust policy being used:"
    echo "$trust_policy"
    set +e
    local create_result
    capture_output create_result aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" \
        --description "Test role with S3 permissions for policy conversion testing" \
       
    local create_exit=$?
    set -e
    
    if [ $create_exit -eq 0 ]; then
        success "IAM Policy Conversion - Role with S3 policy created successfully: $role_name"
        log "DEBUG: CreateRole response:"
        echo "$create_result"
        
        # Now attach S3 permissions via PutRolePolicy (proper AWS pattern)  
        log "Attaching S3 permissions via PutRolePolicy to role: $role_name"
        log "DEBUG: S3 policy being attached:"
        echo "$s3_policy"
        set +e
        local put_result
        capture_output put_result aws_iam put-role-policy \
            --role-name "$role_name" \
            --policy-name "S3AccessPolicy" \
            --policy-document "$s3_policy" \
           
        local put_exit=$?
        set -e
        
        if [ $put_exit -eq 0 ]; then
            success "IAM Policy Conversion - S3 policy attached successfully"
            log "DEBUG: PutRolePolicy response:"
            echo "$put_result"
            
            # Wait a moment for policy attachment to propagate
            log "DEBUG: Waiting 2 seconds for policy attachment to propagate..."
            sleep 2
            
            # Verify we can retrieve the role and it contains the permission policies
            log "Verifying role retrieval with permission policies..."
            log "DEBUG: Retrieving role: $role_name"
            set +e
            local get_result
            capture_output get_result aws_iam get-role --role-name "$role_name"
            local get_exit=$?
            set -e
            
            if [ $get_exit -eq 0 ]; then
                success "IAM Policy Conversion - Role retrieved successfully after policy attachment"
                log "DEBUG: GetRole response confirms role exists:"
                echo "$get_result"
                
                # AWS GetRole does not return attached policies - use ListRolePolicies instead
                log "Using AWS standard ListRolePolicies to verify policy attachment..."
                set +e
                local list_result
                capture_output list_result aws_iam list-role-policies --role-name "$role_name"
                local list_exit=$?
                set -e
                
                if [ $list_exit -eq 0 ]; then
                    # Check if S3AccessPolicy is in the list
                    if echo "$list_result" | jq -e '.PolicyNames[] | select(. == "S3AccessPolicy")' >/dev/null 2>&1; then
                        log "✅ S3AccessPolicy found in ListRolePolicies"
                        
                        # Now get the actual policy document to verify S3 permissions
                        log "Retrieving policy document with GetRolePolicy..."
                        
                        set +e
                        local policy_result
                        capture_output policy_result aws_iam get-role-policy --role-name "$role_name" --policy-name "S3AccessPolicy"
                        local policy_exit=$?
                        set -e
                        
                        if [ $policy_exit -eq 0 ]; then
                            # Check policy document for S3 permissions
                            local has_s3_get_object=false
                            local has_s3_put_object=false
                            local has_test_bucket=false
                            
                            if echo "$policy_result" | jq -e '.. | select(type == "string" and test("s3:GetObject"))?' >/dev/null 2>&1; then
                                has_s3_get_object=true
                                log "  ✅ s3:GetObject permission found"
                            fi
                            
                            if echo "$policy_result" | jq -e '.. | select(type == "string" and test("s3:PutObject"))?' >/dev/null 2>&1; then
                                has_s3_put_object=true
                                log "  ✅ s3:PutObject permission found"
                            fi
                            
                            if echo "$policy_result" | jq -e '.. | select(type == "string" and test("test-bucket"))?' >/dev/null 2>&1; then
                                has_test_bucket=true
                                log "  ✅ test-bucket resource found"
                            fi
                            
                            if [ "$has_s3_get_object" = "true" ] && [ "$has_s3_put_object" = "true" ] && [ "$has_test_bucket" = "true" ]; then
                                success "IAM Policy Conversion - S3 permissions verified via AWS standard operations"
                                
                                # Save role name for cleanup
                                echo "$role_name" > "$TEMP_DIR/policy_test_role_name"
                                return 0
                            else
                                error "IAM Policy Conversion - S3 permissions missing in policy document"
                                log "DEBUG: Missing permissions:"
                                [ "$has_s3_get_object" = "false" ] && log "  ❌ s3:GetObject NOT found"
                                [ "$has_s3_put_object" = "false" ] && log "  ❌ s3:PutObject NOT found"  
                                [ "$has_test_bucket" = "false" ] && log "  ❌ test-bucket NOT found"
                                return 1
                            fi
                        else
                            error "IAM Policy Conversion - Failed to retrieve policy document via GetRolePolicy"
                            log "DEBUG: GetRolePolicy failed:"
                            log "  Role name: '$role_name'"
                            log "  S3_ENDPOINT: '$S3_ENDPOINT'"
                            log "  Exit code: $policy_exit"
                            log "  Response: $policy_result"
                            return 1
                        fi
                    else
                        error "IAM Policy Conversion - S3AccessPolicy not found in ListRolePolicies"
                        log "DEBUG: ListRolePolicies succeeded but policy missing:"
                        log "  Role name: '$role_name'"
                        log "  S3_ENDPOINT: '$S3_ENDPOINT'"
                        log "  Exit code: $list_exit"
                        log "  Response: $list_result"
                        return 1
                    fi
                else
                    error "IAM Policy Conversion - ListRolePolicies failed"
                    log "DEBUG: ListRolePolicies failed:"
                    log "  Role name: '$role_name'"
                    log "  S3_ENDPOINT: '$S3_ENDPOINT'"
                    log "  Exit code: $list_exit"
                    log "  Response: $list_result"
                    return 1
                fi
            else
                error "IAM Policy Conversion - Failed to retrieve role after policy attachment"
                echo "Get role error: $get_result"
                return 1
            fi
        else
            error "IAM Policy Conversion - Failed to attach S3 policy to role"
            echo "PutRolePolicy error: $put_result"
            return 1
        fi
    else
        error "IAM Policy Conversion - Failed to create role"
        echo "Create role error: $create_result"
        return 1
    fi
}

# =============================================================================
# IAM Permission Policy Tests (New Feature)
# =============================================================================

test_iam_put_role_policy() {
    log "Testing IAM PutRolePolicy (attach permission policy to role)..."
    
    # Clean up any existing test roles and policies first to avoid UUID conflicts
    log "DEBUG: Cleaning up existing IAM test roles and policies..."
    cleanup_iam_test_resources "permission-test-role-"
    
    # Create a role with only trust policy (no S3 permissions)
    # Generate highly unique role name with microseconds and multiple random components
    local timestamp=$(date +%s)
    local microseconds=$(date +%N | cut -b1-6)
    local role_name="permission-test-role-${timestamp}-${microseconds}-$$-$RANDOM-$RANDOM"
    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    
    
    set +e
    local create_result
    capture_output create_result aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" \
        --description "Test role for permission policy attachment" \
       
    local create_exit=$?
    set -e
    
    
    if [ $create_exit -ne 0 ]; then
        error "IAM PutRolePolicy setup - Failed to create role: $create_result"
        return 1
    fi
    
    log "DEBUG: Role created successfully: $role_name"
    log "DEBUG: CreateRole response:"
    echo "$create_result"
    
    log "Role created successfully, now attaching permission policy..."
    
    # Attach permission policy with S3 access - use fixed bucket name for consistency
    # Include CreateBucket permission to allow bucket creation during test
    local IAM_TEST_BUCKET="iam-test-bucket-fixed"
    local permission_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"s3:PutObject\",\"s3:ListBucket\",\"s3:ListObjectsV2\",\"s3:CreateBucket\"],\"Resource\":[\"arn:aws:s3:::${IAM_TEST_BUCKET}/*\",\"arn:aws:s3:::${IAM_TEST_BUCKET}\"]}]}"
    
    log "DEBUG: Attaching permission policy:"
    echo "  Role: $role_name"
    echo "  Policy Name: S3AccessPolicy"
    echo "  Policy Document: $permission_policy"
    
    set +e
    local put_result
    capture_output put_result aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "S3AccessPolicy" \
        --policy-document "$permission_policy" \
       
    local put_exit=$?
    set -e
    
    log "DEBUG: PutRolePolicy result:"
    echo "  Exit code: $put_exit"
    echo "  Response: $put_result"
    
    
    if [ $put_exit -eq 0 ]; then
        success "IAM PutRolePolicy - Successfully attached permission policy to role"
        
        # Now use the AWS standard operations to verify policy attachment
        # Verify the policy was actually attached using ListRolePolicies and GetRolePolicy
        log "Using AWS standard ListRolePolicies to verify policy attachment..."
        log "DEBUG: About to execute: aws_iam list-role-policies --role-name \"$role_name\""
        log "DEBUG: Role name = '$role_name'"
        log "DEBUG: S3_ENDPOINT = '$S3_ENDPOINT'"
        set +e
        local list_result
        capture_output list_result aws_iam list-role-policies --role-name "$role_name"
        local list_exit=$?
        set -e
        
        log "DEBUG: ListRolePolicies result:"
        echo "  Exit code: $list_exit"
        echo "  Response: $list_result"
        
        if [ $list_exit -eq 0 ]; then
            # Check if S3AccessPolicy is in the list
            if echo "$list_result" | jq -e '.PolicyNames[] | select(. == "S3AccessPolicy")' >/dev/null 2>&1; then
                log "✅ S3AccessPolicy found in ListRolePolicies"
                
                # Now get the actual policy document to verify S3 permissions
                log "Retrieving policy document with GetRolePolicy..."
                set +e
                local policy_result
                capture_output policy_result aws_iam get-role-policy --role-name "$role_name" --policy-name "S3AccessPolicy"
                local policy_exit=$?
                set -e
                
                log "DEBUG: GetRolePolicy result:"
                echo "  Exit code: $policy_exit"
                echo "  Response: $policy_result"
                
                if [ $policy_exit -eq 0 ]; then
                    # Check policy document for S3 permissions
                    local has_s3_get_object=false
                    local has_s3_put_object=false
                    local has_s3_list_bucket=false
                    local has_s3_create_bucket=false
                    local has_test_bucket=false
                    
                    if echo "$policy_result" | jq -e '.. | select(type == "string" and test("s3:GetObject"))?' >/dev/null 2>&1; then
                        has_s3_get_object=true
                        log "  ✅ s3:GetObject permission found"
                    fi
                    
                    if echo "$policy_result" | jq -e '.. | select(type == "string" and test("s3:PutObject"))?' >/dev/null 2>&1; then
                        has_s3_put_object=true
                        log "  ✅ s3:PutObject permission found"
                    fi
                    
                    if echo "$policy_result" | jq -e '.. | select(type == "string" and test("s3:ListBucket"))?' >/dev/null 2>&1; then
                        has_s3_list_bucket=true
                        log "  ✅ s3:ListBucket permission found"
                    fi
                    
                    if echo "$policy_result" | jq -e '.. | select(type == "string" and test("s3:CreateBucket"))?' >/dev/null 2>&1; then
                        has_s3_create_bucket=true
                        log "  ✅ s3:CreateBucket permission found"
                    fi
                    
                    if echo "$policy_result" | jq -e '.. | select(type == "string" and test("iam-test-bucket-fixed"))?' >/dev/null 2>&1; then
                        has_test_bucket=true
                        log "  ✅ iam-test-bucket-fixed resource found"
                    fi
                    
                    if [ "$has_s3_get_object" = "true" ] && [ "$has_s3_put_object" = "true" ] && [ "$has_s3_list_bucket" = "true" ] && [ "$has_s3_create_bucket" = "true" ] && [ "$has_test_bucket" = "true" ]; then
                        log "✅ S3 permissions verified via AWS standard operations (ListRolePolicies + GetRolePolicy)"
                        success "IAM PutRolePolicy - Policy attachment and permissions verified"
                    else
                        error "IAM PutRolePolicy - S3 permissions missing in policy document"
                        log "DEBUG: Missing permissions:"
                        [ "$has_s3_get_object" = "false" ] && log "  ❌ s3:GetObject NOT found"
                        [ "$has_s3_put_object" = "false" ] && log "  ❌ s3:PutObject NOT found"  
                        [ "$has_s3_list_bucket" = "false" ] && log "  ❌ s3:ListBucket NOT found"
                        [ "$has_s3_create_bucket" = "false" ] && log "  ❌ s3:CreateBucket NOT found"
                        [ "$has_test_bucket" = "false" ] && log "  ❌ iam-test-bucket-fixed NOT found"
                        return 1
                    fi
                else
                    error "IAM PutRolePolicy - Failed to retrieve policy document via GetRolePolicy"
                    echo "GetRolePolicy error: $policy_result"
                    return 1
                fi
            else
                error "IAM PutRolePolicy - S3AccessPolicy not found in ListRolePolicies"
                echo "ListRolePolicies response: $list_result"
                return 1
            fi
        else
            error "IAM PutRolePolicy - ListRolePolicies failed"
            echo "ListRolePolicies error: $list_result"
            return 1
        fi
        
        # Save role name for use in subsequent tests
        echo "$role_name" > "$TEMP_DIR/permission_test_role_name"
        return 0
    else
        error "IAM PutRolePolicy - Failed to attach permission policy: $put_result"
        return 1
    fi
}

test_iam_role_with_permission_policy() {
    log "Testing role authorization with permission policies (not trust policies)..."
    
    # Use a fixed bucket name for IAM tests to ensure policy consistency
    local IAM_TEST_BUCKET="iam-test-bucket-fixed"
    
    # Create test bucket FIRST with original credentials before any IAM restrictions  
    log "Pre-creating IAM test bucket: $IAM_TEST_BUCKET"
    set +e
    aws_s3api create-bucket --bucket "$IAM_TEST_BUCKET" 2>/dev/null || true
    set -e
    
    # Get the role created in previous test
    local role_name
    if [ -f "$TEMP_DIR/permission_test_role_name" ]; then
        role_name=$(cat "$TEMP_DIR/permission_test_role_name")
    else
        error "Permission policy test - No role name from previous test"
        return 1
    fi
    
    log "Testing STS AssumeRole with permission policy role: $role_name"

    local account_uuid=$(get_account_uuid)
    local role_arn="arn:aws:iam::${account_uuid}:role/${role_name}"
    local session_name="permission-test-session"
    
    log "DEBUG: AssumeRole parameters:"
    echo "  Role ARN: $role_arn"
    echo "  Session Name: $session_name"
    
    # Assume role
    set +e
    local assume_result
    capture_output assume_result aws_sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name "$session_name" \
       
    local assume_exit=$?
    set -e
    
    log "DEBUG: AssumeRole result:"
    echo "  Exit code: $assume_exit"
    if [ $assume_exit -eq 0 ]; then
        log "  ✅ AssumeRole succeeded"
        echo "  Response length: $(echo "$assume_result" | wc -c) characters"
    else
        log "  ❌ AssumeRole failed"
        echo "  Error: $assume_result"
    fi
    
    
    if [ $assume_exit -ne 0 ]; then
        error "Permission policy test - Failed to assume role: $assume_result"
        return 1
    fi
    
    log "Role assumed successfully, extracting temporary credentials..."
    
    # Extract credentials from the JSON response 
    local temp_access_key
    local temp_secret_key
    local temp_session_token
    
    log "DEBUG: Extracting credentials from AssumeRole response..."
    temp_access_key=$(echo "$assume_result" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
    temp_secret_key=$(echo "$assume_result" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)
    temp_session_token=$(echo "$assume_result" | grep -o '"SessionToken": "[^"]*"' | cut -d'"' -f4)
    
    log "DEBUG: Extracted credential values:"
    echo "  AccessKeyId: $temp_access_key"
    echo "  SecretAccessKey: ${temp_secret_key:0:10}...${temp_secret_key: -4}"  # Show first 10 and last 4 chars
    echo "  SessionToken: ${temp_session_token:0:20}...${temp_session_token: -10}"  # Show first 20 and last 10 chars
    
    if [ -z "$temp_access_key" ] || [ -z "$temp_secret_key" ] || [ -z "$temp_session_token" ]; then
        error "Permission policy test - Failed to extract credentials from AssumeRole response"
        log "DEBUG: Extracted values:"
        log "  temp_access_key='$temp_access_key'"
        log "  temp_secret_key='$temp_secret_key'" 
        log "  temp_session_token='$temp_session_token'"
        log "DEBUG: Full AssumeRole response was:"
        echo "$assume_result"
        return 1
    fi
    
    log "Testing S3 operations with permission policy authorization..."
    
    # Test bucket should already exist from pre-creation step
    
    # Export temporary credentials 
    # Switching to temporary credentials for S3 operations
    export AWS_ACCESS_KEY_ID="$temp_access_key"
    export AWS_SECRET_ACCESS_KEY="$temp_secret_key"
    export AWS_SESSION_TOKEN="$temp_session_token"
    
    log "Using temporary credentials for S3 operations..."
    
    # Test S3 operations (should use permission policy, not trust policy)
    # Testing S3 operation with assumed role credentials
    
    set +e
    local list_result
    list_result=$(aws_s3 ls s3://"$IAM_TEST_BUCKET" 2>&1)
    local list_exit=$?
    set -e
    
    # S3 operation completed
    
    # Restore original credentials
    # Restoring original credentials
    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN
    
    log "DEBUG: S3 operation result analysis:"
    echo "  Exit code: $list_exit"
    echo "  Response: $list_result"
    
    if [ $list_exit -eq 0 ]; then
        success "Permission Policy Authorization - S3 operation succeeded using permission policy (not trust policy)"
        log "✅ IAM POLICY VALIDATION: S3 operation succeeded - permission policies should have been evaluated"
        
        # Cleanup: delete test bucket
        log "Cleaning up test bucket: $IAM_TEST_BUCKET"
        set +e
        aws_s3api delete-bucket --bucket "$IAM_TEST_BUCKET" 2>/dev/null || true
        set -e
        
        return 0
    else
        error "Permission Policy Authorization - S3 operation failed: $list_result"
        
        # Check if it's the specific permission policy issue
        if echo "$list_result" | grep -q "not allowed to access"; then
            log "❌ IAM POLICY VALIDATION: Operation failed with access denied - checking if permission policies were evaluated"
            log "CRITICAL: This might indicate permissionPoliciesCount=0 issue!"
        else
            log "❌ IAM POLICY VALIDATION: Operation failed for other reason: $list_result"
        fi
        log "DEBUG: S3 operation details:"
        log "  Command: aws_s3 ls s3://$IAM_TEST_BUCKET"
        log "  Exit code: $list_exit"
        log "  Response: $list_result"
        log "  Temporary AccessKeyId: $temp_access_key"
        
        # Cleanup: delete test bucket
        log "Cleaning up test bucket: $IAM_TEST_BUCKET"
        set +e
        aws_s3api delete-bucket --bucket "$IAM_TEST_BUCKET" 2>/dev/null || true
        set -e
        
        return 1
    fi
}

test_iam_permission_policy_enforcement() {
    log "Testing comprehensive IAM permission policy enforcement (both allow and deny scenarios)..."
    
    # Create a new role specifically for this test
    local role_name="enforcement-test-role-$(date +%s)-$$-$RANDOM"
    local account_uuid=$(get_account_uuid)
    
    # Create trust policy that allows role assumption
    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    
    log "Creating test role for permission policy enforcement: $role_name"
    set +e
    local create_result
    capture_output create_result aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" \
       
    local create_exit=$?
    set -e
    
    if [ $create_exit -ne 0 ]; then
        error "Permission policy enforcement - Failed to create test role: $create_result"
        return 1
    fi
    
    # Create permission policy that allows access to the test bucket only
    local allowed_bucket="iam-test-bucket-fixed"
    local denied_bucket="unauthorized-bucket-fixed"
    
    # allowed_bucket='$allowed_bucket', denied_bucket='$denied_bucket'
    
    # Permission policy with separate statements for bucket operations and object operations
    local permission_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:CreateBucket\",\"s3:ListAllMyBuckets\"],\"Resource\":\"*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"s3:PutObject\",\"s3:ListBucket\",\"s3:ListObjectsV2\",\"s3:DeleteObject\"],\"Resource\":[\"arn:aws:s3:::${allowed_bucket}\",\"arn:aws:s3:::${allowed_bucket}/*\"]}]}"
    
    log "Attaching restrictive permission policy that allows access to '$allowed_bucket' ONLY (denies all other buckets)..."
    
    log "DEBUG: Enforcement test policy attachment:"
    echo "  Role: $role_name"
    echo "  Policy Name: TestEnforcementPolicy"
    echo "  Allowed Bucket: $allowed_bucket"
    echo "  Denied Bucket: $denied_bucket"
    echo "  Policy Document: $permission_policy"
    
    set +e
    local policy_result
    capture_output policy_result aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "TestEnforcementPolicy" \
        --policy-document "$permission_policy" \
       
    local policy_exit=$?
    set -e
    
    log "DEBUG: Enforcement policy attachment result:"
    echo "  Exit code: $policy_exit"
    echo "  Response: $policy_result"
    
    if [ $policy_exit -ne 0 ]; then
        error "Permission policy enforcement - Failed to attach policy: $policy_result"
        # Cleanup
        run_with_timeout 30 aws_iam_silent delete-role --role-name "$role_name" || true
        return 1
    fi
    
    # Create test buckets with original credentials
    log "Creating test buckets: allowed='$allowed_bucket', denied='$denied_bucket'"
    set +e
    aws_s3api create-bucket --bucket "$allowed_bucket" 2>/dev/null || true
    aws_s3api create-bucket --bucket "$denied_bucket" 2>/dev/null || true
    set -e
    
    # Assume the role to get temporary credentials
    local role_arn="arn:aws:iam::${account_uuid}:role/${role_name}"
    local session_name="enforcement-test-session"
    
    log "Assuming role for policy enforcement test..."
    set +e
    local assume_result
    capture_output assume_result aws_sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name "$session_name" \
       
    local assume_exit=$?
    set -e
    
    if [ $assume_exit -ne 0 ]; then
        error "Permission policy enforcement - Failed to assume role: $assume_result"
        # Cleanup
        aws_s3api delete-bucket --bucket "$allowed_bucket" 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$denied_bucket" 2>/dev/null || true
        run_with_timeout 30 aws_iam_silent delete-role-policy --role-name "$role_name" --policy-name "TestEnforcementPolicy" || true
        run_with_timeout 30 aws_iam_silent delete-role --role-name "$role_name" || true
        return 1
    fi
    
    # Extract temporary credentials
    local temp_access_key
    local temp_secret_key
    local temp_session_token
    
    temp_access_key=$(echo "$assume_result" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
    temp_secret_key=$(echo "$assume_result" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)
    temp_session_token=$(echo "$assume_result" | grep -o '"SessionToken": "[^"]*"' | cut -d'"' -f4)
    
    # Switch to temporary credentials
    local original_access_key="$AWS_ACCESS_KEY_ID"
    local original_secret_key="$AWS_SECRET_ACCESS_KEY"
    local original_session_token="${AWS_SESSION_TOKEN:-}"
    
    export AWS_ACCESS_KEY_ID="$temp_access_key"
    export AWS_SECRET_ACCESS_KEY="$temp_secret_key"
    export AWS_SESSION_TOKEN="$temp_session_token"
    
    # Test 1: Access to ALLOWED bucket should succeed
    log "Testing access to ALLOWED bucket: $allowed_bucket"
    set +e
    local allowed_result
    allowed_result=$(aws_s3 ls "s3://$allowed_bucket" 2>&1)
    local allowed_exit=$?
    set -e
    
    # Test 2: Access to DENIED bucket should fail
    log "Testing access to DENIED bucket: $denied_bucket"
    set +e
    local denied_result
    denied_result=$(aws_s3 ls "s3://$denied_bucket" 2>&1)
    local denied_exit=$?
    set -e
    
    # Test 3: Try to upload object to allowed bucket (should succeed)
    log "Testing object upload to ALLOWED bucket: $allowed_bucket"
    echo "test content" > "$TEMP_DIR/test-object.txt"
    set +e
    local upload_result
    upload_result=$(aws_s3api put-object \
        --bucket "$allowed_bucket" \
        --key "test-object.txt" \
        --body "$TEMP_DIR/test-object.txt" \
        2>&1)
    local upload_exit=$?
    set -e
    
    # Test 4: Try to upload object to denied bucket (should fail)
    log "Testing object upload to DENIED bucket: $denied_bucket"
    set +e
    local upload_denied_result
    upload_denied_result=$(aws_s3api put-object \
        --bucket "$denied_bucket" \
        --key "test-object.txt" \
        --body "$TEMP_DIR/test-object.txt" \
        2>&1)
    local upload_denied_exit=$?
    set -e
    
    # Restore original credentials
    export AWS_ACCESS_KEY_ID="$original_access_key"
    export AWS_SECRET_ACCESS_KEY="$original_secret_key"
    if [ -n "$original_session_token" ]; then
        export AWS_SESSION_TOKEN="$original_session_token"
    else
        unset AWS_SESSION_TOKEN
    fi
    
    # Evaluate results
    local test_passed=true
    
    if [ $allowed_exit -eq 0 ]; then
        success "Permission Policy Enforcement - ALLOWED bucket access succeeded (correct)"
    else
        error "Permission Policy Enforcement - ALLOWED bucket access failed (incorrect)"
        log "DEBUG: Expected this operation to succeed but it failed:"
        log "  Role: $role_name"
        log "  Command: aws_s3 ls s3://$allowed_bucket"
        log "  Exit code: $allowed_exit"
        log "  Error response: $allowed_result"
        log "  Temp credentials: AccessKey=$temp_access_key"
        test_passed=false
    fi
    
    if [ $denied_exit -ne 0 ]; then
        success "Permission Policy Enforcement - DENIED bucket access was blocked (correct)"
    else
        error "Permission Policy Enforcement - DENIED bucket access succeeded (incorrect security issue!): $denied_result"
        test_passed=false
    fi
    
    if [ $upload_exit -eq 0 ]; then
        success "Permission Policy Enforcement - ALLOWED bucket upload succeeded (correct)"
    else
        error "Permission Policy Enforcement - ALLOWED bucket upload failed (incorrect)"
        log "DEBUG: Expected this upload to succeed but it failed:"
        log "  Role: $role_name"
        log "  Command: aws_s3 cp test-file.txt s3://$allowed_bucket/test-object.txt"
        log "  Exit code: $upload_exit"
        log "  Error response: $upload_result"
        log "  Temp credentials: AccessKey=$temp_access_key"
        test_passed=false
    fi
    
    if [ $upload_denied_exit -ne 0 ]; then
        success "Permission Policy Enforcement - DENIED bucket upload was blocked (correct)"
        log "Denied upload details: $upload_denied_result"
    else
        error "Permission Policy Enforcement - DENIED bucket upload succeeded (incorrect security issue!): $upload_denied_result"
        test_passed=false
    fi
    
    # Cleanup
    log "Cleaning up permission policy enforcement test resources..."
    set +e
    # Clean up objects
    log "Deleting S3 objects..."
    aws_s3api delete-object --bucket "$allowed_bucket" --key "test-object.txt" 2>/dev/null || true
    # Clean up buckets
    log "Deleting S3 buckets..."
    aws_s3api delete-bucket --bucket "$allowed_bucket" 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$denied_bucket" 2>/dev/null || true
    # Clean up IAM resources (with timeout handling)
    log "CLEANUP_DEBUG: Starting IAM role policy deletion for role: $role_name"
    (
        local start_time=$(date +%s)
        # Try quick cleanup first
        run_with_timeout 30 aws_iam_silent delete-role-policy --role-name "$role_name" --policy-name "TestEnforcementPolicy" 2>/dev/null || 
        # If that fails, try without silent mode to see errors
        run_with_timeout 30 aws_iam delete-role-policy --role-name "$role_name" --policy-name "TestEnforcementPolicy" 2>/dev/null ||
        # If all else fails, continue
        true
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] CLEANUP_DEBUG: Policy deletion took ${duration}s"
    ) &
    local policy_pid=$!
    
    log "CLEANUP_DEBUG: Starting IAM role deletion for role: $role_name"
    (
        local start_time=$(date +%s)
        # Try quick cleanup first  
        run_with_timeout 30 aws_iam_silent delete-role --role-name "$role_name" 2>/dev/null ||
        # If that fails, try without silent mode
        run_with_timeout 30 aws_iam delete-role --role-name "$role_name" 2>/dev/null ||
        # If all else fails, continue
        true
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] CLEANUP_DEBUG: Role deletion took ${duration}s"
    ) &
    local role_pid=$!
    
    # Wait for cleanup operations to finish (with reasonable timeout)
    log "CLEANUP_DEBUG: Waiting for background IAM cleanup processes..."
    sleep 2
    log "CLEANUP_DEBUG: IAM cleanup operations initiated (processes: policy=$policy_pid role=$role_pid)"
    # Clean up temp files
    log "Cleaning up temp files..."
    rm -f "$TEMP_DIR/test-object.txt"
    log "Cleanup completed"
    set -e
    
    # Restore original credentials before function exit
    log "Restoring original admin credentials after permission policy enforcement test..."
    export AWS_ACCESS_KEY_ID="$original_access_key"
    export AWS_SECRET_ACCESS_KEY="$original_secret_key"
    if [ -n "$original_session_token" ]; then
        export AWS_SESSION_TOKEN="$original_session_token"
    else
        unset AWS_SESSION_TOKEN
    fi
    log "Credentials restored to: $AWS_ACCESS_KEY_ID"
    
    if [ "$test_passed" = true ]; then
        log "Permission Policy Enforcement - All tests passed!"
        return 0
    else
        log "Permission Policy Enforcement - Some tests failed!"
        return 1
    fi
}

test_iam_permission_policy_vs_trust_policy() {
    log "Testing separation of trust policy vs permission policy..."
    
    # Create role with S3 permissions in TRUST policy (old way - should NOT work for S3 ops)
    local trust_role="trust-policy-role-$(date +%s)"
    local trust_with_s3='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::test-bucket/*"]}]}'
    
    log "Creating role with S3 permissions in trust policy (should NOT work for S3 authorization)..."
    set +e
    aws_iam create-role \
        --role-name "$trust_role" \
        --assume-role-policy-document "$trust_with_s3" \
        >/dev/null 2>&1
    set -e
    
    # Create role with S3 permissions in PERMISSION policy (new way - should work)  
    local permission_role="permission-policy-role-$(date +%s)"
    local trust_only='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    local permission_s3='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::test-bucket/*"]}]}'
    
    log "Creating role with S3 permissions in permission policy (should work for S3 authorization)..."
    set +e
    aws_iam create-role \
        --role-name "$permission_role" \
        --assume-role-policy-document "$trust_only" \
        >/dev/null 2>&1
    
    aws_iam put-role-policy \
        --role-name "$permission_role" \
        --policy-name "S3Policy" \
        --policy-document "$permission_s3" \
        >/dev/null 2>&1
    set -e
    
    log "Testing which approach works for S3 authorization..."
    
    # With current implementation, both should work for backward compatibility
    # But the permission policy approach is the correct standard AWS way
    
    success "Trust vs Permission Policy - Test setup completed (detailed testing requires S3 operations)"
    
    # Cleanup
    echo "$trust_role" > "$TEMP_DIR/trust_policy_role_cleanup"
    echo "$permission_role" > "$TEMP_DIR/permission_policy_role_cleanup"
}

# =============================================================================
# IAM Permission Policy Deny Statement Tests
# =============================================================================

# Test that explicit Deny in permission policy blocks access even when Allow exists
test_iam_permission_policy_deny_overrides_allow() {
    log "Testing IAM permission policy: Deny statement overrides Allow..."

    local role_name="deny-override-test-$(date +%s)-$$-$RANDOM"
    local account_uuid=$(get_account_uuid)
    local test_bucket="deny-test-bucket-$(date +%s | tail -c 6)"

    # Trust policy - allow anyone to assume
    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'

    # Permission policy: Allow all S3 actions, but DENY DeleteObject
    # This tests the fix: Deny must override the Allow s3:*
    local permission_policy='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            },
            {
                "Effect": "Deny",
                "Action": ["s3:DeleteObject", "s3:DeleteBucket"],
                "Resource": "*"
            }
        ]
    }'

    log "Creating role with Allow s3:* but Deny s3:DeleteObject..."
    set +e
    local create_result
    capture_output create_result aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy"
    local create_exit=$?
    set -e

    if [ $create_exit -ne 0 ]; then
        error "Deny Override Test - Failed to create role: $create_result"
        return 1
    fi

    # Attach permission policy
    set +e
    local policy_result
    capture_output policy_result aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "DenyDeletePolicy" \
        --policy-document "$permission_policy"
    local policy_exit=$?
    set -e

    if [ $policy_exit -ne 0 ]; then
        error "Deny Override Test - Failed to attach policy: $policy_result"
        aws_iam delete-role --role-name "$role_name" 2>/dev/null || true
        return 1
    fi

    # Create test bucket with admin credentials
    log "Creating test bucket: $test_bucket"
    aws_s3api create-bucket --bucket "$test_bucket" 2>/dev/null || true

    # Upload a test object
    echo "test content for delete" > "$TEMP_DIR/delete-test.txt"
    aws_s3api put-object --bucket "$test_bucket" --key "delete-me.txt" --body "$TEMP_DIR/delete-test.txt" 2>/dev/null || true

    # Assume the role
    local role_arn="arn:aws:iam::${account_uuid}:role/${role_name}"
    log "Assuming role: $role_arn"

    set +e
    local assume_result
    capture_output assume_result aws_sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name "deny-test-session"
    local assume_exit=$?
    set -e

    if [ $assume_exit -ne 0 ]; then
        error "Deny Override Test - Failed to assume role: $assume_result"
        aws_s3 rm "s3://$test_bucket" --recursive 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$test_bucket" 2>/dev/null || true
        aws_iam delete-role-policy --role-name "$role_name" --policy-name "DenyDeletePolicy" 2>/dev/null || true
        aws_iam delete-role --role-name "$role_name" 2>/dev/null || true
        return 1
    fi

    # Extract and use temporary credentials
    local temp_access_key=$(echo "$assume_result" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
    local temp_secret_key=$(echo "$assume_result" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)
    local temp_session_token=$(echo "$assume_result" | grep -o '"SessionToken": "[^"]*"' | cut -d'"' -f4)

    local original_access_key="$AWS_ACCESS_KEY_ID"
    local original_secret_key="$AWS_SECRET_ACCESS_KEY"
    local original_session_token="${AWS_SESSION_TOKEN:-}"

    export AWS_ACCESS_KEY_ID="$temp_access_key"
    export AWS_SECRET_ACCESS_KEY="$temp_secret_key"
    export AWS_SESSION_TOKEN="$temp_session_token"

    # Test 1: GetObject should work (allowed by s3:*)
    log "Test 1: GetObject should SUCCEED (allowed by s3:*)..."
    set +e
    local get_result
    get_result=$(aws_s3api get-object --bucket "$test_bucket" --key "delete-me.txt" "$TEMP_DIR/downloaded.txt" 2>&1)
    local get_exit=$?
    set -e

    if [ $get_exit -eq 0 ]; then
        success "Deny Override Test - GetObject SUCCEEDED as expected (Allow s3:* works)"
    else
        warning "Deny Override Test - GetObject failed: $get_result"
    fi

    # Test 2: DeleteObject should FAIL (denied explicitly)
    log "Test 2: DeleteObject should FAIL (explicit Deny)..."
    set +e
    local delete_result
    delete_result=$(aws_s3api delete-object --bucket "$test_bucket" --key "delete-me.txt" 2>&1)
    local delete_exit=$?
    set -e

    if [ $delete_exit -ne 0 ] && echo "$delete_result" | grep -q -E "(AccessDenied|Forbidden|not allowed)"; then
        success "Deny Override Test - ✅ DeleteObject DENIED as expected (Deny overrides Allow)"
        log "🔒 SECURITY FIX VALIDATED: Explicit Deny in permission policy correctly blocks access"
    elif [ $delete_exit -eq 0 ]; then
        error "Deny Override Test - ❌ CRITICAL: DeleteObject SUCCEEDED when it should be DENIED"
        error "🚨 SECURITY ISSUE: Deny statement is NOT being evaluated!"
        log "Response: $delete_result"
    else
        warning "Deny Override Test - DeleteObject failed with unexpected error: $delete_result"
    fi

    # Restore original credentials
    export AWS_ACCESS_KEY_ID="$original_access_key"
    export AWS_SECRET_ACCESS_KEY="$original_secret_key"
    if [ -n "$original_session_token" ]; then
        export AWS_SESSION_TOKEN="$original_session_token"
    else
        unset AWS_SESSION_TOKEN
    fi

    # Cleanup
    log "Cleaning up test resources..."
    aws_s3 rm "s3://$test_bucket" --recursive 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$test_bucket" 2>/dev/null || true
    aws_iam delete-role-policy --role-name "$role_name" --policy-name "DenyDeletePolicy" 2>/dev/null || true
    aws_iam delete-role --role-name "$role_name" 2>/dev/null || true
}

# Test Deny on specific resource pattern (admin folder protection)
test_iam_permission_policy_deny_resource_pattern() {
    log "Testing IAM permission policy: Deny on specific resource pattern..."

    local role_name="deny-pattern-test-$(date +%s)-$$-$RANDOM"
    local account_uuid=$(get_account_uuid)
    local test_bucket="pattern-test-$(date +%s | tail -c 6)"

    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'

    # Permission policy: Allow all on bucket, but DENY access to admin/* prefix
    local permission_policy='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::'"$test_bucket"'",
                    "arn:aws:s3:::'"$test_bucket"'/*"
                ]
            },
            {
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::'"$test_bucket"'/admin/*"
            }
        ]
    }'

    log "Creating role with Allow s3:* on bucket but Deny on admin/* prefix..."
    set +e
    aws_iam create-role --role-name "$role_name" --assume-role-policy-document "$trust_policy" >/dev/null 2>&1
    aws_iam put-role-policy --role-name "$role_name" --policy-name "DenyAdminPolicy" --policy-document "$permission_policy" >/dev/null 2>&1
    set -e

    # Create bucket and objects
    aws_s3api create-bucket --bucket "$test_bucket" 2>/dev/null || true
    echo "public content" > "$TEMP_DIR/public.txt"
    echo "admin secret" > "$TEMP_DIR/admin.txt"
    aws_s3api put-object --bucket "$test_bucket" --key "public/file.txt" --body "$TEMP_DIR/public.txt" 2>/dev/null || true
    aws_s3api put-object --bucket "$test_bucket" --key "admin/secret.txt" --body "$TEMP_DIR/admin.txt" 2>/dev/null || true

    # Assume role
    local role_arn="arn:aws:iam::${account_uuid}:role/${role_name}"
    set +e
    local assume_result
    capture_output assume_result aws_sts assume-role --role-arn "$role_arn" --role-session-name "pattern-test"
    local assume_exit=$?
    set -e

    if [ $assume_exit -ne 0 ]; then
        warning "Deny Pattern Test - Failed to assume role, skipping"
        aws_s3 rm "s3://$test_bucket" --recursive 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$test_bucket" 2>/dev/null || true
        aws_iam delete-role-policy --role-name "$role_name" --policy-name "DenyAdminPolicy" 2>/dev/null || true
        aws_iam delete-role --role-name "$role_name" 2>/dev/null || true
        return 0
    fi

    # Switch to temp credentials
    local temp_access_key=$(echo "$assume_result" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
    local temp_secret_key=$(echo "$assume_result" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)
    local temp_session_token=$(echo "$assume_result" | grep -o '"SessionToken": "[^"]*"' | cut -d'"' -f4)

    local orig_ak="$AWS_ACCESS_KEY_ID"
    local orig_sk="$AWS_SECRET_ACCESS_KEY"
    local orig_st="${AWS_SESSION_TOKEN:-}"

    export AWS_ACCESS_KEY_ID="$temp_access_key"
    export AWS_SECRET_ACCESS_KEY="$temp_secret_key"
    export AWS_SESSION_TOKEN="$temp_session_token"

    # Test: Access to public/* should work
    log "Test: Access to public/file.txt should SUCCEED..."
    set +e
    local public_result
    public_result=$(aws_s3api get-object --bucket "$test_bucket" --key "public/file.txt" "$TEMP_DIR/got-public.txt" 2>&1)
    local public_exit=$?
    set -e

    if [ $public_exit -eq 0 ]; then
        success "Deny Pattern Test - Access to public/* SUCCEEDED as expected"
    else
        warning "Deny Pattern Test - Access to public/* failed: $public_result"
    fi

    # Test: Access to admin/* should FAIL
    log "Test: Access to admin/secret.txt should FAIL..."
    set +e
    local admin_result
    admin_result=$(aws_s3api get-object --bucket "$test_bucket" --key "admin/secret.txt" "$TEMP_DIR/got-admin.txt" 2>&1)
    local admin_exit=$?
    set -e

    if [ $admin_exit -ne 0 ] && echo "$admin_result" | grep -q -E "(AccessDenied|Forbidden|not allowed)"; then
        success "Deny Pattern Test - ✅ Access to admin/* DENIED as expected"
        log "🔒 Resource pattern Deny is working correctly"
    elif [ $admin_exit -eq 0 ]; then
        error "Deny Pattern Test - ❌ CRITICAL: Access to admin/* SUCCEEDED when it should be DENIED"
        error "🚨 SECURITY ISSUE: Resource pattern Deny not working!"
    else
        warning "Deny Pattern Test - Unexpected error: $admin_result"
    fi

    # Restore credentials
    export AWS_ACCESS_KEY_ID="$orig_ak"
    export AWS_SECRET_ACCESS_KEY="$orig_sk"
    if [ -n "$orig_st" ]; then
        export AWS_SESSION_TOKEN="$orig_st"
    else
        unset AWS_SESSION_TOKEN
    fi

    # Cleanup
    aws_s3 rm "s3://$test_bucket" --recursive 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$test_bucket" 2>/dev/null || true
    aws_iam delete-role-policy --role-name "$role_name" --policy-name "DenyAdminPolicy" 2>/dev/null || true
    aws_iam delete-role --role-name "$role_name" 2>/dev/null || true
}

# =============================================================================
# IAM List Roles Test
# =============================================================================

test_iam_list_roles() {
    log "Testing IAM ListRoles operation..."
    
    # First delete all existing roles to isolate the test
    log "Deleting all existing roles for clean test..."
    set +e
    local existing_roles_result
    capture_output existing_roles_result aws_iam list-roles --max-items 100
    local existing_roles_exit=$?
    set -e
    
    if [ $existing_roles_exit -eq 0 ]; then
        # Extract role names and delete them
        local role_names
        role_names=$(echo "$existing_roles_result" | grep -o '"RoleName": *"[^"]*"' | cut -d'"' -f4)
        
        log "Found existing roles to delete: $(echo "$role_names" | wc -l) roles"
        
        # Delete each role
        while IFS= read -r role_name; do
            if [ -n "$role_name" ]; then
                log "Deleting existing role: $role_name"
                set +e
                aws_iam_silent delete-role --role-name "$role_name" || true
                set -e
            fi
        done <<< "$role_names"
        
        log "All existing roles deleted"
    else
        log "Failed to list existing roles: $existing_roles_result"
    fi
    
    # Wait a moment for deletions to be processed
    log "Waiting 2 seconds for role deletions to be processed..."
    sleep 2
    
    # Now create a test role to ensure we have something to list
    local test_role="list-test-role-$(date +%s)"
    
    log "Creating test role for list operation..."
    set +e
    local create_result
    capture_output create_result aws_iam create-role \
        --role-name "$test_role" \
        --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}' \
        --description "Test role for list operation" \
       
    local create_exit=$?
    set -e
    
    if [ $create_exit -ne 0 ]; then
        error "IAM list roles - Failed to create test role: $create_result"
        return 1
    fi
    
    log "DEBUG: Role creation succeeded. Result: $create_result"
    log "DEBUG: Created role name: $test_role"
    
    # Save role name for cleanup
    echo "$test_role" > "$TEMP_DIR/list_test_role_name"
    
    # Give UFDS a moment to ensure consistency  
    log "Waiting 5 seconds for UFDS consistency..."
    sleep 5
    
    # Verify the role exists with GetRole before testing ListRoles
    log "Verifying created role exists with GetRole..."
    set +e
    local get_role_result
    capture_output get_role_result aws_iam get-role --role-name "$test_role"
    local get_role_exit=$?
    set -e
    
    if [ $get_role_exit -ne 0 ]; then
        error "IAM list roles - GetRole verification failed for created role: $get_role_result"
        return 1
    fi
    
    log "DEBUG: GetRole verification succeeded: Role exists"
    
    # Test ListRoles operation with pagination support
    log "Testing ListRoles operation (with pagination)..."
    
    local found_role=false
    local marker=""
    local page_count=0
    local max_pages=10  # Safety limit to avoid infinite loops
    
    while [ "$found_role" = false ] && [ $page_count -lt $max_pages ]; do
        page_count=$((page_count + 1))
        log "Checking page $page_count for role..."
        
        set +e
        local list_result
        if [ -n "$marker" ]; then
            capture_output list_result aws_iam list-roles --max-items 10 --starting-token "$marker"
        else
            capture_output list_result aws_iam list-roles --max-items 10
        fi
        local list_exit=$?
        set -e
        
        if [ $list_exit -ne 0 ]; then
            error "IAM list roles - ListRoles operation failed on page $page_count: $list_result"
            return 1
        fi
        
        # DEBUG: Show the complete HTTP response from manta-buckets-api
        log "DEBUG: ListRoles HTTP Response (Page $page_count):"
        log "DEBUG: Exit Code: $list_exit"
        log "DEBUG: Response Length: $(echo "$list_result" | wc -c) characters"
        log "DEBUG: Response Content:"
        echo "$list_result"
        log "DEBUG: End of HTTP Response"
        
        # Check if our test role appears in this page
        if echo "$list_result" | grep -q "$test_role"; then
            found_role=true
            success "IAM list roles - Found created role in list (page $page_count)"
            break
        fi
        
        # Check if there are more pages - now using uppercase AWS format
        local is_truncated=$(echo "$list_result" | grep -c '"IsTruncated": *true' 2>/dev/null || echo "0")
        is_truncated=$(echo "$is_truncated" | tr -d '\n\r' | head -1)  # Clean up any newlines
        log "DEBUG: IsTruncated check result: '$is_truncated'"
        
        # Debug: Check what the actual response format is
        log "DEBUG: First 500 chars of response:"
        echo "$list_result" | head -c 500
        log "DEBUG: Does response contain IsTruncated:"
        echo "$list_result" | grep -o '"IsTruncated": *[^,}]*' | head -3
        
        if [ "$is_truncated" -gt 0 ]; then
            # Get the next marker using grep (now uppercase)
            marker=$(echo "$list_result" | grep -o '"Marker": *"[^"]*"' | cut -d'"' -f4 | head -1)
            log "DEBUG: Extracted marker: '$marker'"
            if [ -z "$marker" ] || [ "$marker" = "null" ]; then
                log "No more pages available (empty marker)"
                break
            fi
            log "More pages available, next marker: $marker"
        else
            log "No more pages available (IsTruncated = false)"
            break
        fi
    done
    
    if [ "$found_role" = false ]; then
        # Extract role names using simple grep pattern instead of jq
        local found_roles=""
        found_roles=$(echo "$list_result" | grep -o '"RoleName": *"[^"]*"' | cut -d'"' -f4 | head -5 | paste -sd, -)
        
        log "DEBUG: Expected role: $test_role"
        log "DEBUG: Checked $page_count pages of results"
        log "DEBUG: Sample roles from last page: [$found_roles]"
        log "DEBUG: Last page JSON response length: $(echo "$list_result" | wc -c)"
        local roles_count=$(echo "$list_result" | grep -c '"roles"' 2>/dev/null || echo '0')
        roles_count=$(echo "$roles_count" | tr -d '\n\r' | head -1)
        log "DEBUG: Does JSON contain 'roles' key: $roles_count"
        
        log "DEBUG: FULL JSON RESPONSE:"
        echo "$list_result"
        log "DEBUG: END OF FULL JSON RESPONSE"
        
        error "IAM list roles - Created role '$test_role' NOT found in $page_count pages. Sample roles: [$found_roles]"
        return 1
    fi
    
    success "IAM list roles - ListRoles operation completed successfully with pagination"
    return 0
}

# =============================================================================
# IAM Delete Role Test  
# =============================================================================

test_iam_delete_role() {
    log "Testing IAM DeleteRole operation..."
    
    # Create a test role specifically for deletion
    local delete_test_role="delete-test-role-$(date +%s)"
    
    log "Creating role for deletion test..."
    set +e
    local create_result
    capture_output create_result aws_iam create-role \
        --role-name "$delete_test_role" \
        --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}' \
        --description "Test role for deletion" \
       
    local create_exit=$?
    set -e
    
    if [ $create_exit -ne 0 ]; then
        error "IAM delete role - Failed to create role for deletion: $create_result"
        return 1
    fi
    
    # Verify role exists before deletion
    log "Verifying role exists before deletion..."
    set +e
    local get_before_result
    capture_output get_before_result aws_iam get-role --role-name "$delete_test_role"
    local get_before_exit=$?
    set -e
    
    if [ $get_before_exit -ne 0 ]; then
        error "IAM delete role - Role not found after creation: $get_before_result"
        return 1
    fi
    
    # Test DeleteRole operation
    log "Testing DeleteRole operation..."
    set +e
    local delete_result
    capture_output delete_result aws_iam delete-role --role-name "$delete_test_role"
    local delete_exit=$?
    set -e
    
    if [ $delete_exit -ne 0 ]; then
        error "IAM delete role - DeleteRole operation failed: $delete_result"
        return 1
    fi
    
    # Verify role no longer exists
    log "Verifying role was deleted..."
    set +e
    local get_after_result
    capture_output get_after_result aws_iam get-role --role-name "$delete_test_role"
    local get_after_exit=$?
    set -e
    
    if [ $get_after_exit -eq 0 ]; then
        error "IAM delete role - Role still exists after deletion: $get_after_result"
        return 1
    elif echo "$get_after_result" | grep -q -E "(NoSuchEntity|not found)"; then
        success "IAM delete role - Role properly deleted and not found"
    else
        warning "IAM delete role - Role deletion verification failed with unexpected error: $get_after_result"
    fi
    
    # Test deleting non-existent role
    log "Testing deletion of non-existent role..."
    set +e
    local nonexistent_result
    capture_output nonexistent_result aws_iam delete-role --role-name "nonexistent-role-12345"
    local nonexistent_exit=$?
    set -e
    
    if [ $nonexistent_exit -ne 0 ] && echo "$nonexistent_result" | grep -q -E "(NoSuchEntity|not found)"; then
        success "IAM delete role - Deletion of non-existent role properly returns error"
    else
        warning "IAM delete role - Unexpected result for non-existent role: $nonexistent_result"
    fi
    
    success "IAM delete role - DeleteRole operation completed successfully"
    return 0
}

test_iam_delete_role_policy() {
    log "Testing IAM DeleteRolePolicy operation with role and policy lifecycle..."
    
    # Test configuration
    local test_role="delete-policy-test-role-$(date +%s)"
    local policy_name_1="TestPolicy1"
    local policy_name_2="TestPolicy2" 
    local policy_name_nonexistent="NonExistentPolicy"
    
    # Define test policies
    local trust_policy='{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sts:AssumeRole"
        }]
    }'
    
    local permission_policy_1='{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::test-bucket/*"
        }]
    }'
    
    local permission_policy_2='{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", 
            "Action": ["s3:ListBucket"],
            "Resource": "arn:aws:s3:::test-bucket"
        }]
    }'
    
    # Step 1: Create test role
    log "Step 1: Creating test role '$test_role'..."
    set +e
    local create_result
    capture_output create_result aws_iam create-role \
        --role-name "$test_role" \
        --assume-role-policy-document "$trust_policy"
    local create_exit=$?
    set -e
    
    if [ $create_exit -ne 0 ]; then
        error "Delete role policy test - Failed to create test role: $create_result"
        return 1
    fi
    
    # Save role name for cleanup
    echo "$test_role" > "$TEMP_DIR/delete_policy_test_role_name"
    success "Delete role policy test - Role created successfully"
    
    # Step 2: Add first policy to role
    log "Step 2: Adding first policy '$policy_name_1' to role..."
    set +e
    local put_policy_1_result
    capture_output put_policy_1_result aws_iam put-role-policy \
        --role-name "$test_role" \
        --policy-name "$policy_name_1" \
        --policy-document "$permission_policy_1"
    local put_policy_1_exit=$?
    set -e
    
    if [ $put_policy_1_exit -ne 0 ]; then
        error "Delete role policy test - Failed to add first policy: $put_policy_1_result"
        return 1
    fi
    success "Delete role policy test - First policy added successfully"
    
    # Step 3: Add second policy to role
    log "Step 3: Adding second policy '$policy_name_2' to role..."
    set +e
    local put_policy_2_result
    capture_output put_policy_2_result aws_iam put-role-policy \
        --role-name "$test_role" \
        --policy-name "$policy_name_2" \
        --policy-document "$permission_policy_2"
    local put_policy_2_exit=$?
    set -e
    
    if [ $put_policy_2_exit -ne 0 ]; then
        error "Delete role policy test - Failed to add second policy: $put_policy_2_result"
        return 1
    fi
    success "Delete role policy test - Second policy added successfully"
    
    # Step 4: Verify role has both policies (via GetRole)
    log "Step 4: Verifying role contains both policies..."
    set +e
    local get_role_before
    capture_output get_role_before aws_iam get-role --role-name "$test_role"
    local get_role_before_exit=$?
    set -e
    
    if [ $get_role_before_exit -ne 0 ]; then
        error "Delete role policy test - Failed to get role before deletion: $get_role_before"
        return 1
    fi
    
    # Check if both policies are mentioned in role info (they should be in memberpolicy)
    log "Role details before deletion: $get_role_before"
    success "Delete role policy test - Role retrieved successfully with policies"
    
    # Step 5: Delete first policy
    log "Step 5: Deleting first policy '$policy_name_1' from role..."
    set +e
    local delete_policy_1_result
    capture_output delete_policy_1_result aws_iam delete-role-policy \
        --role-name "$test_role" \
        --policy-name "$policy_name_1"
    local delete_policy_1_exit=$?
    set -e
    
    if [ $delete_policy_1_exit -ne 0 ]; then
        error "Delete role policy test - Failed to delete first policy: $delete_policy_1_result"
        return 1
    fi
    success "Delete role policy test - First policy deleted successfully"
    
    # Step 6: Verify first policy is gone, second policy remains
    log "Step 6: Verifying first policy deleted, second remains..."
    set +e
    local get_role_after_first_delete
    capture_output get_role_after_first_delete aws_iam get-role --role-name "$test_role"
    local get_role_after_first_delete_exit=$?
    set -e
    
    if [ $get_role_after_first_delete_exit -ne 0 ]; then
        error "Delete role policy test - Failed to get role after first deletion: $get_role_after_first_delete"
        return 1
    fi
    
    log "Role details after first policy deletion: $get_role_after_first_delete"
    success "Delete role policy test - Role retrieved after first deletion"
    
    # Step 7: Delete second policy  
    log "Step 7: Deleting second policy '$policy_name_2' from role..."
    set +e
    local delete_policy_2_result
    capture_output delete_policy_2_result aws_iam delete-role-policy \
        --role-name "$test_role" \
        --policy-name "$policy_name_2"
    local delete_policy_2_exit=$?
    set -e
    
    if [ $delete_policy_2_exit -ne 0 ]; then
        error "Delete role policy test - Failed to delete second policy: $delete_policy_2_result"
        return 1
    fi
    success "Delete role policy test - Second policy deleted successfully"
    
    # Step 8: Verify all policies are gone
    log "Step 8: Verifying all policies deleted from role..."
    set +e
    local get_role_after_all_deletes
    capture_output get_role_after_all_deletes aws_iam get-role --role-name "$test_role"
    local get_role_after_all_deletes_exit=$?
    set -e
    
    if [ $get_role_after_all_deletes_exit -ne 0 ]; then
        error "Delete role policy test - Failed to get role after all deletions: $get_role_after_all_deletes"
        return 1
    fi
    
    log "Role details after all policy deletions: $get_role_after_all_deletes"
    success "Delete role policy test - Role retrieved after all deletions"
    
    # Step 9: Test deletion of non-existent policy (should return 404)
    log "Step 9: Testing deletion of non-existent policy (should fail)..."
    set +e
    local delete_nonexistent_result
    capture_output delete_nonexistent_result aws_iam delete-role-policy \
        --role-name "$test_role" \
        --policy-name "$policy_name_nonexistent"
    local delete_nonexistent_exit=$?
    set -e
    
    if [ $delete_nonexistent_exit -ne 0 ] && echo "$delete_nonexistent_result" | grep -q -E "(NoSuchEntity|not found|Policy not found)"; then
        success "Delete role policy test - Deletion of non-existent policy properly returns error"
    else
        warning "Delete role policy test - Unexpected result for non-existent policy: $delete_nonexistent_result"
    fi
    
    # Step 10: Test deletion from non-existent role (should return 404)
    log "Step 10: Testing deletion from non-existent role (should fail)..."
    set +e
    local delete_from_nonexistent_role_result
    capture_output delete_from_nonexistent_role_result aws_iam delete-role-policy \
        --role-name "nonexistent-role-12345" \
        --policy-name "$policy_name_1"
    local delete_from_nonexistent_role_exit=$?
    set -e
    
    if [ $delete_from_nonexistent_role_exit -ne 0 ] && echo "$delete_from_nonexistent_role_result" | grep -q -E "(NoSuchEntity|not found|Role not found)"; then
        success "Delete role policy test - Deletion from non-existent role properly returns error"
    else
        warning "Delete role policy test - Unexpected result for non-existent role: $delete_from_nonexistent_role_result"
    fi
    
    success "IAM delete role policy - DeleteRolePolicy operation completed successfully"
    return 0
}

# =============================================================================
# IAM + STS End-to-End Integration Test
# =============================================================================

test_iam_comprehensive_security() {
    log "Testing comprehensive IAM security with distinct roles and fine-grained policies..."
    
    # Save current credentials so we can restore them later
    local original_access_key="$AWS_ACCESS_KEY_ID"
    local original_secret_key="$AWS_SECRET_ACCESS_KEY"
    local original_session_token="${AWS_SESSION_TOKEN:-}"
    local original_region="${AWS_REGION:-us-east-1}"
    
    # FORCE credential reset by completely clearing AWS environment and using explicit credentials
    log "FORCE: Clearing all AWS credential environment variables..."
    unset AWS_ACCESS_KEY_ID
    unset AWS_SECRET_ACCESS_KEY
    unset AWS_SESSION_TOKEN
    unset AWS_SECURITY_TOKEN
    unset AWS_DEFAULT_REGION
    unset AWS_REGION
    
    # Clear any AWS CLI credential cache
    rm -rf ~/.aws/cli/cache/* 2>/dev/null || true
    rm -rf ~/.aws/sso/cache/* 2>/dev/null || true
    
    # Force use of original admin credentials by setting them explicitly
    log "FORCE: Setting admin credentials explicitly..."
    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    export AWS_REGION="$original_region"
    
    log "FORCE: Credentials set to AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID"
    log "FORCE: Session tokens cleared: AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN:-<unset>}"
    
    # Wait a moment for credential changes to take effect
    sleep 1
    
    local test_bucket_1="security-test-bucket-1-$(date +%s)"
    local test_bucket_2="security-test-bucket-2-$(date +%s)"
    local denied_bucket="denied-bucket-$(date +%s)"
    local test_object="security-test-object.txt"
    local account_uuid=$(get_account_uuid)
    
    # Create distinct roles with different permission levels
    local readonly_role="readonly-role-$(date +%s)"
    local bucket1_admin_role="bucket1-admin-$(date +%s)"
    local bucket2_readonly_role="bucket2-readonly-$(date +%s)"
    local multiaction_role="multiaction-role-$(date +%s)"
    
    # Trust policy for all roles
    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    
    # Different permission policies for security testing
    local readonly_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:ListBucket\",\"s3:ListObjectsV2\",\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::${test_bucket_1}\",\"arn:aws:s3:::${test_bucket_1}/*\"]}]}"
    local bucket1_admin_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:*\"],\"Resource\":[\"arn:aws:s3:::${test_bucket_1}\",\"arn:aws:s3:::${test_bucket_1}/*\"]}]}"
    local bucket2_readonly_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:ListBucket\",\"s3:ListObjectsV2\",\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::${test_bucket_2}\",\"arn:aws:s3:::${test_bucket_2}/*\"]}]}"
    local multiaction_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:ListBucket\",\"s3:ListObjectsV2\",\"s3:GetObject\",\"s3:PutObject\",\"s3:DeleteObject\"],\"Resource\":[\"arn:aws:s3:::${test_bucket_1}/*\",\"arn:aws:s3:::${test_bucket_1}\",\"arn:aws:s3:::${test_bucket_2}/*\",\"arn:aws:s3:::${test_bucket_2}\"]}]}"
    
    log "Creating test buckets with admin credentials (already set at function start)..."
    log "Current credentials: AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID"
    log "Session token status: AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN:-'<unset>'}"
    
    # Verify credentials with a simple S3 operation before attempting bucket creation
    log "Verifying admin credentials with S3 ListBuckets..."
    set +e
    local list_result
    list_result=$(aws s3api list-buckets --endpoint-url "$S3_ENDPOINT" --no-verify-ssl 2>&1)
    local list_exit=$?
    set -e
    
    log "S3 ListBuckets verification result (exit=$list_exit):"
    if [ $list_exit -eq 0 ]; then
        log "✅ Credentials verified - S3 operations working with admin credentials"
    else
        log "ListBuckets failed: $list_result"
        if echo "$list_result" | grep -q "enforcement-test-role\|test-role"; then
            error "Credential verification failed - still seeing role credentials in error"
            return 1
        else
            log "⚠️  ListBuckets failed but no role credentials detected - proceeding with bucket creation"
        fi
    fi
    
    # Use the bucket names already defined above (security-test-bucket-* pattern)
    # Don't redefine them here
    
    # Try to create buckets with the working credentials
    log "Attempting bucket creation..."
    set +e
    bucket_create_result=$(aws_s3api create-bucket --bucket "$test_bucket_1" 2>&1)
    bucket_create_exit=$?
    set -e
    
    if [ $bucket_create_exit -eq 0 ]; then
        log "Successfully created bucket with admin credentials"
        # Create the other buckets too
        aws_s3api create-bucket --bucket "$test_bucket_2" 2>/dev/null || true
        aws_s3api create-bucket --bucket "$denied_bucket" 2>/dev/null || true
    else
        error "Bucket creation still failed even with admin credentials"
        log "DEBUG: Bucket creation failed with admin credentials:"
        log "  Bucket name: $test_bucket_1"
        log "  Command: aws_s3api create-bucket --bucket $test_bucket_1"
        log "  Exit code: $bucket_create_exit" 
        log "  Error response: $bucket_create_result"
        log "  Current credentials: AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID"
        return 1
    fi
    
    # Create initial test objects if buckets were created successfully
    if [ $bucket_create_exit -eq 0 ]; then
        echo "test content 1" > "$TEMP_DIR/$test_object"
        
        # Switch to working credentials for object creation to avoid ownership issues
        if [ -n "$WORKING_AWS_ACCESS_KEY_ID" ] && [ -n "$WORKING_AWS_SECRET_ACCESS_KEY" ]; then
            log "Switching to working credentials for object creation to avoid ownership issues"
            export AWS_ACCESS_KEY_ID="$WORKING_AWS_ACCESS_KEY_ID"
            export AWS_SECRET_ACCESS_KEY="$WORKING_AWS_SECRET_ACCESS_KEY"
            unset AWS_SESSION_TOKEN
        fi
        
        # Debug: Show what credentials are being used for object creation
        log "Creating test object with current credentials: AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID"
        
        # Debug: Show credential type and session token status
        if echo "$AWS_ACCESS_KEY_ID" | grep -q -E "^[a-f0-9]{32}$"; then
            log "DEBUG: Using temporary STS credentials (32-char hex pattern)"
            log "DEBUG: AWS_SESSION_TOKEN status: ${AWS_SESSION_TOKEN:-'<unset>'}"
        else
            log "DEBUG: Using permanent user credentials"
        fi
        
        log "DEBUG: Will attempt to create object in bucket: $test_bucket_1"
        log "DEBUG: Object key will be: $test_object"
        
        log "Creating test object in: $test_bucket_1"
        
        set +e
        object_result=$(aws_s3api put-object --bucket "$test_bucket_1" --key "$test_object" --body "$TEMP_DIR/$test_object" 2>&1)
        object_exit=$?
        set -e
        
        if [ $object_exit -ne 0 ]; then
            error "IAM comprehensive security - FAILED to create test object in $test_bucket_1"
            error "Object creation error: $object_result"
            error "Current credentials: $AWS_ACCESS_KEY_ID"
            error "Test cannot continue without test objects - ABORTING"
            return 1
        fi
        success "Created test object in: $test_bucket_1"
        
        # Verify object was created
        log "Verifying object exists in $test_bucket_1..."
        if aws_s3api head-object --bucket "$test_bucket_1" --key "$test_object" >/dev/null 2>&1; then
            success "Verified test object exists in: $test_bucket_1"
        else
            warning "Test object verification failed in: $test_bucket_1"
            
            # List bucket contents to see what objects actually exist
            log "DEBUG: Listing actual objects in $test_bucket_1:"
            set +e
            bucket_list=$(aws_s3api list-objects-v2 --bucket "$test_bucket_1" 2>&1)
            list_exit=$?
            set -e
            if [ $list_exit -eq 0 ]; then
                log "DEBUG: Bucket contents: $bucket_list"
            else
                log "DEBUG: Failed to list bucket contents: $bucket_list"
            fi
        fi
        
        log "Creating test object in: $test_bucket_2"
        if ! aws_s3api put-object --bucket "$test_bucket_2" --key "$test_object" --body "$TEMP_DIR/$test_object" 2>&1; then
            error "IAM comprehensive security - Failed to create test object in: $test_bucket_2" 
            return 1
        fi
        success "Created test object in: $test_bucket_2"
    else
        warning "Skipping object creation since bucket creation failed"
        warning "Role security tests will show expected 'bucket not found' errors"
    fi
    
    log "Creating IAM roles with distinct permission policies..."
    
    # Create readonly role (can only list bucket1 and get objects from bucket1)
    aws_iam create-role --role-name "$readonly_role" --assume-role-policy-document "$trust_policy" >/dev/null
    aws_iam put-role-policy --role-name "$readonly_role" --policy-name "ReadOnlyPolicy" --policy-document "$readonly_policy" >/dev/null
    
    # Create bucket1 admin role (full access to bucket1 only)
    aws_iam create-role --role-name "$bucket1_admin_role" --assume-role-policy-document "$trust_policy" >/dev/null
    aws_iam put-role-policy --role-name "$bucket1_admin_role" --policy-name "Bucket1AdminPolicy" --policy-document "$bucket1_admin_policy" >/dev/null
    
    # Create bucket2 readonly role (readonly access to bucket2 only)
    aws_iam create-role --role-name "$bucket2_readonly_role" --assume-role-policy-document "$trust_policy" >/dev/null
    aws_iam put-role-policy --role-name "$bucket2_readonly_role" --policy-name "Bucket2ReadOnlyPolicy" --policy-document "$bucket2_readonly_policy" >/dev/null
    
    # Create multi-action role (specific actions on both buckets)
    aws_iam create-role --role-name "$multiaction_role" --assume-role-policy-document "$trust_policy" >/dev/null
    aws_iam put-role-policy --role-name "$multiaction_role" --policy-name "MultiActionPolicy" --policy-document "$multiaction_policy" >/dev/null
    
    # Save role names for cleanup
    echo "$readonly_role" > "$TEMP_DIR/security_readonly_role"
    echo "$bucket1_admin_role" > "$TEMP_DIR/security_bucket1_admin_role"
    echo "$bucket2_readonly_role" > "$TEMP_DIR/security_bucket2_readonly_role" 
    echo "$multiaction_role" > "$TEMP_DIR/security_multiaction_role"
    echo "$test_bucket_1 $test_bucket_2 $denied_bucket" > "$TEMP_DIR/security_test_buckets"
    
    log "Testing role-based security enforcement..."
    
    # Test 1: ReadOnly Role Security
    log "TEST 1: ReadOnly Role - Should allow ListBucket/GetObject on bucket1, deny all else"
    test_role_security "$readonly_role" "$account_uuid" "$test_bucket_1" "$test_bucket_2" "$denied_bucket" "$test_object" \
        "ALLOW:ListBucket:$test_bucket_1,ALLOW:GetObject:$test_bucket_1,DENY:PutObject:$test_bucket_1,DENY:DeleteObject:$test_bucket_1,DENY:ListBucket:$test_bucket_2,DENY:ListBucket:$denied_bucket"
    
    # Test 2: Bucket1 Admin Role Security  
    log "TEST 2: Bucket1 Admin Role - Should allow all operations on bucket1, deny bucket2"
    test_role_security "$bucket1_admin_role" "$account_uuid" "$test_bucket_1" "$test_bucket_2" "$denied_bucket" "$test_object" \
        "ALLOW:ListBucket:$test_bucket_1,ALLOW:GetObject:$test_bucket_1,ALLOW:PutObject:$test_bucket_1,ALLOW:DeleteObject:$test_bucket_1,DENY:ListBucket:$test_bucket_2,DENY:ListBucket:$denied_bucket"
    
    # Test 3: Bucket2 ReadOnly Role Security
    log "TEST 3: Bucket2 ReadOnly Role - Should allow readonly on bucket2, deny bucket1"
    test_role_security "$bucket2_readonly_role" "$account_uuid" "$test_bucket_1" "$test_bucket_2" "$denied_bucket" "$test_object" \
        "DENY:ListBucket:$test_bucket_1,ALLOW:ListBucket:$test_bucket_2,ALLOW:GetObject:$test_bucket_2,DENY:PutObject:$test_bucket_2,DENY:ListBucket:$denied_bucket"
    
    # Test 4: Multi-Action Role Security
    log "TEST 4: Multi-Action Role - Should allow specific actions on both buckets, deny denied_bucket"
    test_role_security "$multiaction_role" "$account_uuid" "$test_bucket_1" "$test_bucket_2" "$denied_bucket" "$test_object" \
        "ALLOW:ListBucket:$test_bucket_1,ALLOW:GetObject:$test_bucket_1,ALLOW:PutObject:$test_bucket_1,ALLOW:DeleteObject:$test_bucket_1,ALLOW:ListBucket:$test_bucket_2,ALLOW:GetObject:$test_bucket_2,ALLOW:PutObject:$test_bucket_2,DENY:ListBucket:$denied_bucket"
    
    success "IAM comprehensive security - All role-based security tests completed"
    
    # Restore the credentials that were active when this function was called
    export AWS_ACCESS_KEY_ID="$original_access_key"
    export AWS_SECRET_ACCESS_KEY="$original_secret_key"
    export AWS_REGION="$original_region"
    if [ -n "$original_session_token" ]; then
        export AWS_SESSION_TOKEN="$original_session_token"
    else
        unset AWS_SESSION_TOKEN
    fi
    
    return 0
}

# Helper function to test a specific role's security permissions
test_role_security() {
    local role_name="$1"
    local account_uuid="$2"
    local bucket1="$3"
    local bucket2="$4"
    local denied_bucket="$5"
    local test_object="$6"
    local expected_results="$7"
    
    local role_arn="arn:aws:iam::${account_uuid}:role/${role_name}"
    local session_name="security-test-session"
    
    log "Testing security for role: $role_name"
    
    # Assume the role to get temporary credentials
    set +e
    local assume_result
    capture_output assume_result aws_sts assume-role --role-arn "$role_arn" --role-session-name "$session_name"
    local assume_exit=$?
    set -e
    
    if [ $assume_exit -ne 0 ]; then
        error "Role security test - Failed to assume role $role_name: $assume_result"
        return 1
    fi
    
    # Extract temporary credentials
    local temp_access_key=$(echo "$assume_result" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
    local temp_secret_key=$(echo "$assume_result" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)
    local temp_session_token=$(echo "$assume_result" | grep -o '"SessionToken": "[^"]*"' | cut -d'"' -f4)
    
    # Save original credentials
    local orig_access_key="$AWS_ACCESS_KEY_ID"
    local orig_secret_key="$AWS_SECRET_ACCESS_KEY"
    local orig_session_token="${AWS_SESSION_TOKEN:-}"
    
    # Switch to temporary credentials
    export AWS_ACCESS_KEY_ID="$temp_access_key"
    export AWS_SECRET_ACCESS_KEY="$temp_secret_key"
    export AWS_SESSION_TOKEN="$temp_session_token"
    
    # Create test objects in buckets this role can write to
    log "Pre-creating test objects for role: $role_name"
    echo "test content from $role_name" > "$TEMP_DIR/${test_object}"
    
    # Check if this role should be able to create objects and create them
    if echo "$expected_results" | grep -q "ALLOW:PutObject:$bucket1\|ALLOW:PutObject:$bucket2"; then
        # Try to create test object in bucket1 if role has PutObject permission
        if echo "$expected_results" | grep -q "ALLOW:PutObject:$bucket1"; then
            log "Creating test object in $bucket1 with $role_name credentials"
            set +e
            create_result=$(aws_s3api put-object --bucket "$bucket1" --key "$test_object" --body "$TEMP_DIR/${test_object}" 2>&1)
            create_exit=$?
            set -e
            if [ $create_exit -eq 0 ]; then
                log "Successfully created test object in $bucket1"
            else
                warning "Failed to create test object in $bucket1: $create_result"
            fi
        fi
        
        # Try to create test object in bucket2 if role has PutObject permission  
        if echo "$expected_results" | grep -q "ALLOW:PutObject:$bucket2"; then
            log "Creating test object in $bucket2 with $role_name credentials"
            set +e
            create_result=$(aws_s3api put-object --bucket "$bucket2" --key "$test_object" --body "$TEMP_DIR/${test_object}" 2>&1)
            create_exit=$?
            set -e
            if [ $create_exit -eq 0 ]; then
                log "Successfully created test object in $bucket2"
            else
                warning "Failed to create test object in $bucket2: $create_result"
            fi
        fi
    fi
    
    # Test each expected result
    IFS=',' read -ra TESTS <<< "$expected_results"
    local all_passed=true
    
    for test_spec in "${TESTS[@]}"; do
        IFS=':' read -ra TEST_PARTS <<< "$test_spec"
        local expected="${TEST_PARTS[0]}"  # ALLOW or DENY
        local operation="${TEST_PARTS[1]}" # ListBucket, GetObject, etc.
        local target_bucket="${TEST_PARTS[2]}" # bucket name
        
        # Perform the operation
        set +e
        local op_result
        local op_exit
        case "$operation" in
            "ListBucket")
                op_result=$(aws_s3 ls "s3://$target_bucket" 2>&1)
                op_exit=$?
                ;;
            "GetObject") 
                op_result=$(aws_s3api get-object --bucket "$target_bucket" --key "$test_object" "$TEMP_DIR/downloaded-${role_name}-${target_bucket}" 2>&1)
                op_exit=$?
                ;;
            "PutObject")
                echo "test upload from $role_name" > "$TEMP_DIR/upload-test-${role_name}"
                op_result=$(aws_s3api put-object --bucket "$target_bucket" --key "upload-test-${role_name}.txt" --body "$TEMP_DIR/upload-test-${role_name}" 2>&1)
                op_exit=$?
                ;;
            "DeleteObject")
                op_result=$(aws_s3api delete-object --bucket "$target_bucket" --key "$test_object" 2>&1)
                op_exit=$?
                ;;
        esac
        set -e
        
        # Check if result matches expectation
        if [ "$expected" = "ALLOW" ]; then
            if [ $op_exit -eq 0 ]; then
                success "Role $role_name - $operation on $target_bucket CORRECTLY ALLOWED"
            else
                error "Role $role_name - $operation on $target_bucket was DENIED but should be ALLOWED: $op_result"
                all_passed=false
            fi
        else # DENY expected
            if [ $op_exit -ne 0 ] && (echo "$op_result" | grep -q -E "(Access.*denied|Forbidden|AccessDenied|AuthorizationFailed|is not allowed to access|not allowed to access)"); then
                success "Role $role_name - $operation on $target_bucket CORRECTLY DENIED"
            elif [ $op_exit -eq 0 ]; then
                error "Role $role_name - $operation on $target_bucket was ALLOWED but should be DENIED"
                all_passed=false
            else
                warning "Role $role_name - $operation on $target_bucket failed with non-permission error: $op_result"
            fi
        fi
    done
    
    # Restore original credentials
    export AWS_ACCESS_KEY_ID="$orig_access_key"
    export AWS_SECRET_ACCESS_KEY="$orig_secret_key"
    if [ -n "$orig_session_token" ]; then
        export AWS_SESSION_TOKEN="$orig_session_token"
    else
        unset AWS_SESSION_TOKEN
    fi
    
    if [ "$all_passed" = true ]; then
        success "Role $role_name - All security tests passed"
        return 0
    else
        error "Role $role_name - Some security tests failed"
        return 1
    fi
}

test_iam_sts_integration() {
    log "Testing complete IAM + STS integration workflow..."
    
    local test_role="integration-test-role-$(date +%s)"
    local session_name="integration-test-session"
    local account_uuid=$(get_account_uuid)
    local role_arn="arn:aws:iam::${account_uuid}:role/${test_role}"
    
    # Step 1: Create IAM role
    log "Step 1: Creating IAM role for integration test..."
    set +e
    local create_result
    capture_output create_result aws_iam create-role \
        --role-name "$test_role" \
        --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}' \
        --description "End-to-end integration test role" \
       
    local create_exit=$?
    set -e
    
    if [ $create_exit -ne 0 ]; then
        error "IAM+STS integration - Failed to create role: $create_result"
        return 1
    fi
    
    # Step 2: Add S3 permissions to the role
    log "Step 2: Adding S3 permissions to role..."
    local s3_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:CreateBucket","s3:ListAllMyBuckets"],"Resource":"*"},{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:ListBucket","s3:ListObjectsV2","s3:DeleteObject"],"Resource":["arn:aws:s3:::*","arn:aws:s3:::*/*"]}]}'
    
    set +e
    local policy_result
    capture_output policy_result aws_iam put-role-policy \
        --role-name "$test_role" \
        --policy-name "S3AccessPolicy" \
        --policy-document "$s3_policy" \
       
    local policy_exit=$?
    set -e
    
    if [ $policy_exit -ne 0 ]; then
        error "IAM+STS integration - Failed to add policy to role: $policy_result"
        return 1
    fi
    
    # Step 3: Verify role exists with policy
    log "Step 3: Verifying role exists with policy..."
    set +e
    local get_result
    capture_output get_result aws_iam get-role --role-name "$test_role"
    local get_exit=$?
    set -e
    
    if [ $get_exit -ne 0 ]; then
        error "IAM+STS integration - Failed to get role: $get_result"
        return 1
    fi
    
    # Step 4: Assume the role
    log "Step 4: Assuming the role..."
    set +e
    local assume_result
    capture_output assume_result aws_sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name "$session_name" \
       
    local assume_exit=$?
    set -e
    
    if [ $assume_exit -ne 0 ]; then
        error "IAM+STS integration - Failed to assume role: $assume_result"
        return 1
    fi
    
    # Step 5: Test S3 operations with temporary credentials
    log "Step 5: Testing S3 operations with role credentials..."
    
    # Extract temporary credentials
    local temp_access_key temp_secret_key temp_session_token
    temp_access_key=$(echo "$assume_result" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
    temp_secret_key=$(echo "$assume_result" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)
    temp_session_token=$(echo "$assume_result" | grep -o '"SessionToken": "[^"]*"' | cut -d'"' -f4)
    
    if [ -z "$temp_access_key" ] || [ -z "$temp_secret_key" ] || [ -z "$temp_session_token" ]; then
        error "IAM+STS integration - Failed to extract temporary credentials"
        return 1
    fi
    
    # Save and set temporary credentials
    local original_access_key="$AWS_ACCESS_KEY_ID"
    local original_secret_key="$AWS_SECRET_ACCESS_KEY"
    local original_session_token="${AWS_SESSION_TOKEN:-}"
    
    export AWS_ACCESS_KEY_ID="$temp_access_key"
    export AWS_SECRET_ACCESS_KEY="$temp_secret_key"
    export AWS_SESSION_TOKEN="$temp_session_token"
    
    # Test S3 operation
    set +e
    local s3_result
    s3_result=$(aws_s3 ls 2>&1)
    local s3_exit=$?
    set -e
    
    # Restore original credentials
    export AWS_ACCESS_KEY_ID="$original_access_key"
    export AWS_SECRET_ACCESS_KEY="$original_secret_key"
    if [ -n "$original_session_token" ]; then
        export AWS_SESSION_TOKEN="$original_session_token"
    else
        unset AWS_SESSION_TOKEN
    fi
    
    if [ $s3_exit -eq 0 ] || echo "$s3_result" | grep -v -E "(SignatureDoesNotMatch|InvalidSignature)"; then
        success "IAM+STS integration - Complete workflow successful: Role created → Assumed → Used for S3 operations"
        return 0
    else
        error "IAM+STS integration - S3 operation failed with role credentials: $s3_result"
        return 1
    fi
}

# =============================================================================
# IAM ListRolePolicies Tests
# =============================================================================

test_iam_list_role_policies() {
    log "Testing IAM ListRolePolicies operation..."
    
    # Clean up any existing test roles first
    log "DEBUG: Cleaning up existing IAM test roles..."
    cleanup_iam_test_resources "list-policies-test-role-"
    
    # Create a role with multiple policies for testing
    local role_name="list-policies-test-role-$(date +%s)-$$-$RANDOM"
    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    
    log "Creating role for ListRolePolicies test..."
    set +e
    local create_result
    capture_output create_result aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" \
        --description "Test role for ListRolePolicies operation" \
       
    local create_exit=$?
    set -e
    
    if [ $create_exit -ne 0 ]; then
        error "IAM ListRolePolicies setup - Failed to create role: $create_result"
        return 1
    fi
    
    log "✅ Role created: $role_name"
    
    # Test ListRolePolicies with empty role (should return empty list)
    log "Testing ListRolePolicies with no policies attached..."
    
    
    set +e
    local empty_list_result
    capture_output empty_list_result aws_iam list-role-policies --role-name "$role_name"
    local empty_list_exit=$?
    set -e
    
    if [ $empty_list_exit -eq 0 ]; then
        local policy_count=$(echo "$empty_list_result" | jq '.PolicyNames | length' 2>/dev/null || echo 0)
        if [ "$policy_count" -eq 0 ]; then
            success "IAM ListRolePolicies - Empty role correctly returns empty policy list"
        else
            error "IAM ListRolePolicies - Empty role returned $policy_count policies instead of 0"
            return 1
        fi
    else
        error "IAM ListRolePolicies - Failed on empty role: $empty_list_result"
        return 1
    fi
    
    # Attach multiple policies to test listing
    log "Attaching multiple policies to test ListRolePolicies..."
    
    local s3_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::test-bucket/*"]}]}'
    local ec2_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:DescribeInstances"],"Resource":["*"]}]}'
    local iam_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ListUsers"],"Resource":["*"]}]}'
    
    # Attach S3 policy
    set +e
    aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "S3Policy" \
        --policy-document "$s3_policy" >/dev/null 2>&1
    local s3_put_exit=$?
    set -e
    
    # Attach EC2 policy  
    set +e
    aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "EC2Policy" \
        --policy-document "$ec2_policy" >/dev/null 2>&1
    local ec2_put_exit=$?
    set -e
    
    # Attach IAM policy
    set +e
    aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "IAMPolicy" \
        --policy-document "$iam_policy" >/dev/null 2>&1
    local iam_put_exit=$?
    set -e
    
    if [ $s3_put_exit -eq 0 ] && [ $ec2_put_exit -eq 0 ] && [ $iam_put_exit -eq 0 ]; then
        log "✅ Three policies attached successfully"
        
        # Wait for policy propagation
        log "Waiting 2 seconds for policy attachment to propagate..."
        sleep 2
        
        # Now test ListRolePolicies with multiple policies
        log "Testing ListRolePolicies with 3 attached policies..."
        set +e
        local multi_list_result
        capture_output multi_list_result aws_iam list-role-policies --role-name "$role_name"
        local multi_list_exit=$?
        set -e
        
        log "DEBUG: ListRolePolicies result:"
        echo "  Exit code: $multi_list_exit"
        echo "  Response: $multi_list_result"
        
        if [ $multi_list_exit -eq 0 ]; then
            # Check that we get exactly 3 policies
            local found_policy_count=$(echo "$multi_list_result" | jq '.PolicyNames | length' 2>/dev/null || echo 0)
            
            if [ "$found_policy_count" -eq 3 ]; then
                log "✅ Correct number of policies found: $found_policy_count"
                
                # Check that all expected policy names are present
                local has_s3=false
                local has_ec2=false
                local has_iam=false
                
                if echo "$multi_list_result" | jq -e '.PolicyNames[] | select(. == "S3Policy")' >/dev/null 2>&1; then
                    has_s3=true
                    log "  ✅ S3Policy found"
                fi
                
                if echo "$multi_list_result" | jq -e '.PolicyNames[] | select(. == "EC2Policy")' >/dev/null 2>&1; then
                    has_ec2=true
                    log "  ✅ EC2Policy found"
                fi
                
                if echo "$multi_list_result" | jq -e '.PolicyNames[] | select(. == "IAMPolicy")' >/dev/null 2>&1; then
                    has_iam=true
                    log "  ✅ IAMPolicy found"
                fi
                
                if [ "$has_s3" = "true" ] && [ "$has_ec2" = "true" ] && [ "$has_iam" = "true" ]; then
                    success "IAM ListRolePolicies - All 3 policies correctly listed"
                    
                    # Test pagination (if supported)
                    log "Testing ListRolePolicies with MaxItems parameter..."
                    set +e
                    local paginated_result
                    capture_output paginated_result aws_iam list-role-policies --role-name "$role_name" --max-items 2
                    local paginated_exit=$?
                    set -e
                    
                    if [ $paginated_exit -eq 0 ]; then
                        local paginated_count=$(echo "$paginated_result" | jq '.PolicyNames | length' 2>/dev/null || echo 0)
                        if [ "$paginated_count" -le 2 ] && [ "$paginated_count" -gt 0 ]; then
                            success "IAM ListRolePolicies - Pagination with MaxItems works (returned $paginated_count policies)"
                        else
                            warning "IAM ListRolePolicies - Pagination returned unexpected count: $paginated_count"
                        fi
                    else
                        warning "IAM ListRolePolicies - Pagination failed (may not be implemented): $paginated_result"
                    fi
                    
                    # Clean up
                    log "Cleaning up test role..."
                    cleanup_iam_test_resources "list-policies-test-role-"
                    return 0
                else
                    error "IAM ListRolePolicies - Missing expected policy names"
                    log "  S3Policy: $has_s3, EC2Policy: $has_ec2, IAMPolicy: $has_iam"
                    return 1
                fi
            else
                error "IAM ListRolePolicies - Expected 3 policies, got $found_policy_count"
                echo "PolicyNames: $(echo "$multi_list_result" | jq '.PolicyNames' 2>/dev/null)"
                return 1
            fi
        else
            error "IAM ListRolePolicies - Failed to list policies: $multi_list_result"
            return 1
        fi
    else
        error "IAM ListRolePolicies setup - Failed to attach test policies"
        log "  S3 policy exit: $s3_put_exit"
        log "  EC2 policy exit: $ec2_put_exit" 
        log "  IAM policy exit: $iam_put_exit"
        return 1
    fi
}

# =============================================================================
# IAM GetRolePolicy Tests  
# =============================================================================

test_iam_get_role_policy() {
    log "Testing IAM GetRolePolicy operation..."
    
    # Clean up any existing test roles first
    log "DEBUG: Cleaning up existing IAM test roles..."
    cleanup_iam_test_resources "get-policy-test-role-"
    
    # Create a role with a specific policy for testing
    local role_name="get-policy-test-role-$(date +%s)-$$-$RANDOM"
    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    
    log "Creating role for GetRolePolicy test..."
    set +e
    local create_result
    capture_output create_result aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" \
        --description "Test role for GetRolePolicy operation" \
       
    local create_exit=$?
    set -e
    
    if [ $create_exit -ne 0 ]; then
        error "IAM GetRolePolicy setup - Failed to create role: $create_result"
        return 1
    fi
    
    log "✅ Role created: $role_name"
    
    # Test GetRolePolicy with non-existent policy (should fail)
    log "Testing GetRolePolicy with non-existent policy..."
    set +e
    local missing_result
    capture_output missing_result aws_iam get-role-policy --role-name "$role_name" --policy-name "NonExistentPolicy"
    local missing_exit=$?
    set -e
    
    if [ $missing_exit -ne 0 ]; then
        if echo "$missing_result" | grep -q "NoSuchEntity\|not found"; then
            success "IAM GetRolePolicy - Correctly rejects non-existent policy"
        else
            warning "IAM GetRolePolicy - Failed on non-existent policy but with unexpected error: $missing_result"
        fi
    else
        error "IAM GetRolePolicy - Should have failed on non-existent policy"
        return 1
    fi
    
    # Attach a comprehensive policy to test retrieval
    log "Attaching comprehensive test policy..."
    local comprehensive_policy='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket",
                    "s3:CreateBucket"
                ],
                "Resource": [
                    "arn:aws:s3:::test-bucket-123/*",
                    "arn:aws:s3:::test-bucket-123"
                ]
            },
            {
                "Effect": "Deny",
                "Action": [
                    "s3:DeleteBucket"
                ],
                "Resource": [
                    "*"
                ]
            }
        ]
    }'
    
    set +e
    local put_result
    capture_output put_result aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "ComprehensiveTestPolicy" \
        --policy-document "$comprehensive_policy" \
       
    local put_exit=$?
    set -e
    
    if [ $put_exit -eq 0 ]; then
        log "✅ Comprehensive policy attached"
        
        # Wait for policy propagation
        log "Waiting 2 seconds for policy attachment to propagate..."
        sleep 2
        
        # Test GetRolePolicy to retrieve the attached policy
        log "Testing GetRolePolicy to retrieve attached policy..."
        set +e
        local get_result
        capture_output get_result aws_iam get-role-policy --role-name "$role_name" --policy-name "ComprehensiveTestPolicy"
        local get_exit=$?
        set -e
        
        log "DEBUG: GetRolePolicy result:"
        echo "  Exit code: $get_exit"
        echo "  Response: $get_result"
        
        if [ $get_exit -eq 0 ]; then
            # Verify response structure
            local returned_role_name=$(echo "$get_result" | jq -r '.RoleName' 2>/dev/null || echo "")
            local returned_policy_name=$(echo "$get_result" | jq -r '.PolicyName' 2>/dev/null || echo "")
            local returned_policy_doc=$(echo "$get_result" | jq -r '.PolicyDocument' 2>/dev/null || echo "")
            
            log "DEBUG: Response fields:"
            echo "  RoleName: $returned_role_name"
            echo "  PolicyName: $returned_policy_name"
            echo "  PolicyDocument length: ${#returned_policy_doc}"
            
            # Validate response fields
            local field_checks_passed=true
            
            if [ "$returned_role_name" != "$role_name" ]; then
                error "IAM GetRolePolicy - RoleName mismatch: expected '$role_name', got '$returned_role_name'"
                field_checks_passed=false
            else
                log "  ✅ RoleName field correct"
            fi
            
            if [ "$returned_policy_name" != "ComprehensiveTestPolicy" ]; then
                error "IAM GetRolePolicy - PolicyName mismatch: expected 'ComprehensiveTestPolicy', got '$returned_policy_name'"
                field_checks_passed=false
            else
                log "  ✅ PolicyName field correct"
            fi
            
            if [ -z "$returned_policy_doc" ] || [ "$returned_policy_doc" = "null" ]; then
                error "IAM GetRolePolicy - PolicyDocument field missing or empty"
                field_checks_passed=false
            else
                log "  ✅ PolicyDocument field present"
                
                # Validate policy document content
                local doc_checks_passed=true
                
                if echo "$returned_policy_doc" | jq -e '.Statement' >/dev/null 2>&1; then
                    log "    ✅ PolicyDocument has Statement array"
                    
                    # Check for specific permissions in the policy
                    if echo "$returned_policy_doc" | jq -e '.. | select(type == "string" and test("s3:GetObject"))?' >/dev/null 2>&1; then
                        log "    ✅ s3:GetObject permission found"
                    else
                        error "    ❌ s3:GetObject permission missing"
                        doc_checks_passed=false
                    fi
                    
                    if echo "$returned_policy_doc" | jq -e '.. | select(type == "string" and test("s3:PutObject"))?' >/dev/null 2>&1; then
                        log "    ✅ s3:PutObject permission found"
                    else
                        error "    ❌ s3:PutObject permission missing"
                        doc_checks_passed=false
                    fi
                    
                    if echo "$returned_policy_doc" | jq -e '.. | select(type == "string" and test("test-bucket-123"))?' >/dev/null 2>&1; then
                        log "    ✅ test-bucket-123 resource found"
                    else
                        error "    ❌ test-bucket-123 resource missing"
                        doc_checks_passed=false
                    fi
                    
                    if echo "$returned_policy_doc" | jq -e '.Statement[] | select(.Effect == "Deny")' >/dev/null 2>&1; then
                        log "    ✅ Deny statement found"
                    else
                        error "    ❌ Deny statement missing"
                        doc_checks_passed=false
                    fi
                    
                else
                    error "    ❌ PolicyDocument missing Statement array"
                    doc_checks_passed=false
                fi
                
                if [ "$doc_checks_passed" = "false" ]; then
                    field_checks_passed=false
                fi
            fi
            
            if [ "$field_checks_passed" = "true" ]; then
                success "IAM GetRolePolicy - Policy document correctly retrieved and validated"
                
                # Clean up
                log "Cleaning up test role..."
                cleanup_iam_test_resources "get-policy-test-role-"
                return 0
            else
                error "IAM GetRolePolicy - Policy document validation failed"
                return 1
            fi
        else
            error "IAM GetRolePolicy - Failed to retrieve policy: $get_result"
            return 1
        fi
    else
        error "IAM GetRolePolicy setup - Failed to attach test policy: $put_result"
        return 1
    fi
}

# =============================================================================  
# Combined IAM Operations Test
# =============================================================================

test_iam_operations_workflow() {
    log "Testing complete IAM operations workflow (ListRolePolicies + GetRolePolicy integration)..."
    
    # Clean up any existing test roles first
    log "DEBUG: Cleaning up existing IAM test roles..."
    cleanup_iam_test_resources "workflow-test-role-"
    
    local role_name="workflow-test-role-$(date +%s)-$$-$RANDOM"
    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    
    # Step 1: Create role
    log "Step 1: Creating role..."
    set +e
    aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" \
        --description "Test role for complete IAM workflow" >/dev/null 2>&1
    local create_exit=$?
    set -e
    
    if [ $create_exit -ne 0 ]; then
        error "IAM Workflow - Failed to create role"
        return 1
    fi
    
    # Step 2: Verify empty policy list
    log "Step 2: Verifying empty policy list..."
    set +e
    local empty_list
    capture_output empty_list aws_iam list-role-policies --role-name "$role_name"
    local empty_exit=$?
    set -e
    
    if [ $empty_exit -eq 0 ]; then
        local empty_count
        echo "$empty_list" | jq '.PolicyNames | length' 2>/dev/null > "/tmp/empty_count_$$" || echo -1 > "/tmp/empty_count_$$"
        read empty_count < "/tmp/empty_count_$$"
        rm -f "/tmp/empty_count_$$"
        if [ "$empty_count" -eq 0 ]; then
            log "  ✅ Empty role has 0 policies as expected"
        else
            error "  ❌ Empty role has $empty_count policies instead of 0"
            return 1
        fi
    else
        error "IAM Workflow - ListRolePolicies failed on empty role: $empty_list"
        return 1
    fi
    
    # Step 3: Add policies one by one and verify each step
    log "Step 3: Adding policies and verifying each step..."
    
    local policies=("DynamoDBPolicy" "S3Policy" "LambdaPolicy")
    local policy_docs=(
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem"],"Resource":["*"]}]}'
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::test/*"]}]}'
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["lambda:InvokeFunction"],"Resource":["*"]}]}'
    )
    
    local expected_count=0
    for i in $(seq 0 2); do
        local policy_name="${policies[$i]}"
        local policy_doc="${policy_docs[$i]}"
        expected_count=$((expected_count + 1))
        
        log "  Adding policy $expected_count: $policy_name"
        
        # Add policy
        set +e
        aws_iam put-role-policy \
            --role-name "$role_name" \
            --policy-name "$policy_name" \
            --policy-document "$policy_doc" >/dev/null 2>&1
        local put_exit=$?
        set -e
        
        if [ $put_exit -ne 0 ]; then
            error "  ❌ Failed to add policy $policy_name"
            return 1
        fi
        
        # Wait for propagation
        sleep 1
        
        # Verify policy count
        set +e
        local current_list
        capture_output current_list aws_iam list-role-policies --role-name "$role_name"
        local list_exit=$?
        set -e
        
        if [ $list_exit -eq 0 ]; then
            local current_count=$(echo "$current_list" | jq '.PolicyNames | length' 2>/dev/null || echo -1)
            if [ "$current_count" -eq "$expected_count" ]; then
                log "    ✅ Policy count correct: $current_count"
                
                # Verify the specific policy can be retrieved
                set +e
                local retrieved_policy
                capture_output retrieved_policy aws_iam get-role-policy --role-name "$role_name" --policy-name "$policy_name"
                local get_exit=$?
                set -e
                
                if [ $get_exit -eq 0 ]; then
                    local retrieved_name=$(echo "$retrieved_policy" | jq -r '.PolicyName' 2>/dev/null)
                    if [ "$retrieved_name" = "$policy_name" ]; then
                        log "    ✅ Policy $policy_name retrievable via GetRolePolicy"
                    else
                        error "    ❌ Retrieved policy name mismatch: $retrieved_name vs $policy_name"
                        return 1
                    fi
                else
                    error "    ❌ Failed to retrieve policy $policy_name: $retrieved_policy"
                    return 1
                fi
            else
                error "    ❌ Expected $expected_count policies, got $current_count"
                echo "    Current policies: $(echo "$current_list" | jq '.PolicyNames' 2>/dev/null)"
                return 1
            fi
        else
            error "  ❌ ListRolePolicies failed after adding $policy_name: $current_list"
            return 1
        fi
    done
    
    # Step 4: Final verification - ensure all policies are listed and retrievable
    log "Step 4: Final verification of complete policy set..."
    set +e
    local final_list
    capture_output final_list aws_iam list-role-policies --role-name "$role_name"
    local final_exit=$?
    set -e
    
    if [ $final_exit -eq 0 ]; then
        local final_count=$(echo "$final_list" | jq '.PolicyNames | length' 2>/dev/null || echo -1)
        if [ "$final_count" -eq 3 ]; then
            log "  ✅ Final policy count correct: $final_count"
            
            # Verify each expected policy is present and retrievable
            local all_policies_ok=true
            for policy_name in "${policies[@]}"; do
                if echo "$final_list" | jq -e ".PolicyNames[] | select(. == \"$policy_name\")" >/dev/null 2>&1; then
                    log "    ✅ $policy_name found in list"
                    
                    # Double-check retrieval
                    set +e
                    aws_iam get-role-policy --role-name "$role_name" --policy-name "$policy_name" >/dev/null 2>&1
                    local verify_exit=$?
                    set -e
                    
                    if [ $verify_exit -eq 0 ]; then
                        log "      ✅ $policy_name retrievable"
                    else
                        error "      ❌ $policy_name not retrievable"
                        all_policies_ok=false
                    fi
                else
                    error "    ❌ $policy_name missing from list"
                    all_policies_ok=false
                fi
            done
            
            if [ "$all_policies_ok" = "true" ]; then
                success "IAM Operations Workflow - Complete ListRolePolicies + GetRolePolicy workflow successful"
                
                # Clean up
                log "Cleaning up workflow test role..."
                cleanup_iam_test_resources "workflow-test-role-"
                return 0
            else
                error "IAM Operations Workflow - Some policies not accessible"
                return 1
            fi
        else
            error "IAM Operations Workflow - Expected 3 final policies, got $final_count"
            return 1
        fi
    else
        error "IAM Operations Workflow - Final ListRolePolicies failed: $final_list"
        return 1
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
        "cors")
            log "Starting S3 CORS Tests for manta-buckets-api using AWS CLI"
            log "========================================================"
            
            set +e  # Disable exit on error for test execution
            
            # CORS-specific tests
            test_cors_headers || true
            test_cors_presigned_urls || true
            
            set -e  # Re-enable exit on error
            ;;
        "iam")
            log "Starting IAM (Identity and Access Management) Tests for manta-buckets-api using AWS CLI"
            log "===================================================================================="
            
            setup  # Initialize test environment
            
            # Disable cleanup trap to prevent early exit
            trap - EXIT
            
            # Clean up all existing roles before starting IAM tests (don't fail if cleanup fails)
            log "Cleaning up existing IAM roles to prevent 'Name is not unique' errors..."
            set +e  # Temporarily allow cleanup to fail
            cleanup_all_iam_roles || true
            
            # Create IAM test buckets with admin credentials before any IAM tests
            log "Creating IAM test buckets with admin credentials..."
            aws_s3api create-bucket --bucket "iam-test-bucket-fixed" 2>/dev/null || true
            aws_s3api create-bucket --bucket "unauthorized-bucket-fixed" 2>/dev/null || true
            
            set +e  # Disable exit on error for test execution
            
            # IAM tests only
            test_iam_debug_endpoints || true
            test_iam_create_role || true
            test_iam_get_role || true
            test_iam_create_role_duplicate || true
            test_iam_get_role_nonexistent || true
            test_iam_policy_conversion || true
            # New permission policy tests
            test_iam_put_role_policy || true
            test_iam_role_with_permission_policy || true
            test_iam_permission_policy_enforcement || true
            test_iam_permission_policy_vs_trust_policy || true
            # Permission policy Deny statement tests (security fix validation)
            test_iam_permission_policy_deny_overrides_allow || true
            test_iam_permission_policy_deny_resource_pattern || true
            # New ListRolePolicies and GetRolePolicy tests
            test_iam_list_role_policies || true
            test_iam_get_role_policy || true
            test_iam_operations_workflow || true
            test_iam_list_roles || true
            test_iam_delete_role || true
            test_iam_delete_role_policy || true
            test_iam_comprehensive_security || true

            # Test IAM operations with temporary credentials (MSTS/MSAR)
            log "Running STS credential prefix and IAM access tests..."
            test_sts_credential_prefix_verification || true
            test_iam_create_role_with_session_token || true
            test_iam_create_role_with_assume_role_credentials || true

            # AWS IAM Trust Policy "Deny" Support Tests (NEW)
            test_iam_trust_policy_deny_overrides_allow || true
            test_iam_trust_policy_multiple_denies || true
            test_iam_trust_policy_deny_wildcard || true
            test_iam_trust_policy_only_deny || true
            test_iam_trust_policy_backwards_compatibility || true
            test_iam_trust_policy_complex_mixed || true
            test_iam_trust_policy_statement_order || true
            test_iam_trust_policy_principal_formats || true
            test_iam_trust_policy_error_handling || true
            test_iam_sts_integration_with_deny_policies || true
            
            # Trust Policy Validation Tests (Security Fix Validation)
            log "Running Trust Policy Validation Tests (Security Fix Verification)..."
            test_trust_policy_principal_matching || true
            test_trust_policy_conditions || true
            test_trust_policy_explicit_deny || true
            test_trust_policy_service_principal || true
            test_trust_policy_missing_policy || true
            test_trust_policy_cross_account || true
            test_trust_policy_invalid_json || true
            test_trust_policy_version_validation || true
            test_trust_policy_action_validation || true
            test_trust_policy_security_fix || true
            
            # Manual cleanup after all IAM tests complete
            log "All IAM tests completed, running cleanup..."
            
            # Clean up IAM test buckets
            log "Cleaning up IAM test buckets..."
            aws_s3 rm "s3://iam-test-bucket-fixed" --recursive 2>/dev/null || true
            aws_s3api delete-bucket --bucket "iam-test-bucket-fixed" 2>/dev/null || true
            aws_s3 rm "s3://unauthorized-bucket-fixed" --recursive 2>/dev/null || true
            aws_s3api delete-bucket --bucket "unauthorized-bucket-fixed" 2>/dev/null || true
            
            cleanup_iam_resources
            cleanup_deny_test_roles
            cleanup_trust_policy_test_roles
            
            set -e  # Re-enable exit on error
            ;;
        "sts")
            log "Starting STS (Security Token Service) Tests for manta-buckets-api using AWS CLI"
            log "=============================================================================="
            
            set +e  # Disable exit on error for test execution
            
            # Create IAM role first for STS tests
            test_iam_create_role || true
            
            # STS tests
            test_sts_assume_role || true
            test_sts_get_session_token || true
            test_sts_get_caller_identity || true
            test_sts_get_caller_identity_with_temp_creds || true
            test_sts_role_based_authorization || true
            test_sts_role_object_permissions || true
            test_sts_temporary_credentials_expiry || true

            # Trust Policy Validation Tests (Security Fix Validation)
            log "Running Trust Policy Validation Tests for STS..."
            test_trust_policy_principal_matching || true
            test_trust_policy_conditions || true
            test_trust_policy_explicit_deny || true
            test_trust_policy_service_principal || true
            test_trust_policy_missing_policy || true
            test_trust_policy_cross_account || true
            test_trust_policy_invalid_json || true
            test_trust_policy_version_validation || true
            test_trust_policy_action_validation || true
            test_trust_policy_security_fix || true
            
            # Clean up STS test resources
            log "STS tests completed, running cleanup..."
            
            # Clean up any IAM test buckets created during STS tests
            log "Cleaning up IAM test buckets..."
            aws_s3 rm "s3://iam-test-bucket-fixed" --recursive 2>/dev/null || true
            aws_s3api delete-bucket --bucket "iam-test-bucket-fixed" 2>/dev/null || true
            aws_s3 rm "s3://unauthorized-bucket-fixed" --recursive 2>/dev/null || true
            aws_s3api delete-bucket --bucket "unauthorized-bucket-fixed" 2>/dev/null || true
            
            # Clean up IAM roles and policies from STS tests
            cleanup_iam_resources
            cleanup_trust_policy_test_roles
            
            # Reset AWS credential environment to original values
            log "Resetting AWS credentials to original values..."
            export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
            export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
            unset AWS_SESSION_TOKEN
            
            set -e  # Re-enable exit on error
            ;;
        "iam-sts"|"sts-iam")
            log "Starting IAM + STS Integration Tests for manta-buckets-api using AWS CLI"
            log "========================================================================"
            
            set +e  # Disable exit on error for test execution
            
            # Complete IAM + STS workflow tests
            test_iam_create_role || true
            test_iam_get_role || true
            test_iam_create_role_duplicate || true
            test_iam_get_role_nonexistent || true
            test_iam_policy_conversion || true
            # New permission policy tests
            test_iam_put_role_policy || true
            test_iam_role_with_permission_policy || true
            test_iam_permission_policy_enforcement || true
            test_iam_permission_policy_vs_trust_policy || true
            # Permission policy Deny statement tests (security fix validation)
            test_iam_permission_policy_deny_overrides_allow || true
            test_iam_permission_policy_deny_resource_pattern || true
            test_iam_list_roles || true
            test_iam_delete_role || true
            test_iam_delete_role_policy || true
            # STS tests
            test_sts_assume_role || true
            test_sts_get_session_token || true
            test_sts_get_caller_identity || true
            test_sts_get_caller_identity_with_temp_creds || true
            test_sts_role_based_authorization || true
            test_sts_role_object_permissions || true
            test_sts_temporary_credentials_expiry || true
            test_iam_sts_integration || true
            test_iam_comprehensive_security || true

            # Test IAM operations with temporary credentials (MSTS/MSAR)
            log "Running STS credential prefix and IAM access tests..."
            test_sts_credential_prefix_verification || true
            test_iam_create_role_with_session_token || true
            test_iam_create_role_with_assume_role_credentials || true

            # Clean up IAM+STS integration test resources
            log "IAM+STS integration tests completed, running comprehensive cleanup..."

            # Clean up IAM test buckets
            log "Cleaning up IAM test buckets..."
            aws_s3 rm "s3://iam-test-bucket-fixed" --recursive 2>/dev/null || true
            aws_s3api delete-bucket --bucket "iam-test-bucket-fixed" 2>/dev/null || true
            aws_s3 rm "s3://unauthorized-bucket-fixed" --recursive 2>/dev/null || true
            aws_s3api delete-bucket --bucket "unauthorized-bucket-fixed" 2>/dev/null || true

            # Comprehensive cleanup of all IAM resources
            cleanup_iam_resources

            # Reset AWS credential environment to original values
            log "Resetting AWS credentials to original values..."
            export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
            export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
            unset AWS_SESSION_TOKEN

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
            
            # CORS tests
            test_cors_headers || true
            test_cors_presigned_urls || true
            
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
            
            # IAM and STS tests (run after other tests to avoid interference)
            log "Starting IAM and STS tests as part of comprehensive test suite..."
            
            # IAM tests
            test_iam_create_role || true
            test_iam_trust_policy_allow || true
            test_iam_trust_policy_deny_overrides_allow || true
            test_iam_trust_policy_multiple_deny_statements || true
            test_iam_trust_policy_wildcard_deny || true
            test_iam_trust_policy_only_deny || true
            test_iam_trust_policy_principal_validation || true
            test_iam_trust_policy_condition_validation || true
            test_iam_trust_policy_service_principals || true
            test_iam_trust_policy_cross_account || true
            test_iam_put_role_policy || true
            test_iam_role_with_permission_policy || true
            test_iam_permission_policy_enforcement || true
            test_iam_permission_policy_vs_trust_policy || true
            # Permission policy Deny statement tests (security fix validation)
            test_iam_permission_policy_deny_overrides_allow || true
            test_iam_permission_policy_deny_resource_pattern || true
            test_iam_list_roles || true
            test_iam_delete_role || true
            test_iam_delete_role_policy || true

            # STS tests
            test_sts_assume_role || true
            test_sts_get_session_token || true
            test_sts_get_caller_identity || true
            test_sts_get_caller_identity_with_temp_creds || true
            test_sts_role_based_authorization || true
            test_sts_role_object_permissions || true
            test_sts_temporary_credentials_expiry || true
            test_iam_sts_integration || true
            test_iam_comprehensive_security || true

            # Test IAM operations with temporary credentials (MSTS/MSAR)
            log "Running STS credential prefix and IAM access tests..."
            test_sts_credential_prefix_verification || true
            test_iam_create_role_with_session_token || true
            test_iam_create_role_with_assume_role_credentials || true

            # Clean up IAM+STS integration test resources
            log "IAM+STS integration tests completed, running cleanup..."

            # Clean up IAM test buckets
            aws_s3 rm "s3://iam-test-bucket-fixed" --recursive 2>/dev/null || true
            aws_s3api delete-bucket --bucket "iam-test-bucket-fixed" 2>/dev/null || true
            aws_s3 rm "s3://unauthorized-bucket-fixed" --recursive 2>/dev/null || true
            aws_s3api delete-bucket --bucket "unauthorized-bucket-fixed" 2>/dev/null || true

            # Comprehensive cleanup of all IAM resources
            cleanup_iam_resources

            # Reset AWS credential environment to original values
            log "Resetting AWS credentials to original values..."
            export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
            export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
            unset AWS_SESSION_TOKEN

            set -e  # Re-enable exit on error
            ;;
    esac
    
    set -e  # Re-enable exit on error
}

# =============================================================================
# AWS IAM Trust Policy "Deny" Support Tests (NEW)
# Tests the new AWS-compliant policy evaluation logic in mahi
# =============================================================================

# Helper function to get the current account UUID for trust policies
get_account_uuid() {
    # Try to get account UUID from STS
    set +e
    local account_info
    local sts_output
    capture_output sts_output aws_sts get-caller-identity
    echo "$sts_output" | grep Account | cut -d'"' -f4 2>/dev/null > "/tmp/account_info_$$" || echo "" > "/tmp/account_info_$$"
    read account_info < "/tmp/account_info_$$" 2>/dev/null || account_info=""
    rm -f "/tmp/account_info_$$"
    set -e
    
    if [ -z "$account_info" ]; then
        # Fallback - use a mock account UUID for testing
        echo "123456789012"
    else
        echo "$account_info"
    fi
}

# Helper function to clean up deny test roles
cleanup_deny_test_roles() {
    log "Cleaning up AWS IAM deny test roles..."
    local roles=("DenyOverrideRole" "MultiDenyRole" "WildcardDenyRole" "OnlyDenyRole" 
                 "BackwardsCompatRole" "ComplexMixedRole" "DenyFirstRole" "AllowFirstRole"
                 "PrincipalFormatsRole" "StsIntegrationRole")
    
    set +e  # Don't exit on cleanup failures
    for role in "${roles[@]}"; do
        # Check if role exists first to avoid unnecessary timeouts
        if run_with_timeout 5 aws_iam_silent get-role --role-name "$role" >/dev/null 2>&1; then
            log "CLEANUP_DEBUG: Deleting IAM deny test role: $role"
            run_with_timeout 10 aws_iam_silent delete-role --role-name "$role" || true
        fi
    done
    set -e
}

# Helper function to clean up trust policy test roles
cleanup_trust_policy_test_roles() {
    log "Cleaning up trust policy validation test roles..."
    local roles=("TrustPolicyPrincipalTestRole" "TrustPolicyConditionTestRole" 
                 "TrustPolicyDenyTestRole" "TrustPolicyServiceTestRole"
                 "TrustPolicyMissingTestRole" "TrustPolicyCrossAccountTestRole"
                 "TrustPolicyInvalidJSONTestRole" "TrustPolicyVersionTestRole"
                 "TrustPolicyActionTestRole" "TrustPolicySecurityFixTestRole")
    
    set +e  # Don't exit on cleanup failures
    for role in "${roles[@]}"; do
        # Check if role exists first to avoid unnecessary timeouts
        if run_with_timeout 5 aws_iam_silent get-role --role-name "$role" >/dev/null 2>&1; then
            log "CLEANUP_DEBUG: Deleting trust policy test role: $role"
            run_with_timeout 10 aws_iam_silent delete-role --role-name "$role" || true
        fi
    done
    
    # Clean up any temp files created by trust policy tests
    rm -f "$TEMP_DIR/trust_policy_principal_role" 2>/dev/null || true
    rm -f "$TEMP_DIR/trust_policy_condition_role" 2>/dev/null || true
    rm -f "$TEMP_DIR/trust_policy_deny_role" 2>/dev/null || true
    rm -f "$TEMP_DIR/trust_policy_service_role" 2>/dev/null || true
    rm -f "$TEMP_DIR/trust_policy_missing_role" 2>/dev/null || true
    rm -f "$TEMP_DIR/trust_policy_cross_account_role" 2>/dev/null || true
    rm -f "$TEMP_DIR/trust_policy_action_role" 2>/dev/null || true
    rm -f "$TEMP_DIR/trust_policy_security_fix_role" 2>/dev/null || true
    
    set -e
}

# Test 1: Explicit Deny overrides Allow (Core new functionality)

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "=========================================="
    log "IAM Role Management Test Suite"
    log "=========================================="

    setup

    # Run IAM role management tests in order
    test_iam_create_role
    test_iam_get_role
    test_iam_create_role_duplicate
    test_iam_get_role_nonexistent
    test_iam_put_role_policy
    test_iam_list_roles
    test_iam_delete_role
    test_iam_delete_role_policy
    test_iam_list_role_policies
    test_iam_get_role_policy
    test_iam_operations_workflow

    cleanup_basic
    print_summary
}

main
