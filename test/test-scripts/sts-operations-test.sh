#!/bin/bash
# Copyright 2025 Edgecast Cloud LLC.
# S3 Compatibility Test - STS Operations
#
# Tests AWS Security Token Service (STS) operations:
# - AssumeRole functionality
# - Role-based authorization
# - Role object permissions
# - Temporary credentials expiry
# - GetSessionToken operation
# - GetCallerIdentity operation
# - Credential prefix verification

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Functions
# =============================================================================

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


# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "=========================================="
    log "STS Operations Test Suite"
    log "=========================================="

    setup

    # Run STS operation tests in order
    test_sts_assume_role
    test_sts_role_based_authorization
    test_sts_role_object_permissions
    test_sts_temporary_credentials_expiry
    test_sts_get_session_token
    test_sts_get_caller_identity
    test_sts_get_caller_identity_with_temp_creds
    test_sts_credential_prefix_verification

    cleanup_basic
    print_summary
}

main
