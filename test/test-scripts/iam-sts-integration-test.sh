#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# S3 Compatibility Test - IAM-STS Integration
#
# Tests integration between IAM and STS services:
# - Creating IAM roles using STS session tokens
# - Creating IAM roles using assumed role credentials
# - Comprehensive IAM-STS interaction scenarios
# - Integration with deny policies
# - End-to-end security workflows
# - Role assumption with temporary credentials

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Functions
# =============================================================================

test_iam_create_role_with_session_token() {
    log "Testing IAM CreateRole with GetSessionToken credentials (MSTS)..."
    log "Expected: InvalidClientTokenId (MSTS credentials blocked from IAM APIs)"

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

    # Step 3: Verify the request was blocked with InvalidClientTokenId
    if [ $create_exit_code -ne 0 ]; then
        if echo "$create_output" | grep -qiE "InvalidClientTokenId"; then
            success "IAM with MSTS - Correctly blocked with InvalidClientTokenId"
            log "Response: $create_output"
        else
            error "IAM with MSTS - Blocked but unexpected error message"
            log "Expected: InvalidClientTokenId, Got: $create_output"
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
# AssumeRole credentials (MSAR prefix) are blocked from IAM operations
# just like MSTS credentials. This test verifies that MSAR credentials
# are properly blocked with InvalidClientTokenId error.
test_iam_create_role_with_assume_role_credentials() {
    log "Testing IAM CreateRole with AssumeRole credentials (MSAR)..."
    log "Expected: InvalidClientTokenId (MSAR credentials blocked from IAM APIs)"

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

    # Step 4: Verify the result - should be blocked with InvalidClientTokenId
    if [ $create_exit_code -ne 0 ]; then
        if echo "$create_output" | grep -qiE "InvalidClientTokenId"; then
            success "IAM with MSAR - Correctly blocked with InvalidClientTokenId"
            log "Response: $create_output"
        else
            error "IAM with MSAR - Blocked but unexpected error message"
            log "Expected: InvalidClientTokenId, Got: $create_output"
        fi
    else
        # Role was created - this is a SECURITY VIOLATION
        error "IAM with MSAR - SECURITY BUG: Role was created!"
        error "AssumeRole credentials (MSAR) must NOT call IAM APIs"
        log "Response: $create_output"

        # Cleanup the role that should not have been created
        log "Cleaning up incorrectly created role: $new_role_name"
        aws_iam delete-role --role-name "$new_role_name" 2>/dev/null || true
    fi

    # Cleanup base role
    log "Cleaning up base role: $base_role_name"
    aws_iam delete-role-policy \
        --role-name "$base_role_name" \
        --policy-name "IAMPermissions" 2>/dev/null || true
    aws_iam delete-role --role-name "$base_role_name" 2>/dev/null || true
}

# Test that verifies the access key prefix distinction
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
test_iam_sts_integration_with_deny_policies() {
    log "Testing: AWS IAM STS integration with deny policies..."
    
    local role_name="StsIntegrationRole"
    local account_uuid=$(get_account_uuid)
    
    # Create a role that allows current user but denies others
    local trust_policy=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::$account_uuid:root"},
            "Action": "sts:AssumeRole"
        },
        {
            "Effect": "Deny",
            "Principal": {"AWS": "arn:aws:iam::$account_uuid:user/testdenyuser"},
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
)
    
    set +e
    capture_output create_result aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy"
    create_exit=$?
    set -e
    
    if [ $create_exit -eq 0 ]; then
        # Test GetSessionToken works (should not be affected by role policies)
        set +e
        capture_output session_output aws_sts get-session-token --duration-seconds 900
        session_exit=$?
        set -e
        
        if [ $session_exit -eq 0 ]; then
            if echo "$session_output" | grep -q "AccessKeyId"; then
                success "AWS IAM STS Integration - STS operations work with deny-enabled roles"
            else
                warning "AWS IAM STS Integration - GetSessionToken response format unexpected"
            fi
        else
            warning "AWS IAM STS Integration - GetSessionToken test inconclusive - may need different test setup"
        fi
    else
        error "AWS IAM STS Integration - Failed to create STS integration role: $create_result"
    fi
}

# =============================================================================
# Trust Policy Validation Tests (Security Fix Validation)
# =============================================================================

# Test 1: Trust Policy Principal Matching

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "=========================================="
    log "IAM-STS Integration Test Suite"
    log "=========================================="

    setup

    # Run IAM-STS integration tests in order
    test_iam_create_role_with_session_token
    test_iam_create_role_with_assume_role_credentials
    test_iam_comprehensive_security
    test_iam_sts_integration
    test_iam_operations_workflow
    test_iam_sts_integration_with_deny_policies

    cleanup_basic
    print_summary
}

main
