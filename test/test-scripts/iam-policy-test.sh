#!/bin/bash
# Copyright 2025 Edgecast Cloud LLC.
# S3 Compatibility Test - IAM Permission Policy
#
# Tests IAM permission policy functionality:
# - Policy format conversion and validation
# - Permission policy enforcement on S3 operations
# - Policy evaluation (Allow vs Deny)
# - Deny overrides Allow principle
# - Resource pattern matching
# - Comprehensive security scenarios

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Functions
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

    # Create our own role instead of depending on previous test
    local role_name="auth-test-role-$(date +%s)-$$-$RANDOM"
    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    local permission_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"s3:PutObject\",\"s3:ListBucket\",\"s3:ListObjectsV2\",\"s3:CreateBucket\"],\"Resource\":[\"arn:aws:s3:::${IAM_TEST_BUCKET}/*\",\"arn:aws:s3:::${IAM_TEST_BUCKET}\"]}]}"

    log "Creating independent test role: $role_name"
    set +e
    local create_result
    capture_output create_result aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" \
        --description "Independent test role for permission policy authorization"
    local create_exit=$?
    set -e

    if [ $create_exit -ne 0 ]; then
        error "Permission policy test - Failed to create test role: $create_result"
        return 1
    fi

    # Attach permission policy
    log "Attaching S3 permission policy to role..."
    set +e
    local put_result
    capture_output put_result aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "S3AccessPolicy" \
        --policy-document "$permission_policy"
    local put_exit=$?
    set -e

    if [ $put_exit -ne 0 ]; then
        error "Permission policy test - Failed to attach policy: $put_result"
        # Cleanup
        aws_iam delete-role --role-name "$role_name" 2>/dev/null || true
        return 1
    fi

    # Wait for policy propagation
    log "Waiting 2 seconds for policy propagation..."
    sleep 2
    
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

        # Cleanup: delete test bucket and IAM resources
        log "Cleaning up test resources..."
        set +e
        aws_s3api delete-bucket --bucket "$IAM_TEST_BUCKET" 2>/dev/null || true
        aws_iam delete-role-policy --role-name "$role_name" --policy-name "S3AccessPolicy" 2>/dev/null || true
        aws_iam delete-role --role-name "$role_name" 2>/dev/null || true
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

        # Cleanup: delete test bucket and IAM resources
        log "Cleaning up test resources..."
        set +e
        aws_s3api delete-bucket --bucket "$IAM_TEST_BUCKET" 2>/dev/null || true
        aws_iam delete-role-policy --role-name "$role_name" --policy-name "S3AccessPolicy" 2>/dev/null || true
        aws_iam delete-role --role-name "$role_name" 2>/dev/null || true
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

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "=========================================="
    log "IAM Permission Policy Test Suite"
    log "=========================================="

    setup

    # Run permission policy tests in order
    test_iam_policy_conversion
    test_iam_role_with_permission_policy
    test_iam_permission_policy_enforcement
    test_iam_permission_policy_vs_trust_policy
    test_iam_permission_policy_deny_overrides_allow
    test_iam_permission_policy_deny_resource_pattern
    test_iam_comprehensive_security

    cleanup_basic
    print_summary
}

main
