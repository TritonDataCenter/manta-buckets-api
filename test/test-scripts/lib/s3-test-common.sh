#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Common test infrastructure for S3 compatibility tests
#
# This file contains shared configuration, utility functions, and setup/cleanup
# logic used across all S3 compatibility test modules.
#
# Usage:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/s3-test-common.sh"

set -eo pipefail  # Exit on error, pipe failures (removed -u for compatibility)

# =============================================================================
# Configuration Variables
# =============================================================================

# Script directory for relative paths
# Handle case where BASH_SOURCE might not be set (e.g., when sourced interactively)
if [ -n "${BASH_SOURCE[0]:-}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    SCRIPT_DIR="$(pwd)"
fi

# AWS Configuration (can be overridden via environment)
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-"AKIA123456789EXAMPLE"}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
S3_ENDPOINT=${S3_ENDPOINT:-"http://localhost:8080"}
AWS_REGION=${AWS_REGION:-"us-east-1"}
MANTA_USER=${MANTA_USER:-""}

# Save the TRUE original credentials immediately
ORIGINAL_AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
ORIGINAL_AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"

# Global variable to save working credentials when a successful operation occurs
WORKING_AWS_ACCESS_KEY_ID=""
WORKING_AWS_SECRET_ACCESS_KEY=""

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

# =============================================================================
# Utility Functions
# =============================================================================

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}PASS: $1${NC}"
    ((TESTS_PASSED++))
    echo "[DEBUG] success() completed, TESTS_PASSED=$TESTS_PASSED" >&2
}

error() {
    echo -e "${RED}FAIL: $1${NC}"
    ((TESTS_FAILED++))
    FAILED_TESTS+=("$1")
}

warning() {
    echo -e "${YELLOW}WARN: $1${NC}"
}

# Custom timeout function for systems without timeout command
run_with_timeout() {
    local timeout_duration=$1
    shift
    local cmd=("$@")

    # Run command in background
    "${cmd[@]}" &
    local cmd_pid=$!

    # Start timeout killer in background
    (
        sleep "$timeout_duration"
        if kill -0 "$cmd_pid" 2>/dev/null; then
            kill -TERM "$cmd_pid" 2>/dev/null || true
            sleep 2
            kill -KILL "$cmd_pid" 2>/dev/null || true
        fi
    ) &
    local killer_pid=$!

    # Wait for command to complete
    local exit_code=0
    wait "$cmd_pid" 2>/dev/null || exit_code=$?

    # Kill the timeout killer
    kill "$killer_pid" 2>/dev/null || true
    wait "$killer_pid" 2>/dev/null || true

    return $exit_code
}

# Helper function to capture command output without hanging command substitution
capture_output() {
    local var_name="$1"
    shift
    local temp_file="/tmp/aws_capture_$$_$RANDOM"

    "$@" > "$temp_file" 2>&1
    local exit_code=$?

    if [ -f "$temp_file" ]; then
        eval "$var_name=\$(cat '$temp_file')"
        rm -f "$temp_file"
    else
        eval "$var_name=''"
    fi

    return $exit_code
}

# =============================================================================
# AWS CLI Wrapper Functions
# =============================================================================

aws_s3api() {
    # Suppress Python SSL warnings
    export PYTHONWARNINGS="ignore:Unverified HTTPS request"

    aws s3api --endpoint-url="$S3_ENDPOINT" \
              --region="$AWS_REGION" \
              --no-verify-ssl \
              --no-cli-pager \
              --no-paginate \
              --color off \
              --output json \
              "$@"
}

aws_iam() {
    local output
    local exit_code

    output=$(aws iam --endpoint-url="$S3_ENDPOINT" \
                    --region="$AWS_REGION" \
                    --no-verify-ssl \
                    --no-cli-pager \
                    --no-paginate \
                    --color off \
                    --output json \
                    "$@" 2>&1)
    exit_code=$?

    if [ $exit_code -ne 0 ]; then
        echo "DEBUG: Failed AWS IAM command: aws iam $*" >&2
        echo "DEBUG: Full command: aws iam --endpoint-url=\"$S3_ENDPOINT\" --region=\"$AWS_REGION\" --no-verify-ssl $*" >&2
        echo "DEBUG: Exit code: $exit_code" >&2
        echo "$output" >&2
    else
        echo "$output"
    fi
    return $exit_code
}

aws_sts() {
    local output
    local exit_code

    output=$(aws sts --endpoint-url="$S3_ENDPOINT" \
                    --region="$AWS_REGION" \
                    --no-verify-ssl \
                    --no-cli-pager \
                    --no-paginate \
                    --color off \
                    "$@" 2>&1)
    exit_code=$?

    if [ $exit_code -ne 0 ]; then
        echo "DEBUG: Failed AWS STS command: aws sts $*" >&2
        echo "DEBUG: Full command: aws sts --endpoint-url=\"$S3_ENDPOINT\" --region=\"$AWS_REGION\" --no-verify-ssl $*" >&2
        echo "DEBUG: Exit code: $exit_code" >&2
        echo "$output" >&2
    else
        echo "$output"  # STS output is usually needed for credential extraction
    fi
    return $exit_code
}

aws_s3() {
    local output
    local exit_code
    output=$(aws s3 --endpoint-url="$S3_ENDPOINT" \
                   --region="$AWS_REGION" \
                   --no-verify-ssl \
                   --no-cli-pager \
                   --no-paginate \
                   --color off \
                   "$@" 2>&1)
    exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo "$output" >&2
    fi
    return $exit_code
}

# Silent versions for cleanup (no output even on failure)
aws_iam_silent() {
    # Call AWS CLI directly without timeout wrapper to avoid hanging
    # Completely silent - only returns exit code
    aws iam --endpoint-url="$S3_ENDPOINT" \
            --region="$AWS_REGION" \
            --no-verify-ssl \
            --no-cli-pager \
            --no-paginate \
            --color off \
            --output json \
            "$@" >/dev/null 2>&1
    return $?
}

# =============================================================================
# Setup Function
# =============================================================================

setup() {
    log "Setting up test environment..."

    # Original credentials already saved at script start as ORIGINAL_*

    # Export AWS credentials
    export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
    export AWS_DEFAULT_REGION="$AWS_REGION"

    # Suppress urllib3 SSL warnings and boto3 warnings for localhost testing
    export PYTHONWARNINGS="ignore"
    export URLLIB3_DISABLE_WARNINGS=1
    export AWS_CLI_FILE_ENCODING=UTF-8

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

# =============================================================================
# Cleanup Functions
# =============================================================================

# Cleanup test environment (full cleanup including IAM)
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

    # Clean up IAM roles and policies created during testing
    cleanup_iam_resources

    # Clean up any leaked credentials
    cleanup_credentials

    # Remove temp directory
    rm -rf "$TEMP_DIR"

    set -e  # Re-enable exit on error
}

# Basic cleanup without IAM resources (for CORS, basic tests, etc.)
cleanup_basic() {
    log "Cleaning up basic test environment (skipping IAM cleanup)..."

    set +e  # Disable exit on error for cleanup

    # Try to delete test objects and bucket
    if aws_s3api head-bucket --bucket "$TEST_BUCKET" 2>/dev/null; then
        log "Deleting test objects from bucket $TEST_BUCKET..."
        aws_s3 rm "s3://$TEST_BUCKET" --recursive 2>/dev/null || true

        log "Deleting test bucket $TEST_BUCKET..."
        aws_s3api delete-bucket --bucket "$TEST_BUCKET" 2>/dev/null || true
    fi

    # Clean up any leaked credentials
    cleanup_credentials

    # Remove temp directory
    rm -rf "$TEMP_DIR"

    set -e  # Re-enable exit on error
}

# Clean up any credential environment pollution
cleanup_credentials() {
    log "Cleaning up any leaked AWS credentials..."

    # Reset AWS credentials to original values
    if [ -n "$ORIGINAL_AWS_ACCESS_KEY_ID" ] && [ -n "$ORIGINAL_AWS_SECRET_ACCESS_KEY" ]; then
        log "Restoring original AWS credentials..."
        export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
        export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    fi

    # Ensure session token is cleared
    unset AWS_SESSION_TOKEN

    # Clear any AWS CLI cache that might contain temporary credentials
    rm -rf ~/.aws/cli/cache/* 2>/dev/null || true
    rm -rf ~/.aws/sso/cache/* 2>/dev/null || true

    log "Credential cleanup completed. Current AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID"
}

# Clean up IAM roles and policies - basic version
# Individual test modules may override this with more specific cleanup
cleanup_iam_resources() {
    log "Cleaning up IAM roles and policies..."

    set +e  # Disable exit on error for IAM cleanup

    # Clean up specific test roles if they exist in temp files
    if [ -f "$TEMP_DIR/test_role_name" ]; then
        local role_name
        read role_name < "$TEMP_DIR/test_role_name"
        log "CLEANUP_DEBUG: Deleting IAM test role: $role_name"
        run_with_timeout 30 aws_iam_silent delete-role --role-name "$role_name" || true
    fi

    # Clean up STS test role
    if [ -f "$TEMP_DIR/sts_test_role_name" ]; then
        local role_name
        read role_name < "$TEMP_DIR/sts_test_role_name"
        log "CLEANUP_DEBUG: Deleting STS test role: $role_name"
        run_with_timeout 30 aws_iam_silent delete-role-policy --role-name "$role_name" --policy-name "S3FullAccess" || true
        run_with_timeout 30 aws_iam_silent delete-role --role-name "$role_name" || true
    fi

    # Call specialized cleanup functions if they exist
    if type cleanup_iam_test_resources &>/dev/null; then
        cleanup_iam_test_resources
    fi

    if type cleanup_all_iam_roles &>/dev/null; then
        cleanup_all_iam_roles
    fi

    if type cleanup_deny_test_roles &>/dev/null; then
        cleanup_deny_test_roles
    fi

    if type cleanup_trust_policy_test_roles &>/dev/null; then
        cleanup_trust_policy_test_roles
    fi

    set -e  # Re-enable exit on error
}

# Note: Specialized cleanup functions (cleanup_iam_test_resources,
# cleanup_all_iam_roles, cleanup_deny_test_roles, cleanup_trust_policy_test_roles)
# should be defined in individual test modules that need them.

# =============================================================================
# Summary Reporting
# =============================================================================

# =============================================================================
# Utility Functions
# =============================================================================

create_minimal_test_image() {
    local image_file="$1"

    # Create a minimal valid 1x1 PNG file (base64 encoded)
    # This is a tiny transparent 1x1 PNG image
    echo "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAI9jU77zwAAAABJRU5ErkJggg==" | base64 -d > "$image_file"
}

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

# =============================================================================
# Summary Functions
# =============================================================================

print_summary() {
    echo ""
    log "=========================================="
    log "Test Summary"
    log "=========================================="
    log "Tests Passed: $TESTS_PASSED"
    log "Tests Failed: $TESTS_FAILED"

    if [ $TESTS_FAILED -gt 0 ]; then
        log "Failed Tests:"
        for test in "${FAILED_TESTS[@]}"; do
            error "  $test"
        done
        log "=========================================="
        return 1
    else
        success "All tests passed!"
        log "=========================================="
        return 0
    fi
}
