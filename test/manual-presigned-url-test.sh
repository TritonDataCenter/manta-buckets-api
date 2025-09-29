#!/bin/bash
# Copyright 2025 Edgecast Cloud LLC.
# S3 Presigned URL Manual Testing Script (SigV4 only)
#
# This script manually crafts S3 Signature v4 presigned URLs and tests them
# against manta-buckets-api to verify presigned URL functionality works correctly.

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration variables (can be overridden via environment)
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-"AKIA123456789EXAMPLE"}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
S3_ENDPOINT=${S3_ENDPOINT:-"https://localhost:8080"}
AWS_REGION=${AWS_REGION:-"us-east-1"}

# Test configuration
TEST_BUCKET="presigned-test-$(date +%s)"
TEST_OBJECT="test-object.txt"
TEST_CONTENT="Hello from presigned URL test!"
TEMP_DIR="/tmp/presigned-url-test"

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

# Create S3v4 presigned URL (fixed signature calculation)
create_s3v4_presigned_url() {
    local method="$1"
    local bucket="$2"
    local key="$3"
    local expires="$4"
    local access_key="$5"
    local secret_key="$6"
    local region="$7"
    
    # Generate timestamps
    local now=$(date -u +"%Y%m%dT%H%M%SZ")
    local date_stamp=$(echo "$now" | cut -c1-8)
    local amz_date="$now"
    
    # Build credential
    local credential="${access_key}/${date_stamp}/${region}/s3/aws4_request"
    local signed_headers="host"
    
    # Extract host from endpoint (fixed)
    local host=$(echo "$S3_ENDPOINT" | sed 's|^https://||' | sed 's|^http://||' | sed 's|/.*$||')
    
    # Build canonical URI
    local canonical_uri="/${bucket}/${key}"
    
    # Build canonical query string parameters (NOT URL encoded yet)
    local params="X-Amz-Algorithm=AWS4-HMAC-SHA256"
    params="${params}&X-Amz-Credential=${credential}"
    params="${params}&X-Amz-Date=${amz_date}"
    params="${params}&X-Amz-Expires=${expires}"
    params="${params}&X-Amz-SignedHeaders=${signed_headers}"
    
    # URL encode the canonical query string properly
    local canonical_querystring=$(echo "$params" | sed 's|/|%2F|g')
    
    # Build canonical headers (must end with newline)
    local canonical_headers="host:${host}
"
    
    # Build canonical request
    local canonical_request="${method}
${canonical_uri}
${canonical_querystring}
${canonical_headers}
${signed_headers}
UNSIGNED-PAYLOAD"
    
    # Create string to sign
    local algorithm="AWS4-HMAC-SHA256"
    local credential_scope="${date_stamp}/${region}/s3/aws4_request"
    local canonical_request_hash=$(echo -n "$canonical_request" | openssl dgst -sha256 -hex | cut -d' ' -f2)
    
    local string_to_sign="${algorithm}
${amz_date}
${credential_scope}
${canonical_request_hash}"
    
    # HMAC helper functions
    hmac_sha256() {
        local key="$1"
        local data="$2"
        echo -n "$data" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$key" -binary | xxd -p -c 256
    }

    hmac_sha256_string() {
        local key="$1"
        local data="$2"
        echo -n "$data" | openssl dgst -sha256 -mac HMAC -macopt key:"$key" -binary | xxd -p -c 256
    }

    # Calculate signature using fixed HMAC chain
    local kDate=$(hmac_sha256_string "AWS4${secret_key}" "$date_stamp")
    local kRegion=$(hmac_sha256 "$kDate" "$region")
    local kService=$(hmac_sha256 "$kRegion" "s3")
    local kSigning=$(hmac_sha256 "$kService" "aws4_request")
    local signature=$(echo -n "$string_to_sign" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$kSigning" -hex | cut -d' ' -f2)
    
    # Build final URL
    local final_url="${S3_ENDPOINT}/${bucket}/${key}?${canonical_querystring}&X-Amz-Signature=${signature}"
    echo "$final_url"
}

# Make HTTP request to test presigned URL
test_presigned_url() {
    local url="$1"
    local method="$2"
    local body_file="$3"
    local output_file="${4:-}"
    
    local curl_args=("-s" "-w" "%{http_code}" "-X" "$method" "--insecure")
    
    if [ -n "$body_file" ] && [ -f "$body_file" ]; then
        curl_args+=("--data-binary" "@$body_file")
    fi
    
    if [ -n "$output_file" ]; then
        curl_args+=("-o" "$output_file")
    fi
    
    curl_args+=("$url")
    
    log "Making $method request to: ${url:0:100}..." >&2
    curl "${curl_args[@]}"
}

# Setup test environment
setup() {
    log "Setting up test environment..."
    
    # Export AWS credentials
    export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
    export AWS_DEFAULT_REGION="$AWS_REGION"
    
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

# Create test bucket using AWS CLI (requires proper authentication)
create_test_bucket() {
    log "Creating test bucket: $TEST_BUCKET"
    
    # Check if AWS CLI is available
    if ! command -v aws >/dev/null 2>&1; then
        error "AWS CLI is required but not installed. Please install aws-cli."
        return 1
    fi
    
    # Use AWS CLI to create bucket (handles authentication properly)
    set +e
    local result=$(aws s3api create-bucket \
        --bucket "$TEST_BUCKET" \
        --endpoint-url "$S3_ENDPOINT" \
        --region "$AWS_REGION" \
        --no-verify-ssl \
        --no-cli-pager 2>&1)
    local exit_code=$?
    set -e
    
    if [ $exit_code -eq 0 ]; then
        success "Test bucket created: $TEST_BUCKET"
        return 0
    else
        error "Failed to create test bucket: $result"
        return 1
    fi
}

# Test S3v4 presigned URL
test_s3v4_presigned_url() {
    log "Testing S3 Signature v4 presigned URL..."
    
    # Create presigned URL for PUT
    local put_url=$(create_s3v4_presigned_url "PUT" "$TEST_BUCKET" "$TEST_OBJECT" "300" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$AWS_REGION")
    
    log "Generated S3v4 PUT URL: ${put_url:0:150}..."
    
    # Test PUT operation
    local put_response=$(test_presigned_url "$put_url" "PUT" "$TEST_OBJECT" "")
    local put_http_code="${put_response: -3}"
    
    if [ "$put_http_code" -ge 200 ] && [ "$put_http_code" -lt 300 ]; then
        success "S3v4 presigned PUT - Object uploaded successfully"
        
        # Create presigned URL for GET
        local get_url=$(create_s3v4_presigned_url "GET" "$TEST_BUCKET" "$TEST_OBJECT" "300" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$AWS_REGION")
        
        log "Generated S3v4 GET URL: ${get_url:0:150}..."
        
        # Test GET operation
        local download_file="downloaded-$TEST_OBJECT"
        local get_response=$(test_presigned_url "$get_url" "GET" "" "$download_file")
        local get_http_code="$get_response"
        
        if [ "$get_http_code" = "200" ]; then
            if [ -f "$download_file" ]; then
                local get_body=$(cat "$download_file")
                if [ "$get_body" = "$TEST_CONTENT" ]; then
                    success "S3v4 presigned GET - Downloaded content matches uploaded content"
                else
                    error "S3v4 presigned GET - Content mismatch. Expected: '$TEST_CONTENT', Got: '$get_body'"
                fi
                rm -f "$download_file"
            else
                error "S3v4 presigned GET - Download file not created"
            fi
        else
            error "S3v4 presigned GET - Failed with status $get_http_code"
        fi
    else
        error "S3v4 presigned PUT - Failed with status $put_http_code"
    fi
}

# Test expired presigned URL
test_expired_presigned_url() {
    log "Testing expired presigned URL..."
    
    # Create presigned URL that's already expired (negative expires)
    local expired_url=$(create_s3v4_presigned_url "GET" "$TEST_BUCKET" "$TEST_OBJECT" "-300" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$AWS_REGION")
    
    log "Generated expired URL: ${expired_url:0:150}..."
    
    # Test expired URL
    local response=$(test_presigned_url "$expired_url" "GET" "" "")
    local http_code="${response: -3}"
    
    if [ "$http_code" = "403" ] || [ "$http_code" = "400" ]; then
        success "Expired presigned URL - Properly rejected expired URL"
    else
        error "Expired presigned URL - Expected 400/403 but got $http_code"
    fi
}

# Test invalid signature presigned URL
test_invalid_signature_url() {
    log "Testing invalid signature presigned URL..."
    
    # Create valid URL then modify signature
    local valid_url=$(create_s3v4_presigned_url "GET" "$TEST_BUCKET" "$TEST_OBJECT" "300" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$AWS_REGION")
    local invalid_url=$(echo "$valid_url" | sed 's/X-Amz-Signature=[^&]*/X-Amz-Signature=invalidsignature123456789abcdef/')
    
    log "Generated invalid signature URL: ${invalid_url:0:150}..."
    
    # Test invalid URL
    local response=$(test_presigned_url "$invalid_url" "GET" "" "")
    local http_code="${response: -3}"
    
    if [ "$http_code" = "403" ] || [ "$http_code" = "400" ]; then
        success "Invalid signature URL - Properly rejected invalid signature"
    else
        error "Invalid signature URL - Expected 400/403 but got $http_code"
    fi
}

# Clean up test bucket using AWS CLI
cleanup_test_bucket() {
    log "Cleaning up test bucket: $TEST_BUCKET"
    
    set +e  # Disable exit on error for cleanup
    
    # Try to delete objects first using AWS CLI
    aws s3 rm "s3://$TEST_BUCKET" --recursive \
        --endpoint-url "$S3_ENDPOINT" \
        --no-verify-ssl \
        --no-cli-pager 2>/dev/null || true
    
    # Delete bucket using AWS CLI
    aws s3api delete-bucket \
        --bucket "$TEST_BUCKET" \
        --endpoint-url "$S3_ENDPOINT" \
        --no-verify-ssl \
        --no-cli-pager 2>/dev/null || true
    
    log "Test bucket cleaned up: $TEST_BUCKET"
    
    set -e  # Re-enable exit on error
}

# Cleanup test environment
cleanup() {
    log "Cleaning up test environment..."
    
    set +e  # Disable exit on error for cleanup
    
    cleanup_test_bucket
    
    # Remove temp directory
    rm -rf "$TEMP_DIR"
    
    set -e  # Re-enable exit on error
}

# Main test execution
run_tests() {
    log "Starting S3 Presigned URL Manual Tests (SigV4 only)"
    log "================================================="
    
    # Create test bucket
    if ! create_test_bucket; then
        error "Failed to create test bucket. Cannot continue with presigned URL tests."
        return 1
    fi
    
    set +e  # Disable exit on error for test execution
    
    # Run presigned URL tests
    test_s3v4_presigned_url
    test_expired_presigned_url
    test_invalid_signature_url
    
    set -e  # Re-enable exit on error
}

# Print test results
print_results() {
    log "===================================="
    log "S3 Presigned URL Test Results"
    log "===================================="
    
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
        echo -e "\n${GREEN}🎉 All presigned URL tests passed!${NC}"
        exit 0
    fi
}

# Handle command line arguments
case "${1:-}" in
    -h|--help)
        echo "S3 Presigned URL Manual Test Script (SigV4 only)"
        echo
        echo "This script manually crafts S3 Signature v4 presigned URLs and tests them"
        echo "against manta-buckets-api to verify presigned URL functionality."
        echo
        echo "Usage: $0"
        echo
        echo "Environment variables:"
        echo "  AWS_ACCESS_KEY_ID     - AWS access key (default: AKIA123456789EXAMPLE)"
        echo "  AWS_SECRET_ACCESS_KEY - AWS secret key (default: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)"
        echo "  S3_ENDPOINT          - S3 endpoint URL (default: https://localhost:8080)"
        echo "  AWS_REGION           - AWS region (default: us-east-1)"
        echo
        echo "Examples:"
        echo "  $0                    # Run presigned URL tests"
        echo "  AWS_ACCESS_KEY_ID=mykey AWS_SECRET_ACCESS_KEY=mysecret $0"
        echo "  S3_ENDPOINT=https://manta.example.com:8080 $0"
        echo
        echo "Note: This script requires aws-cli, curl and openssl to be available."
        exit 0
        ;;
esac

# Set up trap for cleanup
trap cleanup EXIT

# Main execution
setup
run_tests
print_results