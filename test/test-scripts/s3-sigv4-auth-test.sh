#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# S3 Compatibility Test - SigV4 Authentication Error Handling
#
# Tests S3 signature version 4 authentication error scenarios:
# - Invalid signature formats
# - Malformed authorization headers
# - Invalid credential formats
# - Missing required parameters

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Functions
# =============================================================================

test_sigv4_auth_errors() {
    log "Testing: SigV4 Authentication Error Handling "
    
    local auth_test_bucket="auth-test-$(date +%s)"

    # Test 1: Missing date header
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
    
    # Test 2: InvalidSignature/SignatureDoesNotMatch error case
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
    
    # Test 3: AccessKeyNotFound error case
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
    
    # Test 4: RequestTimeTooSkewed error case  
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
    
    # Test 5: Default authentication failure case
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

    # Test 6: PUT request with application/x-directory content-type and invalid auth
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

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "=========================================="
    log "S3 SigV4 Authentication Error Test Suite"
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

    # Run test
    test_sigv4_auth_errors

    cleanup_basic
    print_summary
}

main
