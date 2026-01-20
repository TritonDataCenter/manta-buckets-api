#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# S3 Compatibility Test - Presigned URL Operations
#
# Tests S3 presigned URL functionality:
# - Basic presigned URL generation and access
# - URL expiry validation
# - Invalid date format handling
# - Invalid expires parameter handling

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Functions
# =============================================================================

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

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "=========================================="
    log "S3 Presigned URL Test Suite"
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
    test_aws_cli_presigned_urls
    test_presigned_url_expiry
    test_presigned_invalid_date_format
    test_presigned_invalid_expires

    cleanup_basic
    print_summary
}

main
