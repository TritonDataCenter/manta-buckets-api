#!/bin/bash
# Copyright 2025 Edgecast Cloud LLC.
# S3cmd ACL Compatibility Test Script for manta-buckets-api
# Tests S3 ACL functionality using s3cmd
#
# Based on s3-compat-test.sh but focuses on ACL operations

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration variables (can be overridden via environment)
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-"AKIA123456789EXAMPLE"}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
S3_ENDPOINT=${S3_ENDPOINT:-"https://localhost:8080"}
AWS_REGION=${AWS_REGION:-"us-east-1"}

# Test configuration
TEST_BUCKET="s3cmd-acl-test-$(date +%s)"
TEST_OBJECT="test-object.txt"
TEST_CONTENT="Hello, S3 World! This is a test file for s3cmd ACL compatibility."
TEMP_DIR="/tmp/s3cmd-acl-test"
S3CMD_CONFIG="$TEMP_DIR/.s3cfg"

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

# s3cmd wrapper with our configuration
s3cmd_exec() {
    s3cmd -c "$S3CMD_CONFIG" "$@"
}

# Setup test environment
setup() {
    log "Setting up test environment..."
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    # Create s3cmd configuration file
    cat > "$S3CMD_CONFIG" << EOF
[default]
access_key = $AWS_ACCESS_KEY_ID
secret_key = $AWS_SECRET_ACCESS_KEY
host_base = ${S3_ENDPOINT#https://}
host_bucket = ${S3_ENDPOINT#https://}
use_https = True
check_ssl_certificate = False
signature_v2 = False
EOF
    
    # Create test file
    echo "$TEST_CONTENT" > "$TEST_OBJECT"
    
    log "Test configuration:"
    log "  Endpoint: $S3_ENDPOINT"
    log "  Access Key: ${AWS_ACCESS_KEY_ID:0:10}..."
    log "  Region: $AWS_REGION"
    log "  Test Bucket: $TEST_BUCKET"
    log "  Test Object: $TEST_OBJECT"
    log "  s3cmd config: $S3CMD_CONFIG"
}

# Cleanup test environment
cleanup() {
    log "Cleaning up test environment..."
    
    set +e  # Disable exit on error for cleanup
    
    # Try to delete test objects and bucket
    if s3cmd_exec ls "s3://$TEST_BUCKET" 2>/dev/null; then
        log "Deleting test objects from bucket $TEST_BUCKET..."
        s3cmd_exec del "s3://$TEST_BUCKET" --recursive 2>/dev/null || true
        
        log "Deleting test bucket $TEST_BUCKET..."
        s3cmd_exec rb "s3://$TEST_BUCKET" 2>/dev/null || true
    fi
    
    # Remove temp directory
    rm -rf "$TEMP_DIR"
    
    set -e  # Re-enable exit on error
}

# Test functions
test_s3cmd_connectivity() {
    log "Testing: s3cmd Connectivity"
    
    set +e  # Temporarily disable exit on error
    result=$(s3cmd_exec ls 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        success "s3cmd connectivity - Successfully connected to S3 endpoint"
    else
        error "s3cmd connectivity - Failed to connect: $result"
        return 1
    fi
}

test_create_bucket() {
    log "Testing: Create Bucket with s3cmd"
    
    set +e  # Temporarily disable exit on error
    result=$(s3cmd_exec mb "s3://$TEST_BUCKET" 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        success "Create bucket - $TEST_BUCKET created successfully"
    else
        error "Create bucket - Failed to create $TEST_BUCKET: $result"
        return 1
    fi
}

test_put_object_with_acl() {
    log "Testing: Put Object with Default ACL"
    
    set +e  # Temporarily disable exit on error
    result=$(s3cmd_exec put "$TEST_OBJECT" "s3://$TEST_BUCKET/" 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        success "Put object - $TEST_OBJECT uploaded successfully"
    else
        error "Put object - Failed to upload $TEST_OBJECT: $result"
        return 1
    fi
}

test_get_bucket_acl() {
    log "Testing: Get Bucket ACL"
    
    set +e  # Temporarily disable exit on error
    result=$(s3cmd_exec info "s3://$TEST_BUCKET" 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        success "Get bucket ACL - Retrieved bucket info successfully"
        log "  Bucket info: $result"
    else
        error "Get bucket ACL - Failed to get bucket info: $result"
    fi
}

test_get_object_acl() {
    log "Testing: Get Object ACL"
    
    set +e  # Temporarily disable exit on error
    result=$(s3cmd_exec info "s3://$TEST_BUCKET/$TEST_OBJECT" 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        success "Get object ACL - Retrieved object info successfully"
        log "  Object info: $result"
    else
        error "Get object ACL - Failed to get object info: $result"
    fi
}

test_put_object_with_canned_acl() {
    local acl_type="$1"
    local test_file="acl-test-$acl_type.txt"
    
    log "Testing: Put Object with Canned ACL ($acl_type)"
    
    # Create test file
    echo "Test content for $acl_type ACL" > "$test_file"
    
    set +e  # Temporarily disable exit on error
    result=$(s3cmd_exec put "$test_file" "s3://$TEST_BUCKET/" --acl-$acl_type 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        success "Put object with $acl_type ACL - Upload successful"
        
        # Try to get info about the object to verify ACL was set
        set +e
        info_result=$(s3cmd_exec info "s3://$TEST_BUCKET/$test_file" 2>&1)
        local info_exit_code=$?
        set -e
        
        if [ $info_exit_code -eq 0 ]; then
            success "Put object with $acl_type ACL - Object info retrieved"
            log "  Object with $acl_type ACL info: $info_result"
        else
            warning "Put object with $acl_type ACL - Could not retrieve object info: $info_result"
        fi
    else
        error "Put object with $acl_type ACL - Failed to upload: $result"
    fi
    
    # Cleanup test file
    rm -f "$test_file"
}

test_setacl_bucket() {
    log "Testing: Set Bucket ACL"
    
    set +e  # Temporarily disable exit on error
    result=$(s3cmd_exec setacl "s3://$TEST_BUCKET" --acl-private 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        success "Set bucket ACL - Successfully set private ACL on bucket"
    else
        error "Set bucket ACL - Failed to set private ACL: $result"
    fi
}

test_setacl_object() {
    log "Testing: Set Object ACL"
    
    set +e  # Temporarily disable exit on error
    result=$(s3cmd_exec setacl "s3://$TEST_BUCKET/$TEST_OBJECT" --acl-private 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        success "Set object ACL - Successfully set private ACL on object"
    else
        error "Set object ACL - Failed to set private ACL: $result"
    fi
}

test_canned_acls() {
    log "Testing: Various Canned ACLs"
    
    # Test different canned ACL types that s3cmd supports
    local acl_types=("private" "public-read" "public-read-write")
    
    for acl in "${acl_types[@]}"; do
        test_put_object_with_canned_acl "$acl"
    done
}

test_acl_bucket_policy() {
    log "Testing: Bucket ACL Policy Operations"
    
    # Try to set bucket to public-read
    set +e  # Temporarily disable exit on error
    result=$(s3cmd_exec setacl "s3://$TEST_BUCKET" --acl-public-read 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        success "Bucket ACL policy - Successfully set public-read ACL on bucket"
        
        # Verify the ACL was set by getting bucket info
        set +e
        info_result=$(s3cmd_exec info "s3://$TEST_BUCKET" 2>&1)
        local info_exit_code=$?
        set -e
        
        if [ $info_exit_code -eq 0 ]; then
            success "Bucket ACL policy - Retrieved bucket info after ACL change"
            log "  Bucket info after ACL change: $info_result"
        else
            warning "Bucket ACL policy - Could not retrieve bucket info: $info_result"
        fi
        
        # Set back to private
        set +e
        s3cmd_exec setacl "s3://$TEST_BUCKET" --acl-private 2>/dev/null || true
        set -e
    else
        error "Bucket ACL policy - Failed to set public-read ACL: $result"
    fi
}

test_list_with_acl_info() {
    log "Testing: List Objects with ACL Information"
    
    set +e  # Temporarily disable exit on error
    result=$(s3cmd_exec ls "s3://$TEST_BUCKET" --long 2>&1)
    local exit_code=$?
    set -e  # Re-enable exit on error
    
    if [ $exit_code -eq 0 ]; then
        if echo "$result" | grep -q "$TEST_OBJECT"; then
            success "List with ACL info - Object listing successful"
            log "  Object listing: $result"
        else
            error "List with ACL info - Object not found in listing: $result"
        fi
    else
        error "List with ACL info - Failed to list objects: $result"
    fi
}

# Main test execution
run_tests() {
    log "Starting S3cmd ACL Compatibility Tests for manta-buckets-api"
    log "============================================================"
    
    set +e  # Disable exit on error for test execution
    
    # Basic connectivity and setup
    test_s3cmd_connectivity || true
    test_create_bucket || true
    test_put_object_with_acl || true
    
    # ACL-specific tests
    test_get_bucket_acl || true
    test_get_object_acl || true
    test_setacl_bucket || true
    test_setacl_object || true
    test_canned_acls || true
    test_acl_bucket_policy || true
    test_list_with_acl_info || true
    
    set -e  # Re-enable exit on error
}

# Print test results
print_results() {
    log "============================================================"
    log "Test Results Summary"
    log "============================================================"
    
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
        echo -e "\n${GREEN}🎉 All ACL tests passed! s3cmd ACL compatibility is working correctly.${NC}"
        exit 0
    fi
}

# Main execution
main() {
    # Handle command line arguments
    case "${1:-}" in
        -h|--help)
            echo "S3cmd ACL Compatibility Test Script for manta-buckets-api"
            echo
            echo "Usage: $0 [options]"
            echo
            echo "Environment variables:"
            echo "  AWS_ACCESS_KEY_ID     - AWS access key (default: AKIA123456789EXAMPLE)"
            echo "  AWS_SECRET_ACCESS_KEY - AWS secret key (default: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)"
            echo "  S3_ENDPOINT          - S3 endpoint URL (default: https://localhost:8080)"
            echo "  AWS_REGION           - AWS region (default: us-east-1)"
            echo
            echo "Examples:"
            echo "  $0"
            echo "  AWS_ACCESS_KEY_ID=mykey AWS_SECRET_ACCESS_KEY=mysecret $0"
            echo "  S3_ENDPOINT=https://manta.example.com:8080 $0"
            exit 0
            ;;
        *)
            ;;
    esac
    
    # Check if s3cmd is available
    if ! command -v s3cmd &> /dev/null; then
        echo -e "${RED}Error: s3cmd is not installed or not in PATH${NC}"
        echo "Please install s3cmd before running this test script."
        echo "On Ubuntu/Debian: sudo apt-get install s3cmd"
        echo "On CentOS/RHEL/Rocky: sudo yum install s3cmd"
        echo "Using pip: pip install s3cmd"
        exit 1
    fi
    
    # Set up trap for cleanup
    trap cleanup EXIT
    
    # Run the tests
    setup
    run_tests
    print_results
}

# Execute main function
main "$@"