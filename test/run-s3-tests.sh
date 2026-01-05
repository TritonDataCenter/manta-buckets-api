#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# S3 Compatibility Test Suite - Test Runner
#
# Runs modular S3 compatibility test suites with flexible execution modes.
#
# Usage:
#   ./run-s3-tests.sh [OPTIONS] [MODULE...]
#
# Options:
#   -h, --help              Show this help message
#   -l, --list              List all available test modules
#   -a, --all               Run all test modules (default)
#   -p, --parallel          Run tests in parallel (experimental)
#   -v, --verbose           Verbose output
#
# Examples:
#   ./run-s3-tests.sh                           # Run all tests sequentially
#   ./run-s3-tests.sh basic-operations          # Run specific module
#   ./run-s3-tests.sh basic-operations multipart # Run multiple modules
#   ./run-s3-tests.sh --list                    # List all modules

set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global counters
TOTAL_MODULES=0
MODULES_PASSED=0
MODULES_FAILED=0
FAILED_MODULES=()

# Test module definitions (in execution order)
declare -a TEST_MODULES=(
    "s3-basic-operations-test.sh"
    "s3-bulk-delete-test.sh"
    "s3-copy-conditional-test.sh"
    "s3-multipart-upload-test.sh"
    "s3-object-tagging-test.sh"
    "s3-cors-test.sh"
    "s3-presigned-url-test.sh"
    "s3-sigv4-auth-test.sh"
    "s3-acl-access-test.sh"
    "s3-aws-chunked-test.sh"
    "iam-role-management-test.sh"
    "iam-policy-test.sh"
    "sts-operations-test.sh"
    "iam-sts-integration-test.sh"
    "iam-trust-policy-test.sh"
)

# Get module description (bash 3.2 compatible)
get_module_description() {
    local module="$1"
    case "$module" in
        s3-basic-operations-test.sh)
            echo "S3 Basic Operations (bucket/object CRUD, checksums)" ;;
        s3-bulk-delete-test.sh)
            echo "S3 Bulk Delete Operations" ;;
        s3-copy-conditional-test.sh)
            echo "S3 Copy and Conditional Operations" ;;
        s3-multipart-upload-test.sh)
            echo "S3 Multipart Upload" ;;
        s3-object-tagging-test.sh)
            echo "S3 Object Tagging" ;;
        s3-cors-test.sh)
            echo "S3 CORS Configuration" ;;
        s3-presigned-url-test.sh)
            echo "S3 Presigned URLs" ;;
        s3-sigv4-auth-test.sh)
            echo "S3 SigV4 Authentication Errors" ;;
        s3-acl-access-test.sh)
            echo "S3 ACL and Access Control" ;;
        s3-aws-chunked-test.sh)
            echo "S3 AWS Chunked Encoding with Signature Verification" ;;
        iam-role-management-test.sh)
            echo "IAM Role Management" ;;
        iam-policy-test.sh)
            echo "IAM Permission Policies" ;;
        sts-operations-test.sh)
            echo "STS Operations" ;;
        iam-sts-integration-test.sh)
            echo "IAM-STS Integration" ;;
        iam-trust-policy-test.sh)
            echo "IAM Trust Policies" ;;
        *)
            echo "Unknown module" ;;
    esac
}

# =============================================================================
# Helper Functions
# =============================================================================

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}$1${NC}"
}

error() {
    echo -e "${RED}$1${NC}"
}

warning() {
    echo -e "${YELLOW}$1${NC}"
}

show_help() {
    cat << EOF
S3 Compatibility Test Suite - Test Runner

Usage:
  $0 [OPTIONS] [MODULE...]

Options:
  -h, --help              Show this help message
  -l, --list              List all available test modules
  -a, --all               Run all test modules (default)
  -p, --parallel          Run tests in parallel (experimental)
  -v, --verbose           Verbose output

Module Names (short form - omit 'test.sh' suffix):
  basic-operations        S3 basic operations
  bulk-delete             S3 bulk delete
  copy-conditional        S3 copy and conditional operations
  multipart-upload        S3 multipart upload
  object-tagging          S3 object tagging
  cors                    S3 CORS configuration
  presigned-url           S3 presigned URLs
  sigv4-auth              S3 SigV4 authentication
  acl-access              S3 ACL and access control
  aws-chunked             S3 AWS chunked encoding with signature verification
  iam-role-management     IAM role management
  iam-policy              IAM permission policies
  sts-operations          STS operations
  iam-sts-integration     IAM-STS integration
  iam-trust-policy        IAM trust policies

Examples:
  $0                                    # Run all tests sequentially
  $0 --list                             # List all modules
  $0 basic-operations                   # Run specific module
  $0 basic-operations multipart-upload  # Run multiple modules
  $0 --all --verbose                    # Run all with verbose output

EOF
}

list_modules() {
    log "Available Test Modules:"
    echo ""
    for module in "${TEST_MODULES[@]}"; do
        local desc=$(get_module_description "$module")
        printf "  %-35s - %s\n" "$module" "$desc"
    done
    echo ""
}

# Convert short name to full filename
get_module_filename() {
    local short_name="$1"
    
    case "$short_name" in
        basic-operations|s3-basic-operations-test.sh)
            echo "s3-basic-operations-test.sh" ;;
        bulk-delete|s3-bulk-delete-test.sh)
            echo "s3-bulk-delete-test.sh" ;;
        copy-conditional|s3-copy-conditional-test.sh)
            echo "s3-copy-conditional-test.sh" ;;
        multipart-upload|multipart|s3-multipart-upload-test.sh)
            echo "s3-multipart-upload-test.sh" ;;
        object-tagging|tagging|s3-object-tagging-test.sh)
            echo "s3-object-tagging-test.sh" ;;
        cors|s3-cors-test.sh)
            echo "s3-cors-test.sh" ;;
        presigned-url|presigned|s3-presigned-url-test.sh)
            echo "s3-presigned-url-test.sh" ;;
        sigv4-auth|sigv4|s3-sigv4-auth-test.sh)
            echo "s3-sigv4-auth-test.sh" ;;
        acl-access|acl|s3-acl-access-test.sh)
            echo "s3-acl-access-test.sh" ;;
        aws-chunked|s3-aws-chunked-test.sh)
            echo "s3-aws-chunked-test.sh" ;;
        iam-role-management|iam-role|iam-role-management-test.sh)
            echo "iam-role-management-test.sh" ;;
        iam-policy|iam-policy-test.sh)
            echo "iam-policy-test.sh" ;;
        sts-operations|sts|sts-operations-test.sh)
            echo "sts-operations-test.sh" ;;
        iam-sts-integration|iam-sts|iam-sts-integration-test.sh)
            echo "iam-sts-integration-test.sh" ;;
        iam-trust-policy|trust-policy|iam-trust-policy-test.sh)
            echo "iam-trust-policy-test.sh" ;;
        *)
            echo "" ;;
    esac
}

# =============================================================================
# Test Execution Functions
# =============================================================================

run_test_module() {
    local module="$1"
    local module_path="$SCRIPT_DIR/test-scripts/$module"

    if [ ! -f "$module_path" ]; then
        error "Module not found: $module"
        return 1
    fi

    if [ ! -x "$module_path" ]; then
        chmod +x "$module_path"
    fi

    log "Running: $module"
    local desc=$(get_module_description "$module")
    echo "  Description: $desc"
    echo ""
    
    ((TOTAL_MODULES++))
    
    # Run the test module and capture exit code
    set +e
    "$module_path"
    local exit_code=$?
    set -e
    
    echo ""
    
    if [ $exit_code -eq 0 ]; then
        ((MODULES_PASSED++))
        success "Module passed: $module"
    else
        ((MODULES_FAILED++))
        FAILED_MODULES+=("$module")
        error "Module failed: $module (exit code: $exit_code)"
    fi
    
    echo ""
    echo "=========================================="
    echo ""
    
    return $exit_code
}

run_all_modules_sequential() {
    log "Running all test modules sequentially..."
    echo ""
    
    local continue_on_error=true
    
    for module in "${TEST_MODULES[@]}"; do
        set +e
        run_test_module "$module"
        local result=$?
        set -e
        
        # Continue running even if a module fails
        if [ $result -ne 0 ] && [ "$continue_on_error" = false ]; then
            error "Stopping due to module failure"
            break
        fi
    done
}

run_selected_modules() {
    local modules=("$@")
    
    log "Running selected test modules..."
    echo ""
    
    for module_arg in "${modules[@]}"; do
        local module=$(get_module_filename "$module_arg")
        
        if [ -z "$module" ]; then
            error "Unknown module: $module_arg"
            continue
        fi
        
        set +e
        run_test_module "$module"
        set -e
    done
}

# =============================================================================
# Summary Reporting
# =============================================================================

print_summary() {
    echo ""
    log "=========================================="
    log "Test Suite Summary"
    log "=========================================="
    echo ""
    
    echo "Total Modules Run: $TOTAL_MODULES"
    success "Modules Passed: $MODULES_PASSED"
    
    if [ $MODULES_FAILED -gt 0 ]; then
        error "Modules Failed: $MODULES_FAILED"
        echo ""
        error "Failed Modules:"
        for module in "${FAILED_MODULES[@]}"; do
            echo "  - $module"
        done
    fi
    
    echo ""
    log "=========================================="
    
    if [ $MODULES_FAILED -eq 0 ]; then
        success "All test modules passed!"
        return 0
    else
        error "Some test modules failed"
        return 1
    fi
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    local run_all=true
    local run_parallel=false
    local verbose=false
    local selected_modules=()
    
    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -l|--list)
                list_modules
                exit 0
                ;;
            -a|--all)
                run_all=true
                shift
                ;;
            -p|--parallel)
                run_parallel=true
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -*)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                # Module name
                run_all=false
                selected_modules+=("$1")
                shift
                ;;
        esac
    done
    
    # Print header
    echo ""
    log "=========================================="
    log "S3 Compatibility Test Suite Runner"
    log "=========================================="
    echo ""
    
    # Execute tests
    if [ "$run_all" = true ]; then
        if [ "$run_parallel" = true ]; then
            warning "Parallel execution not yet implemented, running sequentially"
        fi
        run_all_modules_sequential
    else
        run_selected_modules "${selected_modules[@]}"
    fi
    
    # Print summary and exit with appropriate code
    print_summary
    exit $?
}

main "$@"
