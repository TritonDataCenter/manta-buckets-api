# S3 Compatibility Test Suite

Modular test suite for S3 API compatibility testing.

## Overview

This test suite verifies S3 API compatibility through independent, focused test modules. Each module tests a specific area of S3 functionality and can be run independently or as part of the complete suite.

## Quick Start

```bash
# Run all tests
./run-s3-tests.sh

# Run specific module
./run-s3-tests.sh basic-operations

# List all modules
./run-s3-tests.sh --list

# Get help
./run-s3-tests.sh --help
```

## Test Modules (14 total, 96 tests)

**S3 Core Operations:**
- `s3-basic-operations-test.sh` (13 tests) - Bucket/object CRUD, checksums
- `s3-bulk-delete-test.sh` (5 tests) - Bulk delete operations
- `s3-copy-conditional-test.sh` (2 tests) - Server-side copy, conditional headers
- `s3-multipart-upload-test.sh` (3 tests) - Multipart upload workflow
- `s3-object-tagging-test.sh` (4 tests) - Object tagging
- `s3-cors-test.sh` (2 tests) - CORS configuration
- `s3-presigned-url-test.sh` (4 tests) - Presigned URLs

**Authentication & Authorization:**
- `s3-sigv4-auth-test.sh` (1 test) - SigV4 authentication errors
- `s3-acl-access-test.sh` (11 tests) - ACL and access control

**IAM & STS:**
- `iam-role-management-test.sh` (11 tests) - IAM role operations
- `iam-policy-test.sh` (7 tests) - Permission policy enforcement
- `sts-operations-test.sh` (8 tests) - STS operations
- `iam-sts-integration-test.sh` (6 tests) - IAM-STS integration
- `iam-trust-policy-test.sh` (19 tests) - Trust policy validation

## Configuration

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export S3_ENDPOINT="http://localhost:8080"
export AWS_REGION="us-east-1"  # Optional, default: us-east-1
```

## Running Tests

### All Tests
```bash
./run-s3-tests.sh
```

### Specific Modules
```bash
./run-s3-tests.sh basic-operations
./run-s3-tests.sh multipart-upload cors
```

### Individual Module
```bash
./s3-basic-operations-test.sh
./iam-role-management-test.sh
```

## Module Short Names

Use these names with the test runner:
- `basic-operations`, `bulk-delete`, `copy-conditional`
- `multipart-upload` or `multipart`
- `object-tagging` or `tagging`
- `cors`, `presigned-url` or `presigned`
- `sigv4-auth` or `sigv4`
- `acl-access` or `acl`
- `iam-role-management` or `iam-role`
- `iam-policy`, `sts-operations` or `sts`
- `iam-sts-integration` or `iam-sts`
- `iam-trust-policy` or `trust-policy`

## Common Library

All modules use `lib/s3-test-common.sh` which provides:
- AWS CLI wrappers (`aws_s3api`, `aws_iam`, `aws_sts`)
- Utility functions (`log`, `success`, `error`, `warning`)
- Setup/cleanup functions
- Summary reporting

## Migration from Monolithic Suite

The original `s3-compat-awscli-test.sh` (12,045 lines) has been refactored into 14 focused modules.

**Status:** The monolithic test file has been deprecated and renamed to `s3-compat-awscli-test.sh.deprecated`. It is preserved for reference only and will be removed in a future release.

**Benefits:**
- Faster development (changes isolated to specific modules)
- Easier debugging (run only relevant tests)
- Better organization (tests grouped by function)
- Smaller context (each module 200-5000 lines)

**Equivalent commands:**
```bash
# Old (DEPRECATED - no longer maintained)
./s3-compat-awscli-test.sh.deprecated

# New (Use this instead)
./run-s3-tests.sh --all
```

## CI/CD Integration

```bash
# GitHub Actions / Jenkins
cd test
./run-s3-tests.sh --all
```

## Development

### Adding Tests

1. Add to existing module or create new module
2. Follow pattern: source common library, implement main()
3. Use common library functions for consistency
4. Update `run-s3-tests.sh` if creating new module

### Module Template

```bash
#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

test_my_feature() {
    log "Testing feature..."
    # Test implementation
    success "Feature works!"
}

main() {
    log "=========================================="
    log "My Test Suite"
    log "=========================================="
    setup
    test_my_feature
    cleanup_basic
    print_summary
}

main
```

## License

Copyright 2025 Edgecast Cloud LLC.
