#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Per-Bucket Access Key Scope — Multipart Upload Integration Tests
#
# Tests that scope enforcement applies correctly to every phase of
# the S3 multipart upload lifecycle.
#
# Tests:
#   1. CreateMultipartUpload with readwrite scope → allowed
#   2. UploadPart with readwrite scope → allowed
#   3. CompleteMultipartUpload with readwrite scope → allowed
#   4. AbortMultipartUpload with readwrite scope → allowed
#   5. CreateMultipartUpload with read-only scope → denied
#   6. ListMultipartUploads with read scope → allowed
#   7. ListParts with read scope → allowed
#   8. CreateMultipartUpload on unscoped bucket → denied
#
# Prerequisites:
#   - CloudAPI running (CLOUDAPI_URL)
#   - manta-buckets-api running (S3_ENDPOINT)
#   - MANTA_USER, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY set
#   - jq installed

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

CLOUDAPI_URL=${CLOUDAPI_URL:-"https://localhost:8443"}
REPL_WAIT=${REPL_WAIT:-3}

# Test buckets
MPU_BUCKET="scope-mpu-test-$(date +%s)"
MPU_OUTSIDE="scope-mpu-outside-$(date +%s)"

# Key tracking
MPU_RW_KEY_ID=""
MPU_RW_SECRET=""
MPU_RO_KEY_ID=""
MPU_RO_SECRET=""

SDC_ACCOUNT=${SDC_ACCOUNT:-"neirac"}
SDC_URL=${CLOUDAPI_URL:-"https://localhost:8443"}

# =============================================================================
# CloudAPI helpers
# =============================================================================

cloudapi() {
    local method="$1"
    local path="$2"
    shift 2

    local now
    now=$(date -u '+%a, %d %h %Y %H:%M:%S GMT')
    local signature
    signature=$(echo -n "$now" | \
        openssl dgst -sha256 -sign ~/.ssh/id_rsa | \
        openssl enc -e -a | tr -d '\n')

    curl -sk -X "$method" \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/json' \
        -H "accept-version: ~8" \
        -H "Date: $now" \
        -H "Authorization: Signature keyId=\"/$SDC_ACCOUNT/keys/macbook m1\",algorithm=\"rsa-sha256\" $signature" \
        "$SDC_URL/$SDC_ACCOUNT$path" \
        "$@"
}

create_scoped_key() {
    local scope_json="$1"
    local body

    if [ -n "$scope_json" ]; then
        body=$(jq -n --argjson perms "$scope_json" \
            '{ scope: { version: 1, permissions: $perms } }')
    else
        body='{}'
    fi

    local resp
    resp=$(cloudapi POST /accesskeys -d "$body" 2>/dev/null)

    LAST_KEY_ID=$(echo "$resp" | jq -r '.accesskeyid // empty')
    LAST_KEY_SECRET=$(echo "$resp" | jq -r '.accesskeysecret // empty')

    if [ -z "$LAST_KEY_ID" ] || [ -z "$LAST_KEY_SECRET" ]; then
        echo "DEBUG: CloudAPI response: $resp" >&2
        return 1
    fi
    return 0
}

delete_key() {
    local key_id="$1"
    cloudapi DELETE "/accesskeys/$key_id" 2>/dev/null
}

with_key() {
    local kid="$1"
    local secret="$2"
    shift 2
    AWS_ACCESS_KEY_ID="$kid" \
    AWS_SECRET_ACCESS_KEY="$secret" \
    AWS_SESSION_TOKEN="" \
    "$@"
}

wait_for_replication() {
    log "Waiting ${REPL_WAIT}s for UFDS->Redis replication..."
    sleep "$REPL_WAIT"
}

retry_on_auth() {
    local max_attempts=3
    local delay=1
    local attempt=1
    local result rc

    while [ $attempt -le $max_attempts ]; do
        set +e
        result=$("$@" 2>&1)
        rc=$?
        set -e

        if [ $rc -eq 0 ]; then
            echo "$result"
            return 0
        fi

        if echo "$result" | grep -q "AccessDenied\|403"; then
            if [ $attempt -lt $max_attempts ]; then
                log "  Auth retry $attempt/$max_attempts (backoff ${delay}s)..."
                sleep $delay
                delay=$((delay * 2))
            fi
            attempt=$((attempt + 1))
        else
            echo "$result"
            return $rc
        fi
    done

    echo "$result"
    return $rc
}

# =============================================================================
# Setup
# =============================================================================

test_setup() {
    log "Creating test buckets for multipart tests..."

    aws_s3api create-bucket --bucket "$MPU_BUCKET" >/dev/null 2>&1 || true
    aws_s3api create-bucket --bucket "$MPU_OUTSIDE" >/dev/null 2>&1 || true

    # readwrite key for MPU_BUCKET
    local rw_scope='[{"bucket":"'"$MPU_BUCKET"'","level":"readwrite"}]'
    if ! create_scoped_key "$rw_scope"; then
        error "Setup - failed to create readwrite key"
        return 1
    fi
    MPU_RW_KEY_ID="$LAST_KEY_ID"
    MPU_RW_SECRET="$LAST_KEY_SECRET"
    log "Created readwrite key: $MPU_RW_KEY_ID"

    # read-only key for MPU_BUCKET
    local ro_scope='[{"bucket":"'"$MPU_BUCKET"'","level":"read"}]'
    if ! create_scoped_key "$ro_scope"; then
        error "Setup - failed to create read-only key"
        return 1
    fi
    MPU_RO_KEY_ID="$LAST_KEY_ID"
    MPU_RO_SECRET="$LAST_KEY_SECRET"
    log "Created read-only key: $MPU_RO_KEY_ID"

    wait_for_replication
    success "Multipart test setup complete"
}

# =============================================================================
# Test 1: CreateMultipartUpload with readwrite scope
# =============================================================================

test_mpu_create_readwrite() {
    log "=== Test 1: CreateMultipartUpload with readwrite scope ==="

    set +e
    local result
    result=$(retry_on_auth with_key "$MPU_RW_KEY_ID" "$MPU_RW_SECRET" \
        aws_s3api create-multipart-upload \
            --bucket "$MPU_BUCKET" \
            --key "mpu-rw-test.txt" 2>&1)
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        local upload_id
        upload_id=$(echo "$result" | jq -r '.UploadId // empty')
        if [ -n "$upload_id" ]; then
            success "CreateMultipartUpload readwrite - allowed (UploadId: ${upload_id:0:12}...)"
            # Save for subsequent tests
            echo "$upload_id" > "$TEMP_DIR/mpu_upload_id_rw"
        else
            error "CreateMultipartUpload readwrite - no UploadId returned"
        fi
    else
        error "CreateMultipartUpload readwrite - should be allowed: $result"
    fi
}

# =============================================================================
# Test 2: UploadPart with readwrite scope
# =============================================================================

test_mpu_upload_part() {
    log "=== Test 2: UploadPart with readwrite scope ==="

    local upload_id
    if [ -f "$TEMP_DIR/mpu_upload_id_rw" ]; then
        read upload_id < "$TEMP_DIR/mpu_upload_id_rw"
    fi

    if [ -z "$upload_id" ]; then
        warning "UploadPart test - no upload ID from Test 1, skipping"
        return 0
    fi

    # Create a 5MB part (minimum for S3 multipart, except last part)
    local part_file="$TEMP_DIR/mpu-part1.bin"
    dd if=/dev/urandom of="$part_file" bs=1048576 count=5 2>/dev/null

    set +e
    local result
    result=$(with_key "$MPU_RW_KEY_ID" "$MPU_RW_SECRET" \
        aws_s3api upload-part \
            --bucket "$MPU_BUCKET" \
            --key "mpu-rw-test.txt" \
            --upload-id "$upload_id" \
            --part-number 1 \
            --body "$part_file" 2>&1)
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        local etag
        etag=$(echo "$result" | jq -r '.ETag // empty')
        success "UploadPart readwrite - allowed (ETag: $etag)"
        echo "$etag" > "$TEMP_DIR/mpu_part1_etag"
    else
        error "UploadPart readwrite - should be allowed: $result"
    fi
}

# =============================================================================
# Test 3: CompleteMultipartUpload with readwrite scope
# =============================================================================

test_mpu_complete() {
    log "=== Test 3: CompleteMultipartUpload with readwrite scope ==="

    local upload_id etag
    if [ -f "$TEMP_DIR/mpu_upload_id_rw" ]; then
        read upload_id < "$TEMP_DIR/mpu_upload_id_rw"
    fi
    if [ -f "$TEMP_DIR/mpu_part1_etag" ]; then
        read etag < "$TEMP_DIR/mpu_part1_etag"
    fi

    if [ -z "$upload_id" ] || [ -z "$etag" ]; then
        warning "CompleteMultipartUpload test - missing upload ID or ETag, skipping"
        return 0
    fi

    # Build the multipart upload completion JSON
    local parts_json
    parts_json=$(jq -n --arg etag "$etag" \
        '{ Parts: [{ ETag: $etag, PartNumber: 1 }] }')

    set +e
    local result
    result=$(with_key "$MPU_RW_KEY_ID" "$MPU_RW_SECRET" \
        aws_s3api complete-multipart-upload \
            --bucket "$MPU_BUCKET" \
            --key "mpu-rw-test.txt" \
            --upload-id "$upload_id" \
            --multipart-upload "$parts_json" 2>&1)
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "CompleteMultipartUpload readwrite - allowed"
    else
        error "CompleteMultipartUpload readwrite - should be allowed: $result"
    fi
}

# =============================================================================
# Test 4: AbortMultipartUpload with readwrite scope
# =============================================================================

test_mpu_abort() {
    log "=== Test 4: AbortMultipartUpload with readwrite scope ==="

    # Start a new MPU just to abort it
    set +e
    local result
    result=$(with_key "$MPU_RW_KEY_ID" "$MPU_RW_SECRET" \
        aws_s3api create-multipart-upload \
            --bucket "$MPU_BUCKET" \
            --key "mpu-abort-test.txt" 2>&1)
    local rc=$?
    set -e

    if [ $rc -ne 0 ]; then
        error "AbortMultipartUpload - could not create MPU to abort: $result"
        return 1
    fi

    local upload_id
    upload_id=$(echo "$result" | jq -r '.UploadId // empty')

    set +e
    with_key "$MPU_RW_KEY_ID" "$MPU_RW_SECRET" \
        aws_s3api abort-multipart-upload \
            --bucket "$MPU_BUCKET" \
            --key "mpu-abort-test.txt" \
            --upload-id "$upload_id" >/dev/null 2>&1
    rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "AbortMultipartUpload readwrite - allowed"
    else
        error "AbortMultipartUpload readwrite - should be allowed"
    fi
}

# =============================================================================
# Test 5: CreateMultipartUpload with read-only scope — denied
# =============================================================================

test_mpu_create_readonly() {
    log "=== Test 5: CreateMultipartUpload with read-only scope (denied) ==="

    assert_s3_deny \
        "CreateMultipartUpload read-only - denied (readwrite required)" \
        "AccessDenied" \
        with_key "$MPU_RO_KEY_ID" "$MPU_RO_SECRET" \
            aws_s3api create-multipart-upload \
                --bucket "$MPU_BUCKET" \
                --key "mpu-ro-denied.txt"
}

# =============================================================================
# Test 6: ListMultipartUploads with read scope — allowed
# =============================================================================

test_mpu_list_uploads_readonly() {
    log "=== Test 6: ListMultipartUploads with read scope ==="

    set +e
    local result
    result=$(retry_on_auth with_key "$MPU_RO_KEY_ID" "$MPU_RO_SECRET" \
        aws_s3api list-multipart-uploads \
            --bucket "$MPU_BUCKET" 2>&1)
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "ListMultipartUploads read-only - allowed"
    else
        error "ListMultipartUploads read-only - should be allowed (list = read): $result"
    fi
}

# =============================================================================
# Test 7: ListParts with read scope — allowed
# =============================================================================

test_mpu_list_parts_readonly() {
    log "=== Test 7: ListParts with read scope ==="

    # We need an active MPU to list parts. Create one with admin key.
    set +e
    local mpu_result
    mpu_result=$(aws_s3api create-multipart-upload \
        --bucket "$MPU_BUCKET" \
        --key "mpu-list-parts.txt" 2>&1)
    local mpu_rc=$?
    set -e

    if [ $mpu_rc -ne 0 ]; then
        warning "ListParts test - could not create MPU with admin key, skipping"
        return 0
    fi

    local upload_id
    upload_id=$(echo "$mpu_result" | jq -r '.UploadId // empty')

    set +e
    local result
    result=$(with_key "$MPU_RO_KEY_ID" "$MPU_RO_SECRET" \
        aws_s3api list-parts \
            --bucket "$MPU_BUCKET" \
            --key "mpu-list-parts.txt" \
            --upload-id "$upload_id" 2>&1)
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "ListParts read-only - allowed"
    else
        error "ListParts read-only - should be allowed (list = read): $result"
    fi

    # Cleanup: abort MPU
    aws_s3api abort-multipart-upload \
        --bucket "$MPU_BUCKET" \
        --key "mpu-list-parts.txt" \
        --upload-id "$upload_id" >/dev/null 2>&1 || true
}

# =============================================================================
# Test 8: CreateMultipartUpload on unscoped bucket — denied
# =============================================================================

test_mpu_unscoped_bucket() {
    log "=== Test 8: CreateMultipartUpload on unscoped bucket (denied) ==="

    assert_s3_deny \
        "CreateMultipartUpload unscoped bucket - denied" \
        "AccessDenied" \
        with_key "$MPU_RW_KEY_ID" "$MPU_RW_SECRET" \
            aws_s3api create-multipart-upload \
                --bucket "$MPU_OUTSIDE" \
                --key "mpu-outside-denied.txt"
}

# =============================================================================
# Cleanup
# =============================================================================

test_cleanup() {
    log "Cleaning up multipart test resources..."
    set +e

    # Abort any lingering MPUs
    for bkt in "$MPU_BUCKET" "$MPU_OUTSIDE"; do
        local uploads
        uploads=$(aws_s3api list-multipart-uploads --bucket "$bkt" 2>/dev/null \
            | jq -r '.Uploads[]? | "\(.Key) \(.UploadId)"' 2>/dev/null)
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                local key uid
                key=$(echo "$line" | cut -d' ' -f1)
                uid=$(echo "$line" | cut -d' ' -f2)
                aws_s3api abort-multipart-upload \
                    --bucket "$bkt" --key "$key" --upload-id "$uid" 2>/dev/null || true
            fi
        done <<< "$uploads"

        aws_s3 rm "s3://$bkt" --recursive 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$bkt" 2>/dev/null || true
    done

    for kid in "$MPU_RW_KEY_ID" "$MPU_RO_KEY_ID"; do
        if [ -n "$kid" ]; then
            delete_key "$kid" 2>/dev/null || true
        fi
    done

    cleanup_credentials
    set -e
    log "Cleanup complete"
}

# =============================================================================
# Main
# =============================================================================

main() {
    log "=========================================="
    log "Scope — Multipart Upload Tests"
    log "=========================================="
    log "  S3 Endpoint:      $S3_ENDPOINT"
    log "  CloudAPI:         $CLOUDAPI_URL"
    log "  Account:          $MANTA_USER"
    log "  Replication wait: ${REPL_WAIT}s"
    log "=========================================="

    setup
    test_setup

    test_mpu_create_readwrite
    test_mpu_upload_part
    test_mpu_complete
    test_mpu_abort
    test_mpu_create_readonly
    test_mpu_list_uploads_readonly
    test_mpu_list_parts_readonly
    test_mpu_unscoped_bucket

    test_cleanup
    print_summary
}

main "$@"
