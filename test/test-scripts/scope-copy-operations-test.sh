#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Per-Bucket Access Key Scope — CopyObject & UploadPartCopy Integration Tests
#
# Tests that scope enforcement applies to BOTH source and destination buckets
# on copy operations. The enforceBucketScope middleware checks the destination
# (from URL path); the handler checks the source (from x-amz-copy-source).
#
# Tests:
#   1. CopyObject: source + dest both in scope → 200
#   2. CopyObject: source NOT in scope → 403
#   3. CopyObject: dest NOT in scope → 403
#   4. CopyObject: read-only key copies FROM scoped bucket → 200
#   5. CopyObject: read-only key copies TO scoped bucket → 403
#   6. UploadPartCopy: source in scope → 200
#   7. UploadPartCopy: source NOT in scope → 403
#
# Prerequisites:
#   - CloudAPI running (CLOUDAPI_URL)
#   - manta-buckets-api running (S3_ENDPOINT)
#   - MANTA_USER, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY set
#   - jq installed
#
# Usage:
#   export MANTA_USER=neirac
#   export CLOUDAPI_URL=https://localhost:8443
#   export S3_ENDPOINT=https://dc1-nat.local
#   export AWS_ACCESS_KEY_ID=...
#   export AWS_SECRET_ACCESS_KEY=...
#   bash scope-copy-operations-test.sh

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

CLOUDAPI_URL=${CLOUDAPI_URL:-"https://localhost:8443"}
REPL_WAIT=${REPL_WAIT:-3}

# Test buckets
COPY_SRC="scope-copy-src-$(date +%s)"
COPY_DST="scope-copy-dst-$(date +%s)"
COPY_OUTSIDE="scope-copy-outside-$(date +%s)"

# Key tracking
COPY_RW_KEY_ID=""
COPY_RW_SECRET=""
COPY_RO_KEY_ID=""
COPY_RO_SECRET=""

SDC_ACCOUNT=${SDC_ACCOUNT:-"neirac"}
SDC_URL=${CLOUDAPI_URL:-"https://localhost:8443"}

# =============================================================================
# CloudAPI helpers (same pattern as bucket-scope-test.sh)
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
    log "Creating test buckets and objects for copy tests..."

    aws_s3api create-bucket --bucket "$COPY_SRC" >/dev/null 2>&1 || true
    aws_s3api create-bucket --bucket "$COPY_DST" >/dev/null 2>&1 || true
    aws_s3api create-bucket --bucket "$COPY_OUTSIDE" >/dev/null 2>&1 || true

    local test_file="$TEMP_DIR/copy-src-obj.txt"
    echo "copy source content" > "$test_file"
    aws_s3api put-object --bucket "$COPY_SRC" \
        --key "source.txt" --body "$test_file" >/dev/null 2>&1
    aws_s3api put-object --bucket "$COPY_OUTSIDE" \
        --key "outside.txt" --body "$test_file" >/dev/null 2>&1

    # Key with readwrite on BOTH src and dst
    local rw_scope='[{"bucket":"'"$COPY_SRC"'","level":"readwrite"},{"bucket":"'"$COPY_DST"'","level":"readwrite"}]'
    if ! create_scoped_key "$rw_scope"; then
        error "Setup - failed to create readwrite key"
        return 1
    fi
    COPY_RW_KEY_ID="$LAST_KEY_ID"
    COPY_RW_SECRET="$LAST_KEY_SECRET"
    log "Created readwrite key: $COPY_RW_KEY_ID"

    # Key with read-only on src, nothing on dst
    local ro_scope='[{"bucket":"'"$COPY_SRC"'","level":"read"}]'
    if ! create_scoped_key "$ro_scope"; then
        error "Setup - failed to create read-only key"
        return 1
    fi
    COPY_RO_KEY_ID="$LAST_KEY_ID"
    COPY_RO_SECRET="$LAST_KEY_SECRET"
    log "Created read-only key: $COPY_RO_KEY_ID"

    wait_for_replication
    success "Copy test setup complete"
}

# =============================================================================
# Test 1: CopyObject — source + dest both in scope
# =============================================================================

test_copy_both_in_scope() {
    log "=== Test 1: CopyObject — source + dest both in scope ==="

    set +e
    retry_on_auth with_key "$COPY_RW_KEY_ID" "$COPY_RW_SECRET" \
        aws_s3api copy-object \
            --bucket "$COPY_DST" \
            --key "copied.txt" \
            --copy-source "$COPY_SRC/source.txt" >/dev/null 2>&1
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "CopyObject both in scope - allowed"
    else
        error "CopyObject both in scope - should be allowed"
    fi
}

# =============================================================================
# Test 2: CopyObject — source NOT in scope
# =============================================================================

test_copy_source_not_in_scope() {
    log "=== Test 2: CopyObject — source NOT in scope ==="

    # COPY_RW key has scope on COPY_SRC and COPY_DST, but NOT COPY_OUTSIDE.
    # Copying FROM COPY_OUTSIDE should fail.
    assert_s3_deny \
        "CopyObject source not in scope - denied" \
        "AccessDenied" \
        with_key "$COPY_RW_KEY_ID" "$COPY_RW_SECRET" \
            aws_s3api copy-object \
                --bucket "$COPY_DST" \
                --key "from-outside.txt" \
                --copy-source "$COPY_OUTSIDE/outside.txt"
}

# =============================================================================
# Test 3: CopyObject — dest NOT in scope
# =============================================================================

test_copy_dest_not_in_scope() {
    log "=== Test 3: CopyObject — dest NOT in scope ==="

    # Copying TO COPY_OUTSIDE should fail (middleware checks dest from URL path).
    assert_s3_deny \
        "CopyObject dest not in scope - denied" \
        "AccessDenied" \
        with_key "$COPY_RW_KEY_ID" "$COPY_RW_SECRET" \
            aws_s3api copy-object \
                --bucket "$COPY_OUTSIDE" \
                --key "escaped.txt" \
                --copy-source "$COPY_SRC/source.txt"
}

# =============================================================================
# Test 4: CopyObject — read-only key copies FROM scoped bucket
# =============================================================================

test_copy_readonly_source() {
    log "=== Test 4: CopyObject — read-only source (read level sufficient) ==="

    # The read-only key has read on COPY_SRC only.
    # We need a key with read on src + readwrite on dst to test that
    # read is sufficient for the source side. Create a special key.
    local mixed_scope='[{"bucket":"'"$COPY_SRC"'","level":"read"},{"bucket":"'"$COPY_DST"'","level":"readwrite"}]'
    if ! create_scoped_key "$mixed_scope"; then
        error "Test 4 - failed to create mixed-scope key"
        return 1
    fi
    local mixed_key="$LAST_KEY_ID"
    local mixed_secret="$LAST_KEY_SECRET"
    wait_for_replication

    set +e
    retry_on_auth with_key "$mixed_key" "$mixed_secret" \
        aws_s3api copy-object \
            --bucket "$COPY_DST" \
            --key "ro-copied.txt" \
            --copy-source "$COPY_SRC/source.txt" >/dev/null 2>&1
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "CopyObject read-only source - allowed (read sufficient for source)"
    else
        error "CopyObject read-only source - read should be sufficient for copy source"
    fi

    delete_key "$mixed_key" 2>/dev/null || true
}

# =============================================================================
# Test 5: CopyObject — read-only key copies TO scoped bucket
# =============================================================================

test_copy_readonly_dest() {
    log "=== Test 5: CopyObject — read-only key copies TO bucket (denied) ==="

    # The read-only key has read on COPY_SRC only.
    # PUT (copy dest) requires readwrite — should be denied.
    assert_s3_deny \
        "CopyObject read-only dest - denied (readwrite required)" \
        "AccessDenied" \
        with_key "$COPY_RO_KEY_ID" "$COPY_RO_SECRET" \
            aws_s3api copy-object \
                --bucket "$COPY_SRC" \
                --key "self-copy.txt" \
                --copy-source "$COPY_SRC/source.txt"
}

# =============================================================================
# Test 6: UploadPartCopy — source in scope
# =============================================================================

test_uploadpartcopy_source_in_scope() {
    log "=== Test 6: UploadPartCopy — source in scope ==="

    # Start a multipart upload to COPY_DST
    set +e
    local mpu_result
    mpu_result=$(with_key "$COPY_RW_KEY_ID" "$COPY_RW_SECRET" \
        aws_s3api create-multipart-upload \
            --bucket "$COPY_DST" \
            --key "mpu-copy-test.txt" 2>&1)
    local mpu_rc=$?
    set -e

    if [ $mpu_rc -ne 0 ]; then
        error "UploadPartCopy source in scope - CreateMultipartUpload failed: $mpu_result"
        return 1
    fi

    local upload_id
    upload_id=$(echo "$mpu_result" | jq -r '.UploadId // empty')
    if [ -z "$upload_id" ]; then
        error "UploadPartCopy source in scope - no UploadId returned"
        return 1
    fi

    # UploadPartCopy from COPY_SRC (in scope)
    set +e
    local part_result
    part_result=$(with_key "$COPY_RW_KEY_ID" "$COPY_RW_SECRET" \
        aws_s3api upload-part-copy \
            --bucket "$COPY_DST" \
            --key "mpu-copy-test.txt" \
            --upload-id "$upload_id" \
            --part-number 1 \
            --copy-source "$COPY_SRC/source.txt" 2>&1)
    local part_rc=$?
    set -e

    if [ $part_rc -eq 0 ]; then
        success "UploadPartCopy source in scope - allowed"
    else
        error "UploadPartCopy source in scope - should be allowed: $part_result"
    fi

    # Abort the multipart upload (cleanup)
    set +e
    with_key "$COPY_RW_KEY_ID" "$COPY_RW_SECRET" \
        aws_s3api abort-multipart-upload \
            --bucket "$COPY_DST" \
            --key "mpu-copy-test.txt" \
            --upload-id "$upload_id" >/dev/null 2>&1
    set -e
}

# =============================================================================
# Test 7: UploadPartCopy — source NOT in scope
# =============================================================================

test_uploadpartcopy_source_not_in_scope() {
    log "=== Test 7: UploadPartCopy — source NOT in scope ==="

    # Start a multipart upload to COPY_DST
    set +e
    local mpu_result
    mpu_result=$(with_key "$COPY_RW_KEY_ID" "$COPY_RW_SECRET" \
        aws_s3api create-multipart-upload \
            --bucket "$COPY_DST" \
            --key "mpu-copy-denied.txt" 2>&1)
    local mpu_rc=$?
    set -e

    if [ $mpu_rc -ne 0 ]; then
        error "UploadPartCopy source not in scope - CreateMultipartUpload failed: $mpu_result"
        return 1
    fi

    local upload_id
    upload_id=$(echo "$mpu_result" | jq -r '.UploadId // empty')
    if [ -z "$upload_id" ]; then
        error "UploadPartCopy source not in scope - no UploadId returned"
        return 1
    fi

    # UploadPartCopy from COPY_OUTSIDE (NOT in scope) — should fail
    assert_s3_deny \
        "UploadPartCopy source not in scope - denied" \
        "AccessDenied" \
        with_key "$COPY_RW_KEY_ID" "$COPY_RW_SECRET" \
            aws_s3api upload-part-copy \
                --bucket "$COPY_DST" \
                --key "mpu-copy-denied.txt" \
                --upload-id "$upload_id" \
                --part-number 1 \
                --copy-source "$COPY_OUTSIDE/outside.txt"

    # Abort the multipart upload (cleanup)
    set +e
    with_key "$COPY_RW_KEY_ID" "$COPY_RW_SECRET" \
        aws_s3api abort-multipart-upload \
            --bucket "$COPY_DST" \
            --key "mpu-copy-denied.txt" \
            --upload-id "$upload_id" >/dev/null 2>&1
    set -e
}

# =============================================================================
# Cleanup
# =============================================================================

test_cleanup() {
    log "Cleaning up copy test resources..."
    set +e

    for bkt in "$COPY_SRC" "$COPY_DST" "$COPY_OUTSIDE"; do
        aws_s3 rm "s3://$bkt" --recursive 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$bkt" 2>/dev/null || true
    done

    for kid in "$COPY_RW_KEY_ID" "$COPY_RO_KEY_ID"; do
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
    log "Scope — CopyObject & UploadPartCopy Tests"
    log "=========================================="
    log "  S3 Endpoint:      $S3_ENDPOINT"
    log "  CloudAPI:         $CLOUDAPI_URL"
    log "  Account:          $MANTA_USER"
    log "  Replication wait: ${REPL_WAIT}s"
    log "=========================================="

    setup
    test_setup

    test_copy_both_in_scope
    test_copy_source_not_in_scope
    test_copy_dest_not_in_scope
    test_copy_readonly_source
    test_copy_readonly_dest
    test_uploadpartcopy_source_in_scope
    test_uploadpartcopy_source_not_in_scope

    test_cleanup
    print_summary
}

main "$@"
