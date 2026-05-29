#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Per-Bucket Access Key Scope — AWS Chunked Encoding Integration Tests
#
# Verifies that bucket scope is enforced on the aws-chunked
# (STREAMING-AWS4-HMAC-SHA256-PAYLOAD) request path. Per-chunk
# signature verification uses a derived signing key returned by
# mahi (MANTA-5512); that is a separate code path from the
# standard request validator. If scope enforcement is not applied
# there, a scoped key could bypass its scope by uploading
# aws-chunked.
#
# Tests:
#   1. aws-chunked PUT (20 MiB) with readwrite scope → allowed
#   2. aws-chunked PUT (20 MiB) with read-only scope → denied
#   3. aws-chunked PUT (20 MiB) cross-bucket (scope=A, bucket=B) → denied
#   4. aws-chunked GET (20 MiB) with read scope → allowed, content matches
#   5. aws-chunked GET (20 MiB) cross-bucket → denied
#   6. aws-chunked PUT-then-GET round-trip with readwrite scope → bytes match
#
# Prerequisites:
#   - CloudAPI running (CLOUDAPI_URL)
#   - manta-buckets-api running (S3_ENDPOINT)
#   - MANTA_USER, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY set
#   - jq, openssl, ssh key at ~/.ssh/id_rsa for cloudapi auth

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

CLOUDAPI_URL=${CLOUDAPI_URL:-"https://localhost:8443"}
REPL_WAIT=${REPL_WAIT:-3}

# A 20 MiB body comfortably exceeds AWS CLI's chunking threshold,
# so the upload will use STREAMING-AWS4-HMAC-SHA256-PAYLOAD with
# per-chunk signing. Smaller bodies sometimes get sent as a
# single part and skip the chunked path.
CHUNKED_BODY_BS=1048576
CHUNKED_BODY_COUNT=20

# Test buckets
CHUNK_BUCKET_IN="scope-chunk-in-$(date +%s)"
CHUNK_BUCKET_OUT="scope-chunk-out-$(date +%s)"

# Keys
CHUNK_RW_KEY_ID=""
CHUNK_RW_SECRET=""
CHUNK_RO_KEY_ID=""
CHUNK_RO_SECRET=""

SDC_ACCOUNT=${SDC_ACCOUNT:-"neirac"}
SDC_URL=${CLOUDAPI_URL}

# =============================================================================
# CloudAPI helpers (kept consistent with scope-multipart-test.sh)
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

# =============================================================================
# Setup
# =============================================================================

test_setup() {
    log "Creating test buckets..."
    aws_s3api create-bucket --bucket "$CHUNK_BUCKET_IN"  >/dev/null 2>&1 || true
    aws_s3api create-bucket --bucket "$CHUNK_BUCKET_OUT" >/dev/null 2>&1 || true

    # readwrite key scoped to CHUNK_BUCKET_IN only
    local rw='[{"bucket":"'"$CHUNK_BUCKET_IN"'","level":"readwrite"}]'
    if ! create_scoped_key "$rw"; then
        error "Setup - readwrite key creation failed"
        return 1
    fi
    CHUNK_RW_KEY_ID="$LAST_KEY_ID"
    CHUNK_RW_SECRET="$LAST_KEY_SECRET"
    log "Created readwrite key: $CHUNK_RW_KEY_ID (scope=$CHUNK_BUCKET_IN)"

    # read-only key scoped to CHUNK_BUCKET_IN only
    local ro='[{"bucket":"'"$CHUNK_BUCKET_IN"'","level":"read"}]'
    if ! create_scoped_key "$ro"; then
        error "Setup - read-only key creation failed"
        return 1
    fi
    CHUNK_RO_KEY_ID="$LAST_KEY_ID"
    CHUNK_RO_SECRET="$LAST_KEY_SECRET"
    log "Created read-only key:  $CHUNK_RO_KEY_ID (scope=$CHUNK_BUCKET_IN)"

    # Generate a 20 MiB payload — large enough that AWS CLI uses
    # aws-chunked encoding rather than buffering the body.
    dd if=/dev/urandom of="$TEMP_DIR/chunk-body.bin" \
        bs="$CHUNKED_BODY_BS" count="$CHUNKED_BODY_COUNT" 2>/dev/null

    wait_for_replication
    success "scope-aws-chunked setup complete"
}

# =============================================================================
# Test 1: aws-chunked PUT with readwrite scope → allowed
# =============================================================================
test_chunked_put_rw_allowed() {
    log "=== Test 1: aws-chunked PUT, readwrite scope, in-scope bucket ==="
    set +e
    local result
    result=$(with_key "$CHUNK_RW_KEY_ID" "$CHUNK_RW_SECRET" \
        aws_s3api put-object \
            --bucket "$CHUNK_BUCKET_IN" \
            --key "rw-chunked.bin" \
            --body "$TEMP_DIR/chunk-body.bin" 2>&1)
    local rc=$?
    set -e
    if [ $rc -eq 0 ]; then
        success "RW scope - aws-chunked PUT in-scope allowed"
    else
        error "RW scope - aws-chunked PUT in-scope should be allowed: $result"
    fi
}

# =============================================================================
# Test 2: aws-chunked PUT with read-only scope → denied
# =============================================================================
test_chunked_put_ro_denied() {
    log "=== Test 2: aws-chunked PUT, read-only scope ==="
    assert_s3_deny \
        "RO scope - aws-chunked PUT denied" \
        "AccessDeniedByKeyScope" \
        with_key "$CHUNK_RO_KEY_ID" "$CHUNK_RO_SECRET" \
            aws_s3api put-object \
                --bucket "$CHUNK_BUCKET_IN" \
                --key "ro-chunked.bin" \
                --body "$TEMP_DIR/chunk-body.bin"
}

# =============================================================================
# Test 3: aws-chunked PUT cross-bucket → denied
# =============================================================================
test_chunked_put_cross_bucket_denied() {
    log "=== Test 3: aws-chunked PUT, readwrite scope, OUT-of-scope bucket ==="
    assert_s3_deny \
        "RW scope - aws-chunked PUT out-of-scope denied" \
        "AccessDeniedByKeyScope" \
        with_key "$CHUNK_RW_KEY_ID" "$CHUNK_RW_SECRET" \
            aws_s3api put-object \
                --bucket "$CHUNK_BUCKET_OUT" \
                --key "rw-chunked-cross.bin" \
                --body "$TEMP_DIR/chunk-body.bin"
}

# =============================================================================
# Test 4: aws-chunked GET with read scope → allowed, content matches
# =============================================================================
test_chunked_get_ro_allowed() {
    log "=== Test 4: aws-chunked GET, read scope, in-scope bucket ==="
    set +e
    with_key "$CHUNK_RO_KEY_ID" "$CHUNK_RO_SECRET" \
        aws_s3api get-object \
            --bucket "$CHUNK_BUCKET_IN" \
            --key "rw-chunked.bin" \
            "$TEMP_DIR/chunk-body-ro-get.bin" >/dev/null 2>&1
    local rc=$?
    set -e
    if [ $rc -ne 0 ]; then
        error "RO scope - aws-chunked GET should be allowed (rc=$rc)"
        return
    fi
    local h1 h2
    h1=$(shasum -a 256 "$TEMP_DIR/chunk-body.bin"        | awk '{print $1}')
    h2=$(shasum -a 256 "$TEMP_DIR/chunk-body-ro-get.bin" | awk '{print $1}')
    if [ "$h1" = "$h2" ]; then
        success "RO scope - aws-chunked GET allowed, content integrity verified"
    else
        error "RO scope - aws-chunked GET content mismatch ($h1 vs $h2)"
    fi
}

# =============================================================================
# Test 5: aws-chunked GET cross-bucket → denied
# =============================================================================
test_chunked_get_cross_bucket_denied() {
    log "=== Test 5: aws-chunked GET, read scope, OUT-of-scope bucket ==="
    # Put a probe object as admin so the cross-bucket GET has
    # something to refuse, distinguishing 403 (scope-denied) from
    # 404 (no-such-key).
    aws_s3api put-object \
        --bucket "$CHUNK_BUCKET_OUT" \
        --key "probe.bin" \
        --body "$TEMP_DIR/chunk-body.bin" >/dev/null 2>&1 || true

    assert_s3_deny \
        "RO scope - aws-chunked GET out-of-scope denied" \
        "AccessDeniedByKeyScope" \
        with_key "$CHUNK_RO_KEY_ID" "$CHUNK_RO_SECRET" \
            aws_s3api get-object \
                --bucket "$CHUNK_BUCKET_OUT" \
                --key "probe.bin" \
                "$TEMP_DIR/chunk-body-cross-get.bin"
}

# =============================================================================
# Test 6: PUT + GET round-trip with readwrite scope (integrity)
# =============================================================================
test_chunked_roundtrip_rw() {
    log "=== Test 6: aws-chunked PUT+GET round-trip, readwrite scope ==="
    set +e
    with_key "$CHUNK_RW_KEY_ID" "$CHUNK_RW_SECRET" \
        aws_s3api put-object \
            --bucket "$CHUNK_BUCKET_IN" \
            --key "rw-roundtrip.bin" \
            --body "$TEMP_DIR/chunk-body.bin" >/dev/null 2>&1
    local put_rc=$?
    with_key "$CHUNK_RW_KEY_ID" "$CHUNK_RW_SECRET" \
        aws_s3api get-object \
            --bucket "$CHUNK_BUCKET_IN" \
            --key "rw-roundtrip.bin" \
            "$TEMP_DIR/chunk-body-rt.bin" >/dev/null 2>&1
    local get_rc=$?
    set -e
    if [ $put_rc -ne 0 ] || [ $get_rc -ne 0 ]; then
        error "RW round-trip - PUT/GET failed (put=$put_rc get=$get_rc)"
        return
    fi
    local h1 h2
    h1=$(shasum -a 256 "$TEMP_DIR/chunk-body.bin"    | awk '{print $1}')
    h2=$(shasum -a 256 "$TEMP_DIR/chunk-body-rt.bin" | awk '{print $1}')
    if [ "$h1" = "$h2" ]; then
        success "RW round-trip - PUT+GET integrity verified"
    else
        error "RW round-trip - content mismatch ($h1 vs $h2)"
    fi
}

# =============================================================================
# Cleanup
# =============================================================================

test_cleanup() {
    log "Cleaning up keys + buckets..."
    [ -n "$CHUNK_RW_KEY_ID" ] && delete_key "$CHUNK_RW_KEY_ID" || true
    [ -n "$CHUNK_RO_KEY_ID" ] && delete_key "$CHUNK_RO_KEY_ID" || true
    for b in "$CHUNK_BUCKET_IN" "$CHUNK_BUCKET_OUT"; do
        aws_s3api list-objects-v2 --bucket "$b" --output json 2>/dev/null | \
            jq -r '.Contents[]?.Key' | while read -r k; do
                [ -n "$k" ] && aws_s3api delete-object \
                    --bucket "$b" --key "$k" >/dev/null 2>&1 || true
            done
        aws_s3api delete-bucket --bucket "$b" >/dev/null 2>&1 || true
    done
}

# =============================================================================
# Main
# =============================================================================

main() {
    log "==============================================="
    log "Per-Bucket Access Key Scope - AWS Chunked Tests"
    log "==============================================="

    # Common setup creates TEMP_DIR, exports AWS env, etc.
    setup
    test_setup
    test_chunked_put_rw_allowed
    test_chunked_put_ro_denied
    test_chunked_put_cross_bucket_denied
    test_chunked_get_ro_allowed
    test_chunked_get_cross_bucket_denied
    test_chunked_roundtrip_rw
    test_cleanup

    log ""
    log "==============================================="
    log "Test Summary"
    log "==============================================="
    log "Tests Passed: $TESTS_PASSED"
    log "Tests Failed: $TESTS_FAILED"
    if [ "$TESTS_FAILED" -ne 0 ]; then
        log "Failed Tests:"
        for f in "${FAILED_TESTS[@]}"; do log "  $f"; done
        exit 1
    fi
}

main
