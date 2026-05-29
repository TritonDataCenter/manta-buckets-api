#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Per-Bucket Access Key Scope — Pre-signed URL Integration Tests
#
# Pre-signed URLs are signed with the key's secret. Scope enforcement
# is server-side (in enforceBucketScope middleware), so pre-signed URLs
# must respect the key's scope just like regular requests.
#
# Tests:
#   1. Pre-signed GET on scoped bucket (read) → 200
#   2. Pre-signed GET on unscoped bucket → 403
#   3. Pre-signed PUT on read-only scoped bucket → 403
#   4. Pre-signed PUT on readwrite scoped bucket → 200
#
# Prerequisites:
#   - CloudAPI running (CLOUDAPI_URL)
#   - manta-buckets-api running (S3_ENDPOINT)
#   - MANTA_USER, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY set
#   - jq, curl installed

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

CLOUDAPI_URL=${CLOUDAPI_URL:-"https://localhost:8443"}
REPL_WAIT=${REPL_WAIT:-3}

# Test buckets
PS_BUCKET="scope-presign-test-$(date +%s)"
PS_OUTSIDE="scope-presign-out-$(date +%s)"

# Key tracking
PS_RO_KEY_ID=""
PS_RO_SECRET=""
PS_RW_KEY_ID=""
PS_RW_SECRET=""

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

# Generate a pre-signed URL using the AWS CLI
# Usage: generate_presigned_url <method> <bucket> <key> <key_id> <secret> [expires]
# Returns URL on stdout
generate_presigned_url() {
    local method="$1"
    local bucket="$2"
    local object_key="$3"
    local kid="$4"
    local secret="$5"
    local expires="${6:-300}"

    local url
    if [ "$method" = "GET" ]; then
        url=$(AWS_ACCESS_KEY_ID="$kid" \
              AWS_SECRET_ACCESS_KEY="$secret" \
              AWS_SESSION_TOKEN="" \
              aws s3 presign \
                  "s3://$bucket/$object_key" \
                  --endpoint-url="$S3_ENDPOINT" \
                  --region="$AWS_REGION" \
                  --expires-in "$expires" 2>/dev/null)
    elif [ "$method" = "PUT" ]; then
        url=$(AWS_ACCESS_KEY_ID="$kid" \
              AWS_SECRET_ACCESS_KEY="$secret" \
              AWS_SESSION_TOKEN="" \
              aws s3 presign \
                  "s3://$bucket/$object_key" \
                  --endpoint-url="$S3_ENDPOINT" \
                  --region="$AWS_REGION" \
                  --expires-in "$expires" 2>/dev/null)
    fi

    echo "$url"
}

# =============================================================================
# Setup
# =============================================================================

test_setup() {
    log "Creating test buckets for presigned URL tests..."

    aws_s3api create-bucket --bucket "$PS_BUCKET" >/dev/null 2>&1 || true
    aws_s3api create-bucket --bucket "$PS_OUTSIDE" >/dev/null 2>&1 || true

    local test_file="$TEMP_DIR/presign-test-obj.txt"
    echo "presigned URL test content" > "$test_file"
    aws_s3api put-object --bucket "$PS_BUCKET" \
        --key "test.txt" --body "$test_file" >/dev/null 2>&1
    aws_s3api put-object --bucket "$PS_OUTSIDE" \
        --key "test.txt" --body "$test_file" >/dev/null 2>&1

    # read-only key scoped to PS_BUCKET
    local ro_scope='[{"bucket":"'"$PS_BUCKET"'","level":"read"}]'
    if ! create_scoped_key "$ro_scope"; then
        error "Setup - failed to create read-only key"
        return 1
    fi
    PS_RO_KEY_ID="$LAST_KEY_ID"
    PS_RO_SECRET="$LAST_KEY_SECRET"
    log "Created read-only key: $PS_RO_KEY_ID"

    # readwrite key scoped to PS_BUCKET
    local rw_scope='[{"bucket":"'"$PS_BUCKET"'","level":"readwrite"}]'
    if ! create_scoped_key "$rw_scope"; then
        error "Setup - failed to create readwrite key"
        return 1
    fi
    PS_RW_KEY_ID="$LAST_KEY_ID"
    PS_RW_SECRET="$LAST_KEY_SECRET"
    log "Created readwrite key: $PS_RW_KEY_ID"

    wait_for_replication
    success "Presigned URL test setup complete"
}

# =============================================================================
# Test 1: Pre-signed GET on scoped bucket (read) → allowed
# =============================================================================

test_presigned_get_allowed() {
    log "=== Test 1: Pre-signed GET on scoped bucket ==="

    local url
    url=$(generate_presigned_url "GET" "$PS_BUCKET" "test.txt" \
        "$PS_RO_KEY_ID" "$PS_RO_SECRET")

    if [ -z "$url" ]; then
        error "Presigned GET allowed - could not generate URL"
        return 1
    fi
    log "Pre-signed URL generated (${#url} chars)"

    set +e
    local result http_code
    result=$(curl -sk -o "$TEMP_DIR/presign-get.txt" -w "%{http_code}" "$url" 2>&1)
    http_code=$(echo "$result" | tail -1)
    set -e

    if [ "$http_code" = "200" ]; then
        success "Presigned GET on scoped bucket - 200 OK"
    elif echo "$result" | grep -q "403\|AccessDenied"; then
        error "Presigned GET on scoped bucket - denied (should be allowed)"
    else
        error "Presigned GET on scoped bucket - unexpected HTTP $http_code"
        log "Response: $result"
    fi
}

# =============================================================================
# Test 2: Pre-signed GET on unscoped bucket → denied
# =============================================================================

test_presigned_get_denied() {
    log "=== Test 2: Pre-signed GET on unscoped bucket ==="

    local url
    url=$(generate_presigned_url "GET" "$PS_OUTSIDE" "test.txt" \
        "$PS_RO_KEY_ID" "$PS_RO_SECRET")

    if [ -z "$url" ]; then
        error "Presigned GET denied - could not generate URL"
        return 1
    fi

    set +e
    local body http_code
    body=$(curl -sk -w "\n%{http_code}" "$url" 2>&1)
    http_code=$(echo "$body" | tail -1)
    body=$(echo "$body" | head -n -1)
    set -e

    if [ "$http_code" = "403" ]; then
        success "Presigned GET on unscoped bucket - 403 denied"
    elif echo "$body" | grep -qi "AccessDenied\|Forbidden"; then
        success "Presigned GET on unscoped bucket - denied"
    elif [ "$http_code" = "502" ] || [ "$http_code" = "503" ]; then
        error "Presigned GET on unscoped bucket - 502/503 (backend crash)"
    else
        error "Presigned GET on unscoped bucket - expected 403, got HTTP $http_code"
        log "Body: $body"
    fi
}

# =============================================================================
# Test 3: PUT with read-only scoped key → denied
#
# Note: `aws s3 presign` only generates GET-signed URLs.  For write
# operations we fall back to `aws s3api put-object` with the scoped
# key's credentials, which exercises the same server-side scope check.
# =============================================================================

with_key() {
    local kid="$1"
    local secret="$2"
    shift 2
    AWS_ACCESS_KEY_ID="$kid" \
    AWS_SECRET_ACCESS_KEY="$secret" \
    AWS_SESSION_TOKEN="" \
    "$@"
}

test_put_readonly_denied() {
    log "=== Test 3: PUT object with read-only scoped key (denied) ==="

    assert_s3_deny \
        "PUT read-only key - denied (readwrite required)" \
        "AccessDenied" \
        with_key "$PS_RO_KEY_ID" "$PS_RO_SECRET" \
            aws_s3api put-object \
                --bucket "$PS_BUCKET" \
                --key "presign-put-ro.txt" \
                --body "$TEMP_DIR/presign-test-obj.txt"
}

# =============================================================================
# Test 4: PUT with readwrite scoped key → allowed
# =============================================================================

test_put_readwrite_allowed() {
    log "=== Test 4: PUT object with readwrite scoped key (allowed) ==="

    set +e
    local result
    result=$(retry_on_auth with_key "$PS_RW_KEY_ID" "$PS_RW_SECRET" \
        aws_s3api put-object \
            --bucket "$PS_BUCKET" \
            --key "presign-put-rw.txt" \
            --body "$TEMP_DIR/presign-test-obj.txt" 2>&1)
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "PUT readwrite key - allowed"
    else
        error "PUT readwrite key - should be allowed: $result"
    fi
}

# =============================================================================
# Cleanup
# =============================================================================

test_cleanup() {
    log "Cleaning up presigned URL test resources..."
    set +e

    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN

    for bkt in "$PS_BUCKET" "$PS_OUTSIDE"; do
        aws_s3 rm "s3://$bkt" --recursive 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$bkt" 2>/dev/null || true
    done

    for kid in "$PS_RO_KEY_ID" "$PS_RW_KEY_ID"; do
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
    log "Scope — Pre-signed URL Tests"
    log "=========================================="
    log "  S3 Endpoint:      $S3_ENDPOINT"
    log "  CloudAPI:         $CLOUDAPI_URL"
    log "  Account:          $MANTA_USER"
    log "  Replication wait: ${REPL_WAIT}s"
    log "=========================================="

    setup
    test_setup

    test_presigned_get_allowed
    test_presigned_get_denied
    test_put_readonly_denied
    test_put_readwrite_allowed

    test_cleanup
    print_summary
}

main "$@"
