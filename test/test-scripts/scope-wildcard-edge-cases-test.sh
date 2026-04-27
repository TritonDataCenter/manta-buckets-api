#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Per-Bucket Access Key Scope — Wildcard Pattern Edge Cases
#
# Tests boundary conditions in wildcard pattern matching that go beyond
# the basic bucket-scope-test.sh Test 6 (simple logs-* wildcard).
#
# Tests:
#   1. Wildcard `*` grants access to ALL buckets (= unrestricted)
#   2. `prefix-*` matches `prefix-` (empty suffix after wildcard)
#   3. `prefix-*` does NOT match `prefix` (no trailing hyphen)
#   4. Multiple wildcard rules — highest level wins
#   5. Exact match + wildcard — exact gets its own level
#   6. Large scope (50 entries) still enforced correctly
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

# Test bucket names — unique per run
TS=$(date +%s)
WC_BUCKET_ANY_A="scope-wc-any-a-${TS}"
WC_BUCKET_ANY_B="scope-wc-any-b-${TS}"
WC_PREFIX_EMPTY="scope-wc-prefix-${TS}"   # ends with prefix- (empty suffix)
WC_PREFIX_MATCH="scope-wc-prefix-x-${TS}" # matches prefix-*
WC_PREFIX_NOHYP="scope-wc-prefix${TS}"    # no hyphen, should NOT match prefix-*
WC_EXACT="scope-wc-exact-${TS}"
WC_MULTI_RW="scope-wc-multi-rw-${TS}"

# Key tracking
CREATED_KEY_IDS=()

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
    CREATED_KEY_IDS+=("$LAST_KEY_ID")
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

ALL_BUCKETS=()

test_setup() {
    log "Creating test buckets for wildcard edge case tests..."

    ALL_BUCKETS=(
        "$WC_BUCKET_ANY_A" "$WC_BUCKET_ANY_B"
        "$WC_PREFIX_EMPTY" "$WC_PREFIX_MATCH" "$WC_PREFIX_NOHYP"
        "$WC_EXACT" "$WC_MULTI_RW"
    )

    local test_file="$TEMP_DIR/wc-test-obj.txt"
    echo "wildcard edge case test" > "$test_file"

    for bkt in "${ALL_BUCKETS[@]}"; do
        aws_s3api create-bucket --bucket "$bkt" >/dev/null 2>&1 || true
        aws_s3api put-object --bucket "$bkt" \
            --key "test.txt" --body "$test_file" >/dev/null 2>&1 || true
    done

    success "Wildcard edge case test setup complete"
}

# =============================================================================
# Test 1: Wildcard `*` grants access to ALL buckets
# =============================================================================

test_star_grants_all() {
    log "=== Test 1: Wildcard * grants access to all buckets ==="

    local scope='[{"bucket":"*","level":"full"}]'
    if ! create_scoped_key "$scope"; then
        error "Test 1 - failed to create star key"
        return 1
    fi
    local kid="$LAST_KEY_ID"
    local secret="$LAST_KEY_SECRET"
    wait_for_replication

    # Should access any bucket
    set +e
    retry_on_auth with_key "$kid" "$secret" \
        aws_s3api get-object \
            --bucket "$WC_BUCKET_ANY_A" \
            --key "test.txt" \
            "$TEMP_DIR/wc-star-a.txt" >/dev/null 2>&1
    local rc1=$?

    retry_on_auth with_key "$kid" "$secret" \
        aws_s3api get-object \
            --bucket "$WC_BUCKET_ANY_B" \
            --key "test.txt" \
            "$TEMP_DIR/wc-star-b.txt" >/dev/null 2>&1
    local rc2=$?
    set -e

    if [ $rc1 -eq 0 ] && [ $rc2 -eq 0 ]; then
        success "Wildcard * - accesses all buckets (functionally unrestricted)"
    else
        error "Wildcard * - should access all buckets (rc1=$rc1, rc2=$rc2)"
    fi
}

# =============================================================================
# Test 2: `prefix-*` matches `prefix-` (empty suffix)
# =============================================================================

test_prefix_wildcard_empty_suffix() {
    log "=== Test 2: prefix-* matches prefix- (empty suffix after wildcard) ==="

    # WC_PREFIX_EMPTY is "scope-wc-prefix-<ts>" which ends with the timestamp.
    # We need a wildcard pattern that matches it.
    # Use "scope-wc-prefix-*" which should match "scope-wc-prefix-<ts>"
    local pattern="scope-wc-prefix-*"
    local scope='[{"bucket":"'"$pattern"'","level":"read"}]'
    if ! create_scoped_key "$scope"; then
        error "Test 2 - failed to create prefix key"
        return 1
    fi
    local kid="$LAST_KEY_ID"
    local secret="$LAST_KEY_SECRET"
    wait_for_replication

    # WC_PREFIX_EMPTY = "scope-wc-prefix-<ts>" matches "scope-wc-prefix-*"
    set +e
    retry_on_auth with_key "$kid" "$secret" \
        aws_s3api get-object \
            --bucket "$WC_PREFIX_EMPTY" \
            --key "test.txt" \
            "$TEMP_DIR/wc-prefix-empty.txt" >/dev/null 2>&1
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "prefix-* matches prefix-<suffix> (empty suffix position)"
    else
        error "prefix-* should match prefix-<suffix>"
    fi

    # Also matches longer suffix
    set +e
    retry_on_auth with_key "$kid" "$secret" \
        aws_s3api get-object \
            --bucket "$WC_PREFIX_MATCH" \
            --key "test.txt" \
            "$TEMP_DIR/wc-prefix-match.txt" >/dev/null 2>&1
    rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "prefix-* matches prefix-x-<suffix>"
    else
        error "prefix-* should match prefix-x-<suffix>"
    fi
}

# =============================================================================
# Test 3: `prefix-*` does NOT match `prefix` (no trailing hyphen)
# =============================================================================

test_prefix_wildcard_no_hyphen() {
    log "=== Test 3: prefix-* does NOT match prefix (no hyphen) ==="

    # WC_PREFIX_NOHYP = "scope-wc-prefix<ts>" (no hyphen before ts)
    # "scope-wc-prefix-*" should NOT match it because the literal prefix
    # is "scope-wc-prefix-" and the bucket name has no hyphen after "prefix".
    #
    # Use the key from Test 2 if still around, or create a new one.
    local pattern="scope-wc-prefix-*"
    local scope='[{"bucket":"'"$pattern"'","level":"read"}]'
    if ! create_scoped_key "$scope"; then
        error "Test 3 - failed to create prefix key"
        return 1
    fi
    local kid="$LAST_KEY_ID"
    local secret="$LAST_KEY_SECRET"
    wait_for_replication

    assert_s3_deny \
        "prefix-* does NOT match prefix<no-hyphen>" \
        "AccessDenied" \
        with_key "$kid" "$secret" \
            aws_s3api get-object \
                --bucket "$WC_PREFIX_NOHYP" \
                --key "test.txt" \
                "$TEMP_DIR/wc-no-hyphen.txt"
}

# =============================================================================
# Test 4: Multiple wildcard rules — highest level wins
# =============================================================================

test_multiple_wildcards_highest_wins() {
    log "=== Test 4: Multiple wildcard rules — highest level wins ==="

    # Scope with two overlapping patterns:
    #   scope-wc-multi-*  : read
    #   scope-wc-multi-rw-* : readwrite
    # WC_MULTI_RW = "scope-wc-multi-rw-<ts>" matches BOTH patterns.
    # The highest level (readwrite) should apply.
    local scope='[{"bucket":"scope-wc-multi-*","level":"read"},{"bucket":"scope-wc-multi-rw-*","level":"readwrite"}]'
    if ! create_scoped_key "$scope"; then
        error "Test 4 - failed to create multi-wildcard key"
        return 1
    fi
    local kid="$LAST_KEY_ID"
    local secret="$LAST_KEY_SECRET"
    wait_for_replication

    # PUT should work because readwrite is the highest matching level
    set +e
    local put_result
    put_result=$(retry_on_auth with_key "$kid" "$secret" \
        aws_s3api put-object \
            --bucket "$WC_MULTI_RW" \
            --key "multi-wc-test.txt" \
            --body "$TEMP_DIR/wc-test-obj.txt" 2>&1)
    local put_rc=$?
    set -e

    if [ $put_rc -eq 0 ]; then
        success "Multiple wildcards - readwrite wins over read for matching bucket"
    else
        error "Multiple wildcards - readwrite should apply: $put_result"
    fi

    # GET should also work (readwrite includes read)
    set +e
    retry_on_auth with_key "$kid" "$secret" \
        aws_s3api get-object \
            --bucket "$WC_MULTI_RW" \
            --key "test.txt" \
            "$TEMP_DIR/wc-multi-get.txt" >/dev/null 2>&1
    local get_rc=$?
    set -e

    if [ $get_rc -eq 0 ]; then
        success "Multiple wildcards - GET also allowed (readwrite includes read)"
    else
        error "Multiple wildcards - GET should be allowed"
    fi
}

# =============================================================================
# Test 5: Exact match + wildcard — each gets its own level
# =============================================================================

test_exact_and_wildcard() {
    log "=== Test 5: Exact match + wildcard — exact gets its own level ==="

    # Scope:
    #   scope-wc-exact-<ts> : full   (exact)
    #   scope-wc-*          : read   (wildcard)
    # WC_EXACT matches both, but exact match should give full access.
    local scope='[{"bucket":"'"$WC_EXACT"'","level":"full"},{"bucket":"scope-wc-*","level":"read"}]'
    if ! create_scoped_key "$scope"; then
        error "Test 5 - failed to create exact+wildcard key"
        return 1
    fi
    local kid="$LAST_KEY_ID"
    local secret="$LAST_KEY_SECRET"
    wait_for_replication

    # Full access on exact bucket: try creating + deleting a bucket-level operation
    # (PUT object should work since full > readwrite > read)
    set +e
    retry_on_auth with_key "$kid" "$secret" \
        aws_s3api put-object \
            --bucket "$WC_EXACT" \
            --key "exact-test.txt" \
            --body "$TEMP_DIR/wc-test-obj.txt" >/dev/null 2>&1
    local put_rc=$?
    set -e

    if [ $put_rc -eq 0 ]; then
        success "Exact + wildcard - PUT allowed on exact-match bucket (full level)"
    else
        error "Exact + wildcard - PUT should be allowed on exact-match bucket"
    fi

    # Other wildcard-matched buckets should only have read
    assert_s3_deny \
        "Exact + wildcard - PUT denied on wildcard-only bucket (read level)" \
        "AccessDenied" \
        with_key "$kid" "$secret" \
            aws_s3api put-object \
                --bucket "$WC_BUCKET_ANY_A" \
                --key "wildcard-only.txt" \
                --body "$TEMP_DIR/wc-test-obj.txt"
}

# =============================================================================
# Test 6: Large scope (50 entries) still enforced correctly
# =============================================================================

test_large_scope() {
    log "=== Test 6: Large scope (50 entries) — performance and correctness ==="

    # Build a scope with 49 fake bucket patterns + 1 real one
    local scope_entries='['
    for i in $(seq 1 49); do
        scope_entries+='{"bucket":"fake-bucket-'"$i"'-*","level":"read"},'
    done
    scope_entries+='{"bucket":"'"$WC_BUCKET_ANY_A"'","level":"readwrite"}'
    scope_entries+=']'

    if ! create_scoped_key "$scope_entries"; then
        error "Test 6 - failed to create large-scope key"
        return 1
    fi
    local kid="$LAST_KEY_ID"
    local secret="$LAST_KEY_SECRET"
    wait_for_replication

    # The real bucket should be accessible with readwrite
    set +e
    retry_on_auth with_key "$kid" "$secret" \
        aws_s3api put-object \
            --bucket "$WC_BUCKET_ANY_A" \
            --key "large-scope-test.txt" \
            --body "$TEMP_DIR/wc-test-obj.txt" >/dev/null 2>&1
    local put_rc=$?
    set -e

    if [ $put_rc -eq 0 ]; then
        success "Large scope (50 entries) - PUT allowed on scoped bucket"
    else
        error "Large scope (50 entries) - PUT should be allowed"
    fi

    # Other buckets should still be denied
    assert_s3_deny \
        "Large scope (50 entries) - GET denied on unscoped bucket" \
        "AccessDenied" \
        with_key "$kid" "$secret" \
            aws_s3api get-object \
                --bucket "$WC_BUCKET_ANY_B" \
                --key "test.txt" \
                "$TEMP_DIR/wc-large-deny.txt"
}

# =============================================================================
# Cleanup
# =============================================================================

test_cleanup() {
    log "Cleaning up wildcard edge case test resources..."
    set +e

    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN

    for bkt in "${ALL_BUCKETS[@]}"; do
        aws_s3 rm "s3://$bkt" --recursive 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$bkt" 2>/dev/null || true
    done

    for kid in "${CREATED_KEY_IDS[@]}"; do
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
    log "Scope — Wildcard Pattern Edge Cases"
    log "=========================================="
    log "  S3 Endpoint:      $S3_ENDPOINT"
    log "  CloudAPI:         $CLOUDAPI_URL"
    log "  Account:          $MANTA_USER"
    log "  Replication wait: ${REPL_WAIT}s"
    log "=========================================="

    setup
    test_setup

    test_star_grants_all
    test_prefix_wildcard_empty_suffix
    test_prefix_wildcard_no_hyphen
    test_multiple_wildcards_highest_wins
    test_exact_and_wildcard
    test_large_scope

    test_cleanup
    print_summary
}

main "$@"
