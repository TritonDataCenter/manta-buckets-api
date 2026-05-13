#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Per-Bucket Access Key Scope — Cross-Account Isolation Tests
#
# Verifies that scope JSON in account A does NOT grant access
# to a bucket in account B, even when the scope literally names
# B's bucket. Pins the property that bucket-scope resolution is
# account-local: an access key can only see the bucket
# namespace of its owning account.
#
# Setup is asymmetric so the security failure mode is sharp:
#   - Each account owns a UNIQUELY named bucket with a secret
#     probe object that the OTHER account does not have.
#   - Each account also has a "foreign-scope" key whose scope
#     JSON literally names the OTHER account's bucket.
#
# If scope crossed accounts (the bug we're guarding against),
# the foreign-scope key would read the other account's secret.
# Correct behavior: every cross-account attempt is denied with
# either AccessDenied (403) or NoSuchBucket / NoSuchKey (404),
# because the bucket name does not exist in the calling
# account's namespace.
#
# Tests:
#   1. A2 foreign-scope key → GET A1's probe in A1's bucket → denied
#   2. A2 foreign-scope key → PUT into A1's bucket → denied
#   3. A2 foreign-scope key → DELETE-object in A1's bucket → denied
#   4. A1 foreign-scope key → GET A2's probe in A2's bucket → denied
#   5. A1 foreign-scope key → PUT into A2's bucket → denied
#   6. A1 foreign-scope key → DELETE-object in A2's bucket → denied
#   7. Sanity: each account's OWN-scope key reads its own probe
#      (isolates "cross-account denied" from "scope is broken")
#   8. Sanity: A1's probe + A2's probe are intact after the
#      cross-account attempts (proves no DELETE silently took
#      effect across accounts)
#
# Prerequisites:
#   - CloudAPI running (CLOUDAPI_URL)
#   - manta-buckets-api running (S3_ENDPOINT)
#   - MANTA_USER, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY set
#     (for the primary account — neirac)
#   - A second account (SDC_ACCOUNT_2, default neirac2) exists
#     and has the SAME SSH key (~/.ssh/id_rsa) registered. The
#     CloudAPI key label under that account defaults to
#     "neirac@ThinkBook01" (see SDC_KEY_NAME_2 override).
#   - jq, openssl

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

CLOUDAPI_URL=${CLOUDAPI_URL:-"https://localhost:8443"}
REPL_WAIT=${REPL_WAIT:-3}

# Account 1 (primary — owns AWS_ACCESS_KEY_ID in env)
SDC_ACCOUNT=${SDC_ACCOUNT:-"neirac"}
SDC_KEY_NAME=${SDC_KEY_NAME:-"macbook m1"}

# Account 2 (secondary — same SSH key, different account).
# Same id_rsa is registered under both accounts but with a
# different CloudAPI key label (neirac2 has it under the SSH
# pubkey comment "neirac@ThinkBook01").
SDC_ACCOUNT_2=${SDC_ACCOUNT_2:-"neirac2"}
SDC_KEY_NAME_2=${SDC_KEY_NAME_2:-"neirac@ThinkBook01"}

SDC_URL=${CLOUDAPI_URL}
SSH_KEY=${SSH_KEY:-"$HOME/.ssh/id_rsa"}

# UNIQUE bucket names per account. The whole point of this
# test is that the foreign-scope key names a bucket that does
# NOT exist in its own account's namespace.
BUCKET_A1="xacct-a1-$(date +%s)"
BUCKET_A2="xacct-a2-$(date +%s)"

# Distinct probe content per account. If scope crossed
# account boundaries, the foreign-scope key would download
# the other account's secret string — easy to grep for.
PROBE_A1_CONTENT="probe-account-1-neirac-$(date +%s)-secret-a1"
PROBE_A2_CONTENT="probe-account-2-neirac2-$(date +%s)-secret-a2"

# Key + secret tracking
A1_ADMIN_KEY_ID="$AWS_ACCESS_KEY_ID"
A1_ADMIN_SECRET="$AWS_SECRET_ACCESS_KEY"
A1_OWN_KEY_ID=""      # scope=BUCKET_A1 (sanity)
A1_OWN_SECRET=""
A1_FOREIGN_KEY_ID=""  # scope=BUCKET_A2 (the attack)
A1_FOREIGN_SECRET=""
A2_ADMIN_KEY_ID=""
A2_ADMIN_SECRET=""
A2_OWN_KEY_ID=""      # scope=BUCKET_A2 (sanity)
A2_OWN_SECRET=""
A2_FOREIGN_KEY_ID=""  # scope=BUCKET_A1 (the attack)
A2_FOREIGN_SECRET=""

# =============================================================================
# CloudAPI helpers — parameterized by account/key-name so we
# can sign requests for either account using the same SSH key.
# =============================================================================

cloudapi_as() {
    local account="$1"
    local key_name="$2"
    local method="$3"
    local path="$4"
    shift 4

    local now signature
    now=$(date -u '+%a, %d %h %Y %H:%M:%S GMT')
    signature=$(echo -n "$now" | \
        openssl dgst -sha256 -sign "$SSH_KEY" | \
        openssl enc -e -a | tr -d '\n')

    curl -sk -X "$method" \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/json' \
        -H "accept-version: ~8" \
        -H "Date: $now" \
        -H "Authorization: Signature keyId=\"/$account/keys/$key_name\",algorithm=\"rsa-sha256\" $signature" \
        "$SDC_URL/$account$path" \
        "$@"
}

create_access_key_for() {
    local account="$1"
    local key_name="$2"
    local scope_json="$3"

    local body
    if [ -n "$scope_json" ]; then
        body=$(jq -n --argjson perms "$scope_json" \
            '{ scope: { version: 1, permissions: $perms } }')
    else
        body='{}'
    fi

    local resp
    resp=$(cloudapi_as "$account" "$key_name" POST /accesskeys -d "$body" 2>/dev/null)

    LAST_KEY_ID=$(echo "$resp" | jq -r '.accesskeyid // empty')
    LAST_KEY_SECRET=$(echo "$resp" | jq -r '.accesskeysecret // empty')

    if [ -z "$LAST_KEY_ID" ] || [ -z "$LAST_KEY_SECRET" ]; then
        echo "DEBUG: CloudAPI response: $resp" >&2
        return 1
    fi
    return 0
}

delete_access_key_for() {
    local account="$1"
    local key_name="$2"
    local key_id="$3"
    [ -z "$key_id" ] && return 0
    cloudapi_as "$account" "$key_name" DELETE "/accesskeys/$key_id" 2>/dev/null || true
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

# Permissive cross-account deny check: accept any non-success
# rc whose output mentions a denial / not-found signal.
# Account-local namespace lookup means the foreign bucket name
# doesn't exist in the caller's namespace, so we may get
# NoSuchBucket / NoSuchKey (404) instead of AccessDenied (403).
# Both prove the security property: the caller's account
# cannot resolve the other account's bucket.
#
# leak_marker (optional): if the call surprisingly returns 0,
# also check whether the output contains the OTHER account's
# secret string — a confirmed data leak.
assert_cross_account_denied() {
    local label="$1"
    local leak_marker="$2"
    shift 2
    set +e
    local result
    result=$("$@" 2>&1)
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        if [ -n "$leak_marker" ] && echo "$result" | grep -qF "$leak_marker"; then
            error "$label - CRITICAL LEAK: cross-account content returned"
        else
            error "$label - command unexpectedly succeeded (rc=0)"
        fi
        return 1
    fi

    if echo "$result" | grep -qi "503\|502\|Service Unavailable"; then
        error "$label - 502/503 (backend crash, not a valid deny)"
        return 1
    fi

    # Manta's S3 API may wrap "bucket/key not in your account's
    # namespace" as InternalError with a "was not found" message
    # rather than NoSuchBucket / NoSuchKey. From a security
    # standpoint any of these proves the call failed without
    # returning the other account's data — which is the property
    # we're pinning. Accept all of them.
    if echo "$result" | grep -qiE "403|404|Forbidden|AccessDenied|NoSuchBucket|NoSuchKey|denied|not.found"; then
        local kind
        kind=$(echo "$result" | grep -oiE 'AccessDenied|NoSuchBucket|NoSuchKey|Forbidden|not found|was not found|403|404' | head -1)
        success "$label (denied: ${kind:-error})"
        return 0
    fi

    error "$label - expected denial but got: $result"
    return 1
}

# =============================================================================
# Setup
# =============================================================================

test_setup() {
    log "=== Setup ==="
    log "Account 1: $SDC_ACCOUNT (using existing admin AWS key)"
    log "Account 2: $SDC_ACCOUNT_2 (bootstrapping admin key via CloudAPI)"
    log "Account 1 bucket: $BUCKET_A1"
    log "Account 2 bucket: $BUCKET_A2"

    # ---- Bootstrap an admin (unscoped) key for account 2 ----
    if ! create_access_key_for "$SDC_ACCOUNT_2" "$SDC_KEY_NAME_2" ""; then
        error "Setup - failed to create unscoped admin key for $SDC_ACCOUNT_2"
        return 1
    fi
    A2_ADMIN_KEY_ID="$LAST_KEY_ID"
    A2_ADMIN_SECRET="$LAST_KEY_SECRET"
    log "Created $SDC_ACCOUNT_2 admin key: $A2_ADMIN_KEY_ID"
    wait_for_replication

    # ---- Each account creates its OWN bucket (different names) ----
    set +e
    with_key "$A1_ADMIN_KEY_ID" "$A1_ADMIN_SECRET" \
        aws_s3api create-bucket --bucket "$BUCKET_A1" >/dev/null 2>&1
    local mk1_rc=$?
    with_key "$A2_ADMIN_KEY_ID" "$A2_ADMIN_SECRET" \
        aws_s3api create-bucket --bucket "$BUCKET_A2" >/dev/null 2>&1
    local mk2_rc=$?
    set -e
    [ $mk1_rc -eq 0 ] || { error "Setup - failed to create $BUCKET_A1 under $SDC_ACCOUNT"; return 1; }
    [ $mk2_rc -eq 0 ] || { error "Setup - failed to create $BUCKET_A2 under $SDC_ACCOUNT_2"; return 1; }
    log "Created $BUCKET_A1 (account 1) and $BUCKET_A2 (account 2)"

    # ---- Probe objects ----
    echo "$PROBE_A1_CONTENT" > "$TEMP_DIR/probe-a1.txt"
    echo "$PROBE_A2_CONTENT" > "$TEMP_DIR/probe-a2.txt"
    with_key "$A1_ADMIN_KEY_ID" "$A1_ADMIN_SECRET" \
        aws_s3api put-object \
            --bucket "$BUCKET_A1" --key "probe.txt" \
            --body "$TEMP_DIR/probe-a1.txt" >/dev/null 2>&1
    with_key "$A2_ADMIN_KEY_ID" "$A2_ADMIN_SECRET" \
        aws_s3api put-object \
            --bucket "$BUCKET_A2" --key "probe.txt" \
            --body "$TEMP_DIR/probe-a2.txt" >/dev/null 2>&1
    log "Wrote probe objects in each account's bucket"

    # ---- A1 own-scope key (scope=BUCKET_A1) — sanity baseline ----
    local own_a1_scope='[{"bucket":"'"$BUCKET_A1"'","level":"full"}]'
    if ! create_access_key_for "$SDC_ACCOUNT" "$SDC_KEY_NAME" "$own_a1_scope"; then
        error "Setup - failed to create A1 own-scope key"
        return 1
    fi
    A1_OWN_KEY_ID="$LAST_KEY_ID"
    A1_OWN_SECRET="$LAST_KEY_SECRET"
    log "Created A1 own-scope key:     $A1_OWN_KEY_ID (scope=$BUCKET_A1)"

    # ---- A1 foreign-scope key (scope=BUCKET_A2) — the attack ----
    local foreign_a1_scope='[{"bucket":"'"$BUCKET_A2"'","level":"full"}]'
    if ! create_access_key_for "$SDC_ACCOUNT" "$SDC_KEY_NAME" "$foreign_a1_scope"; then
        error "Setup - failed to create A1 foreign-scope key"
        return 1
    fi
    A1_FOREIGN_KEY_ID="$LAST_KEY_ID"
    A1_FOREIGN_SECRET="$LAST_KEY_SECRET"
    log "Created A1 foreign-scope key: $A1_FOREIGN_KEY_ID (scope=$BUCKET_A2 in A2)"

    # ---- A2 own-scope key (scope=BUCKET_A2) — sanity baseline ----
    local own_a2_scope='[{"bucket":"'"$BUCKET_A2"'","level":"full"}]'
    if ! create_access_key_for "$SDC_ACCOUNT_2" "$SDC_KEY_NAME_2" "$own_a2_scope"; then
        error "Setup - failed to create A2 own-scope key"
        return 1
    fi
    A2_OWN_KEY_ID="$LAST_KEY_ID"
    A2_OWN_SECRET="$LAST_KEY_SECRET"
    log "Created A2 own-scope key:     $A2_OWN_KEY_ID (scope=$BUCKET_A2)"

    # ---- A2 foreign-scope key (scope=BUCKET_A1) — the attack ----
    local foreign_a2_scope='[{"bucket":"'"$BUCKET_A1"'","level":"full"}]'
    if ! create_access_key_for "$SDC_ACCOUNT_2" "$SDC_KEY_NAME_2" "$foreign_a2_scope"; then
        error "Setup - failed to create A2 foreign-scope key"
        return 1
    fi
    A2_FOREIGN_KEY_ID="$LAST_KEY_ID"
    A2_FOREIGN_SECRET="$LAST_KEY_SECRET"
    log "Created A2 foreign-scope key: $A2_FOREIGN_KEY_ID (scope=$BUCKET_A1 in A1)"

    wait_for_replication
    success "Cross-account scope test setup complete"
}

# =============================================================================
# Tests 1-3: Account 2's foreign-scope key cannot reach Account 1's bucket
# =============================================================================

test_a2_foreign_cannot_get_a1_probe() {
    log "=== Test 1: A2 foreign-scope key → GET A1's probe ==="
    assert_cross_account_denied \
        "Cross-account - A2 foreign GET against A1 bucket denied" \
        "$PROBE_A1_CONTENT" \
        with_key "$A2_FOREIGN_KEY_ID" "$A2_FOREIGN_SECRET" \
            aws_s3api get-object \
                --bucket "$BUCKET_A1" --key "probe.txt" \
                "$TEMP_DIR/leak-a2-to-a1.bin"
    # Belt-and-braces leak check
    if [ -f "$TEMP_DIR/leak-a2-to-a1.bin" ] && \
       grep -qF "$PROBE_A1_CONTENT" "$TEMP_DIR/leak-a2-to-a1.bin"; then
        error "Cross-account - LEAK CONFIRMED: A1 probe content in A2 download"
    fi
}

test_a2_foreign_cannot_put_into_a1_bucket() {
    log "=== Test 2: A2 foreign-scope key → PUT into A1's bucket ==="
    echo "from-a2-injection-attempt" > "$TEMP_DIR/a2-inject.txt"
    assert_cross_account_denied \
        "Cross-account - A2 foreign PUT into A1 bucket denied" \
        "" \
        with_key "$A2_FOREIGN_KEY_ID" "$A2_FOREIGN_SECRET" \
            aws_s3api put-object \
                --bucket "$BUCKET_A1" --key "a2-injection.txt" \
                --body "$TEMP_DIR/a2-inject.txt"
}

test_a2_foreign_cannot_delete_a1_object() {
    log "=== Test 3: A2 foreign-scope key → DELETE-object in A1's bucket ==="
    assert_cross_account_denied \
        "Cross-account - A2 foreign DELETE-object in A1 bucket denied" \
        "" \
        with_key "$A2_FOREIGN_KEY_ID" "$A2_FOREIGN_SECRET" \
            aws_s3api delete-object \
                --bucket "$BUCKET_A1" --key "probe.txt"
}

# =============================================================================
# Tests 4-6: Account 1's foreign-scope key cannot reach Account 2's bucket
# =============================================================================

test_a1_foreign_cannot_get_a2_probe() {
    log "=== Test 4: A1 foreign-scope key → GET A2's probe ==="
    assert_cross_account_denied \
        "Cross-account - A1 foreign GET against A2 bucket denied" \
        "$PROBE_A2_CONTENT" \
        with_key "$A1_FOREIGN_KEY_ID" "$A1_FOREIGN_SECRET" \
            aws_s3api get-object \
                --bucket "$BUCKET_A2" --key "probe.txt" \
                "$TEMP_DIR/leak-a1-to-a2.bin"
    if [ -f "$TEMP_DIR/leak-a1-to-a2.bin" ] && \
       grep -qF "$PROBE_A2_CONTENT" "$TEMP_DIR/leak-a1-to-a2.bin"; then
        error "Cross-account - LEAK CONFIRMED: A2 probe content in A1 download"
    fi
}

test_a1_foreign_cannot_put_into_a2_bucket() {
    log "=== Test 5: A1 foreign-scope key → PUT into A2's bucket ==="
    echo "from-a1-injection-attempt" > "$TEMP_DIR/a1-inject.txt"
    assert_cross_account_denied \
        "Cross-account - A1 foreign PUT into A2 bucket denied" \
        "" \
        with_key "$A1_FOREIGN_KEY_ID" "$A1_FOREIGN_SECRET" \
            aws_s3api put-object \
                --bucket "$BUCKET_A2" --key "a1-injection.txt" \
                --body "$TEMP_DIR/a1-inject.txt"
}

test_a1_foreign_cannot_delete_a2_object() {
    log "=== Test 6: A1 foreign-scope key → DELETE-object in A2's bucket ==="
    assert_cross_account_denied \
        "Cross-account - A1 foreign DELETE-object in A2 bucket denied" \
        "" \
        with_key "$A1_FOREIGN_KEY_ID" "$A1_FOREIGN_SECRET" \
            aws_s3api delete-object \
                --bucket "$BUCKET_A2" --key "probe.txt"
}

# =============================================================================
# Test 7: Sanity — each account's OWN-scope key DOES work in
# its own bucket. Isolates "cross-account denied" from "scope
# is broken".
# =============================================================================

test_own_account_works() {
    log "=== Test 7: Each own-scope key reads its own probe ==="

    set +e
    with_key "$A1_OWN_KEY_ID" "$A1_OWN_SECRET" \
        aws_s3api get-object \
            --bucket "$BUCKET_A1" --key "probe.txt" \
            "$TEMP_DIR/own-a1.txt" >/dev/null 2>&1
    local a1_rc=$?
    set -e
    if [ $a1_rc -eq 0 ] && grep -qF "$PROBE_A1_CONTENT" "$TEMP_DIR/own-a1.txt"; then
        success "Own-account - A1 own-scope key reads A1 probe"
    else
        error "Own-account - A1 own-scope key cannot read A1 probe (rc=$a1_rc)"
    fi

    set +e
    with_key "$A2_OWN_KEY_ID" "$A2_OWN_SECRET" \
        aws_s3api get-object \
            --bucket "$BUCKET_A2" --key "probe.txt" \
            "$TEMP_DIR/own-a2.txt" >/dev/null 2>&1
    local a2_rc=$?
    set -e
    if [ $a2_rc -eq 0 ] && grep -qF "$PROBE_A2_CONTENT" "$TEMP_DIR/own-a2.txt"; then
        success "Own-account - A2 own-scope key reads A2 probe"
    else
        error "Own-account - A2 own-scope key cannot read A2 probe (rc=$a2_rc)"
    fi
}

# =============================================================================
# Test 8: Sanity — probes are intact after the cross-account
# attempts (proves no DELETE-object silently took effect across
# accounts).
# =============================================================================

test_probes_intact() {
    log "=== Test 8: Both probes still intact after attack attempts ==="

    set +e
    with_key "$A1_ADMIN_KEY_ID" "$A1_ADMIN_SECRET" \
        aws_s3api get-object \
            --bucket "$BUCKET_A1" --key "probe.txt" \
            "$TEMP_DIR/probe-a1-after.txt" >/dev/null 2>&1
    local a1_get_rc=$?
    with_key "$A2_ADMIN_KEY_ID" "$A2_ADMIN_SECRET" \
        aws_s3api get-object \
            --bucket "$BUCKET_A2" --key "probe.txt" \
            "$TEMP_DIR/probe-a2-after.txt" >/dev/null 2>&1
    local a2_get_rc=$?
    set -e

    if [ $a1_get_rc -eq 0 ] && \
       grep -qF "$PROBE_A1_CONTENT" "$TEMP_DIR/probe-a1-after.txt"; then
        success "Integrity - A1 probe intact after attack attempts"
    else
        error "Integrity - A1 probe missing or modified after attack"
    fi

    if [ $a2_get_rc -eq 0 ] && \
       grep -qF "$PROBE_A2_CONTENT" "$TEMP_DIR/probe-a2-after.txt"; then
        success "Integrity - A2 probe intact after attack attempts"
    else
        error "Integrity - A2 probe missing or modified after attack"
    fi
}

# =============================================================================
# Cleanup
# =============================================================================

test_cleanup() {
    log "Cleaning up keys + buckets in both accounts..."

    # Empty + delete each account's bucket
    for kid_secret_acct_bkt in \
        "$A1_ADMIN_KEY_ID:$A1_ADMIN_SECRET:$BUCKET_A1" \
        "$A2_ADMIN_KEY_ID:$A2_ADMIN_SECRET:$BUCKET_A2"; do
        local kid="${kid_secret_acct_bkt%%:*}"
        local rest="${kid_secret_acct_bkt#*:}"
        local secret="${rest%%:*}"
        local bkt="${rest#*:}"; bkt="${bkt##*:}"
        # rest is "secret:bucket"
        secret="${rest%%:*}"
        bkt="${rest#*:}"
        [ -z "$kid" ] && continue

        with_key "$kid" "$secret" \
            aws_s3api list-objects-v2 \
                --bucket "$bkt" --output json 2>/dev/null | \
            jq -r '.Contents[]?.Key' | while read -r k; do
                [ -n "$k" ] && with_key "$kid" "$secret" \
                    aws_s3api delete-object \
                        --bucket "$bkt" --key "$k" \
                        >/dev/null 2>&1 || true
            done
        with_key "$kid" "$secret" \
            aws_s3api delete-bucket --bucket "$bkt" \
            >/dev/null 2>&1 || true
    done

    # Delete the scoped keys we created
    delete_access_key_for "$SDC_ACCOUNT"   "$SDC_KEY_NAME"   "$A1_OWN_KEY_ID"
    delete_access_key_for "$SDC_ACCOUNT"   "$SDC_KEY_NAME"   "$A1_FOREIGN_KEY_ID"
    delete_access_key_for "$SDC_ACCOUNT_2" "$SDC_KEY_NAME_2" "$A2_OWN_KEY_ID"
    delete_access_key_for "$SDC_ACCOUNT_2" "$SDC_KEY_NAME_2" "$A2_FOREIGN_KEY_ID"

    # Drop the bootstrapped A2 admin key (NOT A1's — that one
    # came from the environment, not from this test).
    delete_access_key_for "$SDC_ACCOUNT_2" "$SDC_KEY_NAME_2" "$A2_ADMIN_KEY_ID"
}

# =============================================================================
# Main
# =============================================================================

main() {
    log "==============================================="
    log "Per-Bucket Access Key Scope - Cross-Account"
    log "==============================================="
    log "  S3 Endpoint:  $S3_ENDPOINT"
    log "  CloudAPI:     $CLOUDAPI_URL"
    log "  Account 1:    $SDC_ACCOUNT (key: $SDC_KEY_NAME)"
    log "  Account 2:    $SDC_ACCOUNT_2 (key: $SDC_KEY_NAME_2)"
    log "  SSH key:      $SSH_KEY"
    log "  A1 bucket:    $BUCKET_A1"
    log "  A2 bucket:    $BUCKET_A2"
    log "==============================================="

    setup
    test_setup

    test_a2_foreign_cannot_get_a1_probe
    test_a2_foreign_cannot_put_into_a1_bucket
    test_a2_foreign_cannot_delete_a1_object

    test_a1_foreign_cannot_get_a2_probe
    test_a1_foreign_cannot_put_into_a2_bucket
    test_a1_foreign_cannot_delete_a2_object

    test_own_account_works
    test_probes_intact

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
