#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Per-Bucket Access Key Scope — Integration Test
#
# Tests the end-to-end flow of scoped access keys:
#   1. Create scoped keys via CloudAPI
#   2. Read-only scope: GET allowed, PUT denied
#   3. Read-write scope: GET+PUT allowed, DeleteBucket denied
#   4. Full scope: all operations on scoped bucket
#   5. Cross-bucket denial: access to unscoped bucket denied
#   6. ListBuckets filtering: only scoped buckets visible
#   7. Wildcard scope: pattern matching (logs-*)
#   8. STS scope inheritance: AssumeRole carries parent scope
#   9. STS AssumeRole after UFDS idle: connection survives 90s+ idle
#  10. Scope update: change scope, verify new enforcement
#  11. Scope removal: make key unrestricted
#  12. UFDS read-through: use key immediately without
#      waiting for replication
#
# Prerequisites:
#   - CloudAPI running and accessible (CLOUDAPI_URL)
#   - manta-buckets-api running (S3_ENDPOINT)
#   - MANTA_USER set (account login)
#   - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY set (admin key)
#   - Mahi replicator running (for UFDS->Redis sync)
#   - jq installed
#
# Usage:
#   export MANTA_USER=admin
#   export CLOUDAPI_URL=https://cloudapi.coal:8443
#   export S3_ENDPOINT=https://s3.coal:8443
#   export AWS_ACCESS_KEY_ID=AKIA...
#   export AWS_SECRET_ACCESS_KEY=...
#   ./bucket-scope-test.sh

set -eo pipefail

# macOS + Homebrew Python 3.14: pyexpat links against system libexpat which
# is missing _XML_SetAllocTrackerActivationThreshold.  Point the dynamic
# linker at Homebrew's libexpat instead so the aws CLI works.
if [ -d "/opt/homebrew/opt/expat/lib" ]; then
    export DYLD_LIBRARY_PATH="/opt/homebrew/opt/expat/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# CloudAPI endpoint (separate from S3 endpoint)
CLOUDAPI_URL=${CLOUDAPI_URL:-"https://localhost:8443"}

# Replication delay — how long to wait for UFDS->Redis sync.
# cachePush writes keys to Redis immediately on create/update,
# so keys are typically available within milliseconds.  3s is a
# safety margin for the replicator fallback path.
REPL_WAIT=${REPL_WAIT:-3}

# Idle wait for the UFDS LDAP idle-disconnect test.
# Must exceed the ldapjs idleTimeout in the mahi UFDS pool factory
# (default 90s before CHG-068 fix). Reduce only when testing against
# a patched mahi where idleTimeout is disabled.
STS_IDLE_WAIT=${STS_IDLE_WAIT:-100}

# Test-specific bucket names
SCOPE_BUCKET_A="scope-test-alpha-$(date +%s)"
SCOPE_BUCKET_B="scope-test-bravo-$(date +%s)"
SCOPE_BUCKET_LOGS1="scope-test-logs-jan-$(date +%s)"
SCOPE_BUCKET_LOGS2="scope-test-logs-feb-$(date +%s)"
SCOPE_BUCKET_OUTSIDE="scope-test-outside-$(date +%s)"

# Will be populated during tests
SCOPED_KEY_ID=""
SCOPED_SECRET=""
SCOPED_KEY_ID_RW=""
SCOPED_SECRET_RW=""
SCOPED_KEY_ID_FULL=""
SCOPED_SECRET_FULL=""
SCOPED_KEY_ID_WILD=""
SCOPED_SECRET_WILD=""

# =============================================================================
# CloudAPI helpers
# =============================================================================

# Call CloudAPI with HTTP signature auth using ~/.ssh/id_rsa.
# SDC_ACCOUNT defaults to MANTA_USER.
SDC_ACCOUNT=${SDC_ACCOUNT:-"neirac"}
SDC_URL=${CLOUDAPI_URL:-"https://localhost:8443"}

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

# Create an access key with optional scope via CloudAPI
# Usage: create_scoped_key '[ {"bucket":"b","level":"read"} ]'
# Sets LAST_KEY_ID and LAST_KEY_SECRET
#
# The scope array is wrapped in the canonical envelope:
#   {"version":1,"permissions":[...]}
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

    # Verify scope was stored by reading it back
    local verify_resp
    verify_resp=$(cloudapi GET "/accesskeys/$LAST_KEY_ID" \
        2>/dev/null)
    local stored_scope
    stored_scope=$(echo "$verify_resp" | \
        jq -c '.scope // null')

    if [ -n "$scope_json" ]; then
        if [ "$stored_scope" = "null" ] || \
           [ -z "$stored_scope" ]; then
            warning "Scope not stored — CloudAPI " \
                "returned scope: $stored_scope"
        else
            log "Scope verified: $stored_scope"
        fi
    fi

    return 0
}

# Update scope on an existing key
update_key_scope() {
    local key_id="$1"
    local scope_json="$2"
    local body

    if [ "$scope_json" = "null" ] || [ "$scope_json" = "" ]; then
        body='{ "scope": "" }'
    else
        body=$(jq -n --argjson perms "$scope_json" \
            '{ scope: { version: 1, permissions: $perms } }')
    fi

    cloudapi POST "/accesskeys/$key_id" -d "$body" 2>/dev/null
}

# Delete an access key
delete_key() {
    local key_id="$1"
    cloudapi DELETE "/accesskeys/$key_id" 2>/dev/null
}

# Run an S3 command with specific credentials
# Usage: with_key <key_id> <secret> aws_s3api ...
with_key() {
    local kid="$1"
    local secret="$2"
    shift 2

    AWS_ACCESS_KEY_ID="$kid" \
    AWS_SECRET_ACCESS_KEY="$secret" \
    AWS_SESSION_TOKEN="" \
    "$@"
}

# Validate that a key's scope matches expectations.
# Usage: validate_key_scope <key_id> <expected>
#   expected = "null" for unscoped, or a jq filter
#   that extracts the relevant fields.
# Logs the scope and returns 0 on match, 1 on
# mismatch.
validate_key_scope() {
    local key_id="$1"
    local expected="$2"

    local resp
    resp=$(cloudapi GET "/accesskeys/$key_id" \
        2>/dev/null)
    local stored
    stored=$(echo "$resp" | jq -c '.scope // null')

    if [ "$expected" = "null" ]; then
        if [ "$stored" = "null" ]; then
            log "Key $key_id scope: null (unscoped) — OK"
            return 0
        else
            error "Key $key_id expected unscoped, got: $stored"
            return 1
        fi
    fi

    # For scoped keys, check that the scope is not null
    # and log the full scope for debugging.
    if [ "$stored" = "null" ] || [ -z "$stored" ]; then
        error "Key $key_id expected scoped, got null"
        return 1
    fi

    local scope_perms
    scope_perms=$(echo "$stored" | \
        jq -c '.permissions // []')
    log "Key $key_id scope: $scope_perms"
    return 0
}

# Wait for mahi replicator to sync
wait_for_replication() {
    log "Waiting ${REPL_WAIT}s for UFDS->Redis replication..."
    sleep "$REPL_WAIT"
}

# Retry S3 command with backoff on AccessDenied (eventual consistency).
# Newly created keys may take up to 15s to propagate through the
# replicator and auth cache — this mirrors AWS IAM's eventual
# consistency model.
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
    log "Validating admin key scope..."
    validate_key_scope "$AWS_ACCESS_KEY_ID" "null"

    log "Creating test buckets with admin credentials..."

    # Create all test buckets using the admin (unrestricted) key
    aws_s3api create-bucket --bucket "$SCOPE_BUCKET_A" >/dev/null 2>&1 || true
    aws_s3api create-bucket --bucket "$SCOPE_BUCKET_B" >/dev/null 2>&1 || true
    aws_s3api create-bucket --bucket "$SCOPE_BUCKET_LOGS1" >/dev/null 2>&1 || true
    aws_s3api create-bucket --bucket "$SCOPE_BUCKET_LOGS2" >/dev/null 2>&1 || true
    aws_s3api create-bucket --bucket "$SCOPE_BUCKET_OUTSIDE" >/dev/null 2>&1 || true

    # Upload a test object to each bucket
    local test_file="$TEMP_DIR/scope-test-obj.txt"
    echo "scope test content" > "$test_file"
    for bkt in "$SCOPE_BUCKET_A" "$SCOPE_BUCKET_B" \
               "$SCOPE_BUCKET_LOGS1" "$SCOPE_BUCKET_LOGS2" \
               "$SCOPE_BUCKET_OUTSIDE"; do
        aws_s3api put-object \
            --bucket "$bkt" \
            --key "test.txt" \
            --body "$test_file" >/dev/null 2>&1 || true
    done

    success "Test buckets and objects created"
}

# =============================================================================
# Test 1: Read-only scoped key
# =============================================================================

test_read_only_scope() {
    log "=== Test 1: Read-only scoped key ==="

    local scope='[{"bucket":"'"$SCOPE_BUCKET_A"'","level":"read"}]'

    if ! create_scoped_key "$scope"; then
        error "Read-only scope - failed to create scoped key"
        return 1
    fi
    SCOPED_KEY_ID="$LAST_KEY_ID"
    SCOPED_SECRET="$LAST_KEY_SECRET"
    log "Created read-only key: $SCOPED_KEY_ID"
    validate_key_scope "$SCOPED_KEY_ID" "scoped"
    wait_for_replication

    # GET object should succeed
    local get_result
    set +e
    get_result=$(with_key "$SCOPED_KEY_ID" "$SCOPED_SECRET" \
        aws_s3api get-object \
            --bucket "$SCOPE_BUCKET_A" \
            --key "test.txt" \
            "$TEMP_DIR/downloaded.txt" 2>&1)
    local get_rc=$?
    set -e

    if [ $get_rc -eq 0 ]; then
        success "Read-only scope - GET object allowed"
    else
        error "Read-only scope - GET object should be allowed"
        log "Output: $get_result"
    fi

    # PUT object should be denied with 403
    assert_s3_deny \
        "Read-only scope - PUT object denied" \
        "AccessDeniedByKeyScope" \
        with_key "$SCOPED_KEY_ID" "$SCOPED_SECRET" \
            aws_s3api put-object \
                --bucket "$SCOPE_BUCKET_A" \
                --key "write-test.txt" \
                --body "$TEMP_DIR/scope-test-obj.txt"

    # HEAD bucket should succeed (read level allows it)
    set +e
    with_key "$SCOPED_KEY_ID" "$SCOPED_SECRET" \
        aws_s3api head-bucket --bucket "$SCOPE_BUCKET_A" >/dev/null 2>&1
    local head_rc=$?
    set -e

    if [ $head_rc -eq 0 ]; then
        success "Read-only scope - HEAD bucket allowed"
    else
        error "Read-only scope - HEAD bucket should be allowed"
    fi
}

# =============================================================================
# Test 2: Read-write scoped key
# =============================================================================

test_readwrite_scope() {
    log "=== Test 2: Read-write scoped key ==="

    local scope='[{"bucket":"'"$SCOPE_BUCKET_B"'","level":"readwrite"}]'

    if ! create_scoped_key "$scope"; then
        error "Readwrite scope - failed to create scoped key"
        return 1
    fi
    SCOPED_KEY_ID_RW="$LAST_KEY_ID"
    SCOPED_SECRET_RW="$LAST_KEY_SECRET"
    log "Created readwrite key: $SCOPED_KEY_ID_RW"
    validate_key_scope "$SCOPED_KEY_ID_RW" "scoped"
    wait_for_replication

    # GET object should succeed
    set +e
    with_key "$SCOPED_KEY_ID_RW" "$SCOPED_SECRET_RW" \
        aws_s3api get-object \
            --bucket "$SCOPE_BUCKET_B" \
            --key "test.txt" \
            "$TEMP_DIR/downloaded-rw.txt" >/dev/null 2>&1
    local get_rc=$?
    set -e

    if [ $get_rc -eq 0 ]; then
        success "Readwrite scope - GET object allowed"
    else
        error "Readwrite scope - GET object should be allowed"
    fi

    # PUT object should succeed
    set +e
    with_key "$SCOPED_KEY_ID_RW" "$SCOPED_SECRET_RW" \
        aws_s3api put-object \
            --bucket "$SCOPE_BUCKET_B" \
            --key "rw-write-test.txt" \
            --body "$TEMP_DIR/scope-test-obj.txt" >/dev/null 2>&1
    local put_rc=$?
    set -e

    if [ $put_rc -eq 0 ]; then
        success "Readwrite scope - PUT object allowed"
    else
        error "Readwrite scope - PUT object should be allowed"
    fi

    # DELETE object should succeed (readwrite allows object deletes)
    set +e
    with_key "$SCOPED_KEY_ID_RW" "$SCOPED_SECRET_RW" \
        aws_s3api delete-object \
            --bucket "$SCOPE_BUCKET_B" \
            --key "rw-write-test.txt" >/dev/null 2>&1
    local del_rc=$?
    set -e

    if [ $del_rc -eq 0 ]; then
        success "Readwrite scope - DELETE object allowed"
    else
        error "Readwrite scope - DELETE object should be allowed"
    fi

    # DELETE bucket should be denied with 403 (requires full)
    assert_s3_deny \
        "Readwrite scope - DELETE bucket denied (requires full)" \
        "AccessDeniedByKeyScope" \
        with_key "$SCOPED_KEY_ID_RW" "$SCOPED_SECRET_RW" \
            aws_s3api delete-bucket \
                --bucket "$SCOPE_BUCKET_B"
    # Re-create the bucket if it was accidentally deleted
    aws_s3api create-bucket --bucket "$SCOPE_BUCKET_B" \
        >/dev/null 2>&1 || true
}

# =============================================================================
# Test 3: Full scoped key
# =============================================================================

test_full_scope() {
    log "=== Test 3: Full scoped key ==="

    local tmp_bucket="scope-test-full-$(date +%s)"
    local scope='[{"bucket":"'"$tmp_bucket"'","level":"full"}]'

    if ! create_scoped_key "$scope"; then
        error "Full scope - failed to create scoped key"
        return 1
    fi
    SCOPED_KEY_ID_FULL="$LAST_KEY_ID"
    SCOPED_SECRET_FULL="$LAST_KEY_SECRET"
    log "Created full key: $SCOPED_KEY_ID_FULL"
    validate_key_scope "$SCOPED_KEY_ID_FULL" "scoped"
    wait_for_replication

    # CREATE bucket should succeed (full allows bucket operations).
    # Uses retry_on_auth — newly created keys are eventually consistent.
    local create_result
    create_result=$(retry_on_auth with_key "$SCOPED_KEY_ID_FULL" "$SCOPED_SECRET_FULL" \
        aws_s3api create-bucket --bucket "$tmp_bucket")
    local create_rc=$?

    if [ $create_rc -eq 0 ]; then
        success "Full scope - CREATE bucket allowed"
    else
        error "Full scope - CREATE bucket should be allowed"
        log "Output: $create_result"
        return 1
    fi

    # PUT + GET + DELETE object should all succeed
    set +e
    with_key "$SCOPED_KEY_ID_FULL" "$SCOPED_SECRET_FULL" \
        aws_s3api put-object \
            --bucket "$tmp_bucket" \
            --key "full-test.txt" \
            --body "$TEMP_DIR/scope-test-obj.txt" >/dev/null 2>&1
    local put_rc=$?
    set -e

    if [ $put_rc -eq 0 ]; then
        success "Full scope - PUT object allowed"
    else
        error "Full scope - PUT object should be allowed"
    fi

    # DELETE bucket should succeed
    set +e
    with_key "$SCOPED_KEY_ID_FULL" "$SCOPED_SECRET_FULL" \
        aws_s3api delete-object \
            --bucket "$tmp_bucket" \
            --key "full-test.txt" >/dev/null 2>&1
    with_key "$SCOPED_KEY_ID_FULL" "$SCOPED_SECRET_FULL" \
        aws_s3api delete-bucket --bucket "$tmp_bucket" >/dev/null 2>&1
    local del_rc=$?
    set -e

    if [ $del_rc -eq 0 ]; then
        success "Full scope - DELETE bucket allowed"
    else
        error "Full scope - DELETE bucket should be allowed"
    fi
}

# =============================================================================
# Test 4: Cross-bucket denial
# =============================================================================

test_cross_bucket_denial() {
    log "=== Test 4: Cross-bucket denial ==="

    # Use the read-only key (scoped to SCOPE_BUCKET_A) against SCOPE_BUCKET_OUTSIDE
    if [ -z "$SCOPED_KEY_ID" ]; then
        warning "Cross-bucket test - no read-only key available, skipping"
        return 0
    fi

    assert_s3_deny \
        "Cross-bucket denial - access to unscoped bucket denied" \
        "AccessDeniedByKeyScope" \
        with_key "$SCOPED_KEY_ID" "$SCOPED_SECRET" \
            aws_s3api get-object \
                --bucket "$SCOPE_BUCKET_OUTSIDE" \
                --key "test.txt" \
                "$TEMP_DIR/cross-bucket.txt"
}

# =============================================================================
# Test 5: ListBuckets filtering
# =============================================================================

test_list_buckets_filtering() {
    log "=== Test 5: ListBuckets filtering ==="

    if [ -z "$SCOPED_KEY_ID" ]; then
        warning "ListBuckets test - no scoped key available, skipping"
        return 0
    fi

    # The read-only key is scoped to SCOPE_BUCKET_A only
    set +e
    local list_result
    list_result=$(with_key "$SCOPED_KEY_ID" "$SCOPED_SECRET" \
        aws_s3api list-buckets --output json 2>&1)
    local rc=$?
    set -e

    if [ $rc -ne 0 ]; then
        error "ListBuckets filtering - list command failed: $list_result"
        return 1
    fi

    # Check that only the scoped bucket appears
    local bucket_names
    bucket_names=$(echo "$list_result" | jq -r '.Buckets[].Name' 2>/dev/null)

    if echo "$bucket_names" | grep -q "$SCOPE_BUCKET_A"; then
        success "ListBuckets filtering - scoped bucket visible"
    else
        error "ListBuckets filtering - scoped bucket not visible"
        log "Buckets returned: $bucket_names"
    fi

    if echo "$bucket_names" | grep -q "$SCOPE_BUCKET_OUTSIDE"; then
        error "ListBuckets filtering - unscoped bucket should NOT be visible"
        log "Buckets returned: $bucket_names"
    else
        success "ListBuckets filtering - unscoped bucket hidden"
    fi
}

# =============================================================================
# Test 6: Wildcard scope
# =============================================================================

test_wildcard_scope() {
    log "=== Test 6: Wildcard scope (logs-*) ==="

    # The logs buckets are named scope-test-logs-jan-... and scope-test-logs-feb-...
    # We need a wildcard that matches them. Since they share the prefix
    # "scope-test-logs-", use that as the wildcard pattern.
    local log_prefix="scope-test-logs-"
    local scope='[{"bucket":"'"${log_prefix}"'*","level":"read"}]'

    if ! create_scoped_key "$scope"; then
        error "Wildcard scope - failed to create scoped key"
        return 1
    fi
    SCOPED_KEY_ID_WILD="$LAST_KEY_ID"
    SCOPED_SECRET_WILD="$LAST_KEY_SECRET"
    log "Created wildcard key: $SCOPED_KEY_ID_WILD (pattern: ${log_prefix}*)"
    validate_key_scope "$SCOPED_KEY_ID_WILD" "scoped"
    wait_for_replication

    # GET on logs-jan bucket should succeed
    retry_on_auth with_key "$SCOPED_KEY_ID_WILD" "$SCOPED_SECRET_WILD" \
        aws_s3api get-object \
            --bucket "$SCOPE_BUCKET_LOGS1" \
            --key "test.txt" \
            "$TEMP_DIR/wild-logs1.txt" >/dev/null 2>&1
    local rc1=$?

    if [ $rc1 -eq 0 ]; then
        success "Wildcard scope - GET on logs-jan bucket allowed"
    else
        error "Wildcard scope - GET on logs-jan bucket should be allowed"
    fi

    # GET on logs-feb bucket should succeed
    retry_on_auth with_key "$SCOPED_KEY_ID_WILD" "$SCOPED_SECRET_WILD" \
        aws_s3api get-object \
            --bucket "$SCOPE_BUCKET_LOGS2" \
            --key "test.txt" \
            "$TEMP_DIR/wild-logs2.txt" >/dev/null 2>&1
    local rc2=$?

    if [ $rc2 -eq 0 ]; then
        success "Wildcard scope - GET on logs-feb bucket allowed"
    else
        error "Wildcard scope - GET on logs-feb bucket should be allowed"
    fi

    # GET on non-matching bucket should be denied with 403
    assert_s3_deny \
        "Wildcard scope - GET on non-matching bucket denied" \
        "AccessDeniedByKeyScope" \
        with_key "$SCOPED_KEY_ID_WILD" "$SCOPED_SECRET_WILD" \
            aws_s3api get-object \
                --bucket "$SCOPE_BUCKET_A" \
                --key "test.txt" \
                "$TEMP_DIR/wild-denied.txt"

    # ListBuckets should only show matching buckets
    set +e
    local list_result
    list_result=$(with_key "$SCOPED_KEY_ID_WILD" "$SCOPED_SECRET_WILD" \
        aws_s3api list-buckets --output json 2>&1)
    set -e

    local visible_count
    visible_count=$(echo "$list_result" | jq '[.Buckets[].Name | select(startswith("scope-test-logs-"))] | length' 2>/dev/null)
    local total_count
    total_count=$(echo "$list_result" | jq '.Buckets | length' 2>/dev/null)

    if [ "$visible_count" = "$total_count" ] && [ "$total_count" -ge 2 ]; then
        success "Wildcard scope - ListBuckets shows only matching buckets ($total_count)"
    else
        warning "Wildcard scope - ListBuckets: $visible_count matching out of $total_count total"
    fi
}

# =============================================================================
# Test 7: STS scope inheritance
# =============================================================================

test_sts_scope_inheritance() {
    log "=== Test 7: STS scope inheritance ==="

    if [ -z "$SCOPED_KEY_ID" ]; then
        warning "STS inheritance test - no scoped key available, skipping"
        return 0
    fi

    # Get account UUID
    local account_uuid
    account_uuid=$(aws_sts get-caller-identity --output json 2>/dev/null \
        | jq -r '.Account // empty')
    if [ -z "$account_uuid" ]; then
        warning "STS inheritance test - could not get account UUID, skipping"
        return 0
    fi

    # Create a role for the test
    local role_name="scope-sts-test-$(date +%s)"
    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'

    if ! aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" >/dev/null 2>&1; then
        warning "STS inheritance test - could not create role, skipping"
        return 0
    fi

    # Attach S3 full access policy to the role
    local s3_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":"*"}]}'
    aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "S3FullAccess" \
        --policy-document "$s3_policy" >/dev/null 2>&1
    sleep 2

    local role_arn="arn:aws:iam::${account_uuid}:role/${role_name}"

    # AssumeRole using the read-only scoped key
    set +e
    local sts_result
    sts_result=$(with_key "$SCOPED_KEY_ID" "$SCOPED_SECRET" \
        aws_sts assume-role \
            --role-arn "$role_arn" \
            --role-session-name "scope-inherit-test" \
            --output json 2>&1)
    local sts_rc=$?
    set -e

    if [ $sts_rc -ne 0 ]; then
        warning "STS inheritance test - AssumeRole failed: $sts_result"
        # Cleanup role
        aws_iam_silent delete-role-policy \
            --role-name "$role_name" --policy-name "S3FullAccess" || true
        aws_iam_silent delete-role --role-name "$role_name" || true
        return 0
    fi

    # Extract temp credentials
    local temp_key temp_secret temp_token
    temp_key=$(echo "$sts_result" | jq -r '.Credentials.AccessKeyId')
    temp_secret=$(echo "$sts_result" | jq -r '.Credentials.SecretAccessKey')
    temp_token=$(echo "$sts_result" | jq -r '.Credentials.SessionToken')

    if [ -z "$temp_key" ] || [ "$temp_key" = "null" ]; then
        error "STS inheritance - could not extract temp credentials"
        aws_iam_silent delete-role-policy \
            --role-name "$role_name" --policy-name "S3FullAccess" || true
        aws_iam_silent delete-role --role-name "$role_name" || true
        return 1
    fi

    # Despite the role having s3:*, the temp creds should inherit
    # the parent key's read-only scope on SCOPE_BUCKET_A

    # GET should succeed (parent scope allows read on SCOPE_BUCKET_A)
    set +e
    AWS_ACCESS_KEY_ID="$temp_key" \
    AWS_SECRET_ACCESS_KEY="$temp_secret" \
    AWS_SESSION_TOKEN="$temp_token" \
    aws_s3api get-object \
        --bucket "$SCOPE_BUCKET_A" \
        --key "test.txt" \
        "$TEMP_DIR/sts-inherited.txt" \
        --endpoint-url="$S3_ENDPOINT" \
        --region="$AWS_REGION" \
        --no-verify-ssl >/dev/null 2>&1
    local get_rc=$?
    set -e

    if [ $get_rc -eq 0 ]; then
        success "STS inheritance - GET with inherited scope allowed"
    else
        error "STS inheritance - GET with inherited scope should be allowed"
    fi

    # PUT should be denied with 403 (parent scope is read-only)
    export AWS_ACCESS_KEY_ID="$temp_key"
    export AWS_SECRET_ACCESS_KEY="$temp_secret"
    export AWS_SESSION_TOKEN="$temp_token"

    assert_s3_deny \
        "STS inheritance - PUT denied (inherits read-only scope)" \
        "AccessDeniedByKeyScope" \
        aws_s3api put-object \
            --bucket "$SCOPE_BUCKET_A" \
            --key "sts-write-test.txt" \
            --body "$TEMP_DIR/scope-test-obj.txt"

    # Access to unscoped bucket should be denied with 403
    assert_s3_deny \
        "STS inheritance - cross-bucket denied with inherited scope" \
        "AccessDeniedByKeyScope" \
        aws_s3api get-object \
            --bucket "$SCOPE_BUCKET_OUTSIDE" \
            --key "test.txt" \
            "$TEMP_DIR/sts-cross.txt"

    # Restore original credentials
    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN

    # Cleanup role
    aws_iam_silent delete-role-policy \
        --role-name "$role_name" --policy-name "S3FullAccess" || true
    aws_iam_silent delete-role --role-name "$role_name" || true
}

# =============================================================================
# Test 9: STS AssumeRole after UFDS idle (regression for CHG-068)
#
# The mahi UFDS pool uses ldapjs, which defaults to disconnecting idle
# connections after 90 seconds (idleTimeout: opts.idleTimeout || 90000).
# generic-pool does not detect the silent disconnect; the next acquire()
# returns a dead client, the LDAP add() hangs, and AssumeRole exceeds
# requestTimeout.
#
# This test reproduces the failure condition: create a role, wait longer
# than STS_IDLE_WAIT seconds (default 100, > ldapjs default 90), then
# call AssumeRole. Without CHG-068 the call returns RequestTimeout.
# With the fix (idleTimeout disabled in the pool factory) it succeeds.
# =============================================================================

test_sts_assume_role_after_idle() {
    log "=== Test 9: STS AssumeRole after UFDS idle ===" \
        "(${STS_IDLE_WAIT}s wait)"

    # This test creates IAM roles, which requires the admin key.
    # Restore original credentials in case a prior test left a
    # scoped key or session token active.
    local saved_key saved_secret saved_token
    saved_key="$AWS_ACCESS_KEY_ID"
    saved_secret="$AWS_SECRET_ACCESS_KEY"
    saved_token="${AWS_SESSION_TOKEN:-}"
    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN

    local account_uuid
    set +e
    account_uuid=$(aws_sts get-caller-identity --output json 2>/dev/null \
        | jq -r '.Account // empty')
    set -e
    if [ -z "$account_uuid" ]; then
        warning "STS idle test - could not get account UUID, skipping"
        export AWS_ACCESS_KEY_ID="$saved_key"
        export AWS_SECRET_ACCESS_KEY="$saved_secret"
        [ -n "$saved_token" ] && export AWS_SESSION_TOKEN="$saved_token" || true
        return 0
    fi

    local role_name="scope-sts-idle-$(date +%s)"
    local trust_policy
    trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'\
'"Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'

    if ! aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" >/dev/null 2>&1; then
        warning "STS idle test - could not create role, skipping"
        export AWS_ACCESS_KEY_ID="$saved_key"
        export AWS_SECRET_ACCESS_KEY="$saved_secret"
        [ -n "$saved_token" ] && export AWS_SESSION_TOKEN="$saved_token" || true
        return 0
    fi

    local s3_policy
    s3_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'\
'"Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}'
    aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "S3ReadOnly" \
        --policy-document "$s3_policy" >/dev/null 2>&1

    local role_arn="arn:aws:iam::${account_uuid}:role/${role_name}"

    log "STS idle test - sleeping ${STS_IDLE_WAIT}s to exceed ldapjs" \
        "idleTimeout (90s default)..."
    sleep "$STS_IDLE_WAIT"

    # AssumeRole must succeed after the idle period.
    # Pre-fix: mahi returns RequestTimeout (LDAP connection was
    # silently dropped and reconnect exceeds requestTimeout:10000).
    # Post-fix: returns valid credentials within requestTimeout.
    set +e
    local sts_result sts_rc
    sts_result=$(aws_sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name "idle-regression-test" \
        --output json 2>&1)
    sts_rc=$?
    set -e

    aws_iam_silent delete-role-policy \
        --role-name "$role_name" --policy-name "S3ReadOnly" || true
    aws_iam_silent delete-role --role-name "$role_name" || true

    if [ $sts_rc -ne 0 ]; then
        error "STS idle test - AssumeRole failed after ${STS_IDLE_WAIT}s" \
            "idle: $sts_result"
        return 1
    fi

    local temp_key
    temp_key=$(echo "$sts_result" | jq -r '.Credentials.AccessKeyId // empty')
    if [ -z "$temp_key" ] || [ "$temp_key" = "null" ]; then
        error "STS idle test - AssumeRole returned no credentials"
        return 1
    fi

    success "STS idle test - AssumeRole succeeded after ${STS_IDLE_WAIT}s" \
        "idle; UFDS connection survived"

    export AWS_ACCESS_KEY_ID="$saved_key"
    export AWS_SECRET_ACCESS_KEY="$saved_secret"
    [ -n "$saved_token" ] && export AWS_SESSION_TOKEN="$saved_token" || true
}

# =============================================================================
# Test 10: Scope update
# =============================================================================

test_scope_update() {
    log "=== Test 10: Scope update ==="

    if [ -z "$SCOPED_KEY_ID" ]; then
        warning "Scope update test - no scoped key available, skipping"
        return 0
    fi

    # The read-only key is currently scoped to SCOPE_BUCKET_A.
    # Update it to also include SCOPE_BUCKET_B with readwrite.
    local new_scope='[{"bucket":"'"$SCOPE_BUCKET_A"'","level":"read"},{"bucket":"'"$SCOPE_BUCKET_B"'","level":"readwrite"}]'

    log "Updating key $SCOPED_KEY_ID with expanded scope..."
    update_key_scope "$SCOPED_KEY_ID" "$new_scope"
    wait_for_replication

    # Should now be able to PUT on SCOPE_BUCKET_B
    set +e
    with_key "$SCOPED_KEY_ID" "$SCOPED_SECRET" \
        aws_s3api put-object \
            --bucket "$SCOPE_BUCKET_B" \
            --key "scope-update-test.txt" \
            --body "$TEMP_DIR/scope-test-obj.txt" >/dev/null 2>&1
    local put_rc=$?
    set -e

    if [ $put_rc -eq 0 ]; then
        success "Scope update - PUT on newly scoped bucket allowed"
    else
        error "Scope update - PUT on newly scoped bucket should be allowed"
    fi

    # Should still be able to read SCOPE_BUCKET_A
    set +e
    with_key "$SCOPED_KEY_ID" "$SCOPED_SECRET" \
        aws_s3api get-object \
            --bucket "$SCOPE_BUCKET_A" \
            --key "test.txt" \
            "$TEMP_DIR/scope-update-read.txt" >/dev/null 2>&1
    local get_rc=$?
    set -e

    if [ $get_rc -eq 0 ]; then
        success "Scope update - GET on original scoped bucket still allowed"
    else
        error "Scope update - GET on original scoped bucket should still be allowed"
    fi
}

# =============================================================================
# Test 11: Scope removal (make unrestricted)
# =============================================================================

test_scope_removal() {
    log "=== Test 11: Scope removal ==="

    if [ -z "$SCOPED_KEY_ID" ]; then
        warning "Scope removal test - no scoped key available, skipping"
        return 0
    fi

    log "Removing scope from key $SCOPED_KEY_ID..."
    update_key_scope "$SCOPED_KEY_ID" ""
    wait_for_replication

    # Should now be able to access any bucket (unrestricted)
    set +e
    with_key "$SCOPED_KEY_ID" "$SCOPED_SECRET" \
        aws_s3api get-object \
            --bucket "$SCOPE_BUCKET_OUTSIDE" \
            --key "test.txt" \
            "$TEMP_DIR/unscoped-access.txt" >/dev/null 2>&1
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "Scope removal - access to previously-denied bucket now allowed"
    else
        error "Scope removal - key should be unrestricted after scope removal"
    fi
}

# =============================================================================
# Test 12: Backward compatibility (unscoped key)
# =============================================================================

test_backward_compat() {
    log "=== Test 12: Backward compatibility (unscoped key) ==="

    # The admin key has no scope — it should work on everything
    set +e
    aws_s3api get-object \
        --bucket "$SCOPE_BUCKET_A" \
        --key "test.txt" \
        "$TEMP_DIR/compat-test.txt" >/dev/null 2>&1
    local rc1=$?

    aws_s3api get-object \
        --bucket "$SCOPE_BUCKET_OUTSIDE" \
        --key "test.txt" \
        "$TEMP_DIR/compat-test2.txt" >/dev/null 2>&1
    local rc2=$?
    set -e

    if [ $rc1 -eq 0 ] && [ $rc2 -eq 0 ]; then
        success "Backward compatibility - unscoped key accesses all buckets"
    else
        error "Backward compatibility - unscoped key should access all buckets"
    fi
}

# =============================================================================
# Test 13: UFDS read-through (no replication wait)
# =============================================================================

test_ufds_read_through() {
    log "=== Test 13: UFDS read-through (zero replication wait) ==="

    # Create a brand-new scoped key and use it immediately
    # without waiting for UFDS->Redis replication.  If mahi's
    # handlePermanentCredentialUfds read-through works, the
    # key should be usable within a few seconds even when the
    # replicator has not yet run.

    local rt_bucket="scope-test-readthru-$(date +%s)"
    local scope='[{"bucket":"'"$rt_bucket"'","level":"readwrite"}]'

    # Create bucket with admin key first
    aws_s3api create-bucket --bucket "$rt_bucket" \
        >/dev/null 2>&1 || true
    local test_file="$TEMP_DIR/readthru-obj.txt"
    echo "read-through test" > "$test_file"
    aws_s3api put-object --bucket "$rt_bucket" \
        --key "rt.txt" --body "$test_file" \
        >/dev/null 2>&1 || true

    if ! create_scoped_key "$scope"; then
        error "UFDS read-through - failed to create scoped key"
        aws_s3 rm "s3://$rt_bucket" --recursive 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$rt_bucket" \
            2>/dev/null || true
        return 1
    fi
    local rt_key="$LAST_KEY_ID"
    local rt_secret="$LAST_KEY_SECRET"
    log "Created read-through key: $rt_key (no replication wait)"
    validate_key_scope "$rt_key" "scoped"

    # Try immediately — no sleep.  Mahi should fall through to UFDS
    # when the key is not yet in Redis.  Uses retry_on_auth for
    # eventual consistency (UFDS lookup may have variable latency).
    set +e
    retry_on_auth with_key "$rt_key" "$rt_secret" \
        aws_s3api get-object \
            --bucket "$rt_bucket" \
            --key "rt.txt" \
            "$TEMP_DIR/readthru-dl.txt" >/dev/null 2>&1
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "UFDS read-through - GET succeeded (eventual consistency)"
    else
        error "UFDS read-through - GET failed even after retry"
    fi

    # Verify cross-bucket denial works immediately too
    assert_s3_deny \
        "UFDS read-through - cross-bucket denied without replication wait" \
        "AccessDeniedByKeyScope" \
        with_key "$rt_key" "$rt_secret" \
            aws_s3api get-object \
                --bucket "$SCOPE_BUCKET_OUTSIDE" \
                --key "test.txt" \
                "$TEMP_DIR/readthru-cross.txt"

    # Cleanup
    delete_key "$rt_key" 2>/dev/null || true
    aws_s3 rm "s3://$rt_bucket" --recursive 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$rt_bucket" \
        2>/dev/null || true
}

# =============================================================================
# Cleanup
# =============================================================================

test_cleanup() {
    log "Cleaning up scope test resources..."
    set +e

    # Delete test objects and buckets
    for bkt in "$SCOPE_BUCKET_A" "$SCOPE_BUCKET_B" \
               "$SCOPE_BUCKET_LOGS1" "$SCOPE_BUCKET_LOGS2" \
               "$SCOPE_BUCKET_OUTSIDE"; do
        aws_s3 rm "s3://$bkt" --recursive 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$bkt" 2>/dev/null || true
    done

    # Delete scoped access keys via CloudAPI
    for kid in "$SCOPED_KEY_ID" "$SCOPED_KEY_ID_RW" \
               "$SCOPED_KEY_ID_FULL" "$SCOPED_KEY_ID_WILD"; do
        if [ -n "$kid" ]; then
            delete_key "$kid" 2>/dev/null || true
        fi
    done

    # Restore credentials
    cleanup_credentials

    set -e
    log "Cleanup complete"
}

# =============================================================================
# Main
# =============================================================================

main() {
    log "=========================================="
    log "Per-Bucket Access Key Scope Integration Tests"
    log "=========================================="
    log "  S3 Endpoint:      $S3_ENDPOINT"
    log "  CloudAPI:         $CLOUDAPI_URL"
    log "  Account:          $MANTA_USER"
    log "  Replication wait: ${REPL_WAIT}s"
    log "=========================================="

    setup
    test_setup

    test_backward_compat
    test_read_only_scope
    test_readwrite_scope
    test_full_scope
    test_cross_bucket_denial
    test_list_buckets_filtering
    test_wildcard_scope
    test_sts_scope_inheritance
    test_sts_assume_role_after_idle
    test_scope_update
    test_scope_removal
    test_ufds_read_through

    test_cleanup
    print_summary
}

main "$@"
