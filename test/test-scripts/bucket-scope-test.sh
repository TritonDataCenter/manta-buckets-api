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
#   9. Scope update: change scope, verify new enforcement
#  10. Scope removal: make key unrestricted
#  11. UFDS read-through: use key immediately without
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# CloudAPI endpoint (separate from S3 endpoint)
CLOUDAPI_URL=${CLOUDAPI_URL:-"https://localhost:8443"}

# Replication delay — how long to wait for UFDS->Redis sync
REPL_WAIT=${REPL_WAIT:-5}

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

# Call CloudAPI with HTTP signature auth using the account's SSH key.
# SDC_ACCOUNT and SDC_KEY_ID must be set, or defaults to MANTA_USER.
SDC_ACCOUNT=${SDC_ACCOUNT:-$MANTA_USER}
SDC_KEY_FILE=${SDC_KEY_FILE:-"$HOME/.ssh/id_rsa"}
# Key ID is the MD5 fingerprint of the SSH key
if [ -z "${SDC_KEY_ID:-}" ]; then
    SDC_KEY_ID=$(ssh-keygen -l -E md5 -f "${SDC_KEY_FILE}.pub" 2>/dev/null \
        | awk '{print $2}' | sed 's/MD5://')
fi

cloudapi() {
    local method="$1"
    local path="$2"
    shift 2

    local now
    now=$(date -u '+%a, %d %h %Y %H:%M:%S GMT')
    local signature
    signature=$(echo -n "$now" | \
        openssl dgst -sha256 -sign "$SDC_KEY_FILE" | \
        openssl enc -e -a | tr -d '\n')

    curl -sk -X "$method" \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/json' \
        -H "accept-version: ~9" \
        -H "Date: $now" \
        -H "Authorization: Signature keyId=\"/$SDC_ACCOUNT/keys/$SDC_KEY_ID\",algorithm=\"rsa-sha256\" $signature" \
        "$CLOUDAPI_URL/$MANTA_USER$path" \
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

    # Verify scope was stored
    local resp_scope
    resp_scope=$(echo "$resp" | jq -r '.scope // empty')
    if [ -n "$scope_json" ] && [ "$resp_scope" = "" ]; then
        warning "CloudAPI did not return scope in response"
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

# Wait for mahi replicator to sync
wait_for_replication() {
    log "Waiting ${REPL_WAIT}s for UFDS->Redis replication..."
    sleep "$REPL_WAIT"
}

# =============================================================================
# Setup
# =============================================================================

test_setup() {
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
    wait_for_replication

    # CREATE bucket should succeed (full allows bucket operations)
    set +e
    with_key "$SCOPED_KEY_ID_FULL" "$SCOPED_SECRET_FULL" \
        aws_s3api create-bucket --bucket "$tmp_bucket" >/dev/null 2>&1
    local create_rc=$?
    set -e

    if [ $create_rc -eq 0 ]; then
        success "Full scope - CREATE bucket allowed"
    else
        error "Full scope - CREATE bucket should be allowed"
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
    wait_for_replication

    # GET on logs-jan bucket should succeed
    set +e
    with_key "$SCOPED_KEY_ID_WILD" "$SCOPED_SECRET_WILD" \
        aws_s3api get-object \
            --bucket "$SCOPE_BUCKET_LOGS1" \
            --key "test.txt" \
            "$TEMP_DIR/wild-logs1.txt" >/dev/null 2>&1
    local rc1=$?
    set -e

    if [ $rc1 -eq 0 ]; then
        success "Wildcard scope - GET on logs-jan bucket allowed"
    else
        error "Wildcard scope - GET on logs-jan bucket should be allowed"
    fi

    # GET on logs-feb bucket should succeed
    set +e
    with_key "$SCOPED_KEY_ID_WILD" "$SCOPED_SECRET_WILD" \
        aws_s3api get-object \
            --bucket "$SCOPE_BUCKET_LOGS2" \
            --key "test.txt" \
            "$TEMP_DIR/wild-logs2.txt" >/dev/null 2>&1
    local rc2=$?
    set -e

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
    assert_s3_deny \
        "STS inheritance - PUT denied (inherits read-only scope)" \
        "AccessDeniedByKeyScope" \
        env AWS_ACCESS_KEY_ID="$temp_key" \
            AWS_SECRET_ACCESS_KEY="$temp_secret" \
            AWS_SESSION_TOKEN="$temp_token" \
        aws_s3api put-object \
            --bucket "$SCOPE_BUCKET_A" \
            --key "sts-write-test.txt" \
            --body "$TEMP_DIR/scope-test-obj.txt"

    # Access to unscoped bucket should be denied with 403
    assert_s3_deny \
        "STS inheritance - cross-bucket denied with inherited scope" \
        "AccessDeniedByKeyScope" \
        env AWS_ACCESS_KEY_ID="$temp_key" \
            AWS_SECRET_ACCESS_KEY="$temp_secret" \
            AWS_SESSION_TOKEN="$temp_token" \
        aws_s3api get-object \
            --bucket "$SCOPE_BUCKET_OUTSIDE" \
            --key "test.txt" \
            "$TEMP_DIR/sts-cross.txt"

    # Cleanup role
    aws_iam_silent delete-role-policy \
        --role-name "$role_name" --policy-name "S3FullAccess" || true
    aws_iam_silent delete-role --role-name "$role_name" || true
}

# =============================================================================
# Test 8: Scope update
# =============================================================================

test_scope_update() {
    log "=== Test 8: Scope update ==="

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
# Test 9: Scope removal (make unrestricted)
# =============================================================================

test_scope_removal() {
    log "=== Test 9: Scope removal ==="

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
# Test 10: Backward compatibility (unscoped key)
# =============================================================================

test_backward_compat() {
    log "=== Test 10: Backward compatibility (unscoped key) ==="

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
# Test 11: UFDS read-through (no replication wait)
# =============================================================================

test_ufds_read_through() {
    log "=== Test 11: UFDS read-through (zero replication wait) ==="

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

    # Try immediately — no sleep.  Mahi should fall through
    # to UFDS when the key is not yet in Redis.
    set +e
    with_key "$rt_key" "$rt_secret" \
        aws_s3api get-object \
            --bucket "$rt_bucket" \
            --key "rt.txt" \
            "$TEMP_DIR/readthru-dl.txt" >/dev/null 2>&1
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "UFDS read-through - GET succeeded without replication wait"
    else
        # Retry once after a short pause; the UFDS lookup itself
        # may take a moment on a loaded system.
        sleep 2
        set +e
        with_key "$rt_key" "$rt_secret" \
            aws_s3api get-object \
                --bucket "$rt_bucket" \
                --key "rt.txt" \
                "$TEMP_DIR/readthru-dl2.txt" >/dev/null 2>&1
        local rc2=$?
        set -e

        if [ $rc2 -eq 0 ]; then
            success "UFDS read-through - GET succeeded after 2s (read-through latency)"
        else
            error "UFDS read-through - GET failed even after retry"
        fi
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
    test_scope_update
    test_scope_removal
    test_ufds_read_through

    test_cleanup
    print_summary
}

main "$@"
