#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Per-Bucket Access Key Scope — Scope + IAM Policy Intersection Tests
#
# Verifies the AND/intersection semantics: BOTH enforceBucketScope (key scope)
# AND authorize() (IAM policy) must pass. Neither gate alone is sufficient.
#
# Tests:
#   1. Scoped key + IAM Allow on same bucket → allowed
#   2. Scoped key + IAM Deny on scoped bucket → denied (IAM blocks)
#   3. Unscoped key + IAM Deny → denied (IAM still blocks)
#   4. Scoped key allows A, IAM allows B only → both denied
#   5. STS: scope=read, IAM=s3:PutObject → denied (scope blocks write)
#   6. STS: scope=readwrite, IAM=s3:GetObject only → denied (IAM blocks write)
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
INT_BUCKET_A="scope-int-alpha-$(date +%s)"
INT_BUCKET_B="scope-int-bravo-$(date +%s)"

# Key tracking
INT_RW_KEY_ID=""
INT_RW_SECRET=""
INT_RO_KEY_ID=""
INT_RO_SECRET=""

# Role tracking (for cleanup)
CREATED_ROLES=()

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

# Create an IAM role and attach an inline policy. Returns role ARN.
# Usage: create_role_with_policy <role_name> <policy_json>
create_role_with_policy() {
    local role_name="$1"
    local policy_json="$2"
    local account_uuid="$3"

    local trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'

    if ! aws_iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "$trust_policy" >/dev/null 2>&1; then
        return 1
    fi

    aws_iam put-role-policy \
        --role-name "$role_name" \
        --policy-name "TestPolicy" \
        --policy-document "$policy_json" >/dev/null 2>&1

    CREATED_ROLES+=("$role_name")
    sleep 2  # Wait for IAM propagation
    echo "arn:aws:iam::${account_uuid}:role/${role_name}"
}

# AssumeRole with given key and return temp credentials.
# Sets TEMP_KEY, TEMP_SECRET, TEMP_TOKEN on success.
assume_role_with_key() {
    local kid="$1"
    local secret="$2"
    local role_arn="$3"
    local session_name="$4"

    local attempt
    local sts_result sts_rc
    for attempt in 1 2 3; do
        set +e
        sts_result=$(with_key "$kid" "$secret" \
            aws_sts assume-role \
                --role-arn "$role_arn" \
                --role-session-name "$session_name" \
                --output json 2>&1)
        sts_rc=$?
        set -e
        if [ $sts_rc -eq 0 ]; then
            break
        fi
        if [ $attempt -lt 3 ]; then
            log "  AssumeRole attempt $attempt failed, retrying in 5s..."
            sleep 5
        fi
    done

    if [ $sts_rc -ne 0 ]; then
        echo "$sts_result" >&2
        return 1
    fi

    TEMP_KEY=$(echo "$sts_result" | jq -r '.Credentials.AccessKeyId')
    TEMP_SECRET=$(echo "$sts_result" | jq -r '.Credentials.SecretAccessKey')
    TEMP_TOKEN=$(echo "$sts_result" | jq -r '.Credentials.SessionToken')

    if [ -z "$TEMP_KEY" ] || [ "$TEMP_KEY" = "null" ]; then
        return 1
    fi
    return 0
}

# =============================================================================
# Setup
# =============================================================================

test_setup() {
    log "Creating test buckets and objects..."

    aws_s3api create-bucket --bucket "$INT_BUCKET_A" >/dev/null 2>&1 || true
    aws_s3api create-bucket --bucket "$INT_BUCKET_B" >/dev/null 2>&1 || true

    local test_file="$TEMP_DIR/int-test-obj.txt"
    echo "intersection test content" > "$test_file"
    aws_s3api put-object --bucket "$INT_BUCKET_A" \
        --key "test.txt" --body "$test_file" >/dev/null 2>&1
    aws_s3api put-object --bucket "$INT_BUCKET_B" \
        --key "test.txt" --body "$test_file" >/dev/null 2>&1

    # readwrite key scoped to BUCKET_A
    local rw_scope='[{"bucket":"'"$INT_BUCKET_A"'","level":"readwrite"}]'
    if ! create_scoped_key "$rw_scope"; then
        error "Setup - failed to create readwrite key"
        return 1
    fi
    INT_RW_KEY_ID="$LAST_KEY_ID"
    INT_RW_SECRET="$LAST_KEY_SECRET"
    log "Created readwrite key (bucket A): $INT_RW_KEY_ID"

    # read-only key scoped to BUCKET_A
    local ro_scope='[{"bucket":"'"$INT_BUCKET_A"'","level":"read"}]'
    if ! create_scoped_key "$ro_scope"; then
        error "Setup - failed to create read-only key"
        return 1
    fi
    INT_RO_KEY_ID="$LAST_KEY_ID"
    INT_RO_SECRET="$LAST_KEY_SECRET"
    log "Created read-only key (bucket A): $INT_RO_KEY_ID"

    wait_for_replication
    success "Intersection test setup complete"
}

# =============================================================================
# Test 1: Scoped key + IAM Allow on same bucket → allowed
# =============================================================================

test_scope_and_iam_allow() {
    log "=== Test 1: Scoped key + IAM Allow on same bucket ==="

    local account_uuid
    account_uuid=$(aws_sts get-caller-identity --output json 2>/dev/null \
        | jq -r '.Account // empty')
    if [ -z "$account_uuid" ]; then
        warning "Test 1 - could not get account UUID, skipping"
        return 0
    fi
    # Save for other tests
    echo "$account_uuid" > "$TEMP_DIR/account_uuid"

    local policy
    policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}]}'

    local role_name="scope-int-allow-$(date +%s)"
    local role_arn
    role_arn=$(create_role_with_policy "$role_name" "$policy" "$account_uuid")
    if [ -z "$role_arn" ]; then
        error "Test 1 - could not create role"
        return 1
    fi

    # AssumeRole with the readwrite scoped key (scoped to BUCKET_A)
    if ! assume_role_with_key "$INT_RW_KEY_ID" "$INT_RW_SECRET" "$role_arn" "int-allow-test"; then
        error "Test 1 - AssumeRole failed"
        return 1
    fi

    # GET on BUCKET_A: scope allows (readwrite), IAM allows (s3:GetObject) → allowed
    set +e
    AWS_ACCESS_KEY_ID="$TEMP_KEY" \
    AWS_SECRET_ACCESS_KEY="$TEMP_SECRET" \
    AWS_SESSION_TOKEN="$TEMP_TOKEN" \
    aws_s3api get-object \
        --bucket "$INT_BUCKET_A" \
        --key "test.txt" \
        "$TEMP_DIR/int-allow.txt" \
        --endpoint-url="$S3_ENDPOINT" \
        --region="$AWS_REGION" \
        --no-verify-ssl >/dev/null 2>&1
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        success "Scope + IAM Allow - GET allowed (both gates pass)"
    else
        error "Scope + IAM Allow - GET should be allowed when both scope and IAM permit"
    fi
}

# =============================================================================
# Test 2: Scoped key + IAM Deny on scoped bucket → denied
# =============================================================================

test_scope_allow_iam_deny() {
    log "=== Test 2: Scoped key + IAM Deny on scoped bucket ==="

    local account_uuid
    if [ -f "$TEMP_DIR/account_uuid" ]; then
        read account_uuid < "$TEMP_DIR/account_uuid"
    fi
    if [ -z "$account_uuid" ]; then
        warning "Test 2 - no account UUID, skipping"
        return 0
    fi

    # IAM policy that explicitly denies s3:GetObject
    local policy
    policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":"*"},{"Effect":"Deny","Action":["s3:GetObject"],"Resource":"*"}]}'

    local role_name="scope-int-deny-$(date +%s)"
    local role_arn
    role_arn=$(create_role_with_policy "$role_name" "$policy" "$account_uuid")
    if [ -z "$role_arn" ]; then
        error "Test 2 - could not create role"
        return 1
    fi

    # AssumeRole with the readwrite scoped key
    if ! assume_role_with_key "$INT_RW_KEY_ID" "$INT_RW_SECRET" "$role_arn" "int-deny-test"; then
        error "Test 2 - AssumeRole failed"
        return 1
    fi

    # GET on BUCKET_A: scope allows, IAM denies → should be denied
    export AWS_ACCESS_KEY_ID="$TEMP_KEY"
    export AWS_SECRET_ACCESS_KEY="$TEMP_SECRET"
    export AWS_SESSION_TOKEN="$TEMP_TOKEN"

    assert_s3_deny \
        "Scope allow + IAM Deny - GET denied (IAM blocks)" \
        "AccessDenied" \
        aws_s3api get-object \
            --bucket "$INT_BUCKET_A" \
            --key "test.txt" \
            "$TEMP_DIR/int-iam-deny.txt"

    # Restore credentials
    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN
}

# =============================================================================
# Test 3: Unscoped key + IAM Deny → denied (scope is not a bypass)
# =============================================================================

test_unscoped_iam_deny() {
    log "=== Test 3: Unscoped key + IAM Deny ==="

    local account_uuid
    if [ -f "$TEMP_DIR/account_uuid" ]; then
        read account_uuid < "$TEMP_DIR/account_uuid"
    fi
    if [ -z "$account_uuid" ]; then
        warning "Test 3 - no account UUID, skipping"
        return 0
    fi

    # IAM policy that denies everything
    local policy
    policy='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:*"],"Resource":"*"}]}'

    local role_name="scope-int-unscoped-$(date +%s)"
    local role_arn
    role_arn=$(create_role_with_policy "$role_name" "$policy" "$account_uuid")
    if [ -z "$role_arn" ]; then
        error "Test 3 - could not create role"
        return 1
    fi

    # AssumeRole with the ADMIN (unscoped) key
    if ! assume_role_with_key \
        "$ORIGINAL_AWS_ACCESS_KEY_ID" "$ORIGINAL_AWS_SECRET_ACCESS_KEY" \
        "$role_arn" "int-unscoped-deny"; then
        error "Test 3 - AssumeRole failed"
        return 1
    fi

    export AWS_ACCESS_KEY_ID="$TEMP_KEY"
    export AWS_SECRET_ACCESS_KEY="$TEMP_SECRET"
    export AWS_SESSION_TOKEN="$TEMP_TOKEN"

    # Unscoped key means scope passes, but IAM denies → should fail
    assert_s3_deny \
        "Unscoped + IAM Deny - GET denied (IAM still blocks)" \
        "AccessDenied" \
        aws_s3api get-object \
            --bucket "$INT_BUCKET_A" \
            --key "test.txt" \
            "$TEMP_DIR/int-unscoped-deny.txt"

    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN
}

# =============================================================================
# Test 4: Scoped key allows A, IAM allows B only → both denied
# =============================================================================

test_scope_a_iam_b() {
    log "=== Test 4: Scope allows bucket A, IAM allows bucket B only ==="

    local account_uuid
    if [ -f "$TEMP_DIR/account_uuid" ]; then
        read account_uuid < "$TEMP_DIR/account_uuid"
    fi
    if [ -z "$account_uuid" ]; then
        warning "Test 4 - no account UUID, skipping"
        return 0
    fi

    # IAM policy allows only BUCKET_B operations
    local policy
    policy=$(jq -n --arg bucket "$INT_BUCKET_B" \
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:ListBucket"],"Resource":["arn:aws:s3:::" + $bucket, "arn:aws:s3:::" + $bucket + "/*"]}]}')

    local role_name="scope-int-ab-$(date +%s)"
    local role_arn
    role_arn=$(create_role_with_policy "$role_name" "$policy" "$account_uuid")
    if [ -z "$role_arn" ]; then
        error "Test 4 - could not create role"
        return 1
    fi

    # AssumeRole with the readwrite key scoped to BUCKET_A
    if ! assume_role_with_key "$INT_RW_KEY_ID" "$INT_RW_SECRET" "$role_arn" "int-ab-test"; then
        error "Test 4 - AssumeRole failed"
        return 1
    fi

    export AWS_ACCESS_KEY_ID="$TEMP_KEY"
    export AWS_SECRET_ACCESS_KEY="$TEMP_SECRET"
    export AWS_SESSION_TOKEN="$TEMP_TOKEN"

    # BUCKET_A: scope allows, IAM denies (not in policy) → denied
    assert_s3_deny \
        "Scope=A, IAM=B - GET on A denied (IAM blocks)" \
        "AccessDenied" \
        aws_s3api get-object \
            --bucket "$INT_BUCKET_A" \
            --key "test.txt" \
            "$TEMP_DIR/int-a-denied.txt"

    # BUCKET_B: scope denies (not in scope), IAM allows → denied
    assert_s3_deny \
        "Scope=A, IAM=B - GET on B denied (scope blocks)" \
        "AccessDenied" \
        aws_s3api get-object \
            --bucket "$INT_BUCKET_B" \
            --key "test.txt" \
            "$TEMP_DIR/int-b-denied.txt"

    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN
}

# =============================================================================
# Test 5: STS scope=read, IAM=s3:PutObject → denied (scope blocks write)
# =============================================================================

test_scope_read_iam_put() {
    log "=== Test 5: STS scope=read, IAM=s3:PutObject ==="

    local account_uuid
    if [ -f "$TEMP_DIR/account_uuid" ]; then
        read account_uuid < "$TEMP_DIR/account_uuid"
    fi
    if [ -z "$account_uuid" ]; then
        warning "Test 5 - no account UUID, skipping"
        return 0
    fi

    # IAM allows PutObject
    local policy
    policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":"*"}]}'

    local role_name="scope-int-roput-$(date +%s)"
    local role_arn
    role_arn=$(create_role_with_policy "$role_name" "$policy" "$account_uuid")
    if [ -z "$role_arn" ]; then
        error "Test 5 - could not create role"
        return 1
    fi

    # AssumeRole with the read-only scoped key
    if ! assume_role_with_key "$INT_RO_KEY_ID" "$INT_RO_SECRET" "$role_arn" "int-roput-test"; then
        error "Test 5 - AssumeRole failed"
        return 1
    fi

    export AWS_ACCESS_KEY_ID="$TEMP_KEY"
    export AWS_SECRET_ACCESS_KEY="$TEMP_SECRET"
    export AWS_SESSION_TOKEN="$TEMP_TOKEN"

    # PUT: scope=read denies write even though IAM allows PutObject
    assert_s3_deny \
        "Scope=read, IAM=PutObject - PUT denied (scope blocks write)" \
        "AccessDenied" \
        aws_s3api put-object \
            --bucket "$INT_BUCKET_A" \
            --key "scope-blocks-this.txt" \
            --body "$TEMP_DIR/int-test-obj.txt"

    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN
}

# =============================================================================
# Test 6: STS scope=readwrite, IAM=s3:GetObject only → denied (IAM blocks write)
# =============================================================================

test_scope_rw_iam_get() {
    log "=== Test 6: STS scope=readwrite, IAM=s3:GetObject only ==="

    local account_uuid
    if [ -f "$TEMP_DIR/account_uuid" ]; then
        read account_uuid < "$TEMP_DIR/account_uuid"
    fi
    if [ -z "$account_uuid" ]; then
        warning "Test 6 - no account UUID, skipping"
        return 0
    fi

    # IAM allows only GetObject
    local policy
    policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}'

    local role_name="scope-int-rwget-$(date +%s)"
    local role_arn
    role_arn=$(create_role_with_policy "$role_name" "$policy" "$account_uuid")
    if [ -z "$role_arn" ]; then
        error "Test 6 - could not create role"
        return 1
    fi

    # AssumeRole with the readwrite scoped key
    if ! assume_role_with_key "$INT_RW_KEY_ID" "$INT_RW_SECRET" "$role_arn" "int-rwget-test"; then
        error "Test 6 - AssumeRole failed"
        return 1
    fi

    export AWS_ACCESS_KEY_ID="$TEMP_KEY"
    export AWS_SECRET_ACCESS_KEY="$TEMP_SECRET"
    export AWS_SESSION_TOKEN="$TEMP_TOKEN"

    # GET should work (scope=readwrite allows, IAM=GetObject allows)
    set +e
    aws_s3api get-object \
        --bucket "$INT_BUCKET_A" \
        --key "test.txt" \
        "$TEMP_DIR/int-rwget-get.txt" \
        --endpoint-url="$S3_ENDPOINT" \
        --region="$AWS_REGION" \
        --no-verify-ssl >/dev/null 2>&1
    local get_rc=$?
    set -e

    if [ $get_rc -eq 0 ]; then
        success "Scope=readwrite, IAM=GetObject - GET allowed (both pass)"
    else
        error "Scope=readwrite, IAM=GetObject - GET should be allowed"
    fi

    # PUT should be denied (scope allows readwrite, but IAM only allows GetObject)
    assert_s3_deny \
        "Scope=readwrite, IAM=GetObject - PUT denied (IAM blocks write)" \
        "AccessDenied" \
        aws_s3api put-object \
            --bucket "$INT_BUCKET_A" \
            --key "iam-blocks-this.txt" \
            --body "$TEMP_DIR/int-test-obj.txt"

    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN
}

# =============================================================================
# Cleanup
# =============================================================================

test_cleanup() {
    log "Cleaning up intersection test resources..."
    set +e

    # Restore admin credentials first
    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN

    # Delete IAM roles
    for role_name in "${CREATED_ROLES[@]}"; do
        if [ -n "$role_name" ]; then
            aws_iam_silent delete-role-policy \
                --role-name "$role_name" --policy-name "TestPolicy" || true
            aws_iam_silent delete-role --role-name "$role_name" || true
        fi
    done

    # Delete test buckets
    for bkt in "$INT_BUCKET_A" "$INT_BUCKET_B"; do
        aws_s3 rm "s3://$bkt" --recursive 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$bkt" 2>/dev/null || true
    done

    # Delete access keys
    for kid in "$INT_RW_KEY_ID" "$INT_RO_KEY_ID"; do
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
    log "Scope — Scope + IAM Intersection Tests"
    log "=========================================="
    log "  S3 Endpoint:      $S3_ENDPOINT"
    log "  CloudAPI:         $CLOUDAPI_URL"
    log "  Account:          $MANTA_USER"
    log "  Replication wait: ${REPL_WAIT}s"
    log "=========================================="

    setup
    test_setup

    test_scope_and_iam_allow
    test_scope_allow_iam_deny
    test_unscoped_iam_deny
    test_scope_a_iam_b
    test_scope_read_iam_put
    test_scope_rw_iam_get

    test_cleanup
    print_summary
}

main "$@"
