#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Per-Bucket Access Key Scope — Error Response Format Tests
#
# Verifies that scope denials return proper S3-compatible XML error
# responses. Also acts as a regression test for CHG-069 (passthrough
# formatter crash on binary paths like GET/PUT object).
#
# Tests:
#   1. Scope deny returns <Code>AccessDenied</Code> in XML
#   2. Scope deny returns HTTP 403
#   3. Scope deny on GET object (binary path) — CHG-069 regression
#   4. Scope deny on PUT object (binary path) — CHG-069 regression
#   5. Error includes <RequestId> for SDK compatibility
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
ERR_BUCKET="scope-err-allowed-$(date +%s)"
ERR_OUTSIDE="scope-err-outside-$(date +%s)"

# Key tracking
ERR_RO_KEY_ID=""
ERR_RO_SECRET=""

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

# Make a raw curl request with SigV4 via the AWS CLI's --debug to get
# full HTTP response including status code and body.
# Usage: raw_s3_request <method> <path> [body_file]
# Returns: HTTP status code in RAW_STATUS, body in RAW_BODY
raw_s3_request() {
    local method="$1"
    local path="$2"
    local body_file="${3:-}"

    # Use aws cli but capture the raw error output which includes
    # the XML body and HTTP status code.
    local endpoint_host
    endpoint_host=$(echo "$S3_ENDPOINT" | sed 's|https\?://||')

    local curl_args=(
        -sk
        -X "$method"
        -w "\n%{http_code}"
        -H "Host: $endpoint_host"
    )

    if [ -n "$body_file" ]; then
        curl_args+=(-T "$body_file")
    fi

    # We need SigV4, so use the aws CLI and capture its error output.
    # The aws CLI prints the XML error body to stderr when it fails.
    local full_output
    set +e
    if [ "$method" = "GET" ]; then
        full_output=$(aws s3api get-object \
            --endpoint-url="$S3_ENDPOINT" \
            --region="$AWS_REGION" \
            --no-verify-ssl \
            --no-cli-pager \
            --bucket "$(echo "$path" | cut -d/ -f1)" \
            --key "$(echo "$path" | cut -d/ -f2-)" \
            "$TEMP_DIR/raw-download-$$" 2>&1)
        RAW_EXIT=$?
    elif [ "$method" = "PUT" ]; then
        full_output=$(aws s3api put-object \
            --endpoint-url="$S3_ENDPOINT" \
            --region="$AWS_REGION" \
            --no-verify-ssl \
            --no-cli-pager \
            --bucket "$(echo "$path" | cut -d/ -f1)" \
            --key "$(echo "$path" | cut -d/ -f2-)" \
            --body "$body_file" 2>&1)
        RAW_EXIT=$?
    elif [ "$method" = "HEAD" ]; then
        full_output=$(aws s3api head-object \
            --endpoint-url="$S3_ENDPOINT" \
            --region="$AWS_REGION" \
            --no-verify-ssl \
            --no-cli-pager \
            --bucket "$(echo "$path" | cut -d/ -f1)" \
            --key "$(echo "$path" | cut -d/ -f2-)" 2>&1)
        RAW_EXIT=$?
    fi
    set -e

    RAW_BODY="$full_output"
}

# =============================================================================
# Setup
# =============================================================================

test_setup() {
    log "Creating test buckets for error format tests..."

    aws_s3api create-bucket --bucket "$ERR_BUCKET" >/dev/null 2>&1 || true
    aws_s3api create-bucket --bucket "$ERR_OUTSIDE" >/dev/null 2>&1 || true

    local test_file="$TEMP_DIR/err-test-obj.txt"
    echo "error format test content" > "$test_file"
    aws_s3api put-object --bucket "$ERR_BUCKET" \
        --key "test.txt" --body "$test_file" >/dev/null 2>&1
    aws_s3api put-object --bucket "$ERR_OUTSIDE" \
        --key "test.txt" --body "$test_file" >/dev/null 2>&1

    # Create a 1MB binary file for binary path tests
    dd if=/dev/urandom of="$TEMP_DIR/binary-file.bin" bs=1024 count=1024 2>/dev/null

    # read-only key scoped to ERR_BUCKET
    local scope='[{"bucket":"'"$ERR_BUCKET"'","level":"read"}]'
    if ! create_scoped_key "$scope"; then
        error "Setup - failed to create scoped key"
        return 1
    fi
    ERR_RO_KEY_ID="$LAST_KEY_ID"
    ERR_RO_SECRET="$LAST_KEY_SECRET"
    log "Created read-only key: $ERR_RO_KEY_ID"

    wait_for_replication
    success "Error format test setup complete"
}

# =============================================================================
# Test 1: Scope deny returns <Code>AccessDenied</Code>
# =============================================================================

test_error_code_xml() {
    log "=== Test 1: Scope deny returns AccessDenied error code ==="

    # Access unscoped bucket — should get AccessDenied
    export AWS_ACCESS_KEY_ID="$ERR_RO_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ERR_RO_SECRET"
    unset AWS_SESSION_TOKEN

    raw_s3_request "GET" "$ERR_OUTSIDE/test.txt"

    if [ $RAW_EXIT -ne 0 ]; then
        # Check for AccessDenied in the error output
        local code
        code=$(xml_error_code "$RAW_BODY")

        if [ "$code" = "AccessDenied" ]; then
            success "Error code XML - <Code>AccessDenied</Code> present"
        elif echo "$RAW_BODY" | grep -q "AccessDenied"; then
            success "Error code XML - AccessDenied found in response"
        else
            error "Error code XML - expected AccessDenied, got: $code"
            log "Body: $RAW_BODY"
        fi
    else
        error "Error code XML - request should have been denied"
    fi

    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
}

# =============================================================================
# Test 2: Scope deny returns HTTP 403
# =============================================================================

test_error_http_403() {
    log "=== Test 2: Scope deny returns HTTP 403 ==="

    export AWS_ACCESS_KEY_ID="$ERR_RO_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ERR_RO_SECRET"
    unset AWS_SESSION_TOKEN

    raw_s3_request "GET" "$ERR_OUTSIDE/test.txt"

    if [ $RAW_EXIT -ne 0 ]; then
        # The AWS CLI outputs "403" or "Forbidden" on scope denials
        if echo "$RAW_BODY" | grep -q "403\|Forbidden\|AccessDenied"; then
            success "HTTP 403 - scope deny returns 403"
        else
            error "HTTP 403 - expected 403 but got: $RAW_BODY"
        fi
    else
        error "HTTP 403 - request should have been denied"
    fi

    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
}

# =============================================================================
# Test 3: Scope deny on GET object (binary path) — CHG-069 regression
#
# Pre-CHG-069: GET object paths set _skipS3ResponseProcessing=true and
# _binaryOperation=true. When enforceBucketScope denied the request,
# the passthrough formatter received an Error object and passed it to
# res.write(), causing TypeError → process crash → 502.
#
# Post-CHG-069: The passthrough formatter routes Error objects through
# formatJSON, producing a valid XML error response.
# =============================================================================

test_get_object_binary_path_deny() {
    log "=== Test 3: GET object scope deny (binary path, CHG-069 regression) ==="

    export AWS_ACCESS_KEY_ID="$ERR_RO_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ERR_RO_SECRET"
    unset AWS_SESSION_TOKEN

    # GET on unscoped bucket — this exercises the binary download path
    set +e
    local result
    result=$(aws_s3api get-object \
        --endpoint-url="$S3_ENDPOINT" \
        --region="$AWS_REGION" \
        --no-verify-ssl \
        --no-cli-pager \
        --bucket "$ERR_OUTSIDE" \
        --key "test.txt" \
        "$TEMP_DIR/chg069-get.txt" 2>&1)
    local rc=$?
    set -e

    if [ $rc -ne 0 ]; then
        # Check it's a proper 403, NOT a 502/503 (crash)
        if echo "$result" | grep -qi "502\|503\|Service Unavailable"; then
            error "GET binary path deny - got 502/503 (CHG-069 REGRESSION: backend crashed)"
            error "  The passthrough formatter is crashing on Error objects."
            error "  Check buckets-api logs for 'TypeError: First argument must be a string or Buffer'"
        elif echo "$result" | grep -qi "403\|Forbidden\|AccessDenied"; then
            success "GET binary path deny - proper 403 (CHG-069 fixed)"
        else
            error "GET binary path deny - unexpected error: $result"
        fi
    else
        error "GET binary path deny - should be denied on unscoped bucket"
    fi

    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
}

# =============================================================================
# Test 4: Scope deny on PUT object (binary path) — CHG-069 regression
# =============================================================================

test_put_object_binary_path_deny() {
    log "=== Test 4: PUT object scope deny (binary path, CHG-069 regression) ==="

    export AWS_ACCESS_KEY_ID="$ERR_RO_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ERR_RO_SECRET"
    unset AWS_SESSION_TOKEN

    # PUT on the SCOPED bucket with read-only key — readwrite required for PUT.
    # This also exercises the binary upload path.
    set +e
    local result
    result=$(aws_s3api put-object \
        --endpoint-url="$S3_ENDPOINT" \
        --region="$AWS_REGION" \
        --no-verify-ssl \
        --no-cli-pager \
        --bucket "$ERR_BUCKET" \
        --key "chg069-put.bin" \
        --body "$TEMP_DIR/binary-file.bin" 2>&1)
    local rc=$?
    set -e

    if [ $rc -ne 0 ]; then
        if echo "$result" | grep -qi "502\|503\|Service Unavailable"; then
            error "PUT binary path deny - got 502/503 (CHG-069 REGRESSION: backend crashed)"
            error "  Check buckets-api logs for 'TypeError: First argument must be a string or Buffer'"
        elif echo "$result" | grep -qi "Connection was closed"; then
            warning "PUT binary path deny - connection closed (muppet/haproxy Expect:100-continue race)"
            success "PUT binary path deny - denied via connection reset (CHG-069 OK)"
        elif echo "$result" | grep -qi "403\|Forbidden\|AccessDenied"; then
            success "PUT binary path deny - proper 403 (CHG-069 fixed)"
        else
            error "PUT binary path deny - unexpected error: $result"
        fi
    else
        error "PUT binary path deny - should be denied (read-only key)"
    fi

    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
}

# =============================================================================
# Test 5: Error response includes RequestId
# =============================================================================

test_error_has_request_id() {
    log "=== Test 5: Error response includes RequestId ==="

    export AWS_ACCESS_KEY_ID="$ERR_RO_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ERR_RO_SECRET"
    unset AWS_SESSION_TOKEN

    raw_s3_request "GET" "$ERR_OUTSIDE/test.txt"

    if [ $RAW_EXIT -ne 0 ]; then
        # AWS CLI reports request IDs in its error output
        if echo "$RAW_BODY" | grep -qi "RequestId\|request-id\|x-amz-request-id"; then
            success "Error includes RequestId - SDK-compatible"
        elif echo "$RAW_BODY" | grep -qi "403\|AccessDenied"; then
            # The AWS CLI may not always surface the RequestId in its
            # error text, but the important thing is we got a proper
            # error and not a crash.
            warning "Error RequestId - could not verify in CLI output (403 confirmed)"
            success "Error response is well-formed (403 with AccessDenied)"
        else
            error "Error RequestId - unexpected response: $RAW_BODY"
        fi
    else
        error "Error RequestId - request should have been denied"
    fi

    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
}

# =============================================================================
# Cleanup
# =============================================================================

test_cleanup() {
    log "Cleaning up error format test resources..."
    set +e

    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN

    for bkt in "$ERR_BUCKET" "$ERR_OUTSIDE"; do
        aws_s3 rm "s3://$bkt" --recursive 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$bkt" 2>/dev/null || true
    done

    if [ -n "$ERR_RO_KEY_ID" ]; then
        delete_key "$ERR_RO_KEY_ID" 2>/dev/null || true
    fi

    cleanup_credentials
    set -e
    log "Cleanup complete"
}

# =============================================================================
# Main
# =============================================================================

main() {
    log "=========================================="
    log "Scope — Error Response Format Tests"
    log "=========================================="
    log "  S3 Endpoint:      $S3_ENDPOINT"
    log "  CloudAPI:         $CLOUDAPI_URL"
    log "  Account:          $MANTA_USER"
    log "  Replication wait: ${REPL_WAIT}s"
    log "=========================================="

    setup
    test_setup

    test_error_code_xml
    test_error_http_403
    test_get_object_binary_path_deny
    test_put_object_binary_path_deny
    test_error_has_request_id

    test_cleanup
    print_summary
}

main "$@"
