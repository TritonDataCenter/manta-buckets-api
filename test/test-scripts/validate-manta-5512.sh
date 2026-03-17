#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Validation script for MANTA-5512:
# "Use mahi-derived signing key for AWS chunked STS verification"
#
# Verifies that aws-chunked uploads work with STS temporary credentials.
# Before this fix, per-chunk signature verification failed because the
# secret access key for STS session keys is not in the account's
# permanent accesskeys map. Mahi now returns a derived signing key after
# verifying the initial SigV4 signature, and buckets-api uses it
# directly for per-chunk verification.
#
# What this script does:
#   1. Gets STS temporary credentials via GetSessionToken
#   2. Creates a bucket using those temp credentials
#   3. Uploads an object with aws-chunked encoding (forces chunked transfer)
#   4. Downloads the object and verifies content matches
#   5. Cleans up
#
# Key log messages to look for (at DEBUG level via bunyan -p):
#   - "AWS chunked: signature verification enabled" (common.js)
#     confirms signing key was available and chunk verification is active
#   - "AWS Decoder: chunk signature verified successfully" (aws-chunked-decoder.js)
#     confirms each chunk's signature was verified against mahi's signing key
#   - "AWS chunked decoder: completed decoding" (aws-chunked-decoder.js)
#     confirms full decode succeeded
#   - "Secret access key not found in account accesskeys" at DEBUG (not WARN)
#     confirms STS key lookup is correctly downgraded (MANTA-5512 companion fix)

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

VALIDATION_BUCKET="manta-5512-validate-$$"
VALIDATION_OBJECT="chunked-sts-test.txt"
VALIDATION_CONTENT="MANTA-5512 validation: aws-chunked upload with STS temporary credentials should have per-chunk signature verification enabled via mahi-derived signing key."

main() {
    log "=========================================="
    log "MANTA-5512 Validation: STS + aws-chunked"
    log "=========================================="

    setup

    # -------------------------------------------------------
    # Step 1: Get STS temporary credentials
    # -------------------------------------------------------
    log "Step 1: Getting STS temporary credentials (GetSessionToken)..."
    local session_output
    capture_output session_output aws_sts get-session-token \
        --duration-seconds 900 --output json

    if [ $? -ne 0 ]; then
        error "MANTA-5512 - Failed to get STS session token"
        print_summary
        return 1
    fi

    local sts_access_key sts_secret_key sts_session_token
    sts_access_key=$(echo "$session_output" | jq -r '.Credentials.AccessKeyId // empty')
    sts_secret_key=$(echo "$session_output" | jq -r '.Credentials.SecretAccessKey // empty')
    sts_session_token=$(echo "$session_output" | jq -r '.Credentials.SessionToken // empty')

    if [ -z "$sts_access_key" ] || [ -z "$sts_secret_key" ] || [ -z "$sts_session_token" ]; then
        error "MANTA-5512 - STS credentials incomplete"
        log "Output: $session_output"
        print_summary
        return 1
    fi

    log "  Got STS key: ${sts_access_key:0:12}..."
    success "MANTA-5512 Step 1 - STS GetSessionToken succeeded"

    # -------------------------------------------------------
    # Step 2: Create bucket with STS credentials
    # -------------------------------------------------------
    log "Step 2: Creating bucket '$VALIDATION_BUCKET' with STS credentials..."

    # Switch to STS credentials
    export AWS_ACCESS_KEY_ID="$sts_access_key"
    export AWS_SECRET_ACCESS_KEY="$sts_secret_key"
    export AWS_SESSION_TOKEN="$sts_session_token"

    set +e
    capture_output create_result aws_s3api create-bucket \
        --bucket "$VALIDATION_BUCKET"
    local create_exit=$?
    set -e

    if [ $create_exit -ne 0 ]; then
        error "MANTA-5512 Step 2 - Failed to create bucket with STS creds: $create_result"
        print_summary
        return 1
    fi

    success "MANTA-5512 Step 2 - Bucket created with STS credentials"

    # -------------------------------------------------------
    # Step 3: Upload object with aws-chunked encoding
    # -------------------------------------------------------
    log "Step 3: Uploading object with aws-chunked encoding via STS credentials..."
    log "  This is the critical test: per-chunk signatures must be verified"
    log "  using the mahi-derived signing key (not the secret access key)."

    # Generate a test file. AWS CLI v2 uses STREAMING-UNSIGNED-PAYLOAD-TRAILER
    # which does NOT include per-chunk signatures. To force per-chunk signed
    # aws-chunked (STREAMING-AWS4-HMAC-SHA256-PAYLOAD), we use a Python script
    # that calls boto3 with the correct signing mode.
    local test_file="$TEMP_DIR/$VALIDATION_OBJECT"
    dd if=/dev/urandom bs=1024 count=256 2>/dev/null | base64 > "$test_file"
    local file_size=$(wc -c < "$test_file" | tr -d ' ')
    log "  Generated test file: ${file_size} bytes (~256KB)"
    log "  Using boto3 with STREAMING-AWS4-HMAC-SHA256-PAYLOAD for per-chunk signatures"

    # Use boto3 to upload with per-chunk signature verification
    # boto3's s3.upload_file uses chunked transfer with signed payloads
    set +e
    # Use curl to send a proper STREAMING-AWS4-HMAC-SHA256-PAYLOAD request.
    # We use the aws s3api put-object with explicit chunked transfer,
    # but AWS CLI v2 doesn't support this. Instead, use a small Python
    # script that manually constructs the aws-chunked request with
    # per-chunk signatures using botocore's internal SigV4 machinery.
    capture_output upload_result /tmp/boto3-env/bin/python3 - "$test_file" \
        "$VALIDATION_BUCKET" "$VALIDATION_OBJECT" \
        "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" \
        "$AWS_SESSION_TOKEN" "$S3_ENDPOINT" <<'PYEOF'
import sys, hashlib, hmac, datetime, os
import urllib3, requests

urllib3.disable_warnings()

test_file, bucket, key = sys.argv[1], sys.argv[2], sys.argv[3]
access_key, secret_key, session_token = sys.argv[4], sys.argv[5], sys.argv[6]
endpoint = sys.argv[7]

with open(test_file, 'rb') as f:
    body = f.read()

# AWS SigV4 helpers
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def get_signature_key(secret, date_stamp, region, service):
    k_date = sign(('AWS4' + secret).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, 'aws4_request')
    return k_signing

now = datetime.datetime.utcnow()
amz_date = now.strftime('%Y%m%dT%H%M%SZ')
date_stamp = now.strftime('%Y%m%d')
region = 'us-east-1'
service = 's3'
host = endpoint.replace('https://', '').replace('http://', '')
credential_scope = f'{date_stamp}/{region}/{service}/aws4_request'

# Build aws-chunked body with per-chunk signatures
CHUNK_SIZE = 65536  # 64KB chunks
signing_key = get_signature_key(secret_key, date_stamp, region, service)

# Calculate seed signature (initial request signature)
decoded_length = len(body)

# Canonical request for STREAMING-AWS4-HMAC-SHA256-PAYLOAD
canonical_uri = f'/{bucket}/{key}'
canonical_querystring = ''
canonical_headers = (
    f'content-encoding:aws-chunked\n'
    f'host:{host}\n'
    f'x-amz-content-sha256:STREAMING-AWS4-HMAC-SHA256-PAYLOAD\n'
    f'x-amz-date:{amz_date}\n'
    f'x-amz-decoded-content-length:{decoded_length}\n'
    f'x-amz-security-token:{session_token}\n'
)
signed_headers = 'content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-security-token'
payload_hash = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'

canonical_request = (
    f'PUT\n{canonical_uri}\n{canonical_querystring}\n'
    f'{canonical_headers}\n{signed_headers}\n{payload_hash}'
)
cr_hash = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

string_to_sign = f'AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{cr_hash}'
seed_signature = hmac.new(signing_key, string_to_sign.encode('utf-8'),
                          hashlib.sha256).hexdigest()

# Build chunked body with per-chunk signatures
EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()
prev_sig = seed_signature
chunked_body = b''
offset = 0

while offset < len(body):
    chunk = body[offset:offset + CHUNK_SIZE]
    chunk_hash = hashlib.sha256(chunk).hexdigest()

    chunk_sts = (
        f'AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{credential_scope}\n'
        f'{prev_sig}\n{EMPTY_SHA256}\n{chunk_hash}'
    )
    chunk_sig = hmac.new(signing_key, chunk_sts.encode('utf-8'),
                         hashlib.sha256).hexdigest()

    chunk_header = f'{len(chunk):x};chunk-signature={chunk_sig}\r\n'.encode()
    chunked_body += chunk_header + chunk + b'\r\n'
    prev_sig = chunk_sig
    offset += CHUNK_SIZE

# Final zero-length chunk
final_sts = (
    f'AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{credential_scope}\n'
    f'{prev_sig}\n{EMPTY_SHA256}\n{EMPTY_SHA256}'
)
final_sig = hmac.new(signing_key, final_sts.encode('utf-8'),
                     hashlib.sha256).hexdigest()
chunked_body += f'0;chunk-signature={final_sig}\r\n\r\n'.encode()

# Calculate content-length of the chunked body
content_length = len(chunked_body)

# Send request
headers = {
    'Host': host,
    'Content-Encoding': 'aws-chunked',
    'Content-Length': str(content_length),
    'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
    'x-amz-date': amz_date,
    'x-amz-decoded-content-length': str(decoded_length),
    'x-amz-security-token': session_token,
    'Authorization': (
        f'AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, '
        f'SignedHeaders={signed_headers}, '
        f'Signature={seed_signature}'
    ),
}

url = f'{endpoint}/{bucket}/{key}'
resp = requests.put(url, data=chunked_body, headers=headers, verify=False)

if resp.status_code == 200:
    print(f'Upload completed successfully (HTTP {resp.status_code})')
    num_chunks = (len(body) + CHUNK_SIZE - 1) // CHUNK_SIZE
    print(f'Sent {num_chunks} signed chunks + final zero chunk')
else:
    print(f'Upload FAILED: HTTP {resp.status_code}', file=sys.stderr)
    print(resp.text, file=sys.stderr)
    sys.exit(1)
PYEOF
    local upload_exit=$?
    set -e

    if [ $upload_exit -ne 0 ]; then
        error "MANTA-5512 Step 3 - aws-chunked upload FAILED with STS creds: $upload_result"
        log "  >>> This is the bug MANTA-5512 fixes. If this fails with"
        log "  >>> SignatureDoesNotMatch, the signing key is not being"
        log "  >>> passed from mahi to the chunk verifier."
        # Cleanup
        aws_s3api delete-bucket --bucket "$VALIDATION_BUCKET" 2>/dev/null || true
        print_summary
        return 1
    fi

    success "MANTA-5512 Step 3 - aws-chunked upload with STS credentials SUCCEEDED"

    # -------------------------------------------------------
    # Step 4: Download and verify content
    # -------------------------------------------------------
    log "Step 4: Downloading object and verifying content integrity..."

    local download_file="$TEMP_DIR/downloaded-$VALIDATION_OBJECT"
    set +e
    capture_output download_result aws_s3 cp \
        "s3://$VALIDATION_BUCKET/$VALIDATION_OBJECT" "$download_file"
    local download_exit=$?
    set -e

    if [ $download_exit -ne 0 ]; then
        error "MANTA-5512 Step 4 - Download failed: $download_result"
    else
        local uploaded_md5 downloaded_md5
        uploaded_md5=$(md5 -q "$test_file" 2>/dev/null || md5sum "$test_file" | awk '{print $1}')
        downloaded_md5=$(md5 -q "$download_file" 2>/dev/null || md5sum "$download_file" | awk '{print $1}')

        if [ "$uploaded_md5" = "$downloaded_md5" ]; then
            success "MANTA-5512 Step 4 - Content integrity verified (md5: $uploaded_md5)"
        else
            error "MANTA-5512 Step 4 - Content mismatch! upload=$uploaded_md5 download=$downloaded_md5"
        fi
    fi

    # -------------------------------------------------------
    # Step 5: Cleanup
    # -------------------------------------------------------
    log "Step 5: Cleaning up..."
    aws_s3api delete-object --bucket "$VALIDATION_BUCKET" \
        --key "$VALIDATION_OBJECT" 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$VALIDATION_BUCKET" 2>/dev/null || true
    rm -f "$test_file" "$download_file" 2>/dev/null || true

    # Restore original credentials
    export AWS_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_ACCESS_KEY"
    unset AWS_SESSION_TOKEN

    success "MANTA-5512 Step 5 - Cleanup complete"

    log ""
    log "=========================================="
    log "Log verification hints (run bunyan -p <pid> on buckets-api zone):"
    log "  Look for these DEBUG messages during the upload:"
    log "  1. 'AWS chunked: signature verification enabled'"
    log "     => signing key was available, chunk verification is active"
    log "  2. 'AWS Decoder: chunk signature verified successfully'"
    log "     => per-chunk signature matched using mahi-derived key"
    log "  3. 'AWS chunked decoder: completed decoding'"
    log "     => full chunked decode succeeded"
    log "  4. 'Secret access key not found in account accesskeys' at DEBUG"
    log "     => STS key lookup correctly at debug (not warn)"
    log "=========================================="

    print_summary
}

main
