#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
#
# Streaming SigV4 detection / decoding regression test.
#
# *** WHY THIS TEST EXISTS ***
#
# manta-buckets-api detects aws-chunked uploads from request headers
# and engages a stream decoder that strips the chunk framing before
# persisting object data.
#
# The AWS SigV4 streaming spec has TWO ways to signal a chunked upload:
#
#   (1) Content-Encoding: aws-chunked          - transport hint,
#                                                ADVISORY, many SDKs
#                                                do not send it
#   (2) x-amz-content-sha256:
#         STREAMING-AWS4-HMAC-SHA256-PAYLOAD   - part of the signed
#                                                canonical request,
#                                                MANDATORY
#
# Signal (2) is the only reliable marker because clients can't omit
# it - the signature math depends on it.  Signal (1) is what AWS docs
# show first and what older awscli used to send, so a "detect by
# Content-Encoding only" implementation looks correct under most
# casual testing but silently breaks for any client that follows the
# spec strictly and omits (1).  Such clients include mc, AWS SDK for
# Go, and AWS SDK for Java (some configs).
#
# When the server fails to detect chunked encoding, the chunk frame
# (chunk-size lines, chunk-signature markers, terminating 0-chunk)
# gets stored as object data:
#
#       wire body sent by client       what the server stores
#       ------------------------       ----------------------
#       1b;chunk-signature=...\r\n
#       hello world this is test\r\n
#       0;chunk-signature=...\r\n      <-- 200 bytes of frame
#                                          instead of 27 bytes of
#                                          payload
#
# Subsequent GETs return the raw frame, MD5 mismatches, ContentLength
# is wrong, etc.  The PUT itself returns 200 OK so the bug is silent
# on the write side.
#
# *** WHY THE EXISTING SUITE DID NOT CATCH IT ***
#
# s3-aws-chunked-test.sh calls `aws s3api put-object` and is named
# accordingly, but awscli v2 (>=2.10 or so) no longer uses streaming
# SigV4 for ordinary put-object - it precomputes Content-Length and
# full-body SHA256 and sends a regular signed PUT.  So that suite
# does not actually exercise streaming SigV4 even though its name
# implies it does.
#
# This test deliberately uses a client (mc) that uses streaming
# SigV4 without sending Content-Encoding, so the broken-detection
# path is exercised on every run.
#
# Bug history: introduced by ca3866d (MANTA-5485, 2026-01-20), fixed
# by 0254ef8 (Fix UploadPartCopy 0-byte hang and aws-chunked
# streaming detection).

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

if ! command -v mc >/dev/null 2>&1; then
    echo "SKIP: mc (MinIO Client) is required for this test"
    exit 0
fi

ALIAS="streaming-sigv4-$$"
BUCKET="streaming-sigv4-$(date +%s)-$$"
SRC=/tmp/streaming-sigv4-src-$$.txt
DST=/tmp/streaming-sigv4-dst-$$.txt

cleanup() {
    mc rb --force --insecure "${ALIAS}/${BUCKET}" >/dev/null 2>&1 || true
    mc alias remove "$ALIAS" >/dev/null 2>&1 || true
    rm -f "$SRC" "$DST"
}
trap cleanup EXIT

log "Streaming SigV4 regression test starting"
log "  S3_ENDPOINT: $S3_ENDPOINT"

mc alias set "$ALIAS" "$S3_ENDPOINT" \
    "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" \
    --api S3v4 --path on >/dev/null

mc mb --insecure "${ALIAS}/${BUCKET}" >/dev/null

# Test 1: Small payload exercises streaming-SigV4 single-chunk path.
log "Test 1: small payload byte integrity (single chunk)"
printf 'hello world this is a test\n' > "$SRC"
mc cp --insecure "$SRC" "${ALIAS}/${BUCKET}/small.txt" >/dev/null

server_size=$(aws_s3api head-object \
    --bucket "$BUCKET" --key small.txt 2>&1 | \
    jq -r '.ContentLength // empty')
local_size=$(wc -c < "$SRC" | tr -d ' ')

if [ "$server_size" = "$local_size" ]; then
    success "Stored object size matches source ($local_size bytes)"
else
    error "Stored object size mismatch (local=$local_size " \
        "server=$server_size) - server likely stored chunk frame"
fi

mc cp --insecure "${ALIAS}/${BUCKET}/small.txt" "$DST" >/dev/null
local_md5=$(md5 -q "$SRC" 2>/dev/null || \
    md5sum "$SRC" | awk '{print $1}')
remote_md5=$(md5 -q "$DST" 2>/dev/null || \
    md5sum "$DST" | awk '{print $1}')

if [ "$local_md5" = "$remote_md5" ]; then
    success "MD5 round-trip matches ($local_md5)"
else
    error "MD5 mismatch (local=$local_md5 remote=$remote_md5)"
fi

# Test 2: Multi-chunk payload exercises the chunk-boundary decoder.
# mc default chunk size is 16 KiB, so 64 KiB gives at least 4 chunks
# plus the 0-chunk terminator.
log "Test 2: multi-chunk payload byte integrity (~64 KiB)"
dd if=/dev/urandom of="$SRC" bs=1024 count=64 2>/dev/null
mc cp --insecure "$SRC" "${ALIAS}/${BUCKET}/multi.bin" >/dev/null

server_size=$(aws_s3api head-object \
    --bucket "$BUCKET" --key multi.bin 2>&1 | \
    jq -r '.ContentLength // empty')
local_size=$(wc -c < "$SRC" | tr -d ' ')

if [ "$server_size" = "$local_size" ]; then
    success "Multi-chunk stored size matches source ($local_size bytes)"
else
    error "Multi-chunk stored size mismatch (local=$local_size " \
        "server=$server_size)"
fi

mc cp --insecure "${ALIAS}/${BUCKET}/multi.bin" "$DST" >/dev/null
local_md5=$(md5 -q "$SRC" 2>/dev/null || \
    md5sum "$SRC" | awk '{print $1}')
remote_md5=$(md5 -q "$DST" 2>/dev/null || \
    md5sum "$DST" | awk '{print $1}')

if [ "$local_md5" = "$remote_md5" ]; then
    success "Multi-chunk MD5 round-trip matches ($local_md5)"
else
    error "Multi-chunk MD5 mismatch (local=$local_md5 remote=$remote_md5)"
fi

# Test 3: Verify the server stripped the chunk framing by scanning
# the GET response for the characteristic chunk-signature= marker.
# This catches the specific symptom of the original bug.
log "Test 3: stored object must not contain chunk-signature framing"
if grep -q "chunk-signature=" "$DST"; then
    error "Stored object contains 'chunk-signature=' framing - " \
        "server failed to strip chunk encoding"
else
    success "Stored object is clean of chunk-signature framing"
fi

print_summary
