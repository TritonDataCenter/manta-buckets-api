#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Validation script for rclone S3 compatibility against manta-buckets-api.
#
# Tests rclone operations and reports which are supported and which fail.
#
# Requires:
#   - rclone installed with an S3 remote named "dev02" configured in
#     ~/.config/rclone/rclone.conf
#
# Usage:
#   RCLONE_REMOTE=dev02  ./rclone-validation-test.sh

set -eo pipefail

# =============================================================================
# Configuration
# =============================================================================

RCLONE_REMOTE=${RCLONE_REMOTE:-"dev02"}
RCLONE_FLAGS="--no-check-certificate --s3-provider=Other"

if ! command -v rclone &>/dev/null; then
    echo "ERROR: rclone is not installed"
    exit 1
fi

REMOTE="${RCLONE_REMOTE}:"
BUCKET="rclone-test-$$-$(date +%s)"
REMOTE_BUCKET="${REMOTE}${BUCKET}"
TEMP_DIR="/tmp/rclone-validation-$$"
SYNC_SRC="$TEMP_DIR/sync-src"
SYNC_DST="$TEMP_DIR/sync-dst"
MIRROR_SRC="$TEMP_DIR/mirror-src"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Result tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
PASSED_OPS=()
FAILED_OPS=()
SKIPPED_OPS=()

# =============================================================================
# Utility Functions
# =============================================================================

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}  PASS: $1${NC}"
    ((TESTS_PASSED++))
    PASSED_OPS+=("$1")
}

error() {
    echo -e "${RED}  FAIL: $1${NC}"
    ((TESTS_FAILED++))
    FAILED_OPS+=("$1")
}

skip() {
    echo -e "${YELLOW}  SKIP: $1${NC}"
    ((TESTS_SKIPPED++))
    SKIPPED_OPS+=("$1")
}

rclone_cmd() {
    rclone $RCLONE_FLAGS "$@" 2>&1
}

# Run a test: run_test "description" command [args...]
# Returns 0 on success, 1 on failure
run_test() {
    local desc="$1"
    shift
    local output
    set +e
    output=$(rclone_cmd "$@" 2>&1)
    local rc=$?
    set -e
    if [ $rc -eq 0 ]; then
        success "$desc"
        echo "$output"
        return 0
    else
        error "$desc"
        if [ -n "$output" ]; then
            echo "    output: $(echo "$output" | head -3)"
        fi
        return 1
    fi
}

cleanup() {
    log "Cleaning up..."
    # Remove remote bucket contents and bucket
    for suffix in "" "-sync" "-mirror" "-copy" "-move-dst"; do
        rclone_cmd purge "${REMOTE}${BUCKET}${suffix}" 2>/dev/null || true
    done
    rm -rf "$TEMP_DIR" 2>/dev/null || true
    log "Cleanup complete"
}

trap cleanup EXIT

# =============================================================================
# Setup
# =============================================================================

log "=========================================="
log "Rclone S3 Compatibility Validation"
log "=========================================="
log "Remote: $RCLONE_REMOTE"
log "Test bucket: $BUCKET"
log "rclone version: $(rclone version 2>/dev/null | head -1)"
log ""

mkdir -p "$SYNC_SRC" "$SYNC_DST" "$MIRROR_SRC" "$TEMP_DIR/download"

# Generate test files
echo "Hello from rclone test" > "$TEMP_DIR/test1.txt"
echo "Second test file for rclone" > "$TEMP_DIR/test2.txt"
dd if=/dev/urandom bs=1024 count=100 2>/dev/null | base64 > "$TEMP_DIR/medium-file.bin"

# Generate files for sync tests
for i in 1 2 3 4 5; do
    echo "Sync file $i - content $(date +%s%N)" > "$SYNC_SRC/file-$i.txt"
done
mkdir -p "$SYNC_SRC/subdir"
echo "Nested file in subdir" > "$SYNC_SRC/subdir/nested.txt"

# Generate files for mirror tests
for i in 1 2 3; do
    echo "Mirror file $i" > "$MIRROR_SRC/mirror-$i.txt"
done

# =============================================================================
# Test 1: Bucket Operations
# =============================================================================

log "--- Bucket Operations ---"

run_test "mkdir (CreateBucket)" mkdir "$REMOTE_BUCKET" || true

run_test "lsd (ListBuckets)" lsd "$REMOTE" || true

# Verify our bucket appears in listing
set +e
listing=$(rclone_cmd lsd "$REMOTE" 2>&1)
set -e
if echo "$listing" | grep -q "$BUCKET"; then
    success "ListBuckets contains test bucket"
else
    error "ListBuckets contains test bucket"
fi

# =============================================================================
# Test 2: Basic File Operations
# =============================================================================

log ""
log "--- Basic File Operations ---"

run_test "copy single file (PutObject)" \
    copy "$TEMP_DIR/test1.txt" "$REMOTE_BUCKET/" || true

run_test "ls (ListObjects)" ls "$REMOTE_BUCKET" || true

run_test "lsl (ListObjects with details)" lsl "$REMOTE_BUCKET" || true

run_test "cat (GetObject to stdout)" cat "$REMOTE_BUCKET/test1.txt" || true

# Verify content matches
set +e
downloaded=$(rclone_cmd cat "$REMOTE_BUCKET/test1.txt" 2>&1)
original=$(cat "$TEMP_DIR/test1.txt")
set -e
if [ "$downloaded" = "$original" ]; then
    success "Content integrity (GetObject matches PutObject)"
else
    error "Content integrity (GetObject matches PutObject)"
fi

run_test "copyto (PutObject with rename)" \
    copyto "$TEMP_DIR/test1.txt" "$REMOTE_BUCKET/renamed-file.txt" || true

run_test "copy file to local (GetObject)" \
    copy "$REMOTE_BUCKET/test1.txt" "$TEMP_DIR/download/" || true

# =============================================================================
# Test 3: File Metadata / Info
# =============================================================================

log ""
log "--- File Metadata Operations ---"

run_test "size (HeadObject / content-length)" \
    size "$REMOTE_BUCKET" || true

run_test "md5sum" md5sum "$REMOTE_BUCKET" || true

# S3 only supports MD5 (via ETag), not SHA1
set +e
sha1_out=$(rclone_cmd sha1sum "$REMOTE_BUCKET" 2>&1)
sha1_rc=$?
set -e
if [ $sha1_rc -eq 0 ]; then
    success "sha1sum"
else
    skip "sha1sum - S3 only supports MD5 (via ETag), not SHA1"
fi

run_test "hashsum MD5" hashsum MD5 "$REMOTE_BUCKET" || true

# =============================================================================
# Test 4: Multiple File Operations
# =============================================================================

log ""
log "--- Multiple File Operations ---"

run_test "copy multiple files" \
    copy "$TEMP_DIR/" "$REMOTE_BUCKET/multi/" \
    --include "test*.txt" || true

# Check file count
set +e
count=$(rclone_cmd ls "$REMOTE_BUCKET/multi/" 2>&1 | wc -l | tr -d ' ')
set -e
if [ "$count" -ge 2 ]; then
    success "Multiple files uploaded (count=$count)"
else
    error "Multiple files uploaded (expected >=2, got $count)"
fi

run_test "delete single file (DeleteObject)" \
    delete "$REMOTE_BUCKET/renamed-file.txt" || true

run_test "deletefile (DeleteObject specific)" \
    deletefile "$REMOTE_BUCKET/test1.txt" || true

# =============================================================================
# Test 5: Medium File (tests chunked upload path)
# =============================================================================

log ""
log "--- Medium File Transfer ---"

run_test "copy medium file (~100KB)" \
    copy "$TEMP_DIR/medium-file.bin" "$REMOTE_BUCKET/medium/" || true

# Verify integrity
set +e
rclone_cmd copy "$REMOTE_BUCKET/medium/medium-file.bin" "$TEMP_DIR/download/" 2>/dev/null
local_md5=$(md5 -q "$TEMP_DIR/medium-file.bin" 2>/dev/null || md5sum "$TEMP_DIR/medium-file.bin" | awk '{print $1}')
remote_md5=$(md5 -q "$TEMP_DIR/download/medium-file.bin" 2>/dev/null || md5sum "$TEMP_DIR/download/medium-file.bin" | awk '{print $1}')
set -e
if [ "$local_md5" = "$remote_md5" ]; then
    success "Medium file integrity (md5=$local_md5)"
else
    error "Medium file integrity (local=$local_md5 remote=$remote_md5)"
fi

# =============================================================================
# Test 6: Large File / Multipart Upload
# =============================================================================

log ""
log "--- Large File / Multipart Upload ---"

# Generate 10MB file and force multipart via --s3-upload-cutoff.
# rclone's default cutoff is ~200MB, so without this flag the 10MB file
# would be uploaded as a single PUT. Setting cutoff to 5M forces MPU.
dd if=/dev/urandom bs=1048576 count=10 2>/dev/null > "$TEMP_DIR/large-file.bin"
large_size=$(wc -c < "$TEMP_DIR/large-file.bin" | tr -d ' ')
log "  Generated large file: ${large_size} bytes (~10MB)"
log "  Forcing multipart: --s3-upload-cutoff 5M --s3-chunk-size 5M"

run_test "multipart upload (CreateMultipartUpload + UploadPart + Complete)" \
    copy "$TEMP_DIR/large-file.bin" "$REMOTE_BUCKET/large/" \
    --s3-upload-cutoff 5M --s3-chunk-size 5M -v || true

# Download and verify
set +e
rclone_cmd copy "$REMOTE_BUCKET/large/large-file.bin" "$TEMP_DIR/download/large/" \
    2>/dev/null
large_local=$(md5 -q "$TEMP_DIR/large-file.bin" 2>/dev/null || md5sum "$TEMP_DIR/large-file.bin" | awk '{print $1}')
large_remote=$(md5 -q "$TEMP_DIR/download/large/large-file.bin" 2>/dev/null || md5sum "$TEMP_DIR/download/large/large-file.bin" | awk '{print $1}')
set -e
if [ -f "$TEMP_DIR/download/large/large-file.bin" ] && [ "$large_local" = "$large_remote" ]; then
    success "Multipart upload integrity verified (md5=$large_local)"
else
    error "Multipart upload integrity (local=$large_local remote=$large_remote)"
fi

# =============================================================================
# Test 7: Sync Operations
# =============================================================================

log ""
log "--- Sync Operations ---"

SYNC_BUCKET="${REMOTE}${BUCKET}-sync"
rclone_cmd mkdir "$SYNC_BUCKET" 2>/dev/null || true

run_test "sync local->remote (initial)" \
    sync "$SYNC_SRC/" "$SYNC_BUCKET/" || true

# Verify all files synced
set +e
synced_count=$(rclone_cmd ls "$SYNC_BUCKET" 2>&1 | wc -l | tr -d ' ')
set -e
if [ "$synced_count" -ge 6 ]; then
    success "sync: all files present (count=$synced_count, expected 6)"
else
    error "sync: all files present (count=$synced_count, expected 6)"
fi

# Modify source: add a file, remove a file
echo "New file added after initial sync" > "$SYNC_SRC/file-new.txt"
rm -f "$SYNC_SRC/file-3.txt"

run_test "sync local->remote (incremental - add+delete)" \
    sync "$SYNC_SRC/" "$SYNC_BUCKET/" || true

# Verify: file-new.txt exists, file-3.txt removed
set +e
has_new=$(rclone_cmd ls "$SYNC_BUCKET/file-new.txt" 2>&1)
has_removed=$(rclone_cmd ls "$SYNC_BUCKET/file-3.txt" 2>&1)
set -e
if echo "$has_new" | grep -q "file-new.txt"; then
    success "sync: new file appeared on remote"
else
    error "sync: new file appeared on remote"
fi

if echo "$has_removed" | grep -q "file-3.txt"; then
    error "sync: deleted file removed from remote (still present)"
else
    success "sync: deleted file removed from remote"
fi

# Sync remote->local
run_test "sync remote->local" \
    sync "$SYNC_BUCKET/" "$SYNC_DST/" || true

set +e
local_count=$(find "$SYNC_DST" -type f | wc -l | tr -d ' ')
set -e
if [ "$local_count" -ge 5 ]; then
    success "sync remote->local: files downloaded (count=$local_count)"
else
    error "sync remote->local: files downloaded (count=$local_count, expected >=5)"
fi

# =============================================================================
# Test 8: Copy (directory)
# =============================================================================

log ""
log "--- Copy (directory-level) ---"

COPY_BUCKET="${REMOTE}${BUCKET}-copy"
rclone_cmd mkdir "$COPY_BUCKET" 2>/dev/null || true

run_test "copy directory local->remote" \
    copy "$SYNC_SRC/" "$COPY_BUCKET/" || true

# Copy remote->remote (server-side copy)
run_test "copy remote->remote (server-side CopyObject)" \
    copy "$COPY_BUCKET/" "${REMOTE}${BUCKET}/server-copy/" || true

# =============================================================================
# Test 9: Move Operations
# =============================================================================

log ""
log "--- Move Operations ---"

MOVE_BUCKET="${REMOTE}${BUCKET}-move-dst"
rclone_cmd mkdir "$MOVE_BUCKET" 2>/dev/null || true

# Upload a file to move
rclone_cmd copy "$TEMP_DIR/test2.txt" "${REMOTE}${BUCKET}/to-move/" 2>/dev/null || true

run_test "moveto (CopyObject + DeleteObject)" \
    moveto "${REMOTE}${BUCKET}/to-move/test2.txt" \
    "$MOVE_BUCKET/moved-file.txt" || true

# Verify source gone, destination exists
set +e
src_exists=$(rclone_cmd ls "${REMOTE}${BUCKET}/to-move/test2.txt" 2>&1)
dst_exists=$(rclone_cmd cat "$MOVE_BUCKET/moved-file.txt" 2>&1)
set -e
if ! echo "$src_exists" | grep -q "test2.txt" && [ -n "$dst_exists" ]; then
    success "moveto: source removed, destination exists"
else
    error "moveto: source removed, destination exists"
fi

# Move directory
rclone_cmd copy "$TEMP_DIR/test1.txt" "${REMOTE}${BUCKET}/move-dir/" 2>/dev/null || true
rclone_cmd copy "$TEMP_DIR/test2.txt" "${REMOTE}${BUCKET}/move-dir/" 2>/dev/null || true

run_test "move directory remote->remote" \
    move "${REMOTE}${BUCKET}/move-dir/" "$MOVE_BUCKET/moved-dir/" || true

# =============================================================================
# Test 10: Check / Verify
# =============================================================================

log ""
log "--- Check / Verify Operations ---"

# Re-sync for a clean check state
rclone_cmd sync "$SYNC_SRC/" "$SYNC_BUCKET/" 2>/dev/null || true
rclone_cmd sync "$SYNC_BUCKET/" "$SYNC_DST/" 2>/dev/null || true

run_test "check (compare local vs remote)" \
    check "$SYNC_SRC/" "$SYNC_BUCKET/" || true

# =============================================================================
# Test 11: Purge
# =============================================================================

log ""
log "--- Purge / Bulk Delete ---"

PURGE_BUCKET="${REMOTE}${BUCKET}-copy"

run_test "purge (recursive delete + rmdir)" \
    purge "$PURGE_BUCKET" || true

# Verify bucket is gone
set +e
purge_check=$(rclone_cmd lsd "$REMOTE" 2>&1)
set -e
if echo "$purge_check" | grep -q "${BUCKET}-copy"; then
    error "purge: bucket still exists after purge"
else
    success "purge: bucket removed successfully"
fi

# =============================================================================
# Test 12: about (GetBucketLocation / storage info)
# =============================================================================

log ""
log "--- Storage Info ---"

# S3 doesn't have a standard storage quota API
set +e
about_out=$(rclone_cmd about "$REMOTE" 2>&1)
about_rc=$?
set -e
if [ $about_rc -eq 0 ]; then
    success "about (storage info)"
else
    skip "about (storage info) - S3 doesn't support storage quota queries"
fi

# =============================================================================
# Test 13: tree (recursive listing)
# =============================================================================

log ""
log "--- Tree Listing ---"

run_test "tree (recursive directory listing)" \
    tree "$REMOTE_BUCKET" || true

# =============================================================================
# Test 14: Bisync
# =============================================================================

log ""
log "--- Bisync ---"

BISYNC_LOCAL="$TEMP_DIR/bisync-local"
BISYNC_REMOTE="${REMOTE}${BUCKET}/bisync"
mkdir -p "$BISYNC_LOCAL"
echo "bisync test file" > "$BISYNC_LOCAL/bisync1.txt"

# Bisync requires --resync on first run
set +e
bisync_output=$(rclone_cmd bisync "$BISYNC_LOCAL/" "$BISYNC_REMOTE/" \
    --resync 2>&1)
bisync_rc=$?
set -e
if [ $bisync_rc -eq 0 ]; then
    success "bisync --resync (initial)"
else
    # bisync often fails on non-standard S3 backends
    error "bisync --resync (initial)"
    echo "    output: $(echo "$bisync_output" | tail -3)"
fi

# =============================================================================
# Test 15: Listings with filters
# =============================================================================

log ""
log "--- Filtered Listings ---"

run_test "ls with --include filter" \
    ls "$SYNC_BUCKET" --include "*.txt" || true

run_test "ls with --max-depth 1" \
    ls "$SYNC_BUCKET" --max-depth 1 || true

run_test "lsf (machine-readable listing)" \
    lsf "$SYNC_BUCKET" || true

run_test "lsjson (JSON listing)" \
    lsjson "$SYNC_BUCKET" || true

# =============================================================================
# Test 16: touch / settier (likely unsupported)
# =============================================================================

log ""
log "--- Operations Likely Unsupported ---"

# touch (requires PutObject with metadata update)
set +e
touch_out=$(rclone_cmd touch "${REMOTE}${BUCKET}/touch-test.txt" 2>&1)
touch_rc=$?
set -e
if [ $touch_rc -eq 0 ]; then
    success "touch (create empty file)"
else
    skip "touch (create empty file) - $touch_out"
fi

# backend versioning (GetBucketVersioning)
set +e
ver_out=$(rclone_cmd backend versioning "$REMOTE_BUCKET" 2>&1)
ver_rc=$?
set -e
if [ $ver_rc -eq 0 ]; then
    success "backend versioning (GetBucketVersioning)"
else
    skip "backend versioning (GetBucketVersioning) - not supported"
fi

# =============================================================================
# Summary
# =============================================================================

log ""
log "=========================================="
log "Rclone Validation Summary"
log "=========================================="
log "Tests Passed:  $TESTS_PASSED"
log "Tests Failed:  $TESTS_FAILED"
log "Tests Skipped: $TESTS_SKIPPED"
log ""

if [ ${#PASSED_OPS[@]} -gt 0 ]; then
    log "--- Supported Operations ---"
    for op in "${PASSED_OPS[@]}"; do
        echo -e "  ${GREEN}+${NC} $op"
    done
fi

log ""

if [ ${#FAILED_OPS[@]} -gt 0 ]; then
    log "--- Unsupported / Failing Operations ---"
    for op in "${FAILED_OPS[@]}"; do
        echo -e "  ${RED}-${NC} $op"
    done
fi

if [ ${#SKIPPED_OPS[@]} -gt 0 ]; then
    log ""
    log "--- Skipped (expected unsupported) ---"
    for op in "${SKIPPED_OPS[@]}"; do
        echo -e "  ${YELLOW}~${NC} $op"
    done
fi

log ""
if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All rclone operations passed!${NC}"
else
    echo -e "${YELLOW}$TESTS_FAILED operation(s) failed — see details above.${NC}"
fi
log "=========================================="
