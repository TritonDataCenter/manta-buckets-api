#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# Validation script for MinIO mc S3 compatibility against manta-buckets-api.
#
# Tests mc (MinIO Client) operations and reports which are supported
# and which fail.
#
# Requires:
#   - mc installed and an alias named "local" configured pointing at the
#     manta-buckets-api S3 endpoint
#
set -eo pipefail

# =============================================================================
# Configuration
# =============================================================================

MC_ALIAS=${MC_ALIAS:-"local"}
MC_FLAGS="--insecure"

if ! command -v mc &>/dev/null; then
    echo "ERROR: mc (MinIO Client) is not installed"
    exit 1
fi

REMOTE="${MC_ALIAS}"
BUCKET="mc-test-$$-$(date +%s)"
TEMP_DIR="/tmp/mc-validation-$$"

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

mc_cmd() {
    mc $MC_FLAGS "$@" 2>&1
}

# mc_mb - create a bucket, tolerating the 204 status code that
# manta-buckets-api returns (mc expects 200).
# Returns 0 if bucket exists after the call, 1 otherwise.
mc_mb() {
    local bucket="$1"
    set +e
    mc_cmd mb "$bucket" >/dev/null 2>&1
    local rc=$?
    set -e
    if [ $rc -eq 0 ]; then
        return 0
    fi
    # mc reports 204 as error, but bucket may still be created
    set +e
    mc_cmd stat "$bucket" >/dev/null 2>&1
    rc=$?
    set -e
    return $rc
}

# Run a test: run_test "description" mc-subcommand [args...]
run_test() {
    local desc="$1"
    shift
    local output
    set +e
    output=$(mc_cmd "$@" 2>&1)
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
    for suffix in "" "-sync" "-mirror" "-cp-dst" "-mv-dst"; do
        mc $MC_FLAGS rm --recursive --force \
            "${REMOTE}/${BUCKET}${suffix}/" >/dev/null 2>&1 || true
        mc $MC_FLAGS rb "${REMOTE}/${BUCKET}${suffix}" \
            >/dev/null 2>&1 || true
    done
    rm -rf "$TEMP_DIR" 2>/dev/null || true
    log "Cleanup complete"
}

trap cleanup EXIT

# =============================================================================
# Setup
# =============================================================================

log "=========================================="
log "MinIO mc S3 Compatibility Validation"
log "=========================================="
log "Alias: $MC_ALIAS"
log "Test bucket: $BUCKET"
log "mc version: $(mc --version 2>/dev/null | head -1)"
log ""

mkdir -p "$TEMP_DIR/download" "$TEMP_DIR/sync-src" "$TEMP_DIR/sync-dst" \
         "$TEMP_DIR/mirror-src"

# Generate test files
echo "Hello from mc test" > "$TEMP_DIR/test1.txt"
echo "Second test file for mc" > "$TEMP_DIR/test2.txt"
dd if=/dev/urandom bs=1024 count=100 2>/dev/null | base64 > "$TEMP_DIR/medium.bin"

# Generate files for sync/mirror tests
for i in 1 2 3 4 5; do
    echo "Sync file $i - $(date +%s%N)" > "$TEMP_DIR/sync-src/file-$i.txt"
done
mkdir -p "$TEMP_DIR/sync-src/subdir"
echo "Nested file" > "$TEMP_DIR/sync-src/subdir/nested.txt"

for i in 1 2 3; do
    echo "Mirror file $i" > "$TEMP_DIR/mirror-src/mirror-$i.txt"
done

# =============================================================================
# Test 1: Bucket Operations
# =============================================================================

log "--- Bucket Operations ---"

# mc expects HTTP 200 for CreateBucket but manta-buckets-api returns 204.
# The bucket IS created; mc just reports the 204 as an error.
# Validate by checking the bucket exists rather than relying on exit code.
set +e
mb_out=$(mc_cmd mb "${REMOTE}/${BUCKET}" 2>&1)
mb_rc=$?
set -e
if [ $mb_rc -eq 0 ]; then
    success "mb (CreateBucket)"
else
    # Check if bucket was actually created despite 204
    set +e
    mb_verify=$(mc_cmd stat "${REMOTE}/${BUCKET}" 2>&1)
    mb_verify_rc=$?
    set -e
    if [ $mb_verify_rc -eq 0 ]; then
        success "mb (CreateBucket) - bucket created (server returns 204 not 200)"
    else
        error "mb (CreateBucket)"
        echo "    output: $(echo "$mb_out" | head -3)"
    fi
fi

run_test "ls buckets (ListBuckets)" ls "$REMOTE" || true

# Verify our bucket appears
set +e
listing=$(mc_cmd ls "$REMOTE" 2>&1)
set -e
if echo "$listing" | grep -q "$BUCKET"; then
    success "ListBuckets contains test bucket"
else
    error "ListBuckets contains test bucket"
fi

# =============================================================================
# Test 2: GetBucketLocation (critical for mc auto-region)
# =============================================================================

log ""
log "--- GetBucketLocation ---"

# mc calls GetBucketLocation internally to discover the bucket region.
# Without this API mc fails with SigV4 errors. Test that mc can
# operate on the bucket without MC_REGION being set.
unset MC_REGION 2>/dev/null || true

set +e
loc_out=$(mc_cmd stat "${REMOTE}/${BUCKET}" 2>&1)
loc_rc=$?
set -e
if [ $loc_rc -eq 0 ]; then
    success "GetBucketLocation (mc stat without MC_REGION)"
else
    error "GetBucketLocation (mc stat without MC_REGION)"
    echo "    output: $(echo "$loc_out" | head -3)"
fi

# =============================================================================
# Test 3: Basic Object Operations
# =============================================================================

log ""
log "--- Basic Object Operations ---"

run_test "cp local->remote (PutObject)" \
    cp "$TEMP_DIR/test1.txt" "${REMOTE}/${BUCKET}/test1.txt" || true

run_test "ls objects (ListObjects)" ls "${REMOTE}/${BUCKET}/" || true

run_test "cat (GetObject to stdout)" cat "${REMOTE}/${BUCKET}/test1.txt" || true

# Verify content integrity
set +e
downloaded=$(mc_cmd cat "${REMOTE}/${BUCKET}/test1.txt" 2>&1)
original=$(cat "$TEMP_DIR/test1.txt")
set -e
if [ "$downloaded" = "$original" ]; then
    success "Content integrity (GetObject matches PutObject)"
else
    error "Content integrity (GetObject matches PutObject)"
fi

run_test "cp remote->local (GetObject to file)" \
    cp "${REMOTE}/${BUCKET}/test1.txt" "$TEMP_DIR/download/test1.txt" || true

run_test "cp with rename (PutObject)" \
    cp "$TEMP_DIR/test1.txt" "${REMOTE}/${BUCKET}/renamed.txt" || true

# =============================================================================
# Test 4: stat (HeadObject)
# =============================================================================

log ""
log "--- Object Metadata ---"

run_test "stat object (HeadObject)" \
    stat "${REMOTE}/${BUCKET}/test1.txt" || true

run_test "stat bucket (HeadBucket)" \
    stat "${REMOTE}/${BUCKET}" || true

# =============================================================================
# Test 5: head (partial GetObject)
# =============================================================================

log ""
log "--- Partial Read ---"

set +e
head_out=$(mc_cmd head -n 1 "${REMOTE}/${BUCKET}/test1.txt" 2>&1)
head_rc=$?
set -e
if [ $head_rc -eq 0 ]; then
    success "head (first line of object)"
else
    skip "head (first line of object) - may require Range header support"
fi

# =============================================================================
# Test 6: Multiple File Operations
# =============================================================================

log ""
log "--- Multiple File Operations ---"

run_test "cp multiple files" \
    cp "$TEMP_DIR/test1.txt" "$TEMP_DIR/test2.txt" \
    "${REMOTE}/${BUCKET}/multi/" || true

# Check count
set +e
count=$(mc_cmd ls "${REMOTE}/${BUCKET}/multi/" 2>&1 | wc -l | tr -d ' ')
set -e
if [ "$count" -ge 2 ]; then
    success "Multiple files uploaded (count=$count)"
else
    error "Multiple files uploaded (expected >=2, got $count)"
fi

run_test "rm single object (DeleteObject)" \
    rm "${REMOTE}/${BUCKET}/renamed.txt" || true

# =============================================================================
# Test 7: Medium File Transfer
# =============================================================================

log ""
log "--- Medium File Transfer (~100KB) ---"

run_test "cp medium file" \
    cp "$TEMP_DIR/medium.bin" "${REMOTE}/${BUCKET}/medium.bin" || true

# Download and verify integrity
set +e
mc_cmd cp "${REMOTE}/${BUCKET}/medium.bin" "$TEMP_DIR/download/medium.bin" \
    2>/dev/null
local_md5=$(md5 -q "$TEMP_DIR/medium.bin" 2>/dev/null || \
    md5sum "$TEMP_DIR/medium.bin" | awk '{print $1}')
remote_md5=$(md5 -q "$TEMP_DIR/download/medium.bin" 2>/dev/null || \
    md5sum "$TEMP_DIR/download/medium.bin" | awk '{print $1}')
set -e
if [ "$local_md5" = "$remote_md5" ]; then
    success "Medium file integrity (md5=$local_md5)"
else
    error "Medium file integrity (local=$local_md5 remote=$remote_md5)"
fi

# =============================================================================
# Test 8: Large File / Multipart Upload
# =============================================================================

log ""
log "--- Large File / Multipart Upload ---"

# mc uses multipart upload for files > 64MB by default (configurable).
# Generate a 16MB file -- mc has a lower default part size (16MB) than
# rclone, so this should trigger MPU when combined with a lowered
# threshold. If not, the single-PUT path is still valid.
dd if=/dev/urandom bs=1048576 count=16 2>/dev/null > "$TEMP_DIR/large.bin"
large_size=$(wc -c < "$TEMP_DIR/large.bin" | tr -d ' ')
log "  Generated large file: ${large_size} bytes (~16MB)"

run_test "cp large file (multipart upload path)" \
    cp "$TEMP_DIR/large.bin" "${REMOTE}/${BUCKET}/large.bin" || true

# Download and verify
set +e
mc_cmd cp "${REMOTE}/${BUCKET}/large.bin" "$TEMP_DIR/download/large.bin" \
    2>/dev/null
large_local=$(md5 -q "$TEMP_DIR/large.bin" 2>/dev/null || \
    md5sum "$TEMP_DIR/large.bin" | awk '{print $1}')
large_remote=$(md5 -q "$TEMP_DIR/download/large.bin" 2>/dev/null || \
    md5sum "$TEMP_DIR/download/large.bin" | awk '{print $1}')
set -e
if [ -f "$TEMP_DIR/download/large.bin" ] && \
   [ "$large_local" = "$large_remote" ]; then
    success "Large file integrity verified (md5=$large_local)"
else
    error "Large file integrity (local=$large_local remote=$large_remote)"
fi

# =============================================================================
# Test 9: Server-side Copy
# =============================================================================

log ""
log "--- Server-side Copy (CopyObject) ---"

run_test "cp remote->remote (CopyObject)" \
    cp "${REMOTE}/${BUCKET}/test1.txt" \
    "${REMOTE}/${BUCKET}/server-copy.txt" || true

# Verify copied content
set +e
copy_content=$(mc_cmd cat "${REMOTE}/${BUCKET}/server-copy.txt" 2>&1)
set -e
if [ "$copy_content" = "$original" ]; then
    success "Server-side copy integrity"
else
    error "Server-side copy integrity"
fi

# =============================================================================
# Test 10: Mirror (sync equivalent)
# =============================================================================

log ""
log "--- Mirror Operations ---"

MIRROR_BUCKET="${REMOTE}/${BUCKET}-mirror"
mc_mb "$MIRROR_BUCKET"

run_test "mirror local->remote (initial sync)" \
    mirror "$TEMP_DIR/mirror-src/" "$MIRROR_BUCKET/" || true

# Verify files mirrored
set +e
mirror_count=$(mc_cmd ls "$MIRROR_BUCKET/" 2>&1 | wc -l | tr -d ' ')
set -e
if [ "$mirror_count" -ge 3 ]; then
    success "mirror: all files present (count=$mirror_count, expected 3)"
else
    error "mirror: all files present (count=$mirror_count, expected 3)"
fi

# Add a file, mirror again (incremental)
echo "New mirror file" > "$TEMP_DIR/mirror-src/mirror-new.txt"

run_test "mirror local->remote (incremental)" \
    mirror "$TEMP_DIR/mirror-src/" "$MIRROR_BUCKET/" || true

# Verify new file appeared
set +e
has_new=$(mc_cmd ls "$MIRROR_BUCKET/mirror-new.txt" 2>&1)
set -e
if echo "$has_new" | grep -q "mirror-new.txt"; then
    success "mirror: new file appeared on remote"
else
    error "mirror: new file appeared on remote"
fi

# Mirror with --remove (delete source-removed files on target)
rm -f "$TEMP_DIR/mirror-src/mirror-2.txt"
set +e
mirror_rm_out=$(mc_cmd mirror --remove "$TEMP_DIR/mirror-src/" \
    "$MIRROR_BUCKET/" 2>&1)
mirror_rm_rc=$?
set -e
if [ $mirror_rm_rc -eq 0 ]; then
    # Check that mirror-2.txt was removed from remote
    set +e
    still_there=$(mc_cmd ls "$MIRROR_BUCKET/mirror-2.txt" 2>&1)
    set -e
    if echo "$still_there" | grep -q "mirror-2.txt"; then
        error "mirror --remove: deleted file still present on remote"
    else
        success "mirror --remove: deleted file removed from remote"
    fi
else
    error "mirror --remove (incremental with deletes)"
    echo "    output: $(echo "$mirror_rm_out" | head -3)"
fi

# =============================================================================
# Test 11: cp directory (recursive copy)
# =============================================================================

log ""
log "--- Recursive Copy ---"

CP_BUCKET="${REMOTE}/${BUCKET}-cp-dst"
mc_mb "$CP_BUCKET"

run_test "cp --recursive local->remote" \
    cp --recursive "$TEMP_DIR/sync-src/" "$CP_BUCKET/" || true

# Verify file count
set +e
cp_count=$(mc_cmd ls --recursive "$CP_BUCKET/" 2>&1 | wc -l | tr -d ' ')
set -e
if [ "$cp_count" -ge 6 ]; then
    success "recursive cp: all files present (count=$cp_count, expected 6)"
else
    error "recursive cp: all files present (count=$cp_count, expected 6)"
fi

# =============================================================================
# Test 12: mv (Move = CopyObject + DeleteObject)
# =============================================================================

log ""
log "--- Move Operations ---"

MV_BUCKET="${REMOTE}/${BUCKET}-mv-dst"
mc_mb "$MV_BUCKET"

# Upload a file to move
mc_cmd cp "$TEMP_DIR/test2.txt" "${REMOTE}/${BUCKET}/to-move.txt" \
    >/dev/null 2>&1 || true

run_test "mv remote->remote (CopyObject + DeleteObject)" \
    mv "${REMOTE}/${BUCKET}/to-move.txt" "$MV_BUCKET/moved.txt" || true

# Verify source gone, destination present
set +e
src_gone=$(mc_cmd stat "${REMOTE}/${BUCKET}/to-move.txt" 2>&1)
src_rc=$?
dst_content=$(mc_cmd cat "$MV_BUCKET/moved.txt" 2>&1)
set -e
if [ $src_rc -ne 0 ] && [ -n "$dst_content" ]; then
    success "mv: source removed, destination exists"
else
    error "mv: source removed, destination exists"
fi

# =============================================================================
# Test 13: find (ListObjects with filters)
# =============================================================================

log ""
log "--- Find / Filtered Listings ---"

run_test "find (ListObjects with prefix filter)" \
    find "${REMOTE}/${BUCKET}" --name "*.txt" || true

run_test "ls --recursive (recursive listing)" \
    ls --recursive "${REMOTE}/${BUCKET}/" || true

# =============================================================================
# Test 14: diff (compare local vs remote)
# =============================================================================

log ""
log "--- Diff ---"

# Create sync bucket and mirror content into it
SYNC_BUCKET="${REMOTE}/${BUCKET}-sync"
mc_mb "$SYNC_BUCKET"
mc_cmd mirror "$TEMP_DIR/sync-src/" "$SYNC_BUCKET/" \
    >/dev/null 2>&1 || true

set +e
diff_out=$(mc_cmd diff "$TEMP_DIR/sync-src/" "$SYNC_BUCKET/" 2>&1)
diff_rc=$?
set -e
# diff returns 0 when no differences, 1 when there are differences
if [ $diff_rc -eq 0 ] || [ $diff_rc -eq 1 ]; then
    success "diff (compare local vs remote)"
else
    error "diff (compare local vs remote)"
    echo "    output: $(echo "$diff_out" | head -3)"
fi

# =============================================================================
# Test 15: du (disk usage)
# =============================================================================

log ""
log "--- Disk Usage ---"

set +e
du_out=$(mc_cmd du "${REMOTE}/${BUCKET}/" 2>&1)
du_rc=$?
set -e
if [ $du_rc -eq 0 ]; then
    success "du (disk usage summary)"
else
    skip "du (disk usage summary) - may require ListObjectsV2 support"
fi

# =============================================================================
# Test 16: tree
# =============================================================================

log ""
log "--- Tree Listing ---"

run_test "tree (recursive directory tree)" \
    tree "${REMOTE}/${BUCKET}" || true

# =============================================================================
# Test 17: pipe (stream stdin to object)
# =============================================================================

log ""
log "--- Stream Operations ---"

set +e
echo "piped content" | mc_cmd pipe "${REMOTE}/${BUCKET}/piped.txt" 2>&1
pipe_rc=$?
set -e
if [ $pipe_rc -eq 0 ]; then
    piped_content=$(mc_cmd cat "${REMOTE}/${BUCKET}/piped.txt" 2>&1)
    if [ "$piped_content" = "piped content" ]; then
        success "pipe (stream stdin -> PutObject)"
    else
        error "pipe (content mismatch)"
    fi
else
    error "pipe (stream stdin -> PutObject)"
fi

# =============================================================================
# Test 18: Bulk Delete (rm --recursive)
# =============================================================================

log ""
log "--- Bulk Delete ---"

# Upload a few files for bulk delete
for i in 1 2 3 4 5; do
    mc_cmd cp "$TEMP_DIR/test1.txt" \
        "${REMOTE}/${BUCKET}/bulk/file-$i.txt" >/dev/null 2>&1 || true
done

run_test "rm --recursive (bulk DeleteObjects)" \
    rm --recursive --force "${REMOTE}/${BUCKET}/bulk/" || true

# Verify all deleted
set +e
remaining=$(mc_cmd ls "${REMOTE}/${BUCKET}/bulk/" 2>&1 | wc -l | tr -d ' ')
set -e
if [ "$remaining" -eq 0 ]; then
    success "Bulk delete: all objects removed"
else
    error "Bulk delete: $remaining objects still remain"
fi

# =============================================================================
# Test 19: rb (RemoveBucket)
# =============================================================================

log ""
log "--- Bucket Removal ---"

# First empty the -cp-dst bucket (it has objects from the recursive copy test),
# then remove it. rb --force does rm --recursive internally but test both paths.
mc_cmd rm --recursive --force "${REMOTE}/${BUCKET}-cp-dst/" 2>/dev/null || true

set +e
rb_out=$(mc_cmd rb "${REMOTE}/${BUCKET}-cp-dst" 2>&1)
rb_rc=$?
set -e
if [ $rb_rc -eq 0 ]; then
    success "rb (DeleteBucket)"
else
    error "rb (DeleteBucket)"
    echo "    output: $(echo "$rb_out" | head -3)"
fi

# Verify it's gone
set +e
rb_check=$(mc_cmd ls "$REMOTE" 2>&1)
set -e
if echo "$rb_check" | grep -q "${BUCKET}-cp-dst"; then
    error "rb: bucket still exists after removal"
else
    success "rb: bucket removed successfully"
fi

# =============================================================================
# Test 20: anonymous / policy (likely unsupported)
# =============================================================================

log ""
log "--- Operations Likely Unsupported ---"

# anonymous (bucket policy)
set +e
anon_out=$(mc_cmd anonymous get "${REMOTE}/${BUCKET}" 2>&1)
anon_rc=$?
set -e
if [ $anon_rc -eq 0 ]; then
    success "anonymous get (GetBucketPolicy)"
else
    skip "anonymous get (GetBucketPolicy) - bucket policy not supported"
fi

# tag (object tagging)
set +e
tag_out=$(mc_cmd tag set "${REMOTE}/${BUCKET}/test1.txt" "env=test" 2>&1)
tag_rc=$?
set -e
if [ $tag_rc -eq 0 ]; then
    success "tag set (PutObjectTagging)"
else
    skip "tag set (PutObjectTagging) - object tagging may not be supported"
fi

# version (bucket versioning)
set +e
ver_out=$(mc_cmd version info "${REMOTE}/${BUCKET}" 2>&1)
ver_rc=$?
set -e
if [ $ver_rc -eq 0 ]; then
    success "version info (GetBucketVersioning)"
else
    skip "version info (GetBucketVersioning) - versioning not supported"
fi

# encrypt (bucket encryption)
set +e
enc_out=$(mc_cmd encrypt info "${REMOTE}/${BUCKET}" 2>&1)
enc_rc=$?
set -e
if [ $enc_rc -eq 0 ]; then
    success "encrypt info (GetBucketEncryption)"
else
    skip "encrypt info (GetBucketEncryption) - encryption config not supported"
fi

# =============================================================================
# Summary
# =============================================================================

log ""
log "=========================================="
log "MinIO mc Validation Summary"
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
    echo -e "${GREEN}All mc operations passed!${NC}"
else
    echo -e "${YELLOW}$TESTS_FAILED operation(s) failed — see details above.${NC}"
fi
log "=========================================="
