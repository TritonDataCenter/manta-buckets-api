#!/bin/bash
# Copyright 2026 Edgecast Cloud LLC.
# S3 Compatibility Test - Multipart Upload Operations
#
# Tests S3 multipart upload functionality:
# - Basic multipart upload workflow
# - Resume interrupted uploads
# - Error handling and validation

set -eo pipefail

# Source common infrastructure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/s3-test-common.sh"

# =============================================================================
# Test Functions
# =============================================================================

test_multipart_upload_basic() {
    log "Testing: Basic Multipart Upload"
    
    local mpu_bucket="mpu-test-$(date +%s)"
    local mpu_object="large-test-file.bin"
    local part_size=8388608  # 8MB - ensures parts stay above 5MB minimum even with aws-chunked
    local total_size=16777216  # 16MB (exactly 2 parts: 8MB + 8MB final)
    
    # Create test bucket
    set +e
    aws_s3api create-bucket --bucket "$mpu_bucket" 2>/dev/null
    local create_exit_code=$?
    set -e
    
    if [ $create_exit_code -ne 0 ]; then
        error "MPU basic test - Failed to create test bucket"
        return 1
    fi
    
    # Create a large test file
    log "  Creating $total_size byte test file..."
    dd if=/dev/urandom of="$mpu_object" bs=1024 count=$((total_size / 1024)) 2>/dev/null
    local original_md5=$(md5sum "$mpu_object" | cut -d' ' -f1)
    
    # Initiate multipart upload
    set +e
    initiate_result=$(aws_s3api create-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" 2>&1)
    local initiate_exit_code=$?
    set -e
    
    if [ $initiate_exit_code -ne 0 ]; then
        error "MPU basic test - Failed to initiate multipart upload: $initiate_result"
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    local upload_id=$(echo "$initiate_result" | jq -r '.UploadId // empty')
    log "  Upload ID: $upload_id"
    
    if [ -z "$upload_id" ]; then
        error "MPU basic test - Failed to extract upload ID from response"
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    # Upload parts - boto3 approach: use server-reported sizes for everything
    local part_number=1
    local uploaded_parts=()
    local bytes_uploaded=0  # Track server-reported total size (authoritative)
    local file_offset=0     # Track position in original file
    
    # Upload parts until file is fully consumed (aws-chunked may compress data)
    while [ $file_offset -lt $total_size ]; do
        local file_remaining=$((total_size - file_offset))
        # Use standard part size, or remaining file data for final part
        local current_part_size=$part_size
        if [ $file_remaining -lt $current_part_size ]; then
            current_part_size=$file_remaining
        fi
        
        # Safety check: if no file data remaining, stop immediately
        if [ $current_part_size -le 0 ]; then
            log "  DEBUG: No more file data to upload (current_part_size=$current_part_size), stopping"
            break
        fi
        
        log "  Uploading part $part_number ($current_part_size bytes from file)..."
        log "  DEBUG: file_offset=$file_offset, bytes_uploaded=$bytes_uploaded, file_remaining=$file_remaining"
        
        # Extract part from original file using file_offset
        local part_file="part$part_number.bin"
        dd if="$mpu_object" of="$part_file" bs=1 skip=$file_offset count=$current_part_size 2>/dev/null
        
        local actual_part_size=$(wc -c < "$part_file")
        log "  DEBUG: Created part file size: $actual_part_size bytes"
        
        set +e
        # AWS CLI upload-part doesn't output anything by default, so we need to capture the ETag differently
        part_result=$(aws_s3api upload-part --bucket "$mpu_bucket" --key "$mpu_object" --part-number $part_number --upload-id "$upload_id" --body "$part_file" 2>&1)
        local part_exit_code=$?
        set -e
        
        # If the command succeeded but returned no output, that's normal for upload-part
        if [ $part_exit_code -eq 0 ] && [ -z "$part_result" ]; then
            log "  Part $part_number uploaded successfully (no output is normal for upload-part)"
        fi
        
        if [ $part_exit_code -ne 0 ]; then
            error "MPU basic test - Failed to upload part $part_number: $part_result"
            aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
            aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
            return 1
        fi
        
        # AWS CLI upload-part doesn't return ETag in output, so we need to get it via list-parts
        # This is actually more realistic as it's what real MPU clients do
        log "  Getting ETag via list-parts (upload-part doesn't output ETags)..."
        
        set +e
        list_result=$(aws_s3api list-parts --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" --part-number-marker $((part_number - 1)) --max-parts 1 2>&1)
        local list_exit_code=$?
        set -e
        
        if [ $list_exit_code -eq 0 ]; then
            echo "=== DEBUG: list-parts response for part $part_number ==="
            echo "$list_result"
            echo "=== END DEBUG ==="
            
            # Extract ETag and Size for specific part using json tool
            part_etag=$(echo "$list_result" | json Parts | json -a -c "this.PartNumber === $part_number" ETag)
            part_size=$(echo "$list_result" | json Parts | json -a -c "this.PartNumber === $part_number" Size)
            echo "DEBUG: part $part_number json tool result: ETag='$part_etag', Size='$part_size'"
        else
            echo "DEBUG: list-parts failed with exit code $list_exit_code"
            echo "DEBUG: list-parts error: $list_result"
            log "  Warning: list-parts failed, using placeholder ETag and calculated size"
            part_etag="placeholder-etag-$part_number"
            part_size=""  # Initialize part_size when list-parts fails
        fi
        
        log "  Part $part_number ETag: '$part_etag'"
        
        # Safety check for empty ETag
        if [ -z "$part_etag" ]; then
            error "MPU basic test - Failed to extract ETag for part $part_number from response: $part_result"
            aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
            aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
            return 1
        fi
        
        # IMPORTANT: The ETag from list-parts is the content MD5, but manta-buckets-api
        # stores object UUIDs. We need to get the stored object IDs for completion.
        # For now, we'll work with the list-parts ETags and handle any validation
        # differences on the server side.
        log "  Part $part_number: Using list-parts ETag '$part_etag' (content MD5 format)"
        
        uploaded_parts+=("ETag=$part_etag,PartNumber=$part_number,Size=$part_size")
        
        # CRITICAL: Always use server-reported size from ListParts API
        # This is the only correct approach for S3 MPU - server is source of truth
        #
        # NOTE: AWS CLI uses 'Content-Encoding: aws-chunked' which adds encoding overhead
        # to the data stream. The client sends 8MB (data + chunked metadata) but the 
        # server stores only the actual decoded data (~6-7MB). This size discrepancy causes
        # v2 commit failures if clients calculate based on what they sent rather than
        # what was actually stored. boto3-resume-mpu.py works because it always uses
        # ListParts sizes. This is the correct S3-compatible behavior.
        echo "DEBUG: Basic MPU Part $part_number - file size: $current_part_size, server size: '$part_size'"
        if [ -n "$part_size" ] && [ "$part_size" -gt 0 ] 2>/dev/null; then
            bytes_uploaded=$((bytes_uploaded + part_size))
            echo "DEBUG: Using server-reported size $part_size (from ListParts) - this is correct S3 behavior"
            echo "DEBUG: Server total: $bytes_uploaded, File offset will be: $((file_offset + current_part_size))"
        else
            # Fallback only if ListParts failed completely
            bytes_uploaded=$((bytes_uploaded + current_part_size))
            echo "WARNING: Server size unavailable, falling back to calculated size $current_part_size"
            echo "WARNING: This may cause completion failures due to size mismatches"
        fi
        
        # Always advance file offset by the actual bytes read from file
        file_offset=$((file_offset + current_part_size))
        part_number=$((part_number + 1))
        rm -f "$part_file"
    done
    
    log "  DEBUG: Upload loop completed - original file size=$total_size, server reported total=$bytes_uploaded"
    log "  DEBUG: File offset reached: $file_offset, Parts created: $((part_number - 1))"
    success "MPU basic test - Uploaded $((part_number - 1)) parts successfully"
    
    # Complete multipart upload
    local parts_json="{"
    parts_json+="\"Parts\": ["
    for i in "${!uploaded_parts[@]}"; do
        if [ $i -gt 0 ]; then
            parts_json+=","
        fi
        local part_info="${uploaded_parts[$i]}"
        local etag=$(echo "$part_info" | cut -d',' -f1 | cut -d'=' -f2)
        local part_num=$(echo "$part_info" | cut -d',' -f2 | cut -d'=' -f2)
        local part_size=$(echo "$part_info" | cut -d',' -f3 | cut -d'=' -f2)
        # Ensure ETag is properly quoted - remove any existing quotes first
        etag=$(echo "$etag" | sed 's/^"//;s/"$//')
        if [ -n "$etag" ]; then
            etag="\"$etag\""
        else
            etag='""'
        fi
        parts_json+="{\"ETag\": $etag, \"PartNumber\": $part_num}"
    done
    parts_json+="]}"
    
    log "  Generated JSON: $parts_json"
    echo "$parts_json" > multipart-complete.json
    
    # Debug: Show the exact JSON being sent to complete-multipart-upload
    log "  DEBUG: JSON content being sent to complete-multipart-upload:"
    cat multipart-complete.json
    log "  DEBUG: Number of parts in JSON: $(echo "$parts_json" | jq '.Parts | length' 2>/dev/null || echo 'jq-failed')"
    
    set +e
    complete_result=$(aws_s3api complete-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" --multipart-upload file://multipart-complete.json 2>&1)
    local complete_exit_code=$?
    set -e
    
    if [ $complete_exit_code -ne 0 ]; then
        error "MPU basic test - Failed to complete multipart upload: $complete_result"
        aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    success "MPU basic test - Multipart upload completed successfully"
    
    # Verify the uploaded object
    local downloaded_file="downloaded-$mpu_object"
    set +e
    aws_s3api get-object --bucket "$mpu_bucket" --key "$mpu_object" "$downloaded_file" 2>/dev/null
    local download_exit_code=$?
    set -e
    
    if [ $download_exit_code -eq 0 ] && [ -f "$downloaded_file" ]; then
        local downloaded_md5=$(md5sum "$downloaded_file" | cut -d' ' -f1)
        if [ "$original_md5" = "$downloaded_md5" ]; then
            success "MPU basic test - Downloaded file MD5 matches original ($original_md5)"
        else
            error "MPU basic test - Downloaded file MD5 mismatch! Original: $original_md5, Downloaded: $downloaded_md5"
        fi
        
        local original_size=$(wc -c < "$mpu_object")
        local downloaded_size=$(wc -c < "$downloaded_file")
        if [ "$original_size" = "$downloaded_size" ]; then
            success "MPU basic test - Downloaded file size matches original ($original_size bytes)"
        else
            error "MPU basic test - Downloaded file size mismatch! Original: $original_size, Downloaded: $downloaded_size"
        fi
    else
        error "MPU basic test - Failed to download completed multipart upload"
    fi
    
    # Cleanup
    set +e
    aws_s3api delete-object --bucket "$mpu_bucket" --key "$mpu_object" 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
    rm -f "$mpu_object" "$downloaded_file" multipart-complete.json
    set -e
}

test_multipart_upload_resume() {
    log "Testing: Multipart Upload Resume"
    
    local mpu_bucket="mpu-resume-test-$(date +%s)"
    local mpu_object="resume-test-file.bin"
    local part_size=6291456  # 6MB (above minimum part size)
    local total_size=15728640  # 15MB (exactly 2.5 parts)
    
    # Create test bucket
    set +e
    aws_s3api create-bucket --bucket "$mpu_bucket" 2>/dev/null
    local create_exit_code=$?
    set -e
    
    if [ $create_exit_code -ne 0 ]; then
        error "MPU resume test - Failed to create test bucket"
        return 1
    fi
    
    # Create a test file
    log "  Creating $total_size byte test file..."
    dd if=/dev/urandom of="$mpu_object" bs=1024 count=$((total_size / 1024)) 2>/dev/null
    local original_md5=$(md5sum "$mpu_object" | cut -d' ' -f1)
    
    # Initiate multipart upload
    set +e
    initiate_result=$(aws_s3api create-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" 2>&1)
    local initiate_exit_code=$?
    set -e
    
    if [ $initiate_exit_code -ne 0 ]; then
        error "MPU resume test - Failed to initiate multipart upload: $initiate_result"
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    local upload_id=$(echo "$initiate_result" | jq -r '.UploadId // empty')
    log "  Upload ID: $upload_id"
    
    # Upload first part only
    log "  Uploading part 1..."
    local part1_file="part1.bin"
    dd if="$mpu_object" of="$part1_file" bs=1 count=$part_size 2>/dev/null
    
    set +e
    part1_result=$(aws_s3api upload-part --bucket "$mpu_bucket" --key "$mpu_object" --part-number 1 --upload-id "$upload_id" --body "$part1_file" 2>&1)
    local part1_exit_code=$?
    set -e
    
    if [ $part1_exit_code -ne 0 ]; then
        error "MPU resume test - Failed to upload part 1: $part1_result"
        aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    # Get ETag via list-parts since upload-part doesn't output ETags
    log "  Getting part 1 ETag via list-parts..."
    
    set +e
    list_result=$(aws_s3api list-parts --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" --max-parts 1 2>&1)
    local list_exit_code=$?
    set -e
    
    if [ $list_exit_code -eq 0 ]; then
        echo "=== DEBUG: list-parts response for part 1 (resume test) ==="
        echo "$list_result"
        echo "=== END DEBUG ==="
        
        # Extract ETag and Size from list-parts response - simplified robust approach
        # Try the most straightforward jq approach first
        part1_etag=$(echo "$list_result" | jq -r '.Parts[0].ETag' 2>/dev/null)
        part1_size=$(echo "$list_result" | jq -r '.Parts[0].Size' 2>/dev/null)
        echo "DEBUG: part1 jq direct array access result: ETag='$part1_etag', Size='$part1_size'"
        
        # If jq fails completely, use a robust sed approach that handles escaped quotes
        if [ -z "$part1_etag" ] || [ "$part1_etag" = "null" ]; then
            # Extract the full ETag value including any escaped quotes
            part1_etag=$(echo "$list_result" | sed -n 's/.*"ETag": *"\(.*\)".*/\1/p' | head -1)
            # Remove escaped quotes from the ETag value
            part1_etag=$(echo "$part1_etag" | sed 's/\\\"//g')
            echo "DEBUG: part1 sed extraction result: '$part1_etag'"
        fi
        
        # If sed fails, try jq as a fallback
        if [ -z "$part1_etag" ]; then
            part1_etag=$(echo "$list_result" | jq -r '.Parts[0].ETag // empty')
            echo "DEBUG: part1 jq fallback extraction result: '$part1_etag'"
        fi
    else
        echo "DEBUG: part1 list-parts failed with exit code $list_exit_code"
        echo "DEBUG: part1 list-parts error: $list_result"
        log "  Warning: list-parts failed, using placeholder ETag"
        part1_etag="placeholder-etag-1"
    fi
    
    log "  Part 1 uploaded with ETag: '$part1_etag'"
    
    # Safety check for empty ETag
    if [ -z "$part1_etag" ] || [ "$part1_etag" = "null" ]; then
        error "MPU resume test - Failed to extract ETag for part 1 from response. List result: $list_result"
        aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    # Simulate interruption - now "resume" by listing existing parts
    log "  Simulating interruption and resuming..."
    
    set +e
    list_parts_result=$(aws_s3api list-parts --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>&1)
    local list_exit_code=$?
    set -e
    
    if [ $list_exit_code -ne 0 ]; then
        error "MPU resume test - Failed to list existing parts: $list_parts_result"
        aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    # Verify part 1 is listed
    if echo "$list_parts_result" | jq -e '.Parts[]? | select(.PartNumber == 1)' >/dev/null 2>&1; then
        success "MPU resume test - ListParts correctly shows existing part 1"
    else
        error "MPU resume test - ListParts does not show existing part 1"
        echo "ListParts response: $list_parts_result"
    fi
    
    # Verify ListParts returns size information
    if echo "$list_parts_result" | jq -e '.Parts[]?.Size' >/dev/null 2>&1; then
        success "MPU resume test - ListParts includes part size information"
    else
        error "MPU resume test - ListParts missing size information (required for resume)"
    fi
    
    # Continue with remaining parts - separate file position from server totals
    local bytes_uploaded=$part1_size  # Server-reported total (for tracking completion)
    local file_offset=$part_size      # File position (for dd operations)
    local part_number=2
    local uploaded_parts=("ETag=$part1_etag,PartNumber=1,Size=$part1_size")
    
    while [ $file_offset -lt $total_size ]; do
        local file_remaining=$((total_size - file_offset))
        # Use standard part size, or remaining file data for final part
        local current_part_size=$part_size
        if [ $file_remaining -lt $current_part_size ]; then
            current_part_size=$file_remaining
        fi
        
        # Safety check: if no file data remaining, stop immediately
        if [ $current_part_size -le 0 ]; then
            log "  DEBUG: No more file data to upload (current_part_size=$current_part_size), stopping resume"
            break
        fi
        
        log "  Uploading part $part_number ($current_part_size bytes)..."
        log "  DEBUG: file_offset=$file_offset, bytes_uploaded=$bytes_uploaded, file_remaining=$file_remaining"
        
        local part_file="part$part_number.bin"
        dd if="$mpu_object" of="$part_file" bs=1 skip=$file_offset count=$current_part_size 2>/dev/null
        
        set +e
        part_result=$(aws_s3api upload-part --bucket "$mpu_bucket" --key "$mpu_object" --part-number $part_number --upload-id "$upload_id" --body "$part_file" 2>&1)
        local part_exit_code=$?
        set -e
        
        if [ $part_exit_code -ne 0 ]; then
            error "MPU resume test - Failed to upload part $part_number: $part_result"
            aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
            aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
            return 1
        fi
        
        # Get ETag via list-parts since upload-part doesn't output ETags
        log "  Getting part $part_number ETag via list-parts..."
        
        set +e
        list_result=$(aws_s3api list-parts --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" --part-number-marker $((part_number - 1)) --max-parts 1 2>&1)
        local list_exit_code=$?
        set -e
        
        echo "=== DEBUG: list-parts response for part $part_number (resume continuation) ==="
        echo "Command: aws_s3api list-parts --part-number-marker $((part_number - 1)) --max-parts 1"
        echo "$list_result"
        echo "=== END DEBUG ==="
        
        if [ $list_exit_code -eq 0 ]; then
            # Extract ETag and Size for specific part using json tool
            part_etag=$(echo "$list_result" | json Parts | json -a -c "this.PartNumber === $part_number" ETag)
            part_size=$(echo "$list_result" | json Parts | json -a -c "this.PartNumber === $part_number" Size)
            echo "DEBUG: part $part_number json tool result: ETag='$part_etag', Size='$part_size'"
        else
            log "  Warning: list-parts failed, using placeholder ETag"
            part_etag="placeholder-etag-$part_number"
        fi
        
        log "  Part $part_number ETag: '$part_etag'"
        uploaded_parts+=("ETag=$part_etag,PartNumber=$part_number,Size=$part_size")
        
        # Use actual part size from server - this is the correct approach for S3 MPU
        if [ -n "$part_size" ] && [ "$part_size" -gt 0 ] 2>/dev/null; then
            bytes_uploaded=$((bytes_uploaded + part_size))
            echo "DEBUG: Resume MPU Part $part_number - using server size $part_size for bytes_uploaded calculation"
        else
            bytes_uploaded=$((bytes_uploaded + current_part_size))
            echo "DEBUG: Resume MPU Part $part_number - server size empty/zero, falling back to calculated size $current_part_size"
        fi
        
        # Always advance file offset by the actual bytes read from file
        file_offset=$((file_offset + current_part_size))
        part_number=$((part_number + 1))
        rm -f "$part_file"
    done
    
    success "MPU resume test - Resumed and completed upload with $((part_number - 1)) total parts"
    
    # Complete multipart upload
    local parts_json="{"
    parts_json+="\"Parts\": ["
    for i in "${!uploaded_parts[@]}"; do
        if [ $i -gt 0 ]; then
            parts_json+=","
        fi
        local part_info="${uploaded_parts[$i]}"
        local etag=$(echo "$part_info" | cut -d',' -f1 | cut -d'=' -f2)
        local part_num=$(echo "$part_info" | cut -d',' -f2 | cut -d'=' -f2)
        local part_size=$(echo "$part_info" | cut -d',' -f3 | cut -d'=' -f2)
        # Ensure ETag is properly quoted - remove any existing quotes first
        etag=$(echo "$etag" | sed 's/^"//;s/"$//')
        if [ -n "$etag" ]; then
            etag="\"$etag\""
        else
            etag='""'
        fi
        parts_json+="{\"ETag\": $etag, \"PartNumber\": $part_num}"
    done
    parts_json+="]}"
    
    log "  Generated resume JSON: $parts_json"
    echo "$parts_json" > multipart-resume-complete.json
    
    # Debug: Show the exact JSON being sent to complete-multipart-upload
    log "  DEBUG: Resume JSON content being sent to complete-multipart-upload:"
    cat multipart-resume-complete.json
    
    set +e
    complete_result=$(aws_s3api complete-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" --multipart-upload file://multipart-resume-complete.json 2>&1)
    local complete_exit_code=$?
    set -e
    
    if [ $complete_exit_code -ne 0 ]; then
        error "MPU resume test - Failed to complete multipart upload: $complete_result"
        aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>/dev/null || true
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    success "MPU resume test - Resumed multipart upload completed successfully"
    
    # Verify the uploaded object
    local downloaded_file="downloaded-resume-$mpu_object"
    set +e
    aws_s3api get-object --bucket "$mpu_bucket" --key "$mpu_object" "$downloaded_file" 2>/dev/null
    local download_exit_code=$?
    set -e
    
    if [ $download_exit_code -eq 0 ] && [ -f "$downloaded_file" ]; then
        local downloaded_md5=$(md5sum "$downloaded_file" | cut -d' ' -f1)
        if [ "$original_md5" = "$downloaded_md5" ]; then
            success "MPU resume test - Downloaded file MD5 matches original ($original_md5)"
        else
            error "MPU resume test - Downloaded file MD5 mismatch! Original: $original_md5, Downloaded: $downloaded_md5"
        fi
    else
        error "MPU resume test - Failed to download completed resumed multipart upload"
    fi
    
    # Cleanup
    set +e
    aws_s3api delete-object --bucket "$mpu_bucket" --key "$mpu_object" 2>/dev/null || true
    aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
    rm -f "$mpu_object" "$downloaded_file" "$part1_file" multipart-resume-complete.json
    set -e
}

test_multipart_upload_errors() {
    log "Testing: Multipart Upload Error Handling"
    
    local mpu_bucket="mpu-error-test-$(date +%s)"
    local mpu_object="error-test-file.bin"
    
    # Create test bucket
    set +e
    aws_s3api create-bucket --bucket "$mpu_bucket" 2>/dev/null
    local create_exit_code=$?
    set -e
    
    if [ $create_exit_code -ne 0 ]; then
        error "MPU error test - Failed to create test bucket"
        return 1
    fi
    
    # Create a small test file (< 5MB)
    local small_size=4194304  # 4MB
    log "  Creating $small_size byte test file..."
    dd if=/dev/urandom of="$mpu_object" bs=1024 count=$((small_size / 1024)) 2>/dev/null
    
    # Initiate multipart upload
    set +e
    initiate_result=$(aws_s3api create-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" 2>&1)
    local initiate_exit_code=$?
    set -e
    
    if [ $initiate_exit_code -ne 0 ]; then
        error "MPU error test - Failed to initiate multipart upload: $initiate_result"
        aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
        return 1
    fi
    
    local upload_id=$(echo "$initiate_result" | jq -r '.UploadId // empty')
    
    # Upload a small part (should fail with EntityTooSmall if not final part)
    log "  Testing EntityTooSmall error for 4MB non-final part..."
    
    # Create two 4MB parts to test EntityTooSmall error
    local part1_file="small-part1.bin"
    local part2_file="small-part2.bin"
    dd if="$mpu_object" of="$part1_file" bs=1 count=4194304 2>/dev/null
    dd if="$mpu_object" of="$part2_file" bs=1 count=4194304 2>/dev/null
    
    # Upload part 1 (4MB - should fail as it's not final)
    set +e
    part1_result=$(aws_s3api upload-part --bucket "$mpu_bucket" --key "$mpu_object" --part-number 1 --upload-id "$upload_id" --body "$part1_file" 2>&1)
    local part1_exit_code=$?
    set -e
    
    # Upload part 2 to make part 1 non-final, then complete to trigger EntityTooSmall
    set +e
    part2_result=$(aws_s3api upload-part --bucket "$mpu_bucket" --key "$mpu_object" --part-number 2 --upload-id "$upload_id" --body "$part2_file" 2>&1)
    local part2_exit_code=$?
    set -e
    
    if [ $part1_exit_code -eq 0 ] && [ $part2_exit_code -eq 0 ]; then
        log "  Parts uploaded, now testing complete with EntityTooSmall validation..."
        
        # Get ETags via list-parts since upload-part doesn't output ETags
        log "  Getting ETags via list-parts..."
        
        set +e
        list_result=$(aws_s3api list-parts --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>&1)
        local list_exit_code=$?
        set -e
        
        if [ $list_exit_code -eq 0 ]; then
            echo "=== DEBUG: list-parts response for error test ==="
            echo "$list_result"
            echo "=== END DEBUG ==="
            
            # Extract ETags from list-parts response - simplified robust approach
            # Try direct array access for both parts
            part1_etag=$(echo "$list_result" | jq -r '.Parts[0].ETag' 2>/dev/null)
            part2_etag=$(echo "$list_result" | jq -r '.Parts[1].ETag' 2>/dev/null)
            echo "DEBUG: error test part1 jq direct access result: '$part1_etag'"
            echo "DEBUG: error test part2 jq direct access result: '$part2_etag'"
            
            # If jq fails, use robust sed approach that handles escaped quotes
            if [ -z "$part1_etag" ] || [ "$part1_etag" = "null" ]; then
                all_etags=$(echo "$list_result" | sed -n 's/.*"ETag": *"\(.*\)".*/\1/p')
                part1_etag=$(echo "$all_etags" | head -1 | sed 's/\\\"//g')
                echo "DEBUG: error test part1 sed result: '$part1_etag'"
            fi
            if [ -z "$part2_etag" ] || [ "$part2_etag" = "null" ]; then
                all_etags=$(echo "$list_result" | sed -n 's/.*"ETag": *"\(.*\)".*/\1/p')
                part2_etag=$(echo "$all_etags" | tail -1 | sed 's/\\\"//g')
                echo "DEBUG: error test part2 sed result: '$part2_etag'"
            fi
            
            # Final fallback - awk approach
            if [ -z "$part1_etag" ]; then
                part1_etag=$(echo "$list_result" | jq -r '.Parts[0].ETag // empty')
                echo "DEBUG: error test part1 jq result: '$part1_etag'"
            fi
            if [ -z "$part2_etag" ]; then
                part2_etag=$(echo "$list_result" | jq -r '.Parts[1].ETag // empty')
                echo "DEBUG: error test part2 jq result: '$part2_etag'"
            fi
        else
            log "  Warning: list-parts failed, using placeholder ETags"
            part1_etag="placeholder-etag-1"
            part2_etag="placeholder-etag-2"
        fi
        
        # Ensure ETags are properly quoted - remove any existing quotes first
        part1_etag=$(echo "$part1_etag" | sed 's/^"//;s/"$//')
        part2_etag=$(echo "$part2_etag" | sed 's/^"//;s/"$//')
        if [ -n "$part1_etag" ]; then
            part1_etag="\"$part1_etag\""
        else
            part1_etag='""'
        fi
        if [ -n "$part2_etag" ]; then
            part2_etag="\"$part2_etag\""
        else
            part2_etag='""'
        fi
        local parts_json="{\"Parts\": [{\"ETag\": $part1_etag, \"PartNumber\": 1}, {\"ETag\": $part2_etag, \"PartNumber\": 2}]}"
        log "  Generated error test JSON: $parts_json"
        echo "$parts_json" > multipart-error-complete.json
        
        set +e
        complete_result=$(aws_s3api complete-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" --multipart-upload file://multipart-error-complete.json 2>&1)
        local complete_exit_code=$?
        set -e
        
        if [ $complete_exit_code -ne 0 ]; then
            if echo "$complete_result" | grep -q "EntityTooSmall"; then
                success "MPU error test - EntityTooSmall error properly returned for 4MB non-final part"
            elif echo "$complete_result" | grep -q "Part.*too small"; then
                success "MPU error test - Part too small error properly returned for 4MB non-final part"
            else
                error "MPU error test - Expected EntityTooSmall error but got: $complete_result"
            fi
        else
            error "MPU error test - Complete should have failed with EntityTooSmall for 4MB parts"
        fi
    else
        warning "MPU error test - Could not upload parts to test EntityTooSmall (parts may have been rejected earlier)"
    fi
    
    # Test aborting multipart upload
    log "  Testing abort multipart upload..."
    set +e
    abort_result=$(aws_s3api abort-multipart-upload --bucket "$mpu_bucket" --key "$mpu_object" --upload-id "$upload_id" 2>&1)
    local abort_exit_code=$?
    set -e
    
    if [ $abort_exit_code -eq 0 ]; then
        success "MPU error test - Multipart upload aborted successfully"
    else
        error "MPU error test - Failed to abort multipart upload: $abort_result"
    fi
    
    # Cleanup
    set +e
    aws_s3api delete-bucket --bucket "$mpu_bucket" 2>/dev/null || true
    rm -f "$mpu_object" "$part1_file" "$part2_file" multipart-error-complete.json
    set -e
}


# =============================================================================
# Main Execution
# =============================================================================

main() {
    log "=========================================="
    log "S3 Multipart Upload Test Suite"
    log "=========================================="

    setup

    # Create test bucket
    log "Creating test bucket: $TEST_BUCKET"
    set +e
    aws_s3api create-bucket --bucket "$TEST_BUCKET" >/dev/null 2>&1
    local create_exit=$?
    set -e

    if [ $create_exit -ne 0 ]; then
        log "Note: Bucket creation returned non-zero, may already exist"
    fi

    # Run tests in order
    test_multipart_upload_basic
    test_multipart_upload_resume
    test_multipart_upload_errors

    cleanup_basic
    print_summary
}

main
