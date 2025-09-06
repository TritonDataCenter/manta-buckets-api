#!/usr/bin/env python3
"""
mpu_resume_autotest.py
End-to-end automated test that:
  - creates a temp file (default 9 MiB),
  - initiates MPU for a key,
  - uploads part 1 (>=5 MiB),
  - simulates an interruption,
  - RESUMES via ListParts and uploads remaining parts,
  - completes the MPU, verifies size,
  - deletes the object (unless --keep).

Credentials are taken from env / AWS config; path-style addressing enforced.
Works with AWS S3 and S3-compatible endpoints.

Usage:
  python mpu_resume_autotest.py --endpoint-url https://s3.local \
    --bucket my-bucket --region us-east-1
"""

import argparse
import os
import sys
import uuid
import tempfile
from typing import Dict, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

MIN_PART = 5 * 1024 * 1024  # 5 MiB


def make_client(endpoint_url: str, region: str, profile: str = None,
                insecure: bool = False, ca_bundle: str = None):
    sess = boto3.session.Session(profile_name=profile) if profile else boto3.session.Session()
    verify = False if insecure else (ca_bundle or True)
    return sess.client(
        "s3",
        endpoint_url=endpoint_url,
        region_name=region,
        verify=verify,
        config=Config(
            s3={"addressing_style": "path"},
            retries={"max_attempts": 5, "mode": "standard"},
            signature_version="s3v4",
            connect_timeout=10,
            read_timeout=300,
        ),
    )


def ensure_bucket(s3, bucket: str, region: str):
    try:
        s3.head_bucket(Bucket=bucket)
        return
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code not in ("404", "NoSuchBucket", "NotFound"):
            raise
    # Try to create; fall back without LocationConstraint if needed
    try:
        if region and region != "us-east-1":
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        else:
            s3.create_bucket(Bucket=bucket)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in (
            "InvalidLocationConstraint",
            "IllegalLocationConstraintException",
            "InvalidRequest",
        ):
            s3.create_bucket(Bucket=bucket)
        else:
            raise


def make_temp_file(size_bytes: int) -> Tuple[str, int]:
    # Create a deterministic pattern to allow sanity checks if desired
    fd, path = tempfile.mkstemp(prefix="mpu-resume-", suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        # Write repeating 1 MiB blocks to avoid large memory peaks
        block = bytes([0xA7]) * (1024 * 1024)
        remaining = size_bytes
        while remaining > 0:
            write_now = min(len(block), remaining)
            f.write(block[:write_now])
            remaining -= write_now
    return path, size_bytes


def list_parts_all(s3, bucket: str, key: str, upload_id: str) -> Dict[int, str]:
    parts = {}
    marker = None
    while True:
        kw = {"Bucket": bucket, "Key": key, "UploadId": upload_id}
        if marker is not None:
            kw["PartNumberMarker"] = marker
        resp = s3.list_parts(**kw)
        for p in resp.get("Parts", []) or []:
            parts[p["PartNumber"]] = p["ETag"]
        if not resp.get("IsTruncated"):
            break
        marker = resp.get("NextPartNumberMarker")
    return parts


def human(n: int) -> str:
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or u == "TiB":
            return f"{n} {u}" if u == "B" else f"{n:.2f} {u}"
        n /= 1024.0
    return f"{n} B"


def main():
    ap = argparse.ArgumentParser(
        description="Automated MPU resume test (start, interrupt, resume, complete)."
    )
    ap.add_argument("--endpoint-url", required=True, help="Custom S3 endpoint, e.g., https://s3.local")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--profile", help="AWS profile (uses env/default if omitted)")
    ap.add_argument("--bucket", required=True)
    ap.add_argument("--key", default=None, help="Object key (default auto)")
    ap.add_argument("--size-mib", type=int, default=9, help="Test file size MiB (default 9)")
    ap.add_argument("--part-size-mib", type=int, default=5, help="Part size MiB (non-final >=5)")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    ap.add_argument("--ca-bundle", help="Path to custom CA bundle")
    ap.add_argument("--keep", action="store_true", help="Keep the uploaded object (no delete)")
    args = ap.parse_args()

    s3 = make_client(args.endpoint_url, args.region, args.profile, args.insecure, args.ca_bundle)

    # Set key if not provided
    key = args.key or f"mpu-resume-autotest-{uuid.uuid4().hex[:10]}.bin"

    # Ensure bucket exists (ok if your endpoint forbids create; we just HEAD)
    try:
        ensure_bucket(s3, args.bucket, args.region)
    except ClientError as e:
        print(f"[warn] Could not ensure bucket: {e}")

    # Prepare temp file
    total_size = max(1, args.size_mib) * 1024 * 1024
    tmp_path, _ = make_temp_file(total_size)
    part_size = max(1, args.part_size_mib) * 1024 * 1024
    print(f"[info] Temp file: {tmp_path} ({human(total_size)}), part_size={human(part_size)}")

    # --- Phase 1: initiate + upload part 1 (simulate interruption) ----------
    try:
        init = s3.create_multipart_upload(Bucket=args.bucket, Key=key)
        upload_id = init["UploadId"]
        print(f"[ok  ] MPU initiated: UploadId={upload_id}")

        # Upload part 1 (auto-bump if too small and more than 1 part)
        more_than_one_part = total_size > part_size
        part1_size = part_size
        if more_than_one_part and part1_size < MIN_PART:
            print(f"[warn] part_size < 5 MiB; bumping part 1 to 5 MiB")
            part1_size = MIN_PART

        with open(tmp_path, "rb") as fh:
            chunk = fh.read(min(part1_size, total_size))

        try:
            up1 = s3.upload_part(
                Bucket=args.bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=chunk
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("EntityTooSmall", "InvalidRequest") and more_than_one_part:
                print("[warn] Server rejected part 1 as too small; retrying with 5 MiB")
                with open(tmp_path, "rb") as fh:
                    chunk = fh.read(min(MIN_PART, total_size))
                up1 = s3.upload_part(
                    Bucket=args.bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=chunk
                )
            else:
                raise

        etag1 = up1["ETag"]
        print(f"[ok  ] Uploaded part 1 (ETag={etag1})")

        # "Interrupt": drop client/context (nothing to do programmatically)
        # We just create a fresh client to emulate resume later.
        s3 = make_client(args.endpoint_url, args.region, args.profile, args.insecure, args.ca_bundle)
        print("[info] Simulated interruption; resuming with a fresh client")

        # --- Phase 2: resume: list existing parts, upload rest, complete -----
        existing = list_parts_all(s3, args.bucket, key, upload_id)
        print(f"[info] Existing parts after interruption: {sorted(existing.keys()) or 'none'}")
        assert 1 in existing, "Part 1 missing after resume; ListParts failed?"

        # Upload remaining parts
        with open(tmp_path, "rb") as fh:
            sent = len(chunk)  # bytes already uploaded in part 1
            part_number = 2
            while sent < total_size:
                to_send = min(part_size, total_size - sent)
                # non-final parts must be >= 5 MiB
                is_final = (sent + to_send) == total_size
                if not is_final and to_send < MIN_PART:
                    print(f"[warn] bumping non-final part {part_number} to 5 MiB")
                    to_send = MIN_PART if sent + MIN_PART <= total_size else total_size - sent

                fh.seek(sent, os.SEEK_SET)
                buf = fh.read(to_send)
                up = s3.upload_part(
                    Bucket=args.bucket, Key=key, PartNumber=part_number,
                    UploadId=upload_id, Body=buf
                )
                print(f"[ok  ] Uploaded part {part_number} ({human(len(buf))}, ETag={up['ETag']})")
                existing[part_number] = up["ETag"]
                sent += len(buf)
                part_number += 1

        # Complete
        parts_list = [{"ETag": existing[pn], "PartNumber": pn} for pn in sorted(existing)]
        s3.complete_multipart_upload(
            Bucket=args.bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts_list},
        )
        print("[ok  ] MPU completed after resume")

        # Verify size
        h = s3.head_object(Bucket=args.bucket, Key=key)
        remote_size = h.get("ContentLength")
        print(f"[info] Remote size={remote_size} B; Local size={total_size} B")
        assert remote_size == total_size, "Final size mismatch"

    except Exception as e:
        # Try to abort if possible
        try:
            if "upload_id" in locals():
                s3.abort_multipart_upload(Bucket=args.bucket, Key=key, UploadId=upload_id)
                print("[info] Aborted MPU due to failure")
        except Exception:
            pass
        print(f"[FAIL] {e}", file=sys.stderr)
        if not args.keep:
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        sys.exit(1)

    # Cleanup object (unless --keep)
    try:
        if not args.keep:
            s3.delete_object(Bucket=args.bucket, Key=key)
            print("[ok  ] Deleted test object")
    except ClientError as e:
        print(f"[warn] DeleteObject failed: {e}")

    # Cleanup temp file
    try:
        os.remove(tmp_path)
    except Exception:
        pass

    print("[PASS] MPU resume test succeeded.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
