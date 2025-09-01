#!/usr/bin/env python3
"""
s3_autotest.py
Automated S3 bucket & object operation tests for a custom S3-compatible
endpoint using PATH-STYLE addressing.

Credentials:
  - Taken automatically from environment (AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN) or ~/.aws/{credentials,config}.
  - Optionally choose a profile via --profile.

What it tests (in order):
  - ListBuckets (reachability)
  - CreateBucket (if missing)
  - HeadBucket
  - PutObject (bytes)
  - HeadObject (metadata + size)
  - GetObject (verify payload)
  - ListObjectsV2 (prefix)
  - CopyObject (same bucket)
  - GetObject with Range (partial reads)
  - Pre-signed GET URL (optional if you keep that block)
  - DeleteObject (copied)
  - Multipart Upload: initiate → upload 2 parts → complete → verify → delete
  - Optional cleanup: Delete original object + bucket

Exit code is non-zero if any test fails.
"""

import argparse
import os
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Callable, List, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError, ReadTimeoutError
import urllib.request

# --- Pretty printing ---------------------------------------------------------
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

def ok(msg):    print(f"{GREEN}[ok]{RESET} {msg}")
def fail(msg):  print(f"{RED}[fail]{RESET} {msg}")
def info(msg):  print(f"{CYAN}[info]{RESET} {msg}")
def warn(msg):  print(f"{YELLOW}[warn]{RESET} {msg}")

# --- Test harness ------------------------------------------------------------
@dataclass
class TestResult:
    name: str
    passed: bool
    detail: str = ""

class TestRunner:
    def __init__(self):
        self.results: List[TestResult] = []

    def run(self, name: str, fn: Callable[[], None]):
        try:
            fn()
            self.results.append(TestResult(name, True))
            ok(name)
        except AssertionError as e:
            self.results.append(TestResult(name, False, str(e)))
            fail(f"{name} :: {e}")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            msg = e.response.get("Error", {}).get("Message")
            self.results.append(TestResult(name, False, f"{code}: {msg}"))
            fail(f"{name} :: {code}: {msg}")
        except Exception as e:
            self.results.append(TestResult(name, False, repr(e)))
            fail(f"{name} :: {e}")

    def summary(self) -> Tuple[int, int]:
        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        print()
        print(f"{BOLD}=== Test Summary ==={RESET}")
        for r in self.results:
            mark = f"{GREEN}PASS{RESET}" if r.passed else f"{RED}FAIL{RESET}"
            detail = f" — {DIM}{r.detail}{RESET}" if (r.detail and not r.passed) else ""
            print(f"{mark}  {r.name}{detail}")
        print(f"{BOLD}Passed {passed}/{total}{RESET}")
        return passed, total

# --- S3 client & helpers -----------------------------------------------------
def make_s3_client(args):
    sess_kwargs = {}
    if args.profile:
        sess_kwargs["profile_name"] = args.profile

    session = boto3.session.Session(**sess_kwargs)

    verify = True
    if args.insecure:
        verify = False
    elif args.ca_bundle:
        verify = args.ca_bundle  # path to custom CA bundle

    # No explicit credentials here — boto3 reads env/credentials files.
    return session.client(
        "s3",
        endpoint_url=args.endpoint_url,
        region_name=args.region,
        verify=verify,
        config=Config(
            s3={"addressing_style": "path"},  # enforce PATH-STYLE
            retries={"max_attempts": 5, "mode": "standard"},
            signature_version="s3v4",
            connect_timeout=30,  # Increased for slow responses during assembly
            read_timeout=120,    # Increased to 2 minutes for background assembly
        ),
    )

def ensure_bucket(s3, bucket: str, region: str):
    # Try HEAD; create if missing
    try:
        s3.head_bucket(Bucket=bucket)
        info(f"Bucket exists: {bucket}")
        return
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code not in ("404", "NoSuchBucket", "NotFound"):
            raise

    # Create (with fallback for S3-compatible targets)
    try:
        if region and region != "us-east-1":
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        else:
            s3.create_bucket(Bucket=bucket)
        info(f"Created bucket: {bucket}")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in (
            "InvalidLocationConstraint",
            "IllegalLocationConstraintException",
            "InvalidRequest",
        ):
            s3.create_bucket(Bucket=bucket)
            info(f"Created bucket (fallback): {bucket}")
        else:
            raise

# --- Main test sequence ------------------------------------------------------
def run_suite(args) -> int:
    s3 = make_s3_client(args)
    tr = TestRunner()

    # Connectivity / list buckets
    def t_list_buckets():
        try:
            resp = s3.list_buckets()
        except EndpointConnectionError as e:
            raise AssertionError(f"Endpoint unreachable: {e}")
        except NoCredentialsError:
            raise AssertionError("Missing credentials (env/CLI profile)")
        assert "Buckets" in resp
    tr.run("ListBuckets (reachability)", t_list_buckets)

    # Names & payloads
    bucket = args.bucket or (f"{args.bucket_prefix}-{uuid.uuid4().hex[:8]}"
                             if args.bucket_prefix else
                             f"s3-autotest-{uuid.uuid4().hex[:8]}")
    key = args.key or "autotest.txt"
    payload = (args.payload.encode() if args.payload is not None else
               f"hello from s3_autotest at {time.strftime('%Y-%m-%d %H:%M:%S')}\n".encode())

    # Ensure/Create bucket
    def t_create_or_head_bucket():
        ensure_bucket(s3, bucket, args.region)
        s3.head_bucket(Bucket=bucket)
    tr.run("Create/HeadBucket", t_create_or_head_bucket)

    # Put object
    def t_put_object():
        s3.put_object(Bucket=bucket, Key=key, Body=payload,
                      Metadata={"autotest": "true"})
    tr.run("PutObject", t_put_object)

    # Head object
    def t_head_object():
        h = s3.head_object(Bucket=bucket, Key=key)
        assert h.get("ContentLength") == len(payload), "size mismatch"
        md = h.get("Metadata", {})
        assert md.get("autotest") == "true", "metadata missing"
    tr.run("HeadObject", t_head_object)

    # Get object verify
    def t_get_object_verify():
        got = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        assert got == payload, "downloaded bytes mismatch"
    tr.run("GetObject (verify)", t_get_object_verify)

    # List objects v2
    def t_list_objects_v2():
        l = s3.list_objects_v2(Bucket=bucket, Prefix=args.prefix or "")
        count = l.get("KeyCount", 0)
        keys = [c["Key"] for c in l.get("Contents", [])] if count else []
        assert key in keys, "uploaded key not listed"
    tr.run("ListObjectsV2", t_list_objects_v2)


    # Range read (partial GET)
    def t_get_range():
        end = min(4, len(payload) - 1)
        r = s3.get_object(Bucket=bucket, Key=key, Range=f"bytes=0-{end}")
        part = r["Body"].read()
        assert part == payload[: end + 1], "range bytes mismatch"
    tr.run("GetObject (Range)", t_get_range)

    # --- OPTIONAL: Pre-signed URL test (remove or guard with a flag) -------
    # def t_presigned_get():
    #     url = s3.generate_presigned_url(
    #         "get_object",
    #         Params={"Bucket": bucket, "Key": key},
    #         ExpiresIn=300,
    #     )
    #     with urllib.request.urlopen(url) as resp:
    #         data = resp.read()
    #     assert data == payload, "presigned GET mismatch"
    # tr.run("Pre-signed GET URL", t_presigned_get)


    # --- Multipart Upload test ---------------------------------------------
    mpu_key = args.mpu_key or "autotest-mpu.bin"

    def make_blob(byte_val: int, size_bytes: int) -> bytes:
        return bytes([byte_val]) * size_bytes

    def t_multipart_upload():
        # Prepare part sizes (MiB -> bytes)
        min_part = 5 * 1024 * 1024  # 5 MiB
        p1_req = int(args.mpu_part1_mib) * 1024 * 1024
        p2_req = int(args.mpu_part2_mib) * 1024 * 1024  # final part may be < 5 MiB

        # Ensure part 1 meets S3 minimum size requirement (force minimum regardless of input)
        if p1_req < min_part:
            warn(f"Part 1 too small ({p1_req} bytes = {p1_req/1024/1024:.1f} MiB), using minimum 5 MiB")
            p1_req = min_part
        
        # Double-check: Force minimum part size to prevent server errors
        p1_req = max(p1_req, min_part)
        
        # Debug: Show actual sizes
        info(f"Part 1 size: {p1_req} bytes ({p1_req / 1024 / 1024:.1f} MiB)")
        info(f"Part 2 size: {p2_req} bytes ({p2_req / 1024 / 1024:.1f} MiB)")

        part1 = make_blob(0xA3, p1_req)
        part2 = make_blob(0x4D, p2_req)

        # DEBUG: Print what we're about to request
        info(f"MPU Debug - Bucket: {bucket}, Key: {mpu_key}")
        info(f"Expected initiate URL: {args.endpoint_url}/{bucket}/{mpu_key}?uploads")

        # Initiate
        init = s3.create_multipart_upload(Bucket=bucket, Key=mpu_key)
        upload_id = init["UploadId"]
        info(f"MPU Upload ID: {upload_id}")

        try:
            # Upload Part 1 with retry-if-too-small safety
            try:
                up1 = s3.upload_part(
                    Bucket=bucket, Key=mpu_key, PartNumber=1,
                    UploadId=upload_id, Body=part1
                )
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code in ("EntityTooSmall", "InvalidRequest"):
                    warn("Part 1 too small per server; retrying with 5 MiB")
                    part1 = make_blob(0xA3, min_part)
                    up1 = s3.upload_part(
                        Bucket=bucket, Key=mpu_key, PartNumber=1,
                        UploadId=upload_id, Body=part1
                    )
                else:
                    raise
            etag1 = up1["ETag"]

            # Upload Part 2 (final part can be small)
            up2 = s3.upload_part(
                Bucket=bucket, Key=mpu_key, PartNumber=2,
                UploadId=upload_id, Body=part2
            )
            etag2 = up2["ETag"]

            # Complete MPU
            s3.complete_multipart_upload(
                Bucket=bucket,
                Key=mpu_key,
                UploadId=upload_id,
                MultipartUpload={
                    "Parts": [
                        {"ETag": etag1, "PartNumber": 1},
                        {"ETag": etag2, "PartNumber": 2},
                    ]
                },
            )

            # Verify size via HEAD with retry for background assembly
            expected = len(part1) + len(part2)
            max_retries = 120  # Up to 4 minutes for MPU assembly (120 * 2s)
            retry_interval = 2  # 2 seconds between retries to reduce load
            info(f"Waiting for MPU object assembly (expected size: {expected} bytes)...")
            
            for attempt in range(max_retries):
                try:
                    h = s3.head_object(Bucket=bucket, Key=mpu_key)
                    actual_size = h.get("ContentLength")
                    if actual_size == expected:
                        info(f"MPU object available after {attempt} retries ({attempt * retry_interval}s)")
                        break
                    else:
                        if attempt % 10 == 0:  # Log every 20 seconds
                            info(f"Attempt {attempt + 1}/{max_retries}: Size {actual_size} != {expected} (waiting...)")
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code in ("NoSuchKey", "404"):
                        if attempt < max_retries - 1:
                            if attempt % 10 == 0:  # Log every 20 seconds
                                info(f"Attempt {attempt + 1}/{max_retries}: Object not yet available, retrying...")
                            time.sleep(retry_interval)
                            continue
                        else:
                            raise AssertionError(f"MPU object not available after {max_retries * retry_interval} seconds")
                    else:
                        raise
                except ReadTimeoutError as e:
                    # Handle HTTP timeout during background assembly
                    if attempt < max_retries - 1:
                        if attempt % 10 == 0:  # Log every 20 seconds
                            info(f"Attempt {attempt + 1}/{max_retries}: Request timed out (assembly in progress), retrying...")
                        time.sleep(retry_interval)
                        continue
                    else:
                        raise AssertionError(f"MPU object still assembling after {max_retries * retry_interval} seconds")
                except Exception as e:
                    # Handle other connection/timeout errors during assembly
                    if attempt < max_retries - 1:
                        if attempt % 10 == 0:  # Log every 20 seconds
                            info(f"Attempt {attempt + 1}/{max_retries}: Error {type(e).__name__}: {e} (retrying...)")
                        time.sleep(retry_interval)
                        continue
                    else:
                        raise
                time.sleep(retry_interval)
            else:
                raise AssertionError(f"MPU size mismatch after {max_retries * retry_interval} seconds: {actual_size} != {expected}")

            # Verify content with retry (object exists but may not be fully readable yet)
            info("Verifying MPU object content...")
            verification_retries = 30  # Up to 1 minute for content verification
            verification_interval = 2
            
            for verify_attempt in range(verification_retries):
                try:
                    # Spot-check first byte & boundary bytes with ranges
                    r1 = s3.get_object(Bucket=bucket, Key=mpu_key, Range="bytes=0-0")["Body"].read()
                    assert r1 == part1[:1], "MPU first byte mismatch"

                    # Byte at the end of part1
                    if expected > 0:
                        r2 = s3.get_object(
                            Bucket=bucket, Key=mpu_key, Range=f"bytes={len(part1)-1}-{len(part1)-1}"
                        )["Body"].read()
                        assert r2 == part1[-1:], "MPU boundary byte (end part1) mismatch"

                    # First byte of part2
                    r3 = s3.get_object(
                        Bucket=bucket, Key=mpu_key, Range=f"bytes={len(part1)}-{len(part1)}"
                    )["Body"].read()
                    assert r3 == part2[:1], "MPU first byte (part2) mismatch"
                    
                    info(f"MPU content verification succeeded after {verify_attempt} retries")
                    break
                    
                except (ReadTimeoutError, ClientError, Exception) as e:
                    if verify_attempt < verification_retries - 1:
                        if verify_attempt % 5 == 0:  # Log every 10 seconds
                            info(f"Content verification attempt {verify_attempt + 1}/{verification_retries}: {type(e).__name__}, retrying...")
                        time.sleep(verification_interval)
                        continue
                    else:
                        raise AssertionError(f"MPU content verification failed after {verification_retries * verification_interval} seconds: {e}")
            else:
                raise AssertionError(f"MPU content verification failed after {verification_retries} attempts")

        except Exception:
            # Abort MPU on any failure to avoid leaks
            try:
                s3.abort_multipart_upload(Bucket=bucket, Key=mpu_key, UploadId=upload_id)
            except Exception:
                pass
            raise

    tr.run("Multipart Upload (init/upload/complete/verify)", t_multipart_upload)

    # Clean up the MPU object (if it exists)
    def t_delete_mpu_object():
        try:
            s3.delete_object(Bucket=bucket, Key=mpu_key)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchKey", "404"):
                info(f"MPU object {mpu_key} not found (likely upload failed), cleanup not needed")
            else:
                raise
        l = s3.list_objects_v2(Bucket=bucket, Prefix=mpu_key)
        assert l.get("KeyCount", 0) == 0, "MPU object still present"
    tr.run("DeleteObject (MPU object)", t_delete_mpu_object)

    # Optional cleanup (original + bucket)
    if args.cleanup:
        def t_cleanup():
            try:
                s3.delete_object(Bucket=bucket, Key=key)
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code != "NoSuchKey":
                    raise
            s3.delete_bucket(Bucket=bucket)
        tr.run("Cleanup (object & bucket)", t_cleanup)
    else:
        warn("Cleanup disabled; test artifacts retained.")

    # Print summary & return failures
    passed, total = tr.summary()
    return 0 if passed == total else 1

# --- CLI ---------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Automated S3 tests against a custom endpoint (path-style)."
    )
    p.add_argument("--endpoint-url", required=True, help="e.g., https://s3.local")
    p.add_argument("--region", default="us-east-1", help="Region name")
    p.add_argument("--profile", help="AWS profile name (uses env/credentials by default)")
    p.add_argument("--bucket", help="Bucket to use (default: auto-generate)")
    p.add_argument("--bucket-prefix", default="s3-autotest",
                   help="Prefix for auto bucket name (ignored if --bucket given)")
    p.add_argument("--key", default="autotest.txt", help="Object key")
    p.add_argument("--prefix", default="", help="Prefix for ListObjectsV2")
    p.add_argument("--payload", help="Custom payload string (default: greeting)")
    p.add_argument("--insecure", action="store_true",
                   help="Disable TLS certificate verification")
    p.add_argument("--ca-bundle", help="Path to custom CA bundle file")

    # Multipart options
    p.add_argument("--mpu-key", default="autotest-mpu.bin",
                   help="Key to use for Multipart Upload test")
    p.add_argument("--mpu-part1-mib", type=int, default=5,
                   help="Part 1 size in MiB (>=5 for AWS S3)")
    p.add_argument("--mpu-part2-mib", type=int, default=1,
                   help="Part 2 size in MiB (final part can be <5)")

    p.add_argument("--cleanup", action="store_true",
                   help="Delete test objects & bucket at the end")
    return p.parse_args()

if __name__ == "__main__":
    try:
        sys.exit(run_suite(parse_args()))
    except KeyboardInterrupt:
        warn("Interrupted.")
        sys.exit(130)
