#!/usr/bin/env python3
# Copyright 2026 Edgecast Cloud LLC.
#
# Integration test for the .mpu-parts/* metadata sweep that runs
# inside cleanupMultipartUpload after a successful v2 commit.
#
# Layered verification:
#
#   1. S3-visible (always run):
#      - CompleteMultipartUpload succeeds and returns a final ETag.
#      - ListParts on the completed uploadId returns NoSuchUpload
#        (the upload record was deleted).
#      - GetObject of the final key returns content whose MD5 matches
#        the locally-assembled bytes.
#      - ListMultipartUploads does not include the completed upload.
#
#      These checks fail BEFORE the fix only on the GetObject path if
#      the v2 commit itself broke; they cannot, by themselves, prove
#      that .mpu-parts/{uploadId}/* metadata rows were cleaned up,
#      because the bug left them behind silently. They are regression
#      sanity for the assembly path.
#
#   2. Metadata-level (opt-in via --metadata-check):
#      SSHes to the configured buckets-mdapi PG host and runs a
#      COUNT(*) across every manta_bucket_*.manta_bucket_object table
#      filtering on `name LIKE '.mpu-parts/{uploadId}/%'`. Expects 0.
#      This is the *only* check that directly verifies the fix.
#
# Run examples:
#
#   # S3-level only, against the local CloudAPI tunnel
#   ./integration-mpu-orphan-cleanup.py \
#       --endpoint-url https://localhost:8443 --insecure
#
#   # With metadata verification (requires SSH + psql on the mdapi zone)
#   ./integration-mpu-orphan-cleanup.py \
#       --endpoint-url https://localhost:8443 --insecure \
#       --metadata-check \
#       --ssh-host dc1 \
#       --mdapi-zone <buckets-mdapi-zone-uuid> \
#       --pg-db buckets_metadata
#
#   # Include the pagination-boundary test (slow: uploads 1100 parts)
#   ./integration-mpu-orphan-cleanup.py --endpoint-url ... --large

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import List, Optional, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# macOS + Homebrew Python 3.14: pyexpat needs Homebrew's libexpat.
# Mirrors the workaround in test/test-scripts/lib/s3-test-common.sh.
if os.path.isdir('/opt/homebrew/opt/expat/lib'):
    os.environ['DYLD_LIBRARY_PATH'] = (
        '/opt/homebrew/opt/expat/lib'
        + (':' + os.environ['DYLD_LIBRARY_PATH']
           if os.environ.get('DYLD_LIBRARY_PATH') else ''))

GREEN = '\033[32m'
RED = '\033[31m'
YELLOW = '\033[33m'
CYAN = '\033[36m'
RESET = '\033[0m'


def ok(msg):
    print(f'{GREEN}[ok]{RESET}   {msg}')


def fail(msg):
    print(f'{RED}[FAIL]{RESET} {msg}')


def info(msg):
    print(f'{CYAN}[info]{RESET} {msg}')


def warn(msg):
    print(f'{YELLOW}[warn]{RESET} {msg}')


@dataclass
class Result:
    passed: int = 0
    failed: int = 0


def make_s3(args):
    verify = False if args.insecure else (args.ca_bundle or True)
    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = boto3.session.Session(
        profile_name=args.profile) if args.profile else boto3.session.Session()
    return session.client(
        's3',
        endpoint_url=args.endpoint_url,
        region_name=args.region,
        verify=verify,
        config=Config(
            s3={'addressing_style': 'path'},
            retries={'max_attempts': 3, 'mode': 'standard'},
            signature_version='s3v4',
            connect_timeout=10,
            read_timeout=120,
        ),
    )


def ensure_bucket(s3, bucket: str):
    try:
        s3.head_bucket(Bucket=bucket)
        return
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code', '')
        if code not in ('404', 'NoSuchBucket', 'NotFound'):
            raise
    s3.create_bucket(Bucket=bucket)


def delete_bucket_best_effort(s3, bucket: str):
    try:
        # Drain anything left over (final objects from prior runs).
        resp = s3.list_objects_v2(Bucket=bucket) or {}
        for obj in resp.get('Contents', []) or []:
            try:
                s3.delete_object(Bucket=bucket, Key=obj['Key'])
            except ClientError:
                pass
        s3.delete_bucket(Bucket=bucket)
    except ClientError as e:
        warn(f'best-effort delete_bucket({bucket}) failed: {e}')


def random_bytes(n: int) -> bytes:
    with open('/dev/urandom', 'rb') as f:
        return f.read(n)


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def upload_parts(s3, bucket: str, key: str, upload_id: str,
                 part_sizes: List[int]
                 ) -> Tuple[List[dict], bytes]:
    """
    Upload parts of the given sizes and return ((PartNumber, ETag) list,
    concatenated bytes). Each part is filled with /dev/urandom so the
    backing object is incompressible.
    """
    uploaded = []
    concat = bytearray()
    for idx, size in enumerate(part_sizes, start=1):
        body = random_bytes(size)
        concat.extend(body)
        resp = s3.upload_part(
            Bucket=bucket, Key=key, PartNumber=idx,
            UploadId=upload_id, Body=body)
        uploaded.append({'PartNumber': idx, 'ETag': resp['ETag']})
    return uploaded, bytes(concat)


def complete(s3, bucket: str, key: str, upload_id: str,
             parts: List[dict]) -> dict:
    return s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id,
        MultipartUpload={'Parts': parts})


def expect_no_such_upload(s3, bucket: str, key: str, upload_id: str,
                          label: str) -> bool:
    try:
        s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)
        fail(f'{label}: ListParts unexpectedly succeeded on a '
             f'completed uploadId')
        return False
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code', '')
        if code in ('NoSuchUpload', '404'):
            ok(f'{label}: ListParts after Complete returned '
               f'NoSuchUpload as expected')
            return True
        fail(f'{label}: ListParts returned unexpected error: {code}')
        return False


def expect_object_matches(s3, bucket: str, key: str,
                          expected: bytes, label: str) -> bool:
    resp = s3.get_object(Bucket=bucket, Key=key)
    got = resp['Body'].read()
    if got != expected:
        fail(f'{label}: GetObject body differs (expected '
             f'{len(expected)} bytes md5={md5_hex(expected)}, '
             f'got {len(got)} bytes md5={md5_hex(got)})')
        return False
    ok(f'{label}: GetObject returned {len(got)} bytes, '
       f'md5={md5_hex(got)} matches')
    return True


def expect_not_listed(s3, bucket: str, upload_id: str,
                      label: str) -> bool:
    resp = s3.list_multipart_uploads(Bucket=bucket) or {}
    for up in resp.get('Uploads', []) or []:
        if up.get('UploadId') == upload_id:
            fail(f'{label}: completed uploadId still appears in '
                 f'ListMultipartUploads')
            return False
    ok(f'{label}: completed uploadId is not in ListMultipartUploads')
    return True


def assert_no_orphan_parts_via_ssh(args, upload_id: str,
                                   label: str) -> bool:
    """
    SSH to args.ssh_host, zlogin into args.mdapi_zone, and run a
    federated COUNT(*) against every manta_bucket_*.manta_bucket_object
    table looking for rows whose name starts with
    `.mpu-parts/{upload_id}/`. Expects 0.

    The query uses pg_class to discover the per-vnode tables so it
    works regardless of how many vnodes the deployment has.
    """
    sql = f"""
DO $$
DECLARE
    r record;
    total bigint := 0;
    n bigint;
BEGIN
    FOR r IN
        SELECT n.nspname AS schema_name, c.relname AS table_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'r'
          AND c.relname = 'manta_bucket_object'
          AND n.nspname LIKE 'manta_bucket_%'
    LOOP
        EXECUTE format(
          'SELECT count(*) FROM %I.%I WHERE name LIKE %L',
          r.schema_name, r.table_name,
          '.mpu-parts/{upload_id}/%') INTO n;
        total := total + n;
    END LOOP;
    RAISE NOTICE 'ORPHAN_COUNT=%', total;
END
$$;
"""
    psql_cmd = (f"psql -X -A -t -d {args.pg_db} -c \"{sql}\"")
    if args.mdapi_zone:
        remote = f"zlogin {args.mdapi_zone} '{psql_cmd}'"
    else:
        remote = psql_cmd
    ssh_cmd = ['ssh', '-o', 'BatchMode=yes', args.ssh_host, remote]

    info(f'{label}: running metadata verification via '
         f'{" ".join(ssh_cmd)}')
    try:
        proc = subprocess.run(
            ssh_cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        fail(f'{label}: metadata verification SSH timed out')
        return False

    output = (proc.stdout or '') + '\n' + (proc.stderr or '')
    if proc.returncode != 0:
        fail(f'{label}: metadata SSH exited {proc.returncode}: '
             f'{output.strip()}')
        return False

    # The DO block prints "NOTICE:  ORPHAN_COUNT=<n>" to stderr.
    match = None
    for line in output.splitlines():
        if 'ORPHAN_COUNT=' in line:
            try:
                match = int(line.rsplit('ORPHAN_COUNT=', 1)[1].strip())
            except ValueError:
                pass
    if match is None:
        fail(f'{label}: could not parse ORPHAN_COUNT from psql '
             f'output: {output.strip()}')
        return False

    if match == 0:
        ok(f'{label}: 0 orphan .mpu-parts/{upload_id}/* rows in '
           f'buckets-mdapi')
        return True
    fail(f'{label}: {match} orphan .mpu-parts/{upload_id}/* rows '
         f'remain in buckets-mdapi')
    return False


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

PART_SIZE_5M = 5 * 1024 * 1024  # S3 minimum non-final part size.


def test_typical_complete(s3, args, bucket: str) -> bool:
    label = 'typical-complete'
    key = f'orphan-cleanup/typical-{uuid.uuid4().hex[:8]}'
    info(f'{label}: 5 parts of 5 MiB each')

    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    info(f'{label}: uploadId={upload_id}')

    parts, concat = upload_parts(s3, bucket, key, upload_id,
                                 [PART_SIZE_5M] * 5)
    resp = complete(s3, bucket, key, upload_id, parts)
    final_etag = resp.get('ETag')
    if not final_etag:
        fail(f'{label}: Complete returned no ETag')
        return False
    ok(f'{label}: Complete returned ETag={final_etag}')

    passed = True
    passed &= expect_no_such_upload(s3, bucket, key, upload_id, label)
    passed &= expect_object_matches(s3, bucket, key, concat, label)
    passed &= expect_not_listed(s3, bucket, upload_id, label)

    if args.metadata_check:
        passed &= assert_no_orphan_parts_via_ssh(args, upload_id, label)

    # Cleanup the final object so the bucket can be torn down later.
    s3.delete_object(Bucket=bucket, Key=key)
    return passed


def test_straggler_parts(s3, args, bucket: str) -> bool:
    """
    Upload 10 parts but call Complete with only parts 1-5. The fix's
    *prefix scan* must catch parts 6-10 too; the in-memory partETags
    list passed to Complete would miss them.
    """
    label = 'stragglers'
    key = f'orphan-cleanup/straggler-{uuid.uuid4().hex[:8]}'
    info(f'{label}: upload 10 parts, complete with parts 1-5')

    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    info(f'{label}: uploadId={upload_id}')

    parts, concat = upload_parts(s3, bucket, key, upload_id,
                                 [PART_SIZE_5M] * 10)
    first_five = parts[:5]
    expected_concat = concat[:PART_SIZE_5M * 5]

    resp = complete(s3, bucket, key, upload_id, first_five)
    if not resp.get('ETag'):
        fail(f'{label}: Complete returned no ETag')
        return False
    ok(f'{label}: Complete with parts 1-5 returned ETag='
       f'{resp["ETag"]}')

    passed = True
    passed &= expect_no_such_upload(s3, bucket, key, upload_id, label)
    passed &= expect_object_matches(s3, bucket, key,
                                    expected_concat, label)

    if args.metadata_check:
        # This is the critical case: parts 6-10 are only swept by the
        # prefix scan, not by the partETags loop. If the fix regressed
        # to a partETags-driven delete, this assertion would fail.
        passed &= assert_no_orphan_parts_via_ssh(args, upload_id, label)

    s3.delete_object(Bucket=bucket, Key=key)
    return passed


def test_idempotent_relist(s3, args, bucket: str) -> bool:
    """
    Re-calling Complete on the same uploadId after success must return
    NoSuchUpload (record gone) and must not leave behind any
    .mpu-parts/* rows.
    """
    label = 'idempotent-recall'
    key = f'orphan-cleanup/idempotent-{uuid.uuid4().hex[:8]}'
    info(f'{label}: complete twice on the same uploadId')

    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    parts, _concat = upload_parts(s3, bucket, key, upload_id,
                                  [PART_SIZE_5M] * 2)
    complete(s3, bucket, key, upload_id, parts)
    ok(f'{label}: first Complete succeeded')

    try:
        complete(s3, bucket, key, upload_id, parts)
        fail(f'{label}: second Complete unexpectedly succeeded')
        return False
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code', '')
        if code not in ('NoSuchUpload', '404'):
            fail(f'{label}: second Complete returned unexpected '
                 f'error: {code}')
            return False
        ok(f'{label}: second Complete returned NoSuchUpload')

    passed = True
    if args.metadata_check:
        passed &= assert_no_orphan_parts_via_ssh(args, upload_id, label)

    s3.delete_object(Bucket=bucket, Key=key)
    return passed


def test_pagination_boundary(s3, args, bucket: str) -> bool:
    """
    Upload 1100 parts to cross the default mdapi page limit (1000). All
    rows must still be swept. Opt-in via --large because this is slow.

    Each part is 5 MiB (S3 minimum), so 1100 parts ≈ 5.5 GiB of writes.
    """
    label = 'pagination'
    key = f'orphan-cleanup/large-{uuid.uuid4().hex[:8]}'
    info(f'{label}: 1100 parts (crosses page-limit boundary)')

    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    info(f'{label}: uploadId={upload_id}')

    # Re-use a single buffer so we don't spend 5.5 GiB of /dev/urandom.
    buf = random_bytes(PART_SIZE_5M)
    parts = []
    h = hashlib.md5()
    t0 = time.time()
    for n in range(1, 1101):
        resp = s3.upload_part(
            Bucket=bucket, Key=key, PartNumber=n,
            UploadId=upload_id, Body=buf)
        parts.append({'PartNumber': n, 'ETag': resp['ETag']})
        h.update(buf)
        if n % 100 == 0:
            elapsed = time.time() - t0
            info(f'{label}: uploaded {n}/1100 parts ({elapsed:.0f}s)')

    resp = complete(s3, bucket, key, upload_id, parts)
    if not resp.get('ETag'):
        fail(f'{label}: Complete returned no ETag')
        return False
    ok(f'{label}: Complete of 1100 parts returned ETag='
       f'{resp["ETag"]}')

    passed = True
    passed &= expect_no_such_upload(s3, bucket, key, upload_id, label)

    if args.metadata_check:
        passed &= assert_no_orphan_parts_via_ssh(args, upload_id, label)

    s3.delete_object(Bucket=bucket, Key=key)
    return passed


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description=('Integration test for the .mpu-parts/* metadata '
                     'sweep added to cleanupMultipartUpload.'))
    p.add_argument('--endpoint-url', required=True,
                   help='e.g. https://localhost:8443')
    p.add_argument('--region', default='us-east-1')
    p.add_argument('--profile', default=None)
    p.add_argument('--insecure', action='store_true',
                   help='disable TLS verification (CloudAPI tunnel)')
    p.add_argument('--ca-bundle', default=None)
    p.add_argument('--bucket', default=None,
                   help='bucket name (default: random)')
    p.add_argument('--keep-bucket', action='store_true',
                   help='do not delete the test bucket on exit')

    p.add_argument('--large', action='store_true',
                   help='also run the 1100-part pagination case (slow)')

    p.add_argument('--metadata-check', action='store_true',
                   help=('SSH to --ssh-host and verify zero .mpu-parts '
                         'rows remain (this is the only check that '
                         'directly validates the fix)'))
    p.add_argument('--ssh-host', default=None,
                   help='SSH target for psql verification')
    p.add_argument('--mdapi-zone', default=None,
                   help=('buckets-mdapi zone uuid (optional: if set, '
                         'psql is run via zlogin)'))
    p.add_argument('--pg-db', default='buckets_metadata',
                   help='Postgres database name for psql -d')
    return p.parse_args()


def main():
    args = parse_args()
    if args.metadata_check and not args.ssh_host:
        print('--metadata-check requires --ssh-host', file=sys.stderr)
        return 2

    s3 = make_s3(args)
    bucket = args.bucket or f'mpu-orphan-{uuid.uuid4().hex[:10]}'
    info(f'using bucket: {bucket}')
    ensure_bucket(s3, bucket)

    result = Result()
    cases = [
        ('typical-complete',      test_typical_complete),
        ('straggler-parts',       test_straggler_parts),
        ('idempotent-recall',     test_idempotent_relist),
    ]
    if args.large:
        cases.append(('pagination-boundary', test_pagination_boundary))

    try:
        for name, fn in cases:
            print()
            info(f'=== {name} ===')
            if fn(s3, args, bucket):
                result.passed += 1
            else:
                result.failed += 1
    finally:
        if not args.keep_bucket:
            delete_bucket_best_effort(s3, bucket)

    print()
    total = result.passed + result.failed
    if result.failed == 0:
        ok(f'all {total} cases passed')
        if not args.metadata_check:
            warn('S3-level only: --metadata-check was not set, so '
                 'this run did not directly verify that '
                 '.mpu-parts/* rows were swept. Use --metadata-check '
                 'with --ssh-host to validate the fix.')
        return 0
    fail(f'{result.failed}/{total} cases failed')
    return 1


if __name__ == '__main__':
    sys.exit(main())
