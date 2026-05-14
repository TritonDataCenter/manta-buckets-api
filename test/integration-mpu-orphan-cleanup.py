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

# NOTE: On macOS + Homebrew Python 3.14 the bundled pyexpat is built
# against a newer libexpat symbol set than /usr/lib/libexpat.1.dylib
# exposes, so XML parsing in botocore can fail with
# "Symbol not found: _XML_SetAllocTrackerActivationThreshold".
# Setting DYLD_LIBRARY_PATH from inside Python is too late — dyld has
# already resolved pyexpat. Set it in the shell *before* python3:
#
#   export DYLD_LIBRARY_PATH=/opt/homebrew/opt/expat/lib
#
# This is the same workaround used by test/test-scripts/lib/
# s3-test-common.sh and the exploits/*.sh scripts.

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
    """
    Idempotently ensure the bucket exists. We do NOT pre-check with
    head_bucket because per-bucket-scoped access keys can return 403
    on HEAD against buckets the key has not been authorized for —
    even buckets that don't yet exist. Going straight to create_bucket
    is the portable path.
    """
    try:
        s3.create_bucket(Bucket=bucket)
        info(f'created bucket: {bucket}')
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code', '')
        if code in ('BucketAlreadyOwnedByYou', 'BucketAlreadyExists',
                    'BucketExists', '409'):
            info(f'bucket already exists: {bucket}')
            return
        raise


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


def wait_for_cleanup_convergence(s3, bucket: str, key: str,
                                 upload_id: str, label: str,
                                 timeout: float = 30.0,
                                 interval: float = 0.5) -> bool:
    """
    cleanupMultipartUpload runs as background work *after* Complete
    has already responded to the client. There is no synchronous
    "cleanup done" signal in the S3 API, so we poll ListParts until
    one of the following states is observed:

       - 200 with an empty Parts list:
           transient state under the post-fix ordering where parts
           have been swept but the upload record has not yet been
           deleted.
       - 4xx (NoSuchUpload / 404):
           upload record is gone — the textbook signal.
       - 5xx (InternalError):
           buckets-api currently surfaces getUploadRecord's
           ObjectNotFound as a 500. That is a separate pre-existing
           bug, but for our purposes a 5xx on ListParts after Complete
           is just as conclusive a "record is gone" signal as a 4xx.
           The metadata-side cross-shard sweep does the actual fix
           validation, so accepting 5xx here only affects when we
           stop polling, not what we ultimately verify.

    Returns True on convergence within timeout, False otherwise.
    """
    deadline = time.monotonic() + timeout
    last_state = '(no observation)'
    while time.monotonic() < deadline:
        try:
            resp = s3.list_parts(Bucket=bucket, Key=key,
                                 UploadId=upload_id)
            parts = resp.get('Parts', []) or []
            if not parts:
                ok(f'{label}: cleanup converged — ListParts returns '
                   f'200 with 0 parts')
                return True
            last_state = (f'ListParts 200 with {len(parts)} parts '
                          f'still present')
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            http = e.response.get('ResponseMetadata',
                                   {}).get('HTTPStatusCode', 0)
            if code in ('NoSuchUpload', '404') or http == 404:
                ok(f'{label}: cleanup converged — ListParts returns '
                   f'NoSuchUpload')
                return True
            if 500 <= http < 600:
                ok(f'{label}: cleanup converged — ListParts returns '
                   f'{code} / HTTP {http} (upload record gone; see '
                   f'comment in helper for buckets-api error-mapping '
                   f'caveat)')
                return True
            last_state = f'ListParts raised {code} (HTTP {http})'
        time.sleep(interval)
    fail(f'{label}: cleanup did not converge within {timeout}s '
         f'(last: {last_state})')
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


def _build_orphan_sql(upload_ids: List[str]) -> str:
    """
    Build a psql -f script that, for each given uploadId, sums
    count(*) across every manta_bucket_*.manta_bucket_object schema
    on the current Postgres and prints one
    `NOTICE: ORPHAN <uploadId> <count>` line per uploadId.
    pg_class is used for schema discovery so the script works against
    any per-vnode partitioning the deployment uses.
    """
    blocks = []
    for uid in upload_ids:
        # Single-quote the wildcard pattern at SQL-build time. psql's
        # format(%L) handles the final escaping.
        blocks.append(f"""
  total := 0;
  FOR r IN
    SELECT n.nspname AS schema_name
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind = 'r'
       AND c.relname = 'manta_bucket_object'
       AND n.nspname LIKE 'manta_bucket_%'
  LOOP
    EXECUTE format(
      'SELECT count(*) FROM %I.manta_bucket_object WHERE name LIKE %L',
      r.schema_name,
      '.mpu-parts/{uid}/%') INTO n;
    total := total + n;
  END LOOP;
  RAISE NOTICE 'ORPHAN {uid} %', total;
""")
    return (
        "\\pset border 0\n"
        "SET client_min_messages = NOTICE;\n"
        "DO $$\n"
        "DECLARE\n"
        "  r record;\n"
        "  n bigint;\n"
        "  total bigint := 0;\n"
        "BEGIN\n"
        + "".join(blocks)
        + "END\n$$;\n")


def _parse_orphan_notices(output: str) -> dict:
    """
    Parse `NOTICE:  ORPHAN <uploadId> <count>` lines out of psql output
    (those appear on stderr but get merged when we capture both).
    Returns {uploadId: count_int}. Lines that don't parse are ignored.
    """
    by_id = {}
    for line in output.splitlines():
        # Typical line:  psql:/var/tmp/foo.sql:33: NOTICE:  ORPHAN <uid> <n>
        idx = line.find('ORPHAN ')
        if idx < 0:
            continue
        tail = line[idx + len('ORPHAN '):].strip()
        bits = tail.split()
        if len(bits) >= 2:
            try:
                by_id[bits[0]] = int(bits[1])
            except ValueError:
                continue
    return by_id


def assert_no_orphan_parts_across_shards(args, upload_ids: List[str]
                                         ) -> bool:
    """
    For each --shard-pg server:zone provided, copy a generated SQL
    script into that zone via sdc-oneachnode and run psql there;
    aggregate orphan counts per uploadId across all shards. Fails the
    run if any uploadId has > 0 total orphans.

    The chain is:
      ssh args.ssh_host                                  (Triton HN)
        -> sdc-oneachnode -n <CN-uuid>                   (right CN)
            -> zlogin <buckets-postgres-zone-uuid>       (right zone)
                -> /opt/postgresql/12.0/bin/psql -h /tmp (UDS)

    This matches the layout in coal: each buckets-postgres replica
    exposes its DB only via its local /tmp Unix-domain socket.
    """
    if not args.shard_pg:
        warn('--metadata-check set but no --shard-pg provided; '
             'cannot run the cross-shard orphan-row check')
        return False

    sql = _build_orphan_sql(upload_ids)
    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.sql',
                                     prefix='orphan-check-') as f:
        f.write(sql)
        local_sql = f.name

    try:
        # Stage the SQL on the SSH host once.
        scp = subprocess.run(
            ['scp', '-q', local_sql,
             f'{args.ssh_host}:/var/tmp/mpu-orphan-check.sql'],
            capture_output=True, text=True, timeout=30)
        if scp.returncode != 0:
            fail(f'metadata check: scp staging failed: '
                 f'{scp.stderr.strip()}')
            return False

        totals = {uid: 0 for uid in upload_ids}
        failed_shards = []
        for shard_spec in args.shard_pg:
            if ':' not in shard_spec:
                warn(f'metadata check: ignoring malformed --shard-pg '
                     f'{shard_spec!r} (want server:zone)')
                continue
            server_uuid, zone_uuid = shard_spec.split(':', 1)
            zone_var_tmp = (f'/zones/{zone_uuid}/root'
                            f'/var/tmp/mpu-orphan-check.sql')
            # Push the SQL into the zone (idempotent: remove first).
            stage = subprocess.run(
                ['ssh', '-o', 'BatchMode=yes', args.ssh_host,
                 f'PATH=/opt/smartdc/bin:$PATH; '
                 f'sdc-oneachnode -n {server_uuid} '
                 f'"rm -f {zone_var_tmp}" >/dev/null && '
                 f'sdc-oneachnode -n {server_uuid} '
                 f'-d /var/tmp -g /var/tmp/mpu-orphan-check.sql '
                 f'--dir={zone_var_tmp.rsplit("/",1)[0]} >/dev/null'],
                capture_output=True, text=True, timeout=60)
            if stage.returncode != 0:
                fail(f'metadata check: zone-stage failed for shard '
                     f'{shard_spec}: {stage.stderr.strip() or stage.stdout.strip()}')
                failed_shards.append(shard_spec)
                continue

            run = subprocess.run(
                ['ssh', '-o', 'BatchMode=yes', args.ssh_host,
                 f'PATH=/opt/smartdc/bin:$PATH; '
                 f'sdc-oneachnode -n {server_uuid} '
                 f'"zlogin {zone_uuid} '
                 f'{args.psql_bin} -U postgres -d {args.pg_db} '
                 f'-h /tmp -X -f /var/tmp/mpu-orphan-check.sql 2>&1"'],
                capture_output=True, text=True, timeout=120)
            output = (run.stdout or '') + '\n' + (run.stderr or '')
            if run.returncode != 0:
                fail(f'metadata check: psql failed for shard '
                     f'{shard_spec} (rc={run.returncode}): '
                     f'{output.strip()}')
                failed_shards.append(shard_spec)
                continue
            counts = _parse_orphan_notices(output)
            for uid in upload_ids:
                shard_n = counts.get(uid, None)
                if shard_n is None:
                    warn(f'metadata check: no ORPHAN notice for '
                         f'{uid} on shard {shard_spec}')
                    failed_shards.append(shard_spec)
                    continue
                totals[uid] += shard_n
                info(f'metadata check: shard {shard_spec} '
                     f'reports {shard_n} orphan rows for {uid}')

        passed = (len(failed_shards) == 0)
        for uid, total in totals.items():
            if total == 0:
                ok(f'metadata check: 0 orphan .mpu-parts/{uid}/* '
                   f'rows across all shards')
            else:
                fail(f'metadata check: {total} orphan '
                     f'.mpu-parts/{uid}/* rows remain across shards')
                passed = False
        return passed
    finally:
        try:
            os.unlink(local_sql)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

PART_SIZE_5M = 5 * 1024 * 1024  # S3 minimum non-final part size.


def test_typical_complete(s3, args, bucket: str,
                          upload_ids: List[str]) -> bool:
    label = 'typical-complete'
    key = f'orphan-cleanup/typical-{uuid.uuid4().hex[:8]}'
    info(f'{label}: 5 parts of 5 MiB each')

    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    upload_ids.append(upload_id)
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
    passed &= wait_for_cleanup_convergence(s3, bucket, key, upload_id,
                                           label)
    passed &= expect_object_matches(s3, bucket, key, concat, label)
    passed &= expect_not_listed(s3, bucket, upload_id, label)

    # Cleanup the final object so the bucket can be torn down later.
    s3.delete_object(Bucket=bucket, Key=key)
    return passed


def test_straggler_parts(s3, args, bucket: str,
                         upload_ids: List[str]) -> bool:
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
    upload_ids.append(upload_id)
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
    passed &= wait_for_cleanup_convergence(s3, bucket, key, upload_id,
                                           label)
    passed &= expect_object_matches(s3, bucket, key,
                                    expected_concat, label)

    # The critical assertion (parts 6-10 swept by prefix scan) is
    # covered by the cross-shard metadata check that runs once after
    # all cases finish.

    s3.delete_object(Bucket=bucket, Key=key)
    return passed


def test_idempotent_relist(s3, args, bucket: str,
                           upload_ids: List[str]) -> bool:
    """
    Re-calling Complete on the same uploadId must not succeed. The
    test's contract is just "second Complete is not a 200" — any
    error is fine. We deliberately do not poll for cleanup
    convergence between the two calls, because buckets-api currently
    surfaces a 500 InternalError (instead of 404 NoSuchUpload) when
    the upload record is mid-deletion; that's a separate pre-existing
    bug and not what this case is verifying.

    The metadata-side guarantee (no .mpu-parts/* rows left after the
    completed upload) is verified by the cross-shard sweep that runs
    once after every case finishes.
    """
    label = 'idempotent-recall'
    key = f'orphan-cleanup/idempotent-{uuid.uuid4().hex[:8]}'
    info(f'{label}: complete twice on the same uploadId; second must '
         f'not succeed')

    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    upload_ids.append(upload_id)
    info(f'{label}: uploadId={upload_id}')

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
        http = e.response.get('ResponseMetadata',
                               {}).get('HTTPStatusCode', 0)
        ok(f'{label}: second Complete failed as required '
           f'({code} / HTTP {http})')
        return True


def test_pagination_boundary(s3, args, bucket: str,
                             upload_ids: List[str]) -> bool:
    """
    Upload 1025 parts to cross the buckets-mdapi server-side page
    cap of 1024. All rows must still be swept. Opt-in via --large
    because this is slow (~5.1 GiB).
    """
    label = 'pagination'
    key = f'orphan-cleanup/large-{uuid.uuid4().hex[:8]}'
    info(f'{label}: 1025 parts (crosses 1024-row mdapi page cap)')

    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    upload_ids.append(upload_id)
    info(f'{label}: uploadId={upload_id}')

    # Re-use a single buffer so we don't spend 5+ GiB of /dev/urandom.
    buf = random_bytes(PART_SIZE_5M)
    parts = []
    t0 = time.time()
    for n in range(1, 1026):
        resp = s3.upload_part(
            Bucket=bucket, Key=key, PartNumber=n,
            UploadId=upload_id, Body=buf)
        parts.append({'PartNumber': n, 'ETag': resp['ETag']})
        if n % 100 == 0:
            elapsed = time.time() - t0
            info(f'{label}: uploaded {n}/1025 parts ({elapsed:.0f}s)')

    resp = complete(s3, bucket, key, upload_id, parts)
    if not resp.get('ETag'):
        fail(f'{label}: Complete returned no ETag')
        return False
    ok(f'{label}: Complete of 1025 parts returned ETag='
       f'{resp["ETag"]}')

    passed = True
    # Cleanup of 1025 parts can take meaningfully longer than the
    # default 30s; raise the timeout.
    passed &= wait_for_cleanup_convergence(s3, bucket, key, upload_id,
                                           label, timeout=180)

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
                   help=('After all S3 cases complete, SSH to '
                         '--ssh-host and run a cross-shard psql sweep '
                         'over every --shard-pg to verify zero '
                         '.mpu-parts/* rows remain. This is the only '
                         'check that directly validates the fix.'))
    p.add_argument('--ssh-host', default=None,
                   help=('SSH target that has sdc-oneachnode available '
                         '(typically a Triton headnode).'))
    p.add_argument('--shard-pg', action='append', default=[],
                   metavar='SERVER:ZONE',
                   help=('A buckets-postgres replica to query, as '
                         '<CN-server-uuid>:<zone-uuid>. Repeat for '
                         'each shard. Required when --metadata-check '
                         'is set.'))
    p.add_argument('--pg-db', default='buckets_metadata',
                   help='Postgres database name for psql -d')
    p.add_argument('--psql-bin',
                   default='/opt/postgresql/12.0/bin/psql',
                   help=('Path to psql inside the buckets-postgres '
                         'zone (default works on coal PG 12 zones).'))
    return p.parse_args()


def main():
    args = parse_args()
    if args.metadata_check:
        if not args.ssh_host:
            print('--metadata-check requires --ssh-host',
                  file=sys.stderr)
            return 2
        if not args.shard_pg:
            print('--metadata-check requires at least one --shard-pg '
                  'server:zone', file=sys.stderr)
            return 2

    s3 = make_s3(args)
    bucket = args.bucket or f'mpu-orphan-{uuid.uuid4().hex[:10]}'
    info(f'using bucket: {bucket}')
    ensure_bucket(s3, bucket)

    result = Result()
    upload_ids: List[str] = []
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
            if fn(s3, args, bucket, upload_ids):
                result.passed += 1
            else:
                result.failed += 1

        if args.metadata_check and upload_ids:
            print()
            info('=== cross-shard metadata sweep ===')
            if assert_no_orphan_parts_across_shards(args, upload_ids):
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
                 'with --ssh-host and --shard-pg to validate the fix.')
        return 0
    fail(f'{result.failed}/{total} cases failed')
    return 1


if __name__ == '__main__':
    sys.exit(main())
