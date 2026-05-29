#!/usr/bin/env python3
# Copyright 2026 Edgecast Cloud LLC.
#
# Wire-level integration test for the MPU error-mapping fix.
#
# Moved the MPU-local error constructors from
# lib/s3-multipart.js (plain Errors with tacked-on
# statusCode/restCode) into lib/errors.js as proper BucketsApiError
# subclasses. The unit test test/errors-mpu.test.js verifies each
# class's *shape* (BucketsApiError prototype, restCode, statusCode).
# This file verifies the wire-level *outcome*: drive each error
# condition through buckets-api and assert the HTTP status code and
# the S3 <Code> element in the response body match the constructor's
# declared semantics.
#
# Why: the unit tests inductively prove "if one BucketsApiError
# subclass serializes correctly, all of them do" given restify's
# design — but a future change that adds a new MPU error using the
# old plain-Error anti-pattern, or a restify upgrade that changes
# serialization for some subclasses but not others, would not be
# caught by the unit test alone. This file catches it.
#
# Cases (mapped to lib/s3-multipart.js callsites):
#
#   NoSuchUpload      ListParts on a completed uploadId   (line 3641)
#   NoSuchUpload      Complete twice on same uploadId     (line 1622)
#   InvalidPartNumber upload_part PartNumber=0 or 10001   (line 1258)
#   InvalidPartOrder  complete with reversed Parts list   (line 2797)
#   InvalidPart       complete listing an unuploaded part (line 2880)
#   EntityTooSmall    complete with non-final part <5 MiB (line 2993)
#
# Out of scope:
#   - EntityTooLarge: needs >5 GiB single part, no shark capacity.
#   - MalformedXML, InvalidRequest: require raw HTTP with broken
#     XML bodies; boto3 generates valid XML and doesn't allow
#     byte-level injection. Covered by the unit test for now.
#
# Run:
#   DYLD_LIBRARY_PATH=/opt/homebrew/opt/expat/lib \
#   AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
#     python3 test/integration-mpu-error-mapping.py \
#       --endpoint-url https://dc1-nat.local --insecure
#
# NOTE: on macOS + Homebrew Python 3.14 the bundled pyexpat is built
# against a newer libexpat symbol set than /usr/lib/libexpat.1.dylib;
# set DYLD_LIBRARY_PATH=/opt/homebrew/opt/expat/lib in the shell
# *before* python3 (same workaround as integration-mpu-orphan-cleanup.py).

import argparse
import sys
import uuid
from dataclasses import dataclass
from typing import Callable, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, ParamValidationError

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


PART_SIZE_5M = 5 * 1024 * 1024


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
            retries={'max_attempts': 1, 'mode': 'standard'},
            signature_version='s3v4',
            connect_timeout=10,
            read_timeout=60,
        ),
    )


def ensure_bucket(s3, bucket: str):
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
        resp = s3.list_objects_v2(Bucket=bucket) or {}
        for obj in resp.get('Contents', []) or []:
            try:
                s3.delete_object(Bucket=bucket, Key=obj['Key'])
            except ClientError:
                pass
        # Abort any leftover MPUs from failed runs so the bucket can
        # actually be deleted.
        mpu_resp = s3.list_multipart_uploads(Bucket=bucket) or {}
        for up in mpu_resp.get('Uploads', []) or []:
            try:
                s3.abort_multipart_upload(
                    Bucket=bucket, Key=up['Key'],
                    UploadId=up['UploadId'])
            except ClientError:
                pass
        s3.delete_bucket(Bucket=bucket)
    except ClientError as e:
        warn(f'best-effort delete_bucket({bucket}) failed: {e}')


def abort_quiet(s3, bucket, key, upload_id):
    try:
        s3.abort_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError:
        pass


def expect_error(label: str, fn: Callable[[], object],
                 want_http: int, want_code: str) -> bool:
    """
    Invoke fn; require it to raise a ClientError whose
    HTTPStatusCode and Error.Code match the expected pair. Any
    ClientError with non-matching code is a test failure (this is
    exactly what catches a regression to plain-Error / 500
    InternalError serialization). A non-error return is also a
    failure.
    """
    try:
        result = fn()
        fail(f'{label}: call returned {result!r} but '
             f'{want_http} {want_code} was expected')
        return False
    except ClientError as e:
        http = e.response.get('ResponseMetadata',
                              {}).get('HTTPStatusCode', 0)
        code = e.response.get('Error', {}).get('Code', '')
        if http == want_http and code == want_code:
            ok(f'{label}: got {http} {code} as expected')
            return True
        fail(f'{label}: expected {want_http} {want_code}, '
             f'got {http} {code!r}')
        return False
    except ParamValidationError as e:
        # boto3 client-side validation rejected the request before
        # it went on the wire. That is a separate kind of "would
        # never reach buckets-api" — flag explicitly so we don't
        # report a false pass.
        fail(f'{label}: rejected by boto3 client-side validation '
             f'(never reached buckets-api): {e}')
        return False


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_nosuchupload_via_listparts(s3, args, bucket: str) -> bool:
    """
    Complete an MPU normally; ListParts on the completed uploadId
    must serialize as 404 NoSuchUpload (was 500 InternalError
    pre-CHG-141 because the local NoSuchUploadError was a plain
    Error with statusCode tacked on).
    """
    label = 'nosuchupload-via-listparts'
    key = f'error-mapping/nsu-list-{uuid.uuid4().hex[:8]}'
    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    info(f'{label}: uploadId={upload_id}')

    # Two 5-MiB parts (the smallest valid non-final part size).
    parts = []
    for n in (1, 2):
        body = b'\0' * PART_SIZE_5M
        resp = s3.upload_part(Bucket=bucket, Key=key, PartNumber=n,
                              UploadId=upload_id, Body=body)
        parts.append({'PartNumber': n, 'ETag': resp['ETag']})
    s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id,
        MultipartUpload={'Parts': parts})

    # Cleanup runs as background work after Complete returns. Poll
    # ListParts until it reflects that — same approach as the
    # orphan-cleanup test. We assert the *final* state must be a
    # 404 NoSuchUpload.
    passed = False
    import time
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)
            # Still 200 — cleanup still running. Loop.
            time.sleep(0.5)
            continue
        except ClientError as e:
            http = e.response.get(
                'ResponseMetadata', {}).get('HTTPStatusCode', 0)
            code = e.response.get('Error', {}).get('Code', '')
            if http == 404 and code == 'NoSuchUpload':
                ok(f'{label}: got 404 NoSuchUpload as expected')
                passed = True
                break
            fail(f'{label}: expected 404 NoSuchUpload, '
                 f'got {http} {code!r}')
            break

    if not passed and time.monotonic() >= deadline:
        fail(f'{label}: cleanup did not converge to 404 NoSuchUpload '
             f'within 30s')

    s3.delete_object(Bucket=bucket, Key=key)
    return passed


def test_nosuchupload_via_double_complete(s3, args, bucket: str
                                          ) -> bool:
    """
    Complete the same uploadId twice. The second call must return
    404 NoSuchUpload — the Complete handler's
    `next(new NoSuchUploadError(...))` at lib/s3-multipart.js:1622.
    """
    label = 'nosuchupload-via-double-complete'
    key = f'error-mapping/nsu-double-{uuid.uuid4().hex[:8]}'
    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    info(f'{label}: uploadId={upload_id}')

    parts = []
    for n in (1, 2):
        body = b'\0' * PART_SIZE_5M
        resp = s3.upload_part(Bucket=bucket, Key=key, PartNumber=n,
                              UploadId=upload_id, Body=body)
        parts.append({'PartNumber': n, 'ETag': resp['ETag']})
    s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id,
        MultipartUpload={'Parts': parts})

    passed = expect_error(
        label,
        lambda: s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id,
            MultipartUpload={'Parts': parts}),
        404, 'NoSuchUpload')

    s3.delete_object(Bucket=bucket, Key=key)
    return passed


def test_invalid_part_number_too_high(s3, args, bucket: str) -> bool:
    """
    upload_part with PartNumber=10001 must serialize as 400
    InvalidPartNumber (lib/s3-multipart.js:1258). S3 spec allows
    parts 1..10000 inclusive.
    """
    label = 'invalid-part-number-too-high'
    key = f'error-mapping/ipn-high-{uuid.uuid4().hex[:8]}'
    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    info(f'{label}: uploadId={upload_id}')

    passed = expect_error(
        label,
        lambda: s3.upload_part(
            Bucket=bucket, Key=key, PartNumber=10001,
            UploadId=upload_id, Body=b'x' * PART_SIZE_5M),
        400, 'InvalidPartNumber')

    abort_quiet(s3, bucket, key, upload_id)
    return passed


def test_invalid_part_number_zero(s3, args, bucket: str) -> bool:
    """
    upload_part with PartNumber=0 should also be rejected as
    InvalidPartNumber. boto3 may client-side-validate this; the
    test handles either outcome but a wire-level 400 is preferred.
    """
    label = 'invalid-part-number-zero'
    key = f'error-mapping/ipn-zero-{uuid.uuid4().hex[:8]}'
    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    info(f'{label}: uploadId={upload_id}')

    passed = expect_error(
        label,
        lambda: s3.upload_part(
            Bucket=bucket, Key=key, PartNumber=0,
            UploadId=upload_id, Body=b'x' * PART_SIZE_5M),
        400, 'InvalidPartNumber')

    abort_quiet(s3, bucket, key, upload_id)
    return passed


def test_invalid_part_order(s3, args, bucket: str) -> bool:
    """
    complete_multipart_upload with parts listed in reverse order
    must serialize as 400 InvalidPartOrder
    (lib/s3-multipart.js:2797).
    """
    label = 'invalid-part-order'
    key = f'error-mapping/order-{uuid.uuid4().hex[:8]}'
    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    info(f'{label}: uploadId={upload_id}')

    parts = []
    for n in (1, 2):
        body = b'\0' * PART_SIZE_5M
        resp = s3.upload_part(Bucket=bucket, Key=key, PartNumber=n,
                              UploadId=upload_id, Body=body)
        parts.append({'PartNumber': n, 'ETag': resp['ETag']})

    reversed_parts = list(reversed(parts))
    passed = expect_error(
        label,
        lambda: s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id,
            MultipartUpload={'Parts': reversed_parts}),
        400, 'InvalidPartOrder')

    abort_quiet(s3, bucket, key, upload_id)
    return passed


def test_invalid_part(s3, args, bucket: str) -> bool:
    """
    complete_multipart_upload listing a part number that was never
    uploaded must serialize as 400 InvalidPart
    (lib/s3-multipart.js:2880).
    """
    label = 'invalid-part'
    key = f'error-mapping/ip-{uuid.uuid4().hex[:8]}'
    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    info(f'{label}: uploadId={upload_id}')

    # Upload only part 1 — then claim {1, 7} on complete.
    body = b'\0' * PART_SIZE_5M
    resp = s3.upload_part(
        Bucket=bucket, Key=key, PartNumber=1,
        UploadId=upload_id, Body=body)
    parts = [
        {'PartNumber': 1, 'ETag': resp['ETag']},
        {'PartNumber': 7, 'ETag': '"deadbeefdeadbeefdeadbeefdeadbeef"'},
    ]

    passed = expect_error(
        label,
        lambda: s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id,
            MultipartUpload={'Parts': parts}),
        400, 'InvalidPart')

    abort_quiet(s3, bucket, key, upload_id)
    return passed


def test_entity_too_small(s3, args, bucket: str) -> bool:
    """
    complete_multipart_upload with a non-final part smaller than
    5 MiB must serialize as 400 EntityTooSmall
    (lib/s3-multipart.js:2993). The *last* part may be smaller;
    every other part must be >=5 MiB per S3 spec.
    """
    label = 'entity-too-small'
    key = f'error-mapping/ets-{uuid.uuid4().hex[:8]}'
    init = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = init['UploadId']
    info(f'{label}: uploadId={upload_id}')

    # Part 1: 1 KiB (too small for a non-final part).
    # Part 2: 1 KiB (this one is the final and may be small).
    small = b'x' * 1024
    r1 = s3.upload_part(Bucket=bucket, Key=key, PartNumber=1,
                        UploadId=upload_id, Body=small)
    r2 = s3.upload_part(Bucket=bucket, Key=key, PartNumber=2,
                        UploadId=upload_id, Body=small)
    parts = [
        {'PartNumber': 1, 'ETag': r1['ETag']},
        {'PartNumber': 2, 'ETag': r2['ETag']},
    ]

    passed = expect_error(
        label,
        lambda: s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id,
            MultipartUpload={'Parts': parts}),
        400, 'EntityTooSmall')

    abort_quiet(s3, bucket, key, upload_id)
    return passed


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description=('Wire-level integration test for MPU error '
                     'mapping (CHG-141 verification).'))
    p.add_argument('--endpoint-url', required=True,
                   help='e.g. https://dc1-nat.local')
    p.add_argument('--region', default='us-east-1')
    p.add_argument('--profile', default=None)
    p.add_argument('--insecure', action='store_true',
                   help='disable TLS verification')
    p.add_argument('--ca-bundle', default=None)
    p.add_argument('--bucket', default=None,
                   help='bucket name (default: random)')
    p.add_argument('--keep-bucket', action='store_true',
                   help='do not delete the test bucket on exit')
    return p.parse_args()


def main():
    args = parse_args()
    s3 = make_s3(args)
    bucket = args.bucket or f'mpu-err-{uuid.uuid4().hex[:10]}'
    info(f'using bucket: {bucket}')
    ensure_bucket(s3, bucket)

    result = Result()
    cases = [
        ('nosuchupload-via-listparts',       test_nosuchupload_via_listparts),
        ('nosuchupload-via-double-complete', test_nosuchupload_via_double_complete),
        ('invalid-part-number-too-high',     test_invalid_part_number_too_high),
        ('invalid-part-number-zero',         test_invalid_part_number_zero),
        ('invalid-part-order',               test_invalid_part_order),
        ('invalid-part',                     test_invalid_part),
        ('entity-too-small',                 test_entity_too_small),
    ]

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
        return 0
    fail(f'{result.failed}/{total} cases failed')
    return 1


if __name__ == '__main__':
    sys.exit(main())
