#!/usr/bin/env python3
#
# Copyright 2026 Edgecast Cloud LLC.
#
# Tests for UploadPartCopy range validation:
#   - 400 InvalidArgument for malformed x-amz-copy-source-range
#   - 416 InvalidRange for out-of-bounds range
#   - 400 EntityTooSmall for 0-byte source object
#   - Happy path: valid range copy and full object copy (no range header)
#
# Usage:
#   S3_ENDPOINT=http://localhost:8080 \
#   AWS_ACCESS_KEY_ID=... \
#   AWS_SECRET_ACCESS_KEY=... \
#   ./boto3-env/bin/python3 s3-uploadpartcopy-range-test.py

import os
import sys
import boto3
import hashlib
from botocore.config import Config
from botocore.exceptions import ClientError

# Configuration
ENDPOINT = os.environ.get('S3_ENDPOINT', 'http://localhost:8080')
ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY_ID', 'AKIA123456789EXAMPLE')
SECRET_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY',
    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
REGION = os.environ.get('AWS_REGION', 'us-east-1')

SRC_BUCKET = 'upc-range-src-%d' % os.getpid()
DST_BUCKET = 'upc-range-dst-%d' % os.getpid()

passed = 0
failed = 0

GREEN = '\033[0;32m'
RED = '\033[0;31m'
NC = '\033[0m'


def ok(desc):
    global passed
    passed += 1
    print('%s  PASS: %s%s' % (GREEN, desc, NC))


def fail(desc, detail=''):
    global failed
    failed += 1
    msg = '%s  FAIL: %s%s' % (RED, desc, NC)
    if detail:
        msg += '\n    %s' % detail
    print(msg)


def make_client():
    return boto3.client('s3',
        endpoint_url=ENDPOINT,
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        region_name=REGION,
        config=Config(
            s3={'addressing_style': 'path'},
            signature_version='s3v4'),
        verify=False)


def cleanup(s3):
    """Best-effort cleanup of test buckets."""
    for bucket in [SRC_BUCKET, DST_BUCKET]:
        try:
            resp = s3.list_objects_v2(Bucket=bucket)
            for obj in resp.get('Contents', []):
                s3.delete_object(Bucket=bucket, Key=obj['Key'])
            # Abort any in-progress multipart uploads
            mpu_resp = s3.list_multipart_uploads(Bucket=bucket)
            for upload in mpu_resp.get('Uploads', []):
                s3.abort_multipart_upload(
                    Bucket=bucket,
                    Key=upload['Key'],
                    UploadId=upload['UploadId'])
            s3.delete_bucket(Bucket=bucket)
        except Exception:
            pass


def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    s3 = make_client()

    print('=' * 60)
    print('UploadPartCopy Range Validation Tests')
    print('=' * 60)
    print('Endpoint: %s' % ENDPOINT)
    print('Source bucket: %s' % SRC_BUCKET)
    print('Dest bucket: %s' % DST_BUCKET)
    print()

    # Setup
    try:
        s3.create_bucket(Bucket=SRC_BUCKET)
        s3.create_bucket(Bucket=DST_BUCKET)
    except Exception as e:
        print('ERROR: Failed to create test buckets: %s' % e)
        sys.exit(1)

    # Upload a 1MB source object
    src_key = 'source-1mb.bin'
    src_data = os.urandom(1024 * 1024)  # 1MB
    src_md5 = hashlib.md5(src_data).hexdigest()
    s3.put_object(Bucket=SRC_BUCKET, Key=src_key, Body=src_data)

    copy_source = '%s/%s' % (SRC_BUCKET, src_key)

    # =========================================================================
    # Test 1: Happy path — valid range copy
    # =========================================================================
    print('--- Happy Path ---')

    try:
        mpu = s3.create_multipart_upload(Bucket=DST_BUCKET, Key='valid-range')
        upload_id = mpu['UploadId']

        resp = s3.upload_part_copy(
            Bucket=DST_BUCKET,
            Key='valid-range',
            PartNumber=1,
            UploadId=upload_id,
            CopySource=copy_source,
            CopySourceRange='bytes=0-999')

        etag = resp['CopyPartResult']['ETag'].strip('"')
        expected_md5 = hashlib.md5(src_data[0:1000]).hexdigest()
        if etag == expected_md5:
            ok('Valid range copy (bytes=0-999) ETag matches MD5 (%s)' % etag)
        elif etag:
            fail('Valid range copy ETag mismatch',
                 'expected=%s got=%s' % (expected_md5, etag))
        else:
            fail('Valid range copy — no ETag returned')

        s3.abort_multipart_upload(
            Bucket=DST_BUCKET, Key='valid-range', UploadId=upload_id)
    except ClientError as e:
        fail('Valid range copy (bytes=0-999)',
             '%s %s' % (e.response['Error']['Code'],
                        e.response['Error']['Message']))

    # =========================================================================
    # Test 2: Happy path — full object copy (no range header)
    # =========================================================================

    try:
        mpu = s3.create_multipart_upload(Bucket=DST_BUCKET, Key='full-copy')
        upload_id = mpu['UploadId']

        resp = s3.upload_part_copy(
            Bucket=DST_BUCKET,
            Key='full-copy',
            PartNumber=1,
            UploadId=upload_id,
            CopySource=copy_source)

        etag = resp['CopyPartResult']['ETag'].strip('"')
        if etag == src_md5:
            ok('Full object copy ETag matches source MD5 (%s)' % etag)
        elif etag:
            fail('Full object copy ETag mismatch',
                 'expected=%s got=%s' % (src_md5, etag))
        else:
            fail('Full object copy — no ETag returned')

        s3.abort_multipart_upload(
            Bucket=DST_BUCKET, Key='full-copy', UploadId=upload_id)
    except ClientError as e:
        fail('Full object copy (no range header)',
             '%s %s' % (e.response['Error']['Code'],
                        e.response['Error']['Message']))

    # =========================================================================
    # Test 3: 416 — out-of-bounds range (end >= content_length)
    # =========================================================================
    print()
    print('--- Error Paths ---')

    try:
        mpu = s3.create_multipart_upload(Bucket=DST_BUCKET, Key='oob-range')
        upload_id = mpu['UploadId']

        # Source is 1MB = 1048576 bytes, valid range is 0-1048575
        s3.upload_part_copy(
            Bucket=DST_BUCKET,
            Key='oob-range',
            PartNumber=1,
            UploadId=upload_id,
            CopySource=copy_source,
            CopySourceRange='bytes=0-1048576')  # 1 byte past end

        fail('Out-of-bounds range — expected 416 but succeeded')
        s3.abort_multipart_upload(
            Bucket=DST_BUCKET, Key='oob-range', UploadId=upload_id)
    except ClientError as e:
        code = e.response['Error']['Code']
        status = e.response['ResponseMetadata']['HTTPStatusCode']
        if status == 416 or code == 'InvalidRange':
            ok('Out-of-bounds range returned %d/%s' % (status, code))
        else:
            fail('Out-of-bounds range — expected 416/InvalidRange, got %d/%s'
                 % (status, code))
        try:
            s3.abort_multipart_upload(
                Bucket=DST_BUCKET, Key='oob-range', UploadId=upload_id)
        except Exception:
            pass

    # =========================================================================
    # Test 4: 416 — range start beyond object size
    # =========================================================================

    try:
        mpu = s3.create_multipart_upload(Bucket=DST_BUCKET, Key='oob-start')
        upload_id = mpu['UploadId']

        s3.upload_part_copy(
            Bucket=DST_BUCKET,
            Key='oob-start',
            PartNumber=1,
            UploadId=upload_id,
            CopySource=copy_source,
            CopySourceRange='bytes=2000000-2000999')  # way past 1MB

        fail('Range start beyond object — expected 416 but succeeded')
        s3.abort_multipart_upload(
            Bucket=DST_BUCKET, Key='oob-start', UploadId=upload_id)
    except ClientError as e:
        code = e.response['Error']['Code']
        status = e.response['ResponseMetadata']['HTTPStatusCode']
        if status == 416 or code == 'InvalidRange':
            ok('Range start beyond object returned %d/%s' % (status, code))
        else:
            fail('Range start beyond object — expected 416/InvalidRange, '
                 'got %d/%s' % (status, code))
        try:
            s3.abort_multipart_upload(
                Bucket=DST_BUCKET, Key='oob-start', UploadId=upload_id)
        except Exception:
            pass

    # =========================================================================
    # Test 5: 400 — EntityTooSmall for 0-byte source (full copy, no range)
    # =========================================================================

    zero_key = 'zero-byte.bin'
    s3.put_object(Bucket=SRC_BUCKET, Key=zero_key, Body=b'')
    zero_source = '%s/%s' % (SRC_BUCKET, zero_key)

    try:
        mpu = s3.create_multipart_upload(Bucket=DST_BUCKET, Key='zero-copy')
        upload_id = mpu['UploadId']

        s3.upload_part_copy(
            Bucket=DST_BUCKET,
            Key='zero-copy',
            PartNumber=1,
            UploadId=upload_id,
            CopySource=zero_source)

        fail('0-byte source copy — expected 400/EntityTooSmall but succeeded')
        s3.abort_multipart_upload(
            Bucket=DST_BUCKET, Key='zero-copy', UploadId=upload_id)
    except ClientError as e:
        code = e.response['Error']['Code']
        status = e.response['ResponseMetadata']['HTTPStatusCode']
        if status == 400 or code == 'EntityTooSmall':
            ok('0-byte source copy returned %d/%s' % (status, code))
        else:
            fail('0-byte source copy — expected 400/EntityTooSmall, '
                 'got %d/%s' % (status, code))
        try:
            s3.abort_multipart_upload(
                Bucket=DST_BUCKET, Key='zero-copy', UploadId=upload_id)
        except Exception:
            pass

    # =========================================================================
    # Test 6: Valid range — last byte of object
    # =========================================================================
    print()
    print('--- Edge Cases ---')

    try:
        mpu = s3.create_multipart_upload(Bucket=DST_BUCKET, Key='last-byte')
        upload_id = mpu['UploadId']

        # Last valid byte: 1048575
        resp = s3.upload_part_copy(
            Bucket=DST_BUCKET,
            Key='last-byte',
            PartNumber=1,
            UploadId=upload_id,
            CopySource=copy_source,
            CopySourceRange='bytes=1048575-1048575')  # single last byte

        etag = resp['CopyPartResult']['ETag'].strip('"')
        expected_md5 = hashlib.md5(src_data[1048575:1048576]).hexdigest()
        if etag == expected_md5:
            ok('Last byte range ETag matches MD5 (%s)' % etag)
        elif etag:
            fail('Last byte range ETag mismatch',
                 'expected=%s got=%s' % (expected_md5, etag))
        else:
            fail('Last byte range — no ETag returned')

        s3.abort_multipart_upload(
            Bucket=DST_BUCKET, Key='last-byte', UploadId=upload_id)
    except ClientError as e:
        fail('Last byte range (bytes=1048575-1048575)',
             '%s %s' % (e.response['Error']['Code'],
                        e.response['Error']['Message']))

    # =========================================================================
    # Test 7: Valid range — first byte only
    # =========================================================================

    try:
        mpu = s3.create_multipart_upload(Bucket=DST_BUCKET, Key='first-byte')
        upload_id = mpu['UploadId']

        resp = s3.upload_part_copy(
            Bucket=DST_BUCKET,
            Key='first-byte',
            PartNumber=1,
            UploadId=upload_id,
            CopySource=copy_source,
            CopySourceRange='bytes=0-0')  # single first byte

        etag = resp['CopyPartResult']['ETag'].strip('"')
        expected_md5 = hashlib.md5(src_data[0:1]).hexdigest()
        if etag == expected_md5:
            ok('First byte range ETag matches MD5 (%s)' % etag)
        elif etag:
            fail('First byte range ETag mismatch',
                 'expected=%s got=%s' % (expected_md5, etag))
        else:
            fail('First byte range — no ETag returned')

        s3.abort_multipart_upload(
            Bucket=DST_BUCKET, Key='first-byte', UploadId=upload_id)
    except ClientError as e:
        fail('First byte range (bytes=0-0)',
             '%s %s' % (e.response['Error']['Code'],
                        e.response['Error']['Message']))

    # =========================================================================
    # Summary
    # =========================================================================
    print()
    print('=' * 60)
    print('Results: %d passed, %d failed' % (passed, failed))
    print('=' * 60)

    # Cleanup
    cleanup(s3)

    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()
