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
    # Test 2: Happy path - full object copy (no range header)
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
    # Test 3: 416 - out-of-bounds range (end >= content_length)
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
    # Test 4: 416 - range start beyond object size
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
    # Test 5: 400 - EntityTooSmall for 0-byte source (full copy, no range)
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
    # Test 6: Valid range - last byte of object
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
    # Test 7: Valid range -  first byte only
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
            fail('First byte range - no ETag returned')

        s3.abort_multipart_upload(
            Bucket=DST_BUCKET, Key='first-byte', UploadId=upload_id)
    except ClientError as e:
        fail('First byte range (bytes=0-0)',
             '%s %s' % (e.response['Error']['Code'],
                        e.response['Error']['Message']))

    # =========================================================================
    # Test 8: UploadPartCopy - overlapping parts
    #   Part 1: bytes=0-524288          (0 to 512KiB)
    #   Part 2: bytes=262144-804864     (256KiB to 786KiB, overlaps part 1)
    #   Part 3: bytes=804864-1048575    (786KiB to 1MiB-1, overlaps part 2
    #                                    at byte 804864)
    # All individual UploadPartCopy calls should succeed (valid ranges).
    # CompleteMultipartUpload should fail,  parts are < 5MB minimum.
    # =========================================================================
    print()
    print('--- Overlapping  UploadPartCopy ---')

    try:
        mpu = s3.create_multipart_upload(Bucket=DST_BUCKET,
                                         Key='overlap-parts')
        upload_id = mpu['UploadId']
        parts = []

        ranges = [
            (1, 'bytes=0-524288'),         # 0 to 512KiB
            (2, 'bytes=262144-804864'),     # 256KiB to 786KiB
            (3, 'bytes=804864-1048575'),    # 786KiB to 1MiB-1
        ]
        slices = [
            src_data[0:524289],
            src_data[262144:804865],
            src_data[804864:1048576],
        ]

        all_ok = True
        for i, (part_num, rng) in enumerate(ranges):
            resp = s3.upload_part_copy(
                Bucket=DST_BUCKET,
                Key='overlap-parts',
                PartNumber=part_num,
                UploadId=upload_id,
                CopySource=copy_source,
                CopySourceRange=rng)
            etag = resp['CopyPartResult']['ETag'].strip('"')
            expected = hashlib.md5(slices[i]).hexdigest()
            if etag != expected:
                fail('Overlapping parts — part %d ETag mismatch' % part_num,
                     'range=%s expected=%s got=%s' % (rng, expected, etag))
                all_ok = False

        if all_ok:
            ok('Overlapping parts — all 3 UploadPartCopy calls succeeded '
               'with correct ETags')

        # Try to complete — should fail with EntityTooSmall (parts < 5MB)
        parts = []
        for i, (part_num, rng) in enumerate(ranges):
            resp = s3.upload_part_copy(
                Bucket=DST_BUCKET,
                Key='overlap-parts',
                PartNumber=part_num,
                UploadId=upload_id,
                CopySource=copy_source,
                CopySourceRange=rng)
            parts.append({
                'PartNumber': part_num,
                'ETag': resp['CopyPartResult']['ETag']
            })

        try:
            s3.complete_multipart_upload(
                Bucket=DST_BUCKET,
                Key='overlap-parts',
                UploadId=upload_id,
                MultipartUpload={'Parts': parts})
            fail('Overlapping parts — CompleteMultipartUpload should have '
                 'failed (parts < 5MB)')
            # Clean up if it somehow succeeded
            s3.delete_object(Bucket=DST_BUCKET, Key='overlap-parts')
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'EntityTooSmall':
                ok('Overlapping parts — CompleteMultipartUpload correctly '
                   'returned EntityTooSmall')
            else:
                fail('Overlapping parts — expected EntityTooSmall, got %s'
                     % code)

        s3.abort_multipart_upload(
            Bucket=DST_BUCKET, Key='overlap-parts', UploadId=upload_id)
    except ClientError as e:
        fail('Overlapping parts',
             '%s %s' % (e.response['Error']['Code'],
                        e.response['Error']['Message']))

    # =========================================================================
    # Test 9: UploadPartCopy MPU - broken middle (range exceeds source object)
    #   Part 1: bytes=0-524288          (0 to 512KiB)
    #   Part 2: bytes=524288-1048577    (512KiB to 1MiB+1, 2 bytes past end)
    #
    # Part 2 should fail with 416 InvalidRange.
    # =========================================================================

    try:
        mpu = s3.create_multipart_upload(Bucket=DST_BUCKET,
                                         Key='broken-middle')
        upload_id = mpu['UploadId']

        # Part 1 should succeed
        resp = s3.upload_part_copy(
            Bucket=DST_BUCKET,
            Key='broken-middle',
            PartNumber=1,
            UploadId=upload_id,
            CopySource=copy_source,
            CopySourceRange='bytes=0-524288')
        etag = resp['CopyPartResult']['ETag'].strip('"')
        expected = hashlib.md5(src_data[0:524289]).hexdigest()
        if etag == expected:
            ok('Broken middle — part 1 (bytes=0-524288) succeeded with '
               'correct ETag')
        else:
            fail('Broken middle — part 1 ETag mismatch',
                 'expected=%s got=%s' % (expected, etag))

        # Part 2 range exceeds source — should fail with 416
        try:
            s3.upload_part_copy(
                Bucket=DST_BUCKET,
                Key='broken-middle',
                PartNumber=2,
                UploadId=upload_id,
                CopySource=copy_source,
                CopySourceRange='bytes=524288-1048577')
            fail('Broken middle — part 2 should have failed (range exceeds '
                 'source object)')
        except ClientError as e:
            code = e.response['Error']['Code']
            status = e.response['ResponseMetadata']['HTTPStatusCode']
            if status == 416 or code == 'InvalidRange':
                ok('Broken middle — part 2 (bytes=524288-1048577) correctly '
                   'returned %d/%s' % (status, code))
            else:
                fail('Broken middle — part 2 expected 416/InvalidRange, '
                     'got %d/%s' % (status, code))

        s3.abort_multipart_upload(
            Bucket=DST_BUCKET, Key='broken-middle', UploadId=upload_id)
    except ClientError as e:
        fail('Broken middle',
             '%s %s' % (e.response['Error']['Code'],
                        e.response['Error']['Message']))

    # =========================================================================
    # Test 10: Overlapping MPU - out of order but valid part ranges
    #   Part 1: bytes=262144-804863     (256KiB to 786KiB-1)
    #   Part 2: bytes=804864-1048575    (786KiB to 1MiB-1)
    #   Part 3: bytes=0-262143          (0 to 256KiB-1)
    #
    # Ranges are non-overlapping and together cover the full 1MiB source,
    # but parts are numbered so the byte order is scrambled (middle, end,
    # start).  All UploadPartCopy calls should succeed.
    # CompleteMultipartUpload fails — parts < 5MB.
    #
    # NOTE:
    #  The final object is totally scrambled, is responsability of
    #  the users to upload the parts using the correct ranges and parts.
    # =========================================================================

    try:
        mpu = s3.create_multipart_upload(Bucket=DST_BUCKET,
                                         Key='ooo-good')
        upload_id = mpu['UploadId']

        ranges = [
            (1, 'bytes=262144-804863'),    # middle: 256KiB to 786KiB-1
            (2, 'bytes=804864-1048575'),   # end:    786KiB to 1MiB-1
            (3, 'bytes=0-262143'),         # start:  0 to 256KiB-1
        ]
        slices = [
            src_data[262144:804864],
            src_data[804864:1048576],
            src_data[0:262144],
        ]

        all_ok = True
        parts = []
        for i, (part_num, rng) in enumerate(ranges):
            resp = s3.upload_part_copy(
                Bucket=DST_BUCKET,
                Key='ooo-good',
                PartNumber=part_num,
                UploadId=upload_id,
                CopySource=copy_source,
                CopySourceRange=rng)
            etag = resp['CopyPartResult']['ETag'].strip('"')
            expected = hashlib.md5(slices[i]).hexdigest()
            parts.append({
                'PartNumber': part_num,
                'ETag': resp['CopyPartResult']['ETag']
            })
            if etag != expected:
                fail('Out-of-order good — part %d ETag mismatch' % part_num,
                     'range=%s expected=%s got=%s' % (rng, expected, etag))
                all_ok = False

        if all_ok:
            ok('Out-of-order good — all 3 UploadPartCopy calls succeeded '
               'with correct ETags')

        # Try to complete — should fail with EntityTooSmall
        try:
            s3.complete_multipart_upload(
                Bucket=DST_BUCKET,
                Key='ooo-good',
                UploadId=upload_id,
                MultipartUpload={'Parts': parts})
            fail('Out-of-order good — CompleteMultipartUpload should have '
                 'failed (parts < 5MB)')
            s3.delete_object(Bucket=DST_BUCKET, Key='ooo-good')
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'EntityTooSmall':
                ok('Out-of-order good — CompleteMultipartUpload correctly '
                   'returned EntityTooSmall')
            else:
                fail('Out-of-order good — expected EntityTooSmall, got %s'
                     % code)

        try:
            s3.abort_multipart_upload(
                Bucket=DST_BUCKET, Key='ooo-good', UploadId=upload_id)
        except Exception:
            pass
    except ClientError as e:
        fail('Out-of-order good',
             '%s %s' % (e.response['Error']['Code'],
                        e.response['Error']['Message']))

    # =========================================================================
    # Test 11: Overlapping MPU - out of order with overlap
    #   Part 1: bytes=262144-804864     (256KiB to 786KiB, overlaps parts 2&3)
    #   Part 2: bytes=804864-1048575    (786KiB to 1MiB-1, overlaps part 1
    #                                    at byte 804864)
    #   Part 3: bytes=0-262144          (0 to 256KiB, overlaps part 1
    #                                    at byte 262144)
    # All UploadPartCopy calls should succeed (each range is valid).
    # CompleteMultipartUpload fails as parts < 5MB.
    # =========================================================================

    try:
        mpu = s3.create_multipart_upload(Bucket=DST_BUCKET,
                                         Key='ooo-overlap')
        upload_id = mpu['UploadId']

        ranges = [
            (1, 'bytes=262144-804864'),    # middle chunk, overlaps at edges
            (2, 'bytes=804864-1048575'),   # tail, overlaps part 1 at 804864
            (3, 'bytes=0-262144'),         # head, overlaps part 1 at 262144
        ]
        slices = [
            src_data[262144:804865],
            src_data[804864:1048576],
            src_data[0:262145],
        ]

        all_ok = True
        parts = []
        for i, (part_num, rng) in enumerate(ranges):
            resp = s3.upload_part_copy(
                Bucket=DST_BUCKET,
                Key='ooo-overlap',
                PartNumber=part_num,
                UploadId=upload_id,
                CopySource=copy_source,
                CopySourceRange=rng)
            etag = resp['CopyPartResult']['ETag'].strip('"')
            expected = hashlib.md5(slices[i]).hexdigest()
            parts.append({
                'PartNumber': part_num,
                'ETag': resp['CopyPartResult']['ETag']
            })
            if etag != expected:
                fail('Out-of-order overlap — part %d ETag mismatch'
                     % part_num,
                     'range=%s expected=%s got=%s' % (rng, expected, etag))
                all_ok = False

        if all_ok:
            ok('Out-of-order overlap — all 3 UploadPartCopy calls succeeded '
               'with correct ETags')

        # Try to complete — should fail with EntityTooSmall
        try:
            s3.complete_multipart_upload(
                Bucket=DST_BUCKET,
                Key='ooo-overlap',
                UploadId=upload_id,
                MultipartUpload={'Parts': parts})
            fail('Out-of-order overlap — CompleteMultipartUpload should have '
                 'failed (parts < 5MB)')
            s3.delete_object(Bucket=DST_BUCKET, Key='ooo-overlap')
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'EntityTooSmall':
                ok('Out-of-order overlap — CompleteMultipartUpload correctly '
                   'returned EntityTooSmall')
            else:
                fail('Out-of-order overlap — expected EntityTooSmall, got %s'
                     % code)

        try:
            s3.abort_multipart_upload(
                Bucket=DST_BUCKET, Key='ooo-overlap', UploadId=upload_id)
        except Exception:
            pass
    except ClientError as e:
        fail('Out-of-order overlap',
             '%s %s' % (e.response['Error']['Code'],
                        e.response['Error']['Message']))

    # =========================================================================
    # Test 12: Completable overlapping MPU large enough to pass 5MB minimum
    #
    # Uses a 20MiB source object.  Three parts with deliberate overlaps:
    #   Part 1: bytes=0-7340031            (0 to 7MiB-1,   7MiB)
    #   Part 2: bytes=5242880-15728639     (5MiB to 15MiB-1, 10MiB,
    #                                       overlaps part 1 by 2MiB)
    #   Part 3: bytes=14680064-20971519    (14MiB to 20MiB-1, 6MiB,
    #                                       overlaps part 2 by 1MiB)
    #
    # Each non-last part is >= 5MB so CompleteMultipartUpload should succeed.
    # The assembled object = src[0:7M] + src[5M:15M] + src[14M:20M] = 23MiB.
    # We download it and verify byte-for-byte content.
    # =========================================================================
    print()
    print('--- Completable Overlapping MPU (20MiB source) ---')

    MiB = 1024 * 1024
    big_key = 'source-20mb.bin'
    big_data = os.urandom(20 * MiB)
    s3.put_object(Bucket=SRC_BUCKET, Key=big_key, Body=big_data)
    big_source = '%s/%s' % (SRC_BUCKET, big_key)

    try:
        mpu = s3.create_multipart_upload(Bucket=DST_BUCKET,
                                         Key='big-overlap')
        upload_id = mpu['UploadId']

        # Part definitions: (part_num, range_str, python_slice)
        part_defs = [
            (1, 'bytes=0-7340031',
             big_data[0:7340032]),               # 0 to 7MiB-1
            (2, 'bytes=5242880-15728639',
             big_data[5242880:15728640]),         # 5MiB to 15MiB-1
            (3, 'bytes=14680064-20971519',
             big_data[14680064:20971520]),        # 14MiB to 20MiB-1
        ]

        parts = []
        all_ok = True
        for part_num, rng, expected_data in part_defs:
            resp = s3.upload_part_copy(
                Bucket=DST_BUCKET,
                Key='big-overlap',
                PartNumber=part_num,
                UploadId=upload_id,
                CopySource=big_source,
                CopySourceRange=rng)
            etag = resp['CopyPartResult']['ETag'].strip('"')
            expected_md5 = hashlib.md5(expected_data).hexdigest()
            parts.append({
                'PartNumber': part_num,
                'ETag': resp['CopyPartResult']['ETag']
            })
            sz = len(expected_data)
            if etag != expected_md5:
                fail('Big overlap — part %d (%s, %d bytes) ETag mismatch'
                     % (part_num, rng, sz),
                     'expected=%s got=%s' % (expected_md5, etag))
                all_ok = False

        if all_ok:
            ok('Big overlap — all 3 UploadPartCopy calls succeeded with '
               'correct ETags (7MiB + 10MiB + 6MiB)')

        # Complete — should succeed since parts 1 (7MiB) and 2 (10MiB) >= 5MB
        s3.complete_multipart_upload(
            Bucket=DST_BUCKET,
            Key='big-overlap',
            UploadId=upload_id,
            MultipartUpload={'Parts': parts})
        ok('Big overlap — CompleteMultipartUpload succeeded')

        # Download and verify assembled content
        resp = s3.get_object(Bucket=DST_BUCKET, Key='big-overlap')
        assembled = resp['Body'].read()

        # Expected: part1 + part2 + part3 concatenated
        expected_assembled = (big_data[0:7340032] +
                              big_data[5242880:15728640] +
                              big_data[14680064:20971520])

        if len(assembled) == len(expected_assembled):
            ok('Big overlap — assembled object size correct (%d bytes)'
               % len(assembled))
        else:
            fail('Big overlap — size mismatch',
                 'expected=%d got=%d' % (len(expected_assembled),
                                         len(assembled)))

        if assembled == expected_assembled:
            ok('Big overlap — assembled object content matches expected '
               'byte-for-byte (overlapping source ranges concatenated)')
        else:
            # Find first mismatch offset for debugging
            for off in range(min(len(assembled), len(expected_assembled))):
                if assembled[off] != expected_assembled[off]:
                    fail('Big overlap — content mismatch at offset %d' % off)
                    break
            else:
                fail('Big overlap — content mismatch (length differs)')

        s3.delete_object(Bucket=DST_BUCKET, Key='big-overlap')
    except ClientError as e:
        fail('Big overlap',
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
