#!/usr/bin/env python3
"""
Debug script to isolate the multipart upload issue with boto3.
This will test just the initiate step with detailed logging.
"""

import boto3
import logging
import time
from botocore.config import Config
from botocore.exceptions import ClientError

# Enable debug logging for boto3
logging.basicConfig(level=logging.DEBUG)
boto3.set_stream_logger('botocore.endpoint', logging.DEBUG)
boto3.set_stream_logger('urllib3.connectionpool', logging.DEBUG)

def test_upload_part():
    """Test the upload part step that's failing"""
    
    client = boto3.client(
        's3',
        endpoint_url='https://localhost:8080',
        region_name='us-east-1',
        verify=False,
        config=Config(
            s3={"addressing_style": "path"},
            signature_version="s3v4"
        )
    )
    
    bucket = 'public'  # Use existing bucket
    key = 'test-mpu-debug.bin'
    
    try:
        print("=== Testing Full Multipart Upload Flow ===")
        print(f"Endpoint: https://localhost:8080")
        print(f"Bucket: {bucket}")
        print(f"Key: {key}")
        print()
        
        # Step 1: Initiate
        print("1. Initiating multipart upload...")
        response = client.create_multipart_upload(Bucket=bucket, Key=key)
        upload_id = response['UploadId']
        print(f"SUCCESS - Upload ID: {upload_id}")
        print()
        
        # Step 2: Upload Part (this is likely where it fails)
        print("2. Uploading part 1...")
        part_data = b"A" * (5 * 1024 * 1024)  # 5MB
        expected_url = f"https://localhost:8080/{bucket}/{key}?partNumber=1&uploadId={upload_id}"
        print(f"Expected URL: {expected_url}")
        
        part_response = client.upload_part(
            Bucket=bucket,
            Key=key,
            PartNumber=1,
            UploadId=upload_id,
            Body=part_data
        )
        etag1 = part_response['ETag']
        print(f"SUCCESS - Part 1 ETag: {etag1}")
        print()
        
        # Step 3: Complete
        print("3. Completing multipart upload...")
        expected_complete_url = f"https://localhost:8080/{bucket}/{key}?uploadId={upload_id}"
        print(f"Expected complete URL: {expected_complete_url}")
        
        client.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                'Parts': [
                    {'ETag': etag1, 'PartNumber': 1}
                ]
            }
        )
        print("SUCCESS - Multipart upload completed!")
        
        # Verify the object was assembled (with retry for background assembly)
        print("4. Verifying object availability...")
        max_retries = 30  # Up to 30 seconds
        retry_interval = 1  # 1 second between retries
        
        for attempt in range(max_retries):
            try:
                head_response = client.head_object(Bucket=bucket, Key=key)
                expected_size = len(part_data)
                actual_size = head_response.get('ContentLength', 0)
                
                if actual_size == expected_size:
                    print(f"SUCCESS - Object available after {attempt} retries")
                    print(f"Object size: {actual_size} bytes (expected {expected_size})")
                    break
                else:
                    print(f"Attempt {attempt + 1}: Size mismatch {actual_size} != {expected_size}")
                    
            except ClientError as e:
                code = e.response.get('Error', {}).get('Code', '')
                if code in ('NoSuchKey', '404'):
                    if attempt < max_retries - 1:
                        print(f"Attempt {attempt + 1}: Object not yet available, retrying...")
                        time.sleep(retry_interval)
                        continue
                    else:
                        print(f"TIMEOUT - Object not available after {max_retries} seconds")
                        break
                else:
                    raise
            time.sleep(retry_interval)
        else:
            print(f"Size verification failed after {max_retries} retries")
        
        # Clean up the completed object
        try:
            client.delete_object(Bucket=bucket, Key=key)
            print("Cleanup: deleted object")
        except Exception as e:
            print(f"Cleanup failed: {e}")
            
    except ClientError as e:
        print("FAILED!")
        print(f"Error Code: {e.response['Error']['Code']}")
        print(f"Error Message: {e.response['Error']['Message']}")
        print(f"HTTP Status: {e.response['ResponseMetadata']['HTTPStatusCode']}")
        
        # Print request details
        operation_name = e.operation_name
        print(f"Operation: {operation_name}")
        
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    test_upload_part()