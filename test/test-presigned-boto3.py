#!/usr/bin/env python3
"""
Simple boto3 presigned URL test script for debugging signature issues.
"""

import boto3
import os
import requests
from botocore.config import Config
import urllib3

# Disable SSL warnings for localhost testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration from environment
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID', 'your access key id')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY', 'your secret key')
S3_ENDPOINT = os.environ.get('S3_ENDPOINT', 'https://localhost:8080')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

# Test configuration
BUCKET = "test-bucket"
OBJECT = "test-object.txt"
TEST_CONTENT = b"Hello from boto3 presigned URL test!"

def main():
    print(f"Testing presigned URLs with boto3")
    print(f"Endpoint: {S3_ENDPOINT}")
    print(f"Region: {AWS_REGION}")
    print(f"Access Key: {AWS_ACCESS_KEY_ID[:10]}...")
    print()

    # Create S3 client
    s3 = boto3.client(
        's3',
        endpoint_url=S3_ENDPOINT,
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        verify=False,
        config=Config(
            s3={"addressing_style": "path"},
            signature_version="s3v4"
        )
    )

    try:
        # Create bucket if needed
        try:
            s3.head_bucket(Bucket=BUCKET)
            print(f"✓ Bucket {BUCKET} exists")
        except:
            s3.create_bucket(Bucket=BUCKET)
            print(f"✓ Created bucket {BUCKET}")

        # Test PUT presigned URL
        print("\n=== Testing PUT presigned URL ===")
        put_url = s3.generate_presigned_url(
            'put_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT},
            ExpiresIn=300
        )
        
        print(f"PUT URL: {put_url}")
        
        # Extract signature for comparison
        if 'X-Amz-Signature=' in put_url:
            sig_start = put_url.find('X-Amz-Signature=') + len('X-Amz-Signature=')
            sig_end = put_url.find('&', sig_start)
            if sig_end == -1:
                sig_end = len(put_url)
            signature = put_url[sig_start:sig_end]
            print(f"PUT Signature: {signature}")

        # Test the PUT URL
        response = requests.put(put_url, data=TEST_CONTENT, verify=False)
        print(f"PUT Response: {response.status_code}")
        
        if response.status_code == 200:
            print("✓ PUT presigned URL works!")
        else:
            print(f"✗ PUT failed: {response.text}")

        # Test GET presigned URL
        print("\n=== Testing GET presigned URL ===")
        get_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT},
            ExpiresIn=300
        )
        
        print(f"GET URL: {get_url}")
        
        # Extract signature for comparison
        if 'X-Amz-Signature=' in get_url:
            sig_start = get_url.find('X-Amz-Signature=') + len('X-Amz-Signature=')
            sig_end = get_url.find('&', sig_start)
            if sig_end == -1:
                sig_end = len(get_url)
            signature = get_url[sig_start:sig_end]
            print(f"GET Signature: {signature}")

        # Test the GET URL
        response = requests.get(get_url, verify=False)
        print(f"GET Response: {response.status_code}")
        
        if response.status_code == 200:
            content = response.content
            if content == TEST_CONTENT:
                print("✓ GET presigned URL works and content matches!")
            else:
                print(f"✗ Content mismatch: expected {TEST_CONTENT}, got {content}")
        else:
            print(f"✗ GET failed: {response.text}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
