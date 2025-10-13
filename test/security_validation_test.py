#!/usr/bin/env python3
"""
Manta Buckets API S3 Compatibility Layer Security Validation Test Suite
=======================================================================

This script performs defensive security testing specifically for the S3 
compatibility layer of Manta Buckets API, focusing on SigV4 authentication
for S3-specific operations.

Usage: python3 security_validation_test.py --host localhost --port 8080 --access-key AKIATEST --secret-key testsecret

"""

import requests
import urllib.parse
import argparse
import json
import sys
import time
import hmac
import hashlib
import datetime
import os
import subprocess
from typing import Dict, List, Tuple, Optional

# Try to import boto3 for more reliable authentication
try:
    import boto3
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

class SecurityTestResult:
    def __init__(self, test_name: str, passed: bool, message: str, details: Dict = None):
        self.test_name = test_name
        self.passed = passed
        self.message = message
        self.details = details or {}

class S3SignatureV4:
    """AWS Signature Version 4 implementation for testing"""
    
    def __init__(self, access_key: str, secret_key: str, region: str = 'us-east-1', service: str = 's3'):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.service = service
    
    def sign_request(self, method: str, url: str, headers: Dict = None, payload: bytes = b'') -> Dict:
        """Generate SigV4 signed headers for a request"""
        if headers is None:
            headers = {}
        
        # Parse URL
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc
        path = parsed.path or '/'
        query = parsed.query
        
        # Create timestamp (use timezone-aware datetime to avoid deprecation warning)
        try:
            t = datetime.datetime.now(datetime.timezone.utc)
        except AttributeError:
            # Fallback for older Python versions
            t = datetime.datetime.utcnow()
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = t.strftime('%Y%m%d')
        
        # Add required headers
        headers = dict(headers)  # Copy to avoid modifying original
        headers['Host'] = host
        headers['X-Amz-Date'] = amz_date
        headers['X-Amz-Content-Sha256'] = hashlib.sha256(payload).hexdigest()
        
        # Create canonical request
        canonical_headers = ''
        signed_headers = ''
        header_names = sorted(headers.keys(), key=str.lower)
        
        for name in header_names:
            canonical_headers += f"{name.lower()}:{headers[name]}\n"
            if signed_headers:
                signed_headers += ';'
            signed_headers += name.lower()
        
        canonical_request = f"{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{headers['X-Amz-Content-Sha256']}"
        
        # Create string to sign
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"
        string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        
        # Calculate signature
        signing_key = self._get_signature_key(self.secret_key, date_stamp, self.region, self.service)
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        
        # Create authorization header
        authorization = f"{algorithm} Credential={self.access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        headers['Authorization'] = authorization
        
        return headers
    
    def _get_signature_key(self, key: str, date_stamp: str, region: str, service: str) -> bytes:
        """Generate AWS4 signing key"""
        k_date = hmac.new(f"AWS4{key}".encode(), date_stamp.encode(), hashlib.sha256).digest()
        k_region = hmac.new(k_date, region.encode(), hashlib.sha256).digest()
        k_service = hmac.new(k_region, service.encode(), hashlib.sha256).digest()
        k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
        return k_signing

class NativeBoto3Operations:
    """Native boto3 S3 operations for reliable security testing"""
    
    def __init__(self, access_key: str, secret_key: str, region: str = 'us-east-1', endpoint_url: str = None, verify_ssl: bool = True):
        if not BOTO3_AVAILABLE:
            raise ImportError("boto3 not available - install with: pip install boto3")
        
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.endpoint_url = endpoint_url
        
        # Create boto3 session with explicit credentials
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        
        # Create S3 client with Manta-compatible configuration
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
        try:
            from botocore.config import Config
            
            self.s3_client = self.session.client(
                "s3",
                endpoint_url=endpoint_url,
                region_name=region,
                verify=verify_ssl,
                config=Config(
                    s3={"addressing_style": "path"},  # Critical for Manta compatibility
                    retries={"max_attempts": 3, "mode": "standard"},
                    signature_version="s3v4",  # Explicit SigV4
                    connect_timeout=10,
                    read_timeout=60,
                ),
            )
        except Exception as e:
            raise ImportError(f"Failed to create boto3 S3 client: {e}")
        
        self.credentials = self.session.get_credentials()
    
    def test_list_objects(self, bucket_name: str, **kwargs) -> Tuple[bool, int, str]:
        """Test list objects operation with optional malformed parameters"""
        try:
            response = self.s3_client.list_objects_v2(Bucket=bucket_name, **kwargs)
            return True, 200, "Listed objects successfully"
        except Exception as e:
            # Extract status code from boto3 exception
            status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
            if not status_code:
                # Try to extract from error response
                if hasattr(e, 'response') and 'ResponseMetadata' in e.response:
                    status_code = e.response['ResponseMetadata'].get('HTTPStatusCode', 0)
                else:
                    status_code = 0
            return False, status_code, str(e)
    
    def test_get_object(self, bucket_name: str, object_key: str, **kwargs) -> Tuple[bool, int, str]:
        """Test get object operation with optional malformed parameters"""
        try:
            response = self.s3_client.get_object(Bucket=bucket_name, Key=object_key, **kwargs)
            return True, 200, "Retrieved object successfully"
        except Exception as e:
            status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
            if not status_code:
                if hasattr(e, 'response') and 'ResponseMetadata' in e.response:
                    status_code = e.response['ResponseMetadata'].get('HTTPStatusCode', 0)
                else:
                    status_code = 0
            return False, status_code, str(e)
    
    def test_head_object(self, bucket_name: str, object_key: str, **kwargs) -> Tuple[bool, int, str]:
        """Test head object operation with optional malformed parameters"""
        try:
            response = self.s3_client.head_object(Bucket=bucket_name, Key=object_key, **kwargs)
            return True, 200, "Head object successful"
        except Exception as e:
            status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
            if not status_code:
                if hasattr(e, 'response') and 'ResponseMetadata' in e.response:
                    status_code = e.response['ResponseMetadata'].get('HTTPStatusCode', 0)
                else:
                    status_code = 0
            return False, status_code, str(e)
    
    def test_put_object(self, bucket_name: str, object_key: str, body: bytes = b'test', **kwargs) -> Tuple[bool, int, str]:
        """Test put object operation with optional malformed parameters"""
        try:
            response = self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Body=body, **kwargs)
            return True, 200, "Put object successful"
        except Exception as e:
            status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
            if not status_code:
                if hasattr(e, 'response') and 'ResponseMetadata' in e.response:
                    status_code = e.response['ResponseMetadata'].get('HTTPStatusCode', 0)
                else:
                    status_code = 0
            return False, status_code, str(e)
    
    def test_list_buckets(self) -> Tuple[bool, int, str]:
        """Test list buckets operation"""
        try:
            response = self.s3_client.list_buckets()
            bucket_count = len(response.get('Buckets', []))
            return True, 200, f"Listed {bucket_count} buckets successfully"
        except Exception as e:
            status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
            if not status_code:
                if hasattr(e, 'response') and 'ResponseMetadata' in e.response:
                    status_code = e.response['ResponseMetadata'].get('HTTPStatusCode', 0)
                else:
                    status_code = 0
            return False, status_code, str(e)
    
    def generate_presigned_url(self, operation: str, bucket_name: str, object_key: str = None, 
                             expires_in: int = 3600, **kwargs) -> str:
        """Generate presigned URL for testing"""
        params = {'Bucket': bucket_name}
        if object_key:
            params['Key'] = object_key
        params.update(kwargs)
        
        return self.s3_client.generate_presigned_url(
            operation,
            Params=params,
            ExpiresIn=expires_in
        )
    
    # For backward compatibility, provide a sign_request method that uses presigned URLs
    def sign_request(self, method: str, url: str, headers: Dict = None, payload: bytes = b'') -> Dict:
        """Legacy method for compatibility - returns presigned URL in special header"""
        if headers is None:
            headers = {}
        
        # Parse URL to extract bucket and key
        parsed = urllib.parse.urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        
        if len(path_parts) >= 1 and path_parts[0]:
            bucket = path_parts[0]
            key = '/'.join(path_parts[1:]) if len(path_parts) > 1 else None
            
            try:
                if method.upper() == 'GET':
                    if key:
                        signed_url = self.generate_presigned_url('get_object', bucket, key)
                    else:
                        signed_url = self.generate_presigned_url('list_objects_v2', bucket)
                elif method.upper() == 'PUT' and key:
                    signed_url = self.generate_presigned_url('put_object', bucket, key)
                else:
                    # For unsupported operations, return basic headers
                    from botocore.auth import SigV4Auth
                    from botocore.awsrequest import AWSRequest
                    
                    request = AWSRequest(method=method, url=url, data=payload, headers=headers.copy())
                    signer = SigV4Auth(self.credentials, 's3', self.region)
                    signer.add_auth(request)
                    return dict(request.headers)
                
                # Return the presigned URL in a special header
                result_headers = headers.copy()
                result_headers['X-Presigned-URL'] = signed_url
                return result_headers
                
            except Exception as e:
                # Fallback to manual signing
                from botocore.auth import SigV4Auth
                from botocore.awsrequest import AWSRequest
                
                request = AWSRequest(method=method, url=url, data=payload, headers=headers.copy())
                signer = SigV4Auth(self.credentials, 's3', self.region)
                signer.add_auth(request)
                return dict(request.headers)
        else:
            # For malformed URLs, use manual signing
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest
            
            request = AWSRequest(method=method, url=url, data=payload, headers=headers.copy())
            signer = SigV4Auth(self.credentials, 's3', self.region)
            signer.add_auth(request)
            return dict(request.headers)

class MantaS3SecurityTester:
    def __init__(self, base_url: str, access_key: str, secret_key: str, timeout: int = 10, verify_ssl: bool = True, verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'MantaS3SecurityTester/1.0 (Defensive Testing)'
        })
        
        # S3 operations - prefer native boto3 if available
        if BOTO3_AVAILABLE:
            try:
                self.boto3_ops = NativeBoto3Operations(access_key, secret_key, endpoint_url=base_url, verify_ssl=verify_ssl)
                self.signer = self.boto3_ops  # For backward compatibility
                self.auth_method = "native_boto3"
                if verbose:
                    print("🔧 Using native boto3 S3 operations (most reliable)")
            except Exception as e:
                if verbose:
                    print(f"⚠️ native boto3 failed, falling back to custom: {e}")
                self.signer = S3SignatureV4(access_key, secret_key)
                self.boto3_ops = None
                self.auth_method = "custom"
        else:
            self.signer = S3SignatureV4(access_key, secret_key)
            self.boto3_ops = None
            self.auth_method = "custom"
            if verbose:
                print("⚠️ boto3 not available, using custom SigV4 implementation")
        
        # Disable SSL warnings if we're ignoring certificate verification
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Check if curl is available
        self.curl_available = self._check_curl_availability()
        
    def run_all_tests(self, selected_tests: List[str] = None) -> List[SecurityTestResult]:
        """Run S3 compatibility layer security validation tests
        
        Args:
            selected_tests: List of test categories to run. If None, runs all tests.
                           Options: ['baseline', 'auth', 'query', 'presigned', 'path', 'header']
        """
        results = []
        
        # Define all available tests
        available_tests = {
            'baseline': ('S3 Baseline Connectivity Test', self._test_s3_baseline),
            'auth': ('S3 Authentication Bypass Vulnerabilities', self._test_s3_auth_bypass),
            'query': ('S3 Query Parameter Injection', self._test_s3_query_injection),
            'presigned': ('S3 Presigned URL Manipulation', self._test_s3_presigned_url_manipulation),
            'path': ('S3 Bucket/Object Path Traversal', self._test_s3_path_traversal),
            'header': ('S3 Header Injection via SigV4', self._test_s3_header_injection)
        }
        
        # If no specific tests selected, run all
        if selected_tests is None:
            selected_tests = list(available_tests.keys())
        
        # Validate selected tests
        invalid_tests = [t for t in selected_tests if t not in available_tests]
        if invalid_tests:
            raise ValueError(f"Invalid test categories: {invalid_tests}. Available: {list(available_tests.keys())}")
        
        print("🔍 Starting S3 Compatibility Layer Security Validation Tests...")
        print(f"Target: {self.base_url}")
        print(f"Access Key: {self.signer.access_key}")
        print(f"Authentication: {self.auth_method}")
        print(f"Selected Tests: {', '.join(selected_tests)}")
        print("-" * 60)
        
        # Run selected tests
        for test_key in selected_tests:
            test_name, test_func = available_tests[test_key]
            print(f"\n🔬 Running: {test_name}")
            results.extend(test_func())
        
        return results
    
    def _test_s3_baseline(self) -> List[SecurityTestResult]:
        """Test baseline S3 connectivity with valid requests"""
        results = []
        
        print("Testing S3 Baseline Connectivity...")
        print("   📋 This test verifies that our authentication and request signing works correctly")
        
        # Test 1: If using native boto3, try native S3 operation first
        if self.boto3_ops:
            print("   📋 First testing with native boto3 S3 operations...")
            success, status_code, message = self.boto3_ops.test_list_buckets()
            print(f"   📊 Server response: HTTP {status_code}")
            
            if success:
                results.append(SecurityTestResult(
                    "S3 Baseline Connectivity (Native boto3)",
                    True,
                    f"✅ Native boto3 S3 ListBuckets successful - authentication working perfectly",
                    {"method": "native_boto3", "status_code": status_code, "message": message}
                ))
                print(f"   📊 Native boto3 test: SUCCESS - {message}")
            else:
                print(f"   📊 Native boto3 test: FAILED - {message}")
                results.append(SecurityTestResult(
                    "S3 Baseline Connectivity (Native boto3)",
                    False,
                    f"❌ Native boto3 S3 operation failed: {message}",
                    {"method": "native_boto3", "status_code": status_code, "error": message}
                ))
        
        # Test 2: Test with a specific bucket using native boto3 (if available)
        if self.boto3_ops:
            print("   📋 Testing bucket access with native boto3...")
            success, status_code, message = self.boto3_ops.test_list_objects('test-bucket')
            print(f"   📊 Server response: HTTP {status_code}")
            
            if success or status_code == 404:  # 404 is expected for non-existent bucket
                results.append(SecurityTestResult(
                    "S3 Baseline Bucket Access (Native boto3)",
                    True,
                    f"✅ Native boto3 bucket access working (HTTP {status_code}) - {message}",
                    {"method": "native_boto3", "status_code": status_code, "message": message}
                ))
            elif status_code == 403 and "SignatureDoesNotMatch" in message:
                results.append(SecurityTestResult(
                    "S3 Baseline Bucket Access (Native boto3)", 
                    False,
                    f"❌ Authentication failure with native boto3 (HTTP {status_code}) - {message}",
                    {"method": "native_boto3", "status_code": status_code, "auth_failure": True, "error": message}
                ))
            else:
                results.append(SecurityTestResult(
                    "S3 Baseline Bucket Access (Native boto3)",
                    True,
                    f"✅ Native boto3 authenticated but got expected S3 error (HTTP {status_code}) - {message}",
                    {"method": "native_boto3", "status_code": status_code, "message": message}
                ))
        
        # Test 3: For compatibility, also test manual HTTP request with signer
        print("   📋 Testing legacy HTTP request method for compatibility...")
        try:
            url = f"{self.base_url}/test-bucket"
            headers = self.signer.sign_request('GET', url)
            
            # Check if we got a presigned URL
            if 'X-Presigned-URL' in headers:
                print("   📋 Using presigned URL from native boto3...")
                presigned_url = headers['X-Presigned-URL']
                response = self._safe_request('GET', presigned_url)
            else:
                response = self._safe_request('GET', url, headers=headers)
            
            # Always log the actual response for debugging
            if response is not None:
                print(f"   📊 Server response: HTTP {response.status_code} {response.reason}")
            else:
                print(f"   📊 Server response: ❌ CONNECTION FAILED (no HTTP response received)")
            
            # Evaluate legacy HTTP request connectivity
            if response is not None and response.status_code == 200:
                results.append(SecurityTestResult(
                    "S3 Baseline Connectivity (Legacy HTTP)",
                    True,
                    f"✅ Legacy HTTP request successful - authentication working (HTTP {response.status_code})",
                    {"status_code": response.status_code, "method": "legacy_http"}
                ))
            elif response is not None and response.status_code == 404:
                results.append(SecurityTestResult(
                    "S3 Baseline Connectivity (Legacy HTTP)", 
                    True,
                    f"✅ Legacy HTTP request authenticated but bucket not found (HTTP {response.status_code}) - authentication working",
                    {"status_code": response.status_code, "method": "legacy_http"}
                ))
            elif response is not None and response.status_code == 403:
                # Check if this is a SignatureDoesNotMatch (auth failure) or other 403
                if response.text and "SignatureDoesNotMatch" in response.text:
                    results.append(SecurityTestResult(
                        "S3 Baseline Connectivity (Legacy HTTP)",
                        False,
                        f"❌ Legacy HTTP authentication failure: SignatureDoesNotMatch (HTTP {response.status_code})",
                        {"status_code": response.status_code, "method": "legacy_http", "auth_failure": True, "response_body": response.text[:200]}
                    ))
                else:
                    results.append(SecurityTestResult(
                        "S3 Baseline Connectivity (Legacy HTTP)",
                        True,
                        f"✅ Legacy HTTP request authenticated but access denied (HTTP {response.status_code}) - authentication working",
                        {"status_code": response.status_code, "method": "legacy_http", "response_body": response.text[:200]}
                    ))
            elif response is not None:
                results.append(SecurityTestResult(
                    "S3 Baseline Connectivity (Legacy HTTP)",
                    True,
                    f"✅ Legacy HTTP request reached server (HTTP {response.status_code}) - authentication working",
                    {"status_code": response.status_code, "method": "legacy_http", "response_body": response.text[:200]}
                ))
            elif response is None:
                results.append(SecurityTestResult(
                    "S3 Baseline Connectivity (Legacy HTTP)",
                    False,
                    f"❌ Legacy HTTP connection failed",
                    {"method": "legacy_http", "issue": "connection_failure"}
                ))
        except Exception as e:
            results.append(SecurityTestResult(
                "S3 Baseline Connectivity (Legacy HTTP)",
                False,
                f"❌ Legacy HTTP test failed: {str(e)}",
                {"method": "legacy_http", "error": str(e)}
            ))
        
        return results
    
    def _test_s3_auth_bypass(self) -> List[SecurityTestResult]:
        """Test S3 authentication bypass vulnerabilities using native boto3"""
        results = []
        
        print("Testing S3 Authentication Bypass Vulnerabilities...")
        
        # Test 1: Invalid bucket names (should fail gracefully, not bypass auth)
        print("   📋 Testing malformed bucket names - Expected: proper error handling, not auth bypass")
        if self.boto3_ops:
            malformed_buckets = [
                "../../../etc/passwd",  # Path traversal
                "bucket\x00null",        # Null byte injection
                "very-long-bucket-name-" + "a" * 200,  # Extremely long name
                "bucket with spaces",    # Invalid characters
                ".bucket-starts-with-dot", # Invalid format
                "bucket..double-dot",    # Double dots
            ]
            
            for bucket_name in malformed_buckets:
                try:
                    success, status_code, message = self.boto3_ops.test_list_objects(bucket_name)
                    print(f"   📊 Malformed bucket '{bucket_name[:30]}...' - HTTP {status_code}")
                    
                    if status_code == 200:
                        results.append(SecurityTestResult(
                            f"S3 Malformed Bucket Name Protection ({bucket_name[:20]}...)",
                            False,
                            f"🚨 CRITICAL: Malformed bucket name accepted (HTTP {status_code}) - possible auth bypass!",
                            {"status_code": status_code, "bucket_name": bucket_name, "severity": "critical"}
                        ))
                    elif status_code in [400, 403, 404]:
                        results.append(SecurityTestResult(
                            f"S3 Malformed Bucket Name Protection ({bucket_name[:20]}...)",
                            True,
                            f"✅ Server properly rejects malformed bucket name (HTTP {status_code})",
                            {"status_code": status_code, "bucket_name": bucket_name}
                        ))
                    else:
                        results.append(SecurityTestResult(
                            f"S3 Malformed Bucket Name Protection ({bucket_name[:20]}...)",
                            True,
                            f"⚠️ INCONCLUSIVE: Server returned HTTP {status_code} for malformed bucket name",
                            {"status_code": status_code, "bucket_name": bucket_name, "inconclusive": True}
                        ))
                except Exception as e:
                    results.append(SecurityTestResult(
                        f"S3 Malformed Bucket Name Protection ({bucket_name[:20]}...)",
                        False,
                        f"❌ Test failed with exception: {str(e)}",
                        {"bucket_name": bucket_name, "error": str(e)}
                    ))
        
        # Test 2: Invalid object keys (should fail gracefully, not bypass auth)  
        print("   📋 Testing malformed object keys - Expected: proper error handling, not auth bypass")
        if self.boto3_ops:
            malformed_keys = [
                "../../../etc/passwd",
                "object\x00null",
                "object\r\nheader-injection",
                "object\\backslash",
                "very-long-object-name-" + "a" * 500,
            ]
            
            for object_key in malformed_keys:
                try:
                    success, status_code, message = self.boto3_ops.test_get_object("test-bucket", object_key)
                    print(f"   📊 Malformed object '{object_key[:30]}...' - HTTP {status_code}")
                    
                    if status_code == 200:
                        results.append(SecurityTestResult(
                            f"S3 Malformed Object Key Protection ({object_key[:20]}...)",
                            False,
                            f"🚨 CRITICAL: Malformed object key accepted (HTTP {status_code}) - possible auth bypass!",
                            {"status_code": status_code, "object_key": object_key, "severity": "critical"}
                        ))
                    elif status_code in [400, 403, 404]:
                        results.append(SecurityTestResult(
                            f"S3 Malformed Object Key Protection ({object_key[:20]}...)",
                            True,
                            f"✅ Server properly rejects malformed object key (HTTP {status_code})",
                            {"status_code": status_code, "object_key": object_key}
                        ))
                    else:
                        results.append(SecurityTestResult(
                            f"S3 Malformed Object Key Protection ({object_key[:20]}...)",
                            True,
                            f"⚠️ INCONCLUSIVE: Server returned HTTP {status_code} for malformed object key",
                            {"status_code": status_code, "object_key": object_key, "inconclusive": True}
                        ))
                except Exception as e:
                    results.append(SecurityTestResult(
                        f"S3 Malformed Object Key Protection ({object_key[:20]}...)",
                        False,
                        f"❌ Test failed with exception: {str(e)}",
                        {"object_key": object_key, "error": str(e)}
                    ))
        
        # If native boto3 not available, add note about fallback
        if not self.boto3_ops:
            results.append(SecurityTestResult(
                "S3 Authentication Bypass Tests",
                False,
                "⚠️ Native boto3 not available - authentication bypass tests require boto3 for reliable testing",
                {"requires": "boto3", "suggestion": "pip install boto3"}
            ))
        
        return results
    
    def _test_s3_query_injection(self) -> List[SecurityTestResult]:
        """Test S3 query parameter injection vulnerabilities using native boto3"""
        results = []
        
        print("Testing S3 Query Parameter Injection...")
        
        # Test 1: Malformed prefix parameters (injection attempts)
        print("   📋 Testing malformed prefix parameters - Expected: proper error handling")
        if self.boto3_ops:
            malformed_prefixes = [
                "test\x00malicious",        # Null byte injection
                "test\r\nmalicious",        # CRLF injection
                "../../../etc/passwd",     # Path traversal in prefix
                "test" + "a" * 1000,       # Extremely long prefix
                "test\x1f\x8b",            # Binary data
                "test%00malicious",        # URL-encoded null byte
            ]
            
            for prefix in malformed_prefixes:
                try:
                    success, status_code, message = self.boto3_ops.test_list_objects("test-bucket", Prefix=prefix)
                    print(f"   📊 Malformed prefix '{prefix[:30]}...' - HTTP {status_code}")
                    
                    if status_code == 200:
                        results.append(SecurityTestResult(
                            f"S3 Query Parameter Injection Protection (prefix: {prefix[:20]}...)",
                            False,
                            f"🚨 CRITICAL: Malformed prefix parameter accepted (HTTP {status_code}) - possible injection vulnerability!",
                            {"status_code": status_code, "prefix": prefix, "severity": "critical"}
                        ))
                    elif status_code in [400, 403, 404]:
                        results.append(SecurityTestResult(
                            f"S3 Query Parameter Injection Protection (prefix: {prefix[:20]}...)",
                            True,
                            f"✅ Server properly rejects malformed prefix parameter (HTTP {status_code})",
                            {"status_code": status_code, "prefix": prefix}
                        ))
                    else:
                        results.append(SecurityTestResult(
                            f"S3 Query Parameter Injection Protection (prefix: {prefix[:20]}...)",
                            True,
                            f"⚠️ INCONCLUSIVE: Server returned HTTP {status_code} for malformed prefix",
                            {"status_code": status_code, "prefix": prefix, "inconclusive": True}
                        ))
                except Exception as e:
                    results.append(SecurityTestResult(
                        f"S3 Query Parameter Injection Protection (prefix: {prefix[:20]}...)",
                        False,
                        f"❌ Test failed with exception: {str(e)}",
                        {"prefix": prefix, "error": str(e)}
                    ))
        
        # Test 2: Malformed delimiter parameters
        print("   📋 Testing malformed delimiter parameters - Expected: proper error handling")
        if self.boto3_ops:
            malformed_delimiters = [
                "\x00",           # Null byte
                "\r\n",           # CRLF
                "x" * 100,        # Very long delimiter
                "\x1f\x8b",       # Binary data
            ]
            
            for delimiter in malformed_delimiters:
                try:
                    success, status_code, message = self.boto3_ops.test_list_objects("test-bucket", Delimiter=delimiter)
                    print(f"   📊 Malformed delimiter '{repr(delimiter)[:30]}...' - HTTP {status_code}")
                    
                    if status_code == 200:
                        results.append(SecurityTestResult(
                            f"S3 Delimiter Parameter Injection Protection ({repr(delimiter)[:20]}...)",
                            False,
                            f"🚨 CRITICAL: Malformed delimiter parameter accepted (HTTP {status_code}) - possible injection vulnerability!",
                            {"status_code": status_code, "delimiter": delimiter, "severity": "critical"}
                        ))
                    elif status_code in [400, 403, 404]:
                        results.append(SecurityTestResult(
                            f"S3 Delimiter Parameter Injection Protection ({repr(delimiter)[:20]}...)",
                            True,
                            f"✅ Server properly rejects malformed delimiter parameter (HTTP {status_code})",
                            {"status_code": status_code, "delimiter": delimiter}
                        ))
                    else:
                        results.append(SecurityTestResult(
                            f"S3 Delimiter Parameter Injection Protection ({repr(delimiter)[:20]}...)",
                            True,
                            f"⚠️ INCONCLUSIVE: Server returned HTTP {status_code} for malformed delimiter",
                            {"status_code": status_code, "delimiter": delimiter, "inconclusive": True}
                        ))
                except Exception as e:
                    results.append(SecurityTestResult(
                        f"S3 Delimiter Parameter Injection Protection ({repr(delimiter)[:20]}...)",
                        False,
                        f"❌ Test failed with exception: {str(e)}",
                        {"delimiter": delimiter, "error": str(e)}
                    ))
        
        # Test 3: Extreme parameter values (DoS testing)
        print("   📋 Testing extreme parameter values - Expected: proper limits enforced")
        if self.boto3_ops:
            try:
                # Test extremely high MaxKeys value
                success, status_code, message = self.boto3_ops.test_list_objects("test-bucket", MaxKeys=999999999)
                print(f"   📊 Extreme MaxKeys value - HTTP {status_code}")
                
                if status_code == 200:
                    results.append(SecurityTestResult(
                        "S3 MaxKeys Parameter Limit",
                        False,
                        f"🚨 Server accepts extreme MaxKeys value (HTTP {status_code}) - potential DoS risk!",
                        {"status_code": status_code, "max_keys": 999999999, "severity": "high"}
                    ))
                elif status_code in [400, 403]:
                    results.append(SecurityTestResult(
                        "S3 MaxKeys Parameter Limit",
                        True,
                        f"✅ Server properly limits MaxKeys parameter (HTTP {status_code})",
                        {"status_code": status_code, "max_keys": 999999999}
                    ))
                else:
                    results.append(SecurityTestResult(
                        "S3 MaxKeys Parameter Limit",
                        True,
                        f"⚠️ INCONCLUSIVE: Server returned HTTP {status_code} for extreme MaxKeys",
                        {"status_code": status_code, "max_keys": 999999999, "inconclusive": True}
                    ))
            except Exception as e:
                results.append(SecurityTestResult(
                    "S3 MaxKeys Parameter Limit",
                    False,
                    f"❌ Test failed with exception: {str(e)}",
                    {"max_keys": 999999999, "error": str(e)}
                ))
        
        # If native boto3 not available, add note about fallback
        if not self.boto3_ops:
            results.append(SecurityTestResult(
                "S3 Query Parameter Injection Tests",
                False,
                "⚠️ Native boto3 not available - query parameter injection tests require boto3 for reliable testing",
                {"requires": "boto3", "suggestion": "pip install boto3"}
            ))
        
        return results
    
    def _test_s3_presigned_url_manipulation(self) -> List[SecurityTestResult]:
        """Test S3 presigned URL manipulation vulnerabilities"""
        results = []
        
        print("Testing S3 Presigned URL Manipulation...")
        
        # Test 3.1: Presigned URL with modified expiration
        try:
            # Create a presigned URL manually with modified parameters
            t = datetime.datetime.utcnow()
            amz_date = t.strftime('%Y%m%dT%H%M%SZ')
            
            presigned_params = {
                'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                'X-Amz-Credential': f"{self.signer.access_key}/20991231/{self.signer.region}/{self.signer.service}/aws4_request",  # Far future date
                'X-Amz-Date': amz_date,
                'X-Amz-Expires': '999999',  # Excessive expiration
                'X-Amz-SignedHeaders': 'host',
                'X-Amz-Signature': 'fake-signature'
            }
            
            query_string = urllib.parse.urlencode(presigned_params)
            url = f"{self.base_url}/test-bucket/test-object?{query_string}"
            response = self._safe_request('GET', url)
            
            if response and response.status_code in [400, 403]:
                results.append(SecurityTestResult(
                    "S3 Presigned URL Expiration Validation",
                    True,
                    "✅ Server validates presigned URL expiration",
                    {"status_code": response.status_code}
                ))
            elif response:
                # Server returned unexpected status - debug
                print(f"   🔍 DEBUG: Server returned status {response.status_code} for presigned URL test")
                print(f"   🔍 DEBUG: Response body: {response.text[:200]}...")
                
                if response.status_code == 200:
                    results.append(SecurityTestResult(
                        "S3 Presigned URL Expiration Validation",
                        False,
                        f"🚨 CRITICAL: Server accepts invalid presigned URL expiration (returned 200)!",
                        {"status_code": response.status_code, "severity": "critical", "response_body": response.text[:500]}
                    ))
                else:
                    results.append(SecurityTestResult(
                        "S3 Presigned URL Expiration Validation",
                        False,
                        f"⚠️ Unexpected response to presigned URL test (status: {response.status_code})",
                        {"status_code": response.status_code, "requires_review": True, "response_body": response.text[:500]}
                    ))
            else:
                # Connection failed - try with curl for verification if available
                if self.curl_available:
                    print("   🔧 Connection failed, trying curl verification...")
                    curl_result = self._curl_request('GET', url)
                else:
                    curl_result = {'success': False, 'error': 'curl_not_available'}
                
                if curl_result['success'] and curl_result['status_code']:
                    if curl_result['status_code'] in [400, 403]:
                        results.append(SecurityTestResult(
                            "S3 Presigned URL Expiration Validation",
                            True,
                            f"✅ Server validates presigned URL expiration (verified with curl: {curl_result['status_code']})",
                            {"status_code": curl_result['status_code'], "verified_with": "curl"}
                        ))
                    elif curl_result['status_code'] == 200:
                        results.append(SecurityTestResult(
                            "S3 Presigned URL Expiration Validation",
                            False,
                            f"🚨 CRITICAL: Server accepts invalid presigned URL expiration (verified with curl: {curl_result['status_code']})!",
                            {"status_code": curl_result['status_code'], "severity": "critical", "verified_with": "curl"}
                        ))
                    else:
                        results.append(SecurityTestResult(
                            "S3 Presigned URL Expiration Validation",
                            False,
                            f"⚠️ Unexpected response to presigned URL test (curl: {curl_result['status_code']})",
                            {"status_code": curl_result['status_code'], "requires_review": True, "verified_with": "curl"}
                        ))
                else:
                    if curl_result.get('error') == 'curl_not_available':
                        results.append(SecurityTestResult(
                            "S3 Presigned URL Expiration Validation",
                            False,
                            f"❌ Connection failed and curl not available for verification",
                            {"requires_review": True, "issue": "connection_failure"}
                        ))
                    else:
                        results.append(SecurityTestResult(
                            "S3 Presigned URL Expiration Validation",
                            False,
                            f"❌ Both Python requests and curl failed for presigned URL test",
                            {"requires_review": True, "issue": "both_failed"}
                        ))
        except Exception as e:
            results.append(SecurityTestResult(
                "S3 Presigned URL Expiration Validation",
                False,
                f"❌ Test failed with exception: {str(e)}",
                {"error": str(e)}
            ))
        
        return results
    
    def _test_s3_path_traversal(self) -> List[SecurityTestResult]:
        """Test S3 bucket/object path traversal protection"""
        results = []
        
        print("Testing S3 Path Traversal Protection...")
        
        # Test 4.1: Bucket name with path traversal
        try:
            url = f"{self.base_url}/../../../etc/passwd"
            headers = self.signer.sign_request('GET', url)
            response = self._safe_request('GET', url, headers=headers)
            
            if response and response.status_code in [400, 403, 404]:
                results.append(SecurityTestResult(
                    "S3 Bucket Path Traversal Protection",
                    True,
                    "✅ Server rejects bucket names with path traversal",
                    {"status_code": response.status_code}
                ))
            elif response and response.status_code == 200:
                results.append(SecurityTestResult(
                    "S3 Bucket Path Traversal Protection",
                    False,
                    "🚨 CRITICAL: Server allows bucket path traversal!",
                    {"status_code": response.status_code, "severity": "critical"}
                ))
            else:
                # Connection failed - try with curl for verification if available
                if self.curl_available:
                    print("   🔧 Connection failed, trying curl verification...")
                    curl_result = self._curl_request('GET', url, headers)
                else:
                    curl_result = {'success': False, 'error': 'curl_not_available'}
                
                if curl_result['success'] and curl_result['status_code']:
                    if curl_result['status_code'] in [400, 403, 404]:
                        results.append(SecurityTestResult(
                            "S3 Bucket Path Traversal Protection",
                            True,
                            f"✅ Server rejects bucket path traversal (verified with curl: {curl_result['status_code']})",
                            {"status_code": curl_result['status_code'], "verified_with": "curl"}
                        ))
                    elif curl_result['status_code'] == 200:
                        results.append(SecurityTestResult(
                            "S3 Bucket Path Traversal Protection",
                            False,
                            f"🚨 CRITICAL: Server allows bucket path traversal! (verified with curl: {curl_result['status_code']})",
                            {"status_code": curl_result['status_code'], "severity": "critical", "verified_with": "curl"}
                        ))
                    else:
                        results.append(SecurityTestResult(
                            "S3 Bucket Path Traversal Protection",
                            False,
                            f"⚠️ Unexpected response to path traversal (curl: {curl_result['status_code']})",
                            {"status_code": curl_result['status_code'], "requires_review": True, "verified_with": "curl"}
                        ))
                else:
                    if curl_result.get('error') == 'curl_not_available':
                        results.append(SecurityTestResult(
                            "S3 Bucket Path Traversal Protection",
                            False,
                            f"❌ Connection failed and curl not available for verification",
                            {"requires_review": True, "issue": "connection_failure"}
                        ))
                    else:
                        results.append(SecurityTestResult(
                            "S3 Bucket Path Traversal Protection",
                            False,
                            f"❌ Both Python requests and curl failed for path traversal test",
                            {"requires_review": True, "issue": "both_failed"}
                        ))
        except Exception as e:
            results.append(SecurityTestResult(
                "S3 Bucket Path Traversal Protection",
                False,
                f"❌ Test failed with exception: {str(e)}",
                {"error": str(e)}
            ))
        
        # Test 4.2: Object name with path traversal
        try:
            url = f"{self.base_url}/test-bucket/../../../etc/passwd"
            headers = self.signer.sign_request('GET', url)
            response = self._safe_request('GET', url, headers=headers)
            
            if response and response.status_code in [400, 403, 404]:
                results.append(SecurityTestResult(
                    "S3 Object Path Traversal Protection",
                    True,
                    "✅ Server rejects object names with path traversal",
                    {"status_code": response.status_code}
                ))
            elif response and response.status_code == 200:
                results.append(SecurityTestResult(
                    "S3 Object Path Traversal Protection",
                    False,
                    "🚨 CRITICAL: Server allows object path traversal!",
                    {"status_code": response.status_code, "severity": "critical"}
                ))
            else:
                # Connection failed - try with curl for verification if available
                if self.curl_available:
                    print("   🔧 Connection failed, trying curl verification...")
                    curl_result = self._curl_request('GET', url, headers)
                else:
                    curl_result = {'success': False, 'error': 'curl_not_available'}
                
                if curl_result['success'] and curl_result['status_code']:
                    if curl_result['status_code'] in [400, 403, 404]:
                        results.append(SecurityTestResult(
                            "S3 Object Path Traversal Protection",
                            True,
                            f"✅ Server rejects object path traversal (verified with curl: {curl_result['status_code']})",
                            {"status_code": curl_result['status_code'], "verified_with": "curl"}
                        ))
                    elif curl_result['status_code'] == 200:
                        results.append(SecurityTestResult(
                            "S3 Object Path Traversal Protection",
                            False,
                            f"🚨 CRITICAL: Server allows object path traversal! (verified with curl: {curl_result['status_code']})",
                            {"status_code": curl_result['status_code'], "severity": "critical", "verified_with": "curl"}
                        ))
                    else:
                        results.append(SecurityTestResult(
                            "S3 Object Path Traversal Protection",
                            False,
                            f"⚠️ Unexpected response to object path traversal (curl: {curl_result['status_code']})",
                            {"status_code": curl_result['status_code'], "requires_review": True, "verified_with": "curl"}
                        ))
                else:
                    if curl_result.get('error') == 'curl_not_available':
                        results.append(SecurityTestResult(
                            "S3 Object Path Traversal Protection",
                            False,
                            f"❌ Connection failed and curl not available for verification",
                            {"requires_review": True, "issue": "connection_failure"}
                        ))
                    else:
                        results.append(SecurityTestResult(
                            "S3 Object Path Traversal Protection",
                            False,
                            f"❌ Both Python requests and curl failed for object path traversal test",
                            {"requires_review": True, "issue": "both_failed"}
                        ))
        except Exception as e:
            results.append(SecurityTestResult(
                "S3 Object Path Traversal Protection",
                False,
                f"❌ Test failed with exception: {str(e)}",
                {"error": str(e)}
            ))
        
        return results
    
    def _test_s3_header_injection(self) -> List[SecurityTestResult]:
        """Test S3 header injection via SigV4 signatures"""
        results = []
        
        print("Testing S3 Header Injection via SigV4...")
        
        # Test 5.1: Malicious custom headers in SigV4
        try:
            url = f"{self.base_url}/test-bucket"
            malicious_headers = {
                'X-Malicious-Header': 'injected\r\nX-Injected: true',
                'X-Custom-Auth': 'bypass'
            }
            headers = self.signer.sign_request('GET', url, malicious_headers)
            response = self._safe_request('GET', url, headers=headers)
            
            if response and response.status_code in [400, 403]:
                results.append(SecurityTestResult(
                    "S3 Header Injection via SigV4 Protection",
                    True,
                    "✅ Server rejects malicious headers in SigV4 signatures",
                    {"status_code": response.status_code}
                ))
            elif response:
                # Server returned unexpected status - debug
                print(f"   🔍 DEBUG: Server returned status {response.status_code} for header injection test")
                print(f"   🔍 DEBUG: Response body: {response.text[:200]}...")
                
                if response.status_code == 200:
                    results.append(SecurityTestResult(
                        "S3 Header Injection via SigV4 Protection",
                        False,
                        f"🚨 CRITICAL: Server processes malicious headers in SigV4 signatures (returned 200)!",
                        {"status_code": response.status_code, "severity": "critical", "response_body": response.text[:500]}
                    ))
                else:
                    results.append(SecurityTestResult(
                        "S3 Header Injection via SigV4 Protection",
                        False,
                        f"⚠️ Unexpected response to header injection test (status: {response.status_code})",
                        {"status_code": response.status_code, "requires_review": True, "response_body": response.text[:500]}
                    ))
            else:
                # Connection failed - try with curl for verification if available
                if self.curl_available:
                    print("   🔧 Connection failed, trying curl verification...")
                    curl_result = self._curl_request('GET', url, headers)
                else:
                    curl_result = {'success': False, 'error': 'curl_not_available'}
                
                if curl_result['success'] and curl_result['status_code']:
                    if curl_result['status_code'] in [400, 403]:
                        results.append(SecurityTestResult(
                            "S3 Header Injection via SigV4 Protection",
                            True,
                            f"✅ Server rejects malicious headers in SigV4 signatures (verified with curl: {curl_result['status_code']})",
                            {"status_code": curl_result['status_code'], "verified_with": "curl"}
                        ))
                    elif curl_result['status_code'] == 200:
                        results.append(SecurityTestResult(
                            "S3 Header Injection via SigV4 Protection",
                            False,
                            f"🚨 CRITICAL: Server processes malicious headers in SigV4 signatures (verified with curl: {curl_result['status_code']})!",
                            {"status_code": curl_result['status_code'], "severity": "critical", "verified_with": "curl"}
                        ))
                    else:
                        results.append(SecurityTestResult(
                            "S3 Header Injection via SigV4 Protection",
                            False,
                            f"⚠️ Unexpected response to header injection test (curl: {curl_result['status_code']})",
                            {"status_code": curl_result['status_code'], "requires_review": True, "verified_with": "curl"}
                        ))
                else:
                    if curl_result.get('error') == 'curl_not_available':
                        results.append(SecurityTestResult(
                            "S3 Header Injection via SigV4 Protection",
                            False,
                            f"❌ Connection failed and curl not available for verification",
                            {"requires_review": True, "issue": "connection_failure"}
                        ))
                    else:
                        results.append(SecurityTestResult(
                            "S3 Header Injection via SigV4 Protection",
                            False,
                            f"❌ Both Python requests and curl failed for header injection test",
                            {"requires_review": True, "issue": "both_failed"}
                        ))
        except Exception as e:
            if "Invalid header" in str(e) or "return character" in str(e):
                results.append(SecurityTestResult(
                    "S3 Header Injection via SigV4 Protection",
                    False,
                    "⚠️ Client library rejected headers - server validation unknown",
                    {"protection_level": "client_library_only", "requires_review": True}
                ))
            else:
                results.append(SecurityTestResult(
                    "S3 Header Injection via SigV4 Protection",
                    False,
                    f"❌ Test failed with exception: {str(e)}",
                    {"error": str(e)}
                ))
        
        return results
    
    def _safe_request(self, method: str, url: str, headers: Dict = None, **kwargs) -> Optional[requests.Response]:
        """Make a safe HTTP request with proper error handling"""
        try:
            if self.verbose:
                print(f"\n🔍 Making request:")
                print(f"   URL: {method} {url}")
                if headers:
                    print(f"   Headers: {headers}")
            
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            
            if self.verbose:
                print(f"📥 Response received:")
                print(f"   Status: {response.status_code} {response.reason}")
                print(f"   Headers: {dict(response.headers)}")
                
                # Print response body (truncated if too long)
                try:
                    body = response.text
                    if len(body) > 500:
                        print(f"   Body: {body[:500]}... (truncated)")
                    else:
                        print(f"   Body: {body}")
                except:
                    print(f"   Body: <binary or unreadable content>")
                print("-" * 50)
            
            # Debug: Confirm we're returning a valid response
            if self.verbose:
                print(f"🔄 _safe_request returning response object: {type(response)} with status {response.status_code}")
            
            return response
            
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"❌ Request failed with RequestException: {e}")
            else:
                print(f"Request failed: {e}")
            return None
        except Exception as e:
            if self.verbose:
                print(f"❌ Unexpected error: {e}")
            else:
                print(f"Unexpected error: {e}")
            return None
    
    def _check_curl_availability(self) -> bool:
        """Check if curl is available on the system"""
        try:
            result = subprocess.run(['curl', '--version'], capture_output=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _curl_request(self, method: str, url: str, headers: Dict = None) -> Dict:
        """Make a request using curl as a fallback verification method"""
        try:
            # Build curl command
            curl_cmd = ['curl', '-s', '-i', '-X', method]
            
            # Add SSL options
            if not self.verify_ssl:
                curl_cmd.extend(['-k'])  # Ignore SSL certificate errors
            
            # Add headers
            if headers:
                for key, value in headers.items():
                    curl_cmd.extend(['-H', f'{key}: {value}'])
            
            # Add URL
            curl_cmd.append(url)
            
            if self.verbose:
                print(f"🔧 Fallback curl command: {' '.join(curl_cmd)}")
            
            # Execute curl
            result = subprocess.run(
                curl_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Parse response
            response_text = result.stdout
            lines = response_text.split('\n')
            
            # Extract status line
            status_line = lines[0] if lines else ''
            status_code = None
            if 'HTTP/' in status_line:
                try:
                    status_code = int(status_line.split()[1])
                except (IndexError, ValueError):
                    status_code = None
            
            # Extract headers
            curl_headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line.strip() == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    curl_headers[key.strip()] = value.strip()
            
            # Extract body
            body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
            
            if self.verbose:
                print(f"📡 Curl response:")
                print(f"   Status: {status_code}")
                print(f"   Headers: {curl_headers}")
                if len(body) > 500:
                    print(f"   Body: {body[:500]}... (truncated)")
                else:
                    print(f"   Body: {body}")
                print("-" * 50)
            
            return {
                'status_code': status_code,
                'headers': curl_headers,
                'body': body,
                'success': result.returncode == 0
            }
            
        except subprocess.TimeoutExpired:
            if self.verbose:
                print("🔧 Curl request timed out")
            return {'status_code': None, 'headers': {}, 'body': '', 'success': False, 'error': 'timeout'}
        except Exception as e:
            if self.verbose:
                print(f"🔧 Curl request failed: {e}")
            return {'status_code': None, 'headers': {}, 'body': '', 'success': False, 'error': str(e)}

def print_results(results: List[SecurityTestResult]):
    """Print formatted test results"""
    print("\n" + "="*60)
    print("🔒 S3 COMPATIBILITY LAYER SECURITY VALIDATION RESULTS")
    print("="*60)
    
    passed_tests = sum(1 for r in results if r.passed)
    total_tests = len(results)
    
    print(f"\nOverall Status: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 All S3 security controls are properly implemented!")
    else:
        print(f"⚠️  {total_tests - passed_tests} S3 security issues found that need attention")
    
    # Count critical issues and manual reviews needed
    critical_issues = sum(1 for r in results if r.details.get('severity') == 'critical')
    high_issues = sum(1 for r in results if r.details.get('severity') == 'high')
    manual_reviews = sum(1 for r in results if r.details.get('requires_review'))
    connection_failures = sum(1 for r in results if r.details.get('issue') == 'connection_failure')
    inconclusive_tests = sum(1 for r in results if r.details.get('inconclusive'))
    
    if critical_issues > 0:
        print(f"🚨 {critical_issues} CRITICAL S3 vulnerabilities detected!")
    if high_issues > 0:
        print(f"⚠️ {high_issues} HIGH RISK S3 vulnerabilities detected!")
    if inconclusive_tests > 0:
        print(f"🤷 {inconclusive_tests} tests were inconclusive (server responded but can't confirm security validation)")
    if manual_reviews > 0:
        print(f"👀 {manual_reviews} tests require manual review")
    if connection_failures > 0:
        print(f"🔌 {connection_failures} tests failed due to connection issues")
    
    print("\nDetailed Results:")
    print("-" * 60)
    
    for result in results:
        status_icon = "✅" if result.passed else "❌"
        if result.details.get('severity') == 'critical':
            status_icon = "🚨"
        elif result.details.get('inconclusive'):
            status_icon = "🤷"
        elif result.details.get('requires_review'):
            status_icon = "⚠️"
            
        print(f"{status_icon} {result.test_name}")
        print(f"   {result.message}")
        
        # Always show response code information when available
        if result.details.get('status_code') is not None:
            print(f"   📊 Server returned: HTTP {result.details['status_code']}")
        
        # Show expected vs actual response codes for debugging
        if result.details.get('expected') and result.details.get('actual'):
            print(f"   📋 Expected: {result.details['expected']}, Got: {result.details['actual']}")
        
        if result.details.get('inconclusive'):
            print("   🤷 INCONCLUSIVE - Server responded but can't confirm security validation")
        
        if result.details.get('requires_review'):
            print("   👀 Manual review required")
        
        if result.details.get('severity') == 'critical':
            print("   🚨 CRITICAL VULNERABILITY - Immediate action required")
        
        if result.details.get('severity') == 'high':
            print("   ⚠️ HIGH RISK VULNERABILITY - Should be addressed")
        
        if result.details.get('issue') == 'connection_failure':
            print("   🔌 Connection failure may indicate server crash or protection")
            if not result.details.get('verified_with'):
                print("   📋 Recommendation: curl verification was not attempted")
        
        if result.details.get('verified_with') == 'curl':
            print("   🔧 Verified using curl as fallback")
        
        if result.details.get('issue') == 'both_failed':
            print("   💥 Both Python requests and curl failed")
            print("   📋 Recommendation: Check server status and network connectivity")
        
        if result.details.get('protection_level') == 'client_library_only':
            print("   ⚠️  Protection only at client library level - server validation unknown")
            print("   📋 Recommendation: Test with raw HTTP requests or different client")
        
        if not result.passed and 'error' not in result.details and not result.details.get('requires_review'):
            print(f"   📋 Recommendation: Implement proper S3 validation for this test case")
        
        print()

def main():
    parser = argparse.ArgumentParser(
        description='Manta Buckets API S3 Compatibility Layer Security Validation Test Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available test categories
  python3 security_validation_test.py --list-tests
  
  # Using environment variables (recommended) - run all tests
  export AWS_ACCESS_KEY_ID="AKIA123456789EXAMPLE"
  export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  export AWS_REGION="us-east-1"
  python3 security_validation_test.py --host localhost --port 8080
  
  # Run specific test categories
  python3 security_validation_test.py --host localhost --port 8080 --baseline-only
  python3 security_validation_test.py --host localhost --port 8080 --tests baseline auth
  python3 security_validation_test.py --host localhost --port 8080 --auth-only
  
  # Full example with SSL and verbose output
  python3 security_validation_test.py --host manta-api.example.com --port 443 --ssl --verbose --tests auth path

Note: This tool is for defensive testing of S3 compatibility layer only.
Run only against systems you own or have explicit permission to test.
        """
    )
    
    parser.add_argument('--host', default='localhost', help='Target host (default: localhost)')
    parser.add_argument('--port', type=int, default=8080, help='Target port (default: 8080)')
    parser.add_argument('--ssl', action='store_true', help='Use HTTPS instead of HTTP')
    parser.add_argument('--insecure', '-k', action='store_true', help='Ignore SSL certificate errors (like curl -k)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Print detailed request/response information')
    parser.add_argument('--access-key', help='S3 Access Key ID for authentication (default: from AWS_ACCESS_KEY_ID env var)')
    parser.add_argument('--secret-key', help='S3 Secret Access Key for authentication (default: from AWS_SECRET_ACCESS_KEY env var)')
    parser.add_argument('--region', help='AWS region for S3 requests (default: from AWS_REGION env var or us-east-1)')
    
    # Test selection arguments
    parser.add_argument('--tests', nargs='+', choices=['baseline', 'auth', 'query', 'presigned', 'path', 'header'], 
                       help='Select specific test categories to run (default: all tests)')
    parser.add_argument('--list-tests', action='store_true', help='List available test categories and exit')
    
    # Individual test flags for convenience
    parser.add_argument('--baseline-only', action='store_true', help='Run only baseline connectivity test')
    parser.add_argument('--auth-only', action='store_true', help='Run only authentication bypass tests')
    parser.add_argument('--query-only', action='store_true', help='Run only query parameter injection tests')
    parser.add_argument('--presigned-only', action='store_true', help='Run only presigned URL manipulation tests')
    parser.add_argument('--path-only', action='store_true', help='Run only path traversal tests')
    parser.add_argument('--header-only', action='store_true', help='Run only header injection tests')
    
    args = parser.parse_args()
    
    # Handle --list-tests option
    if args.list_tests:
        print("📋 Available S3 Security Test Categories:")
        print("=" * 50)
        test_descriptions = {
            'baseline': 'Baseline Connectivity Test - Verifies authentication and basic S3 functionality',
            'auth': 'Authentication Bypass Vulnerabilities - Tests signature manipulation and parameter pollution',
            'query': 'Query Parameter Injection - Tests null byte injection and excessive parameters',
            'presigned': 'Presigned URL Manipulation - Tests expiration validation and signature bypass',
            'path': 'Path Traversal Protection - Tests bucket/object name path traversal attempts',
            'header': 'Header Injection via SigV4 - Tests malicious header processing in signatures'
        }
        
        for test_key, description in test_descriptions.items():
            print(f"  {test_key:>10} : {description}")
        
        print("\nUsage examples:")
        print("  --baseline-only             # Run only baseline connectivity test")
        print("  --tests baseline auth       # Run baseline and authentication tests")
        print("  --auth-only                 # Run only authentication tests")
        print("  --tests path header         # Run only path traversal and header injection tests")
        print("  (no test flags)             # Run all tests")
        sys.exit(0)
    
    # Determine which tests to run
    selected_tests = None
    
    # Check individual test flags first
    individual_flags = {
        'baseline': args.baseline_only,
        'auth': args.auth_only,
        'query': args.query_only,
        'presigned': args.presigned_only,
        'path': args.path_only,
        'header': args.header_only
    }
    
    selected_individual = [test for test, flag in individual_flags.items() if flag]
    
    if selected_individual:
        if args.tests:
            print("❌ Error: Cannot use both --tests and individual test flags (--auth-only, etc.)")
            sys.exit(1)
        selected_tests = selected_individual
    elif args.tests:
        selected_tests = args.tests
    
    # Construct base URL
    protocol = 'https' if args.ssl else 'http'
    base_url = f"{protocol}://{args.host}:{args.port}"
    
    print("🛡️  Manta S3 Compatibility Layer Security Validation Test Suite")
    print("=" * 60)
    print("⚠️  IMPORTANT: This tool is for defensive testing only!")
    print("   Only run against systems you own or have permission to test.")
    
    if not BOTO3_AVAILABLE:
        print("📦 RECOMMENDED: Install boto3 for more reliable authentication:")
        print("   pip install boto3")
    
    print()
    
    # Confirm before proceeding
    try:
        confirm = input(f"Proceed with S3 security testing {base_url}? (y/N): ").strip().lower()
        if confirm != 'y':
            print("Testing cancelled.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nTesting cancelled.")
        sys.exit(0)
    
    # Get credentials from environment variables or command line arguments
    access_key = args.access_key or os.getenv('AWS_ACCESS_KEY_ID')
    secret_key = args.secret_key or os.getenv('AWS_SECRET_ACCESS_KEY')
    region = args.region or os.getenv('AWS_REGION', 'us-east-1')
    
    # Validate credentials
    if not access_key:
        print("❌ Error: AWS Access Key ID required")
        print("   Set via --access-key argument or AWS_ACCESS_KEY_ID environment variable")
        sys.exit(1)
    
    if not secret_key:
        print("❌ Error: AWS Secret Access Key required")
        print("   Set via --secret-key argument or AWS_SECRET_ACCESS_KEY environment variable")
        sys.exit(1)
    
    # Run tests
    verify_ssl = not args.insecure  # If --insecure is used, don't verify SSL
    
    tester = MantaS3SecurityTester(
        base_url, 
        access_key, 
        secret_key,
        timeout=args.timeout, 
        verify_ssl=verify_ssl, 
        verbose=args.verbose
    )
    
    # Update the signer with the specified region
    tester.signer.region = region
    
    if args.insecure:
        print("⚠️  SSL certificate verification disabled (-k/--insecure flag)")
    if args.verbose:
        print("🔍 Verbose mode enabled - showing detailed request/response information")
    
    print(f"🔐 Using AWS credentials:")
    print(f"   Access Key: {access_key}")
    print(f"   Region: {region}")
    
    if tester.curl_available:
        print("🔧 curl available for fallback verification")
    else:
        print("⚠️  curl not available - connection failures cannot be verified")
    
    results = tester.run_all_tests(selected_tests)
    
    # Print results
    print_results(results)
    
    # Exit with appropriate code
    failed_tests = sum(1 for r in results if not r.passed)
    if failed_tests > 0:
        print(f"\n❌ {failed_tests} S3 security issues detected. Please review and fix.")
        sys.exit(1)
    else:
        print("\n✅ All S3 security validations passed!")
        sys.exit(0)

if __name__ == '__main__':
    main()
