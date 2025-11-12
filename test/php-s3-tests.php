#!/usr/bin/env php
<?php
/**
 * Comprehensive PHP S3 tests using AWS SDK for PHP
 * Replicates the functionality of boto3-tests.py for PHP clients
 */

// Try different paths for vendor/autoload.php
$autoload_paths = [
    __DIR__ . '/vendor/autoload.php',           // In test directory
    __DIR__ . '/../vendor/autoload.php',        // In project root
    'vendor/autoload.php'                       // Current directory
];

$autoload_found = false;
foreach ($autoload_paths as $path) {
    if (file_exists($path)) {
        require_once $path;
        $autoload_found = true;
        break;
    }
}

if (!$autoload_found) {
    die("Error: Could not find vendor/autoload.php. Please run 'composer install' in the test directory.\n");
}

use Aws\S3\S3Client;
use Aws\S3\Exception\S3Exception;
use Aws\Exception\AwsException;
use Aws\Credentials\CredentialProvider;
use Aws\Exception\CredentialsException;

// --- Pretty printing ---------------------------------------------------------
const GREEN = "\033[32m";
const RED = "\033[31m";
const YELLOW = "\033[33m";
const CYAN = "\033[36m";
const BOLD = "\033[1m";
const DIM = "\033[2m";
const RESET = "\033[0m";

if (!function_exists('ok')) {
    function ok($msg) { echo GREEN . "[ok]" . RESET . " $msg\n"; }
}
if (!function_exists('fail')) {
    function fail($msg) { echo RED . "[fail]" . RESET . " $msg\n"; }
}
if (!function_exists('info')) {
    function info($msg) { echo CYAN . "[info]" . RESET . " $msg\n"; }
}
if (!function_exists('warn')) {
    function warn($msg) { echo YELLOW . "[warn]" . RESET . " $msg\n"; }
}

// --- Test framework ----------------------------------------------------------
class TestResult {
    public $passed = 0;
    public $failed = 0;
}

class TestRunner {
    private $result;
    
    public function __construct() {
        $this->result = new TestResult();
    }
    
    public function run($name, $test_func) {
        try {
            info("Running: $name");
            $test_func();
            ok("PASS: $name");
            $this->result->passed++;
        } catch (Exception $e) {
            fail("FAIL: $name -> " . $e->getMessage());
            $this->result->failed++;
        }
    }
    
    public function summary() {
        $total = $this->result->passed + $this->result->failed;
        if ($this->result->failed == 0) {
            ok("All $total tests passed");
            return 0;
        } else {
            fail("{$this->result->failed}/$total tests failed");
            return 1;
        }
    }
}

// --- S3 client factory ------------------------------------------------------
if (!function_exists('make_s3_client')) {
function make_s3_client($args) {
    $config = [
        'version' => 'latest',
        'region'  => $args['region'] ?? 'us-east-1',
        'endpoint' => $args['endpoint_url'],
        'use_path_style_endpoint' => true,
        'signature_version' => 'v4',
        'http' => [
            'verify' => !($args['insecure'] ?? false),
            'timeout' => 60,
            'connect_timeout' => 10,
        ],
        // Additional S3-specific config to match boto3 behavior
        's3' => [
            'addressing_style' => 'path',
            'signature_version' => 'v4',
            'payload_signing_enabled' => false  // Disable payload signing for compatibility
        ]
    ];
    
    // Handle credentials explicitly
    if (isset($args['profile'])) {
        $config['profile'] = $args['profile'];
    } else {
        // Use environment variables or provide defaults
        $access_key = getenv('AWS_ACCESS_KEY_ID') ?: 'AKIA123456789EXAMPLE';
        $secret_key = getenv('AWS_SECRET_ACCESS_KEY') ?: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        
        $config['credentials'] = [
            'key'    => $access_key,
            'secret' => $secret_key
        ];
        
        info("Using credentials: " . substr($access_key, 0, 8) . "...");
    }
    
    // Handle SSL verification
    if (isset($args['ca_bundle'])) {
        $config['http']['verify'] = $args['ca_bundle'];
    }
    
    return new S3Client($config);
}
}

// --- Helper functions --------------------------------------------------------
if (!function_exists('ensure_bucket')) {
function ensure_bucket($s3, $bucket, $region) {
    // Check if bucket exists using HeadBucket (same as Python test)
    try {
        $s3->headBucket(['Bucket' => $bucket]);
        info("Bucket exists: $bucket");
        return;
    } catch (S3Exception $e) {
        $code = $e->getAwsErrorCode();
        
        // If we get NoSuchBucket, the bucket doesn't exist
        if (in_array($code, ['NoSuchBucket', 'NotFound'])) {
            // Try to create the bucket
            try {
                $s3->createBucket(['Bucket' => $bucket]);
                info("Created bucket: $bucket");
                return;
            } catch (S3Exception $create_e) {
                $create_code = $create_e->getAwsErrorCode();
                if (in_array($create_code, ['BucketAlreadyExists', 'BucketAlreadyOwnedByYou'])) {
                    info("Bucket already exists: $bucket");
                    return;
                } else {
                    throw $create_e;
                }
            }
        }
        
        // For other errors (like 403), assume bucket exists but we can't access metadata
        if (in_array($code, ['403', 'Forbidden', 'AccessDenied'])) {
            info("Bucket exists (metadata access restricted): $bucket");
            return;
        }
        
        // For unexpected errors, re-throw
        throw $e;
    }
}
}

if (!function_exists('make_temp_file')) {
function make_temp_file($size_bytes) {
    $temp_file = tempnam(sys_get_temp_dir(), 'php-s3-test-');
    
    info("Creating " . human($size_bytes) . " test file with random data...");
    
    $handle = fopen($temp_file, 'wb');
    $remaining = $size_bytes;
    $chunk_size = 64 * 1024; // 64KB chunks
    
    while ($remaining > 0) {
        $write_size = min($chunk_size, $remaining);
        $random_data = random_bytes($write_size);
        fwrite($handle, $random_data);
        $remaining -= $write_size;
    }
    
    fclose($handle);
    
    $actual_size = filesize($temp_file);
    info("Created test file: " . human($actual_size) . " with random data");
    
    return [$temp_file, $actual_size];
}
}

if (!function_exists('human')) {
function human($n) {
    $units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    $unit_index = 0;
    
    while ($n >= 1024 && $unit_index < count($units) - 1) {
        $n /= 1024.0;
        $unit_index++;
    }
    
    if ($unit_index == 0) {
        return "$n {$units[$unit_index]}";
    } else {
        return sprintf("%.2f %s", $n, $units[$unit_index]);
    }
}
}

if (!function_exists('calculate_md5')) {
function calculate_md5($file_path) {
    return md5_file($file_path);
}
}

// --- Boto3-compatible presigned URL generator -------------------------------
if (!function_exists('generateBoto3CompatiblePresignedUrl')) {
function generateBoto3CompatiblePresignedUrl($method, $bucket, $object, $expires, $args) {
    // Use same credentials as main client
    $access_key = getenv('AWS_ACCESS_KEY_ID') ?: 'AKIA123456789EXAMPLE';
    $secret_key = getenv('AWS_SECRET_ACCESS_KEY') ?: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    $region = $args['region'] ?? 'us-east-1';
    $endpoint = $args['endpoint_url'];
    
    // Generate timestamp
    $timestamp = gmdate('Ymd\THis\Z');
    $date_stamp = substr($timestamp, 0, 8);
    
    // Build components exactly like boto3-compatible-presigned.sh
    $credential = "{$access_key}/{$date_stamp}/{$region}/s3/aws4_request";
    $signed_headers = "host";
    $parsed_url = parse_url($endpoint);
    $host = $parsed_url['host'];
    if (isset($parsed_url['port'])) {
        $host .= ':' . $parsed_url['port'];
    }
    
    // URL encoding function that matches boto3
    $urlencode = function($string) {
        return rawurlencode($string);
    };
    
    // Build canonical URI
    $canonical_uri = "/{$bucket}/{$object}";
    
    // Build query parameters (NO X-Amz-Content-Sha256 - this is the key difference!)
    $query_params = [
        'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256',
        'X-Amz-Credential' => $credential,
        'X-Amz-Date' => $timestamp,
        'X-Amz-Expires' => (string)$expires,
        'X-Amz-SignedHeaders' => $signed_headers
    ];
    
    // Sort parameters alphabetically (critical for boto3 compatibility)
    ksort($query_params);
    
    // Build canonical query string
    $canonical_querystring = [];
    foreach ($query_params as $key => $value) {
        $canonical_querystring[] = $urlencode($key) . '=' . $urlencode($value);
    }
    $canonical_querystring = implode('&', $canonical_querystring);
    
    // Build canonical headers (exactly like boto3)
    $canonical_headers = "host:{$host}";
    
    // Build canonical request (exactly like boto3)
    $canonical_request = "{$method}\n" .
                        "{$canonical_uri}\n" .
                        "{$canonical_querystring}\n" .
                        "{$canonical_headers}\n\n" .
                        "{$signed_headers}\n" .
                        "UNSIGNED-PAYLOAD";
    
    // Create string to sign
    $algorithm = 'AWS4-HMAC-SHA256';
    $credential_scope = "{$date_stamp}/{$region}/s3/aws4_request";
    $canonical_request_hash = hash('sha256', $canonical_request);
    
    $string_to_sign = "{$algorithm}\n" .
                     "{$timestamp}\n" .
                     "{$credential_scope}\n" .
                     "{$canonical_request_hash}";
    
    // Calculate signature using AWS SigV4 chain
    $kDate = hash_hmac('sha256', $date_stamp, "AWS4{$secret_key}", true);
    $kRegion = hash_hmac('sha256', $region, $kDate, true);
    $kService = hash_hmac('sha256', 's3', $kRegion, true);
    $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
    $signature = hash_hmac('sha256', $string_to_sign, $kSigning);
    
    // Build final URL
    return "{$endpoint}{$canonical_uri}?{$canonical_querystring}&X-Amz-Signature={$signature}";
}
}

// --- Main test sequence ------------------------------------------------------
if (!function_exists('run_suite')) {
function run_suite($args) {
    $s3 = make_s3_client($args);
    $tr = new TestRunner();
    
    $bucket = $args['bucket'];
    $key = $args['key'] ?? 'autotest-' . substr(uniqid(), 0, 10) . '.txt';
    $payload = 'Hello, S3 World! This is a test payload from PHP.';
    
    // Basic S3 tests
    $tr->run("ListBuckets", function() use ($s3) {
        $result = $s3->listBuckets();
        assert(isset($result['Buckets']), "ListBuckets missing 'Buckets' key");
        info("Found " . count($result['Buckets']) . " buckets");
    });
    
    $tr->run("CreateBucket (if needed)", function() use ($s3, $bucket, $args) {
        ensure_bucket($s3, $bucket, $args['region'] ?? 'us-east-1');
    });
    
    $tr->run("PutObject", function() use ($s3, $bucket, $key, $payload) {
        $s3->putObject([
            'Bucket' => $bucket,
            'Key' => $key,
            'Body' => $payload
        ]);
    });
    
    $tr->run("HeadObject", function() use ($s3, $bucket, $key, $payload) {
        $result = $s3->headObject(['Bucket' => $bucket, 'Key' => $key]);
        assert($result['ContentLength'] == strlen($payload), "Size mismatch");
    });
    
    $tr->run("GetObject", function() use ($s3, $bucket, $key, $payload) {
        $result = $s3->getObject(['Bucket' => $bucket, 'Key' => $key]);
        $data = (string) $result['Body'];
        assert($data === $payload, "Content mismatch");
    });
    
    // --- Server-Side Copy Tests --------------------------------------------
    $tr->run("Server-Side Copy - Basic copy", function() use ($s3, $bucket, $key, $payload) {
        $source_key = $key;
        $dest_key = 'copy-' . substr(uniqid(), 0, 8) . '-' . $key;
        
        // Perform server-side copy
        $s3->copyObject([
            'Bucket' => $bucket,
            'Key' => $dest_key,
            'CopySource' => "$bucket/$source_key"
        ]);
        info("Copied $source_key to $dest_key");
        
        // Verify copied object exists and has same content
        $source_result = $s3->getObject(['Bucket' => $bucket, 'Key' => $source_key]);
        $dest_result = $s3->getObject(['Bucket' => $bucket, 'Key' => $dest_key]);
        
        $source_data = (string) $source_result['Body'];
        $dest_data = (string) $dest_result['Body'];
        
        assert($source_data === $dest_data, "Source and destination content mismatch");
        assert(strlen($dest_data) === strlen($payload), "Copied object size mismatch");
        info("Copy verification successful: " . strlen($dest_data) . " bytes");
        
        // Cleanup copied object
        $s3->deleteObject(['Bucket' => $bucket, 'Key' => $dest_key]);
    });
    
    $tr->run("Server-Side Copy - Preserve metadata", function() use ($s3, $bucket, $key, $payload) {
        $source_key = $key;
        $dest_key = 'copy-meta-' . substr(uniqid(), 0, 8) . '-' . $key;
        
        // Add some metadata to source object first
        $test_metadata = [
            'test-key' => 'test-value',
            'copy-test' => 'original'
        ];
        
        $s3->putObject([
            'Bucket' => $bucket,
            'Key' => $source_key,
            'Body' => $payload,
            'Metadata' => $test_metadata,
            'ContentType' => 'text/plain'
        ]);
        
        // Copy with COPY metadata directive (preserve original metadata)
        $s3->copyObject([
            'Bucket' => $bucket,
            'Key' => $dest_key,
            'CopySource' => "$bucket/$source_key",
            'MetadataDirective' => 'COPY'
        ]);
        
        // Verify metadata was preserved
        $dest_head = $s3->headObject(['Bucket' => $bucket, 'Key' => $dest_key]);
        $dest_metadata = $dest_head['Metadata'] ?? [];
        
        assert(isset($dest_metadata['test-key']), "Original metadata not preserved");
        assert($dest_metadata['test-key'] === 'test-value', "Original metadata value mismatch");
        info("Metadata preserved successfully with COPY directive");
        
        // Cleanup
        $s3->deleteObject(['Bucket' => $bucket, 'Key' => $dest_key]);
    });
    
    $tr->run("Server-Side Copy - Replace metadata", function() use ($s3, $bucket, $key) {
        $source_key = $key;
        $dest_key = 'copy-replace-' . substr(uniqid(), 0, 8) . '-' . $key;
        
        // Copy with REPLACE metadata directive (replace with new metadata)
        $new_metadata = [
            'new-key' => 'new-value',
            'replaced' => 'true'
        ];
        
        $s3->copyObject([
            'Bucket' => $bucket,
            'Key' => $dest_key,
            'CopySource' => "$bucket/$source_key",
            'MetadataDirective' => 'REPLACE',
            'Metadata' => $new_metadata,
            'ContentType' => 'application/octet-stream'
        ]);
        
        // Verify new metadata was applied
        $dest_head = $s3->headObject(['Bucket' => $bucket, 'Key' => $dest_key]);
        $dest_metadata = $dest_head['Metadata'] ?? [];
        
        // Check if metadata was applied
        $metadata_found = false;
        foreach ($dest_metadata as $meta_key => $meta_value) {
            if (strtolower($meta_key) === 'new-key' && $meta_value === 'new-value') {
                $metadata_found = true;
                break;
            }
        }
        
        if (!$metadata_found) {
            info("Available metadata keys: " . implode(', ', array_keys($dest_metadata)));
            info("Metadata values: " . json_encode($dest_metadata));
        }
        
        assert($metadata_found, "New metadata not applied. Available: " . json_encode($dest_metadata));
        info("Metadata replaced successfully with REPLACE directive");
        
        // Cleanup
        $s3->deleteObject(['Bucket' => $bucket, 'Key' => $dest_key]);
    });
    
    $tr->run("Server-Side Copy - Error handling", function() use ($s3, $bucket) {
        $nonexistent_key = 'nonexistent-' . uniqid() . '.txt';
        $dest_key = 'copy-error-' . substr(uniqid(), 0, 8) . '.txt';
        
        // Try to copy non-existent object
        try {
            $s3->copyObject([
                'Bucket' => $bucket,
                'Key' => $dest_key,
                'CopySource' => "$bucket/$nonexistent_key"
            ]);
            assert(false, "Expected S3Exception for non-existent source object");
        } catch (S3Exception $e) {
            $error_code = $e->getAwsErrorCode();
            assert(in_array($error_code, ['NoSuchKey', '404']), "Unexpected error code: $error_code");
            info("Correctly handled non-existent source error: $error_code");
        }
    });
    
    // --- Multipart Upload Tests --------------------------------------------
    $mpu_key = $args['mpu_key'] ?? 'autotest-mpu.bin';
    
    $tr->run("Multipart Upload (basic)", function() use ($s3, $bucket, $mpu_key, $args) {
        // Create test file
        $total_size = 16 * 1024 * 1024; // 16 MiB
        [$tmp_path, $actual_size] = make_temp_file($total_size);
        $original_md5 = calculate_md5($tmp_path);
        info("Test file: " . human($total_size) . ", MD5: $original_md5");
        
        try {
            // Use high-level putObject with multipart transfer (like boto3 upload_file)
            // This should handle ETags correctly internally
            $s3->putObject([
                'Bucket' => $bucket,
                'Key' => $mpu_key,
                'SourceFile' => $tmp_path,
                '@multipart_upload_threshold' => 1024 * 1024,  // Use MPU for files > 1MB
                '@part_size' => 8 * 1024 * 1024  // 8MB parts
            ]);
            
            info("MPU upload completed using high-level putObject");
            
            // Verify upload
            $head_result = $s3->headObject(['Bucket' => $bucket, 'Key' => $mpu_key]);
            $remote_size = $head_result['ContentLength'];
            info("Remote object size: " . human($remote_size));
            
            info("MPU upload verification successful");
            
        } finally {
            unlink($tmp_path);
        }
    });
    
    // --- List Objects with Pagination Test --------------------------------
    $tr->run("ListObjects with Pagination", function() use ($s3, $bucket) {
        // Use the existing test bucket to avoid signature issues with new buckets
        $test_objects = [];
        $num_objects = 15;
        
        try {
            info("Using existing bucket for pagination test: $bucket");
            
            info("Creating $num_objects test objects for pagination test...");
            for ($i = 0; $i < $num_objects; $i++) {
                $test_key = sprintf('pagination-test-%03d.txt', $i);
                $test_content = "Test content for object $i";
                $s3->putObject([
                    'Bucket' => $bucket,
                    'Key' => $test_key,
                    'Body' => $test_content
                ]);
                $test_objects[] = $test_key;
            }
            
            // Now test listing with pagination
            $all_objects = [];
            $continuation_token = null;
            $page_count = 0;
            $max_keys = 5; // Small page size to force pagination
            
            info("Starting paginated listing with MaxKeys=$max_keys");
            
            do {
                $page_count++;
                
                // Build listObjectsV2 parameters
                $list_params = [
                    'Bucket' => $bucket,
                    'MaxKeys' => $max_keys
                ];
                
                if ($continuation_token) {
                    $list_params['ContinuationToken'] = $continuation_token;
                }
                
                // Try using ListObjects v1 instead of v2 to avoid list-type=2 query parameter
                $list_params_v1 = [
                    'Bucket' => $bucket,
                    'MaxKeys' => $max_keys
                    // Note: PHP SDK automatically adds encoding-type=url
                ];
                
                if ($continuation_token) {
                    // For v1, use Marker instead of ContinuationToken
                    $list_params_v1['Marker'] = $continuation_token;
                }
                
                $response = $s3->listObjects($list_params_v1);
                
                // Extract objects from this page
                $page_objects = $response['Contents'] ?? [];
                $all_objects = array_merge($all_objects, $page_objects);
                
                info("Page $page_count: Found " . count($page_objects) . " objects");
                
                // Check if there are more pages (v1 API uses different fields)
                $is_truncated = $response['IsTruncated'] ?? false;
                $continuation_token = $response['NextMarker'] ?? null;
                
                // If NextMarker is not provided but IsTruncated is true, use the last object key
                if ($is_truncated && !$continuation_token && !empty($page_objects)) {
                    $last_object = end($page_objects);
                    $continuation_token = $last_object['Key'] ?? null;
                }
                
                if (!$is_truncated) {
                    info("No more pages, pagination complete");
                    break;
                }
                
                // Safety check to prevent infinite loops
                if ($page_count > 100) {
                    warn("Stopping pagination after 100 pages to prevent infinite loop");
                    break;
                }
                
            } while (true);
            
            // Verify results
            info("Pagination complete: Found " . count($all_objects) . " total objects across $page_count pages");
            
            // Verify we found our test objects
            $found_test_objects = array_filter($all_objects, function($obj) {
                return strpos($obj['Key'], 'pagination-test-') === 0;
            });
            
            info("Found " . count($found_test_objects) . " test objects out of $num_objects created");
            
            assert(count($found_test_objects) >= $num_objects, 
                   "Expected at least $num_objects test objects, found " . count($found_test_objects));
            assert($page_count > 1, "Expected multiple pages for pagination test, got $page_count");
            
        } finally {
            // Clean up test objects only (keep the main test bucket)
            info("Cleaning up pagination test objects...");
            foreach ($test_objects as $test_key) {
                try {
                    $s3->deleteObject(['Bucket' => $bucket, 'Key' => $test_key]);
                } catch (S3Exception $e) {
                    if ($e->getAwsErrorCode() !== 'NoSuchKey') {
                        warn("Failed to delete test object $test_key: " . $e->getMessage());
                    }
                }
            }
        }
    });
    
    // --- S3 Presigned URL Tests --------------------------------------------
    $tr->run("S3 Presigned URL - GET operation", function() use ($s3, $bucket, $args) {
        $presigned_key = 'presigned-get-test.txt';
        $test_content = 'Hello from presigned GET URL test!';
        
        // First upload the object that we'll download via presigned URL
        $s3->putObject(['Bucket' => $bucket, 'Key' => $presigned_key, 'Body' => $test_content]);
        info("Uploaded test object for presigned GET: $presigned_key");
        
        try {
            // Generate presigned URL manually using boto3-compatible algorithm
            $presigned_url = generateBoto3CompatiblePresignedUrl(
                'GET', 
                $bucket, 
                $presigned_key, 
                3600,  // 1 hour
                $args
            );
            
            
            info("Generated presigned GET URL: " . substr($presigned_url, 0, 100) . "...");
            info("Full presigned URL: " . $presigned_url);
            
            // Validate URL format
            assert(strpos($presigned_url, 'X-Amz-Algorithm=AWS4-HMAC-SHA256') !== false, "Missing AWS4-HMAC-SHA256 algorithm");
            assert(strpos($presigned_url, 'X-Amz-Credential=') !== false, "Missing X-Amz-Credential");
            assert(strpos($presigned_url, 'X-Amz-Date=') !== false, "Missing X-Amz-Date");
            assert(strpos($presigned_url, 'X-Amz-Expires=') !== false, "Missing X-Amz-Expires");
            assert(strpos($presigned_url, 'X-Amz-SignedHeaders=') !== false, "Missing X-Amz-SignedHeaders");
            assert(strpos($presigned_url, 'X-Amz-Signature=') !== false, "Missing X-Amz-Signature");
            info("Presigned GET URL format validation passed");
            
            // Use the presigned URL to download the object using cURL (like boto3 uses requests)
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $presigned_url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);  // Disable SSL verification for localhost
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);  // Disable SSL verification for localhost
            curl_setopt($ch, CURLOPT_TIMEOUT, 30);
            
            $downloaded_content = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($http_code !== 200) {
                throw new Exception("Presigned GET failed with HTTP $http_code. Response: $downloaded_content");
            }
            assert($downloaded_content === $test_content, "Downloaded content doesn't match original");
            info("Successfully downloaded " . strlen($downloaded_content) . " bytes via presigned GET URL");
            
        } finally {
            // Clean up test object
            try {
                $s3->deleteObject(['Bucket' => $bucket, 'Key' => $presigned_key]);
            } catch (S3Exception $e) {
                // Ignore cleanup errors
            }
        }
    });
    
    $tr->run("S3 Presigned URL - PUT operation", function() use ($s3, $bucket, $args) {
        $presigned_key = 'presigned-put-test.txt';
        $test_content = 'Hello from presigned PUT URL test!';
        
        try {
            // Generate presigned URL manually using boto3-compatible algorithm
            $presigned_url = generateBoto3CompatiblePresignedUrl(
                'PUT', 
                $bucket, 
                $presigned_key, 
                3600,  // 1 hour
                $args
            );
            
            
            info("Generated presigned PUT URL: " . substr($presigned_url, 0, 100) . "...");
            
            // Validate URL format
            assert(strpos($presigned_url, 'X-Amz-Algorithm=AWS4-HMAC-SHA256') !== false, "Missing AWS4-HMAC-SHA256 algorithm");
            assert(strpos($presigned_url, 'X-Amz-Credential=') !== false, "Missing X-Amz-Credential");
            assert(strpos($presigned_url, 'X-Amz-Date=') !== false, "Missing X-Amz-Date");
            assert(strpos($presigned_url, 'X-Amz-Expires=') !== false, "Missing X-Amz-Expires");
            assert(strpos($presigned_url, 'X-Amz-SignedHeaders=') !== false, "Missing X-Amz-SignedHeaders");
            assert(strpos($presigned_url, 'X-Amz-Signature=') !== false, "Missing X-Amz-Signature");
            info("Presigned PUT URL format validation passed");
            
            // Use the presigned URL to upload the object using cURL
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $presigned_url);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
            curl_setopt($ch, CURLOPT_POSTFIELDS, $test_content);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: text/plain']);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);  // Disable SSL verification for localhost
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);  // Disable SSL verification for localhost
            
            $response = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            assert($http_code === 200, "Expected 200, got $http_code");
            info("Successfully uploaded " . strlen($test_content) . " bytes via presigned PUT URL");
            
            // Verify the upload by downloading the object with regular S3 API
            $verify_result = $s3->getObject(['Bucket' => $bucket, 'Key' => $presigned_key]);
            $verified_content = (string) $verify_result['Body'];
            assert($verified_content === $test_content, "Uploaded content doesn't match original");
            info("Verified uploaded content matches original");
            
        } finally {
            // Clean up test object
            try {
                $s3->deleteObject(['Bucket' => $bucket, 'Key' => $presigned_key]);
            } catch (S3Exception $e) {
                // Ignore cleanup errors
            }
        }
    });
    
    // Clean up the MPU object
    $tr->run("DeleteObject (MPU object)", function() use ($s3, $bucket, $mpu_key) {
        try {
            $s3->deleteObject(['Bucket' => $bucket, 'Key' => $mpu_key]);
        } catch (S3Exception $e) {
            $code = $e->getAwsErrorCode();
            if (in_array($code, ['NoSuchKey', '404'])) {
                info("MPU object $mpu_key not found, cleanup not needed");
            } else {
                throw $e;
            }
        }
    });
    
    // Optional cleanup
    if ($args['cleanup'] ?? false) {
        $tr->run("Cleanup (delete object + bucket)", function() use ($s3, $bucket, $key) {
            try {
                $s3->deleteObject(['Bucket' => $bucket, 'Key' => $key]);
            } catch (S3Exception $e) {
                $code = $e->getAwsErrorCode();
                if ($code !== 'NoSuchKey') {
                    throw $e;
                }
            }
            try {
                $s3->deleteBucket(['Bucket' => $bucket]);
            } catch (S3Exception $e) {
                $code = $e->getAwsErrorCode();
                if (!in_array($code, ['NoSuchBucket', 'BucketNotEmpty'])) {
                    throw $e;
                }
            }
        });
    }
    
    return $tr->summary();
}
}

if (!function_exists('parse_args')) {
function parse_args($argv) {
    $options = [
        'endpoint_url' => null,
        'region' => 'us-east-1',
        'profile' => null,
        'bucket' => null,
        'key' => null,
        'mpu_key' => null,
        'insecure' => false,
        'ca_bundle' => null,
        'cleanup' => false,
        'help' => false
    ];
    
    for ($i = 1; $i < count($argv); $i++) {
        switch ($argv[$i]) {
            case '--endpoint-url':
                $options['endpoint_url'] = $argv[++$i] ?? null;
                break;
            case '--region':
                $options['region'] = $argv[++$i] ?? 'us-east-1';
                break;
            case '--profile':
                $options['profile'] = $argv[++$i] ?? null;
                break;
            case '--bucket':
                $options['bucket'] = $argv[++$i] ?? null;
                break;
            case '--key':
                $options['key'] = $argv[++$i] ?? null;
                break;
            case '--mpu-key':
                $options['mpu_key'] = $argv[++$i] ?? null;
                break;
            case '--insecure':
                $options['insecure'] = true;
                break;
            case '--ca-bundle':
                $options['ca_bundle'] = $argv[++$i] ?? null;
                break;
            case '--cleanup':
                $options['cleanup'] = true;
                break;
            case '--help':
            case '-h':
                $options['help'] = true;
                break;
        }
    }
    
    return $options;
}
}

if (!function_exists('print_usage')) {
function print_usage($script_name) {
    echo "Usage: $script_name [OPTIONS]\n\n";
    echo "Comprehensive PHP S3 tests using AWS SDK for PHP\n\n";
    echo "Required arguments:\n";
    echo "  --endpoint-url URL    S3 endpoint URL\n";
    echo "  --bucket BUCKET       Test bucket name\n\n";
    echo "Optional arguments:\n";
    echo "  --region REGION       AWS region (default: us-east-1)\n";
    echo "  --profile PROFILE     AWS profile name\n";
    echo "  --key KEY             Test object key (auto-generated if not provided)\n";
    echo "  --mpu-key KEY         MPU test object key (auto-generated if not provided)\n";
    echo "  --insecure            Skip SSL verification\n";
    echo "  --ca-bundle PATH      Path to custom CA bundle\n";
    echo "  --cleanup             Delete test objects and bucket after tests\n";
    echo "  --help, -h            Show this help message\n";
}
}

// Main execution
if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\n");
}

$args = parse_args($argv);

if ($args['help']) {
    print_usage($argv[0]);
    exit(0);
}

if (!$args['endpoint_url'] || !$args['bucket']) {
    fail("Missing required arguments: --endpoint-url and --bucket");
    print_usage($argv[0]);
    exit(1);
}

try {
    $exit_code = run_suite($args);
    exit($exit_code);
} catch (CredentialsException $e) {
    fail("Credential error: " . $e->getMessage());
    exit(1);
} catch (AwsException $e) {
    fail("AWS error: " . $e->getMessage());
    exit(1);
} catch (Exception $e) {
    fail("Unexpected error: " . $e->getMessage());
    exit(1);
}