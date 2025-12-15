# Unit Test Coverage

This document describes all unit tests available for the helper functions extracted during the refactoring work.

---

## AWS Chunked Encoding Tests

### Test File: `test/aws-chunked-encoding.test.js`

**What it tests:**
- `isAwsChunked()` - Detects AWS chunked transfer encoding from headers
- `getDecodedSize()` - Extracts decoded content length from headers
- `configureAwsChunkedEncoding()` - Configures AWS chunked encoding settings for part requests

**Test Cases (12 tests, 18 assertions):**

1. **isAwsChunked:**
   - Returns true for 'aws-chunked' content-encoding
   - Returns false for other encodings (e.g., 'gzip')
   - Returns false when no encoding header present

2. **getDecodedSize:**
   - Returns parsed size from x-amz-decoded-content-length header
   - Returns null when header is missing
   - Returns null for invalid number strings
   - Handles zero size correctly

3. **configureAwsChunkedEncoding:**
   - Sets _size to decoded size for aws-chunked requests
   - Sets _awsChunkedExpectedSize and _awsChunkedMPU flags
   - Skips configuration for non-chunked requests
   - Handles missing decoded size gracefully
   - Handles invalid decoded size values
   - Preserves encoded content-length header

**How to run:**
```bash
node node_modules/.bin/nodeunit test/aws-chunked-encoding.test.js
```

---

## S3 Upload Part Handler Tests

### Test File: `test/s3-upload-part-helpers.test.js`

**What it tests:**
- `validatePartNumber()` - Validates part numbers are in range 1-10000
- `generatePartKey()` - Generates part key path from upload ID and part number
- `resolveETag()` - Resolves final ETag with priority: captured > result.id > 'unknown'
- `createIsChunkedFunction()` - Creates function to detect chunked transfer encoding
- `configureDurabilityLevel()` - Extracts durability level from upload record or headers

**Test Cases (13 tests, 24 assertions):**

1. **validatePartNumber:**
   - Accepts valid part numbers (1, 5000, 10000)
   - Rejects invalid part numbers (0, -1, 10001)

2. **generatePartKey:**
   - Generates correct format: `.mpu-parts/{uploadId}/{partNumber}`
   - Handles various upload IDs and part numbers

3. **resolveETag:**
   - Prioritizes captured ETag when available
   - Falls back to result.id when no captured ETag
   - Returns 'unknown' when no ETag sources available

4. **createIsChunkedFunction:**
   - Checks transfer-encoding header for 'chunked'
   - Uses req.isChunked() when available
   - Returns false for non-chunked encodings

5. **configureDurabilityLevel:**
   - Uses durability level from upload record when available
   - Falls back to request headers (durability-level or x-durability-level)
   - Uses default value (2) when no sources available
   - Sets header as string value

**How to run:**
```bash
node node_modules/.bin/nodeunit test/s3-upload-part-helpers.test.js
```

---

### Test File: `test/s3-upload-part-helpers-advanced.test.js`

**What it tests (uses mock infrastructure):**
- `configureBasicPartRequest()` - Configures part request with params, headers, objectId
- `configurePreAllocatedSharks()` - Configures pre-allocated sharks from upload record
- `createETagCapturingResponse()` - Creates response wrapper that captures ETag headers

**Test Cases (8 tests, 19 assertions):**

1. **configureBasicPartRequest:**
   - Sets bucket_name, object_name, objectId correctly
   - Copies request headers to part request
   - Provides header() function for retrieving headers
   - Marks request as S3 request with PUT method

2. **configurePreAllocatedSharks:**
   - Sets preAllocatedSharks from upload record when available
   - Logs error when no sharks found in upload record
   - Preserves all shark data

3. **createETagCapturingResponse:**
   - Captures ETag from header() method
   - Captures ETag from setHeader() method
   - Handles case-insensitive ETag headers (ETAG, ETag, etag)
   - Returns null when no ETag is set

**How to run:**
```bash
node node_modules/.bin/nodeunit test/s3-upload-part-helpers-advanced.test.js
```

---

## S3 Complete Multipart Upload Tests

### Test File: `test/s3-complete-mpu-helpers.test.js`

**What it tests:**
- `extractPartETags()` - Extracts ETag array from parsed XML parts
- `createCommitBody()` - Creates commit body structure for multipart assembly
- `transformAssemblyError()` - Transforms assembly errors to S3-compatible errors
- `releaseLockSafely()` - Safely releases distributed lock with logging
- `cleanupAndExit()` - Releases lock before calling error callback

**Test Cases (13 tests, 31 assertions):**

1. **extractPartETags:**
   - Extracts ETag array from parts with multiple entries
   - Handles empty array
   - Handles single part

2. **createCommitBody:**
   - Creates valid structure with version, nbytes, account, objectId, parts
   - Handles zero bytes
   - Includes all part ETags in correct order

3. **transformAssemblyError:**
   - Transforms NotEnoughSpaceError to 507 InsufficientStorage
   - Uses default message for NotEnoughSpaceError when message is empty
   - Transforms generic errors to 500 InternalError
   - Uses default message for generic errors when message is empty

4. **releaseLockSafely:**
   - Returns immediately when lockInfo is null
   - Calls lockManager.releaseLock() for valid lockInfo
   - Handles release errors by logging warning and passing error to callback

5. **cleanupAndExit:**
   - Releases lock before calling callback
   - Passes original error to callback after lock release

**How to run:**
```bash
node node_modules/.bin/nodeunit test/s3-complete-mpu-helpers.test.js
```

---

## Distributed Lock Manager Tests

### Test File: `test/acquire-lock-helpers.test.js`

**What it tests:**
- `createLockData()` - Creates lock data structure with metadata
- `parseLockState()` - Parses existing lock state from JSON and headers
- `determineLockAction()` - Determines action based on lock ownership and expiration

**Test Cases (10 tests, 28 assertions):**

1. **createLockData:**
   - Creates valid structure with uploadId, instanceId, acquired, expires
   - Sets operation to 'complete-multipart'
   - Includes processId and hostname
   - Sets expiration in future based on lockTimeout

2. **parseLockState:**
   - Parses valid JSON lock data
   - Handles missing expires by checking headers (x-lock-expires)
   - Extracts instanceId from headers as fallback (x-lock-instance)
   - Flags parsing errors for invalid expiration dates
   - Returns success:false for invalid JSON

3. **determineLockAction:**
   - Returns 'owned' action when instanceId matches
   - Returns 'claim-expired' action for expired locks
   - Returns 'retry-held' action for active locks held by others
   - Returns 'retry-parsing-error' for locks with parsing errors
   - Includes appropriate metadata for each action type

**How to run:**
```bash
node node_modules/.bin/nodeunit test/acquire-lock-helpers.test.js
```

---

### Test File: `test/acquire-lock-helpers-advanced.test.js`

**What it tests (uses mock Manta client):**
- `createLockAtomic()` - Atomically creates lock using Manta createObject
- `updateLockAtomic()` - Atomically updates expired lock using Manta updateObject

**Test Cases (6 tests, 13 assertions):**

1. **createLockAtomic:**
   - Creates lock successfully and returns success action with lockInfo
   - Handles ObjectExistsError (race condition) by returning retry-race action
   - Handles system errors by returning error action with error object

2. **updateLockAtomic:**
   - Updates expired lock successfully and returns success action
   - Handles ObjectNotFoundError (lock deleted) by returning retry-deleted action
   - Handles system errors by returning error action with error object

**How to run:**
```bash
node node_modules/.bin/nodeunit test/acquire-lock-helpers-advanced.test.js
```

---

## Anonymous Access Handler Tests

### Test File: `test/anonymous-access-helpers.test.js`

**What it tests:**
- `parseMantaBucketObjectPath()` - Parses Manta bucket object path into parts
- `isMantaAnonymousObjectAccess()` - Checks if request is for anonymous object access
- `setupMantaObjectParams()` - Extracts account, bucket_name, object_name from path
- `flattenHandlers()` - Flattens nested handler arrays into single array
- `executeHandlerChain()` - Executes middleware handler chain with error handling

**Test Cases (17 tests, 42 assertions):**

1. **parseMantaBucketObjectPath:**
   - Parses standard path into parts (account/buckets/name/objects/file)
   - Handles trailing slashes by filtering empty segments
   - Handles nested object paths (folder/subfolder/file)

2. **isMantaAnonymousObjectAccess:**
   - Returns true for valid anonymous access path with flag set
   - Returns false when potentialAnonymousAccess flag is false
   - Returns false for paths with less than 5 parts
   - Returns false for incorrect path format (wrong keywords)

3. **setupMantaObjectParams:**
   - Extracts account, bucket_name, object_name from path parts
   - Handles nested object paths by joining with slashes
   - Creates params object if missing

4. **flattenHandlers:**
   - Flattens nested handler arrays into single array
   - Handles all nested arrays
   - Preserves non-nested handlers

5. **executeHandlerChain:**
   - Executes all handlers sequentially
   - Stops execution on error
   - Handles invalid handlers (non-functions) with error
   - Catches exceptions thrown by handlers

**How to run:**
```bash
node node_modules/.bin/nodeunit test/anonymous-access-helpers.test.js
```

---

## Running All Tests

### Run all unit tests:
```bash
node node_modules/.bin/nodeunit \
  test/aws-chunked-encoding.test.js \
  test/s3-upload-part-helpers.test.js \
  test/s3-upload-part-helpers-advanced.test.js \
  test/s3-complete-mpu-helpers.test.js \
  test/acquire-lock-helpers.test.js \
  test/acquire-lock-helpers-advanced.test.js \
  test/anonymous-access-helpers.test.js
```

### Run tests for specific topic:
```bash
# AWS Chunked Encoding
node node_modules/.bin/nodeunit test/aws-chunked-encoding.test.js

# S3 Upload Part
node node_modules/.bin/nodeunit test/s3-upload-part-helpers*.test.js

# S3 Complete Multipart Upload
node node_modules/.bin/nodeunit test/s3-complete-mpu-helpers.test.js

# Distributed Locking
node node_modules/.bin/nodeunit test/acquire-lock-helpers*.test.js

# Anonymous Access
node node_modules/.bin/nodeunit test/anonymous-access-helpers.test.js
```

---

## Test Summary

| Topic | Test Files | Tests | Assertions |
|-------|------------|-------|------------|
| AWS Chunked Encoding | 1 | 12 | 18 |
| S3 Upload Part | 2 | 21 | 43 |
| S3 Complete MPU | 1 | 13 | 31 |
| Distributed Locking | 2 | 16 | 41 |
| Anonymous Access | 1 | 17 | 42 |
| **TOTAL** | **7** | **79** | **175** |

---

## Mock Infrastructure

Tests marked with "uses mock infrastructure" or "uses mock Manta client" utilize the mock factories defined in `test/mock-infrastructure.js`. These mocks enable testing of functions that require complex dependencies like:

- Manta metadata client (createObject, updateObject, getObject)
- BucketHelpers module
- Request/Response objects
- Logger instances
- Metadata placement

See `test/mock-infrastructure.js` for complete mock factory documentation.

---

**Last Updated**: 2025-12-14
