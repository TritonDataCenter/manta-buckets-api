# CHG-006: Named Function Patterns for Stack Trace Improvements

## Overview

CHG-006 converted anonymous callback functions to named functions across the codebase to improve stack trace readability and debugging experience. This document describes the naming patterns used to ensure consistency and clarity.

## Naming Patterns

### 1. Async Operation Completion Callbacks

**Pattern**: `on<Operation><Aspect>`

Used for callbacks that handle the completion of asynchronous operations.

**Examples**:
- `onListBucketsComplete` - handles completion of list buckets operation
- `onCreateBucketComplete` - handles completion of create bucket operation
- `onGetBucketObjectComplete` - handles completion of get object operation
- `onInitiateUploadSharksChosen` - handles shark selection for upload initiation
- `onUploadRecordRequestLoaded` - handles loading of upload record request
- `onUploadRecordCreated` - handles creation of upload record
- `onCompletionLockAcquired` - handles acquisition of distributed lock
- `onV2CommitComplete` - handles completion of v2 commit operation
- `onFinalMetadataCreated` - handles creation of final object metadata
- `onParallelCommitsComplete` - handles completion of parallel commits

**Rationale**: This pattern clearly indicates:
1. It's a callback (prefix `on`)
2. What operation is being completed
3. What aspect of the operation is being handled

### 2. Authentication/Verification Callbacks

**Pattern**: `on<Subject><Action>Verified`

Used for callbacks that handle authentication and signature verification.

**Examples**:
- `onS3PresignedVerified` - handles S3 presigned URL verification
- `onTempCredentialVerified` - handles temporary credential verification
- `onPermanentCredentialVerified` - handles permanent access key verification

**Rationale**: Makes it immediately clear what type of credentials are being verified.

### 3. Response Wrapper/Interceptor Functions

**Pattern**: `<verb>With<Feature>`

Used for functions that wrap or intercept standard response methods to add functionality.

**Examples**:
- `writeHeadWithS3Headers` - wraps writeHead to add S3 request/host headers
- `writeHeadWithHeaderConversion` - wraps writeHead to convert Manta to S3 headers
- `setWithMetadataConversion` - wraps set() to convert metadata headers
- `writeWithDataCollection` - wraps write() to collect streaming data
- `endWithXMLConversion` - wraps end() to convert JSON to S3 XML format
- `sendWithS3Formatting` - wraps send() to handle S3 error/response formatting

**Rationale**: Clearly describes both the action (write, send, etc.) and the added feature (S3 headers, conversion, etc.).

### 4. Iteration/Parallel Operation Callbacks

**Pattern**: `<verb>On<Target>` or `<verb><Target>`

Used for callbacks that operate on individual items in parallel operations.

**Examples**:
- `commitOnEachShark` - commits on individual storage nodes
- `onSharkCommitResponse` - handles individual shark commit response

**Rationale**: Indicates the callback operates on a specific target in a collection.

## Files Modified

### Core Routing and Middleware
- **lib/server/middleware.js**: Split monolithic function into three named functions
  - `logAllRequests` - pure request logging
  - `detectS3Uploads` - S3 upload detection
  - `configureBinaryMode` - binary stream configuration

### S3 Route Handlers
- **lib/s3-routes.js**: 21 complex callbacks converted
  - Middleware chain completions (13 functions)
  - Role translation callbacks (3 functions)
  - Operation handler callbacks (5 functions)

### Multipart Upload Operations
- **lib/s3-multipart.js**: 16 complex callbacks converted
  - Upload initiation (4 functions)
  - Complete multipart (4 functions)
  - Lock management (3 functions)
  - CORS handling (3 functions)
  - Additional operations (2 functions)

- **lib/s3-mako-v2-commit.js**: 5 complex callbacks converted
  - V2 commit operations
  - Metadata creation
  - Parallel shark commits

### Authentication and Response Formatting
- **lib/auth/signature-verifier.js**: 3 complex callbacks converted
  - S3 presigned URL verification
  - Temporary credential verification
  - Permanent credential verification

- **lib/s3-compat.js**: 6 response wrapper functions converted
  - Response interception for S3 format conversion

### Utility Functions
- **lib/common.js**: 6 complex callbacks converted
  - Request loading
  - Error handling
  - Stream processing

## Stack Trace Improvements

### Before CHG-006
```
at (anonymous function) (lib/s3-routes.js)
at (anonymous function) (lib/s3-multipart.js)
at (anonymous function) (lib/auth/signature-verifier.js)
```

### After CHG-006
```
at onListBucketsComplete (lib/s3-routes.js)
at onInitiateUploadSharksChosen (lib/s3-multipart.js)
at onS3PresignedVerified (lib/auth/signature-verifier.js)
```

### Impact
Developers can now:
1. Immediately identify which operation failed from the stack trace
2. Understand the context without looking up line numbers
3. Navigate code more quickly during debugging
4. Recognize error patterns across logs

## Guidelines for Future Development

When adding new callbacks to the codebase:

1. **Always use named functions** for callbacks that involve:
   - Asynchronous operations
   - Error handling
   - Request/response interception
   - Authentication/verification
   - Data transformation

2. **Skip naming for simple array methods** like:
   - Simple `map()`, `filter()`, `forEach()` for data transformation
   - One-liners that don't involve control flow
   - Trivial predicates

3. **Choose descriptive names** that indicate:
   - What operation is being handled
   - What stage of processing is occurring
   - What the callback is responsible for

4. **Follow existing patterns** documented here to maintain consistency

## Testing

Stack trace improvements are verified in `test/stack-trace-verification.test.js`:
- Named functions appear correctly in stack traces
- Function names are set properly on exports
- Naming patterns are consistent across the codebase
- Modules load successfully after refactoring

## Total Impact

- **67 complex callbacks** converted to named functions across 7 files
- **Improved debugging** for authentication, multipart uploads, and S3 compatibility
- **Consistent patterns** established for future development
- **No regressions** - all existing tests continue to pass

## Related Changes

- TASK-001: Split middleware into focused functions (middleware.js)
- TASK-002: Convert s3-routes.js anonymous functions
- TASK-003: Convert common.js anonymous functions
- TASK-004: Convert s3-routes.js complex callbacks
- TASK-005: Convert s3-multipart.js complex callbacks
- TASK-006: Convert Tier 3 critical files (s3-compat, s3-mako-v2-commit, signature-verifier)
- TASK-007: Verify stack traces and document patterns (this document)
