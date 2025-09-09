# S3 Error Codes Reference

This document describes all error codes, HTTP status codes, error messages, and conditions that manta-buckets-api can send to S3 clients.

## Authentication and Authorization Errors

| **Error Code** | **HTTP Status** | **Error Message** | **When/Why Occurs** | **S3 Operations** |
|---|---|---|---|---|
| `AccessDenied` | 403 | "Access Denied" | User lacks permission for the operation | All S3 operations |
| `SignatureDoesNotMatch` | 403 | "The request signature we calculated does not match the signature you provided." | S3 signature validation fails | All authenticated operations |
| `InvalidSignature` | 403 | "The signature we calculated does not match the one you sent" | Signature validation fails | All S3 operations |
| `RequestTimeTooSkewed` | 403 | "The difference between the request time and the current time is too large." | Request timestamp outside acceptable range | All timestamped operations |
| `AuthorizationRequired` | 401 | "Authorization is required" | Authentication missing | All S3 operations |
| `InvalidKeyId` | 403 | "the KeyId token you provided is invalid" | Key ID in auth is invalid | All S3 operations |

## Bucket-Related Errors

| **Error Code** | **HTTP Status** | **Error Message** | **When/Why Occurs** | **S3 Operations** |
|---|---|---|---|---|
| `NoSuchBucket` | 404 | "The specified bucket does not exist." | Accessing non-existent bucket | All bucket operations |
| `BucketAlreadyExists` | 409 | "The requested bucket name is not available." | Creating bucket with existing name | CreateBucket |
| `BucketNotEmpty` | 409 | "{bucket} is not empty" | Deleting non-empty bucket | DeleteBucket |
| `InvalidBucketName` | 422 | "{name} is not a valid bucket name" | Bucket name violates naming rules | CreateBucket |

## Object-Related Errors

| **Error Code** | **HTTP Status** | **Error Message** | **When/Why Occurs** | **S3 Operations** |
|---|---|---|---|---|
| `NoSuchKey` | 404 | "The specified key does not exist." | Accessing non-existent object | GetObject, HeadObject, DeleteObject |
| `ObjectNotFound` | 404 | "{object} was not found" | Object doesn't exist | All object operations |
| `InvalidBucketObjectName` | 422 | "{name} is not a valid bucket object name" | Object name violates naming rules | All object operations |

## Multipart Upload Errors

| **Error Code** | **HTTP Status** | **Error Message** | **When/Why Occurs** | **S3 Operations** |
|---|---|---|---|---|
| `InvalidPart` | 400 | "One or more parts have size discrepancies that prevent assembly" | Part references are invalid or parts are missing | CompleteMultipartUpload |
| `EntityTooSmall` | 400 | "Your proposed upload is smaller than the minimum allowed object size." | Multipart part < 5MB (except last part) | UploadPart |
| `MultipartUploadInvalidArgument` | 409 | "cannot create upload: {msg}" or "upload {id}: {msg}" | Invalid multipart upload arguments | InitiateMultipartUpload, UploadPart, CompleteMultipartUpload |
| `InvalidMultipartUploadState` | 409 | "upload {id}: {msg}" | Multipart upload in wrong state | CompleteMultipartUpload, AbortMultipartUpload |

## Content and Transfer Errors

| **Error Code** | **HTTP Status** | **Error Message** | **When/Why Occurs** | **S3 Operations** |
|---|---|---|---|---|
| `ContentMD5Mismatch` | 400 | "Content-MD5 expected {expected}, but was {actual}" | MD5 checksum mismatch | PutObject, UploadPart |
| `ContentLengthRequired` | 411 | "Content-Length must be >= 0" | Missing/invalid Content-Length | PutObject, UploadPart |
| `MaxContentLengthExceeded` | 413 | "request has exceeded {max} bytes" | Upload exceeds size limit | PutObject, UploadPart |
| `RequestedRangeNotSatisfiable` | 416 | "{range} is an invalid range" | Invalid Range header | GetObject |
| `InvalidDurabilityLevel` | 400 | "durability-level must be between {min} and {max}" | durability-level header out of range | PutObject, InitiateMultipartUpload |

## Conditional Request Errors

| **Error Code** | **HTTP Status** | **Error Message** | **When/Why Occurs** | **S3 Operations** |
|---|---|---|---|---|
| `PreconditionFailed` | 412 | "object was modified at '{timestamp}'; if-unmodified-since '{timestamp}'" | Conditional headers don't match | GetObject, HeadObject, PutObject |

## System and Resource Errors

| **Error Code** | **HTTP Status** | **Error Message** | **When/Why Occurs** | **S3 Operations** |
|---|---|---|---|---|
| `InternalError` | 500 | "We encountered an internal error. Please try again." | Unexpected system errors, storage exhaustion | All S3 operations |
| `ServiceUnavailable` | 503 | "manta is unable to serve this request" | Service temporarily unavailable | All S3 operations |
| `InsufficientStorage` | 507 | "There is insufficient storage space to complete the request." | Storage nodes lack space | PutObject, UploadPart |
| `NotEnoughSpace` | 507 | "not enough free space for {size} MB" | Insufficient storage space | PutObject, UploadPart |
| `ThrottledError` | 503 | "manta throttled this request" | Rate limits exceeded | All S3 operations |

## Account and User Errors

| **Error Code** | **HTTP Status** | **Error Message** | **When/Why Occurs** | **S3 Operations** |
|---|---|---|---|---|
| `AccountDoesNotExist` | 403 | "{account} does not exist" | Account doesn't exist in Manta | All S3 operations |
| `AccountBlocked` | 403 | "{login} is not an active account" | Account is blocked/inactive | All S3 operations |
| `UserDoesNotExist` | 403 | "{account}/{user} does not exist" | Sub-user doesn't exist | All S3 operations |

## Connection and Transfer Errors

| **Error Code** | **HTTP Status** | **Error Message** | **When/Why Occurs** | **S3 Operations** |
|---|---|---|---|---|
| `UploadAbandoned` | 499 | "request was aborted prematurely by the client" | Client disconnects during upload | PutObject, UploadPart |
| `UploadTimeout` | 408 | "request took too long to send data" | Upload times out | PutObject, UploadPart |

## Parameter and Query Errors

| **Error Code** | **HTTP Status** | **Error Message** | **When/Why Occurs** | **S3 Operations** |
|---|---|---|---|---|
| `InvalidArgumentError` | 400 | "limit={limit} is invalid: must be between [1, 1024]" | List limit out of range | ListObjects, ListObjectsV2 |
| `InvalidParameter` | 400 | "{value} is invalid for {parameter}" | Parameter value invalid | Various operations |

## Security Errors

| **Error Code** | **HTTP Status** | **Error Message** | **When/Why Occurs** | **S3 Operations** |
|---|---|---|---|---|
| `SecureTransportRequired` | 403 | "Manta requires a secure transport (SSL/TLS)" | HTTP used when HTTPS required | All S3 operations |

## Error Mapping Notes

1. **Error Translation**: Manta internal errors are automatically translated to S3-compatible error codes
2. **Conditional Operations**: S3 conditional headers are fully supported and can trigger appropriate precondition errors
3. **Storage Exhaustion**: When storage nodes are unavailable, errors are mapped to `InternalError` with HTTP 500/503
4. **Multipart States**: Complex state management with specific errors for each multipart operation phase
5. **Authentication Chain**: Multiple authentication layers each produce specific error codes