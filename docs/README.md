# Manta Buckets API - S3 Compatibility Documentation

This directory contains documentation for the S3-compatible layer of the Manta Buckets API.

## Table of Contents

### S3 Compatibility Documentation

| Document | Purpose | Key Topics |
|----------|---------|------------|
| **[quickstart.md](quickstart.md)** | **S3 Quick Start Guide** | Access key creation, S3 client configuration, basic S3 operations, troubleshooting |
| **[architecture.md](architecture.md)** | **S3-to-Manta Architecture** | Request processing, S3 route handlers, header translation, ACL system |
| **[anonymous-access.md](anonymous-access.md)** | **Anonymous S3 Access** | Public bucket access, S3 ACL support, browser access, security controls |
| **[mpu.md](mpu.md)** | **S3 Multipart Upload** | Multipart upload design, v2 commit assembly, distributed locking, performance |
| **[divergences.md](divergences.md)** | **S3 Compatibility Matrix** | AWS S3 vs Manta feature comparison, supported/unsupported operations |
| **[error-codes.md](error-codes.md)** | **S3 Error Codes** | Complete S3 error reference, HTTP status codes, troubleshooting |
| **[testing.md](testing.md)** | **S3 Compatibility Testing** | AWS CLI and s3cmd test suites, validation procedures |
| **[deployment.md](deployment.md)** | **S3 Layer Deployment** | Production setup, access key generation, role configuration |
| **[faq.md](faq.md)** | **S3 Troubleshooting** | Common S3 client issues, authentication, file location |

## Quick Navigation

### For S3 Users
1. **[quickstart.md](quickstart.md)** - Get started with S3 clients
2. **[divergences.md](divergences.md)** - Understand S3 compatibility limitations  
3. **[error-codes.md](error-codes.md)** - Troubleshoot S3 errors

### For Developers
1. **[architecture.md](architecture.md)** - S3 request processing flow
2. **[mpu.md](mpu.md)** - Multipart upload implementation
3. **[testing.md](testing.md)** - S3 compatibility validation

### For Operations  
1. **[deployment.md](deployment.md)** - Deploy S3 compatibility layer
2. **[anonymous-access.md](anonymous-access.md)** - Configure public access
3. **[faq.md](faq.md)** - Resolve common issues
