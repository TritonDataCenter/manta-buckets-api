# Manta Buckets API - S3 Layer Quick Start Guide

This guide will help you get started with using the S3-compatible layer of the Manta Buckets API. You'll learn how to create access keys and configure your S3 clients to work with Manta storage.

## Prerequisites

### System Requirements
- **AWS CLI**: Version 2.0+ with JSON output support
- **s3cmd**: Version 2.0+ for s3cmd tests
- **jq**: JSON processor for parsing responses
- **json**: Node.js json tool (`npm install -g json`)
- **curl**: For HTTP requests
- **Basic Unix tools**: grep, sed, awk, dd, md5sum

### Install Dependencies

#### macOS (Homebrew)
```bash
brew install awscli s3cmd jq node 
npm install -g json
```

#### SmartOS/macOS (pkgsrc)
```bash
pkgin in jq py310-awscli-1.36.10 curl nodejs 
npm install -g json
```

#### Ubuntu/Debian
```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscli.zip"
unzip awscli.zip && sudo ./aws/install

# Other tools
sudo apt-get update
sudo apt-get install s3cmd jq nodejs npm 
sudo npm install -g json

```

## Creating Access Keys

### Step 1: Create Access Key and Secret

The S3 layer uses your Manta your access keys and secret access key from your account.
To create the access key and secret, we need to use [cloudapi](https://docs.mnx.io/cloudapi/api-introduction).

```bash
# Call cloudapi to generate access keys and secret
cloudapi /your-manta-account/accesskeys | json -H
[]
# as expected your account those not have access keys, so let's generate them.
cloudapi /your-manta-account/accesskeys -X POST
{"dn":"accesskeyid=your-access-key-id, uuid=your-manta-account-uuid, ou=users, o=smartdc","controls":[],"accesskeyid":"your-access-key-id","accesskeysecret":"your-access-key-secret","created":"2025-07-28T14:38:51.900Z","objectclass":"accesskey","status":"Active"}

```

### Step 2: Configure Your S3 Client

#### AWS CLI Configuration

```ini
[default]
aws_access_key_id = "your-manta-access-key"
aws_secret_access_key = "your-manta-secret-key"
region = us-east-1
s3=
         addressing_style = path
```

#### s3cmd Configuration

Create or edit `~/.s3cfg`:

```ini
[default]
access_key = your-access-key
secret_key = your-secret-key
host_base = your-manta-endpoint
host_bucket = your-manta-endpoint
use_https = True
signature_v2 = False

```

#### Environment Variables

You can also use environment variables:

```bash
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-access-key
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=https://your-manta-endpoint
```

## Testing Your Configuration

### Test Basic Operations

```bash
# List buckets
aws s3 ls --endpoint-url https://your-manta-endpoint

# Create a bucket
aws s3 mb s3://test-bucket --endpoint-url https://your-manta-endpoint

# Upload a file
aws s3 cp local-file.txt s3://test-bucket/ --endpoint-url https://your-manta-endpoint

# List objects in bucket
aws s3 ls s3://test-bucket/ --endpoint-url https://your-manta-endpoint

# Download a file
aws s3 cp s3://test-bucket/local-file.txt downloaded-file.txt --endpoint-url https://your-manta-endpoint
```

### Test with ACLs
ACLs are not applied to objects within a bucket, not to the bucket itself.

```bash
# Upload with public-read ACL
aws s3 cp local-file.txt s3://test-bucket/ --acl public-read --endpoint-url https://your-manta-endpoint

```

## Service Dependencies

The following table shows the services that the Manta Buckets API S3 layer depends on:

| Service Name | Service Type | UUID/Identifier | Needs Extra Steps? |
|--------------|--------------|-----------------|-------------------|
| `authcache` | Authentication & Authorization |  2d6c9916-2bc3-40d7-ad3c-4f76fb5fbc05 | Yes - Requires cache rebuild |
| `buckets-api`| Core Bucket Operations |  684049e8-9b78-49b3-8e09-8744f7df3698  | No - Direct integration |
| `storage`  | Storage Nodes |  5735eba4-746c-4f93-b275-8d739e53f1e4| No - Backend dependency |
| `loadbalancer` | Traffic Distribution | f9f32770-14fa-4f85-a7cc-a1b8b62ede07| No -  direct integration  |

### Services Requiring Extra Steps

Required steps after the required services from the service dependencies table
are specified in https://github.com/TritonDataCenter/manta-buckets-api/blob/MANTA-5471/docs/deployment.md

## Additional information

- [Presigned URLs](https://github.com/TritonDataCenter/manta-buckets-api/blob/MANTA-5471/docs/presigned.md)

- [Anonymous Access](https://github.com/TritonDataCenter/manta-buckets-api/blob/MANTA-5471/docs/anonymous-access.md)

- [Divergences between Manta and S3] (https://github.com/TritonDataCenter/manta-buckets-api/blob/MANTA-5471/docs/divergences.md)

- [S3 Compatibility Documentation] (https://github.com/TritonDataCenter/manta-buckets-api/blog/MANTA-5471/docs/s3.md)

- [Testing] (https://github.com/TritonDatacenter/manta-buckets-api/blog/MANTA-5471/docs/testing.md)
