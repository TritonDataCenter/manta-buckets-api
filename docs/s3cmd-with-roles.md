# Using s3cmd with Manta Roles for Subuser Access

This document explains how to use s3cmd with the new S3 ACL to Manta role mapping feature to enable subuser access to buckets.

## Configuration

### Basic s3cmd Configuration

Create a `.s3cfg` file:

```ini
[default]
access_key = your-manta-access-key
secret_key = your-manta-secret-key
host_base = your-manta-endpoint
host_bucket = your-manta-endpoint
use_https = True
signature_v2 = False
```

## Creating Buckets with Role-Based Access

### Using S3 Canned ACLs

s3cmd supports canned ACLs that now map to Manta roles:

```bash
# Create a bucket accessible by authenticated users
s3cmd --no-check-certificate --acl-public \
      mb s3://team-shared-bucket

# Create a bucket readable by public users
s3cmd --no-check-certificate --add-header="x-amz-acl:public-read" \
      mb s3://public-readable-bucket

# Create a bucket with full public access
s3cmd --no-check-certificate --add-header="x-amz-acl:public-read-write" \
      mb s3://public-bucket
```

### Using S3 Grant Headers

For more fine-grained control:

```bash
# Grant read access to all authenticated users
s3cmd --no-check-certificate \
      --add-header="x-amz-grant-read:uri=\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\"" \
      mb s3://auth-readable-bucket

# Grant full control to all users
s3cmd --no-check-certificate \
      --add-header="x-amz-grant-full-control:uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"" \
      mb s3://public-full-access-bucket
```

## S3 ACL to Manta Role Mapping

| S3 ACL | Manta Roles | Description |
|--------|-------------|-------------|
| `private` | (none) | Default - owner only |
| `public-read` | `public-reader` | Anyone can read |
| `public-read-write` | `public-reader`, `public-writer` | Anyone can read/write |
| `authenticated-read` | `authenticated-reader` | Authenticated users can read |
| `bucket-owner-read` | `owner-reader` | Bucket owner can read |
| `bucket-owner-full-control` | `owner-full-control` | Bucket owner has full control |

## Grant Headers to Manta Role Mapping

| S3 Grant | Manta Role | Description |
|----------|------------|-------------|
| `x-amz-grant-read` with `AllUsers` | `public-reader` | Public read access |
| `x-amz-grant-read` with `AuthenticatedUsers` | `authenticated-reader` | Authenticated read access |
| `x-amz-grant-write` with `AllUsers` | `public-writer` | Public write access |
| `x-amz-grant-write` with `AuthenticatedUsers` | `authenticated-writer` | Authenticated write access |
| `x-amz-grant-full-control` with `AllUsers` | `public-reader`, `public-writer` | Full public access |

## Subuser Access

Once buckets are created with appropriate roles, subusers can access them by specifying their roles:

### Using curl with Manta authentication

```bash
# Subuser accesses bucket with role
curl -H "role: public-reader" \
     -H "Authorization: ..." \
     GET https://manta-endpoint/user/buckets/team-shared-bucket/objects
```

### Using s3cmd (requires separate subuser credentials)

Subusers need their own s3cmd configuration with their access keys:

```ini
[subuser]
access_key = subuser-access-key
secret_key = subuser-secret-key
host_base = your-manta-endpoint
host_bucket = your-manta-endpoint
use_https = True
signature_v2 = False
```

Then access the bucket:

```bash
s3cmd --config=~/.s3cfg-subuser --no-check-certificate \
      ls s3://team-shared-bucket/
```

## Implementation Details

The S3 role mapping works by:

1. **S3 Request Detection**: Identifies SigV4 authenticated requests
2. **Header Translation**: Converts `x-amz-acl` and `x-amz-grant-*` headers to `role-tag`
3. **Role Population**: Stores roles with bucket metadata during creation
4. **Authorization**: Uses Manta's existing RBAC system for access control

## Troubleshooting

### Debug Logging

Enable debug logging to see role translation:

```bash
# Set environment variable for detailed logging
export NODE_LOG_LEVEL=debug

# Check logs for role translation messages
grep "s3RoleTranslator" /var/log/buckets-api.log
```

### Common Issues

1. **No role-tag header**: Check that S3 ACL headers are being sent correctly
2. **Access denied**: Verify that the user has the required roles
3. **S3 request not detected**: Ensure SigV4 authentication is being used

## Examples

### Complete Workflow

1. Create bucket with public read access:
```bash
s3cmd --add-header="x-amz-acl:public-read" mb s3://shared-docs
```

2. Upload file:
```bash
s3cmd put document.pdf s3://shared-docs/
```

3. Subuser accesses (with appropriate role):
```bash
# Using curl with role header
curl -H "role: public-reader" \
     -H "Authorization: Signature ..." \
     GET https://manta/user/buckets/shared-docs/objects/document.pdf
```

This enables fine-grained access control using S3-compatible tools while leveraging Manta's robust RBAC system.