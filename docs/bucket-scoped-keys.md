---
title: Bucket-Scoped Access Keys
markdown2extras: wiki-tables, code-friendly
---

# Bucket-Scoped Access Keys

Bucket-scoped access keys restrict S3 operations to a
declared set of buckets with per-bucket permission levels.
A scoped key can only access the buckets named in its scope
and only at the granted permission level.  An unscoped key
(the default) has unrestricted access to all buckets.

Scoped keys are managed through CloudAPI and enforced by
manta-buckets-api on every S3 request.

## Scope Envelope

A scope is a JSON object with a version number and a list
of permission entries:

```json
{
  "version": 1,
  "permissions": [
    { "bucket": "app-data", "level": "readwrite" },
    { "bucket": "logs-*", "level": "read" }
  ]
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | number | yes | Must be `1` |
| `permissions` | array | yes | 1 to 1000 permission entries |
| `permissions[].bucket` | string | yes | Bucket name or wildcard pattern (1-63 chars) |
| `permissions[].level` | string | yes | One of `read`, `readwrite`, `full` |

### Limits

- Maximum 1000 permission entries per scope
- Maximum scope JSON size: 256K characters
- Bucket names must follow S3 naming rules (3-63 chars,
  lowercase letters, numbers, hyphens, periods, labels
  separated by periods, no IP-address lookalikes)
- No duplicate bucket patterns in a single scope

## Permission Levels

Three permission levels are available, each granting all
operations of the levels below it:

| Level | S3 Operations Allowed |
|-------|----------------------|
| `read` | GetObject, HeadObject, HeadBucket, ListObjects, ListBuckets (filtered) |
| `readwrite` | All `read` operations plus PutObject, DeleteObject, multipart upload (CreateMultipartUpload, UploadPart, CompleteMultipartUpload, AbortMultipartUpload) |
| `full` | All `readwrite` operations plus CreateBucket, DeleteBucket |

### Operation-to-level mapping

| HTTP Method | Target | Required Level |
|-------------|--------|----------------|
| GET | object or list | read |
| HEAD | object or bucket | read |
| PUT | object | readwrite |
| DELETE | object | readwrite |
| POST | multipart operations | readwrite |
| PUT | bucket (create) | full |
| DELETE | bucket | full |

## Wildcard Patterns

Bucket patterns support a trailing wildcard (`*`) for
prefix matching:

| Pattern | Matches |
|---------|---------|
| `app-data` | Exactly `app-data` |
| `logs-*` | Any bucket starting with `logs-` (e.g. `logs-jan`, `logs-2026`) |
| `*` | All buckets (equivalent to unscoped for that level) |

Non-trailing wildcards are rejected:

- `*-logs` -- invalid (leading wildcard)
- `pre-*-suf` -- invalid (middle wildcard)

## Creating a Scoped Key

Scoped keys are created through the CloudAPI access key
endpoints.  Pass the scope envelope as the `scope` parameter.

### Create a read-only key for one bucket

```bash
curl -sk -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Date: $(date -u '+%a, %d %h %Y %H:%M:%S GMT')" \
  -H "Authorization: Signature keyId=\"/$ACCOUNT/keys/$KEY_ID\",algorithm=\"rsa-sha256\" $(echo -n "$(date -u '+%a, %d %h %Y %H:%M:%S GMT')" | openssl dgst -sha256 -sign ~/.ssh/id_rsa | openssl enc -e -a | tr -d '\n')" \
  -d '{
    "scope": {
      "version": 1,
      "permissions": [
        {"bucket": "app-data", "level": "read"}
      ]
    }
  }' \
  "$CLOUDAPI_URL/$ACCOUNT/accesskeys"
```

Response:

```json
{
  "accesskeyid": "a1b2c3d4e5f6...",
  "accesskeysecret": "tdc_...",
  "status": "Active",
  "scope": {
    "version": 1,
    "permissions": [
      {"bucket": "app-data", "level": "read"}
    ]
  },
  "created": "2026-04-28T00:00:00.000Z"
}
```

The `accesskeysecret` is only returned on creation.  Store
it securely.

### Create a key with multiple buckets and wildcard

```bash
curl -sk -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: ..." \
  -d '{
    "scope": {
      "version": 1,
      "permissions": [
        {"bucket": "prod-data", "level": "readwrite"},
        {"bucket": "staging-data", "level": "readwrite"},
        {"bucket": "logs-*", "level": "read"},
        {"bucket": "backups", "level": "full"}
      ]
    }
  }' \
  "$CLOUDAPI_URL/$ACCOUNT/accesskeys"
```

### Create an unscoped key (unrestricted)

Omit the `scope` parameter:

```bash
curl -sk -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: ..." \
  -d '{}' \
  "$CLOUDAPI_URL/$ACCOUNT/accesskeys"
```

## Using a Scoped Key with S3

Configure the AWS CLI or any S3 client with the scoped
key credentials:

```bash
export AWS_ACCESS_KEY_ID="a1b2c3d4e5f6..."
export AWS_SECRET_ACCESS_KEY="tdc_..."
```

### Allowed operation succeeds

```bash
# Key has read access to app-data
aws s3api get-object \
  --endpoint-url "$S3_ENDPOINT" \
  --bucket app-data \
  --key report.csv \
  report.csv
```

### Denied operation returns 403

```bash
# Key has read access, PUT requires readwrite
aws s3api put-object \
  --endpoint-url "$S3_ENDPOINT" \
  --bucket app-data \
  --key new-file.txt \
  --body new-file.txt

# Returns: AccessDeniedByKeyScope
```

### Cross-bucket access denied

```bash
# Key is scoped to app-data, not other-bucket
aws s3api get-object \
  --endpoint-url "$S3_ENDPOINT" \
  --bucket other-bucket \
  --key file.txt \
  file.txt

# Returns: AccessDeniedByKeyScope
```

## ListBuckets Filtering

When a scoped key calls ListBuckets, only buckets that
match the scope are returned.  Unscoped buckets are hidden
from the listing.

A key with scope `[{"bucket": "app-*", "level": "read"}]`
calling ListBuckets will see `app-data`, `app-logs`, etc.
but not `other-bucket`.

## Updating a Key's Scope

Use the CloudAPI update endpoint to change or remove the
scope on an existing key.

### Replace the scope

```bash
curl -sk -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: ..." \
  -d '{
    "scope": {
      "version": 1,
      "permissions": [
        {"bucket": "new-bucket", "level": "full"}
      ]
    }
  }' \
  "$CLOUDAPI_URL/$ACCOUNT/accesskeys/$KEY_ID"
```

### Remove the scope (make unrestricted)

Pass an empty string or null as the scope:

```bash
curl -sk -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: ..." \
  -d '{"scope": ""}' \
  "$CLOUDAPI_URL/$ACCOUNT/accesskeys/$KEY_ID"
```

## STS Scope Inheritance

When a scoped key calls STS AssumeRole or GetSessionToken,
the resulting temporary credentials inherit the parent
key's scope.  The temporary credentials cannot access
buckets outside the parent key's scope, regardless of the
role's permission policy.

Example: a key scoped to `app-data` (read) calls
AssumeRole on a role with full S3 access.  The temporary
credentials can only read from `app-data` -- the scope
from the parent key is the ceiling.

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `AccessDeniedByKeyScope` | 403 | The scoped key does not grant sufficient access to the requested bucket or operation |

The error response includes the standard S3 XML format:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Access denied by key scope: bucket 'other-bucket'
    not in scope, or insufficient permission level</Message>
  <RequestId>...</RequestId>
</Error>
```

## Backward Compatibility

- Existing keys without a scope continue to work with
  unrestricted access.
- The `scope` field is present in all CloudAPI access key
  responses (`null` for unscoped keys).
- No changes to the S3 API surface -- scope enforcement is
  transparent to S3 clients.  A scoped key behaves exactly
  like an unscoped key for operations within its scope.

## Architecture

```
CloudAPI                    UFDS (LDAP)
  create key + scope -----> validate scope schema
                            store accesskeyscope attribute
                     <----- return key

                            UFDS replicator
                            sync to mahi Redis
                              key + scope stored together

S3 Client                   manta-buckets-api
  request with key -------> authenticate via mahi
                            mahi returns caller + scope
                            enforceBucketScope middleware:
                              parse scope
                              match bucket against patterns
                              check required level
                              allow or deny (403)
                     <----- response
```

Scope validation happens at two boundaries:

1. **Write gate (UFDS):** Validates the scope envelope
   structure, bucket naming rules, permission levels,
   duplicate patterns, and size limits when the key is
   created or updated.

2. **Enforcement gate (buckets-api):** Checks the scope
   against every S3 request at runtime.  This is a
   fail-closed design -- malformed scope JSON results in
   denial, not unrestricted access.
