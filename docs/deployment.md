<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright 2025 Edgecast Cloud LLC.
-->

# manta-buckets-api S3 compat layer deployment

### Obtaining access keys 
First we need to generate the access keys for an account, (https://docs.mnx.io/cloudapi/api-introduction)[CloudAPI]. The new REST endpoint that generates the keys is not used on the operator portal, so we need to generate
the keys manually.

```
cloudapi /your-manta-account/accesskeys -X POST
```
The response should be something like this.

```
HTTP/1.1 201 Created
location: /your-manta-account/accesskeys/your-access-key
content-type: application/json
content-length: 346
access-control-allow-origin: *
access-control-allow-headers: Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, Api-Version, Response-Time
access-control-allow-methods: POST, GET, HEAD
access-control-expose-headers: Api-Version, Request-Id, Response-Time
content-md5: IWO6EvVxPH542Zv+Q9fAAA==
date: Mon, 28 Jul 2025 14:38:51 GMT
server: cloudapi/9.20.0
api-version: 9.0.0
request-id: 9fd136ad-1021-4d55-a257-aeeffdac2071
response-time: 373

{"dn":"accesskeyid=your-access-key-id, uuid=your-user-uuid, ou=users, o=smartdc","controls":[],"accesskeyid":"your-access-key-id","accesskeysecret":"your-access-key-secret","created":"2025-07-28T14:38:51.900Z","objectclass":"accesskey","status":"Active"}

```

### Rebuild caches for authcache instances.
The new changes in manta-buckets-api require that all caches from authcache instances to be rebuilt in order for Sigv4 authentication to work.
Document for this procedure is  here : https://github.com/TritonDataCenter/mahi/blob/master/docs/index.md

The steps for rebuilding caches are :

1. In the mahi zone, disable registrar and mahi-server. This takes mahi out of DNS so services will not try to use this instance of mahi. HA setups (Manta) will continue to use other instances.
    
    ```
     svcadm disable registrar
     svcadm disable mahi-server
    ```
    
2. Disable mahi-replicator, flush the redis database and re-enable mahi-replicator.
    
    ```
     svcadm disable mahi-replicator
     redis-cli -n $(json -f /opt/smartdc/mahi/etc/mahi2.json redis.db || 0) flushdb
     svcadm enable mahi-replicator
    ```

3. Enable mahi-server and registrar. Registrar's healthcheck won't pass and mahi-server will return 500s until mahi-replicator has caught up.
    
    ```
     svcadm enable mahi-server
     svcadm enable registrar
    ```
4. Test if data has been refreshed

This command should return the uuid for the account associated with the access key id
```
redis-cli -n 1 get "/accesskey/your-access-key-id"
```


## Roles

Now we are able to share buckets anonymously using --acl-public with s3cmd, for this on manta we
need to create the public-read role as follows.

```
[root@headnode (coal) ~]# sdc-login cloudapi
[Connected to zone 'be0dc4b6-8c96-4637-9f8c-f9d6c5b820fb' pts/6]
Last login: Tue Jul 15 16:31:41 on pts/3
 =  J O Y E N T  =

    cloudapi (master-20250326T183907Z-g10c3963)
    https://github.com/tritondatacenter/sdc-cloudapi.git
    triton-origin-x86_64-21.4.0@master-20220322T012137Z-g9382491

[root@be0dc4b6-8c96-4637-9f8c-f9d6c5b820fb (coal:cloudapi0) ~]# export SDC_ACCOUNT=your-admin-account
[root@be0dc4b6-8c96-4637-9f8c-f9d6c5b820fb (coal:cloudapi0) ~]# export SDC_KEY_ID=your-adminkey-fingerprint
[root@be0dc4b6-8c96-4637-9f8c-f9d6c5b820fb (coal:cloudapi0) ~]# export SDC_KEY=~/.ssh/id_rsa
[root@be0dc4b6-8c96-4637-9f8c-f9d6c5b820fb (coal:cloudapi0) ~]# export SDC_URL=https://10.88.88.3
[root@be0dc4b6-8c96-4637-9f8c-f9d6c5b820fb (coal:cloudapi0) ~]# export SDC_TESTING=1
[root@be0dc4b6-8c96-4637-9f8c-f9d6c5b820fb (coal:cloudapi0) ~]# sdc-policy create --name=read-public --rules='CAN getobject'
{
  "name": "read-public",
  "id": "203c03fd-8271-472c-a5f9-cc4ab0f21e6a",
  "rules": [
    "CAN getobject"
  ]
}
[root@be0dc4b6-8c96-4637-9f8c-f9d6c5b820fb (coal:cloudapi0) ~]# sdc-role create  --name=public-read   --policies=read-public
{
  "name": "public-read",
  "id": "c72e37a0-6a49-4660-86c4-1d6655702413",
  "members": [],
  "default_members": [],
  "policies": [
    "read-public"
  ]
}

```

## Subuser Management and Fine-Grained Access Control

The Manta Buckets API supports creating subusers with fine-grained permissions for specific buckets and operations. This enables secure multi-tenant S3 access where different users can have different levels of access to buckets and objects.

### Creating Subusers with Bucket-Specific Access

#### Step 1: Create a Subuser

```bash
# Create a subuser
sdc-user create --login=s3qa --email=s3qa@example.com
```
[
  {
    "id": "04a54897-82c0-4ab9-a77a-bbf800ff371a",
    "login": "s3qa",
    "email": "s3qa@localhost",
    "firstName": "s3qa",
    "updated": "2025-10-06T21:15:04.278Z",
    "created": "2025-10-06T18:21:55.703Z"
  }
]
```

# Generate access keys for the subuser
sdc-user upload-key  --name=s3qa-key  <user id>  ~/.ssh/s3qa_rsa.pub
```

#### Step 2: Create Policies for Fine-Grained Access

Policies define what actions can be performed on which resources.

```bash
# Read-only access to specific bucket
sdc-policy create --name=bucket-reader --rules='CAN getbucket test-bucket' --rules='CAN getobject test-bucket/*'

# Full access to uploads bucket
sdc-policy create --name=upload-manager --rules='CAN getbucket uploads' --rules='CAN getobject uploads/*' --rules='CAN putobject uploads/*' --rules='CAN deleteobject uploads/*'

# Multi-bucket development access (pattern-based)
sdc-policy create --name=dev-access --rules='CAN getbucket dev-*' --rules='CAN getobject dev-*/*' --rules='CAN putobject dev-*/*'

# Bucket creator (can create new buckets)
sdc-policy create --name=bucket-creator --rules='CAN putbucket *'
```

#### Step 3: Create Roles and Assign Users

Roles group policies together and assign them to users. **Critical**: For S3 compatibility, subusers must be in `default_members`.

```bash
# Create role for read-only access
sdc-role create --name=storage-reader --policies=bucket-reader --default_members=s3qa

# Create role for upload management
sdc-role create --name=uploader --policies=upload-manager --default_members=s3qa

# Create role with multiple policies
sdc-role create --name=developer --policies=dev-access,bucket-creator --default_members=s3qa
```

### Common Access Patterns and Examples

#### Example 1: Read-Only User for Specific Bucket

```bash
# Create policy
sdc-policy create --name=analytics-reader \
  --rules='CAN getbucket analytics-data' \
  --rules='CAN getobject analytics-data/*'

# Create role
sdc-role create --name=data-analyst \
  --policies=analytics-reader \
  --default_members=analyst-user

# Test with S3 client
aws --endpoint-url=https://manta.example.com \
    --region=us-east-1 \
    s3 ls s3://analytics-data/
```

#### Example 2: Application User with Upload Rights

```bash
# Create comprehensive policy for app backend
sdc-policy create --name=app-backend \
  --rules='CAN getbucket app-uploads' \
  --rules='CAN getobject app-uploads/*' \
  --rules='CAN putobject app-uploads/*' \
  --rules='CAN deleteobject app-uploads/*'

# Create role
sdc-role create --name=backend-service \
  --policies=app-backend \
  --default_members=app-user

# Test upload
aws --endpoint-url=https://manta.example.com \
    s3 cp ./file.txt s3://app-uploads/
```

#### Example 3: Development Team with Pattern-Based Access

```bash
# Policy for all dev-* buckets
sdc-policy create --name=dev-team-access \
  --rules='CAN getbucket dev-*' \
  --rules='CAN getobject dev-*/*' \
  --rules='CAN putobject dev-*/*' \
  --rules='CAN deleteobject dev-*/*' \
  --rules='CAN putbucket dev-*'

# Create role
sdc-role create --name=developers \
  --policies=dev-team-access \
  --default_members=dev-user1,dev-user2

# Users can access dev-alice, dev-bob, dev-staging, etc.
```

#### Example 4: Multi-Bucket User with Different Permissions

```bash
# Create multiple policies
sdc-policy create --name=public-reader \
  --rules='CAN getbucket public-assets' \
  --rules='CAN getobject public-assets/*'

sdc-policy create --name=private-manager \
  --rules='CAN getbucket private-docs' \
  --rules='CAN getobject private-docs/*' \
  --rules='CAN putobject private-docs/*' \
  --rules='CAN deleteobject private-docs/*'

# Combine policies in single role
sdc-role create --name=content-manager \
  --policies=public-reader,private-manager \
  --default_members=content-user
```

### Permission Reference

| S3 Operation | Required Permission | Example |
|--------------|-------------------|---------|
| **List Bucket** | `getbucket` | `CAN getbucket my-bucket` |
| **Get Object** | `getobject` | `CAN getobject my-bucket/*` |
| **Put Object** | `putobject` | `CAN putobject my-bucket/*` |
| **Delete Object** | `deleteobject` | `CAN deleteobject my-bucket/*` |
| **Create Bucket** | `putbucket` | `CAN putbucket *` |
| **Head Bucket/Object** | Same as Get | `CAN getbucket` / `CAN getobject` |

### Wildcard Patterns

```bash
# Bucket patterns
"CAN getbucket my-bucket"      # Specific bucket only
"CAN getbucket dev-*"          # All buckets starting with dev-
"CAN putbucket *"              # Can create any bucket

# Object patterns  
"CAN getobject my-bucket/*"    # All objects in my-bucket
"CAN getobject */public/*"     # All objects in public/ folder of any bucket
"CAN putobject uploads/user-*" # Objects matching pattern in uploads bucket
```

### Troubleshooting Access Issues

#### Check Role Activation
```bash
# Verify user is in default_members (critical for S3)
sdc-role get storage-reader

# Should show:
# "default_members": ["s3qa"]
```

#### Test Permissions
```bash
# Test bucket listing
aws --endpoint-url=https://manta.example.com s3 ls

# Test specific bucket access
aws --endpoint-url=https://manta.example.com s3 ls s3://my-bucket/

# Enable debug logging
aws --debug --endpoint-url=https://manta.example.com s3 ls s3://my-bucket/
```

#### Common Issues

1. **403 Forbidden**: User not in `default_members` of role
2. **Bucket access works but object access fails**: Missing `getobject` permission  
3. **Can read but can't upload**: Missing `putobject` permission
4. **Pattern not matching**: Check wildcard syntax and escaping

**Note**: Role and policy changes may take 5-10 seconds to propagate through the authentication system.

