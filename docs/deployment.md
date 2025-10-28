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
First we need to generate the access keys for an account, [CloudAPI version 9.11.0](https://docs.mnx.io/cloudapi/api-introduction) The new REST endpoint that generates the keys is not used on the operator portal, so we need to generate the keys manually.

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
sdc-user create --login=<some user name>  --email=<some user email>
```
[
  {
    "id": "04a54897-82c0-4ab9-a77a-bbf800ff371a",
    "login": "someuser",
    "email": "someuser@localhost",
    "firstName": "someruser",
    "updated": "2025-10-06T21:15:04.278Z",
    "created": "2025-10-06T18:21:55.703Z"
  }
]
```

# Generate access keys for the subuser
sdc-user upload-key  --name=<description of key name>  <user id>  <path for public ssh key>
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


## User Access Control for Buckets and Objects

This section explains how to create subusers and grant them specific access to buckets and objects using Manta's Role-Based Access Control (RBAC) system.

**⚠️ Important Note**: Role and policy changes take a few seconds to become effective. After creating or modifying roles and policies, wait 5-10 seconds before testing access.

### Creating Subusers with Bucket-Specific Access

#### Step 1: Create a Subuser

```bash
# Create a subuser for S3 access
sdc-user create --login s3qa --email s3qa@example.com --password temp-password

# Example response:
{
    "id": "04a54897-82c0-4ab9-a77a-bbf800ff371a",
    "login": "s3qa",
    "email": "s3qa@localhost",
    "firstName": "s3qa",
    "updated": "2025-10-06T18:21:55.703Z",
    "created": "2025-10-06T18:21:55.703Z"
  } 
```

#### Step 2: Generate Access Keys for the Subuser

```bash
# Generate S3 access keys for the subuser
cloudapi /your-account/users/s3qa/accesskeys -X POST

# Example response:
[
  {
    "dn": "accesskeyid=<b6856fbd3d5a3645e1347931fe8e9226>, uuid=04a54897-82c0-4ab9-a77a-bbf800ff371a, uuid=c116efce-086f-455e-9ae4-26d49551428d, ou=users, o=smartdc",
    "controls": [],
    "accesskeyid": <"your access key">,
    "accesskeysecret": <"your secret key">,
    "created": "2025-10-06T21:20:09.540Z",
    "objectclass": "accesskey",
    "status": "Active"
  }
]
```

#### Step 3: Create Policies for Bucket Access

```bash
# Policy for reading objects from a specific bucket
sdc-policy create --name=bucket-reader --rules='CAN getbucket test-bucket' --rules='CAN getobject test-bucket/*'

# Policy for full access to a specific bucket
sdc-policy create --name=bucket-admin --rules='CAN getbucket test-bucket' --rules='CAN getobject test-bucket/*' --rules='CAN putobject test-bucket/*' --rules='CAN deleteobject test-bucket/*'

# Policy for read-only access to multiple buckets
sdc-policy create --name=multi-bucket-reader --rules='CAN getbucket dev-bucket' --rules='CAN getobject dev-bucket/*' --rules='CAN getbucket prod-bucket' --rules='CAN getobject prod-bucket/*'
```

#### Step 4: Create Roles and Assign to Subuser

**Critical for S3 clients**: Subusers must be in both `members` AND `default_members` arrays for S3 compatibility, as S3 clients cannot send role headers.

```bash
# Create role for bucket reading access
sdc-role create --name=storage-reader --members=s3qa --default_members=s3qa --policies=bucket-reader

# Create role for full bucket access
sdc-role create --name=storage-admin --members=s3qa --default_members=s3qa --policies=bucket-admin
```

### Common Access Patterns

#### Read-Only Access to Specific Bucket

```bash
# Create policy
sdc-policy create --name=readonly-mybucket --rules='CAN getbucket mybucket' --rules='CAN getobject mybucket/*'

# Create role with default activation for user s3qa
sdc-role create --name=mybucket-reader --members=s3qa --default_members=s3qa --policies=readonly-mybucket
```

#### Upload and Download Access to Specific Bucket

```bash
# Create policy
sdc-policy create --name=readwrite-uploads --rules='CAN getbucket uploads' --rules='CAN getobject uploads/*' --rules='CAN putobject uploads/*'

# Create role with default activation for s3qa
sdc-role create --name=uploads-user --members=s3qa --default_members=s3qa --policies=readwrite-uploads
```

#### Multiple Bucket Access with Different Permissions

```bash
# Policy for development environment (full access)
sdc-policy create --name=dev-full-access --rules='CAN getbucket dev-*' 'CAN getobject dev-*/*' 'CAN putobject dev-*/*' 'CAN deleteobject dev-*/*'

# Policy for production environment (read-only)
sdc-policy create --name=prod-readonly --rules='CAN getbucket prod-*' 'CAN getobject prod-*/*'

# Combined role
sdc-role create --name=developer --members=s3qa --default_members=s3qa --policies=dev-full-access,prod-readonly
```

### Testing Subuser Access

#### Configure S3 Client with Subuser Credentials

```bash
# Configure AWS CLI with subuser credentials
aws configure set aws_access_key_id 'your_access_key'
aws configure set aws_secret_access_key 'your_secret_key'

# Test access
aws s3 ls s3://test-bucket/ --endpoint-url https://your-manta-endpoint
aws s3 cp localfile.txt s3://test-bucket/ --endpoint-url https://your-manta-endpoint
```

#### Verify Permissions

```bash
# Should succeed (if user has getbucket permission)
aws s3 ls s3://test-bucket/ --endpoint-url https://your-manta-endpoint

# Should succeed (if user has getobject permission)  
aws s3 cp s3://test-bucket/file.txt downloaded.txt --endpoint-url https://your-manta-endpoint

# Should fail (if user lacks permission for different bucket)
aws s3 ls s3://other-bucket/ --endpoint-url https://your-manta-endpoint
```

### Troubleshooting Access Issues

#### Common Issues

1. **403 Forbidden Errors**
   - Verify user is in both `members` and `default_members` of role
   - Check that policy includes required permissions (`getbucket`, `getobject`, `putobject`)
   - Wait 5-10 seconds after role/policy changes

2. **Empty activeRoles**
   - User must be in `default_members` for automatic role activation
   - S3 clients cannot send Role headers, so default activation is required

3. **Bucket-scoped permissions not working**
   - Use bucket-scoped patterns: `bucketname/*` for objects
   - Ensure bucket name in policy matches exactly

#### Debugging Commands

```bash
# Check user's roles and permissions
sdc-user get s3qa

# List all roles for account
sdc-role list

# View specific role details
sdc-role get storage-reader

# Check policy rules
sdc-policy get bucket-reader
```

### Security Best Practices

1. **Principle of Least Privilege**: Grant minimum required permissions
2. **Bucket-Specific Access**: Use bucket-scoped permissions rather than wildcards
3. **Regular Audit**: Periodically review user permissions and active roles
4. **Access Key Rotation**: Regularly rotate subuser access keys
5. **Default Role Management**: Only add users to `default_members` when necessary for S3 compatibility

### Permission Reference

| Operation | Required Permission | Example |
|-----------|-------------------|---------|
| List bucket contents | `CAN getbucket bucket-name` | `CAN getbucket uploads` |
| Download objects | `CAN getobject bucket-name/*` | `CAN getobject uploads/*` |
| Upload objects | `CAN putobject bucket-name/*` | `CAN putobject uploads/*` |
| Delete objects | `CAN deleteobject bucket-name/*` | `CAN deleteobject uploads/*` |
| Bucket metadata | `CAN getbucket bucket-name` | `CAN getbucket uploads` |

**Note**: `getbucket` permission is required for both bucket listing and bucket metadata operations for the S3 compatibility layer.

## Advanced Configuration

### Custom Role Management

If you need custom roles beyond the standard S3 ACLs, zlogin into the cloudapi
instance from the headnode and create the policy and role required.
Also you could install rbac tools for Triton which is described  [https://docs.tritondatacenter.com/public-cloud/rbac/quickstart](here)
For example here we create the required public-read role and read-public policy
used by the canned acl 'public-read'

```bash
# Create custom roles using Manta CLI

[root@1d812d88-6e82-4b6d-8300-c7e5816f353a (us-central-a:cloudapi0) ~]#  sdc-policy create --name=read-public --rules='CAN getobject'
{
  "name": "read-public",
  "id": "48617132-dd3d-4a87-ab7d-1f125db1512f",
  "rules": [
    "CAN getobject"
  ]
}
[root@1d812d88-6e82-4b6d-8300-c7e5816f353a (us-central-a:cloudapi0) ~]# sdc-role create   --name=public-read        --policies=read-public
{
  "name": "public-read",
  "id": "cdc6c74c-9c75-4200-bfc8-fdbe9fd94a22",
  "members": [],
  "default_members": [],
  "policies": [
    "read-public"
  ]
}

# test the policy/role
aws s3 cp file.txt s3://bucket/ --acl=public-read --endpoint-url https://your-manta-endpoint
```


## Troubleshooting


### Mahi is not picking up changes

Authcache must be rebuild to pickup the new structure for accesskeys 
https://github.com/TritonDataCenter/mahi/blob/master/docs/index.md


### Where is my bucket object stored? 
https://github.com/TritonDataCenter/manta/blob/master/docs/operator-guide/maintenance.md#pickerstorinfo-toggle

For manta-buckets-api there is /opt/smartdc/buckets-api/bin/mlocate 

```
[root@c7aaf162 (buckets-api) /opt/smartdc/buckets-api]$ ./bin/mlocate neirac/test5/sopa.txt  | json
{"name":"mlocate","hostname":"c7aaf162-6a9b-4873-b82e-19b8cb35490e","pid":26684,"component":"CueBallDNSResolver","domain":"nameservice.coal.joyent.us","level":30,"removed":["10.99.99.11"],"msg":"removed 1 resolvers from bootstrap","time":"2025-07-30T16:30:08.560Z","v":0}
{"name":"mlocate","hostname":"c7aaf162-6a9b-4873-b82e-19b8cb35490e","pid":26684,"component":"BucketsMdapiClient","domain":"buckets-mdplacement.coal.joyent.us","local":"10.77.77.22:44521","remote":"10.77.77.25:2021","key":"R4yi9i8ue6tXRAS1Z41aOM6BhFE=.1","level":30,"msg":"new connection","time":"2025-07-30T16:30:08.580Z","v":0}
{"name":"mlocate","hostname":"c7aaf162-6a9b-4873-b82e-19b8cb35490e","pid":26684,"component":"BucketsMdapiClient","domain":"1.buckets-mdapi.coal.joyent.us","local":"10.77.77.22:43654","remote":"10.77.77.26:2030","key":"YxCC9C7ibWSuMQh7MiERHMTSHB8=.1","level":30,"msg":"new connection","time":"2025-07-30T16:30:08.615Z","v":0}
{"name":"mlocate","hostname":"c7aaf162-6a9b-4873-b82e-19b8cb35490e","pid":26684,"component":"BucketsMdapiClient","domain":"1.buckets-mdapi.coal.joyent.us","local":"10.77.77.22:46025","remote":"10.77.77.26:2030","key":"YxCC9C7ibWSuMQh7MiERHMTSHB8=.1","level":30,"msg":"new connection","time":"2025-07-30T16:30:08.626Z","v":0}
{
  "bucket_id": "afc19bda-99de-461c-81f5-8b0633c88259",
  "content_length": 6,
  "content_md5": "R4EsbxCWGllPX3vFgGxy4Q==",
  "content_type": "text/plain",
  "created": "2025-07-30T16:15:14.559859Z",
  "headers": {
    "m-s3cmd-attrs": "atime:1753892103/ctime:1753892103/gid:0/gname:wheel/md5:47812c6f10961a594f5f7bc5806c72e1/mode:33188/mtime:1753892103/uid:501/uname:carlosneira"
  },
  "id": "56ccac05-c9c6-4e6b-8a8e-5daad7d4e44f",
  "modified": "2025-07-30T16:15:14.559859Z",
  "name": "sopa.txt",
  "owner": "c116efce-086f-455e-9ae4-26d49551428d",
  "properties": {},
  "sharks": [
    {
      "datacenter": "coal",
      "manta_storage_id": "1.stor.coal.joyent.us"
    },
    {
      "datacenter": "coal",
      "manta_storage_id": "3.stor.coal.joyent.us"
    }
  ],
  "_key": "c116efce-086f-455e-9ae4-26d49551428d:afc19bda-99de-461c-81f5-8b0633c88259:4116ddb8d538f4db68253ca6a6fb9bee",
  "_node": {
    "pnode": "tcp://1.buckets-mdapi.coal.joyent.us:2030",
    "vnode": 3,
    "data": 1
  },
  "_bucket_name": "test5",
  "_buckets_mdplacement": "buckets-mdplacement.coal.joyent.us"
}

```

The important part here is the _key_  and id , the file name that contains the data is a concatenation of id and the last element from _key_ (we split by  ':' ) . For example to obtain the file we just concatenate these values adding ',' between them: 
```
id : 56ccac05-c9c6-4e6b-8a8e-5daad7d4e44f
last element from key: 4116ddb8d538f4db68253ca6a6fb9bee

So the filename is called 
56ccac05-c9c6-4e6b-8a8e-5daad7d4e44f,4116ddb8d538f4db68253ca6a6fb9bee

```

The file is should be located in storage node 3, under directory
```
/manta/v2/<owneruuid>/<second element from _key>/<2 first bytes of id>/
```

For example 

```
[root@b948d68a (storage) /manta/v2/c116efce-086f-455e-9ae4-26d49551428d/afc19bda-99de-461c-81f5-8b0633c88259/56]$ ls -lrt
total 1
-rw-r--r-- 1 nobody nobody 6 Jul 30 16:15 56ccac05-c9c6-4e6b-8a8e-5daad7d4e44f,4116ddb8d538f4db68253ca6a6fb9bee
[root@b948d68a (storage) /manta/v2/c116efce-086f-455e-9ae4-26d49551428d/afc19bda-99de-461c-81f5-8b0633c88259/56]$ cat 56ccac05-c9c6-4e6b-8a8e-5daad7d4e44f,4116ddb8d538f4db68253ca6a6fb9bee
sopa1

```
