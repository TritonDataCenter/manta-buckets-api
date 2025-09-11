# Manta Buckets API - S3 Layer Quick Start Guide

This guide will help you get started with using the S3-compatible layer of the Manta Buckets API. You'll learn how to create access keys and configure your S3 clients to work with Manta storage.

## Prerequisites

Before you begin, ensure you have:
- A Manta account 
- An S3 client (AWS CLI, s3cmd)

## Creating Access Keys

### Step 1: Create Access Key and Secret

The S3 layer uses your Manta your access keys and secret access key from your account.
To create the access key and secret, we need to use cloudapi.

```bash
# Call cloudapi to generate access keys and secret
cloudapi /your-manta-account/accesskeys | json
HTTP/1.1 200 OK
content-type: application/json
content-length: 2
access-control-allow-origin: *
access-control-allow-headers: Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, Api-Version, Response-Time
access-control-allow-methods: POST, GET, HEAD
access-control-expose-headers: Api-Version, Request-Id, Response-Time
content-md5: 11FxOYiYfpMxmANj4kGJzg==
date: Mon, 28 Jul 2025 14:38:39 GMT
server: cloudapi/9.20.0
api-version: 9.0.0
request-id: 6bf0b965-d49b-40c0-8619-675c02afa305
response-time: 320

[]
# as expected your account those not have access keys, so let's generate them.
cloudapi /your-manta-account/accesskeys -X POST
HTTP/1.1 201 Created
location: /neirac/accesskeys/91f41250ffff1bb1472611dd3b0bde50
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
| `buckets-api`| Core Bucket Operations |  684049e8-9b78-49b3-8e09-8744f7df3698" | No - Direct integration |
| `storage`  | Storage Nodes |  5735eba4-746c-4f93-b275-8d739e53f1e4| No - Backend dependency |
| `loadbalancer` | Traffic Distribution | |f9f32770-14fa-4f85-a7cc-a1b8b62ede07| No -  direct integration  |

### Services Requiring Extra Steps

Required steps after the required services from the service dependencies table
are specified in https://github.com/TritonDataCenter/manta-buckets-api/blob/MANTA-5471/docs/deployment.md

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

## Advanced Configuration

### Custom Role Management

If you need custom roles beyond the standard S3 ACLs, zlogin into the cloudapi
instance from the headnode and create the policy and role required.
For example here we create the required public-read role and read-public policy
used by the canned acl 'public-read'

```bash
# Create custom roles using Manta CLI
manta-create-role --name custom-readers --members user1,user2

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
