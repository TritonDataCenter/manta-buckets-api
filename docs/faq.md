# FAQs

This document will try to cover things that are usually needed to know when
dealing with a manta-buckets-api deployment.

### How to locate a file in manta-buckets-api

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

The important part here is the _key_  and id , the file name that contains the 
data is a concatenation of id and the last element from _key_ (we split by  ':')
. For example to obtain the file we just concatenate these values adding ',' 
between them: 
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

