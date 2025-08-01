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

