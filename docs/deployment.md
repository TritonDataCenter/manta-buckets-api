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




