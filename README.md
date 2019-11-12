<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright 2019 Joyent, Inc.
-->

# manta-buckets-api: The Manta Web API

This repository is part of the Joyent Manta project.  For contribution
guidelines, issues, and general documentation, visit the main
[Manta](http://github.com/joyent/manta) project page.

manta-buckets-api holds the source code for the Manta API, otherwise known as
"the front door".  It is analogous to CloudAPI for SDC.  See the restdown
docs for API information, but effectively this is where you go to call
PUT/GET/DEL on your stuff, as well as to submit and control compute jobs.

API documentation is in [docs/index.md](./docs/index.md).  Some design
documentation (possibly quite dated) is in [docs/internal](./docs/internal).
Developer notes are in this README.


## Testing

Coming soon

## Deploying a buckets-api image

If you're changing anything about the way buckets-api is deployed, configured, or
started, you should definitely test creating a buckets-api image and deploying that
into your Manta.  This is always a good idea anyway.  To run tests against an
image, your configuration will be a bit different.  Your `MANTA_URL` will be the
manta network IP of a buckets-api instance, with a port number of a buckets-api process
inside a buckets-api zone (8081).  Your `SDC_URL` will be the external network IP of
the cloudapi0 zone.  You can find both of these IPs with the commands:

    $ vmadm get <buckets-api_zone_uuid> | json -a nics | json -a nic_tag ip
    $ vmadm lookup -j alias=cloudapi0 | json -a nics | json -a ip

There are various documents about deploying/updating a buckets-api image in
Manta. If you're doing this for the first time, and not sure what to
do, I had success with `make buildimage` which leaves you with an
image and manifest in `./bits`. You can then import this image and
follow this guide to upgrading manta components:
https://github.com/joyent/manta/blob/master/docs/operator-guide.md#upgrading-manta-components

## Metrics

Buckets-Api exposes metrics via [node-artedi](https://github.com/joyent/node-artedi).
See the [design](./docs/internal/design.md) document for more information about
the metrics that are exposed, and how to access them. For development, it is
probably easiest to use `curl` to scrape metrics:

```
$ curl http://localhost:8881/metrics
```

Notably, some metadata labels are not being collected due to their potential
for high cardinality.  Specifically, remote IP address, object owner, and caller
username are not collected.  Metadata labels that have a large number of unique
values cause memory strain on metric client processes (buckets-api) as well as
metric servers (Prometheus).  It's important to understand what kind of an
effect on the entire system the addition of metrics and metadata labels can have
before adding them. This is an issue that would likely not appear in a
development or staging environment.

## Service registration

Like most other components in Triton and Manta, this service is configured to
use [Registrar](https://github.com/joyent/registrar/). Each of the API server
ports are registered under a `SRV` record as described in the Registrar
documentation, and the registration type is `load\_balancer`.

The general mechanism is [documented in detail in the Registrar
README](https://github.com/joyent/registrar/blob/master/README.md).

As with other services providing multiple ports per zone instance, the registrar
template is itself modified during setup via `boot/setup.sh` to populate the
list of ports. Consequently, querying DNS for `SRV` entries will show something
like (if we have two instances each with four API servers):

````
$ dig +nocmd +nocomments +noquestion +nostats -t SRV _http._tcp.buckets-api.manta.example.com
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8081 243844f9-8cc1-497d-99a0-627263524e7a.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8082 243844f9-8cc1-497d-99a0-627263524e7a.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8083 243844f9-8cc1-497d-99a0-627263524e7a.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8084 243844f9-8cc1-497d-99a0-627263524e7a.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8081 4a1af359-a671-47d1-bc8b-70e4ea81af7c.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8082 4a1af359-a671-47d1-bc8b-70e4ea81af7c.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8083 4a1af359-a671-47d1-bc8b-70e4ea81af7c.buckets-api.manta.example.com.
_http._tcp.buckets-api.manta.example.com. 60 IN SRV 0 10 8084 4a1af359-a671-47d1-bc8b-70e4ea81af7c.buckets-api.manta.example.com.
243844f9-8cc1-497d-99a0-627263524e7a.buckets-api.manta.example.com. 30 IN A 192.168.0.39
4a1af359-a671-47d1-bc8b-70e4ea81af7c.buckets-api.manta.example.com. 30 IN A 192.168.0.38
```

The `buckets-api` client, [muppet](https://github.com/joyent/muppet), doesn't
directly use DNS lookups: instead the corresponding Zookeeper nodes are watched
for changes, updating its `haproxy` configuration as needed. This is partly for
historical reasons (both muppet and the old webapi registered themselves with a
service name of "manta"), and to reduce load on
[binder](https://github.com/joyent/binder/).

## Dtrace Probes

Buckets-Api has two dtrace providers. The first, `buckets-api`, has the following probes:
* `client_close`: `json`. Fires if a client uploading an object or part closes
  before data has been streamed to mako. Also fires if the client closes the
  connection while the stream is in progress. The argument json object has the
  following format:
  ```
  {
      id: restify uuid, or x-request-id/request-id http header (string)
      method: request http method (string)
      headers: http headers specified by the client (object)
      url: http request url (string)
      bytes_sent: number of bytes streamed to mako before client close (int)
      bytes_expected: number of bytes that should have been streamed (int)
  }
  ```
* `socket_timeout`: `json`. Fires when the timeout limit is reached on a
  connection to a client. This timeout can be configured either by setting the
  `SOCKET_TIMEOUT` environment variable. The default is 120 seconds. The object
  passed has the same fields to the `client_close` dtrace probe, except for the
  `bytes_sent` and `bytes_expected`. These parameters are only present if buckets-api
  is able to determine the last request sent on this socket.

The second provider, `buckets-api-throttle`, has the following probes, which will not
fire if the throttle is disabled:
* `request_throttled`: `int`, `int`, `char *`, `char *` - slots occupied, queued
  requests, url, method. Fires when a request has been throttled.
* `request_handled`: `int`, `int`, `char *`, `char *` - slots occupied, queued
  requests, url, method. Fires after a request has been handled.
Internally, the buckets-api throttle is implemented with a vasync-queue. A "slot"
in the above description refers to one of `concurrency` possible spaces
allotted for concurrently scheduled request-handling callbacks. If all slots are
occupied, incoming requests will be "queued", which indicates that they are
waiting for slots to free up.
* `queue_enter`: `char *` - restify request uuid. This probe fires as a request
enters the queue.
* `queue_leave`: `char *` - restify request uuid. This probe fires as a request
is dequeued, before it is handled. The purpose of these probes is to make it
easy to write d scripts that measure the latency impact the throttle has on
individual requests.

The script `bin/throttlestat.d` is implemented as an analog to `moraystat.d`
with the `queue_enter` and `queue_leave` probes. It is a good starting point for
gaining insight into both how actively a buckets-api process is being throttled and
how much stress it is under.

The throttle probes are provided in a separate provider to prevent coupling the
throttle implementation with buckets-api itself. Future work may involve making the
throttle a generic module that can be included in any service with minimal code
modification.
