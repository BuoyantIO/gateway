# Gateway Architecture

## Summary

This is the canonical architecture document for Gateway project.

## What is this document useful for

We need a document that breaks down the product into manageble
architectural artefacts. Each of these artefacts (called areas), should
consist of at minimum:

- exploration of prior art
- proposed approach
- concrete scope for v0 delivery

The proposed approach should encode the main architectural phylosophy of
the area that is being covered without attempting to elaborate on the full
set of features that will go into this area. When reading through an area,
the reader should feel able to extrapolate on how that area will be
extended with further features/functionality. Additionally the concrete
scope for v0 delivery should prescribe a set of functionalities that should
go into the first functional version of the product.

To put this in concrete terms, the configuration area can prescribe core
concepts such as port bindings, filters, routes, upstreams, etc. Once this
context is set, it should be possible for the reader to imagine building
additional functionality on top of these concepts - for example adding
support for upstream mTLS origination via ingesting certs from a third
party control plane (e.g. Linkerd Identity or SPIRE).


## Architecture by Area


- [Configuration Schema](#01-configuration)
- [Runtime model, concurrency and traffic admission](#02-runtime-model-concurrency-and-traffic-admission)
- [Traffic filtering](#03-traffic-filtering)
- [Route and backend selection](#04-route-and-backend-selection)
- Endpoint picking and inventory 
- Backend origination
- Extendibility

### 01. Configuration

#### Problem statement

We need a gateway configuration schema with explicit types and
relationships that can express entrypoints, routing, backend forwarding,
route filters, and inline settings. The schema must support asynchronous update
behavior and remain extensible as new settings and filter capabilities are
introduced.

#### Goals

- Define core entities and required fields for v0.
- Define route filters and inline settings behavior.
- Clarify asynchronous update points and convergence expectations.

#### Non-goals

- Full Gateway API integration in v0.
- Config transport implementation details (for example gRPC stream wiring
  to control plane vs filesystem config).

#### Baseline gateway intent ([Gateway API](https://kubernetes.io/docs/concepts/services-networking/gateway/))

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: demo-gateway
spec:
  gatewayClassName: demo-gateway-class
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      hostname: app.example.com
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            name: app-tls
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app-route
spec:
  parentRefs:
    - name: demo-gateway
      sectionName: https
  hostnames:
    - app.example.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api
      filters:
        - type: RequestHeaderModifier
          requestHeaderModifier:
            add:
              - name: x-gateway
                value: demo
      backendRefs:
        - name: api-svc
          port: 8080

    - matches:
        - path:
            type: PathPrefix
            value: /healthz
      backendRefs:
        - name: health-svc
          port: 8080
```

This baseline intent is used as the comparison target for prior art:
terminate TLS for `app.example.com`, route `/api` with a request-header
filter to `api-svc`, and route `/healthz` to `health-svc`.

#### Prior art: Agent Gateway

##### Configuration philosophy

Configuration is modeled as a core traffic graph, and behavior is added
through typed filters and inline settings. In this architecture, ordered
traffic filters live on routes, while declarative settings live directly on
the graph node that consumes them.

Core shape:
`bind -> listener -> route -> backend`

In Agent Gateway, this graph is the stable backbone of the data plane.
Each level has a distinct responsibility: `bind` defines where traffic
enters the gateway, `listener` defines how that traffic is spoken
(protocol/TLS), `route` defines how requests are matched and governed,
and `backend` defines where traffic is ultimately forwarded. The key
design idea is separation of concerns across these nodes: flow structure
stays simple and predictable, while additional behavior is layered on top
through attachments. That makes the model easier to evolve because most new
capabilities do not require changing the core graph itself.

##### Example config

```yaml
binds:
- port: 443
  listeners:
  - hostname: app.example.com
    protocol: HTTPS
    tls:
      certificateRefs:
      - name: app-tls
        kind: Secret
    routes:
    - name: api-route
      matches:
      - path: { pathPrefix: /api }
      policies:
        requestHeaderModifier:
          add:
            x-gateway: demo
      backends:
      - host: api-svc.default.svc.cluster.local:8080
    - name: health-route
      matches:
      - path: { pathPrefix: /healthz }
      backends:
      - host: health-svc.default.svc.cluster.local:8080
```

This bind/listener/route/backend graph terminates TLS on port 443 for
`app.example.com`, applies `x-gateway: demo` on `/api`, routes `/api` to
`api-svc`, and routes `/healthz` to `health-svc`.

In essence:

- Listener carries protocol and TLS concerns.
- Route carries match conditions and most behavior attachment points.
- Backend carries target and destination semantics.
- Policy complexity grows inside typed policy objects without changing the
  top-level concept graph.

##### Asynchronous update points

Agent Gateway treats the traffic graph as incrementally updatable. Core
primitives can be updated asynchronously and converge as dependencies are
satisfied.

- `Bind`
- `Listener`
- `Route`
- `Backend`

##### Pros

- Compact core graph that remains stable as capabilities grow.
- Attachment model expands behavior without reshaping core concepts.
- Works well with high-velocity, out-of-order config updates.

##### Cons

- Partial convergence creates temporary intermediate states.
- Dependency and activation semantics must be documented precisely.

##### Sources

[Documentation](https://agentgateway.dev/docs/)
[Motivation](https://www.youtube.com/watch?v=qa5vSE86z-s)
[Motivation](https://www.youtube.com/watch?v=SomP92JWPmE)
[General feature overview](https://agentgateway.dev/docs/standalone/latest/about/introduction/)

#### Prior art: Envoy

##### Configuration philosophy

Core routing and upstream resources are first-class objects, while
behavior is extended through filter configuration.

Core HTTP shape:
`listener -> filter chain -> route config -> cluster -> endpoint`

- `listener` defines downstream bind and protocol entrypoint.
- `filter chain` defines transport/L7 processing pipeline.
- `route config` defines virtual hosts, matches, and route actions.
- `cluster` defines upstream service policy and connection behavior.
- `endpoint` defines concrete upstream instances for a cluster.

##### Example config

```yaml
static_resources:
  listeners:
  - name: ingress-https
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 443
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificates:
            - certificate_chain:
                filename: /etc/envoy/tls/app-tls.crt
              private_key:
                filename: /etc/envoy/tls/app-tls.key
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_https
          route_config:
            name: ingress_routes
            virtual_hosts:
            - name: app
              domains: ["app.example.com"]
              routes:
              - match:
                  prefix: "/api"
                route:
                  cluster: api_svc
                  timeout: 15s
                request_headers_to_add:
                - header:
                    key: x-gateway
                    value: demo
              - match:
                  prefix: "/healthz"
                route:
                  cluster: health_svc
                  timeout: 15s
          http_filters:
          - name: envoy.filters.http.router
  clusters:
  - name: api_svc
    connect_timeout: 2s
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    load_assignment:
      cluster_name: api_svc
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: api-svc.default.svc.cluster.local
                port_value: 8080
  - name: health_svc
    connect_timeout: 2s
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    load_assignment:
      cluster_name: health_svc
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: health-svc.default.svc.cluster.local
                port_value: 8080

admin:
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 19000
```

This static bootstrap creates one HTTPS listener with an
`HttpConnectionManager` virtual host for `app.example.com`, routes `/api`
to `api_svc` with `x-gateway: demo`, routes `/healthz` to `health_svc`,
and resolves backends through DNS-backed clusters.

Conceptually:
- Listener owns downstream connection entry and protocol handoff.
- Route config owns host/path matching and route actions.
- Cluster owns upstream policy (LB, timeouts, connection settings).
- Endpoint set owns concrete upstream destinations.
- Filter configs attach behavior without replacing core resource types.

##### Config update semantics

This example uses static bootstrap resources for readability. In
production, the same resource model can be delivered dynamically through
xDS.

Asynchronous resource update points:

- `Listener` (LDS)
- `Route config` (RDS)
- `Cluster` (CDS)
- `Endpoint` (EDS)
- `Secret` (SDS)

Resources are not all activated immediately on receipt. Activation is
resource-aware and dependency-aware (for example listeners/routes depend
on referenced upstream resources being usable). When a resource
references dependencies that are missing or not ready, Envoy does not
treat it as fully active dataplane state. The control-plane snapshot can
be accepted while some references remain operationally not ready until
dependencies converge.

In Kubernetes deployments there are various ways to configure the proxy
through the xDS API. To name a few: 
- [Envoy gateway](https://gateway.envoyproxy.io/)
- [Istio](https://istio.io/latest/docs/)
- [Gloo](https://github.com/solo-io/gloo)

These typically act as control plane layers that transition Gateway API
resources into xDS updates.

##### Pros

- Fine-grained dynamic update model.
- Mature control-plane and data-plane contract.

##### Cons

- Higher conceptual and operational complexity.
- Dependency ordering and partial activation are hard in practice.

##### Sources

[Latest docs](https://www.envoyproxy.io/docs/envoy/v1.37.2/)
[Life of a request](https://www.envoyproxy.io/docs/envoy/v1.37.2/intro/life_of_a_request)
[Envoy AI gateway](https://aigateway.envoyproxy.io/blog/introducing-envoy-ai-gateway/)
[External processing](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter)
[Envoy WASM extensions](https://gateway.envoyproxy.io/docs/tasks/extensibility/wasm/)

#### Prior art: NGINX

##### Configuration philosophy

Configuration is hierarchical. Core traffic flow is expressed through
nested contexts, and behavior is attached by module directives scoped to
those contexts.

Core HTTP shape:
`main -> http -> server -> location -> upstream`

- `main` defines process-level runtime behavior.
- `http` defines protocol-wide defaults and shared components for HTTP.
- `server` defines virtual host entrypoints.
- `location` defines request matching and forwarding behavior.
- `upstream` defines destination pools used by proxying directives.

##### Example config

```nginx
worker_processes auto;

events {
  worker_connections 1024;
}

http {
  upstream api_backend {
    server api-svc.default.svc.cluster.local:8080;
  }

  upstream health_backend {
    server health-svc.default.svc.cluster.local:8080;
  }

  server {
    listen 443 ssl;
    server_name app.example.com;

    ssl_certificate /etc/nginx/tls/app-tls.crt;
    ssl_certificate_key /etc/nginx/tls/app-tls.key;

    location = /api {
      proxy_set_header X-Gateway demo;
      proxy_pass http://api_backend;
    }

    location ^~ /api/ {
      proxy_set_header X-Gateway demo;
      proxy_pass http://api_backend;
    }

    location = /healthz {
      proxy_pass http://health_backend;
    }

    location ^~ /healthz/ {
      proxy_pass http://health_backend;
    }
  }
}
```

This config terminates TLS in a `server` for `app.example.com`, routes
`/api` and `/api/*` to `api_backend` with `X-Gateway: demo`, and routes
`/healthz` and `/healthz/*` to `health_backend`.

NGINX expresses behavior through context-scoped directives. 
Shared defaults and reusable components are typically defined in
`http`/`stream,`, including upstream pools. Host-specific
behavior is then layered in `server`, where TLS, hostname matching, and
server-level policy are declared. Finally, `location` carries the most
request-specific behavior, such as path-based proxying, header mutation,
authentication hooks, timeouts, and per-route rate limits.

##### Config update semantics

NGINX does not ingest independent route/listener/backend deltas during
normal config updates. The update unit is a full configuration
generation that is parsed and validated as one candidate snapshot. If
the new generation is valid and resources can be prepared, NGINX starts
a new worker generation on the new snapshot and gracefully drains old
workers.

It is worth noting that NGINX Plus API, which is not free is capable of
applying incremental updates to Nginx configuration. That coupled with the
NGINX Gateway Fabric provides a way for the system to work with Gateway API.

##### Pros

- Clear scope ownership through hierarchical contexts.
- Full-generation validation before activation.
- Simpler mental model for config publication.

##### Cons

- Limited fine-grained asynchronous graph updates.
- Full-generation reload cost grows with config size.

##### Sources

[Latest docs](https://nginx.org/en/docs/)
[How NGINX's Handles Million Concurrent Connections](https://engineeringatscale.substack.com/p/nginx-millions-connections-event-driven-architecture)
[NGINX Gateway Fabric](https://github.com/nginx/nginx-gateway-fabric)
[NGINX Gateway Architecture](https://docs.nginx.com/nginx-gateway-fabric/overview/gateway-architecture/)

#### Proposed approach

The goal of this section is to define the smallest set of concepts needed
to explain how configuration is structured and how traffic intent is
represented.

##### Core primitives

`GatewayConfig` is the root object. It represents one desired
configuration view for the gateway. It also contains global settings
applicable to the gateway as a whole (log level, concurrency settings, etc).

The core graph is composed of primitives:

- `Bind` is the network entrypoint. It defines where traffic first lands,
  groups the listeners that are served on a particular port, and owns
  the socket dispatch path through `BindProtocol`.
  Example: a public bind might carry `address: 0.0.0.0:443`,
  `bindProtocol: TLS`, and the set of listeners associated with that
  port.
- `Listener` is the protocol-facing child of a bind. It defines the
  per-listener protocol and TLS behavior through `ListenerProtocol`.
  Example: a listener might carry `listenerProtocol: HTTPS`, a hostname
  such as `app.example.com`, and TLS configuration such as certificate
  references or passthrough mode, together with the set of routes that
  apply on that entrypoint.
- `Route` is the unit of traffic selection. It holds match conditions and
  the references that decide where matching traffic should be forwarded.
  Example: a route might carry a host/path match like
  `app.example.com` + `/api`, together with references to one or more
  backends.
- `Backend` is the reusable upstream definition. It exists separately so
  routes can refer to named targets instead of embedding destination
  details inline everywhere. Example: a backend might carry a Kubernetes
  Service reference, a static endpoint set, or upstream connection
  settings that are shared across routes. 
- `BackendRef` is the edge between a route and a backend. It lets route
  intent stay small while allowing backend definitions to be shared and
  evolved independently. Example: a backend ref might carry the backend
  name plus route-specific forwarding details such as weight or priority.
- `Filter` is an inline, route-owned traffic processing step. Filters have
  ordered execution semantics and may inspect, mutate, short-circuit, or
  report on traffic through hooks defined by the traffic-filtering area.
  Example: a route filter might add a request header, enforce an auth
  check, emit custom metrics, or eventually be implemented by a plugin that
  satisfies the same filter interface.
- `Secret` is also a reusable definition. Just like backends, it exists
  separately so other nodes can refer to it for the purpose of TLS
  termination,origination, etc.

The relationships are explicit:

- `GatewayConfig -> Bind -> Listener -> Route -> BackendRef`
- `Route -> Filter`
- `BackendRef -> Backend`
- `Route` and `Backend` own inline settings
- `Listener -> Secret` 

##### Top Level Schema

The table below is the configuration model. Each row map to a concrete type
and validation path as well as update mechanism.

| Object | Identity | Required fields | Important defaults | References |
| --- | --- | --- | --- | --- |
| `GatewayConfig` | `name` | `name`, `binds` | Empty global settings use runtime defaults | Owns `Bind`, `Backend`, and `Secret` collections |
| `Bind` | `name` | `name`, `address`, `port`, `bindProtocol` | `address: 0.0.0.0` if omitted by a higher-level config source | Owns one or more `Listener` objects |
| `Listener` | `bind.name/listener.name` | `name`, `listenerProtocol`, `hostname`, `tls.mode` for TLS-family listeners | Empty hostname means catch-all listener | Parent `Bind`; may reference `Secret` for TLS termination |
| `Route` | `listener.key/route.name` | `name`, `matches`, `backendRefs` | Match dimensions are protocol-specific; `filters: []` | Parent `Listener`; references `Backend` through `BackendRef`; owns inline `Filter` entries and route settings |
| `Filter` | Inline within `Route` by `name` | `name`, `type` | No ordering field; list position in `Route.filters[]` is authoritative | Belongs to one `Route` |
| `BackendRef` | Inline within `Route` by referenced backend name | `name` | `weight: 1` | References one `Backend` |
| `Backend` | `name` | `name`, `type` | No implicit backend type; empty `settings` | Owns or references concrete `Endpoint` entries and backend settings |
| `Endpoint` | `backend.name/endpoint.name` | `name`, `address`, `port` | No health/readiness default in Area 01 | Belongs to one `Backend` |
| `Secret` | `name` | `name`, `type`, secret material reference or inline material | No default material; invalid or missing material is not allowed | Referenced by `Listener` for TLS termination; backend origination deferred |

Each object should define required fields, optional fields, defaults,
reference rules, update behavior, and delete behavior. Missing required
fields reject the object. Missing references stash the object.

For this inventory, identity means the stable key used for updates,
deletes, dependency tracking, and status.

`Endpoint` is listed because static backends need concrete destinations.
Endpoint readiness, health, and dynamic inventory remain outside Area 01
and belong to load balancing and endpoint picking section.

##### Protocol and listener selection

`BindProtocol` controls the accepted socket dispatch path.
`ListenerProtocol` controls what a selected listener does with traffic
after dispatch. This mirrors the Agent Gateway split: the bind decides how
to classify the connection, while the listener decides TLS termination,
passthrough, or later protocol handling.

`BindProtocol` is configured once per bind. The model includes:

- `TLS` for connections whose dispatch path reads a TLS ClientHello. For
  TLS-terminated listeners (`ListenerProtocol::HTTPS`), the gateway
  advertises ALPN `["h2", "http/1.1"]` during the handshake. The
  post-handshake stream is then served by the same HTTP codec selection
  path used by plaintext `HTTP` listeners.
- `TCP` for opaque TCP connections. No protocol negotiation.
- `HTTP` for plaintext HTTP connections. Both HTTP/1.1 and HTTP/2 cleartext
  are accepted: the HTTP/2 connection preface is detected on the stream
  and selects the H2 codec; otherwise HTTP/1.1 is used.

`ListenerProtocol` is configured once per listener. The model includes:

- `TLS` for TLS listeners that may terminate TLS or pass it through.
- `HTTPS` for TLS-terminated HTTP listeners. HTTP codec is selected on the
  post-handshake stream by the same mechanism used for plaintext `HTTP`
  listeners; the ALPN negotiated during the handshake on the parent bind
  constrains what the client will transmit to that mechanism.
- `TCP` for opaque TCP listeners.
- `HTTP` for plaintext HTTP listeners. HTTP codec is selected by detecting
  the HTTP/2 connection preface on the per-connection stream — preface
  match wires in the H2 codec, otherwise HTTP/1.1.

HTTP version selection on `HTTP` and `HTTPS` listeners is automatic.
There is no per-listener version knob in v0; the advertised ALPN list and
any HTTP/2 codec settings are static defaults. See Area 02 for the runtime
detail.

The dispatch path filters eligible listeners by `ListenerProtocol`. A TLS
dispatch peeks the ClientHello, extracts SNI, and considers TLS-family
listeners such as `HTTPS` and `TLS`. An HTTP dispatch reads `:authority` or
`Host`. A TCP dispatch has no hostname input. `Auto` chooses a dispatch
path before listener selection.

When hostname input is available, listener selection prefers exact
hostname, then longest wildcard suffix, then empty-hostname catch-all. If
no listener matches, the connection or request is rejected or closed. TLS
and TCP listener selection is connection-scoped. Plaintext HTTP listener
selection may be request-scoped.

Gateway API has no top-level `Bind` concept. The gateway materializes binds
by grouping Gateway API listeners by address and port. The protocol split
maps as follows:

| Gateway API `protocol` | `tls.mode` | `BindProtocol` | `ListenerProtocol` |
| --- | --- | --- | --- |
| `TLS` | `Terminate` | `TLS` | `TLS(Some(ServerTLSConfig))` |
| `TLS` | `Passthrough` | `TLS` | `TLS(None)` |

##### Route filter semantics

Filters are the ordered traffic-processing surface in Area 01. For now,
filters attach only as an inline `filters[]` list on a `Route`. A filter
is not an independently addressed graph node and is validated, updated,
activated, and deleted as part of its parent route.

Route filters run only after route selection. On the request path, filters
run in the order they appear in `Route.filters[]`. On the response path,
response-capable filters run in reverse list order. The list has no
separate numeric ordering field.

Filters are the right place for traffic execution behavior: header
mutation, authentication checks, short-circuit responses, custom metrics,
and future plugin-backed behavior that satisfies the filter interface.
Body and chunk hooks are owned by the traffic-filtering area. A filter
that does not opt into a body hook must not receive body chunks.

##### Inline settings

Settings are unordered declarative configuration consumed by the graph node
they live on. They do not execute in filter order and are not independently
addressed resources.

`Route.settings` is for route-scoped runtime parameters such as retry,
timeout, or other behavior that is consumed after a route is selected.
`Backend.settings` is for backend-scoped runtime parameters such as
connection pool, backend transport, or backend TLS origination settings.
`Listener.tls` remains the native place for TLS termination and passthrough
configuration.

##### Example mapping

The following YAML shows how the baseline Gateway API example would map
into this model in our particular case.

```yaml
gatewayConfig:
  name: demo-gateway-config
  binds:
    - name: public-https
      address: 0.0.0.0
      port: 443
      listeners:
        - name: app-https
          protocol: HTTPS
          hostname: app.example.com
          tls:
            mode: Terminate
            certificates:
              - name: app-tls
                kind: Secret
          routes:
            - name: api-route
              matches:
                - path:
                    type: PathPrefix
                    value: /api
              backendRefs:
                - name: api-backend
              filters:
                - name: add-gateway-header
                  type: RequestHeaderModifier
                  requestHeaders:
                    add:
                      - name: x-gateway
                        value: demo
            - name: health-route
              matches:
                - path:
                    type: PathPrefix
                    value: /healthz
              backendRefs:
                - name: health-backend
  backends:
    - name: api-backend
      type: Service
      service:
        name: api-svc
        port: 8080
    - name: health-backend
      type: Service
      service:
        name: health-svc
        port: 8080
  secrets: 
    - name: app-tls
      data: ...
```

##### Update semantics

Like Agent Gateway, this model assumes an incrementally updatable graph
rather than full-graph replacement on every change.

The independently updated units are:

- `Bind`
- `Listener`
- `Route`
- `Backend`
- `Secret`

Inline `Filter` entries are not independently updated units. They are
validated and activated with their parent `Route` or `Backend`.

Each object is first validated on its own and then either becomes
active, is rejected, or is stashed because a required dependency is
missing.

Stashing is what makes unordered updates workable. A `Listener` can be
stashed until its `Bind` or `Secret` that are not present are observed. A
`Route` can be stashed until its parent listener and referenced backends
exist.

| Update unit | Stashable | Why |
| --- | --- | --- |
| `Bind` | No | A bind is a top-level entrypoint object and does not depend on another graph node to exist first. |
| `Listener` | Yes | A listener depends on its parent bind and its secrets. If either the bind or its secrets are missing, the listener can be stashed. |
| `Route` | Yes | A route depends on its parent listener and on the backends it references. |
| `Backend` | No | A backend is a standalone reusable target definition. Routes may wait on it, but it does not wait on routes. |
| `Secret` | No | A secret is a standalone, reusable resource. |

Stashed objects are kept and retried when a
relevant dependency changes. If a newer revision of the same stashed
object arrives, it replaces the older one. Once the dependency graph is
satisfied, the object becomes active and leaves the stashed set.

Convergence is incremental. One unresolved route or backend should not
block unrelated binds, listeners, routes, or backends from becoming
active. If an active dependency disappears, dependents should fall back
out of the active graph rather than continue serving against a broken
reference.

##### Update semantics examples

Assuming the following Gateway API config

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: demo-gateway
spec:
  gatewayClassName: demo-gateway-class
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      hostname: app.example.com
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            name: app-tls
    - name: pass
      protocol: TLS
      port: 443
      hostname: pass.example.com
      tls:
        mode: Passthrough
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app-route
spec:
  parentRefs:
    - name: demo-gateway
      sectionName: https
  hostnames:
    - app.example.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api
      filters:
        - type: RequestHeaderModifier
          requestHeaderModifier:
            add:
              - name: x-gateway
                value: demo
      backendRefs:
        - name: api-svc
          port: 8080

    - matches:
        - path:
            type: PathPrefix
            value: /healthz
      backendRefs:
        - name: health-svc
          port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: api-svc
spec:
  selector:
    app: api
  ports:
    - port: 8080
      targetPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: health-svc
spec:
  selector:
    app: health
  ports:
    - port: 8080
      targetPort: 8080
---
apiVersion: v1
kind: Secret
metadata:
  name: app-tls
type: kubernetes.io/tls
stringData:
  tls.crt: |
    -----BEGIN CERTIFICATE-----
    REPLACE_WITH_TLS_CERTIFICATE
    -----END CERTIFICATE-----
  tls.key: |
    -----BEGIN PRIVATE KEY-----
    REPLACE_WITH_TLS_PRIVATE_KEY
    -----END PRIVATE KEY-----
```

###### Scenario 1 - in order updates

Assuming we get the following updates: 
- Service `api-svc`
- Service `health-svc`
- Secret  `app-tls`
- Gateway `demo-gateway`
- HTTPRoute `app-route`


The following happens: 
- Service `api-svc` is inserted in the active list of services
- Service `health-svc` is inserted in the active list of services
- Secret `app-tls` is inserted in the active list of secrets
- Gateway `demo-gateway` results in creating two active listeners and a bind
- HTTPRoute `app-route` is inserted into the list of active routes


###### Scenario 2 - out of order updates

Assuming we get the following updates: 
- Secret  `app-tls`
- Gateway `demo-gateway`
- HTTPRoute `app-route`
- Service `api-svc`
- Service `health-svc`


The following happens:
- Secret `app-tls` is inserted in the active list of secrets
- Gateway `demo-gateway` results in creating two active listeners and a bind
- HTTPRoute `app-route` is stashed because it references two missing
  services
- Service `api-svc` is inserted in the active list of services but
  HTTPRoute remains stashed because health-svc is still missing for it
- Service `health-svc` is inserted in the active list of services, as part
  of this update HTTPRoute is unstashed and added to the set of active
  routes


###### Scenario 3 - depndency update out of order

We assume that we have arrived at the end state described in [Scenario
1](#scenario-1---in-order-updates) and the following actions take place:
- Gateway `demo-gateway` is updated so the tls secret now points to
  `app-tls-2`
- Secret  `app-tls-2` created
- Secret `app-tls` deleted


The following happens:
- the listener named `https` is updated to point to the new secret and
  since it is missing transitions to stashed. The same happens to the
  HTTPRoute named `app-route`
- Secret `app-tls-2` is received and as a result of that we unstash the
  stashed listener along with the routes
- Secret `app-tls` is removed from the list of secrets

###### Scenario 4 - dependency deletion

We assume that we have arrived at the end state described in [Scenario
1](#scenario-1---in-order-updates) and the following actions take place:
- Gateway `demo-gateway` is deleted


The following happens:
- Binds and listeners associated with this gateway are deleted, connections
  drained, etc
- HTTPRoute `app-route` is stashed as well

###### Scenario 5 - tls secret update

We assume that we have arrived at the end state described in [Scenario
1](#scenario-1---in-order-updates) and the following actions take place:
- Operator updates the contents of `Secret` `app-tls` as part of a certs rotation routine


The following happens:
- an update for Secret `app-tls` is received
- the TLS material is atomically swapped in the runtime graph 
- old connections resume on negotiated certs
- new connections are negotiated based on the latest state


##### Open questions and implementation considerations

1. How do we avoid pathological situations where the set of stashed objects
   grows to infinity?

There are a couple of strategies that we can implement here. One is to have
a TTL on them. It is hard to anchor ourselves to something concrete that
informs this TTL. Additionally we can have a hard cap on the number of
stashed objects per type and do some back of the envelope math to determine
how much memory we can spare for these. Realistically however, the safest
bet is to expose introscpection tools that give us information about the
current state of the runtime. These could be debug endpoints that dump the
state or prometheus metrics that give us precise data about the size of the
stash sets.

Given these pieces of information and a sensible control plane
implementation, we can implement stress tests via frameworks such as
[Kwok](https://kwok.sigs.k8s.io/) that allows us to mimic pathological
scenarios and determine their impact on the system.

2. Do we care about endpoint readiness for backends and how does that
   relate to stashing?

Short answer is we do not. At least at this level. Endpoint readiness is a
loadbalancer/endpoint picking concern. A service/backend exists no matter
of its readiness. This means that it can be a fully active node of a config
graph even if no endpoints exist of it. 

#### V0 scope

V0 is the first supported slice of this schema, not the full long-term
shape. It keeps the current graph model
`Bind -> Listener -> Route -> BackendRef -> Backend` and focuses on an
initial TLS-oriented entrypoint shape.

V0 should support:

- multiple binds under the same `GatewayConfig`
- multiple listeners per `Bind`
- `BindProtocol: TLS` with TLS-family listeners
- optional `TLS` termination based on listener TLS config
- route matches on SNI for TLS traffic
- static backends with multiple endpoints
- a simple TLS Client Hello log filter in `Route.filters[]`

In practical terms, this means `Bind` must support `BindProtocol: TLS`, and
`Listener` must support TLS-family `ListenerProtocol` values and optional
termination of the TLS session based on listener TLS config. `Route` must
support an SNI match for TLS traffic, with SNI interpreted from the Client
Hello before termination. `Backend` must support a static form with an
explicit list of endpoints. `Route.filters[]` must support one initial TLS
filter type for Client Hello logging. Inline settings remain reserved for
unordered declarative configuration, not filter execution.

V0 does not attempt to cover the full long-term surface. In particular,
it does not include dynamic endpoint discovery for backends, full
Gateway API parity for TLS-oriented resources, or detailed semantics for
weighted balancing, advanced health checking.


### 02. Runtime model, concurrency and traffic admission

#### Problem statement

We need a runtime model for the gateway that defines how the process uses
the CPU it is given: how worker threads are structured, how inbound
connections are admitted and distributed across workers, how upstream
connection state is shared across concurrent work, and how
control-plane/config resolution activity is kept off the data path.

#### Goals

- Define the threading model for the data plane.
- Define how listener sockets are accepted and how connections are
  distributed across workers.
- Define the ownership model for upstream connection pools (per-worker vs
  shared).
- Define the configuration surface operators use to size the runtime.

#### Non-goals

- Graceful process-level upgrades (fd passing, dual-process cutovers).
- Custom per-worker schedulers.
- Alternative IO implementations (for example `io_uring`).

#### Prior art: Envoy

##### Runtime philosophy

Envoy uses one main thread and N worker threads. Each worker runs an
independent event loop. When a downstream connection is accepted it is
bound to a single worker for its entire lifetime, and all subsequent work
for that connection — filter chain processing, upstream pool lookups,
upstream connection establishment — happens on that same worker.

##### Type of threads

- Main Thread - a single thread that handles various coordination tasks.
  This includes configuration updates (xDS), stats flushing, and the
  administration interface.

- Worker Threads - a configurable number of threads (controlled by the
  `--concurrency` flag) that handle the actual listening and processing of
  traffic.

- File Flusher Thread - a dedicated thread for flushing access logs to disk
  to avoid blocking the main processing path.

The general recommendation from the documentation is that the number of
worker threads should be equal to the number of hardware threads on the
machine.

##### Handling a connection

A connection lives its whole life on the worker that accepted it.

1. The kernel hands the new TCP socket to one worker. With `reuse_port`
   each worker has its own listening socket and the kernel distributes
   accepts across them. Without it all workers race on a shared socket and
   the kernel still picks one. Either way, exactly one worker owns the
   connection from this point on.

2. The listener filter chain, and the HTTP codec state are instantiated
   locally. If the codec is HTTP/2 and the client multiplexes many streams
   over the connection, every stream is handled on the same worker.

3. When the router filter needs the current route table, it reads from the
   worker's Thread Local Storage. The main thread publishes xDS updates by
   posting a fresh snapshot into each worker's slot, so the worker only
   ever sees a coherent snapshot on the read path.

4. The router asks connection pool for an outbound connection. That pool
   is per-worker: idle connections held by other workers are not visible.
   If the local pool is empty the worker opens a new upstream TCP
   connection itself.

5. Bytes go downstream, through the filter chain, out to upstream, and
   back, without crossing a thread boundary. Access log writes are queued
   for the file flusher thread so the worker doesn't block on disk I/O.

From the request's point of view Envoy behaves like a single-threaded
proxy.

##### Connection draining

Drain is per-listener. It triggers on SIGTERM, or on a listener being
modified or removed via control plane update. The strategy is controlled by
`--drain-time-s` and `--drain-strategy` (`gradual` or `immediate`). During
drain the listener stops accepting new connections and existing ones are
closed: HTTP/1 responses get `Connection: close`, HTTP/2 sends `GOAWAY`.
Once the drain time elapses any still-open connections are forcibly closed.

##### Pros

- Simple per-worker ownership model — no mutexing on the hot path.
- Scales linearly when connections and upstream traffic are approximately
  uniform across workers.

##### Cons

- Per-worker pools decrease connection reuse.
- Heavy connection skew between workers is possible when one long-lived
  connection dominates (H2, gRPC, MCP use cases).

##### Sources

[Threading model doc](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/intro/threading_model)
[Threading model blog post](https://blog.envoyproxy.io/envoy-threading-model-a8d44b922310)

#### Prior art: Agent Gateway

##### Runtime philosophy

Agent Gateway runs two Tokio runtimes inside the same process. The control
plane is a `current_thread` runtime on the main OS thread. The data plane
is a `multi_thread`, work-stealing runtime hosted on a dedicated thread.

Connections are not pinned to a specific worker. The accept loop is one
Tokio task per bind, and each accepted connection is `tokio::spawn`ed as
its own future on the data-plane runtime, where work-stealing makes it
eligible to be polled by any worker.

##### Type of threads

- Main OS thread - hosts the control-plane `current_thread` runtime. Runs
  config ingestion (xDS), the admin and the metrics server and signal handling.

- Data-plane worker threads - N Tokio worker threads named agentgateway-(N-1)
  that run accept loops, TLS handshakes, the
  request pipeline, and upstream dials. The count is configured from
  `workerThreads`. Default is `num_cpus::get()`.

##### Handling a connection

A connection has no fixed home worker.

1. There is a per-bind accept task on the data-plane runtime.

2. The per-bind task owns the `tokio::net::TcpListener`. On accept it
   `tokio::spawn`s a per-connection future. From this point on the future
   is eligible for work-stealing and can resume on any worker between
   awaits.

3. TLS handshake and protocol decoding runs inline on the data-plane
   runtime via `tokio_rustls`.

4. When the request pipeline reads config (routes, backends, TLS secrets),
   it does so off of a shared `Store` structure. It minimizes
   synchronization by holding the lock for as little as possible and
   cloning the state it needs atomically. The worker then operates on a
   private snapshot; later control-plane writes do not race the in-flight
   request.

5. The router queries the shared upstream pool. The pool is process-wide
   and sharded. The worker locks one shard, pulls or creates a connection,
   and releases. Any worker can use any pooled connection.

6. Bytes flow downstream, through filters, out to upstream, and back. The
   future may resume on a different worker across awaits.

From the request's point of view there is no owning worker. Cross-worker
coordination is concentrated in two shared structures: the binds store and
the upstream pool.

##### Connection draining

Each long-lived component runs under `run_with_drain`, which on signal
stops accepting new connections, waits up to a configured deadline for
in-flight work to finish, then triggers a force-shutdown watch that tells
spawned tasks to terminate. At the protocol level this is the standard
Hyper drain: HTTP/1 responses go out with `Connection: close` and the
socket is closed after the in-flight response; HTTP/2 connections send
`GOAWAY` so no new streams are opened, and once the deadline expires any
still-open connections are forcibly dropped. Drain fires both on process
shutdown (SIGTERM) and on per-bind reconfiguration.

##### Pros

- Control and data plane are isolated by runtime, so config-loop work
  cannot starve request-serving work.
- A single shared upstream pool keeps idle connections usable by every
  worker, avoiding the per-worker pool pattern.
- Uneven distribution across workers is avoided due to work stealing.

##### Cons

- Work stealing is known to introduce bookkeeping overhead.
- Using a shared pool/state store efficiently adds implementation complexity.

##### Sources

[Data-plane runtime construction (`app.rs`)](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/app.rs)
[Sharded upstream pool (`pool/pool.rs`)](https://github.com/agentgateway/agentgateway/blob/main/crates/pool/src/pool.rs)
[Bind store (`store/binds.rs`)](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/store/binds.rs)
[Gateway accept loop (`proxy/gateway.rs`)](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/proxy/gateway.rs)

#### Prior Art: linkerd2-proxy

##### Runtime Philosophy

The proxy runs on tokio runtimes inside the same process. The main proxy
runtime chooses its flavor at startup from the resolved CPU budget. It
hosts the inbound and outbound data paths. A second runtime — a
`current_thread` one, running on a dedicated thread hosts the admin HTTP
server, the identity service (cert rotation) and the rest of the book
keeping.

The main difference between this model and the agent gateway one is that
control plane look ups such as endpoints updates and policy lookup happen
on the data plane runtime as part of the request/connection lifecycle. 

##### Type of threads: 

- Proxy threads - hosts the main proxy runtime. With `current_thread` (1
  core) the main thread is the runtime; all proxy work runs on it. With
  `multi_thread` (N cores) Tokio spawns N worker threads named `proxy` that
  run the work-stealing scheduler.

- Admin thread - a single thread running a separate `current_thread` Tokio
  runtime. Hosts the admin HTTP server (readiness, metrics export), the
  identity service that drives mTLS cert rotation against the control
  plane, the tap debug interface, and the trace collector.


##### Listeners are static

Unlike agent gateway, linkerd2-proxy does not reconfigure its listening
sockets at runtime. The set of bound ports (inbound, outbound, admin,
control) is fixed at startup from configuration; only the routing, policy
and endpoint state behind those ports changes via control plane updates.
There is no equivalent of the agent gateway or envoy's flow where a
control-plane update spawns a fresh per-bind accept task and shuts down an
old one.

##### Sizing the work stealing pool

The work stealing main pool is sized from the env-var precedence chain:
`LINKERD2_PROXY_CORES_MIN` (or legacy `LINKERD2_PROXY_CORES`) sets the
floor, `LINKERD2_PROXY_CORES_MAX` / `LINKERD2_PROXY_CORES_MAX_RATIO` cap
it. `num_cpus::get()` is used for the available count, which is
cgroup-aware. Default with no env vars set is 1 core.


##### Handling a connection

Inbound and outbound connections both run as tasks on the main proxy
runtime.

1. The `serve()` loop (one per direction) drives a stream of accepted
   connections. Each accepted socket is `tokio::spawn`ed as. There is no
   per-worker pinning; the work-stealing scheduler places the task on
   whichever worker is free.

2. The per-connection task runs through the Tower stack. Protocol detection
   peeks at the first bytes to decide between mTLS, plain HTTP, and opaque
   TCP. 

3. If the connection carries mTLS the handshake runs inline via
   `tokio_rustls`. The identity cert is read from a `tokio::sync::watch`
   channel; the writer side of that watch lives on the admin runtime.

4. For HTTP traffic the task builds or reuses a Tower service stack for the
   target. Connection reuse is managed by Hyper's built-in pool inside that
   service stack. There is no process-wide pool; each destination's pool
   lives inside its cached service entry.

5. Destination and policy resolution happen on the same runtime as the data
   path. The gRPC clients that talk to the linkerd control plane for
   DST/policy run as concurrent tasks on the main runtime, so a slow
   discovery response can compete for workers with in-flight requests.

6. For outbound mTLS the task dials the upstream peer and performs the
   client-side TLS handshake inline.

7. Bytes flow in both directions on the same task. On stream end the task
   drops the connection and any held service references.

##### Upstream connection caching

Reuse of upstream connections is built around Hyper's clients rather than a
single shared pool.

For each resolved destination the proxy caches a complete Tower service
stack keyed by the target. The cache is a per-entry. As long as a
destination keeps receiving traffic, the service stack — and the upstream
connections it owns sticks around.

Inside the cached stack sits a load balancer that holds one client service
per resolved endpoint and picks between them.

At the leaf each endpoint client is a Hyper client.

Two destinations that happen to resolve to overlapping endpoints do not
share idle connections — the pool is owned by the destination's service
stack, not by a process-wide registry. That is the main structural
difference from agent gateway's sharded global pool.

##### Connection draining

Drain is process-wide and only fires at shutdown — there are no per-bind
drains because listeners are static. SIGTERM/SIGINT (or an admin-initiated
shutdown via the mpsc returned from `Config::build`) triggers the drain
handle. The accept loop in `serve()` exits so no new connections are taken.
In-flight per-connection tasks are signalled to finish their current
request (HTTP/2 sends GOAWAY, HTTP/1 closes after the in-flight response).
The whole drain is bounded by `shutdown_grace_period`; when it expires the
runtime drops everything and exits.

##### Pros

- Identity (mTLS cert rotation) is isolated on its own runtime.
- Single proxy runtime for the data path is operationally simple
- cgroup-aware CPU detection fits Kubernetes pod sizing without extra
  configuration.

##### Cons

- Destination and policy gRPC traffic still run on the main runtime
- There is no global upstream pool; each destination's pool is isolated
  inside its service stack, which can lead to under-utilisation of
  connections across concurrent tasks.

##### Sources

- [Entrypoint
  (`main.rs`)](https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd2-proxy/src/main.rs)
- [App spawn / admin daemon thread
  (`linkerd/app/src/lib.rs`)](https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/app/src/lib.rs)
- [Accept loop
  (`linkerd/app/core/src/serve.rs`)](https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/app/core/src/serve.rs)


#### Proposed Approach

##### Runtime separation

The gateway runs two Tokio runtimes inside the same process. The admin one
is a `current_thread` runtime on the main OS thread. It hosts the control
plane update stream, the discovery task, signal handling, the admin and
metrics servers. For the data plane tasks, we use a work stealing pool.

##### Type of threads

- Main OS thread — hosts the control-plane `current_thread` runtime.

- Data-plane worker threads — N Tokio worker threads spawned by the
  data-plane runtime, sized from config. They run the work-stealing
  scheduler that polls the per-bind accept tasks and the per-connection
  futures (TLS handshakes, the request pipeline, and upstream origination).

##### Sizing the data-plane runtime

A single integer controls the size of the pool. It is read once at startup.
Further improvements of semantics can be considered at later stage.

##### Listener / bind model

Binds are dynamic. The gateway tracks active binds keyed by listen address
and reacts to a stream of bind events from the configuration store. An
add event allocates a `TcpListener` and a per-bind shutdown hook and
`tokio::spawn`s the bind's accept task on the data-plane runtime. A
remove event drains and tears down the bind. The bind set therefore
changes at runtime without restarting the process — the same shape as agent
gateway, and unlike linkerd2-proxy where the bind set is fixed at startup.

##### Handling a connection

A connection has no fixed home worker thread. Each connection is one
`tokio::spawn`ed future on the data-plane runtime, and the work-stealing
scheduler is free to resume it on whichever worker thread is available
between awaits. Cross-thread coordination is concentrated in two shared
structures: the configuration store and the upstream pool.

1. One task per bind on the data-plane runtime. It owns the bind's
   `TcpListener` and waits on either `socket.accept()` or its per-bind
   shutdown signal.

2. When `accept()` resolves, the accept task spawns a per-connection future
   carrying the socket and immediately loops back to `accept()`. From this
   point on the future is eligible for work-stealing across all data-plane
   worker threads; it can resume on a different worker between awaits. The
   accept task itself does no per-connection work, so a slow handshake or
   upstream dial cannot stall admission on this bind.

3. For an HTTPS bind the per-connection future's first await is the TLS
   handshake. The server advertises ALPN `["h2", "http/1.1"]`; the
   negotiated value (or its absence) constrains what wire protocol the
   client will transmit next. SNI is read off the resulting
   `ServerConnection` for listener selection. For an HTTP bind no
   handshake runs; the per-connection future works with the raw TCP
   stream.

4. When the future needs route, backend, or TLS-secret state, it reads from
   the shared configuration store. The store. The future holds the lock for
   as little as possible, clones what it needs atomically, and releases.
   From this point on the future operates on a snapshot — control-plane
   writes do not race the in-flight request. Subsequent requests on the
   same connection re-read the store, so route changes between requests on
   a long-lived connection are visible. If we experience any bottlenecks
   due to contention here, we can employ different strategies to reduce
   synchroniztion further at the expense of implementation complexity.

5. Host and path as well as other protocol specific concepts are matched
   against the snapshot to pick a listener/route and a backend; configured
   filters run inline on the future.

6. The future asks the process-wide upstream pool for a connection to the
   chosen endpoint. Any per-connection future on any worker thread can use
   any pooled connection.

7. Bytes move downstream → filters → upstream and back on the same future.

8. When the connection ends the future drops.

A TCP or TLS-passthrough connection follows the same shape: the accept task
spawns a per-connection future, which runs the protocol preamble (a
ClientHello peek for passthrough) and copies bytes between downstream and
upstream.

##### Upstream pooling

Upstream connections live in a single process-wide pool, shared across
every per-connection future. Idle connections opened to a backend are
reusable by another future on the next request, so reuse is not bounded by
which worker thread picked up the new connection.

Agent gateway does some extra optimizations here -  a sharded mutex pool
keyed by destination, where each shard locks briefly, hands out or creates
a connection, and releases. linkerd2-proxy sits at the other end — a
per-destination cached service stack with better isolation but worse reuse.

##### Connection draining

Drain is per-bind. On a bind being removed by the control plane, or on
process shutdown, the gateway:

1. Flips the per-bind shutdown signal. The accept loop exits and the
   listening socket is closed so no new connections are admitted on that
   bind.
2. Awaits the bind's in-flight counter reaching zero, bounded by a fixed
   10s timeout.
3. On timeout expiry the still-in-flight per-connection futures are
   dropped.

There will be no protocol level signaling at this point (no GOAWAY,
Connection: close, etc). Further down the line we can revisit that logic
and implement more sophisticated connection draining logic based on the
prior art that is relevant.

##### Pros

- Hard scheduler isolation between control and data work. This means,
  config propagation logic does not interfere with data plane one.
- No per-worker pinning of connections: work-stealing distributes load
  naturally, and a long-lived HTTP/2 connection cannot create a loaded
  worker because the future is rescheduled across awaits.
- Globally shared connection pool.

##### Cons

- As of right now there is no global or per listener admission cap. This
  means that overload manifests as latency and memory growth rather than
  visible rejection.
- Work-stealing carries some bookkeeping overhead relative to per-worker
  pinning.


##### V0 scope

- a control-plane `current_thread` Tokio runtime hosted on the main
  OS thread
- a data-plane `multi_thread` Tokio runtime hosted on a dedicated
  `std::thread`, with worker thread count from a single config
  integer
- one accept task per active bind, spawned and torn down on bind
  add / remove events
- TLS handshake (terminate) and ClientHello peek (passthrough) run
  on the spawned per-connection future, not the accept task
- HTTP version selection: hyper's `auto::Builder` performs HTTP/2 preface
  peek on the per-connection stream regardless of transport, selecting
  the H1 or H2 codec. On HTTPS the advertised ALPN list `["h2", "http/1.1"]`
  narrows what the client will transmit to that peek; the codec-selection
  mechanism itself is identical on `HTTP` and `HTTPS` listeners. Both
  HTTP/1.1 and HTTP/2 are accepted on both.
- not so graceful connection draining with a grace period.
- a single shared upstream connection pool

### 03. Traffic filtering

#### Problem statement

We need to define the filter interface the gateway exposes for traffic policy
enforcement and traffic mutation on the data path. This includes the shape
of a filter for different protocols. We need to determine what decisions
these filters are capable of mandating - short-circuiting, header
manupulation, etc. The interfaces for these filters need to be put in place
and later used for building conrete filter implementations as well as
serving as injection points for our extensibility mechanism.

#### Goals

- Define the filter interface at the TCP / TLS / HTTP layer.
- Define interface for streaming-body-aware filters, including how a filter
  accumulates context across frames without unbounded buffering.
- Define filter attachment points (i.e. listener vs  route).
- Solidify a shared interface shape so in-process and external (e.g. Wasm)
  filters are interchangeable behind the same hooks.
- Determine the chain execution semantics — request-side and response-side
  ordering, and the effect of a short-circuit on the rest of the chain

#### Non-Goals

- The v0 filter catalog itself.
- Concrete byte and time bounds for body-inspection limits.
- Wasm runtime selection.


#### Prior Art: Envoy

##### Overview

The essence of Envoy’s filtering philosophy is that proxy behavior with
respect to protocol is not hard-coded into listeners. Instead, behavior is
assembled by composing filters. Connection-level concerns such as TLS
handling and TCP proxying belong in the
listener/filter-chain/network-filter path. Request-level concerns such as
authentication, authorization, rate limiting, header mutation, body
inspection and routing belong in the HTTP connection manager’s filter chain
with the http connection manager being a filter of its own.

##### Filter execution pipeline

From the perspective of an incoming HTTPs connection the filtering pipeline
looks like: 

- 1. the listener accepts the connection and inspects the connection
     metadata
- 2. based on that metadata a filter chain is selected. This filter chain
     dictates how traffic is handled. For example for an HTTPs connection a
     filter chain may be selected based on SNI
- 3. the filter chain itself contains details that determine whether for
     example TLS is termianted and what certs are used.
- 4. after TLS is termianted envoy runs the network filters in the chain.
     These filters can be `http_connection_manager`, `tcp_proxy`,
     `mysql_proxy`. For HTTPs connectionsns the important filter usually is
     `http_connection_manager`
- 5. envoy now executes the http connection manager filter. This is a
     filter that understands the HTTP protocol and can parse it and process
     it. It can be further extended with additional HTTP specific filters
     such as `envoy.filters.http.jwt_authn`, `envoy.filters.http.cors`,
     etc. The majority of the functionality of these filters is centered
     around http-ish things - header mutation, body inspection, etc. One
     particular filter is the http router one which applies the routing
     that envoy hs been configured with to determine wich backend this
     request should be sent to.

##### Handling Streaming bodies

Envoy’s HTTP filter API is streaming-first. Request and response bodies are
delivered incrementally through `decodeData(...)` and `encodeData(...)`
calls. as opposed to a "full body arrived" event.

At each body callback, the filter chooses one of the `FilterDataStatus`.

- `Continue` passes the current body chunk onward.
- `StopIterationAndBuffer` pauses iteration and asks Envoy to buffer body
  data for later dispatch.
- `StopIterationAndWatermark` also pauses and buffers, but is meant for
  cases where incoming data flow should stop until the filter resumes
  (applying backpressure).
- `StopIterationNoBuffer` pauses iteration without asking Envoy to retain
  the body data. This is the path for filters that want to manage buffering
  and replay themselves.

By default buffering itself is implemented inside Envoy’s HTTP filter
manager rather than by each filter individually.

The main safety guardrail is the stream buffer limit. When a body must be
buffered and exceeds the configured limit, Envoy returns `413` on the
request path. On the response path, exceeding the limit results in a `500`
or a reset if headers have already been sent. 

A clear hypothetical example of using this model is a filter that is
decoding an MCP payload carried in the HTTP body. In that case a filter
should return StopIterationAndBuffer. Envody buffers subsequent chunks for
that filter. Once enough data is vaiable the filter parses it and decides
to either call continueDecoding() to resume the filter chain or return a
local synthesized resposne in order to interrupt the filter chain
processing

##### Pros

- Real filter-chain model at both network and HTTP layers.
- Strong streaming-body contract: `Continue`, `StopIterationAndBuffer`,
  `StopIterationAndWatermark`, and `StopIterationNoBuffer` give filters
  precise control over buffering and backpressure.
- Clearly defined filtering contract can be reused in extensability
  mechanism (e.g. Wasm, extProc)

##### Cons

- Buffering semantics are complex - understanding of resume contract and
  buffer limits is needed.
- The mental model of everything being a filter is a bit hard to grasp
  initially.

##### Sources
- [HTTP filter architecture overview](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/http_filters)
- [Listener filters overview](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/listeners/listener_filters)
- [Network filters overview](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/listeners/network_filters)
- [Wasm HTTP filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/wasm_filter)
- [HTTP Filter interface](https://github.com/envoyproxy/envoy/blob/main/envoy/http/filter.h)
- [Network filter interface](https://github.com/envoyproxy/envoy/blob/main/envoy/network/filter.h)
- [MCP filter overview](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/mcp_filter)


#### Prior Art: Pingora

##### Overview

Pingora uses a trait-based lifecycle rather than a chain of independently
configured filters. The main HTTP surface is the `ProxyHttp` trait, and one
implementation of that trait owns request, upstream selection, response,
and body handling for the service. Note that Pingora is a library as
opposed to an actual end product. A side effect of that is that there is no
notion of filter chaining. You are essentially given one `ProxyHttp` impl
to work with. If you want to do filter chaining, you need to design some
abstractions yourself.

##### Filter execution pipeline

From the perspective of an incoming HTTPS connection the filtering pipeline
looks like:
- 1. the connection enters the transport layer through
     `ServerApp::process_new`. If the optional `ConnectionFilter` feature
     is enabled, `should_accept` can reject by peer address or other
     metadata before the HTTP service proceeds.
- 2. once the request is in the HTTP proxy path, Pingora creates
     per-request state with `new_ctx()` and starts calling `ProxyHttp`
     hooks on that request.
- 3. the earliest request hook is `early_request_filter` followed by
     `request_filter`, which is where access control and short-circuit
     responses can happen.
- 4. if the request is going upstream, Pingora continues through
     `proxy_upstream_filter`, `upstream_peer` for peer selection before
     writing headers upstream.
- 5. as the upstream response comes back, Pingora runs
     `upstream_response_filter`.
- 6. body handling happens through the dedicated body hooks
     `request_body_filter` and `upstream_response_body_filter`.

##### Handling Streaming bodies

Pingora's body surface is explicitly chunked. `request_body_filter`,
`upstream_response_body_filter`, and `response_body_filter` all receive
`Option<Bytes>` plus `end_of_stream` bool. That means a filter sees one
chunk at a time, can replace it with different `Bytes`, or can set the
option to `None` to drop that chunk from the stream.

Short-circuiting with a local response does not happen through a
body-filter return code; that is done with `Session` helpers such as
`respond_error`.

By default buffering is pushed to the filter implementor. `ProxyHttp` does
not define an Envoy-style "buffer and resume" primitive, nor a built-in
buffer limit, or filter-specific timeout for body accumulation. If a filter
wants to see the entire body before deciding, it has to append chunks into
its contextand decide for itself how much to retain. The absence of these
controls are due to the fact that Pingora is a library providing the
primitives to build a final product that contains all of these safeguards.

A an example of decoding an MCP payload carried in the HTTP request body
would look like this. On each `request_body_filter` call it would take the
current `Bytes`, append them into a local and set `*body = None` so the
partial chunk is not forwarded upstream yet. While `end_of_stream` is
`false` it returns `Ok(())` and waits for more chunks. On the final call,
when `end_of_stream` is `true`, it parses the accumulated payload. If
parsing succeeds it can replace the current chunk with a reconstructed
`Bytes` value and return `Ok(())` so the upstream sees the final payload.
If parsing fails or we need or we need to respond with some error
indicating policy conflict, it can use `Session::respond_error_with_body`
to emit a local error response and stop treating the request. The important
point is that the buffer, the size limit, and the failure policy all live
in the `ProxyHttp` implementation, not in an overarching level above.

As observed, the filtering interface is quite low level as it is meant
for building higher level abstractions.

##### Pros

- Very simple mental model - one `ProxyHttp` implementation owns the while
  lifecycle.
- Body filtering is easy because hooks receive `&mut Option<Bytes>` plus
  `end_of_stream`.
- Easy to build product-specific logic without fitting it into a
  framework-owned chain abstraction.

##### Cons

- No framework-level filter composition model: ordering, reuse, and scoping
  are all up to the implementor
- No built-in buffering contract for body filters.

##### Sources
- [Filter usage guidelines](https://github.com/cloudflare/pingora/blob/main/docs/user_guide/phase.md#general-filter-usage-guidelines)
- [Examples](https://github.com/cloudflare/pingora/tree/main/pingora-proxy/examples)
- [the `ProxyHttp` trait](https://github.com/cloudflare/pingora/blob/main/pingora-proxy/src/proxy_trait.rs)
- [`Session` helpers and proxy lifecycle](https://github.com/cloudflare/pingora/blob/main/pingora-proxy/src/lib.rs)
- [the `ConnectionFilter` trait](https://github.com/cloudflare/pingora/blob/main/pingora-core/src/listeners/connection_filter.rs)

#### Prior Art: Agent Gateway

##### Overview

Agent Gateway does not expose a generic filter trait. Instead of filters,
the gateway is designed around policies Each policy is its own typed struct
that does not implement a common trait. These are applied through [direct
calls](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/proxy/httpproxy.rs#L121)
an not in a order that is goverened by any kind of precedence that is
configurable.

##### Types of policies

The gateway defines four types of policies that have different scope and
attachement points and hence take effect durring different points of the
request lifecycle.

- FrontendPolices — listener/gateway-attached policies that apply per
  gateway/listener. Focuses on protocol specific settings (e.g. min TLS
  version)
- GatewayPolicies — listener-attached HTTP behavior policies that apply to
  every route under a specific lsitener that listener. Used when an auth or
  transformation rule must hit all requests on the listene regardless of
  match results.
- RoutePolicies — route-attached protocol behavior policies. Superset of
  GatewayPolicies plus everything that only makes sense once a specific
  route has been picked: authorization, request_header_modifier,
  request_redirect, etc.
- BackendPolicies — backend-attached behavior policies, applied just before
  the upstream is contacted: backend_tls originagion, backend_auth, etc.
  These describe how the gateway talks to the specific backend chosen

##### Pros
- Execution order is centralized in a few functions, so real behavior is
  easy to trace in code.

##### Cons

- There is no general filter trait or reusable filter-chain abstraction -
  adding new behavior is a source change across enums, aggregation, and
  execution code.
- Body inspection is not a first-class per-chunk concept. Much of it feel
  bolted on to a specific use case (e.g. MCP body parsing)

##### Sources

- [Policy invocation for HTTP](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/proxy/httpproxy.rs#L121)
- [`typed filter structs (`HeaderModifier`, `RequestRedirect`, `DirectResponse`)](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/http/filters.rs)
- [`apply_gateway_policies`, `apply_request_policies`, `apply_backend_policies`](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/proxy/httpproxy.rs)

#### Proposed Approach

##### Overview

The filter system has four primitives.

- A `TcpFilter` runs once per accepted connection and decides whether to
  admit it. A second trait, `TlsRouteFilter`, runs after a TLS-passthrough
  connection's ClientHello has been parsed and matched to a route, and
  decides whether to forward. There is no explicit body processing at this
  layer (for now).
- An `HttpFilter` is constructed per request and runs four hooks across the
  request lifecycle: request headers, request body chunks (opt-in), end of
  request body (opt-in), and response headers.
- A `LocalHttpResponse` is the short-circuit response any HTTP hook can
  return in place of forwarding.
- A pre-forward gate buffers the request body when at least one filter on
  the matched route asks to inspect it, bounded in bytes and time so an
  indecisive filter cannot stall the connection or grow memory.

##### TCP / TLS layer

The TCP/TLS layer has two lifecycle points where a filter can run, each
exposed as its own trait.

```rust
trait TcpFilter {
    async fn on_accept(&self, ctx: &TcpFilterContext)
        -> Result<TcpFilterDecision>;
}

trait TlsRouteFilter {
    async fn on_route_matched(&self, ctx: &TlsRouteFilterContext)
        -> Result<TcpFilterDecision>;
}

enum TcpFilterDecision { Allow, Deny }
```

`TcpFilter::on_accept` runs against the freshly-accepted connection before
TLS termination or any peek. `TcpFilterContext` carries `listener_name`,
`peer_addr` as wel as other relevant meta. It us used for connection-level
decisions.

`TlsRouteFilter::on_route_matched` runs only on TLS-passthrough
connections, after the ClientHello has been peeked and the SNI matched to a
route. `TlsRouteFilterContext` adds `sni: String` and `route_name: String`
to the context. Used for decisions that depend on which route was selected:
SNI based allow/deny lists, route-scoped logging, etc. The filter is shared
across every connection that matches the route it is attached to.

The actions across both filters `Allow` / `Deny`. There is no synthesized
responses. At this point the gateway does not have L7 knowledge.

##### HTTP layer

An HTTP filter is constructed per request. The instance has three hooks
across the request lifecycle: request headers, request body chunk (opt-in),
and response headers.

```rust
trait HttpFilterFactory {
    fn request_body_mode(&self) -> HttpRequestBodyMode {
        HttpRequestBodyMode::PassThrough
    }
    fn new_instance(&self) -> Box<dyn HttpFilter + Send>;
}

trait HttpFilter {
    async fn on_request_headers(
        &mut self,
        parts: &mut http::request::Parts,
        ctx: &HttpFilterContext,
    ) -> Result<HttpRequestAction>;

    async fn on_request_body_chunk(
        &mut self,
        chunk: &mut Option<Bytes>,
        held: &BodyBufferView,
        end_stream: bool,
        ctx: &HttpFilterContext,
    ) -> Result<HttpRequestBodyAction>;

    async fn on_response_headers(
        &mut self,
        parts: &mut http::response::Parts,
        ctx: &HttpFilterContext,
    ) -> Result<()>;
}

enum HttpRequestAction {
    Continue,
    Respond(LocalHttpResponse),
}

enum HttpRequestBodyMode {
    PassThrough,    // default — body hooks not invoked
    GateDecision,   // body hooks invoked, pre-forward gate engaged
}

enum HttpRequestBodyAction {
    Hold,
    Continue,
    Respond(LocalHttpResponse),
}
```

`on_request_headers` runs first. It returns `Continue` or
`Respond(LocalHttpResponse)` (short-circuit with a synthesized response).
`on_response_headers` runs on the way back and is mutation-only.

Body inspection per filter is opt-in, declared at the factory via
`request_body_mode`. If every factory on the matched route is
`PassThrough`, request bodies stream straight to the upstream — there is no
per-frame hop into a filter and no buffering.

When at least one factory on the route is `GateDecision`, the gateway runs
the pre-forward gate. The gate calls into `on_request_body_chunk` per chunk
and withholds the request from the upstream until the gate opens. The chunk
argument is `&mut Option<Bytes>` — the same shape Pingora's body filter
uses. Mutating the `Bytes` transforms the chunk. Setting `*chunk = None`
drops it from the stream.

The `held` argument is a borrowed view over the gate buffer — every chunk
this filter has previously held, in order. The framework owns the buffer
and the filter reads from it without taking ownership. This is how a filter
that needs the full body to decide accumulates context without growing its
own copy. The filter returns `Hold` on each chunk and inspects the
cumulative bytes through `held` on the next call.

The possible actions for a body hook are:

- `Continue` — the gate opens for this filter. If every gating filter on
  the route returned `Continue`, the buffered chunks are released to the
  upstream and subsequent chunks stream through unbuffered. It is important
  to note that once a filter returns `Continue` the body hook for this
  filter instance will not be invoked again.
- `Hold` — the gate stays closed for this filter. The current chunk (in
  whatever state the filter left it) is appended to the gate buffer and the
  gate waits for the next chunk.
- `Respond(LocalHttpResponse)` — short-circuit; the synthesized response
  flows through every filter's `on_response_headers` in reverse chain
  order.

##### Filter execution guardrails

When designing a generic filter interface, we need to make sure that
filters are safe to run in the context of the gateway. Namely, we want to
make sure that we guard against the following cases:

- crashing the gateway
- cosuming unbounded resources (e.g. memory)
- execution taking unbounded amount of time and thereby introducing traffic
  latency

for that reason we need to adopt the folloinwg mechanisms and restrictions.

##### Filter failure mode

A filter can fail by returning `Err` or  timing out. Each filter declares a
`failure_mode`:

- `FailClosed` (default) — failure rejects the request with a 5xx
  synthesized response. The safe default for security-critical filters
  (e.g. authorization)
- `FailOpen` — failure skips the filter as if it had returned `Continue`.
  Used for filters where this  is acceptable (e.g observability, access
  logging, etc).

This is the same shape Envoy's ext_authz, ext_proc, and Wasm filters expose
(`failure_mode_allow`). If a filter panics, we always resort to FailClosed


###### Upper threshold for buffer cap

When the pre-forward gate is engaged, the gateway buffers held chunks until
every gating filter on the route has returned `Continue`. The buffer is
bounded in bytes by a configurable `gate_buffer_max_bytes`. Exceeding the
cap fails the request closed with `413 Payload Too Large`.

###### Gate decision timeout

Independent of bytes, the gate runs under a time budged. The gateway starts
a timer on the first chunk and fails closed with `504 Gateway Timeout` if
the gate has not opened by the deadline.

###### Per-hook execution timeout

Hooks are `async fn`, so a filter that awaits an external service that has
gone away would otherwise stall the per-connection future indefinitely.
Each hook invocation runs under a configurable per-hook timeout. On expiry
the framework drops the in-flight hook future and treats the outcome per
the filter's failure mode.

ext_proc's `message_timeout` is the precedent: every external-call filter
(ext_authz, ext_proc, Wasm callouts) has its own deadline rather than
relying on the request-level timeout. We adopt the same shape — every hook
call has a deadline.

###### Pros

- Streaming-first body interface.
- `request_body_mode` opt-in so data path is not changed for filters that
  do not care for the body
- clera bounds on filter execution semantics
- clear order is predictable - declaration order on request, reverse on
  response

###### Cons

- The pre-forward gate adds head-of-line latency on routes where any filter
  declares `GateDecision`

###### V0 scope

- TCP/TLS-layer filters at two lifecycle points: at connection accept, and
  after SNI-routed route selection for TLS-passthrough.
- HTTP-layer filters with hooks for request headers, request body, and
  response headers. Body inspection is opt-in per filter.
- A pre-forward gate that buffers held chunks until every gating filter on
  the matched route releases, bounded in bytes and time, both fail-closed.
- Async filter execution on the per-connection future.
- Per-hook execution timeout and per-filter failure mode.

### 04. Route and backend selection

#### Problem statement

Given an inbound connection, the gateway must decide which `Route` applies
and which `BackendRef` is selected from that route. We need to be clear
about the logic itself -  how matches are evaluated per protocol how
precedence is resolved when more than one route matches and how a backend
ref is picked when a route has more than one.

#### Goals

- Define match evaluation per protocol: SNI for TLS passthrough,
  SNI plus host/path/headers/method for HTTPS, etc
- Define the precedence rule when multiple routes match the same
  request/connection.
- Define the algorithm for picking one `BackendRef` from a route's set.
- determine the decision granularity per protocol (i.e. per request for
  HTTP and per connection for TLS)

#### Non-goals

- Full Gateway API integration in v0.

#### Prior Art: Agent Gateway

##### Overview

The main idea of agent gateway is that it has a view of all the routes
attached to a listener and matching is done per request/connection by
following the logic of:

- first pick a `Listener` for the bind, usually from SNI or request host
- then match a `Route` from a the set of routes for this listener
- then choose a backend from that route's backend list,
- then let backend-specific logic refine the final upstream target.

##### Picking a listener

The bind protocol chooses the way listerner selection is performed.

- Plaintext HTTP selects a listener by Host -  the gateway reads the
  request authority/Host value and selects among HTTP listeners attached to
  the bind.
- TLS traffic selects a listener by SNI - the gateway reads the ClientHello
  and selects among TLS listeners using SNI. TLS listeners include HTTPS
  listeners and TLS passthrough listeners. In this situation the listener
  decides termination behaviour. If the selected listener is HTTPs, TLS is
  terminated. If the listener that is selected is TLS Passthrough, then the
  stream is passed as is, following the usual TCP semantics.
- A raw TCP bind is valid only when there is a single listener attached to
  it.
- A bind with protocol set to auto  can support plaintext HTTP and
  TLS-family listeners on one port because it chooses the HTTP or TLS path
  per connection before listener selection.

##### Picking a route

Once a a listener has been selected, the gateway is ready to pick a route.
This follows the usual Gateway API semantice:

- route lookup uses the request authority/Host value. Routes with matching
  hostnames are considered first. Hostname matching prefers exact
  hostnames, then wildcard hostnames, then routes with no hostnames as
  catch-all routes.
- after hostname filtering, each candidate route rule is checked against
  the request path, method, headers, and query parameters. A rule must
  satisfy all of its configured match conditions to remain a candidate.
- the most specific rule wins - exact path matches beat prefix matches,
  longer prefixes beat shorter prefixes, method-specific matches beat
  methodless matches, and rules with more header or query matches beat
  broader rules

##### Picking a backend

Picking a backend in the presence of multiple backends in random with
wights applied.

##### Sources

- [protocol specific dispatch on `BindProtocol](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/proxy/gateway.rs#L393)
- [SNI read](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/proxy/gateway.rs#L862)
- [`BindProtocol` / `ListenerProtocol` enums](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/types/agent.rs#L520)
- [per-request route matcher](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/http/route.rs#L106)
- [weighted random backend pick over `route.backends`](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/proxy/httpproxy.rs#L48)


#### Proposed Approach

##### Listener selection

A `Bind` carries multiple `Listeners`. We split the protocol into two
fields, matching the Agent Gateway model:

- BindProtocol — one per bind. One of `HTTP`, `TLS`, `TCP`. Decides the
  dispatch path: whether to buffer a ClientHello, read HTTP requests, treat
  the socket as raw TCP.
- ListenerProtocol — one per listener. One of `HTTP`, `HTTPS`, `TLS`,
  `TCP`. Decides per-listener behavior -  TLS cert material, termination vs
  passthrough, which pipeline runs.

The bind's dispatch path selects which match function runs. The match
function filters listeners by their listener protocol:

1. Read the bind's `BindProtocol`.
2. Derive the hostname input: `TLS` reads SNI from the ClientHello; `HTTP`
   reads `:authority`/`Host`; `TCP` reads nothing and requires the bind to
   carry exactly one listener
3. Filter the bind's listeners by `ListenerProtocol`. A TLS dispatch keeps
   `HTTPS` and `TLS` listeners while an HTTP dispatch keeps `HTTP`
   listeners.
4. Match the hostname against the filtered set: exact hostname first, then
   longest suffix, then any empty-hostname listener as catch-all.
5. Lifetime of the match is set by `BindProtocol` - `TLS` fixes the
   listener for the whole connection; `HTTP` re-runs the match on every
   request, so a connection may switch listeners per request.

##### Route selectuon

Once the listener is selected, the gateway picks one route from that
listener's route set. Routes are bucketed by hostname witch each hostname
bucket holds a list Route objects kept in descending precedence order at
insertion time.

Per-request match:

- Hostname — exact, wildcard `*.example.com`, or empty (hostname-agnostic).
- HTTP path — `Exact`, `PathPrefix`, or `Regex`.
- Method — single case-sensitive byte string.
- Headers — exact or regex per header. All declared headers must match.
- Query parameters — exact or regex per key. All declared keys must match.
  Duplicate keys collapse; only one value is checked.
- For L4 (TLS passthrough / opaque TCP), hostname is the only routing key.

##### Backend selection

Once a route is selected, the gateway picks one `BackendRef`: 

- Each `BackendRef` carries a non-negative integer weight.
- Selection is weighted random over the list.

##### Pros

- Splitting bind and listener protocol makes explicit what kind of traffic
  the socket is serving.
- Tha matching semantics are aligned with Gateway API logic

##### Cons

- Trying to preorder route matching on insertion time can get complicated
  quickly.
- Since Bind protocol is not a GatewayAPI concept, it is the control
  plane's job to group listeneres per protocol.

### 05. Endpoint picking and inventory

#### Problem statement

Area 04 stops at "one `BackendRef` is fixed; a `Backend` is resolved." A
`Backend` is the addressable target - a Kubernetes service, a static
upstream set, an MCP target, an inference pool. It is not yet one concrete
IP:port the gateway can dial. This area covers the step that turns a chosen
`Backend` into one `Endpoint` per request or connection, the inventory the
endpoints come from, the per-endpoint runtime state the picker scores
against, the failure model, and the extension seam for protocol- and
AI-specific picker variants.

#### Goals

- Define the inventory sources the model supports and which one ships in
  v0.
- Define one default endpoint picker that covers any multi-endpoint backend
  regardless of transport.
- Define per-endpoint runtime state and where it lives relative to the
  config store.
- Define the dial-failure model: passive eviction with TTL, no request-time
  re-pick.
- Define the extension seam so future picker variants (MCP session
  affinity, model-aware / inference selection) plug in without changing
  core types.

#### Non-goals

- Dynamic endpoint discovery. The discovery interface is named in the model
  but no concrete discoverer ships in v0.
- The wire protocol by which an external picker talks to the gateway. That
  belongs to a later inference-extension area.
- Active health checking. V0 uses passive dial-failure ejection only.
- Upstream connection pooling, upstream TLS, upstream auth. These live in
  the backend-origination area, after an endpoint is chosen.

#### Prior Art: Agent Gateway

##### Overview

In Agent Gateway, endpoint picking is the backend's job, not the route's.
The route picks a backend by weighted random. The backend then carries its
own endpoint set and its own selection logic. What that logic does depends
on the backend kind. A Kubernetes service runs P2C over a locality-bucketed
endpoint set. An opaque target has no pool and gets dialed directly. An MCP
backend terminates the session at the gateway and binds it to an upstream
through a session map held by the MCP handler. An inference-pool backend
calls out to an external endpoint picker before each request.

##### Backend kinds and endpoint inventory

Agent Gateway has several backend kinds. Where the endpoint list comes from
depends on the kind:

- Services get their endpoints from Kubernetes workload discovery over xDS.
  The list lives on the service object.
- Opaque targets carry a single address inline in config. No pool, no
  refresh.
- MCP and A2A backends carry a list of MCP targets. Each target resolves to
  a downstream backend (usually a service).
- Inference pools are modelled as a synthetic service. Endpoints come from
  xDS like any other service; what differs is a policy attachment that
  overrides selection through an external callout.

##### Endpoint storage at runtime

The list of endpoints per service is broken into priority buckets ranked by
locality. Bucket zero holds the most-local endpoints; bucket one the
next-most local; and so on. Inside each bucket the endpoints are kept in
two sets — currently usable and currently rejected — with a sampler
attached.

##### Per-protocol picker variants

###### HTTP / gRPC service backends — load-balanced picking with locality bucketing

The picker walks the locality ladder, picks the most-local non-empty
bucket, and runs P2C inside it. Two endpoints are sampled at random,
scored, and the better one wins. The score is roughly health divided by a
penalty that combines recent dial latency and outstanding request count. If
no bucket has a usable endpoint, a deterministic fallback scan visits
buckets in locality order and returns the best it can find.

###### TCP backends — weighted random at the route layer

A TCP route picks one backend by weighted random. This is selection between
backends, not between endpoints — the same operation HTTP routes do for
backend selection. Once the chosen backend is resolved, picking proceeds
normally: a service backend runs the same locality-bucketed P2C path as
HTTP; an opaque target gets dialed straight.

###### MCP backends — session-terminating proxy with handler-level stickiness

The gateway terminates the MCP session itself. The client's long-lived
stream (SSE or streamable HTTP) ends at the gateway, not at an upstream MCP
server. From the client's view the gateway is the MCP server. The session
ID the gateway hands back to the client is its own; the upstream's session
ID is held internally, mapped from the client-facing one.

Two modes:

- **Passthrough** (one MCP target): the session maps 1:1 to that upstream.
  Every request in the session goes to the same endpoint.
- **Federation** (multiple MCP targets): one client-facing session composes
  several per-upstream sub-sessions opened at session creation. The
  persisted session ID encodes which target hosts each sub-session. Tool
  calls are routed by name — a `service.tool` prefix splits, and the
  service component picks the upstream.

In both modes the session-to-upstream binding is sticky. The picker doesn't
run for in-session requests; the MCP handler holds its own session →
upstream map and bypasses the picker. The picker only runs at session
creation, when a new session needs an upstream chosen.

###### InferencePool — external endpoint picker

Inference-pool backends share the regular service endpoint set, but
selection runs through an external callout. Before each request, an
inference-routing policy on the backend opens an ext_proc stream to an
endpoint-picker service and forwards the request. The response
carries a destination header (`x-gateway-destination-endpoint`) with the
endpoint's address.

That address gets fed into the regular endpoint-selection path as an
override. The override skips scoring: the picker scans the endpoint set for
a matching address and returns it. The scan covers both the usable and
rejected sets, so an endpoint marked unhealthy by passive dial-failure
tracking still gets dialed if the external picker returns it. The
assumption is that the external picker has better information than the
gateway's connect-failure signals.

###### Decision granularity per protocol

HTTP picks per request. The proxy invokes the picker on every request,
including each HTTP/2 stream on a single client connection (Hyper hands
each stream to the request pipeline as its own request). Two requests on
the same downstream connection can land on different upstream endpoints.

TCP picks once per accepted connection. The picker runs in the accept
handler and the chosen endpoint serves the connection for its lifetime. If
the resolved backend is a service, the TCP path runs the same picker as
HTTP — both go through `build_service_call`. Opaque targets get dialed
straight.

MCP picks once per session, at session creation. After that the handler
holds the binding (per-tool for federation) and the picker isn't consulted
for the session's lifetime.

| Signal | HTTP (per request) | TCP (per connection) |
| --- | --- | --- |
| In-flight counter | concurrent requests | concurrent open TCP connections |
| Latency EWMA | full request roundtrip | forward duration |
| Health / eviction | request outcomes | connection outcomes |

The in-flight handle lives in the request log and drops when the log drops
(at response body completion, not at response headers), so it measures
in-flight work, not in-flight dials. And the latency EWMA is full request
roundtrip — HTTP upstream connections are pooled per endpoint, and every
completed request still updates the EWMA. The picker scores service
latency, not connect latency.

##### Health and eviction

EWMA-smoothed health, EWMA-smoothed latency, and pending counts feed the
P2C score. Crossing a consecutive-failure threshold moves the endpoint from
`active` to `rejected`; the eviction worker schedules uneviction after a
configurable duration and may restore partial health rather than restarting
from zero.

##### Sources

- [`Backend` enum](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/types/agent.rs#L1039)
- [`EndpointGroup<T>`](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/types/loadbalancer.rs#L100)
- [`EndpointSet<T>`](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/types/loadbalancer.rs#L192)
- [`select_endpoint`](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/types/loadbalancer.rs#L237)
- [`select_p2c`](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/types/loadbalancer.rs#L294)
- [`LocalityRanker`](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/types/loadbalancer.rs#L378)
- [eviction worker](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/types/loadbalancer.rs#L499)
- [`EndpointInfo`](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/types/loadbalancer.rs#L576)
- [P2C scoring](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/types/loadbalancer.rs#L610)
- [`select_tcp_backend`](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/proxy/tcpproxy.rs#L411)
- [MCP `SessionManager`](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/mcp/session.rs#L282)
- [`InferencePoolRouter`](https://github.com/agentgateway/agentgateway/blob/main/crates/agentgateway/src/http/ext_proc.rs#L143)

#### Prior Art: linkerd2-proxy

##### Overview

Linkerd doesn't have Agent Gateway's per-backend-kind divergence. Each
route backend has one of three dispatch variants: balance over an endpoint
set, forward to a fixed address, or fail. The same three variants apply to
HTTP, gRPC, and opaque TCP.

##### Inventory: a streaming destination channel

Endpoint inventory comes from the control plane's destination service over
gRPC. The proxy opens a long-lived stream per destination and the control
plane keeps it open, pushing updates as endpoints come and go. No polling.
Updates arrive as one of four event types: add, remove, full reset, or
"does not exist." Per-endpoint metadata travels with the address: labels,
weight, optional mTLS identity, a protocol hint, optional authority
overrides, HTTP/2 parameters, and a zone-locality flag.

##### Endpoint storage: a per-destination service stack

There's no process-wide endpoint registry. Each destination has its own
service stack — the discovery stream, the balancer it feeds, and the
per-endpoint services the balancer picks from. A destination-keyed cache
keeps these stacks alive. As long as traffic keeps coming, the stack stays
up; when the last consumer drops and the idle timeout elapses the stack
tears down. Two distinct destinations that resolve to overlapping endpoints
don't share connections.

##### Picker dispatch: balance, forward, or fail

Each route backend gets one of three dispatch variants. HTTP and opaque TCP
use the same three:

- **Balance** opens a destination stream and runs the load balancer. The
  multi-endpoint path.
- **Forward** dials one fixed address with attached metadata. No balancer.
- **Fail** returns a service that rejects every request with a configured
  error - mostly used for policy enforcement.

##### Load metric: peak-EWMA round-trip time (changing)

Today the balancer scores endpoints by recent peak-EWMA RTT. P2C: sample
two endpoints at random, pick the one with the lower load score. RTT is the
only signal the picker reads. Pending-request counts are tracked by a
separate queue layer for back-pressure but don't feed into picking.

This is changing. The current metric has a known limitation: a failing
endpoint that returns fast errors (HTTP 503s, gRPC UNAVAILABLE) looks fast
to peak-EWMA, so P2C keeps sending it traffic.
[linkerd/linkerd2-proxy#4537](https://github.com/linkerd/linkerd2-proxy/pull/4537)
lands the building blocks for a failure-aware replacement:

- a new `linkerd-ewma` crate with non-mutating time-projected reads that
  tracks RTT and a penalty dimension
- a `retry_after` parser for HTTP `Retry-After` (RFC 7231) and gRPC
  `grpc-retry-pushback-ms` (gRPC A6),
- a `linkerd-load-biaser` Tower service wrapper that injects a temporary
  penalty on HTTP 429/503/5xx and gRPC RESOURCE_EXHAUSTED/UNAVAILABLE
  responses, amplified when a Retry-After hint is present.

The new load metric is `max(rtt * (pending + 1), penalty)`. Pending count
folds back into the picker's signal, and explicit failure responses become
first-class quality input. When all endpoints are healthy the metric
reduces to the same behaviour as PeakEwma.

##### Decision granularity

Each pick is one service call on the balancer. Tower's service model lets
the surrounding stack decide what one "call" means, so the same balancer
plugs into different protocol pipelines with different cadences:

- HTTP — per request - Hyper drives one `Service::call` per request on
  both HTTP/1.1 and HTTP/2.A long-lived downstream H2 connection carrying
  ten requests across ten streams produces ten balancer picks.
- Opaque TCP — per accepted connection. The router calls into the inner
  service once per accepted TCP connection. After the dial, the byte stream
  is bound to the chosen endpoint for the connection's lifetime.

The per-destination cache keeps the whole stack alive across picks. For
HTTP that's many request picks against the same destination. For opaque TCP
that's many connections to the same destination, each producing a fresh
upstream dial but reusing the cached balancer state. Either way, the picker
keeps its memory: RTT averages, gate state, failure counts. What changes
between cadences is just the unit of work each measurement describes.

##### Sources

- [`Resolve<S>`](https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/proxy/api-resolve/src/resolve.rs#L14)
- [`Update<T>`](https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/proxy/core/src/resolve.rs#L30)
- [`Metadata`](https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/proxy/api-resolve/src/metadata.rs)
- [`IdleCache`](https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/idle-cache/src/lib.rs#L24)
- [HTTP `Dispatch`](https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/app/outbound/src/http/concrete.rs#L32)
- [Opaque `Dispatch`](https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/app/outbound/src/opaq/concrete.rs#L33)
- [`P2cPool`](https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/pool/p2c/src/lib.rs#L28)
- [`PeakEwma` import](https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/proxy/balance/src/lib.rs#L16)
- [`ConsecutiveFailures`](https://github.com/linkerd/linkerd2-proxy/blob/main/linkerd/app/outbound/src/http/breaker/consecutive_failures.rs#L5)
- [PR 4537 — failure-aware P2C building blocks](https://github.com/linkerd/linkerd2-proxy/pull/4537)
