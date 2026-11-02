# Architecture

The gateway serves the traffic that Kubernetes Gateway API resources
describe. The control plane, gateway-cp, watches `Gateway`, `HTTPRoute`
and the resources that they reference, decides once what each one means,
and publishes one snapshot per `Gateway` to the data planes over a
streaming gRPC channel. For each `Gateway` that it owns, the control
plane also provisions one gatewayd Deployment and its Service. The data
plane, gatewayd, applies the snapshot into an in-memory Store, accepts
connections on each bind, matches each request to a listener and a
route, runs the route's filters as extensions, picks a destination and
proxies the request. Nothing in the data plane reads Kubernetes. The
control-plane replicas elect one of themselves to write status and to
provision data planes; every replica serves data planes.

This page is the map: where code lives, which way imports go, what must
stay true, and where new code goes. Change it in the same pull request as
any move. To follow one request step by step, read
[docs/request-lifecycle.md](docs/request-lifecycle.md).

## Vocabulary

- Bind: one listening socket, an address and port with a protocol.
  gatewayd runs one accept task per active bind.
- Listener: one protocol entry under a bind, with its hostname and its
  TLS settings. A Gateway API listener translates to one listener.
- Route: the match rules, filters and backend refs that an `HTTPRoute`
  attaches to a listener.
- Backend: a destination that a backend ref names. It is either an
  endpoint set that the request path balances over or a dialable host
  that gatewayd resolves and dials itself.
- Endpoint: one address in an endpoint set, read from `EndpointSlice`s.
- Pending and active: the Store's two partitions. An entity is active
  when every precondition holds, and the request path reads only active
  entities.
- Outcome: the accept or reject decision that `resolve` records for
  each element. Status is built from outcomes.
- Snapshot: the per-Gateway collection of proto upserts that the
  translator emits. The world is the map of every Gateway's last
  published snapshot.
- `ConfigUpdate`: one batched message of upserts and removes, the diff
  of two snapshots. A bootstrap carries `sync_complete = true`.
- Client id: the `{namespace}/{name}` of the `Gateway` that a data plane
  serves, sent in `Hello`.
- Extension: per-request filter code behind the `Extension` trait. A
  core filter and an `Extension` custom resource both resolve to one. A
  class configures a builder once per route revision, and the builder
  creates one instance per request.
- Selector: the one instance on a rule that declares `selects_targets`
  and picks the destination, such as the kinference selector.
- Drain: the shutdown signal, with a barrier that completes only when
  every `Watch` clone has dropped.
- Leader: the one replica that writes status and provisions data
  planes. Every replica translates and serves data planes.

## Entry points

- `crates/gatewayd/src/main.rs`. The data-plane binary. It builds the
  Store, the registry and the drain, connects the control-plane client
  or loads a YAML config, registers the extension classes and runs
  `Gateway::run`.
- `crates/gateway-cp/src/main.rs`. The control-plane binary. It spawns
  the admin server, the elector, the writers and the watch loop, and
  serves gRPC until a signal arrives.
- `watch::run`, in `crates/gateway-cp/src/watch.rs`. One pass per
  relevant event: resolve, translate, publish, status, infra.
- `Gateway::run`, in `crates/gateway-runtime/src/gateway.rs`. One accept
  task per active bind, driven by the Store's `BindEvent`s.
- `crates/gateway-cp-proto/proto/`, the wire contract between the two
  binaries.
- `e2e/tests/e2e/main.rs`, the end-to-end suite.

## Code map

Each concern has one crate. Each crate's `lib.rs` lists its modules and
what they own; this map stays at the crate level.

### `gateway-config`, in `crates/gateway-config`

The typed config model, YAML parsing and per-object validation.

**Invariant.** No async, no I/O. Matches are compiled when the config is
deserialized, never per request.

### `gateway-state`, in `crates/gateway-state`

The Store: the in-memory runtime config that the request path reads. It
takes per-entity upserts and removes, stashes objects whose references
have not arrived, and promotes them when the dependencies land.

**Invariants.** Every entity is in exactly one of `pending_*` or
`active_*`, so the request path never sees a partially applied config.
Read the comment above `Inner` before changing the apply logic.

### `gateway-drain`, in `crates/gateway-drain`

The shutdown primitive that both binaries use.

**Invariant.** `Signal::drain` completes only when every `Watch` and
`ReleaseShutdown` clone has dropped. Dropping a `Signal` fires its
watchers.

### `gateway-cp-proto`, in `crates/gateway-cp-proto`

The tonic and prost types for the `gateway.controlplane.v1` package.

**Invariant.** Generated code only. The one place where a blanket lint
`allow` is acceptable.

### `gateway-extension`, in `crates/gateway-extension`

The `Extension` and `ExtensionBuilder` traits, `Declarations`, the
`Registry` of classes and the per-request `Cx`.

**Invariants.** Request hooks run in filter order and may gate; response
hooks run in reverse and only observe. A new capability is a field on
`Declarations`, not a trait method. No network client.

### `gateway-extension-impls`, in `crates/gateway-extension-impls`

The Gateway API core filters on the `Extension` trait, and the
kinference selector.

**Invariant.** A core filter parses its config once, at builder
construction, so its hooks are infallible.

### `gateway-runtime`, in `crates/gateway-runtime`

The request path: accept loops, TLS termination, the HTTP proxy with its
body handling and extension driving, TLS origination, the load balancer
and the metric schema.

**Invariants.** Route resolution copies what it needs out of the Store
under a read lock and drops the lock. The picker takes pre-built
candidates and returns a choice. Metric labels are config-derived names,
never raw request attributes.

### `gateway-cp-client`, in `crates/gateway-cp-client`

The data-plane side of the config stream: reconnect, convert proto to
native types, apply into the Store.

**Invariant.** `convert` and `apply` are pure and fail closed on missing
or invalid input, so a translator bug surfaces at the data plane.

### `gateway-cp`, in `crates/gateway-cp`

The Kubernetes control plane: the reflectors and the pass, `resolve`, the
translator, the diff, the gRPC server, the status and infra writers,
leader election and the CRD types.

**Invariants.** `resolve` makes every decision exactly once; the
translator only maps. Status and infra writes go through `watch`
channels, so they never block config publication. Only the leader
writes. This is the one crate that depends on `kube`.

### `gatewayd`, in `crates/gatewayd`

The data-plane binary: flags, the subscriber, the admin server and the
registration of the extension classes.

**Invariant.** The two binaries are the only crates that read flags or
the environment, only at startup, and the only crates that use `anyhow`.

### `e2e`, in `e2e`

The end-to-end harness and its test backends: `echo`, `grpc_echo` and
`openai_mock`.

**Invariant.** Every test is `#[ignore]`d; `just test-e2e` runs them.

### Import direction

- `gateway-config`, `gateway-drain` and `gateway-cp-proto` import
  nothing of ours.
- `gateway-state` imports `gateway-config`.
- `gateway-extension` imports `gateway-config` and `gateway-state`.
- `gateway-extension-impls` imports `gateway-config` and
  `gateway-extension`.
- `gateway-runtime` imports `gateway-config`, `gateway-state`,
  `gateway-drain` and `gateway-extension`.
- `gateway-cp-client` imports `gateway-config`, `gateway-state` and
  `gateway-cp-proto`.
- `gateway-cp` imports `gateway-config`, `gateway-state`,
  `gateway-drain` and `gateway-cp-proto`, never the runtime.
- `gatewayd` imports all of the data-plane crates.

`kube` stays in `gateway-cp`. `hyper` and `rustls` stay in the runtime
and the admin servers. Decision logic takes data and returns data.

## Cross-cutting concerns

### Configuration

gatewayd takes `--config`, a YAML file, or `--control-plane` with
`--client-id`. gateway-cp takes flags, which the chart renders from its
values. Each binary reads flags and the environment once, in `main`.

### Errors

Each library crate has its own hand-written error enum. The two binaries
use `anyhow`, to add context before they exit.

### Metrics

gatewayd owns the one Prometheus registry, under the `gateway_` prefix,
and the admin server renders it. The schema in `metrics.rs` fixes the
label policy. The control plane exposes no metrics.

### Locking

The Store is one `RwLock`, read briefly and dropped before any await.
The control-plane server publishes through one broadcast channel per
Gateway. The writers sit behind `watch` channels and never hold up the
pass.

### Shutdown and leadership

Each binary has one drain channel. A signal fires it, the admin server
goes unready, in-flight work finishes under a grace deadline, and the
admin server drains last. gateway-cp elects a leader over a Lease; the
leader writes status and provisions data planes, and routing never waits
on leadership.

### Observability

Both binaries log through `tracing`, filtered by `RUST_LOG`. The
`gateway.buoyant.io/dp-log-filter` annotation on a `Gateway` sets the
filter of its provisioned data plane. The access log writes one line per
request.

### Testing

Unit tests sit inline in the module that they cover. The `e2e` crate runs
the real binaries on a kind cluster; `docs/local-development.md` says how
to bring it up.

## Where new code goes

- A new Gateway API field. `resolve` decides and records the outcome,
  the translator maps it, `convert` parses it, the Store holds it and
  the runtime reads it.
- A new proto field. Add it to the proto; the translator emits it and
  `convert` parses it. No logic in either.
- A new extension. Implement the traits in `gateway-extension-impls` and
  register the class in `gatewayd`'s `main`. A new capability is a field
  on `Declarations`.
- A new metric. Add the family to the schema in `metrics.rs`, with
  config-derived labels only, and record it where the event happens.
- A new flag. Add it to the binary's clap `Args` and pass it through the
  chart template. Give it a type, not a raw string.
- A new custom resource. Put the type in `crd.rs`, add a reflector in
  `watch`, decide it in `resolve`, and ship the schema in the
  `gateway-crds` chart.
- Anything that talks to the apiserver. Put it in `gateway-cp`, behind a
  writer that a `watch` channel feeds and that checks leadership.

## Rules for a move

- Behaviour stays the same. Tests, clippy and fmt stay green after every
  commit.
- One structural change per commit. Move, test, commit. Rename, test,
  commit.
- No constructor takes more than six arguments. Group the handles in a
  struct that `main` builds once.
- Add a trait only where two implementations exist.
- A module's `//!` header says what the module owns and the one rule that
  a caller must respect. The crate's `lib.rs` lists its modules, one line
  each.
