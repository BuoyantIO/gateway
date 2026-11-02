# Architecture

## Crate graph

Dependencies point in one direction, `gateway-config` and
`gateway-state` at the bottom, the two binaries at the top:

- `gateway-config` — typed config model, YAML parsing, per-object
  validation. No async, no I/O.
- `gateway-state` — `Store`: the in-memory runtime config the request
  path reads. Accepts per-entity upserts/removes and broadcasts
  `BindEvent`s.
- `gateway-drain` — the drain primitive both binaries shut down
  with: a watch channel for "start draining" plus a drop-counted
  mpsc barrier over an uninhabited type.
- `gateway-runtime` — the data-plane request path: accept loops, TLS
  termination, routing, extensions, load balancing, metrics.
- `gateway-cp-proto` — tonic/prost types for
  `gateway.controlplane.v1` (`crates/gateway-cp-proto/proto/`).
- `gateway-cp-client` — DP side of the stream: reconnecting gRPC
  loop, proto to native conversion, apply into the `Store`.
- `gateway-cp` — the Kubernetes controller and gRPC server.
- `gatewayd`, `gateway-cp` — the two binaries.
- `e2e` — harness plus the `echo`/`grpc_echo` test backends.

## Config path (CP to DP)

`watch.rs` runs one kube reflector per watched kind and drives one
pass per relevant event. A pass is `resolve` then `translate` then `publish` then
status then infra:

- `resolve.rs` makes every accept/reject decision exactly once
  (ownership, listener classification, route attachment, backend and
  certificateRef resolution) and records an outcome per element.
  Classification logic belongs here, nowhere else.
- `translator.rs` maps the resolved graph onto per-Gateway
  `Snapshot`s of proto upserts. It only maps; it never re-decides.
- `status/` builds Gateway API status from the same outcomes;
  `infra/` computes the desired gatewayd `Deployment`/`Service`/
  `ServiceAccount`. Both split pure (`build`, `desired`) from writer,
  and both reach the apiserver through `watch` channels so status
  writes can never block config publication.
- `server.rs` holds the last published world plus a broadcast channel
  per Gateway. `diff.rs` turns snapshot pairs into one batched
  `ConfigUpdate`. A connecting DP subscribes *before* reading the
  world so a concurrent publish arrives as a delta instead of being
  lost, then gets a bootstrap batch with `sync_complete = true`.
- `lease.rs` is leader election: one replica writes status and
  reconciles infra, every replica translates and serves DPs.

## The Store's promotion model

`gateway-state/src/store.rs` is a strict partition: every known
entity is in exactly one of `pending_*` or `active_*`, and it is
active only when its preconditions hold (a route needs its bind and
listener registered; a listener needs at least one active route).
Objects arriving out of order are stashed and re-evaluated when their
dependencies land, so the request path never observes a partially
applied config. Read the comment block above `Inner` before changing
apply logic. `Store::retain` is how a resync drops keys the CP no
longer sends.

## Request path

`docs/request-lifecycle.md` is the canonical description of one
request from accepted socket to end of response, including every
error status and metric reason. Read it before touching
`crates/gateway-runtime/src/proxy/`; keep it updated when behavior
there changes. In short: `Gateway` runs one accept task per active
bind, hyper's `auto::Builder` picks H1 or H2 by peeking the preface,
routing snapshots what it needs from the `Store` under a read lock
and drops it, and the P2C-EWMA picker in `lb/` chooses an endpoint
using per-endpoint state (in-flight count, latency EWMA, passive
eviction) that outlives the request.

## Extensions

Everything that touches a request, including the Gateway API core
filters, is an `Extension` (`gateway-runtime/src/extension/`). One
`ExtensionBuilder` per plugin lives in the `Registry`; one instance
per filter per request. A builder returns `Declarations`
(`request_body`, `response`, `selects_targets`), copied into the
`Member` at instantiation, and those declarations pick the host's
machinery before any hook runs: which body tier is used, whether the
response gets wrapped, whether the terminal hook is delivered. Add a
new declaration as a field on `Declarations`, not as another trait
method. Request hooks run in filter order and may gate the request;
response hooks run in reverse and only observe. At most one member
per rule may declare `selects_targets`.
