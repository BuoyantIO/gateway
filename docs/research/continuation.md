# Beating agentgateway — state and continuation notes

Written 2026-07-13. Everything needed to pick this effort back up.

## Where things live

| what | where |
|---|---|
| research + measured cost model | `docs/research/beating-agentgateway.md` (this branch) |
| probe scoreboard (latest) | `docs/research/scoreboard-probe.md` (this branch) |
| CP/DP micro-benchmarks | `crates/gateway-cp/tests/probe_scale_cost.rs`, `crates/gateway-state/tests/dp_apply_cost.rs` (this branch) |
| phase 1a — event filter | **merged to main** (#55) |
| phase 2a — DP incremental apply | branch `zd/dp-incremental-apply`, commit `05d5965`, awaiting PR/review |
| phase 2b — CP incremental route path | branch `zd/cp-world-cache` (stacked on main + 2a), commit `e3e3c3d`, awaiting PR/review |
| benchmark runner | separate repo `~/dev/gateway-bench` (local-only git) |
| bench runbook (manual steps) | `docs/bench-runbook.md` (uncommitted working tree) |
| kgateway source for comparison | `/tmp/kgateway-tag` at tag `v2.2.0-alpha.1` |

## Measured results (probe, fresh cluster per run, agentgateway as control)

| run | buoyant mean | agw mean | CP CPU (b/a) | CP mem (b/a) | notes |
|---|---|---|---|---|---|
| main @1500 | 246ms (ramping) | 111ms | 0.71 / 0.06 | 129 / 87 MiB | pinned core |
| 1a @1500 | 88ms (sloping) | 110ms | 0.29 / 0.08 | 136 / 89 MiB | crossover ~route 1400 |
| 2a-only @1500 | 157ms | 113ms | ~main | ~main | DP CPU 0.029 (3.5x win), DP mem 10 MiB |
| 1a+2a+2b @3000 | **41ms flat** | 112ms | **0.038 / 0.113** | **84 / 127 MiB** | errors=0; DP CPU 0.196 (lose), DP mem 41.7 vs 24.5 (lose) |
| 2b simplified @500 | 11.5ms (excl. route-0) | 115ms | — | — | confirms no regression |

Full PDFs in `~/dev/gateway-bench/bench-report-*.pdf`; per-run artifacts
(logs, panels) in `~/dev/gateway-bench/runs/<stamp>/`.

## The design that landed (2b, simplified)

`crates/gateway-cp/src/world.rs`. Core invariant: **everything that is
not a route only changes via a full pass, so between full passes the
world is frozen** — a route's old output is recomputable from its old
spec instead of remembered. Hot path per route event:

1. resolve + translate just the route (scoped), before the swap;
2. swap the route into the owned state, resolve + translate again;
3. `diff()` old vs new per gateway = the delta; `ServerState::
   apply_delta` mutates the stored world in place and broadcasts.

Carried state: only `attachedRoutes` counters and per-backend
refcounts (both underivable from one route, both rebuilt on every
full pass). A randomized test (`incremental_matches_full_recompute`)
applies ~400 route changes and asserts, after each one, that the
shortcut equals a full recompute; it caught deliberate sabotage at
steps 3 and 7 when we mutation-tested it.

History worth remembering: the first 2b used contribution ledgers
(remember-what-you-emitted). The rewrite to recompute-and-diff
deleted ~180 lines and two concepts with zero measured cost. The
enabler for the fearless rewrite was the equivalence test.

## Maintenance contracts (things that will bite if forgotten)

- **Event filter (1a, merged)**: skips Gateway/HTTPRoute/GatewayClass
  events whose (generation, annotations-for-Gateways) fingerprint is
  unchanged. If a pass ever starts reading a NEW metadata field from
  those kinds (labels, deletionTimestamp/finalizers), the fingerprint
  in `watch.rs` must grow with it.
- **Frozen-world invariant (2b)**: anything that makes route
  resolution depend on a new resource kind (namespace labels for
  allowedRoutes, ReferenceGrant) must either trigger full passes for
  that kind's events (easy: it already does — only routes take the
  hot path) or be added to the scoped path deliberately.
- **The hot path skips infra recompute** (routes can't affect
  desired infra). If that ever changes, `watch.rs` Action::Route must
  stop skipping it.

## kgateway comparison (why our shape differs, with pointers)

Their equivalents, all in `/tmp/kgateway-tag`:
- per-route memoized translation: krt collection,
  `pkg/agentgateway/translator/route_collections.go:39-71` (they split
  one resource per rule per match).
- removals without ledgers: resource names derive from route identity
  alone (attachment is content, not name); deletes detected by lookup
  failure, `internal/kgateway/agentgatewaysyncer/krtxds/xds.go:1105-1157`.
- attachedRoutes: recount over an indexed fetch, no counters,
  `syncer.go:125-152` + `route_collections.go:563-590`.
- their flat ~105ms probe latency is `PILOT_DEBOUNCE_AFTER` (100ms
  default, env-tunable) in the pilot-derived syncer, not compute.

Conclusion reached: don't build a krt-like framework for this repo
(one hot dependency edge doesn't amortize framework costs; a Rust
mini-krt converges on salsa). Revisit only when the dependency graph
becomes a web (ReferenceGrant + allowedRoutes selectors + policy
attachment); then evaluate salsa vs. hand-rolled indexes in the
architecture doc.

## Remaining queue, in suggested order

1. **PR + merge 2a then 2b** (both verified: unit, equivalence test,
   e2e 15/15, benchmarks above).
2. **Issue #46 — eviction fail-open** (filed): the 30s single-endpoint
   lockout puts ~5,000 errors and a 31s max on route 0 of every
   fresh-cluster probe. Small fix, biggest cosmetic win.
3. **Phase 3 — DP at scale** (both probe reds live here):
   - request matching is a linear scan (`gateway-runtime/src/proxy/
     http.rs`, `pick_http_route`) → DP CPU 0.196 vs 0.069 at 3000;
     fix: hostname-indexed, specificity-sorted lookup (agentgateway's
     RouteSet shape, `store/binds.rs` + `types/agent.rs` in their repo).
   - DP memory 41.7 vs 24.5 MiB at 3000: one stored entry per rule
     (2x their count on the bench shape) + allocator high-water;
     levers: entry compaction, jemalloc-with-decay.
4. **Phase 1b — drain-the-queue coalescing** (bounds delete storms;
   less urgent now that passes are cheap).
5. **Bench queue #6 (EndpointSlice)** — prerequisite for real
   failover behavior; then the backendfailover test becomes winnable.
6. **listenerset support (#12)** to enter that benchmark at all.

## Benchmark tooling notes

- `uv run benchrunner plans/<plan>.yaml` in `~/dev/gateway-bench`;
  always provisions a fresh cluster from `gateway_repo`'s current
  checkout (that's how A/B works: check out the branch, run).
  `--skip-setup` reuses a live cluster for fast iteration.
- Methodology that made results trustworthy: fresh cluster per run,
  agentgateway as unchanged control (its numbers matched within 2%
  across every run), exact-window panel rendering, probe summaries
  parsed from harness stdout (panel legends cap at 1000 samples).
- Known runner nits: two same-named tests in one plan overwrite each
  other's logs/panels; probe adapter could pre-warm the backend
  (`kubectl rollout status deploy/backend`) to remove the route-0
  cold-start artifact from the error column.
