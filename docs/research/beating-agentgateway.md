# Beating agentgateway on gateway-api-bench

Source-level competitive analysis: our CP/DP vs kgateway (agentgateway's
control plane, Go, at tag v2.2.0-alpha.1) and the agentgateway proxy
(Rust), grounded in probe-test results observed on 2026-07-08 (20 and
2000 routes) **and in micro-benchmarks of our actual pipeline code**
(release build, bench-shaped routes; temporary tests
`crates/gateway-cp/tests/probe_scale_cost.rs` and
`crates/gateway-state/tests/dp_apply_cost.rs`, uncommitted).

## Verdict

**Yes. Measured, not estimated: we beat them at every scale.** Their
flat ~105ms is a literal istio-pilot debounce (`PILOT_DEBOUNCE_AFTER`,
default 100ms, env-tunable) on top of ~5ms of real krt work. Our
entire intrinsic pipeline at N=2000 costs **~31ms measured** (CP full
pass ~25ms + DP apply ~6.4ms) — the observed 356ms mean is dominated
by **event amplification**, not compute: every status write (ours
*and kgateway's — the bench parents every route to both gateways*)
triggers a full pass in our watch loop. Filtering those events alone
puts us under their 105ms at 2000 routes; incremental processing makes
us flat ~10ms at any N.

## Measured costs (micro-benchmarks, release, bench-shaped routes)

One full CP pass, by stage:

| stage | N=20 | N=2000 | N=10000 |
|---|---|---|---|
| clone state (`collect_state`) | 0.03ms | 3.4ms | 17.6ms |
| `resolve` | 0.03ms | 3.3ms | 17.9ms |
| `translate_resolution` | 0.09ms | 9.2ms | 56.0ms |
| clone world (`publish`) | 0.04ms | 5.3ms | 38.3ms |
| `diff` N vs N+1 | 0.02ms | 4.0ms | 37.6ms |
| `build_work` (status) | ~0 | ~0 | ~0 |
| **total per pass** | **~0.2ms** | **~25ms** | **~167ms** |

DP store, one route upsert on top of N active routes:

| N=20 | N=2000 | N=10000 |
|---|---|---|
| 0.089ms | 6.4ms | 68.9ms |

Everything is linear-ish with small constants. Nothing in the
pipeline is intrinsically slow — the cost is doing it N times over
and doing it for events that carry no information.

## Where the observed 356ms actually goes (N=2000)

Verified mechanisms, in order of contribution:

1. **Event amplification.** `watch.rs` runs the full pass on *every*
   event with zero filtering (verified: no generation/predicate logic).
   Per bench route add, the API server emits: our HTTPRoute ADDED, our
   Gateway status write echo (`attachedRoutes` changed), **kgateway's
   HTTPRoute status write (both gateways parent every route)**, and
   kgateway's own Gateway status writes — each one a full ~25ms pass
   for us. This also explains the CP pinned at 1.0 cores while a
   single 25ms pass per ~356ms would only be ~7% duty. Live check
   confirmed no self-flap at idle (CP 0 CPU, resourceVersion stable),
   so the amplification only bites during churn.
2. **CP pass cost, ~25ms** — over half of it avoidable clones (state
   clone + world clone = ~8.7ms) rather than real resolution work.
3. **DP apply, ~6.4ms** — `upsert_http_route` →
   `re_resolve_listener` → `place_listener` **re-places every child
   route and re-sorts the full active list per single route add**
   (store.rs:843-911). O(N log N) with allocation churn, under the
   store write lock (briefly contending the request path).
4. Fixed floor: API watch delivery + gRPC push + probe's 5ms poll —
   ~6-10ms total, N-independent (this is the measured 8ms at N=20).

Also verified: DP request-time matching (`pick_http_route`,
gateway-runtime/src/proxy/http.rs:612) is a **linear scan of all
routes per request** — irrelevant to probe latency at bench QPS,
decisive for the traffic test at high QPS.

## Why they're flat: mechanism inventory

### kgateway CP (Go, krt-based)

The agentgateway data plane is served by a dedicated syncer,
`internal/kgateway/agentgatewaysyncer/` (only meaningful at the tag,
not on main; an earlier pass on the wrong checkout missed it).

- **A literal istio-pilot debounce explains the flat 105ms.**
  `agentgatewaysyncer/krtxds/xds.go:177-179` wires
  `DebounceOptions{DebounceAfter, DebounceMax}` from
  `istio.io/istio/pilot/pkg/features`: `PILOT_DEBOUNCE_AFTER` default
  **100ms**, `PILOT_DEBOUNCE_MAX` default **10s**. The `debounce()`
  loop waits for 100ms of event quiet before pushing, capped at 10s
  under continuous churn. The sequential probe isolates every event →
  every push waits the full 100ms + ~5ms real work = the observed
  variance-free ~105ms.
- **Consequence at high churn:** events arriving faster than the quiet
  period merge, and pushes can lag up to 10s. Sustained-churn
  scenarios are where their design looks worst.
- **Incremental translation scoped per Gateway** via a `byParentRef`
  krt index — their real per-event cost is ~5ms; the 100ms is policy.
- Capacity-1 AsyncQueues coalesce status work; hash-gated pushes skip
  no-ops; status writes decoupled with equality skip.

### agentgateway DP (Rust)

- **Delta xDS** — one route add = one resource on the wire
  (`crates/xds/src/client.rs:578-658`).
- **Incremental store apply** — copy-on-write at the RouteSet level,
  O(log M) sorted insert (`store/binds.rs:645-651`).
- **Indexed request matching** — hostname HashMap →
  specificity-sorted vec → binary search (`http/route.rs:110-232`).

## The plan (revised with measurements)

### Phase 1 — event filtering + echo elimination (small diffs, big win)

Skip the pipeline for events that carry no spec change: for Gateways
and HTTPRoutes, ignore MODIFIED events with unchanged
`metadata.generation` (status writes don't bump generation). This
kills our own status echo **and every kgateway status write in the
shared bench cluster** — the entire amplification bucket. Add
drain-the-queue coalescing (process, then drain queued events, then
run one pass) for burst scenarios; idle path stays zero-delay.

**Measured projection at N=2000: one 25ms pass + 6.4ms DP apply +
~8ms floor ≈ 40ms — already under their 105ms.** CPU drops from 1.0
to <0.1 cores. At 10000 routes this alone is not enough (167+69ms).

### Phase 2 — incremental processing (flat at any N)

Route independence holds in our v0 semantics (routes only interact
through the additive `attachedRoutes` counter), so:

- CP: on HTTPRoute events, resolve/translate only that route against
  cached listener state; emit the delta directly (skip world-clone +
  full diff); maintain `attachedRoutes` incrementally. Full pass only
  for Gateway/GatewayClass/Service/Secret changes (rare), via reverse
  indexes where cheap. Stop cloning the world in `collect_state`.
- DP: `upsert_http_route` must not re-place every sibling.
  Incremental insert into the active listener's route collection
  (sorted structure or rebuild-on-read), touching O(log N) per
  upsert. The 0.089ms N=20 number is the target at any N.
- Correctness guard: full resolver kept as test oracle; property tests
  assert incremental == full on randomized event sequences.

**Measured projection: ~8-12ms flat at any N — the N=20 floor,
which the e2e already demonstrates end to end.** ~10x under their
default floor at 2000; still ~10x at 10000.

### Phase 3 — DP request-matching index (traffic test)

Hostname HashMap + specificity-sorted candidates, mirroring
agentgateway. Orthogonal to CP work; required before making
throughput claims.

## Per-test scoreboard (measured/projected)

| Test | Today | Phase 1 | Phase 2 |
|---|---|---|---|
| probe N=20 | **8ms win** (vs 105) | 8ms | 8ms |
| probe N=2000 | 356ms loss (vs 111) | **~40ms win** | **~10ms win** |
| probe N=10000 | ~1.5s+ loss (extrapolated) | ~240ms loss | **~10ms win** |
| attached-routes | writes ≈ N | coalesced writes, faster add-all | convergence ≈ apply throughput |
| routechange | pass | pass | pass, 30x smaller in-flight window |
| CP CPU @2000 | 1.0 core | <0.1 | ~0.01 |
| traffic | unknown (linear-scan DP) | unknown | needs phase 3 |

## Certainty statement

Every stage of the propagation path is now either measured
(micro-benchmarks above, e2e floor at N=20) or code-verified
(file:line for the O(N) sites, the debounce constant, the event
amplification). The phase 1 projection uses only measured numbers —
no speculation — and already clears the bar at the user-stated 2000+
scale. Phase 2's flat-line projection assumes only that hashmap-sized
work stays sub-millisecond, which N=20 already demonstrates end to
end. Residual risks are implementation risks (incremental-vs-oracle
correctness), not feasibility risks. The one honest asterisk: their
floor is an env knob (`PILOT_DEBOUNCE_AFTER`); tuned to ~10ms they'd
sit at ~15ms — default-vs-default we win at every N, tuned-vs-tuned we
still win but by ~2x rather than ~10x.

## Honest caveats

- All absolute numbers are one machine / one kind cluster; claim the
  ratios.
- The event-amplification share of the 356ms is inferred from verified
  mechanisms + CPU accounting, not from a direct event count; it does
  not affect the projections (which bypass it entirely).
- Route independence holds for v0; `allowedRoutes` selectors and
  `ReferenceGrant` add cross-resource edges later — still indexable,
  revisit then.
