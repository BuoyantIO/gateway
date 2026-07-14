# Probe benchmark scoreboard — 2026-07-13

Phases 1a (event filter, merged) + 2a (DP incremental apply) +
2b (CP WorldCache) stacked. probe at 3000 routes, fresh cluster,
agentgateway as unchanged control.

| column | buoyant | agentgateway | verdict |
|---|---|---|---|
| propagation mean | **41 ms** (flat) | 112 ms (flat) | **win 2.7x** |
| errors | **0** | 0 | par |
| CP CPU mean/max | **0.038 / 0.126** | 0.113 / 0.305 | **win 3x** |
| CP memory max | **84 MiB** | 127 MiB | **win 1.5x** |
| DP memory | 41.7 MiB max | 24.5 MiB | **lose at 3000** |
| DP CPU | 0.196 mean, ramps to 0.476 | 0.069 | **lose at 3000** |

Both red columns are DP-side scale effects:

- DP CPU: request matching scans all N routes per request, so CPU
  grows with route count under the probe's continuous polling — the
  phase-3 item (hostname-indexed matching). At ≤1500 routes the 2a
  run measured us below agentgateway; the crossover is between 1500
  and 3000.
- DP memory: at 1500 routes (2a run) we were below them (~10 vs
  ~13 MiB); at 3000 we're 1.7x above. Two contributors: the CP emits
  one DP route entry per rule (the bench route has two rules → 6,000
  stored entries at 3,000 routes, roughly twice their count), and
  ~22 MiB of allocator high-water carried over from the preceding
  1500-route section of the same run (fresh-cluster-per-test would
  isolate the true footprint). Compaction of per-rule entries and/or
  jemalloc-with-decay are the levers.

Reports: bench-report-probe-2b-20260713-150427.pdf (this run),
bench-report-probe1500-{main,dp}-*.pdf (baselines) in
~/dev/gateway-bench.

Benchrunner note: two same-named tests in one plan overwrite each
other's logs/panels (first probe section shows the second's charts) —
small tool fix pending.
