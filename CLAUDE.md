# Agent contract for the `gateway` repo

## Single source of truth

`docs/ARCHITECTURE.md` is canonical for every design decision. Do not
infer scope, naming, or relationships from any other document, comment,
or memory. If the master doc is silent on something, ask the user — do
not invent.

## How the repo grows

- Cargo workspace at the root.
- One crate per area, named `gateway-<area>` under `crates/`.
- Do not create empty placeholder crates for areas not yet started.
- The workspace `members` list grows by exactly one entry per area start.
- A `bin/gatewayd` and a `tests/e2e/` directory appear only once at least
  two areas exist and wiring them together is meaningful.

## Implementation order

Areas are tackled in the order they appear in the master doc's TOC. For
each area, finish the **full v0 scope** (the area's `V0 scope`
subsection in `docs/ARCHITECTURE.md`) before starting the next area.

## Style and quality gates

- `cargo fmt` — committed code must be formatted.
- `cargo clippy -- -D warnings` — no warnings.
- `cargo test` — green before declaring an area v0-complete.
- Edition: `2024`. Toolchain pinned via `rust-toolchain.toml`.

## What not to do

- Don't exceed the v0 scope of the current area. v0 is intentionally
  narrow.
- Don't pre-design for stubbed areas (05–07). The master doc lists them
  but does not yet define their shape.
- Don't introduce cross-area abstractions until at least two areas
  exist — early abstractions tend to be wrong.
- Don't add features, fallbacks, or validation beyond what the master
  doc requires.
- do not add references in the code that target the architecture file