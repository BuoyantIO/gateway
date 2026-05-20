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

## Rust file organization

Top-to-bottom order within a `.rs` file (matching `tokio`'s style):

1. **Module-level doc comment** (`//!`) — what this module is, for any
   non-trivial file. Skip on small helper files.
2. **`use` statements**, grouped with blank lines between groups, in this
   order:
   - `std::` imports.
   - External-crate imports (`tokio::`, `serde::`, `parking_lot::`, …).
   - Internal imports (`crate::`, `super::`).
   Imports are alphabetical within each group. `rustfmt` handles
   alphabetization but does not reorder between groups — keep the order
   manually.
3. **`mod` / `pub mod` declarations.**
4. **`pub use` re-exports.**
5. **`const` / `static`** definitions.
6. **Public types first, principal type at the top.** When a file
   has one main type (e.g. `Gateway`, `Store`, `EndpointInfo`), it
   leads. Other public types follow. Private types come after public
   ones unless they're tightly coupled to a specific public method.
7. **Pair each type with its `impl`s immediately below it.** This is
   the strongest rule: a reader looking for methods on `Foo` should
   find them right under `struct Foo`. Trait `impl`s (`Drop`,
   `Default`, `Debug`, `From`, etc.) also live next to the type they
   target. Don't collect all `impl`s into a section at the end.
8. **Free functions** at the bottom of the type-related section,
   grouped by what they do.
9. **Tests last**, in an inline `#[cfg(test)] mod tests { ... }`
   block. Integration tests live in `tests/`, not in the source file.

A useful concrete example:

```rust
//! What this module is for.

use std::sync::Arc;

use tokio::net::TcpStream;

use crate::error::ProxyError;

pub struct Gateway { /* fields */ }

impl Gateway {
    pub fn new(...) -> Self { ... }
    pub async fn run(...) -> Result<(), RuntimeError> { ... }
    fn helper(&self) { ... }
}

impl Drop for Gateway { ... }   // trait impl on the same type

// private helper struct, defined where it's used
struct BindSession { ... }
impl Drop for BindSession { ... }

// free helpers
fn build_addr(...) -> SocketAddr { ... }

#[cfg(test)]
mod tests {
    use super::*;
    // ...
}
```

`rustfmt` does NOT reorder items — these are human conventions to
keep. If you find yourself searching for an `impl` block, the file is
probably misorganized; move the `impl` next to its type.

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