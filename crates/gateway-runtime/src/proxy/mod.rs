//! Per-protocol proxy submodules. Each submodule owns its connection
//! handler, route resolution, and any per-protocol filter execution.
//! The `accept::run_bind` dispatcher decides which submodule to invoke
//! based on the bind's `BindProtocol`.

pub(crate) mod http;
pub(crate) mod tcp;
