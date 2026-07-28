//! HTTP proxy submodule. The accept loop dispatches every accepted
//! connection here — the store guarantees that's the only protocol
//! family that reaches the runtime.

pub(crate) mod access;
pub(crate) mod http;
