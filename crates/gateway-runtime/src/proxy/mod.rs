//! HTTP proxy submodule. The accept loop dispatches every accepted
//! connection here — the store guarantees that's the only protocol
//! family that reaches the runtime.

pub(crate) mod access;
pub(crate) mod body;
pub(crate) mod extensions;
pub(crate) mod gate;
pub(crate) mod http;
pub(crate) mod oauth2;
pub(crate) mod originate;
pub(crate) mod tap;
