//! Per-request context shared down the extension list. The host owns
//! and populates it; extensions read it.

use bytes::Bytes;

use crate::lb::Candidate;

/// Per-request context: host-populated state extensions read through
/// the accessors.
pub struct Cx<'a> {
    targets: Targets<'a>,
    request_buffer: Option<Bytes>,
    response_buffer: Option<Bytes>,
    matched_path_prefix: Option<&'a str>,
    request_host: Option<&'a str>,
}

impl<'a> Cx<'a> {
    pub fn new() -> Self {
        Self {
            targets: Targets { backends: &[] },
            request_buffer: None,
            response_buffer: None,
            matched_path_prefix: None,
            request_host: None,
        }
    }

    /// The rule's backendRefs. Empty until the host resolves them.
    pub fn targets(&self) -> &Targets<'a> {
        &self.targets
    }

    /// The request body buffered so far. `None` unless some extension
    /// declared `Buffer`; during body hooks it includes the current
    /// chunk; complete once the body ended.
    pub fn request_buffer(&self) -> Option<&Bytes> {
        self.request_buffer.as_ref()
    }

    /// The response body buffered so far. Same rules as
    /// [`Cx::request_buffer`], response direction.
    pub fn response_buffer(&self) -> Option<&Bytes> {
        self.response_buffer.as_ref()
    }

    /// The `PathPrefix` the route matched on, when it matched by
    /// prefix.
    pub fn matched_path_prefix(&self) -> Option<&str> {
        self.matched_path_prefix
    }

    /// The request's host, with any port stripped.
    pub fn request_host(&self) -> Option<&str> {
        self.request_host
    }
}

impl Default for Cx<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// The rule's backendRefs, resolved. Selections are validated against
/// this set: it is the allowlist.
pub struct Targets<'a> {
    pub backends: &'a [Backend<'a>],
}

pub struct Backend<'a> {
    pub name: &'a str,
    pub weight: u32,
    pub kind: BackendKind<'a>,
}

pub enum BackendKind<'a> {
    /// Service-backed: discovered endpoints with their runtime state.
    Endpoints(&'a [Candidate<'a>]),
    /// Dialed by the host with its own auth and TLS.
    Dialable,
}
