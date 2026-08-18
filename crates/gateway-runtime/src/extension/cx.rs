//! Per-request context shared down the extension list. The host owns
//! and populates it; extensions read it.

use bytes::BytesMut;

use crate::lb::Candidate;

/// Per-request context: host-populated state extensions read through
/// the accessors.
pub struct Cx<'a> {
    targets: Targets<'a>,
    request_buffer: Option<BytesMut>,
    response_buffer: Option<BytesMut>,
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

    /// The request body accumulated so far. `Some` exactly when a
    /// member declared `Buffer`: during body hooks it includes the
    /// current chunk, and it is complete once `end_of_stream` was
    /// delivered. `None` on rules whose members stream — nothing is
    /// retained for them. A borrow, not an owned handle: the buffer
    /// is still growing while hooks run, so an extension that wants
    /// to keep bytes copies them.
    pub fn request_buffer(&self) -> Option<&[u8]> {
        self.request_buffer.as_deref()
    }

    /// The response body accumulated so far. Same rules as
    /// [`Cx::request_buffer`], response direction.
    pub fn response_buffer(&self) -> Option<&[u8]> {
        self.response_buffer.as_deref()
    }

    /// Append a chunk to the request accumulation, creating it on
    /// first use. Written by the body gate only.
    pub(crate) fn append_request_buffer(&mut self, chunk: &[u8]) {
        self.request_buffer
            .get_or_insert_with(BytesMut::new)
            .extend_from_slice(chunk);
    }

    /// Take the accumulated request body, leaving the accessor
    /// `None`. The gate calls this once, after end-of-stream, to
    /// forward the bytes without a copy.
    pub(crate) fn take_request_buffer(&mut self) -> Option<BytesMut> {
        self.request_buffer.take()
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

    pub fn set_matched_path_prefix(&mut self, prefix: Option<&'a str>) {
        self.matched_path_prefix = prefix;
    }

    pub fn set_request_host(&mut self, host: Option<&'a str>) {
        self.request_host = host;
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
