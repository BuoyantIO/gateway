//! Per-request context shared down the extension list. The host owns
//! and populates it; extensions read it.

use std::sync::Arc;

use bytes::BytesMut;
use gateway_config::backend::Endpoint;
use gateway_state::ActiveBackend;

/// Per-request context: host-populated state extensions read through
/// the accessors.
pub struct Cx {
    targets: Targets,
    request_buffer: Option<BytesMut>,
    matched_path_prefix: Option<Arc<str>>,
    request_host: Option<Arc<str>>,
}

impl Cx {
    pub fn new() -> Self {
        Self {
            targets: Targets {
                backends: Vec::new(),
            },
            request_buffer: None,
            matched_path_prefix: None,
            request_host: None,
        }
    }

    /// The rule's backendRefs. Populated only for requests whose
    /// members include a selector; empty otherwise.
    pub fn targets(&self) -> &Targets {
        &self.targets
    }

    /// Install the rule's resolved refs. Host-side, selector rules
    /// only.
    pub(crate) fn set_targets(&mut self, targets: Targets) {
        self.targets = targets;
    }

    /// The request body accumulated so far. `Some` exactly when a
    /// member declared `Buffer`: during body hooks it includes the
    /// current chunk, and it is complete once `end_of_stream` was
    /// delivered. `None` on rules whose members stream — nothing is
    /// retained for them. A borrow, not an owned handle: the buffer
    /// is still growing while hooks run, so an extension that wants
    /// to keep bytes copies them.
    ///
    /// During [`crate::extension::Extension::select`] the drained
    /// body travels in the `Held` argument instead, and this reads
    /// `None`.
    pub fn request_buffer(&self) -> Option<&[u8]> {
        self.request_buffer.as_deref()
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
        self.matched_path_prefix.as_deref()
    }

    /// The request's host, with any port stripped.
    pub fn request_host(&self) -> Option<&str> {
        self.request_host.as_deref()
    }

    pub fn set_matched_path_prefix(&mut self, prefix: Option<&str>) {
        self.matched_path_prefix = prefix.map(Arc::from);
    }

    pub fn set_request_host(&mut self, host: Option<&str>) {
        self.request_host = host.map(Arc::from);
    }
}

impl Default for Cx {
    fn default() -> Self {
        Self::new()
    }
}

/// The rule's backendRefs, resolved. Selections are validated against
/// this set: it is the allowlist.
pub struct Targets {
    backends: Vec<TargetBackend>,
}

impl Targets {
    pub(crate) fn new(backends: Vec<TargetBackend>) -> Self {
        Self { backends }
    }

    pub fn backends(&self) -> &[TargetBackend] {
        &self.backends
    }

    /// The ref named `name`, when the rule has one.
    pub fn backend(&self, name: &str) -> Option<&TargetBackend> {
        self.backends.iter().find(|b| b.name() == name)
    }
}

/// One of the rule's backendRefs: the name and weight from the route,
/// plus the backend it resolved to. Holds the backend by `Arc`, so
/// building this costs one reference count per ref and no endpoint
/// copies.
pub struct TargetBackend {
    name: String,
    weight: u32,
    backend: Option<Arc<ActiveBackend>>,
}

impl TargetBackend {
    pub(crate) fn new(name: String, weight: u32, backend: Option<Arc<ActiveBackend>>) -> Self {
        Self {
            name,
            weight,
            backend,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn weight(&self) -> u32 {
        self.weight
    }

    /// The endpoints behind this ref. Empty when the ref names a
    /// backend that is not registered, or one that is dialable
    /// rather than a set of endpoints — a selector must treat such a
    /// ref as having nothing to offer.
    pub fn endpoints(&self) -> &[Endpoint] {
        self.backend
            .as_deref()
            .map_or(&[], ActiveBackend::endpoints)
    }
}
