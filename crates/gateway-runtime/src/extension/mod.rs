//! Per-request extensions attached to routes.
//!
//! An extension is built once per configured plugin and instantiated
//! once per request. Request hooks run in the rule's filter order and
//! may gate the request; response hooks run in reverse order and only
//! observe. One extension per rule may select the upstream target.

use std::net::SocketAddr;

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use http_body_util::combinators::BoxBody;

pub mod builtin;
mod cx;
mod registry;

// Re-exported so extensions implemented outside this crate use the
// same macro version the trait was defined with.
pub use async_trait::async_trait;
pub use cx::{Cx, TargetBackend, Targets};
pub use registry::{Registry, RegistryError};

/// Error an extension hook returns, and the error type of a body an
/// extension supplies.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Built once per configured extension
pub trait ExtensionBuilder: Send + Sync {
    /// What this builder's instances want from the host. The
    /// declarations live here so the host can choose machinery
    /// before any instance runs.
    fn declares(&self) -> Declarations {
        Declarations::default()
    }

    fn build(&self) -> Box<dyn Extension>;
}

/// What a builder declares about its instances, as one value; copied
/// into the [`Member`] at instantiation.
#[derive(Debug, Clone, Copy, Default)]
pub struct Declarations {
    pub request_body: BodyMode,
    pub response: ResponseMode,
    /// Whether instances may be asked to [`Extension::select`]. At
    /// most one builder per rule declares this.
    pub selects_targets: bool,
}

/// One instance per request, alive until the response ends.
#[async_trait]
pub trait Extension: Send {
    /// # Errors
    /// An error fails the request per the extension's configured
    /// failure mode.
    async fn on_request_start(
        &mut self,
        _head: &mut http::request::Parts,
        _cx: &mut Cx,
    ) -> Result<Action, Error> {
        Ok(Action::Continue)
    }

    /// One request-body chunk, in arrival order. Fires only for
    /// builders that declared [`BodyMode::Stream`] or
    /// [`BodyMode::Buffer`] — the same view in both; the mode changes
    /// what the host does with the bytes, never what the hook sees.
    /// The final call always has `end_of_stream: true`, with an empty
    /// chunk when the body ended on a frame boundary. The chunk is
    /// immutable and cheap to clone: keep a clone of what you need.
    ///
    /// # Errors
    /// An error fails the request per the extension's configured
    /// failure mode.
    async fn on_request_body(
        &mut self,
        _chunk: Bytes,
        _end_of_stream: bool,
        _cx: &mut Cx,
    ) -> Result<Action, Error> {
        Ok(Action::Continue)
    }

    fn on_response_start(&mut self, _head: &mut http::response::Parts, _cx: &mut Cx) {}

    /// One response-body chunk. Read-only tap; fires only for
    /// builders that declared [`ResponseMode::Tap`].
    fn on_response_body(&mut self, _chunk: Bytes, _end_of_stream: bool, _cx: &mut Cx) {}

    /// Runs exactly once per request, whatever the ending: a clean
    /// finish, a mid-stream failure, a client disconnect, or a
    /// request answered before it reached an upstream. Fires only for
    /// builders that declared [`ResponseMode::End`] or
    /// [`ResponseMode::Tap`].
    fn on_response_end(&mut self, _end: &ResponseEnd, _cx: &mut Cx) {}

    /// Pick where the request goes. Called exactly once, on the
    /// rule's single member whose builder declared
    /// [`ExtensionBuilder::selects_targets`], after the request body
    /// has been fully delivered. Members that did not declare it are
    /// never asked.
    ///
    /// `held` is what the host kept of the request body;
    /// [`Held::forward`] turns it into the source to forward, `None`
    /// when nothing was kept — a selector on a streaming rule
    /// consumed the body and must supply the one to forward.
    ///
    /// # Errors
    /// An error fails the request. There is no fallback to the
    /// default load balancer: a selector that cannot decide is a
    /// failed request, not a differently routed one.
    async fn select(&mut self, _held: Held<'_>, _cx: &mut Cx) -> Result<Selected, Error> {
        Err("member declared selects_targets but does not implement select".into())
    }
}

/// A selector's decision.
pub enum Selected {
    /// Route to this target with this body.
    Target(Selection),
    /// Short-circuit with a local response — the selector's own
    /// error path (a shed, an overload) rather than a failure.
    Respond(LocalResponse),
}

/// What the host kept of the request body by the time selection runs.
pub enum Held<'a> {
    /// The drained body, complete. Rules whose strictest mode is
    /// `Buffer`.
    Buffered(&'a [u8]),
    /// Never read: the selector decided from headers alone, so the
    /// client's stream is intact and can flow to the target as-is.
    Untouched,
    /// Nothing — the body streamed through the hooks unretained.
    Nothing,
}

impl Held<'_> {
    /// Forward the body the host kept (or never touched). `None`
    /// when it kept none: there is nothing to forward, and the
    /// selector must supply a body instead.
    pub fn forward(&self) -> Option<BodySource> {
        match self {
            Self::Buffered(_) | Self::Untouched => Some(BodySource::Original),
            Self::Nothing => None,
        }
    }
}

/// Request-body access an extension declares. The rule's effective
/// mode is the strictest across its members
/// (`Buffer` > `Stream` > `None`) and selects the host machinery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum BodyMode {
    /// Never sees the body. When every member of a rule declares
    /// `None`, the gateway forwards the body without reading a frame.
    #[default]
    None,
    /// Chunks delivered as they arrive; the gateway retains nothing
    /// and [`Cx::request_buffer`] stays `None`. On a rule with no
    /// selector, dispatch happens first and frames flow through to
    /// the upstream as the hooks see them — memory stays flat in the
    /// body size and trailers pass through.
    Stream,
    /// The host drains the body before dispatch, delivering each
    /// chunk and accumulating the whole into
    /// [`Cx::request_buffer`]. Bounded by a size cap and an idle
    /// timeout.
    Buffer,
}

/// Response access an extension declares. Ordered: `Tap` includes
/// the terminal, and the host wraps the response only for routes
/// with a member above `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum ResponseMode {
    /// No response phase; the route's response is not wrapped.
    #[default]
    None,
    /// [`Extension::on_response_end`] only — a member can settle at
    /// the terminal without reading a byte, like a limiter closing
    /// its reservation.
    End,
    /// [`Extension::on_response_body`] per chunk, plus the terminal.
    Tap,
}

/// What a request-side hook decided.
#[derive(Debug)]
pub enum Action {
    Continue,
    /// Short-circuit with a local response. From a body hook this
    /// stops the drain and discards the rest of the upload; on a
    /// streaming rule it also aborts the in-flight upstream request.
    /// The client receives this response either way.
    Respond(LocalResponse),
}

/// A response produced by an extension instead of an upstream.
#[derive(Debug)]
pub struct LocalResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// An instantiated member of a route's filter list: the per-request
/// extension instance plus a copy of its builder's [`Declarations`],
/// taken at build time — the builder is not consulted again.
pub struct Member {
    pub decl: Declarations,
    pub ext: Box<dyn Extension>,
}

impl Member {
    /// Build one instance and record what its builder declared.
    pub fn from_builder(builder: &dyn ExtensionBuilder) -> Self {
        Self {
            decl: builder.declares(),
            ext: builder.build(),
        }
    }
}

/// A routing decision: where the request goes and which body is
/// forwarded there. No hook returns this yet — selection arrives as
/// its own phase on [`Extension`].
#[derive(Debug)]
pub struct Selection {
    pub target: Target,
    pub body: BodySource,
}

/// The selected destination. Must name one of the rule's backendRefs.
#[derive(Debug)]
pub enum Target {
    /// An endpoint of a Service-backed backend.
    Endpoint { backend: String, addr: SocketAddr },
    /// A dialable backend; the host attaches auth and dials it.
    Backend { name: String },
}

/// The request body the host forwards upstream.
pub enum BodySource {
    /// The body the host kept (or never touched), as
    /// [`Held::forward`] hands it out. Invalid on a rule that
    /// retained nothing: the host fails the request rather than
    /// forward a silently empty body.
    Original,
    /// A complete body replacing the original. The host reframes
    /// content-length and discards the rest of the client upload.
    Replace(Bytes),
    /// A body the extension supplies — for a picker, the stream it
    /// pulls back from its own service. The length, when the
    /// extension knows it, is what lets the upstream tell a truncated
    /// request from a complete one; the host holds the body to it.
    Stream(BoxBody<Bytes, Error>, Option<u64>),
}

// Hand-written: a supplied body is not `Debug`, and its contents are
// not something to log anyway.
impl std::fmt::Debug for BodySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Original => f.write_str("Original"),
            Self::Replace(bytes) => f.debug_tuple("Replace").field(&bytes.len()).finish(),
            Self::Stream(_, len) => f.debug_tuple("Stream").field(len).finish(),
        }
    }
}

/// Terminal summary handed to [`Extension::on_response_end`]. Plain
/// data: copy it, compare it, keep it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseEnd {
    /// What the client was answered with, whether that came from an
    /// upstream or was synthesized here.
    pub status: StatusCode,
    /// Response body bytes that reached the client.
    pub body_bytes: u64,
    /// Whether the response ran to its end. `false` covers a client
    /// that disconnected mid-stream, a failed body, and a request
    /// answered before any upstream response existed.
    pub complete: bool,
    /// Whether the status came from an upstream response. `false`
    /// covers a filter answering, a body limit, a failed selection,
    /// and a failed dial — endings where no upstream response
    /// existed. Host-populated.
    pub upstream: bool,
}
