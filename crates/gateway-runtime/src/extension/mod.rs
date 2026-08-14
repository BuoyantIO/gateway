//! Per-request extensions attached to routes.
//!
//! An extension is built once per configured plugin and instantiated
//! once per request. Request hooks run in the rule's filter order and
//! may gate the request; response hooks run in reverse order and only
//! observe. One extension per rule may select the upstream target.

use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, StatusCode};

pub mod builtin;
mod cx;
mod registry;

pub use cx::{Backend, BackendKind, Cx, Targets};
pub use registry::{Registry, RegistryError};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Built once per configured extension
pub trait ExtensionBuilder: Send + Sync {
    fn request_body(&self) -> BodyMode {
        BodyMode::None
    }

    fn response_body(&self) -> BodyMode {
        BodyMode::None
    }

    /// Whether instances may return [`Action::Select`]. At most one
    /// builder per rule declares this.
    fn selects_targets(&self) -> bool {
        false
    }

    fn build(&self) -> Box<dyn Extension>;
}

/// One instance per request, alive until the response ends.
#[async_trait]
pub trait Extension: Send {
    /// # Errors
    /// An error fails the request per the extension's configured
    /// failure mode.
    async fn on_request_start(
        &mut self,
        head: &mut http::request::Parts,
        cx: &mut Cx<'_>,
    ) -> Result<Action, Error>;

    /// One request-body chunk, in arrival order. Fires only for
    /// builders that declared [`BodyMode::Observe`] or
    /// [`BodyMode::Buffer`]. The final call always has
    /// `end_of_stream: true`, with an empty chunk when the body ended
    /// on a frame boundary.
    ///
    /// # Errors
    /// An error fails the request per the extension's configured
    /// failure mode.
    async fn on_request_body(
        &mut self,
        _chunk: &[u8],
        _end_of_stream: bool,
        _cx: &mut Cx<'_>,
    ) -> Result<Action, Error> {
        Ok(Action::Continue)
    }

    fn on_response_start(&mut self, _head: &mut http::response::Parts, _cx: &mut Cx<'_>) {}

    /// One response-body chunk. Read-only tap; fires only for
    /// builders that declared a response [`BodyMode::Observe`].
    fn on_response_body(&mut self, _chunk: &[u8], _end_of_stream: bool, _cx: &mut Cx<'_>) {}

    /// Runs exactly once per request, whatever the ending: clean end,
    /// mid-stream failure, client disconnect, or an upstream that
    /// never produced a response.
    fn on_response_end(&mut self, _end: &ResponseEnd, _cx: &mut Cx<'_>) {}
}

/// Body access an extension declares, per direction. `Observe` sees
/// chunks as they stream through; `Buffer` makes the host accumulate
/// the body and, on the request side, hold dispatch until it is
/// complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BodyMode {
    #[default]
    None,
    Observe,
    Buffer,
}

/// What a request-side hook decided.
#[derive(Debug)]
pub enum Action {
    Continue,
    /// Short-circuit with a local response.
    Respond(LocalResponse),
    /// Route to the selected target. Only instances whose builder
    /// declared [`ExtensionBuilder::selects_targets`], at most once
    /// per chain/request.
    Select(Selection),
}

/// A response produced by an extension instead of an upstream.
#[derive(Debug)]
pub struct LocalResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// A routing decision: where the request goes and which body is
/// forwarded there.
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
#[derive(Debug)]
pub enum BodySource {
    Original,
    /// A complete body replacing the original. The host reframes
    /// content-length and discards the rest of the client upload.
    Replace(Bytes),
}

/// Terminal summary handed to [`Extension::on_response_end`].
#[derive(Debug)]
pub struct ResponseEnd {
    /// `None` when the upstream never produced a response.
    pub status: Option<StatusCode>,
    pub body_bytes: u64,
    pub complete: bool,
}
