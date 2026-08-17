//! HTTP connection acceptance and request forwarding.
//!
//! The HTTP and HTTPS data paths converge here (per the architecture
//! doc): `handle_connection` wraps the accepted socket in
//! `hyper_util::rt::TokioIo`, hands it to `auto::Builder`, and lets
//! hyper select the HTTP/1.1 or HTTP/2 codec by peeking the HTTP/2
//! connection preface. From the request handler's point of view the
//! version is invisible.
//!
//! Filters run as extensions (`crate::extension`): one instance per
//! filter per request, built from the config by
//! `extension::builtin::instance_for`, executing request hooks in
//! route order and response hooks in reverse.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use bytes::Bytes;
use gateway_config::backend::{BackendProtocol, Endpoint};
use gateway_config::filter::HttpFilter as HttpFilterConfig;
use gateway_config::route::{
    HeaderMatch, HeaderValueMatch, HttpMatch, PathMatch, QueryParamMatch, QueryValueMatch,
};
use gateway_state::{
    ActiveBackend, ActiveBackendRef, ActiveHttpRoute, ActiveListener, BindKey, Store,
};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rand::Rng;

use crate::drain;
use crate::extension::builtin::instance_for;
use crate::extension::{Action, Cx, Extension, LocalResponse};
use crate::gateway::ProxyCtx;
use crate::lb::EndpointInfo;
use crate::metrics::Reason;
use crate::proxy::access::{Access, RequestOutcome};

pub(super) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(super) type ResponseBody = BoxBody<Bytes, BoxError>;

/// Request body forwarded upstream. An enum, not a boxed body:
/// every source is known at compile time.
pub(super) enum UpstreamBody {
    /// The client's own stream, forwarded as-is.
    Incoming(Incoming),
    /// A complete body supplied by the host or an extension. Unused
    /// until the host can buffer or replace a body.
    #[allow(dead_code)]
    Full(Full<Bytes>),
}

// Both variants are `Unpin`, so no pin projection is needed.
impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Incoming(b) => std::pin::Pin::new(b)
                .poll_frame(cx)
                .map(|frame| frame.map(|r| r.map_err(Into::into))),
            Self::Full(b) => std::pin::Pin::new(b)
                .poll_frame(cx)
                .map(|frame| frame.map(|r| r.map_err(Into::into))),
        }
    }

    // Forwarded, not defaulted: hyper picks content-length vs
    // chunked framing from `size_hint`.
    fn is_end_stream(&self) -> bool {
        match self {
            Self::Incoming(b) => b.is_end_stream(),
            Self::Full(b) => b.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Incoming(b) => b.size_hint(),
            Self::Full(b) => b.size_hint(),
        }
    }
}

/// Process-wide HTTP client used to dial upstreams. Wraps
/// `hyper_util::client::legacy::Client` — internally it owns a
/// connection pool that is shared across every cloned handle.
///
/// Process-wide upstream HTTP client. Holds one HTTP/1.1 client and
/// one HTTP/2-only client; `forward()` selects between them by the
/// backend's `BackendProtocol`. The H2 client over a plaintext
/// connector speaks h2c (prior-knowledge) — that's how we reach a
/// plaintext gRPC backend.
///
/// TODO: replace these two hyper legacy clients
#[derive(Clone)]
pub struct HttpClient {
    h1: hyper_util::client::legacy::Client<HttpConnector, UpstreamBody>,
    h2: hyper_util::client::legacy::Client<HttpConnector, UpstreamBody>,
}

impl HttpClient {
    /// Pick the client + outgoing wire version for a backend protocol.
    fn select(
        &self,
        protocol: BackendProtocol,
    ) -> (
        &hyper_util::client::legacy::Client<HttpConnector, UpstreamBody>,
        http::Version,
    ) {
        match protocol {
            BackendProtocol::Http1 => (&self.h1, http::Version::HTTP_11),
            BackendProtocol::Http2 => (&self.h2, http::Version::HTTP_2),
        }
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        let h1 = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .build_http::<UpstreamBody>();
        let h2 = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build_http::<UpstreamBody>();
        Self { h1, h2 }
    }
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient").finish_non_exhaustive()
    }
}

// =================== connection + request handlers ===================

/// Handle one accepted downstream connection. `io` is the byte stream —
/// a plaintext `TcpStream`, or a `TlsStream` once the TLS bind path has
/// terminated the handshake. Either way the HTTP serving is identical.
///
/// `auto::Builder::serve_connection_with_upgrades` peeks the first
/// bytes for the HTTP/2 preface and wires the H2 codec on match,
/// otherwise HTTP/1.1, so the gateway itself never has to
/// distinguish H1 from H2C.
pub(crate) async fn handle_connection<I>(
    ctx: ProxyCtx,
    stream: I,
    peer: SocketAddr,
    drain: drain::Watch,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tracing::debug!(bind = %ctx.bind_key, %peer, "connection accepted");

    let io = TokioIo::new(stream);
    let svc = service_fn(move |req: Request<Incoming>| {
        let ctx = ctx.clone();
        async move {
            let resp = serve_request(ctx, peer, req).await;
            Ok::<_, Infallible>(resp)
        }
    });

    let builder = auto::Builder::new(TokioExecutor::new());
    let conn = builder.serve_connection_with_upgrades(io, svc);
    let mut conn = std::pin::pin!(conn);

    // Serve until the client closes — or the drain fires (process
    // shutdown merged with this bind's teardown), in which case tell
    // the peer to go away (`Connection: close` on HTTP/1, GOAWAY on
    // HTTP/2), keep driving in-flight work to completion, and only
    // then release the drain barrier (the handle held below).
    //
    // Hand-rolled poll instead of `select!`: polling the auto
    // connection from multiple await points trips rustc's
    // "implementation of `From` is not general enough" false positive
    // on its error conversions. hyper-util has this exact future
    // internally (its graceful-shutdown watcher) but keeps it private.
    let mut signaled = std::pin::pin!(drain.signaled());
    let mut release = None;
    let result = std::future::poll_fn(|cx| {
        if release.is_none()
            && let Poll::Ready(shutdown) = signaled.as_mut().poll(cx)
        {
            conn.as_mut().graceful_shutdown();
            release = Some(shutdown);
        }
        conn.as_mut().poll(cx)
    })
    .await;
    drop(release);
    if let Err(e) = result {
        tracing::debug!(%peer, error = %e, "http connection terminated");
    }
}

/// Top-level per-request handler. Every response passes through
/// here, so the [`Access`] record sees served and synthesized
/// traffic alike.
async fn serve_request(
    ctx: ProxyCtx,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Response<ResponseBody> {
    let access = Access::begin(Arc::clone(&ctx.metrics), &ctx.bind_key.0, peer, &req);
    let (resp, outcome) = serve_request_inner(&ctx, req).await;
    access.finish(outcome, resp)
}

/// Resolves a route, applies filters, dials a backend endpoint, and
/// forwards the request. Returns the response (upstream's or a
/// synthesized error) plus the [`RequestOutcome`] describing how it
/// went.
async fn serve_request_inner(
    ctx: &ProxyCtx,
    req: Request<Incoming>,
) -> (Response<ResponseBody>, RequestOutcome) {
    let host_owned = host_from_request(&req).map(str::to_owned);
    let host_stripped = host_owned.as_deref().map(strip_port).map(str::to_owned);
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(str::to_owned);
    let method = req.method().clone();
    let headers = req.headers().clone();

    let match_ctx = MatchContext {
        host: host_stripped.as_deref(),
        path: &path,
        method: &method,
        headers: &headers,
        query: query.as_deref(),
    };

    let resolved = match resolve_http_route(&ctx.store, &ctx.bind_key, &match_ctx) {
        Ok(r) => r,
        Err(e) => {
            return (
                synthesize_error(e),
                RequestOutcome::short_circuit(None, None, Reason::from(e)),
            );
        }
    };
    let listener = Some(resolved.listener_name.as_str());
    let route = Some(resolved.route_name.as_str());

    let mut cx = Cx::new();
    cx.set_matched_path_prefix(resolved.matched_path_prefix.as_deref());
    cx.set_request_host(host_stripped.as_deref());

    // One extension instance per filter, alive from the request phase
    // through the response phase. Invalid filter config fails here,
    // before dispatch.
    let mut extensions = match build_extensions(&resolved.filters) {
        Ok(exts) => exts,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build filter extension");
            return (
                synthesize_status(StatusCode::INTERNAL_SERVER_ERROR),
                RequestOutcome::short_circuit(listener, route, Reason::Internal),
            );
        }
    };

    let (mut parts, body) = req.into_parts();
    match run_request_hooks(&mut extensions, &mut parts, &mut cx).await {
        RequestPhase::Continue => {}
        // An extension answering directly (e.g. a redirect) is the
        // route working as configured.
        RequestPhase::Respond(resp) => {
            return (
                local_response(resp),
                RequestOutcome::short_circuit(listener, route, Reason::Ok),
            );
        }
        RequestPhase::Failed => {
            return (
                synthesize_status(StatusCode::INTERNAL_SERVER_ERROR),
                RequestOutcome::short_circuit(listener, route, Reason::Internal),
            );
        }
    }
    let req = Request::from_parts(parts, UpstreamBody::Incoming(body));

    // No filter short-circuited, so this route must proxy — it needs a
    // backend with a pickable endpoint.
    let backend = match resolved.backend {
        BackendChoice::Picked(b) => b,
        BackendChoice::None => {
            return (
                synthesize_error(RouteResolveError::NoBackend),
                RequestOutcome::short_circuit(listener, route, Reason::NoBackend),
            );
        }
        BackendChoice::Unresolved => {
            return (
                synthesize_error(RouteResolveError::BackendUnresolved),
                RequestOutcome::short_circuit(listener, route, Reason::BackendUnresolved),
            );
        }
    };
    let Some((endpoint, info)) = ctx.lb.pick_endpoint(&backend) else {
        return (
            synthesize_status(StatusCode::SERVICE_UNAVAILABLE),
            RequestOutcome::short_circuit(listener, route, Reason::NoEndpoint),
        );
    };
    let _active = info.acquire();
    let endpoint_authority = format!("{}:{}", endpoint.address, endpoint.port);

    let (upstream, reason, dial_ms) =
        forward(&ctx.http_client, backend.protocol, req, &endpoint, &info).await;
    let outcome = RequestOutcome {
        listener: listener.map(str::to_owned),
        route: route.map(str::to_owned),
        reason,
        endpoint: Some(endpoint_authority),
        dial_ms,
    };

    // Response hooks run in **reverse** order per Area 03
    // ("response-side runs reverse-of-request"). Hop-by-hop
    // stripping (below) runs after, so an extension can't
    // accidentally keep a hop-by-hop header alive.
    let (mut parts, body) = upstream.into_parts();
    for ext in extensions.iter_mut().rev() {
        ext.on_response_start(&mut parts, &mut cx);
    }
    strip_hop_by_hop_headers(&mut parts.headers);
    (Response::from_parts(parts, body), outcome)
}

/// Build one extension instance per filter, in route order.
fn build_extensions(
    filters: &[HttpFilterConfig],
) -> Result<Vec<Box<dyn Extension>>, crate::extension::builtin::FilterError> {
    filters.iter().map(instance_for).collect()
}

/// What the request-side hooks decided for this request.
enum RequestPhase {
    Continue,
    Respond(LocalResponse),
    Failed,
}

/// Run the request-side hooks in route order.
async fn run_request_hooks(
    extensions: &mut [Box<dyn Extension>],
    parts: &mut http::request::Parts,
    cx: &mut Cx<'_>,
) -> RequestPhase {
    for ext in extensions.iter_mut() {
        match ext.on_request_start(parts, cx).await {
            Ok(Action::Continue) => {}
            Ok(Action::Respond(resp)) => return RequestPhase::Respond(resp),
            // No core filter selects targets; selector semantics
            // arrive with configurable extensions.
            Ok(Action::Select(_)) => {
                tracing::error!("core filter returned a target selection");
                return RequestPhase::Failed;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to apply request filter");
                return RequestPhase::Failed;
            }
        }
    }
    RequestPhase::Continue
}

/// Turn an extension's [`LocalResponse`] into the wire response.
/// Headers land verbatim — nothing is injected.
fn local_response(resp: LocalResponse) -> Response<ResponseBody> {
    let body = Full::new(resp.body)
        .map_err(|never: Infallible| match never {})
        .boxed();
    let mut out = Response::new(body);
    *out.status_mut() = resp.status;
    *out.headers_mut() = resp.headers;
    out
}

// =================== route resolution ===================

struct ResolvedRoute {
    backend: BackendChoice,
    filters: Vec<HttpFilterConfig>,
    route_name: String,
    /// Name of the listener the route hangs off — the `listener`
    /// metric label.
    listener_name: String,
    /// The route's `PathPrefix` value that matched this request
    matched_path_prefix: Option<String>,
}

/// Outcome of the weighted pick across a route's backend refs.
enum BackendChoice {
    /// The route has no backend refs (a redirect route legitimately
    /// proxies nothing).
    None,
    /// The pick landed on a ref whose backend is not registered, or no
    /// ref is eligible for traffic (all weights zero) — the request is
    /// answered with a synthesized 500.
    Unresolved,
    Picked(Arc<ActiveBackend>),
}

/// Borrow-struct carrying everything route resolution reads from the
/// incoming request. Built once per request in `serve_request` and
/// passed by reference through the match helpers.
pub(crate) struct MatchContext<'a> {
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub method: &'a Method,
    pub headers: &'a http::HeaderMap,
    pub query: Option<&'a str>,
}

/// Per-request match summary. The `Ord` impl encodes Gateway API
/// precedence: path-match (Exact > Prefix; then length) wins first,
/// then method-match presence, then header-match count, then
/// query-param-match count.
///
/// The field order of this struct is load-bearing for derived
/// `PartialOrd` / `Ord`: comparisons walk fields in declaration order.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RequestMatch {
    /// Variant order in `PathSummary` is load-bearing: `Prefix <
    /// Exact`, then within each, longer wins.
    path: PathSummary,
    /// Whether a method match was specified AND matched.
    method: bool,
    /// Count of header-match entries that matched (all must match for
    /// the rule to be a candidate).
    headers: usize,
    /// Count of query-param-match entries that matched.
    query_params: usize,
}

/// Summarized path match. Order: `Prefix(_) < Regex(_) < Exact(_)`
/// regardless of length; within a variant, longer wins. Encodes
/// Gateway API path precedence directly through variant order.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PathSummary {
    Prefix(usize),
    Regex(usize),
    Exact(usize),
}

impl PathSummary {
    /// Build from `score_path`-style raw output. Returns `None` when
    /// no path entry matched.
    fn from_match(pm: &PathMatch, path: &str) -> Option<Self> {
        let len = score_path(pm, path)?;
        match pm {
            PathMatch::PathPrefix { .. } => Some(Self::Prefix(len)),
            PathMatch::Regex { .. } => Some(Self::Regex(len)),
            PathMatch::Exact { .. } => Some(Self::Exact(len)),
        }
    }
}

/// Walk `bind → listeners → routes` and pick:
///  1. the HTTP listener whose `hostname` matches the request `Host` /
///     `:authority` (exact host preferred over the empty-host catch-all);
///  2. the route under that listener whose match summary ranks highest
///     per Gateway API precedence (tiebreak by route name order, which
///     the store sorts at placement time).
fn resolve_http_route(
    store: &Store,
    bind_key: &BindKey,
    ctx: &MatchContext<'_>,
) -> Result<ResolvedRoute, RouteResolveError> {
    let read = store.read();
    let bind = read.bind(bind_key).ok_or(RouteResolveError::BindGone)?;

    let listener = pick_listener_by_hostname(&bind.listeners, ctx.host)
        .ok_or(RouteResolveError::NoListener)?;

    let chosen = pick_http_route(&listener.routes, ctx).ok_or(RouteResolveError::NoRoute)?;

    // Backend and endpoint availability are enforced later, on the
    // proxy path — a redirect route legitimately has neither.
    let backend = pick_backend_ref(&chosen.backends);

    Ok(ResolvedRoute {
        backend,
        filters: chosen.filters.clone(),
        route_name: chosen.key.name.clone(),
        listener_name: chosen.key.listener.name.clone(),
        matched_path_prefix: matched_prefix(&chosen.matches, ctx.path).map(str::to_owned),
    })
}

/// Weighted pick across a route's backend refs. Each ref receives a
/// traffic share proportional to its weight; a share that lands on a
/// ref whose backend is not registered is `Unresolved` and answers
/// 500. Weight-zero refs receive no traffic, so a route whose refs
/// are all weight zero is `Unresolved` for every request.
fn pick_backend_ref(backends: &[ActiveBackendRef]) -> BackendChoice {
    if backends.is_empty() {
        return BackendChoice::None;
    }
    let total: u64 = backends.iter().map(|br| u64::from(br.weight)).sum();
    if total == 0 {
        return BackendChoice::Unresolved;
    }
    let mut point = rand::rng().random_range(0..total);
    for br in backends {
        let w = u64::from(br.weight);
        if point < w {
            return match &br.backend {
                Some(b) => BackendChoice::Picked(Arc::clone(b)),
                None => BackendChoice::Unresolved,
            };
        }
        point -= w;
    }
    unreachable!("point is below the summed weights");
}

/// The longest `PathPrefix` match on the route whose value is a
/// segment-prefix of `path` — the prefix a redirect's
/// `ReplacePrefixMatch` strips.
fn matched_prefix<'a>(matches: &'a [HttpMatch], path: &str) -> Option<&'a str> {
    matches
        .iter()
        .filter_map(|m| match &m.path {
            pp @ PathMatch::PathPrefix { value } if score_path(pp, path).is_some() => {
                Some(value.as_str())
            }
            _ => None,
        })
        .max_by_key(|v| v.len())
}

/// Pick the listener whose hostname best matches `host`: exact >
/// wildcard suffix > catch-all (`hostname: None`). Host-agnostic — the
/// HTTP path passes the request `Host`, the TLS accept path passes the
/// `ClientHello` SNI.
pub(crate) fn pick_listener_by_hostname<'a>(
    listeners: &'a [Arc<ActiveListener>],
    host: Option<&str>,
) -> Option<&'a ActiveListener> {
    let mut exact_match: Option<&ActiveListener> = None;
    let mut wildcard_match: Option<&ActiveListener> = None;
    let mut catchall: Option<&ActiveListener> = None;
    for l in listeners {
        match (&l.hostname, host) {
            (Some(want), Some(got)) if hostname_matches(want, got) => {
                // A more specific hostname wins, so an exact match
                // outranks a wildcard one independent of listener order.
                if want.starts_with("*.") {
                    wildcard_match.get_or_insert(l.as_ref());
                } else {
                    exact_match.get_or_insert(l.as_ref());
                }
            }
            (None, _) if catchall.is_none() => {
                catchall = Some(l.as_ref());
            }
            _ => {}
        }
    }
    exact_match.or(wildcard_match).or(catchall)
}

fn pick_http_route<'a>(
    routes: &'a [Arc<ActiveHttpRoute>],
    ctx: &MatchContext<'_>,
) -> Option<&'a Arc<ActiveHttpRoute>> {
    let mut best: Option<(RequestMatch, &Arc<ActiveHttpRoute>)> = None;
    for r in routes {
        if let Some(summary) = best_match_summary(&r.matches, ctx) {
            match &best {
                Some((cur, _)) if &summary <= cur => {}
                _ => best = Some((summary, r)),
            }
        }
    }
    best.map(|(_, r)| r)
}

/// Return the highest-ranking `RequestMatch` across a route's match
/// entries; `None` if no entry matches. A match entry fails the rule
/// on any single dimension miss (host / method / header / query
/// param / path), so we evaluate all dimensions before computing the
/// path summary.
fn best_match_summary(matches: &[HttpMatch], ctx: &MatchContext<'_>) -> Option<RequestMatch> {
    let mut best: Option<RequestMatch> = None;
    for m in matches {
        // Host filter (from HTTPRoute.hostnames fan-out).
        if let Some(want) = m.host.as_deref() {
            match ctx.host {
                Some(got) if hostname_matches(want, got) => {}
                _ => continue,
            }
        }
        // Method.
        let method_matched = match &m.method {
            Some(want) => {
                if !method_matches(want, ctx.method) {
                    continue;
                }
                true
            }
            None => false,
        };
        // Headers (all must match).
        if !m.headers.iter().all(|h| header_matches(h, ctx.headers)) {
            continue;
        }
        // Query params (all must match).
        if !m
            .query_params
            .iter()
            .all(|q| query_param_matches(q, ctx.query))
        {
            continue;
        }
        // Path last; if it doesn't match, the rule doesn't apply.
        let Some(path_summary) = PathSummary::from_match(&m.path, ctx.path) else {
            continue;
        };
        let summary = RequestMatch {
            path: path_summary,
            method: method_matched,
            headers: m.headers.len(),
            query_params: m.query_params.len(),
        };
        match &best {
            Some(cur) if &summary <= cur => {}
            _ => best = Some(summary),
        }
    }
    best
}

/// Whether `pattern` covers the concrete `host`. Case-insensitive.
///
/// Per Gateway API, wildcards are **suffix match**: `*.example.com`
/// covers `app.example.com`, `foo.bar.example.com`, and any other
/// hostname ending in `.example.com` (with at least one extra
/// label). It does NOT cover `example.com` itself.
fn hostname_matches(pattern: &str, host: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return pattern.eq_ignore_ascii_case(host);
    };
    // host must be `<prefix>.<suffix>` with non-empty prefix.
    if host.len() <= suffix.len() {
        return false;
    }
    let (head, tail) = host.split_at(host.len() - suffix.len());
    if !tail.eq_ignore_ascii_case(suffix) {
        return false;
    }
    let Some(prefix) = head.strip_suffix('.') else {
        return false;
    };
    !prefix.is_empty()
}

fn score_path(pm: &PathMatch, path: &str) -> Option<usize> {
    match pm {
        PathMatch::PathPrefix { value } => {
            let prefix = value.as_str();
            if prefix.is_empty() {
                return Some(0);
            }
            if path == prefix {
                return Some(prefix.len());
            }
            if let Some(rest) = path.strip_prefix(prefix)
                && (prefix.ends_with('/') || rest.starts_with('/'))
            {
                return Some(prefix.len());
            }
            None
        }
        // Variant precedence (`Prefix < Regex < Exact`) is encoded
        // in `PathSummary`'s variant order; this function returns
        // raw match length only.
        PathMatch::Exact { value } => (value == path).then_some(value.len()),
        // Anchored at both ends: regex must match the whole path,
        // not just a substring. Mirrors the header/query helper.
        PathMatch::Regex { value: re } => re
            .find(path)
            .and_then(|m| (m.start() == 0 && m.end() == path.len()).then_some(path.len())),
    }
}

// =================== per-dimension match helpers ===================

fn method_matches(want: &Method, got: &Method) -> bool {
    want == got
}

/// Match one header constraint against the request's header map.
/// Header names are compared case-insensitively (via `HeaderName`),
/// values are compared case-sensitively for `Exact`, and regexes are
/// anchored at both ends.
///
/// Repeated header values: if the request carries multiple values
/// for the same header, the match succeeds if **any** of them
/// matches (Gateway API leaves this undefined; any-of is the common
/// proxy behavior).
fn header_matches(want: &HeaderMatch, headers: &http::HeaderMap) -> bool {
    let values = headers.get_all(&want.name);
    match &want.value {
        HeaderValueMatch::Exact { value: v } => values.iter().any(|h| h == v),
        HeaderValueMatch::Regex { value: re } => values.iter().any(|h| match h.to_str() {
            Ok(s) => regex_anchored(re, s),
            Err(_) => false,
        }),
    }
}

/// Match one query-param constraint against the request's query
/// string. Names are case-sensitive. Both sides are percent-decoded
/// via `form_urlencoded`. Regexes are anchored at both ends.
///
/// Repeated keys: match succeeds if **any** occurrence's value
/// matches (Gateway API leaves this undefined; any-of is the common
/// proxy behavior).
fn query_param_matches(want: &QueryParamMatch, query: Option<&str>) -> bool {
    let Some(qs) = query else {
        return false;
    };
    form_urlencoded::parse(qs.as_bytes()).any(|(k, v)| {
        if k != want.name {
            return false;
        }
        match &want.value {
            QueryValueMatch::Exact { value: want_v } => &*v == want_v.as_str(),
            QueryValueMatch::Regex { value: re } => regex_anchored(re, &v),
        }
    })
}

/// Whole-string regex match. `regex::Regex::find` matches anywhere;
/// we explicitly check `start == 0 && end == len` so a pattern only
/// matches the entire value.
fn regex_anchored(re: &regex::Regex, value: &str) -> bool {
    re.find(value)
        .is_some_and(|m| m.start() == 0 && m.end() == value.len())
}

fn strip_port(authority: &str) -> &str {
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _port)| host)
}

pub(super) fn host_from_request<B>(req: &Request<B>) -> Option<&str> {
    if let Some(auth) = req.uri().authority() {
        return Some(auth.as_str());
    }
    req.headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
}

// =================== header hygiene ===================

/// Standard hop-by-hop headers (RFC 7230 §6.1) that an intermediary
/// must not forward across a proxy hop.
const HOP_BY_HOP: [&str; 8] = [
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Remove hop-by-hop headers before forwarding across the proxy hop:
/// the standard set above, every header named in a `Connection`
/// header value, and `Connection` itself. Applied to both the
/// upstream request and the downstream response.
fn strip_hop_by_hop_headers(headers: &mut http::HeaderMap) {
    // Headers named inside a `Connection` value are also hop-by-hop.
    let connection_named: Vec<http::HeaderName> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|tok| http::HeaderName::try_from(tok.trim()).ok())
        .collect();

    headers.remove(http::header::CONNECTION);
    for name in &HOP_BY_HOP {
        headers.remove(*name);
    }
    for name in connection_named {
        headers.remove(name);
    }
}

// =================== upstream forward ===================

/// Rewrite `req` to target `endpoint`, set the server-side wire
/// version from the backend's `protocol`, strip hop-by-hop headers,
/// and forward via the matching client. On dial failure the
/// endpoint's failure counter is incremented and a 502 is returned.
///
/// The server-side protocol is fully independent of the client-side
/// version the gateway served: an `Http2` backend gets h2c
/// origination whether the client spoke H1 or H2.
async fn forward(
    client: &HttpClient,
    protocol: BackendProtocol,
    mut req: Request<UpstreamBody>,
    endpoint: &Endpoint,
    info: &Arc<EndpointInfo>,
) -> (Response<ResponseBody>, Reason, Option<f64>) {
    let authority = format!("{}:{}", endpoint.address, endpoint.port);
    let pq = req
        .uri()
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let upstream_uri = match Uri::builder()
        .scheme(http::uri::Scheme::HTTP)
        .authority(authority)
        .path_and_query(pq)
        .build()
    {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build upstream uri");
            return (
                synthesize_status(StatusCode::INTERNAL_SERVER_ERROR),
                Reason::Internal,
                None,
            );
        }
    };
    *req.uri_mut() = upstream_uri;

    // Pick the client + wire version for this backend's protocol. The
    // client-side version (which may be H2 when the downstream codec
    // was H2) does not constrain the server side.
    let (upstream_client, version) = client.select(protocol);
    *req.version_mut() = version;

    // Strip hop-by-hop headers before crossing the proxy hop. This is
    // load-bearing for H2: a stale `Connection` / `Transfer-Encoding`
    // carried from a downstream H1 request is illegal on an H2
    // upstream and would be rejected.
    strip_hop_by_hop_headers(req.headers_mut());

    let dial_start = Instant::now();
    let (upstream_resp, dial_ms) = match upstream_client.request(req).await {
        Ok(r) => {
            let dial_ms = dial_start.elapsed().as_secs_f64() * 1000.0;
            info.record_success(dial_ms);
            (r, dial_ms)
        }
        Err(e) => {
            info.record_failure();
            tracing::warn!(error = %e, "upstream dial failed");
            // The elapsed time still reaches the log: how long the
            // dial waited before the 502.
            return (
                synthesize_status(StatusCode::BAD_GATEWAY),
                Reason::DialFailure,
                Some(dial_start.elapsed().as_secs_f64() * 1000.0),
            );
        }
    };

    // Response-side hop-by-hop stripping is deferred to
    // `serve_request` so that response filters can run on the
    // raw upstream headers first.
    let (parts, body) = upstream_resp.into_parts();
    let boxed: ResponseBody = body.map_err(|e| Box::new(e) as BoxError).boxed();
    (
        Response::from_parts(parts, boxed),
        Reason::Ok,
        Some(dial_ms),
    )
}

// =================== error → status synthesis ===================

#[derive(Debug, Clone, Copy, thiserror::Error)]
enum RouteResolveError {
    #[error("bind not in store")]
    BindGone,
    #[error("no listener matches the request host")]
    NoListener,
    #[error("no route matches the request path")]
    NoRoute,
    #[error("route has no backend refs")]
    NoBackend,
    #[error("route backend ref does not resolve")]
    BackendUnresolved,
}

impl From<RouteResolveError> for Reason {
    fn from(err: RouteResolveError) -> Self {
        match err {
            // All three answer 404: the request never matched
            // anything the config names.
            RouteResolveError::BindGone
            | RouteResolveError::NoListener
            | RouteResolveError::NoRoute => Reason::NoRoute,
            RouteResolveError::NoBackend => Reason::NoBackend,
            RouteResolveError::BackendUnresolved => Reason::BackendUnresolved,
        }
    }
}

fn synthesize_error(err: RouteResolveError) -> Response<ResponseBody> {
    let status = match err {
        RouteResolveError::BindGone
        | RouteResolveError::NoListener
        | RouteResolveError::NoRoute => StatusCode::NOT_FOUND,
        RouteResolveError::NoBackend => StatusCode::SERVICE_UNAVAILABLE,
        // An unresolvable backend ref is a server-side misconfiguration,
        // distinct from "no route matched".
        RouteResolveError::BackendUnresolved => StatusCode::INTERNAL_SERVER_ERROR,
    };
    synthesize_status(status)
}

fn synthesize_status(status: StatusCode) -> Response<ResponseBody> {
    let reason = status.canonical_reason().unwrap_or("");
    let body = Full::new(Bytes::from(reason.to_owned()))
        .map_err(|never: Infallible| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("synthesized response is well-formed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm(v: &str) -> PathMatch {
        PathMatch::PathPrefix { value: v.into() }
    }

    fn pm_exact(v: &str) -> PathMatch {
        PathMatch::Exact { value: v.into() }
    }

    fn pm_regex(pattern: &str) -> PathMatch {
        PathMatch::Regex {
            value: regex::Regex::new(pattern).unwrap(),
        }
    }

    // --- UpstreamBody ---

    #[test]
    fn upstream_body_forwards_full_framing() {
        let empty = UpstreamBody::Full(Full::new(Bytes::new()));
        assert!(empty.is_end_stream());
        assert_eq!(empty.size_hint().exact(), Some(0));

        let filled = UpstreamBody::Full(Full::new(Bytes::from_static(b"hello")));
        assert!(!filled.is_end_stream());
        assert_eq!(filled.size_hint().exact(), Some(5));
    }

    #[tokio::test]
    async fn upstream_body_full_yields_its_bytes() {
        let body = UpstreamBody::Full(Full::new(Bytes::from_static(b"payload")));
        let collected = body.collect().await.expect("collect").to_bytes();
        assert_eq!(collected, Bytes::from_static(b"payload"));
    }

    // --- local_response ---

    #[test]
    fn local_response_preserves_parts_verbatim() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::LOCATION,
            "https://x.example/".parse().unwrap(),
        );
        let resp = local_response(LocalResponse {
            status: StatusCode::MOVED_PERMANENTLY,
            headers,
            body: Bytes::new(),
        });
        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        // Exactly the extension's headers — nothing injected.
        assert_eq!(resp.headers().len(), 1);
        assert_eq!(
            resp.headers().get(http::header::LOCATION).unwrap(),
            "https://x.example/"
        );
    }

    // --- hop-by-hop header stripping ---

    #[test]
    fn strip_removes_standard_hop_by_hop() {
        let mut h = http::HeaderMap::new();
        h.insert("connection", "keep-alive".parse().unwrap());
        h.insert("keep-alive", "timeout=5".parse().unwrap());
        h.insert("proxy-connection", "keep-alive".parse().unwrap());
        h.insert("proxy-authenticate", "Basic".parse().unwrap());
        h.insert("proxy-authorization", "Basic xyz".parse().unwrap());
        h.insert("te", "trailers".parse().unwrap());
        h.insert("trailer", "x-trace".parse().unwrap());
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        h.insert("upgrade", "h2c".parse().unwrap());
        h.insert("content-type", "text/plain".parse().unwrap());

        strip_hop_by_hop_headers(&mut h);

        for name in [
            "connection",
            "keep-alive",
            "proxy-connection",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(!h.contains_key(name), "{name} should be stripped");
        }
        assert_eq!(h.get("content-type").unwrap(), "text/plain");
    }

    #[test]
    fn strip_removes_connection_named_headers() {
        let mut h = http::HeaderMap::new();
        h.insert("connection", "x-foo, x-bar".parse().unwrap());
        h.insert("x-foo", "1".parse().unwrap());
        h.insert("x-bar", "2".parse().unwrap());
        h.insert("x-keep", "3".parse().unwrap());

        strip_hop_by_hop_headers(&mut h);

        assert!(!h.contains_key("connection"));
        assert!(!h.contains_key("x-foo"));
        assert!(!h.contains_key("x-bar"));
        assert_eq!(h.get("x-keep").unwrap(), "3");
    }

    #[test]
    fn strip_keeps_end_to_end_headers() {
        let mut h = http::HeaderMap::new();
        h.insert("content-type", "application/grpc".parse().unwrap());
        h.insert("x-custom", "v".parse().unwrap());
        h.insert("authorization", "Bearer t".parse().unwrap());

        strip_hop_by_hop_headers(&mut h);

        assert_eq!(h.get("content-type").unwrap(), "application/grpc");
        assert_eq!(h.get("x-custom").unwrap(), "v");
        assert_eq!(h.get("authorization").unwrap(), "Bearer t");
    }

    // --- score_path basic ---

    #[test]
    fn score_exact_match() {
        assert_eq!(score_path(&pm("/api"), "/api"), Some(4));
    }

    #[test]
    fn score_prefix_then_slash() {
        assert_eq!(score_path(&pm("/api"), "/api/v2"), Some(4));
    }

    #[test]
    fn score_prefix_then_non_slash_rejected() {
        assert_eq!(score_path(&pm("/api"), "/apix"), None);
    }

    #[test]
    fn score_prefix_with_trailing_slash() {
        assert_eq!(score_path(&pm("/api/"), "/api/foo"), Some(5));
    }

    #[test]
    fn score_root_matches_anything() {
        assert_eq!(score_path(&pm("/"), "/foo/bar"), Some(1));
    }

    #[test]
    fn score_exact_equal_returns_length() {
        // Exact-vs-prefix precedence is now expressed by `PathSummary`,
        // so `score_path` returns the same usize for both kinds; only
        // the variant carries the precedence bit.
        assert_eq!(score_path(&pm_exact("/foo"), "/foo"), Some(4));
        assert_eq!(score_path(&pm_exact("/healthz"), "/healthz"), Some(8));
    }

    #[test]
    fn score_exact_unequal_rejected() {
        // Critical: Exact must not prefix-match. `/foo/bar` is NOT `/foo`.
        assert_eq!(score_path(&pm_exact("/foo"), "/foo/bar"), None);
        assert_eq!(score_path(&pm_exact("/healthz"), "/healthzz"), None);
        // Trailing slash matters: `/foo` and `/foo/` are different.
        assert_eq!(score_path(&pm_exact("/foo"), "/foo/"), None);
        assert_eq!(score_path(&pm_exact("/foo/"), "/foo"), None);
    }

    // --- PathSummary::Ord ---

    #[test]
    fn path_summary_exact_beats_any_prefix() {
        // Even when the prefix is longer, Exact wins.
        assert!(PathSummary::Exact(3) > PathSummary::Prefix(100));
    }

    #[test]
    fn path_summary_longer_prefix_beats_shorter() {
        assert!(PathSummary::Prefix(7) > PathSummary::Prefix(3));
    }

    #[test]
    fn path_summary_longer_exact_beats_shorter_exact() {
        assert!(PathSummary::Exact(9) > PathSummary::Exact(5));
    }

    // --- regex path match ---

    #[test]
    fn score_regex_matches_whole_path() {
        // Regex matches `/api/v1` exactly when anchored.
        assert_eq!(score_path(&pm_regex(r"^/api/v\d+$"), "/api/v1"), Some(7));
        assert_eq!(score_path(&pm_regex(r"^/api/v\d+$"), "/api/v42"), Some(8));
    }

    #[test]
    fn score_regex_substring_rejected() {
        // Without anchoring, `/api` would match `/foo/api/bar`; we
        // anchor both ends explicitly, so substring matches are
        // rejected.
        assert_eq!(score_path(&pm_regex(r"/api"), "/foo/api/bar"), None);
        // A regex that lacks anchors still must match the whole
        // path under our enforcement; `bar` doesn't match
        // `/foo/bar`.
        assert_eq!(score_path(&pm_regex(r"bar"), "/foo/bar"), None);
    }

    #[test]
    fn score_regex_partial_path_rejected() {
        // Regex matches `/api` but request is `/api/v1` — anchoring
        // forces whole-path match, so this is None.
        assert_eq!(score_path(&pm_regex(r"^/api$"), "/api/v1"), None);
    }

    #[test]
    fn path_summary_regex_beats_prefix() {
        // Regex outranks Prefix even when prefix is much longer.
        assert!(PathSummary::Regex(5) > PathSummary::Prefix(99));
    }

    #[test]
    fn path_summary_exact_beats_regex() {
        // Exact still outranks Regex unconditionally.
        assert!(PathSummary::Exact(3) > PathSummary::Regex(99));
    }

    #[test]
    fn path_summary_longer_regex_beats_shorter_regex() {
        assert!(PathSummary::Regex(8) > PathSummary::Regex(3));
    }

    // --- strip_port ---

    #[test]
    fn strip_port_with_port() {
        assert_eq!(strip_port("example.com:443"), "example.com");
    }

    #[test]
    fn strip_port_without_port() {
        assert_eq!(strip_port("example.com"), "example.com");
    }

    // --- match helpers: best_match_summary ---

    fn ctx<'a>(
        host: Option<&'a str>,
        path: &'a str,
        method: &'a Method,
        headers: &'a http::HeaderMap,
        query: Option<&'a str>,
    ) -> MatchContext<'a> {
        MatchContext {
            host,
            path,
            method,
            headers,
            query,
        }
    }

    fn am(path: PathMatch) -> HttpMatch {
        HttpMatch {
            host: None,
            path,
            method: None,
            headers: vec![],
            query_params: vec![],
        }
    }

    #[test]
    fn summary_picks_longest_prefix_path() {
        let matches = vec![am(pm("/api")), am(pm("/api/v2"))];
        let m = Method::GET;
        let h = http::HeaderMap::new();
        let c = ctx(None, "/api/v2/foo", &m, &h, None);
        let s = best_match_summary(&matches, &c).expect("matched");
        assert_eq!(s.path, PathSummary::Prefix(7));
    }

    #[test]
    fn summary_filters_on_host() {
        let mut a = am(pm("/"));
        a.host = Some("a.example.com".into());
        let m = Method::GET;
        let h = http::HeaderMap::new();
        assert!(
            best_match_summary(&[a.clone()], &ctx(Some("b.example.com"), "/", &m, &h, None))
                .is_none()
        );
        assert!(best_match_summary(&[a], &ctx(Some("a.example.com"), "/", &m, &h, None)).is_some());
    }

    #[test]
    fn summary_with_wildcard_host() {
        let mut a = am(pm("/"));
        a.host = Some("*.example.com".into());
        let m = Method::GET;
        let h = http::HeaderMap::new();
        assert!(
            best_match_summary(
                &[a.clone()],
                &ctx(Some("foo.example.com"), "/", &m, &h, None)
            )
            .is_some()
        );
        // bare suffix does NOT match — wildcard needs extra label
        assert!(best_match_summary(&[a], &ctx(Some("example.com"), "/", &m, &h, None)).is_none());
    }

    #[test]
    fn summary_exact_outranks_prefix_at_same_path() {
        let exact_only = vec![am(pm_exact("/foo"))];
        let prefix_only = vec![am(pm("/foo"))];
        let method = Method::GET;
        let headers = http::HeaderMap::new();
        let cx = ctx(None, "/foo", &method, &headers, None);
        let exact_score = best_match_summary(&exact_only, &cx).unwrap();
        let prefix_score = best_match_summary(&prefix_only, &cx).unwrap();
        assert!(exact_score > prefix_score, "exact must outrank prefix");
    }

    // --- method matching ---

    #[test]
    fn method_match_exact() {
        let mut a = am(pm("/"));
        a.method = Some(Method::POST);
        let h = http::HeaderMap::new();
        let m_get = Method::GET;
        let m_post = Method::POST;
        assert!(best_match_summary(&[a.clone()], &ctx(None, "/", &m_get, &h, None)).is_none());
        let s = best_match_summary(&[a], &ctx(None, "/", &m_post, &h, None)).unwrap();
        assert!(s.method, "method-present should mark summary.method = true");
    }

    // --- header matching ---

    fn header_exact(name: &str, value: &str) -> HeaderMatch {
        HeaderMatch {
            name: http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value: HeaderValueMatch::Exact {
                value: http::HeaderValue::from_str(value).unwrap(),
            },
        }
    }

    fn header_regex(name: &str, pattern: &str) -> HeaderMatch {
        HeaderMatch {
            name: http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value: HeaderValueMatch::Regex {
                value: regex::Regex::new(pattern).unwrap(),
            },
        }
    }

    #[test]
    fn header_match_exact_matches_case_insensitive_name() {
        let mut headers = http::HeaderMap::new();
        headers.insert("X-Debug", "1".parse().unwrap());
        assert!(header_matches(&header_exact("x-debug", "1"), &headers));
        assert!(header_matches(&header_exact("X-DEBUG", "1"), &headers));
        assert!(!header_matches(&header_exact("x-debug", "2"), &headers));
    }

    #[test]
    fn header_match_exact_value_is_case_sensitive() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-mode", "Active".parse().unwrap());
        assert!(header_matches(&header_exact("x-mode", "Active"), &headers));
        assert!(!header_matches(&header_exact("x-mode", "active"), &headers));
    }

    #[test]
    fn header_match_repeated_value_matches_any() {
        let mut headers = http::HeaderMap::new();
        headers.append("x-tag", "a".parse().unwrap());
        headers.append("x-tag", "b".parse().unwrap());
        headers.append("x-tag", "c".parse().unwrap());
        assert!(header_matches(&header_exact("x-tag", "b"), &headers));
    }

    #[test]
    fn header_match_regex_is_anchored() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-id", "bar".parse().unwrap());
        // Regex `bar` should match full `bar` value.
        assert!(header_matches(&header_regex("x-id", "bar"), &headers));
        // Regex `bar` should NOT match `barbaz` — patterns are
        // anchored at both ends.
        headers.insert("x-id", "barbaz".parse().unwrap());
        assert!(!header_matches(&header_regex("x-id", "bar"), &headers));
        // Regex `b.+` matches the whole string.
        assert!(header_matches(&header_regex("x-id", "b.+"), &headers));
    }

    #[test]
    fn header_match_missing_header_no_match() {
        let headers = http::HeaderMap::new();
        assert!(!header_matches(&header_exact("x-missing", "v"), &headers));
    }

    // --- query param matching ---

    fn qp_exact(name: &str, value: &str) -> QueryParamMatch {
        QueryParamMatch {
            name: name.into(),
            value: QueryValueMatch::Exact {
                value: value.into(),
            },
        }
    }

    fn qp_regex(name: &str, pattern: &str) -> QueryParamMatch {
        QueryParamMatch {
            name: name.into(),
            value: QueryValueMatch::Regex {
                value: regex::Regex::new(pattern).unwrap(),
            },
        }
    }

    #[test]
    fn query_param_exact_matches() {
        assert!(query_param_matches(
            &qp_exact("foo", "bar"),
            Some("foo=bar")
        ));
        assert!(query_param_matches(
            &qp_exact("foo", "bar"),
            Some("a=1&foo=bar&b=2")
        ));
        assert!(!query_param_matches(
            &qp_exact("foo", "bar"),
            Some("foo=baz")
        ));
        assert!(!query_param_matches(&qp_exact("foo", "bar"), None));
    }

    #[test]
    fn query_param_percent_decoded_comparison() {
        // form_urlencoded percent-decodes both sides.
        assert!(query_param_matches(
            &qp_exact("x", "hello world"),
            Some("x=hello%20world")
        ));
    }

    #[test]
    fn query_param_repeated_key_matches_any() {
        // First-or-any; both should match here.
        assert!(query_param_matches(
            &qp_exact("k", "v2"),
            Some("k=v1&k=v2&k=v3")
        ));
    }

    #[test]
    fn query_param_regex_is_anchored() {
        // `bar` matches full `bar` but not `barbaz`.
        assert!(query_param_matches(&qp_regex("x", "bar"), Some("x=bar")));
        assert!(!query_param_matches(
            &qp_regex("x", "bar"),
            Some("x=barbaz")
        ));
        assert!(query_param_matches(&qp_regex("x", "b.+"), Some("x=barbaz")));
    }

    // --- RequestMatch::Ord cascade (Gateway API spec order) ---

    fn rm(path: PathSummary, method: bool, headers: usize, query: usize) -> RequestMatch {
        RequestMatch {
            path,
            method,
            headers,
            query_params: query,
        }
    }

    #[test]
    fn request_match_ord_path_beats_method() {
        // Exact path with no method beats Prefix path with method.
        let a = rm(PathSummary::Exact(4), false, 0, 0);
        let b = rm(PathSummary::Prefix(4), true, 0, 0);
        assert!(a > b);
    }

    #[test]
    fn request_match_ord_method_beats_headers() {
        // Same path; method-present > more-headers.
        let a = rm(PathSummary::Prefix(1), true, 0, 0);
        let b = rm(PathSummary::Prefix(1), false, 5, 0);
        assert!(a > b);
    }

    #[test]
    fn request_match_ord_more_headers_beats_fewer() {
        let a = rm(PathSummary::Prefix(1), false, 3, 0);
        let b = rm(PathSummary::Prefix(1), false, 2, 100);
        assert!(a > b);
    }

    #[test]
    fn request_match_ord_more_query_beats_fewer_when_tied() {
        let a = rm(PathSummary::Prefix(1), false, 1, 2);
        let b = rm(PathSummary::Prefix(1), false, 1, 1);
        assert!(a > b);
    }

    // --- end-to-end via best_match_summary: header rule beats catchall ---

    #[test]
    fn summary_header_rule_beats_catchall() {
        let header_rule = vec![HttpMatch {
            host: None,
            path: pm("/"),
            method: None,
            headers: vec![header_exact("x-feature", "on")],
            query_params: vec![],
        }];
        let catchall = vec![am(pm("/"))];

        let mut request_headers = http::HeaderMap::new();
        request_headers.insert("x-feature", "on".parse().unwrap());
        let method = Method::GET;

        let with_header = best_match_summary(
            &header_rule,
            &ctx(None, "/", &method, &request_headers, None),
        )
        .unwrap();
        let catchall_only =
            best_match_summary(&catchall, &ctx(None, "/", &method, &request_headers, None))
                .unwrap();
        assert!(
            with_header > catchall_only,
            "header-matched rule must outrank catch-all at the same path"
        );

        // Without the header, the header rule does not match.
        let empty = http::HeaderMap::new();
        assert!(best_match_summary(&header_rule, &ctx(None, "/", &method, &empty, None)).is_none());
        assert!(best_match_summary(&catchall, &ctx(None, "/", &method, &empty, None)).is_some());
    }

    // --- hostname_matches ---

    #[test]
    fn hostname_matches_exact() {
        assert!(hostname_matches("a.example.com", "a.example.com"));
        assert!(!hostname_matches("a.example.com", "b.example.com"));
    }

    #[test]
    fn hostname_matches_is_case_insensitive() {
        assert!(hostname_matches("A.Example.COM", "a.example.com"));
        assert!(hostname_matches("*.Example.COM", "App.EXAMPLE.com"));
    }

    #[test]
    fn hostname_matches_wildcard_suffix_match() {
        // Per Gateway API: suffix match — covers single AND multi-label
        // prefixes alike.
        assert!(hostname_matches("*.example.com", "app.example.com"));
        assert!(hostname_matches("*.example.com", "a.b.example.com"));
        assert!(hostname_matches("*.example.com", "foo.bar.baz.example.com"));
    }

    #[test]
    fn hostname_matches_wildcard_rejects_bare_suffix() {
        // wildcard requires at least one extra label before the suffix
        assert!(!hostname_matches("*.example.com", "example.com"));
    }

    #[test]
    fn hostname_matches_wildcard_unrelated_domain() {
        assert!(!hostname_matches("*.example.com", "app.other.com"));
    }

    #[test]
    fn best_match_with_wildcard_host() {
        // covered by summary_with_wildcard_host above; kept as the
        // dedicated single-case test in case future refactors split
        // host filtering out of `best_match_summary`.
        let mut a = am(pm("/"));
        a.host = Some("*.example.com".into());
        let m = Method::GET;
        let h = http::HeaderMap::new();
        assert!(
            best_match_summary(
                &[a.clone()],
                &ctx(Some("foo.example.com"), "/", &m, &h, None)
            )
            .is_some()
        );
        assert!(
            best_match_summary(
                &[a.clone()],
                &ctx(Some("a.b.example.com"), "/", &m, &h, None)
            )
            .is_some()
        );
        assert!(best_match_summary(&[a], &ctx(Some("example.com"), "/", &m, &h, None)).is_none());
    }

    // --- pick_listener_by_hostname ---

    fn listener(name: &str, hostname: Option<&str>) -> Arc<ActiveListener> {
        Arc::new(ActiveListener {
            key: gateway_state::ListenerKey::new(BindKey::new("b"), name),
            hostname: hostname.map(str::to_owned),
            routes: Vec::new(),
            tls: None,
        })
    }

    fn picked<'a>(ls: &'a [Arc<ActiveListener>], host: Option<&str>) -> Option<&'a str> {
        pick_listener_by_hostname(ls, host).map(|l| l.key.name.as_str())
    }

    #[test]
    fn pick_listener_exact_match() {
        let ls = [listener("exact", Some("a.example.com"))];
        assert_eq!(picked(&ls, Some("a.example.com")), Some("exact"));
        assert_eq!(picked(&ls, Some("b.example.com")), None);
    }

    #[test]
    fn pick_listener_wildcard_match() {
        let ls = [listener("wild", Some("*.example.com"))];
        assert_eq!(picked(&ls, Some("app.example.com")), Some("wild"));
        assert_eq!(picked(&ls, Some("a.b.example.com")), Some("wild"));
        assert_eq!(picked(&ls, Some("example.com")), None);
    }

    #[test]
    fn pick_listener_exact_beats_wildcard() {
        // Both match `app.example.com`; the exact listener must win
        // regardless of iteration order.
        let exact = listener("exact", Some("app.example.com"));
        let wild = listener("wild", Some("*.example.com"));
        assert_eq!(
            picked(&[wild.clone(), exact.clone()], Some("app.example.com")),
            Some("exact"),
        );
        assert_eq!(
            picked(&[exact, wild.clone()], Some("app.example.com")),
            Some("exact"),
        );
        // A host only the wildcard covers still picks the wildcard.
        assert_eq!(picked(&[wild], Some("other.example.com")), Some("wild"));
    }

    #[test]
    fn pick_listener_wildcard_beats_catchall() {
        let wild = listener("wild", Some("*.example.com"));
        let catchall = listener("catchall", None);
        assert_eq!(
            picked(&[catchall.clone(), wild.clone()], Some("app.example.com")),
            Some("wild"),
        );
        // No hostname match → fall back to the catch-all.
        assert_eq!(
            picked(&[catchall, wild], Some("nomatch.org")),
            Some("catchall"),
        );
    }

    #[test]
    fn pick_listener_catchall_only() {
        let ls = [listener("catchall", None)];
        assert_eq!(picked(&ls, Some("anything.com")), Some("catchall"));
        assert_eq!(picked(&ls, None), Some("catchall"));
    }

    // --- pick_backend_ref ---

    fn backend_ref(name: &str, resolved: bool, weight: u32) -> ActiveBackendRef {
        let key = gateway_state::BackendKey::new(name);
        ActiveBackendRef {
            key: key.clone(),
            backend: resolved.then(|| {
                Arc::new(ActiveBackend {
                    key,
                    endpoints: vec![],
                    protocol: BackendProtocol::Http1,
                })
            }),
            weight,
        }
    }

    #[test]
    fn pick_no_refs_is_none() {
        assert!(matches!(pick_backend_ref(&[]), BackendChoice::None));
    }

    #[test]
    fn pick_single_resolved_ref() {
        let refs = [backend_ref("be", true, 1)];
        assert!(matches!(
            pick_backend_ref(&refs),
            BackendChoice::Picked(b) if b.key.0 == "be"
        ));
    }

    #[test]
    fn pick_single_unresolved_ref() {
        let refs = [backend_ref("ghost", false, 1)];
        assert!(matches!(pick_backend_ref(&refs), BackendChoice::Unresolved));
    }

    #[test]
    fn pick_all_zero_weights_is_unresolved() {
        let refs = [backend_ref("be0", true, 0), backend_ref("be1", true, 0)];
        assert!(matches!(pick_backend_ref(&refs), BackendChoice::Unresolved));
    }

    #[test]
    fn pick_skips_zero_weight_refs() {
        let refs = [backend_ref("ghost", false, 0), backend_ref("be", true, 1)];
        for _ in 0..64 {
            assert!(matches!(
                pick_backend_ref(&refs),
                BackendChoice::Picked(b) if b.key.0 == "be"
            ));
        }
    }
}
