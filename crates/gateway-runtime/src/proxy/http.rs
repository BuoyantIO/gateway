//! HTTP connection acceptance and request forwarding.
//!
//! The HTTP and HTTPS data paths converge here (per the architecture
//! doc): `handle_connection` wraps the accepted socket in
//! `hyper_util::rt::TokioIo`, hands it to `auto::Builder`, and lets
//! hyper select the HTTP/1.1 or HTTP/2 codec by peeking the HTTP/2
//! connection preface. From the request handler's point of view the
//! version is invisible.
//!
//! Filters apply through a `HttpFilter` trait declared in this
//! module — one impl struct per `gateway_config::filter::HttpFilter`
//! variant, plus a `build_http_filter(cfg)` shim that converts the
//! config-shaped enum into a trait object at use time.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use gateway_config::backend::Endpoint;
use gateway_config::filter::{HeaderPair, HttpFilter as HttpFilterConfig, RequestHeaderOps};
use gateway_config::route::{HttpMatch, PathMatch, PathMatchKind};
use gateway_state::{ActiveBackend, ActiveHttpListener, ActiveHttpRoute, BindKey, Store};
use http::{HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpStream;

use crate::lb::{EndpointInfo, LoadBalancer};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ResponseBody = BoxBody<Bytes, BoxError>;

/// Process-wide HTTP client used to dial upstreams. Wraps
/// `hyper_util::client::legacy::Client` — internally it owns a
/// connection pool that is shared across every cloned handle.
///
/// TODO: replace hyper's legacy client pool with our own
/// destination-keyed pool.
/// Hyper's default pool is hostname-keyed, isn't connect-failure-
/// aware, and gives us no control over idle limits per destination.
#[derive(Clone)]
pub struct HttpClient {
    inner: hyper_util::client::legacy::Client<HttpConnector, Incoming>,
}

impl Default for HttpClient {
    fn default() -> Self {
        let inner = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .build_http::<Incoming>();
        Self { inner }
    }
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient").finish_non_exhaustive()
    }
}

// =================== filter trait + impls ===================

/// Runtime-side HTTP filter contract. Each
/// `gateway_config::filter::HttpFilter` variant maps to one impl of
/// this trait via [`build_http_filter`].
pub(crate) trait HttpFilter: Send + Sync {
    fn apply_request_headers(
        &self,
        parts: &mut http::request::Parts,
    ) -> Result<HttpFilterDecision, FilterError>;
}

pub(crate) enum HttpFilterDecision {
    Continue,
    // Future: Respond(LocalHttpResponse),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum FilterError {
    #[error("invalid header name `{0}`")]
    InvalidHeaderName(String),
    #[error("invalid header value for `{0}`")]
    InvalidHeaderValue(String),
}

/// Build a runtime filter trait object from a config-shaped variant.
fn build_http_filter(cfg: &HttpFilterConfig) -> Arc<dyn HttpFilter> {
    match cfg {
        HttpFilterConfig::RequestHeaderModifier {
            request_headers, ..
        } => Arc::new(RequestHeaderModifierFilter {
            ops: request_headers.clone(),
        }),
    }
}

struct RequestHeaderModifierFilter {
    ops: RequestHeaderOps,
}

impl HttpFilter for RequestHeaderModifierFilter {
    fn apply_request_headers(
        &self,
        parts: &mut http::request::Parts,
    ) -> Result<HttpFilterDecision, FilterError> {
        for HeaderPair { name, value } in &self.ops.set {
            let header_name = HeaderName::try_from(name.as_str())
                .map_err(|_| FilterError::InvalidHeaderName(name.clone()))?;
            let header_value = HeaderValue::try_from(value.as_str())
                .map_err(|_| FilterError::InvalidHeaderValue(name.clone()))?;
            parts.headers.insert(header_name, header_value);
        }
        for HeaderPair { name, value } in &self.ops.add {
            let header_name = HeaderName::try_from(name.as_str())
                .map_err(|_| FilterError::InvalidHeaderName(name.clone()))?;
            let header_value = HeaderValue::try_from(value.as_str())
                .map_err(|_| FilterError::InvalidHeaderValue(name.clone()))?;
            parts.headers.append(header_name, header_value);
        }
        for name in &self.ops.remove {
            if let Ok(n) = HeaderName::try_from(name.as_str()) {
                parts.headers.remove(n);
            }
        }
        Ok(HttpFilterDecision::Continue)
    }
}

// =================== connection + request handlers ===================

/// Handle one accepted plaintext-HTTP downstream connection.
///
/// `auto::Builder::serve_connection_with_upgrades` peeks the first
/// bytes for the HTTP/2 preface and wires the H2 codec on match,
/// otherwise HTTP/1.1. This is the same wiring agent gateway uses; it
/// removes any need for the gateway itself to distinguish H1 from H2C.
pub(crate) async fn handle_connection(
    store: Store,
    bind_key: BindKey,
    stream: TcpStream,
    peer: SocketAddr,
    lb: Arc<LoadBalancer>,
    client: HttpClient,
) {
    tracing::debug!(bind = %bind_key, %peer, "http connection accepted");

    let io = TokioIo::new(stream);
    let svc = service_fn(move |req: Request<Incoming>| {
        let store = store.clone();
        let bind_key = bind_key.clone();
        let lb = Arc::clone(&lb);
        let client = client.clone();
        async move {
            let resp = serve_request(store, bind_key, lb, client, req).await;
            Ok::<_, Infallible>(resp)
        }
    });

    let builder = auto::Builder::new(TokioExecutor::new());
    if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
        tracing::debug!(%peer, error = %e, "http connection terminated");
    }
}

/// Top-level per-request handler. Resolves a route, applies filters,
/// dials a backend endpoint, forwards the request, and returns the
/// upstream's response (or a synthesized error response on any failure).
async fn serve_request(
    store: Store,
    bind_key: BindKey,
    lb: Arc<LoadBalancer>,
    client: HttpClient,
    req: Request<Incoming>,
) -> Response<ResponseBody> {
    let host = host_from_request(&req).map(str::to_owned);
    let path = req.uri().path().to_owned();

    let resolved = match resolve_http_route(&store, &bind_key, host.as_deref(), &path) {
        Ok(r) => r,
        Err(e) => return synthesize_error(e),
    };

    let (mut parts, body) = req.into_parts();
    for cfg in &resolved.filters {
        let filter = build_http_filter(cfg);
        match filter.apply_request_headers(&mut parts) {
            Ok(HttpFilterDecision::Continue) => {}
            Err(e) => {
                tracing::warn!(error = %e, "failed to apply request filter");
                return synthesize_status(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }
    let req = Request::from_parts(parts, body);

    let Some((endpoint, info)) = lb.pick_endpoint(&resolved.backend) else {
        return synthesize_status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let _active = info.acquire();

    tracing::debug!(
        bind = %bind_key,
        route = %resolved.route_name,
        endpoint = %endpoint.name,
        upstream = %format!("{}:{}", endpoint.address, endpoint.port),
        "http request routed"
    );

    forward(&client, req, &endpoint, &info).await
}

// =================== route resolution ===================

struct ResolvedRoute {
    backend: Arc<ActiveBackend>,
    filters: Vec<HttpFilterConfig>,
    route_name: String,
}

/// Walk `bind → listeners → routes` and pick:
///  1. the HTTP listener whose `hostname` matches the request `Host` /
///     `:authority` (exact host preferred over the empty-host catch-all);
///  2. the route under that listener with the longest matching path
///     prefix (tiebreak by route name order, which the store sorts at
///     placement time).
fn resolve_http_route(
    store: &Store,
    bind_key: &BindKey,
    host: Option<&str>,
    path: &str,
) -> Result<ResolvedRoute, RouteResolveError> {
    let read = store.read();
    let bind = read.bind(bind_key).ok_or(RouteResolveError::BindGone)?;

    let host_only = host.map(strip_port);

    let listener =
        pick_http_listener(&bind.listeners, host_only).ok_or(RouteResolveError::NoListener)?;

    let chosen =
        pick_http_route(&listener.routes, host_only, path).ok_or(RouteResolveError::NoRoute)?;

    let backend_ref = chosen
        .backends
        .first()
        .ok_or(RouteResolveError::NoBackend)?;
    if backend_ref.backend.endpoints.is_empty() {
        return Err(RouteResolveError::NoEndpoint);
    }

    Ok(ResolvedRoute {
        backend: Arc::clone(&backend_ref.backend),
        filters: chosen.filters.clone(),
        route_name: chosen.key.name.clone(),
    })
}

fn pick_http_listener<'a>(
    listeners: &'a [Arc<ActiveHttpListener>],
    host: Option<&str>,
) -> Option<&'a ActiveHttpListener> {
    let mut exact: Option<&ActiveHttpListener> = None;
    let mut catchall: Option<&ActiveHttpListener> = None;
    for l in listeners {
        match (&l.hostname, host) {
            (Some(want), Some(got)) if want.eq_ignore_ascii_case(got) && exact.is_none() => {
                exact = Some(l.as_ref());
            }
            (None, _) if catchall.is_none() => {
                catchall = Some(l.as_ref());
            }
            _ => {}
        }
    }
    exact.or(catchall)
}

fn pick_http_route<'a>(
    routes: &'a [Arc<ActiveHttpRoute>],
    host: Option<&str>,
    path: &str,
) -> Option<&'a Arc<ActiveHttpRoute>> {
    let mut best: Option<(usize, &Arc<ActiveHttpRoute>)> = None;
    for r in routes {
        if let Some(len) = best_match_score(&r.matches, host, path) {
            match best {
                Some((cur, _)) if len <= cur => {}
                _ => best = Some((len, r)),
            }
        }
    }
    best.map(|(_, r)| r)
}

/// Return the longest matching path-prefix length across all of a
/// route's `HttpMatch` entries; `None` if no entry matches.
fn best_match_score(matches: &[HttpMatch], host: Option<&str>, path: &str) -> Option<usize> {
    let mut best: Option<usize> = None;
    for m in matches {
        if let Some(want) = m.host.as_deref() {
            match host {
                Some(got) if want.eq_ignore_ascii_case(got) => {}
                _ => continue,
            }
        }
        if let Some(len) = score_path(&m.path, path) {
            best = Some(best.map_or(len, |cur| cur.max(len)));
        }
    }
    best
}

fn score_path(pm: &PathMatch, path: &str) -> Option<usize> {
    match pm.kind {
        PathMatchKind::PathPrefix => {
            let prefix = pm.value.as_str();
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
    }
}

fn strip_port(authority: &str) -> &str {
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _port)| host)
}

fn host_from_request<B>(req: &Request<B>) -> Option<&str> {
    if let Some(auth) = req.uri().authority() {
        return Some(auth.as_str());
    }
    req.headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
}

// =================== upstream forward ===================

/// Rewrite `req` to target `endpoint` and forward it via the shared
/// hyper client. On dial failure the endpoint's failure counter is
/// incremented and a 502 is returned downstream.
async fn forward(
    client: &HttpClient,
    mut req: Request<Incoming>,
    endpoint: &Endpoint,
    info: &Arc<EndpointInfo>,
) -> Response<ResponseBody> {
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
            return synthesize_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    *req.uri_mut() = upstream_uri;
    // Force the outgoing request to HTTP/1.1: the upstream client is
    // configured for HTTP/1.1 only in v0. The incoming version (which
    // may be HTTP/2 when the downstream codec was H2) is independent
    // of the upstream wire protocol. Per-backend HTTPS / scheme
    // negotiation is deferred.
    *req.version_mut() = http::Version::HTTP_11;

    let dial_start = Instant::now();
    let upstream_resp = match client.inner.request(req).await {
        Ok(r) => {
            let dial_ms = dial_start.elapsed().as_secs_f64() * 1000.0;
            info.record_success(dial_ms);
            r
        }
        Err(e) => {
            info.record_failure();
            tracing::warn!(error = %e, "upstream dial failed");
            return synthesize_status(StatusCode::BAD_GATEWAY);
        }
    };

    let (parts, body) = upstream_resp.into_parts();
    let boxed: ResponseBody = body.map_err(|e| Box::new(e) as BoxError).boxed();
    Response::from_parts(parts, boxed)
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
    #[error("backend has no endpoints")]
    NoEndpoint,
}

fn synthesize_error(err: RouteResolveError) -> Response<ResponseBody> {
    let status = match err {
        RouteResolveError::BindGone | RouteResolveError::NoListener => {
            StatusCode::MISDIRECTED_REQUEST
        }
        RouteResolveError::NoRoute => StatusCode::NOT_FOUND,
        RouteResolveError::NoBackend | RouteResolveError::NoEndpoint => {
            StatusCode::SERVICE_UNAVAILABLE
        }
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
        PathMatch {
            kind: PathMatchKind::PathPrefix,
            value: v.into(),
        }
    }

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
    fn strip_port_with_port() {
        assert_eq!(strip_port("example.com:443"), "example.com");
    }

    #[test]
    fn strip_port_without_port() {
        assert_eq!(strip_port("example.com"), "example.com");
    }

    #[test]
    fn best_match_uses_longest_prefix() {
        let matches = vec![
            HttpMatch {
                host: None,
                path: pm("/api"),
            },
            HttpMatch {
                host: None,
                path: pm("/api/v2"),
            },
        ];
        assert_eq!(best_match_score(&matches, None, "/api/v2/foo"), Some(7));
    }

    #[test]
    fn best_match_filters_on_host() {
        let matches = vec![HttpMatch {
            host: Some("a.example.com".into()),
            path: pm("/"),
        }];
        assert!(best_match_score(&matches, Some("b.example.com"), "/").is_none());
        assert_eq!(
            best_match_score(&matches, Some("a.example.com"), "/"),
            Some(1)
        );
    }
}
