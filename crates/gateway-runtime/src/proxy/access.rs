//! Per-request access logging, in one type.
//!
//! [`Access`] owns a request's observability: `begin` captures the
//! request facts; `finish` emits the `"request"` line and records
//! the metrics at response headers, then rides the response body to
//! emit the `"stream end"` line — measured bytes, full duration,
//! completion flag, gRPC trailer status — when the stream finishes.
//! Both lines use the `access` target at info
//! (`RUST_LOG=info,access=off` silences them).
//!
//! The end line fires from `Drop`, so an abandoned stream still
//! logs (`complete=false`). A client that disconnects before
//! response headers logs nothing.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http::{Request, Response};
use http_body::{Body, Frame};

use crate::metrics::{Metrics, Reason};

use super::body::BoxError;
use super::http::ResponseBody;

/// Label value when no listener/route matched; mirrors the metric
/// labels.
const UNKNOWN: &str = "unknown";

/// What the serving path learned about one request. Identity fields
/// stay `None` when the request never matched.
pub(crate) struct RequestOutcome {
    pub(crate) listener: Option<String>,
    pub(crate) route: Option<String>,
    pub(crate) reason: Reason,
    /// `{address}:{port}` of the picked upstream endpoint.
    pub(crate) endpoint: Option<String>,
    /// Upstream dial time, as measured for the balancer's EWMA.
    pub(crate) dial_ms: Option<f64>,
}

impl RequestOutcome {
    /// An outcome that ended before reaching an upstream.
    pub(crate) fn short_circuit(
        listener: Option<&str>,
        route: Option<&str>,
        reason: Reason,
    ) -> Self {
        Self {
            listener: listener.map(str::to_owned),
            route: route.map(str::to_owned),
            reason,
            endpoint: None,
            dial_ms: None,
        }
    }
}

/// The access record of one request, from arrival to end of the
/// response stream.
pub(crate) struct Access {
    metrics: Arc<Metrics>,
    bind: String,
    client: SocketAddr,
    method: String,
    host: String,
    path: String,
    user_agent: String,
    start: Instant,
}

impl Access {
    /// Capture the request-side facts. Call before serving.
    pub(crate) fn begin<B>(
        metrics: Arc<Metrics>,
        bind: &str,
        client: SocketAddr,
        req: &Request<B>,
    ) -> Self {
        let host = super::http::host_from_request(req)
            .unwrap_or_default()
            .to_owned();
        let user_agent = req
            .headers()
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        Self {
            metrics,
            bind: bind.to_owned(),
            client,
            method: req.method().to_string(),
            host,
            path: req.uri().path().to_owned(),
            user_agent,
            start: Instant::now(),
        }
    }

    /// Response headers are ready: emit the `"request"` line, record
    /// the request metrics, and wrap the response body so the
    /// `"stream end"` line fires when the stream finishes.
    pub(crate) fn finish(
        self,
        outcome: RequestOutcome,
        resp: Response<ResponseBody>,
    ) -> Response<ResponseBody> {
        let status = resp.status().as_u16();
        let setup = self.start.elapsed();
        let listener = outcome.listener.unwrap_or_else(|| UNKNOWN.to_owned());
        let route = outcome.route.unwrap_or_else(|| UNKNOWN.to_owned());

        tracing::info!(
            target: "access",
            bind = %self.bind,
            listener = %listener,
            route = %route,
            client = %self.client,
            method = %self.method,
            host = %self.host,
            path = %self.path,
            status,
            reason = outcome.reason.as_str(),
            endpoint = outcome.endpoint.as_deref().unwrap_or(""),
            dial_ms = outcome.dial_ms.unwrap_or(0.0),
            duration_ms = setup.as_secs_f64() * 1000.0,
            user_agent = %self.user_agent,
            "request"
        );
        self.metrics.record_request(
            &self.bind,
            Some(&listener),
            Some(&route),
            status,
            outcome.reason,
            setup,
        );

        let (parts, body) = resp.into_parts();
        // A trailers-only gRPC error puts grpc-status in the headers
        // and ends the body before it is ever polled — seed from the
        // headers and emit immediately.
        let header_grpc_status = parts
            .headers
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut logged = LoggedBody {
            inner: body,
            end: Some(EndLine {
                access: self,
                listener,
                route,
                status,
            }),
            bytes: 0,
            grpc_status: header_grpc_status,
            complete: false,
        };
        if logged.inner.is_end_stream() {
            logged.complete = true;
            logged.emit();
        }
        Response::from_parts(parts, ResponseBody::new(logged))
    }
}

/// Everything the end line needs, moved into the body wrapper.
struct EndLine {
    access: Access,
    listener: String,
    route: String,
    status: u16,
}

/// Response body that emits the `"stream end"` line when the stream
/// completes — or, via `Drop`, when it's abandoned mid-flight.
struct LoggedBody {
    inner: ResponseBody,
    /// Taken when the end line is emitted; still `Some` in `Drop`
    /// means the stream never completed.
    end: Option<EndLine>,
    bytes: u64,
    grpc_status: Option<String>,
    complete: bool,
}

impl LoggedBody {
    fn emit(&mut self) {
        let Some(end) = self.end.take() else {
            return;
        };
        tracing::info!(
            target: "access",
            bind = %end.access.bind,
            listener = %end.listener,
            route = %end.route,
            client = %end.access.client,
            method = %end.access.method,
            host = %end.access.host,
            path = %end.access.path,
            status = end.status,
            bytes = self.bytes,
            duration_ms = end.access.start.elapsed().as_secs_f64() * 1000.0,
            complete = self.complete,
            grpc_status = self.grpc_status.as_deref().unwrap_or(""),
            "stream end"
        );
    }
}

impl Body for LoggedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes += data.len() as u64;
                } else if let Some(trailers) = frame.trailers_ref()
                    && let Some(v) = trailers.get("grpc-status")
                    && let Ok(s) = v.to_str()
                {
                    this.grpc_status = Some(s.to_owned());
                }
                // Content-length bodies end via is_end_stream after
                // the last frame; their final `None` is never polled.
                if this.inner.is_end_stream() {
                    this.complete = true;
                    this.emit();
                }
            }
            Poll::Ready(None) => {
                this.complete = true;
                this.emit();
            }
            Poll::Ready(Some(Err(_))) | Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for LoggedBody {
    fn drop(&mut self) {
        // Still armed here means the stream never completed.
        self.emit();
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Mutex;

    use http_body_util::{BodyExt, Full};

    use super::*;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Capture {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Capture {
            self.clone()
        }
    }

    /// Installs a capturing subscriber as the thread default and
    /// returns it with its buffer; the guard must outlive the events.
    fn capture() -> (Capture, tracing::subscriber::DefaultGuard) {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (capture, guard)
    }

    fn begin() -> Access {
        let req = Request::builder()
            .method("GET")
            .uri("http://app.example/p")
            .header("host", "app.example")
            .header("user-agent", "test-agent/1.0")
            .body(())
            .unwrap();
        Access::begin(Metrics::new(), "b1", "10.1.2.3:5555".parse().unwrap(), &req)
    }

    fn outcome() -> RequestOutcome {
        RequestOutcome {
            listener: Some("web".into()),
            route: Some("route-a".into()),
            reason: Reason::Ok,
            endpoint: Some("10.0.0.9:8080".into()),
            dial_ms: Some(1.5),
        }
    }

    fn response(body: &'static [u8]) -> Response<ResponseBody> {
        Response::new(
            Full::new(Bytes::from_static(body))
                .map_err(|never: std::convert::Infallible| match never {})
                .boxed_unsync(),
        )
    }

    #[tokio::test]
    async fn completed_response_emits_start_and_end_lines() {
        let (out, _guard) = capture();
        let mut resp = begin().finish(outcome(), response(b"hello world"));
        while let Some(frame) = resp.body_mut().frame().await {
            frame.unwrap();
        }
        drop(resp);

        let out = out.contents();
        assert_eq!(out.matches("access: request").count(), 1, "{out}");
        assert_eq!(out.matches("stream end").count(), 1, "{out}");
        for part in [
            "route=route-a",
            "listener=web",
            "reason=\"ok\"",
            "endpoint=\"10.0.0.9:8080\"",
            "user_agent=test-agent/1.0",
            "bytes=11",
            "complete=true",
        ] {
            assert!(out.contains(part), "{part} missing in {out}");
        }
    }

    #[tokio::test]
    async fn unmatched_request_logs_unknown_identity() {
        let (out, _guard) = capture();
        let resp = begin().finish(
            RequestOutcome::short_circuit(None, None, Reason::NoRoute),
            response(b"not found"),
        );
        drop(resp);

        let out = out.contents();
        assert!(out.contains("listener=unknown"), "{out}");
        assert!(out.contains("route=unknown"), "{out}");
        assert!(out.contains("reason=\"no_route\""), "{out}");
    }

    #[tokio::test]
    async fn abandoned_body_emits_incomplete_end_line() {
        let (out, _guard) = capture();
        let resp = begin().finish(outcome(), response(b"hello"));
        // dropped without being polled: the client went away
        drop(resp);

        let out = out.contents();
        assert_eq!(out.matches("stream end").count(), 1, "{out}");
        assert!(out.contains("complete=false"), "{out}");
        assert!(out.contains("bytes=0"), "{out}");
    }

    #[tokio::test]
    async fn trailers_only_response_emits_completed_end_line() {
        let (out, _guard) = capture();
        // Empty body (end_stream from the start) with grpc-status in
        // the response headers — the trailers-only gRPC error shape.
        let body: ResponseBody = http_body_util::Empty::new()
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed_unsync();
        let resp = Response::builder()
            .status(200)
            .header("grpc-status", "13")
            .body(body)
            .unwrap();
        drop(begin().finish(outcome(), resp));

        let out = out.contents();
        assert_eq!(out.matches("stream end").count(), 1, "{out}");
        assert!(out.contains("complete=true"), "{out}");
        assert!(out.contains("grpc_status=\"13\""), "{out}");
    }

    #[tokio::test]
    async fn trailers_carry_grpc_status_onto_the_end_line() {
        let (out, _guard) = capture();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "7".parse().unwrap());
        let frames: Vec<Result<Frame<Bytes>, BoxError>> = vec![
            Ok(Frame::data(Bytes::from_static(b"msg"))),
            Ok(Frame::trailers(trailers)),
        ];
        let body: ResponseBody =
            http_body_util::StreamBody::new(futures::stream::iter(frames)).boxed_unsync();
        let mut resp = begin().finish(outcome(), Response::new(body));
        while let Some(frame) = resp.body_mut().frame().await {
            frame.unwrap();
        }
        drop(resp);

        let out = out.contents();
        assert!(out.contains("grpc_status=\"7\""), "{out}");
        assert!(out.contains("complete=true"), "{out}");
        assert!(out.contains("bytes=3"), "{out}");
    }
}
