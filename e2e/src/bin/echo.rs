//! Test echo backend. Mirrors the in-process echo used by
//! `crates/gateway-runtime/tests/http_forward.rs::spawn_http_echo`.
//!
//! Replies 200 with body `"{method} {path}"`, reflects every
//! `X-Test-*` request header as `X-Echo-*` on the response, emits an
//! `X-Server-Version` header naming the HTTP wire version it spoke,
//! and an `X-Echo-Pod` header carrying `$HOSTNAME` (the pod name in
//! Kubernetes) so tests can observe which replica served. Uses
//! `hyper_util::server::conn::auto::Builder` so HTTP/1.1 and HTTP/2
//! (prior knowledge / h2c) both work.

use std::convert::Infallible;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let bind = std::env::var("ECHO_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let pod: &'static str = std::env::var("HOSTNAME").unwrap_or_default().leak();
    let listener = TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "echo server listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<Incoming>| async move {
                let method = req.method().to_string();
                let path = req.uri().path().to_string();
                let server_version = format!("{:?}", req.version());
                // `?delay-ms=N` holds the response, keeping a request
                // in flight for drain tests.
                if let Some(ms) = req
                    .uri()
                    .query()
                    .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("delay-ms=")))
                    .and_then(|v| v.parse::<u64>().ok())
                {
                    tokio::time::sleep(std::time::Duration::from_millis(ms.min(30_000))).await;
                }
                let mut echoed: Vec<(String, String)> = Vec::new();
                for (k, v) in req.headers() {
                    let name = k.as_str().to_ascii_lowercase();
                    if let Some(rest) = name.strip_prefix("x-test-")
                        && let Ok(value) = v.to_str()
                    {
                        echoed.push((format!("x-echo-{rest}"), value.to_owned()));
                    }
                }
                let body_text = format!("{method} {path}");
                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header("x-server-version", server_version)
                    .header("x-echo-pod", pod);
                for (k, v) in echoed {
                    builder = builder.header(k, v);
                }
                let resp = builder
                    .body(Full::new(Bytes::from(body_text)))
                    .expect("well-formed");
                Ok::<_, Infallible>(resp)
            });
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await
            {
                tracing::debug!(%peer, error = %e, "echo connection terminated");
            }
        });
    }
}
