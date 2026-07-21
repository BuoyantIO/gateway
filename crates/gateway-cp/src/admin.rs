//! Admin HTTP server: the probe endpoints kubelet hits.
//!
//! `GET /healthz/ready` answers 200 once the watch loop has finished
//! a full pass with every reflector past its initial sync — the
//! point where a connecting data plane gets a bootstrap derived from
//! complete cluster state. Before that it answers 503 and names the
//! kinds still waiting. On shutdown it flips back to 503 so a
//! draining pod leaves the Service endpoints before its streams
//! close.
//!
//! `GET /healthz/alive` answers 200 unconditionally: liveness means
//! "the process and its runtime respond", nothing deeper.

use std::convert::Infallible;
use std::future::Future;
use std::pin::pin;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// What the readiness endpoint reports. Starts with every kind
/// pending; the watch loop trims the list as reflectors deliver
/// their initial state and marks shutdown when draining begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyState {
    /// Resource kinds still waiting for their initial sync.
    pub pending: Vec<&'static str>,
    pub shutting_down: bool,
}

impl ReadyState {
    pub fn is_ready(&self) -> bool {
        self.pending.is_empty() && !self.shutting_down
    }
}

/// Accept loop on an already-bound listener (binding stays in
/// `main` so a bad `--admin-addr` fails startup instead of leaving
/// a silently unready pod). Runs until `shutdown` resolves.
pub async fn serve(
    listener: TcpListener,
    ready: watch::Receiver<ReadyState>,
    shutdown: impl Future<Output = ()>,
) {
    let mut shutdown = pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => return,
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::warn!(error = %e, "admin accept failed");
                        continue;
                    }
                };
                let ready = ready.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let state = ready.borrow().clone();
                        let response = respond(req.method(), req.uri().path(), &state);
                        async move { Ok::<_, Infallible>(response) }
                    });
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        tracing::debug!(error = %e, "admin connection error");
                    }
                });
            }
        }
    }
}

fn respond(method: &Method, path: &str, state: &ReadyState) -> Response<Full<Bytes>> {
    if *method != Method::GET && *method != Method::HEAD {
        return response(StatusCode::NOT_FOUND, Bytes::from_static(b"not found\n"));
    }
    match path {
        "/healthz/alive" => response(StatusCode::OK, Bytes::from_static(b"alive\n")),
        "/healthz/ready" if state.is_ready() => {
            response(StatusCode::OK, Bytes::from_static(b"ready\n"))
        }
        "/healthz/ready" => {
            let body = if state.shutting_down {
                "shutting down\n".to_string()
            } else {
                format!("not ready, pending: {}\n", state.pending.join(", "))
            };
            response(StatusCode::SERVICE_UNAVAILABLE, Bytes::from(body))
        }
        _ => response(StatusCode::NOT_FOUND, Bytes::from_static(b"not found\n")),
    }
}

fn response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(body))
        .expect("static response parts are valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn pending(kinds: &[&'static str]) -> ReadyState {
        ReadyState {
            pending: kinds.to_vec(),
            shutting_down: false,
        }
    }

    async fn spawn_admin(ready: watch::Receiver<ReadyState>) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, ready, std::future::pending()));
        addr
    }

    async fn get(addr: std::net::SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nhost: test\r\nconnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn ready_names_pending_kinds_then_flips() {
        let (tx, rx) = watch::channel(pending(&["Gateway", "Secret"]));
        let addr = spawn_admin(rx).await;

        let response = get(addr, "/healthz/ready").await;
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(response.contains("pending: Gateway, Secret"), "{response}");

        tx.send_replace(pending(&[]));
        let response = get(addr, "/healthz/ready").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    #[tokio::test]
    async fn shutdown_goes_unready() {
        let (tx, rx) = watch::channel(pending(&[]));
        let addr = spawn_admin(rx).await;

        let response = get(addr, "/healthz/ready").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        tx.send_replace(ReadyState {
            pending: Vec::new(),
            shutting_down: true,
        });
        let response = get(addr, "/healthz/ready").await;
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(response.contains("shutting down"), "{response}");
    }

    #[tokio::test]
    async fn alive_is_unconditional() {
        let (_tx, rx) = watch::channel(pending(&["Gateway"]));
        let addr = spawn_admin(rx).await;

        let response = get(addr, "/healthz/alive").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    #[tokio::test]
    async fn unknown_path_is_404() {
        let (_tx, rx) = watch::channel(pending(&[]));
        let addr = spawn_admin(rx).await;

        let response = get(addr, "/nope").await;
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }
}
