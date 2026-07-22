//! Admin HTTP server: the readiness endpoint kubelet probes hit.
//!
//! `GET /healthz/ready` answers 200 once the data plane has applied
//! its config bootstrap (file config loaded, or the first
//! `sync_complete` batch from the control plane) and 503 before
//! that. A control-plane reconnect never flips it back, because the
//! store keeps serving its last state while the stream resyncs; the
//! one thing that does is shutdown, so a draining pod leaves the
//! Service endpoints while in-flight work finishes.

use std::convert::Infallible;
use std::pin::pin;

use gateway_runtime::drain;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// Accept loop on an already-bound listener (binding stays in
/// `main` so a bad `--admin-addr` fails startup instead of leaving
/// a silently unready pod). Runs until `drain` fires; in-flight
/// probe responses finish under the drain barrier like any other
/// connection.
pub async fn serve(listener: TcpListener, ready: watch::Receiver<bool>, drain: drain::Watch) {
    let mut stop = pin!(drain.clone().signaled());
    loop {
        tokio::select! {
            biased;
            _release = &mut stop => return,
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::warn!(error = %e, "admin accept failed");
                        continue;
                    }
                };
                let ready = ready.clone();
                let drain = drain.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let response = respond(req.method(), req.uri().path(), *ready.borrow());
                        async move { Ok::<_, Infallible>(response) }
                    });
                    let conn = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service);
                    let mut conn = pin!(conn);
                    let result = tokio::select! {
                        res = conn.as_mut() => res,
                        shutdown = drain.signaled() => {
                            conn.as_mut().graceful_shutdown();
                            let res = conn.await;
                            drop(shutdown);
                            res
                        }
                    };
                    if let Err(e) = result {
                        tracing::debug!(error = %e, "admin connection error");
                    }
                });
            }
        }
    }
}

fn respond(method: &Method, path: &str, ready: bool) -> Response<Full<Bytes>> {
    let is_probe = (*method == Method::GET || *method == Method::HEAD) && path == "/healthz/ready";
    let (status, body) = if is_probe {
        if ready {
            (StatusCode::OK, "ready\n")
        } else {
            (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
        }
    } else {
        (StatusCode::NOT_FOUND, "not found\n")
    };
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("static response parts are valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn spawn_admin(ready: watch::Receiver<bool>) -> (std::net::SocketAddr, drain::Signal) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (signal, watch) = drain::channel();
        tokio::spawn(serve(listener, ready, watch));
        (addr, signal)
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
    async fn not_ready_then_ready() {
        let (tx, rx) = watch::channel(false);
        let (addr, _stop) = spawn_admin(rx).await;

        let response = get(addr, "/healthz/ready").await;
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");

        tx.send_replace(true);
        let response = get(addr, "/healthz/ready").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    #[tokio::test]
    async fn unknown_path_is_404() {
        let (_tx, rx) = watch::channel(true);
        let (addr, _stop) = spawn_admin(rx).await;

        let response = get(addr, "/nope").await;
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }
}
