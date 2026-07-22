//! Graceful drain integration tests. A slow upstream keeps requests
//! in flight while shutdown (or a bind teardown) starts; the gateway
//! must finish that work — `Connection: close` on HTTP/1, GOAWAY on
//! HTTP/2 — instead of cutting it, and must stop accepting afterward.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use bytes::Bytes;
use gateway_config::backend::{Backend, BackendProtocol, BackendRef, Endpoint, StaticBackend};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::config::GatewayConfig;
use gateway_config::listener::{HttpListener as SchemaHttpListener, Listener};
use gateway_config::route::{HttpMatch, HttpRoute, PathMatch};
use gateway_runtime::{Gateway, drain};
use gateway_state::{BindKey, Store};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// How long the slow upstream holds each request before answering.
const UPSTREAM_DELAY: Duration = Duration::from_millis(500);
const GRACE: Duration = Duration::from_secs(5);

/// Echo server that sleeps before answering, keeping requests
/// in flight long enough for a drain to start under them.
async fn spawn_slow_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async {
                    tokio::time::sleep(UPSTREAM_DELAY).await;
                    Ok::<_, Infallible>(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from_static(b"slow ok")))
                            .unwrap(),
                    )
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    port
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

fn bind(name: &str, port: u16, backend: &str) -> Bind {
    Bind {
        name: name.into(),
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        bind_protocol: BindProtocol::Http,
        listeners: vec![Listener::Http(SchemaHttpListener {
            name: "l".into(),
            hostname: None,
            routes: vec![HttpRoute {
                name: "r".into(),
                matches: vec![HttpMatch {
                    host: None,
                    path: PathMatch::PathPrefix { value: "/".into() },
                    method: None,
                    headers: vec![],
                    query_params: vec![],
                }],
                backend_refs: vec![BackendRef {
                    name: backend.into(),
                    weight: 1,
                }],
                filters: vec![],
            }],
        })],
    }
}

fn config(binds: Vec<Bind>, upstream_port: u16) -> GatewayConfig {
    GatewayConfig {
        name: "test".into(),
        binds,
        backends: vec![Backend::Static(StaticBackend {
            name: "be".into(),
            endpoints: vec![Endpoint {
                name: "e0".into(),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: upstream_port,
            }],
            protocol: BackendProtocol::Http1,
        })],
        secrets: vec![],
    }
}

async fn wait_for_listening(port: u16) {
    for _ in 0..40 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("gateway did not start listening on port {port}");
}

fn spawn_gateway(store: Store) -> (JoinHandle<()>, drain::Signal) {
    let (signal, watch) = drain::channel();
    let gw = Gateway::new(store);
    let handle = tokio::spawn(async move {
        gw.run(watch).await.unwrap();
    });
    (handle, signal)
}

fn get(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Empty<Bytes>>,
    port: u16,
) -> impl Future<Output = Result<StatusCode, String>> + use<> {
    let req = Request::builder()
        .uri(format!("http://127.0.0.1:{port}/"))
        .body(Empty::new())
        .unwrap();
    let client = client.clone();
    async move {
        let resp = client.request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status();
        let _ = resp.into_body().collect().await;
        Ok(status)
    }
}

#[tokio::test]
async fn h1_drain_answers_connection_close_then_closes_the_socket() {
    let upstream = spawn_slow_echo().await;
    let port = free_port().await;
    let store = Store::new();
    let _ = store.apply(&config(vec![bind("b", port, "be")], upstream));

    let (gw_handle, signal) = spawn_gateway(store);
    wait_for_listening(port).await;

    // Raw keep-alive HTTP/1.1 request so the response bytes are
    // observable: draining must add `connection: close` and then
    // actually close the socket (EOF), not leave keep-alive open.
    let mut raw = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    raw.write_all(b"GET / HTTP/1.1\r\nhost: test\r\n\r\n")
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(150)).await;
    let drained = tokio::spawn(tokio::time::timeout(GRACE, signal.drain()));

    let mut response = String::new();
    tokio::time::timeout(GRACE, raw.read_to_string(&mut response))
        .await
        .expect("response should arrive before the deadline")
        .expect("read to EOF");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let headers = response.to_ascii_lowercase();
    assert!(
        headers.contains("connection: close"),
        "drained HTTP/1.1 response must carry connection: close: {response}"
    );

    gw_handle.await.unwrap();
    drained.await.unwrap().expect("drain should complete");

    // The drained gateway no longer accepts new connections.
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
}

#[tokio::test]
async fn h2_drain_sends_goaway_after_in_flight_stream() {
    let upstream = spawn_slow_echo().await;
    let port = free_port().await;
    let store = Store::new();
    let _ = store.apply(&config(vec![bind("b", port, "be")], upstream));

    let (gw_handle, signal) = spawn_gateway(store);
    wait_for_listening(port).await;

    // Raw h2 client: GOAWAY is observable as the connection finishing
    // cleanly (no error) while new streams are refused with a GOAWAY
    // error, after the in-flight stream completed.
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut send_request, connection) = h2::client::handshake(tcp).await.unwrap();
    let conn_task = tokio::spawn(connection);

    let req = Request::builder()
        .uri(format!("http://127.0.0.1:{port}/"))
        .body(())
        .unwrap();
    let (response, _) = send_request.send_request(req, true).unwrap();

    tokio::time::sleep(Duration::from_millis(150)).await;
    let drained = tokio::spawn(tokio::time::timeout(GRACE, signal.drain()));

    // The in-flight stream completes...
    let response = tokio::time::timeout(GRACE, response)
        .await
        .expect("stream should finish before the deadline")
        .expect("in-flight stream must complete");
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    while let Some(chunk) = body.data().await {
        let _ = chunk.expect("body chunk");
    }

    // ...the session ends cleanly (GOAWAY, not a reset: a reset would
    // surface as an error from the connection future)...
    tokio::time::timeout(GRACE, conn_task)
        .await
        .expect("connection should close after drain")
        .unwrap()
        .expect("connection must close cleanly via GOAWAY, not an error");

    // ...and a new stream on the drained session is refused with the
    // GOAWAY error, not accepted.
    let err = tokio::time::timeout(GRACE, send_request.ready())
        .await
        .expect("readiness should resolve")
        .expect_err("new streams must be refused after GOAWAY");
    assert!(err.is_go_away(), "expected GOAWAY error, got: {err}");

    gw_handle.await.unwrap();
    drained.await.unwrap().expect("drain should complete");
}

#[tokio::test]
async fn bind_removal_drains_its_connections_only() {
    let upstream = spawn_slow_echo().await;
    let port_a = free_port().await;
    let port_b = free_port().await;
    let store = Store::new();
    let _ = store.apply(&config(
        vec![bind("a", port_a, "be"), bind("b", port_b, "be")],
        upstream,
    ));

    let (gw_handle, signal) = spawn_gateway(store.clone());
    wait_for_listening(port_a).await;
    wait_for_listening(port_b).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let in_flight = tokio::spawn(get(&client, port_a));

    tokio::time::sleep(Duration::from_millis(150)).await;
    store.remove_bind(&BindKey::new("a"));

    // The in-flight request on the removed bind still completes...
    let status = in_flight
        .await
        .unwrap()
        .expect("in-flight request must complete");
    assert_eq!(status, StatusCode::OK);

    // ...new connections to it are refused once the accept task stops...
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(TcpStream::connect(("127.0.0.1", port_a)).await.is_err());

    // ...and the untouched bind keeps serving.
    let status = get(&client, port_b).await.expect("bind b still serves");
    assert_eq!(status, StatusCode::OK);

    drop(signal);
    gw_handle.await.unwrap();
}
