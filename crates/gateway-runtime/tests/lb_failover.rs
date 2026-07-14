//! P2C-EWMA failover integration test, HTTP edition.
//!
//! Spins up two hyper-based counting echo servers, points the gateway
//! at both via a single HTTP backend with two endpoints, drives traffic
//! through the gateway, kills one upstream, and asserts traffic shifts
//! to the survivor after the failure threshold trips eviction. Same
//! assertion shape as the TCP version that came before; only the
//! transport changed.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use gateway_config::GatewayConfig;
use gateway_config::backend::{Backend, BackendProtocol, BackendRef, Endpoint, StaticBackend};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::listener::{HttpListener as SchemaHttpListener, Listener};
use gateway_config::route::{HttpMatch, HttpRoute, PathMatch};
use gateway_runtime::Gateway;
use gateway_runtime::lb::{EndpointStateConfig, LoadBalancer, P2cConfig, P2cEwma};
use gateway_state::Store;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// HTTP echo server that counts requests it serves. Returns 200 OK
/// with a tiny body. Aborting the returned `JoinHandle` "kills" the
/// server — the accept loop exits, the listener is dropped, AND the
/// currently-being-served connection (if any) is dropped because
/// `serve_connection` is awaited inline.
///
/// Inline-serve serializes accepts (only one connection in flight at
/// a time). HTTP/1.1 keep-alive means a single client connection can
/// still pump many requests, which is what the gateway's upstream
/// pool does. Adequate for this test.
async fn spawn_counting_http() -> (u16, Arc<AtomicU64>, JoinHandle<()>) {
    spawn_counting_http_on(0).await
}

/// Like `spawn_counting_http` but binds a specific port (0 =
/// ephemeral). Lets a test restart an upstream at the same address.
async fn spawn_counting_http_on(port: u16) -> (u16, Arc<AtomicU64>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let counter = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&counter);
    let h = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let c = Arc::clone(&c);
            let io = TokioIo::new(stream);
            let svc = service_fn(move |_req: Request<Incoming>| {
                let c = Arc::clone(&c);
                async move {
                    c.fetch_add(1, Ordering::Relaxed);
                    Ok::<_, Infallible>(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .unwrap(),
                    )
                }
            });
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        }
    });
    (port, counter, h)
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
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

fn cfg_endpoints(bind_port: u16, ports: &[u16]) -> GatewayConfig {
    GatewayConfig {
        name: "test".into(),
        binds: vec![Bind {
            name: "b".into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: bind_port,
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
                        name: "be".into(),
                        weight: 1,
                    }],
                    filters: vec![],
                }],
            })],
        }],
        backends: vec![Backend::Static(StaticBackend {
            name: "be".into(),
            endpoints: ports
                .iter()
                .enumerate()
                .map(|(i, p)| Endpoint {
                    name: format!("e{i}"),
                    address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: *p,
                })
                .collect(),
            protocol: BackendProtocol::Http1,
        })],
        secrets: vec![],
    }
}

fn cfg_two_endpoints(bind_port: u16, p1: u16, p2: u16) -> GatewayConfig {
    cfg_endpoints(bind_port, &[p1, p2])
}

/// Drive one GET through the gateway. Returns the response status, or
/// an error if the *transport* itself failed (which should not happen
/// — failed upstreams manifest as 502 responses from the gateway,
/// not as client-side errors).
async fn round_trip(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Empty<Bytes>>,
    bind_port: u16,
) -> StatusCode {
    let resp = client
        .get(format!("http://127.0.0.1:{bind_port}/").parse().unwrap())
        .await
        .expect("request to gateway failed");
    let status = resp.status();
    // Drain the body so the client connection can be pooled / closed
    // cleanly rather than left half-read.
    let _ = resp.into_body().collect().await;
    status
}

#[tokio::test]
async fn p2c_distributes_then_evicts_failing_endpoint() {
    let (p1, c1, h1) = spawn_counting_http().await;
    let (p2, c2, _h2) = spawn_counting_http().await;
    let bind_port = free_port().await;

    let cfg = cfg_two_endpoints(bind_port, p1, p2);
    let store = Store::new();
    let _ = store.apply(&cfg);

    let picker = Arc::new(P2cEwma::new(P2cConfig {
        load_penalty: 0.1,
        latency_penalty_ms: 0.001,
    }));
    let state_cfg = EndpointStateConfig {
        ewma_alpha: 0.5,
        failure_threshold: 1,
        eviction_duration: Duration::from_secs(5),
    };
    let lb = LoadBalancer::with_picker(picker, state_cfg);
    let gateway = Gateway::with_lb(store, lb);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let gw_handle = tokio::spawn(async move {
        gateway
            .run(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    wait_for_listening(bind_port).await;

    // Build a client that does NOT pool connections to the gateway
    // — fresh per-request makes each request a fresh picker call
    // (otherwise hyper might pool the same downstream connection
    // and serialize requests through the same picked endpoint).
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build_http();

    // Phase 1: both endpoints up. Drive 20 requests; P2C should
    // sprinkle traffic across both.
    for _ in 0..20 {
        let status = round_trip(&client, bind_port).await;
        assert_eq!(status, StatusCode::OK, "phase 1 request should succeed");
    }
    let c1_pre = c1.load(Ordering::Relaxed);
    let c2_pre = c2.load(Ordering::Relaxed);
    assert!(c1_pre > 0, "endpoint 1 saw no traffic in phase 1: {c1_pre}");
    assert!(c2_pre > 0, "endpoint 2 saw no traffic in phase 1: {c2_pre}");
    assert_eq!(c1_pre + c2_pre, 20);

    // Phase 2: kill endpoint 1. After `failure_threshold = 1`,
    // endpoint 1 should be evicted and subsequent requests should land
    // on endpoint 2.
    h1.abort();
    // Give the abort a moment to actually close the listener.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut bad_gateway = 0;
    for _ in 0..30 {
        let status = round_trip(&client, bind_port).await;
        match status {
            StatusCode::OK => {}
            StatusCode::BAD_GATEWAY => bad_gateway += 1,
            other => panic!("unexpected status in phase 2: {other}"),
        }
    }
    let c2_after = c2.load(Ordering::Relaxed) - c2_pre;
    let c1_after = c1.load(Ordering::Relaxed) - c1_pre;

    // Endpoint 1 is dead, so its counter can't grow. Allow up to a
    // few 502s while the picker still tries the doomed endpoint
    // before eviction kicks in.
    assert!(
        bad_gateway <= 3,
        "too many 502s before eviction: {bad_gateway}"
    );
    assert_eq!(c1_after, 0, "endpoint 1 served requests after being killed");
    assert!(
        c2_after >= 25,
        "endpoint 2 didn't pick up the load: c2_after={c2_after}, bad_gateway={bad_gateway}"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

/// A single-endpoint backend must fail open. While the
/// endpoint is down every request gets a 502 (a real dial was
/// attempted — never a synthesized 503 from an empty pick), and the
/// first request after the endpoint comes back succeeds immediately.
/// The eviction duration is deliberately much longer than the test:
/// recovery can only come from the fail-open dial clearing the
/// eviction, not from the deadline lapsing.
#[tokio::test]
async fn single_endpoint_fails_open_and_recovers() {
    let (p1, _c1, h1) = spawn_counting_http().await;
    let bind_port = free_port().await;

    let cfg = cfg_endpoints(bind_port, &[p1]);
    let store = Store::new();
    let _ = store.apply(&cfg);

    let picker = Arc::new(P2cEwma::new(P2cConfig::default()));
    let state_cfg = EndpointStateConfig {
        ewma_alpha: 0.5,
        failure_threshold: 1,
        eviction_duration: Duration::from_mins(1),
    };
    let lb = LoadBalancer::with_picker(picker, state_cfg);
    let gateway = Gateway::with_lb(store, lb);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let gw_handle = tokio::spawn(async move {
        gateway
            .run(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build_http();

    // Phase 1: endpoint up — requests succeed.
    for _ in 0..5 {
        assert_eq!(round_trip(&client, bind_port).await, StatusCode::OK);
    }

    // Phase 2: endpoint down. `failure_threshold = 1` evicts on the
    // first failed dial; without fail-open every subsequent request
    // would be a synthesized 503 for the whole 60s eviction window.
    // With fail-open each request still dials the dead endpoint and
    // gets a 502.
    h1.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    for _ in 0..10 {
        let status = round_trip(&client, bind_port).await;
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "downtime must answer 502 after a dial attempt, never 503"
        );
    }

    // Phase 3: endpoint back on the same port. The very next request
    // must succeed — the successful dial clears the eviction.
    let (_p1_again, c1_again, _h1_again) = spawn_counting_http_on(p1).await;
    assert_eq!(
        round_trip(&client, bind_port).await,
        StatusCode::OK,
        "first request after recovery must succeed"
    );
    for _ in 0..5 {
        assert_eq!(round_trip(&client, bind_port).await, StatusCode::OK);
    }
    assert!(c1_again.load(Ordering::Relaxed) >= 6);

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}
