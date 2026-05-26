//! HTTP integration tests. Spins up a real hyper echo server upstream,
//! a real `Gateway` listening on a free port, and drives requests
//! through with both HTTP/1.1 and HTTP/2 clients. Mirrors the shape of
//! `tcp_forward.rs`.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use bytes::Bytes;
use gateway_config::backend::{Backend, BackendRef, Endpoint, StaticBackend};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::config::GatewayConfig;
use gateway_config::filter::{HeaderPair, HttpFilter, RequestHeaderOps};
use gateway_config::listener::{HttpListener as SchemaHttpListener, Listener};
use gateway_config::route::{HttpMatch, HttpRoute, PathMatch, PathMatchKind};
use gateway_runtime::Gateway;
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

// =================== test harness ===================

/// Spawn an HTTP echo server that returns a body of `"{METHOD} {PATH}"`
/// and reflects any `x-test-*` header it received into a `x-echo-*`
/// response header. Returns the bound port.
async fn spawn_http_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let method = req.method().to_string();
                    let path = req.uri().path().to_string();
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
                    let mut builder = http::Response::builder().status(StatusCode::OK);
                    for (k, v) in echoed {
                        builder = builder.header(k, v);
                    }
                    let resp = builder.body(Full::new(Bytes::from(body_text))).unwrap();
                    Ok::<_, Infallible>(resp)
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    port
}

/// Pick a free TCP port by binding to :0 and reading the assigned port,
/// then dropping the listener. There's a tiny race window before the
/// gateway re-binds the same port, but it's robust enough for tests.
async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

fn http_route(name: &str, path_prefix: &str, backend: &str) -> HttpRoute {
    HttpRoute {
        name: name.into(),
        matches: vec![HttpMatch {
            host: None,
            path: PathMatch {
                kind: PathMatchKind::PathPrefix,
                value: path_prefix.into(),
            },
        }],
        backend_refs: vec![BackendRef {
            name: backend.into(),
            weight: 1,
        }],
        filters: vec![],
    }
}

fn http_route_with_filter(
    name: &str,
    path_prefix: &str,
    backend: &str,
    filter: HttpFilter,
) -> HttpRoute {
    let mut r = http_route(name, path_prefix, backend);
    r.filters.push(filter);
    r
}

fn http_listener(name: &str, hostname: Option<&str>, routes: Vec<HttpRoute>) -> Listener {
    Listener::Http(SchemaHttpListener {
        name: name.into(),
        hostname: hostname.map(str::to_owned),
        routes,
    })
}

fn static_backend(name: &str, port: u16) -> Backend {
    Backend::Static(StaticBackend {
        name: name.into(),
        endpoints: vec![Endpoint {
            name: "e0".into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        }],
    })
}

fn http_config_one_listener(
    bind_port: u16,
    upstream_port: u16,
    path_prefix: &str,
) -> GatewayConfig {
    GatewayConfig {
        name: "test".into(),
        binds: vec![Bind {
            name: "b".into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: bind_port,
            bind_protocol: BindProtocol::Http,
            listeners: vec![http_listener(
                "l",
                None,
                vec![http_route("r", path_prefix, "be")],
            )],
        }],
        backends: vec![static_backend("be", upstream_port)],
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

fn spawn_gateway(store: Store) -> (tokio::task::JoinHandle<()>, oneshot::Sender<()>) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let gw = Gateway::new(store);
    let handle = tokio::spawn(async move {
        gw.run(async {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });
    (handle, shutdown_tx)
}

// =================== tests ===================

#[tokio::test]
async fn http1_round_trip() {
    let upstream_port = spawn_http_echo().await;
    let bind_port = free_port().await;
    let cfg = http_config_one_listener(bind_port, upstream_port, "/");
    let store = Store::new();
    let _ = store.apply(&cfg);

    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .get(
            format!("http://127.0.0.1:{bind_port}/hello")
                .parse()
                .unwrap(),
        )
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"GET /hello");

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

#[tokio::test]
async fn http2_prior_knowledge_round_trip() {
    let upstream_port = spawn_http_echo().await;
    let bind_port = free_port().await;
    let cfg = http_config_one_listener(bind_port, upstream_port, "/");
    let store = Store::new();
    let _ = store.apply(&cfg);

    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http();
    let resp = client
        .get(
            format!("http://127.0.0.1:{bind_port}/h2-path")
                .parse()
                .unwrap(),
        )
        .await
        .expect("h2 request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.version(), http::Version::HTTP_2);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"GET /h2-path");

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

#[tokio::test]
async fn host_routing_picks_matching_listener() {
    let upstream_a = spawn_http_echo().await;
    let upstream_b = spawn_http_echo().await;
    let bind_port = free_port().await;

    let cfg = GatewayConfig {
        name: "test".into(),
        binds: vec![Bind {
            name: "b".into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: bind_port,
            bind_protocol: BindProtocol::Http,
            listeners: vec![
                http_listener(
                    "la",
                    Some("a.example.com"),
                    vec![http_route("ra", "/", "be-a")],
                ),
                http_listener(
                    "lb",
                    Some("b.example.com"),
                    vec![http_route("rb", "/", "be-b")],
                ),
            ],
        }],
        backends: vec![
            static_backend("be-a", upstream_a),
            static_backend("be-b", upstream_b),
        ],
        secrets: vec![],
    };

    let store = Store::new();
    let _ = store.apply(&cfg);
    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    for host in ["a.example.com", "b.example.com"] {
        let req = Request::builder()
            .method("GET")
            .uri(format!("http://127.0.0.1:{bind_port}/"))
            .header("host", host)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = client.request(req).await.expect("request failed");
        assert_eq!(resp.status(), StatusCode::OK, "host={host}");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"GET /", "host={host}");
    }

    let req = Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{bind_port}/"))
        .header("host", "nope.example.com")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

#[tokio::test]
async fn path_routing_longest_prefix_wins() {
    let upstream_port = spawn_http_echo().await;
    let bind_port = free_port().await;

    let cfg = GatewayConfig {
        name: "test".into(),
        binds: vec![Bind {
            name: "b".into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: bind_port,
            bind_protocol: BindProtocol::Http,
            listeners: vec![http_listener(
                "l",
                None,
                vec![
                    http_route("r-api", "/api", "be"),
                    http_route("r-api-v2", "/api/v2", "be"),
                ],
            )],
        }],
        backends: vec![static_backend("be", upstream_port)],
        secrets: vec![],
    };

    let store = Store::new();
    let _ = store.apply(&cfg);
    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    let resp = client
        .get(
            format!("http://127.0.0.1:{bind_port}/api/v2/users")
                .parse()
                .unwrap(),
        )
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"GET /api/v2/users");

    let resp = client
        .get(
            format!("http://127.0.0.1:{bind_port}/other")
                .parse()
                .unwrap(),
        )
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

#[tokio::test]
async fn request_header_modifier_applies() {
    let upstream_port = spawn_http_echo().await;
    let bind_port = free_port().await;

    let filter = HttpFilter::RequestHeaderModifier {
        name: "add-test".into(),
        request_headers: RequestHeaderOps {
            add: vec![HeaderPair {
                name: "x-test-added".into(),
                value: "from-filter".into(),
            }],
            set: vec![],
            remove: vec![],
        },
    };
    let cfg = GatewayConfig {
        name: "test".into(),
        binds: vec![Bind {
            name: "b".into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: bind_port,
            bind_protocol: BindProtocol::Http,
            listeners: vec![http_listener(
                "l",
                None,
                vec![http_route_with_filter("r", "/", "be", filter)],
            )],
        }],
        backends: vec![static_backend("be", upstream_port)],
        secrets: vec![],
    };
    let store = Store::new();
    let _ = store.apply(&cfg);
    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .get(format!("http://127.0.0.1:{bind_port}/").parse().unwrap())
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    let echoed = resp
        .headers()
        .get("x-echo-added")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(echoed, "from-filter");

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

#[tokio::test]
async fn unreachable_backend_returns_502() {
    let bind_port = free_port().await;
    let cfg = http_config_one_listener(bind_port, 1, "/");
    let store = Store::new();
    let _ = store.apply(&cfg);

    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .get(format!("http://127.0.0.1:{bind_port}/").parse().unwrap())
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}
