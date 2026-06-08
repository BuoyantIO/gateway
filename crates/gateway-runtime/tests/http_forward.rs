//! HTTP integration tests. Spins up a real hyper echo server upstream,
//! a real `Gateway` listening on a free port, and drives requests
//! through with both HTTP/1.1 and HTTP/2 clients. Mirrors the shape of
//! `tcp_forward.rs`.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use bytes::Bytes;
use gateway_config::backend::{Backend, BackendProtocol, BackendRef, Endpoint, StaticBackend};
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
                    // Reflect the wire version the gateway spoke to us
                    // (the server side) so tests can assert it.
                    let server_version = format!("{:?}", req.version());
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
                    let mut builder = http::Response::builder()
                        .status(StatusCode::OK)
                        .header("x-server-version", server_version);
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
            method: None,
            headers: vec![],
            query_params: vec![],
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
    static_backend_proto(name, port, BackendProtocol::Http1)
}

fn static_backend_proto(name: &str, port: u16, protocol: BackendProtocol) -> Backend {
    Backend::Static(StaticBackend {
        name: name.into(),
        endpoints: vec![Endpoint {
            name: "e0".into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        }],
        protocol,
    })
}

fn http_config_one_listener(
    bind_port: u16,
    upstream_port: u16,
    path_prefix: &str,
) -> GatewayConfig {
    http_config_proto(
        bind_port,
        upstream_port,
        path_prefix,
        BackendProtocol::Http1,
    )
}

fn http_config_proto(
    bind_port: u16,
    upstream_port: u16,
    path_prefix: &str,
    protocol: BackendProtocol,
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
        backends: vec![static_backend_proto("be", upstream_port, protocol)],
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

/// Header-based routing: a route with `headers: [x-feature=on]`
/// must beat a catch-all `/` route per Gateway API precedence, but
/// only when the header is set.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn header_routing_picks_header_rule_over_catchall() {
    let upstream_a = spawn_http_echo().await;
    let upstream_b = spawn_http_echo().await;
    let bind_port = free_port().await;

    // Two backends. Each route has a filter that injects a
    // `x-test-served-by` header so the echo server reflects it back
    // as `x-echo-served-by`. That's how the test discriminates which
    // backend handled the request.
    let route_with_header_match = {
        let mut r = HttpRoute {
            name: "r-header".into(),
            matches: vec![HttpMatch {
                host: None,
                path: PathMatch {
                    kind: PathMatchKind::PathPrefix,
                    value: "/".into(),
                },
                method: None,
                // header-match field is on the **config-side**
                // HttpMatch; the Store compiles it into an
                // ActiveHttpMatch at apply time.
                headers: vec![gateway_config::route::HeaderMatch {
                    name: http::HeaderName::from_static("x-feature"),
                    value: gateway_config::route::HeaderValueMatch::Exact {
                        value: http::HeaderValue::from_static("on"),
                    },
                }],
                query_params: vec![],
            }],
            backend_refs: vec![BackendRef {
                name: "be-a".into(),
                weight: 1,
            }],
            filters: vec![HttpFilter::RequestHeaderModifier {
                name: "tag-a".into(),
                request_headers: RequestHeaderOps {
                    add: vec![HeaderPair {
                        name: "x-test-served-by".into(),
                        value: "A".into(),
                    }],
                    set: vec![],
                    remove: vec![],
                },
            }],
        };
        // Sanity: the helper above doesn't apply, build by hand.
        r.name = "r-header".into();
        r
    };
    let catchall_route = http_route_with_filter(
        "r-catchall",
        "/",
        "be-b",
        HttpFilter::RequestHeaderModifier {
            name: "tag-b".into(),
            request_headers: RequestHeaderOps {
                add: vec![HeaderPair {
                    name: "x-test-served-by".into(),
                    value: "B".into(),
                }],
                set: vec![],
                remove: vec![],
            },
        },
    );

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
                vec![route_with_header_match, catchall_route],
            )],
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

    // Request 1: header set → route A should win.
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{bind_port}/"))
        .header("x-feature", "on")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    let served = resp
        .headers()
        .get("x-echo-served-by")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        served, "A",
        "header set should route to header-matched rule"
    );

    // Request 2: no header → catchall.
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{bind_port}/"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    let served = resp
        .headers()
        .get("x-echo-served-by")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(served, "B", "no header should fall through to catchall");

    // Request 3: wrong header value → catchall.
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{bind_port}/"))
        .header("x-feature", "off")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    let served = resp
        .headers()
        .get("x-echo-served-by")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        served, "B",
        "wrong header value should fall through to catchall"
    );

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

// =================== version matrix (client side × server side) ===================
//
// "client side"  = client ↔ gateway (version the client speaks).
// "server side"  = gateway ↔ backend (version the gateway originates,
//                  set by the backend's `protocol`).
// The echo backend reflects the version it received as `x-server-version`.

/// Spawn an echo backend that returns the request body verbatim and
/// reflects the received wire version as `x-server-version`. Used for
/// the gRPC body round-trip.
async fn spawn_body_echo() -> u16 {
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
                    let server_version = format!("{:?}", req.version());
                    let body = req
                        .into_body()
                        .collect()
                        .await
                        .map(http_body_util::Collected::to_bytes)
                        .unwrap_or_default();
                    let resp = http::Response::builder()
                        .status(StatusCode::OK)
                        .header("x-server-version", server_version)
                        .body(Full::new(body))
                        .unwrap();
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

/// Run one matrix cell: server-side protocol = `server_proto`; client
/// speaks H2 iff `client_h2`. Returns (status, x-server-version).
async fn run_version_case(server_proto: BackendProtocol, client_h2: bool) -> (StatusCode, String) {
    let upstream = spawn_http_echo().await;
    let bind_port = free_port().await;
    let cfg = http_config_proto(bind_port, upstream, "/", server_proto);
    let store = Store::new();
    let _ = store.apply(&cfg);
    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let uri = format!("http://127.0.0.1:{bind_port}/");
    let resp = if client_h2 {
        let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build_http();
        client
            .get(uri.parse().unwrap())
            .await
            .expect("request failed")
    } else {
        let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        client
            .get(uri.parse().unwrap())
            .await
            .expect("request failed")
    };
    let status = resp.status();
    let server_version = resp
        .headers()
        .get("x-server-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), gw_handle).await;
    (status, server_version)
}

#[tokio::test]
async fn client_h1_server_h1() {
    let (status, server_version) = run_version_case(BackendProtocol::Http1, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(server_version, "HTTP/1.1");
}

#[tokio::test]
async fn client_h2_server_h1() {
    let (status, server_version) = run_version_case(BackendProtocol::Http1, true).await;
    assert_eq!(status, StatusCode::OK);
    // Gateway downgrades H2 (client) → H1 (server).
    assert_eq!(server_version, "HTTP/1.1");
}

#[tokio::test]
async fn client_h1_server_h2() {
    let (status, server_version) = run_version_case(BackendProtocol::Http2, false).await;
    assert_eq!(status, StatusCode::OK);
    // h2c origination: server side is H2 even though the client spoke H1.
    assert_eq!(server_version, "HTTP/2.0");
}

#[tokio::test]
async fn client_h2_server_h2() {
    let (status, server_version) = run_version_case(BackendProtocol::Http2, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(server_version, "HTTP/2.0");
}

#[tokio::test]
async fn grpc_shaped_round_trip() {
    let upstream = spawn_body_echo().await;
    let bind_port = free_port().await;
    let cfg = http_config_proto(bind_port, upstream, "/", BackendProtocol::Http2);
    let store = Store::new();
    let _ = store.apply(&cfg);
    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    // gRPC: H2 client → gateway → h2c to the (Http2) backend. Body is a
    // length-prefixed gRPC frame; assert it round-trips byte-for-byte.
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http();
    let payload = Bytes::from_static(b"\x00\x00\x00\x00\x05hello");
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{bind_port}/svc.Service/Method"))
        .header("content-type", "application/grpc")
        .body(Full::new(payload.clone()))
        .unwrap();
    let resp = client.request(req).await.expect("grpc request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-server-version")
            .and_then(|v| v.to_str().ok()),
        Some("HTTP/2.0"),
        "gateway must speak HTTP/2 to a gRPC (Http2) backend"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, payload);

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), gw_handle).await;
}
