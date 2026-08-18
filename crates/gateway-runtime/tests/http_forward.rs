//! HTTP integration tests. Spins up a real hyper echo server upstream,
//! a real `Gateway` listening on a free port, and drives requests
//! through with both HTTP/1.1 and HTTP/2 clients. Mirrors the shape of
//! `tcp_forward.rs`.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use bytes::Bytes;
use gateway_config::backend::{Backend, BackendProtocol, BackendRef, Endpoint, StaticBackend};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::config::GatewayConfig;
use gateway_config::filter::{HeaderOps, HeaderPair, HttpFilter, RedirectStatus, Scheme};
use gateway_config::listener::{HttpListener as SchemaHttpListener, Listener};
use gateway_config::route::{HttpMatch, HttpRoute, PathMatch};
use gateway_runtime::extension::{
    Action, BodyMode, Cx, Error as ExtensionError, Extension, ExtensionBuilder, LocalResponse,
    Registry, async_trait,
};
use gateway_runtime::{Gateway, drain};
use gateway_state::Store;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::{TcpListener, TcpStream};

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
            path: PathMatch::PathPrefix {
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

fn spawn_gateway(store: Store) -> (tokio::task::JoinHandle<()>, drain::Signal) {
    let (stop, watch) = drain::channel();
    let gw = Gateway::new(store);
    let handle = tokio::spawn(async move {
        gw.run(watch).await.unwrap();
    });
    (handle, stop)
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

    drop(shutdown_tx);
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

    drop(shutdown_tx);
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
    // An unmatched host answers 404 — the same status whether or not
    // any listener on the bind is active.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    drop(shutdown_tx);
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

    drop(shutdown_tx);
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
        request_headers: HeaderOps {
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

    drop(shutdown_tx);
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
                path: PathMatch::PathPrefix { value: "/".into() },
                method: None,
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
                request_headers: HeaderOps {
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
            request_headers: HeaderOps {
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

    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

/// A regex `path` match routes to its backend when the request
/// path matches the (anchored) pattern, and falls through to a
/// sibling catchall when it doesn't.
#[tokio::test]
async fn regex_path_routes_matching_request() {
    let upstream_match = spawn_http_echo().await;
    let upstream_catchall = spawn_http_echo().await;
    let bind_port = free_port().await;

    // Route A: matches `^/api/v\d+/.*` — anchored regex.
    let regex_route = HttpRoute {
        name: "r-regex".into(),
        matches: vec![HttpMatch {
            host: None,
            path: PathMatch::Regex {
                value: regex::Regex::new(r"^/api/v\d+/.*").unwrap(),
            },
            method: None,
            headers: vec![],
            query_params: vec![],
        }],
        backend_refs: vec![BackendRef {
            name: "be-regex".into(),
            weight: 1,
        }],
        filters: vec![HttpFilter::RequestHeaderModifier {
            name: "tag-regex".into(),
            request_headers: HeaderOps {
                add: vec![HeaderPair {
                    name: "x-test-served-by".into(),
                    value: "REGEX".into(),
                }],
                set: vec![],
                remove: vec![],
            },
        }],
    };
    // Route B: plain `/` catchall.
    let catchall_route = http_route_with_filter(
        "r-catchall",
        "/",
        "be-catchall",
        HttpFilter::RequestHeaderModifier {
            name: "tag-catchall".into(),
            request_headers: HeaderOps {
                add: vec![HeaderPair {
                    name: "x-test-served-by".into(),
                    value: "CATCHALL".into(),
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
            listeners: vec![http_listener("l", None, vec![regex_route, catchall_route])],
        }],
        backends: vec![
            static_backend("be-regex", upstream_match),
            static_backend("be-catchall", upstream_catchall),
        ],
        secrets: vec![],
    };

    let store = Store::new();
    let _ = store.apply(&cfg);
    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    // 1: path matches the regex → route A wins (Regex outranks Prefix).
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{bind_port}/api/v1/users"))
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
        served, "REGEX",
        "regex-matching path should hit the regex route"
    );

    // 2: path doesn't match the regex → falls through to catchall.
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{bind_port}/healthz"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    let served = resp
        .headers()
        .get("x-echo-served-by")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(served, "CATCHALL", "non-matching path should fall through");

    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

/// Response-side filter mutates the upstream response's headers
/// before they reach the client. Mirrors the
/// `request_header_modifier_applies` test on the response side.
#[tokio::test]
async fn response_header_modifier_applies() {
    use gateway_config::filter::HeaderOps;

    let upstream_port = spawn_http_echo().await;
    let bind_port = free_port().await;

    // Echo server sets `x-server-version: HTTP/1.1` on every
    // response. The filter:
    //   - adds `x-test-csp` (will appear on the response)
    //   - sets `x-test-frame-options` (no upstream collision; just
    //     present)
    //   - removes `x-server-version` (upstream-set; should disappear)
    let filter = HttpFilter::ResponseHeaderModifier {
        name: "rsp".into(),
        response_headers: HeaderOps {
            add: vec![HeaderPair {
                name: "x-test-csp".into(),
                value: "default-src 'self'".into(),
            }],
            set: vec![HeaderPair {
                name: "x-test-frame-options".into(),
                value: "sameorigin".into(),
            }],
            remove: vec!["x-server-version".into()],
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
    assert_eq!(
        resp.headers()
            .get("x-test-csp")
            .and_then(|v| v.to_str().ok()),
        Some("default-src 'self'"),
        "added header should be on the response"
    );
    assert_eq!(
        resp.headers()
            .get("x-test-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("sameorigin"),
        "set header should be on the response"
    );
    assert!(
        !resp.headers().contains_key("x-server-version"),
        "removed header must not appear on the response"
    );

    drop(shutdown_tx);
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

    drop(shutdown_tx);
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

    drop(shutdown_tx);
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
async fn h2_request_body_round_trips() {
    let upstream = spawn_body_echo().await;
    let bind_port = free_port().await;
    let cfg = http_config_proto(bind_port, upstream, "/", BackendProtocol::Http2);
    let store = Store::new();
    let _ = store.apply(&cfg);
    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    // H2 client → gateway → h2c backend: the request body must reach
    // the backend and the response body must come back byte-for-byte.
    // (The version matrix above checks status and wire version only;
    // real gRPC semantics — trailers, streams, large messages — are
    // covered by the e2e suite against a real gRPC server.)
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http();
    let payload = Bytes::from_static(b"\x00\x00\x00\x00\x05hello");
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{bind_port}/"))
        .body(Full::new(payload.clone()))
        .unwrap();
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-server-version")
            .and_then(|v| v.to_str().ok()),
        Some("HTTP/2.0"),
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, payload);

    drop(shutdown_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), gw_handle).await;
}

// =================== unresolved backend refs ===================

/// A rule whose backendRef names a backend that was never registered
/// still matches and answers 500 — not 404 — and starts proxying the
/// moment the backend registers, without any route re-apply.
#[tokio::test]
async fn route_with_unregistered_backend_returns_500() {
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
                    http_route("broken", "/missing", "ghost-be"),
                    http_route("real", "/", "be"),
                ],
            )],
        }],
        backends: vec![static_backend("be", upstream_port)],
        secrets: vec![],
    };
    let store = Store::new();
    let _ = store.apply(&cfg);

    let (gw_handle, shutdown_tx) = spawn_gateway(store.clone());
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let base = format!("http://127.0.0.1:{bind_port}");

    // The broken rule matches and answers 500; the sibling rule with a
    // resolvable backend is unaffected.
    let resp = client
        .get(format!("{base}/missing").parse().unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let resp = client
        .get(format!("{base}/other").parse().unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The backend appears: the same rule proxies with no route re-apply.
    store.upsert_backend(static_backend("ghost-be", upstream_port));
    let resp = client
        .get(format!("{base}/missing").parse().unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // And it goes back to 500 — not 404 — when the backend disappears.
    store.remove_backend(&gateway_state::BackendKey::new("ghost-be"));
    let resp = client
        .get(format!("{base}/missing").parse().unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

/// With weighted backendRefs where only some resolve, the traffic share
/// of the unresolvable ref answers 500 while the rest proxies normally.
#[tokio::test]
async fn weighted_refs_split_between_resolved_and_missing() {
    let upstream_port = spawn_http_echo().await;
    let bind_port = free_port().await;
    let mut route = http_route("r", "/", "be");
    route.backend_refs.push(BackendRef {
        name: "ghost-be".into(),
        weight: 1,
    });
    let cfg = GatewayConfig {
        name: "test".into(),
        binds: vec![Bind {
            name: "b".into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: bind_port,
            bind_protocol: BindProtocol::Http,
            listeners: vec![http_listener("l", None, vec![route])],
        }],
        backends: vec![static_backend("be", upstream_port)],
        secrets: vec![],
    };
    let store = Store::new();
    let _ = store.apply(&cfg);

    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut oks = 0;
    let mut errors = 0;
    for _ in 0..64 {
        let resp = client
            .get(format!("http://127.0.0.1:{bind_port}/").parse().unwrap())
            .await
            .unwrap();
        match resp.status() {
            StatusCode::OK => oks += 1,
            StatusCode::INTERNAL_SERVER_ERROR => errors += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    // 64 fair coin flips: both outcomes appear (P(one-sided) ~ 1e-19).
    assert!(oks > 0, "resolved ref received no traffic");
    assert!(errors > 0, "unresolved ref received no traffic");

    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

/// A short-circuiting filter (redirect) answers without response-side
/// filter treatment: the 301 carries no `ResponseHeaderModifier`
/// headers. Pins deliberately preserved pre-extension behavior.
#[tokio::test]
async fn redirect_short_circuit_skips_response_filters() {
    let bind_port = free_port().await;

    let route = HttpRoute {
        name: "r".into(),
        matches: vec![HttpMatch {
            host: None,
            path: PathMatch::PathPrefix { value: "/".into() },
            method: None,
            headers: vec![],
            query_params: vec![],
        }],
        backend_refs: vec![],
        filters: vec![
            HttpFilter::ResponseHeaderModifier {
                name: "rsp".into(),
                response_headers: HeaderOps {
                    add: vec![HeaderPair {
                        name: "x-test-csp".into(),
                        value: "default-src 'self'".into(),
                    }],
                    set: vec![],
                    remove: vec![],
                },
            },
            HttpFilter::RequestRedirect {
                name: "to-https".into(),
                scheme: Some(Scheme::Https),
                hostname: None,
                port: None,
                status_code: RedirectStatus::MovedPermanently,
                path: None,
            },
        ],
    };
    let cfg = GatewayConfig {
        name: "test".into(),
        binds: vec![Bind {
            name: "b".into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: bind_port,
            bind_protocol: BindProtocol::Http,
            listeners: vec![http_listener("l", None, vec![route])],
        }],
        backends: vec![],
        secrets: vec![],
    };
    let store = Store::new();
    let _ = store.apply(&cfg);
    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .uri(format!("http://127.0.0.1:{bind_port}/foo?x=1"))
        .header("host", "app.example")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        resp.headers()
            .get(http::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("https://app.example/foo?x=1"),
    );
    assert!(
        resp.headers().get("x-test-csp").is_none(),
        "response filters must not run on a short-circuited response"
    );

    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

/// An invalid header name in filter config fails the request before
/// dispatch: 500, and the upstream (a dead port here) is never dialed
/// (a dial attempt would 502 instead).
#[tokio::test]
async fn invalid_filter_config_answers_500_before_dispatch() {
    let dead_port = free_port().await;
    let bind_port = free_port().await;

    let filter = HttpFilter::RequestHeaderModifier {
        name: "bad".into(),
        request_headers: HeaderOps {
            add: vec![HeaderPair {
                name: "bad name".into(),
                value: "v".into(),
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
        backends: vec![static_backend("be", dead_port)],
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
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

// =================== extension refs ===================

/// Stamps a header on the response. Defined here rather than in the
/// crate to exercise the extension traits from outside.
struct StampBuilder;

struct Stamp;

impl ExtensionBuilder for StampBuilder {
    fn build(&self) -> Box<dyn Extension> {
        Box::new(Stamp)
    }
}

#[async_trait]
impl Extension for Stamp {
    async fn on_request_start(
        &mut self,
        _head: &mut http::request::Parts,
        _cx: &mut Cx<'_>,
    ) -> Result<Action, ExtensionError> {
        Ok(Action::Continue)
    }

    fn on_response_start(&mut self, head: &mut http::response::Parts, _cx: &mut Cx<'_>) {
        head.headers
            .insert("x-stamped", "by-extension".parse().unwrap());
    }
}

fn extension_ref_config(bind_port: u16, upstream_port: u16, plugin: &str) -> GatewayConfig {
    let filter = HttpFilter::ExtensionRef {
        name: plugin.into(),
    };
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
                vec![http_route_with_filter("r", "/", "be", filter)],
            )],
        }],
        backends: vec![static_backend("be", upstream_port)],
        secrets: vec![],
    }
}

#[tokio::test]
async fn registered_extension_runs_for_a_route_that_references_it() {
    let upstream_port = spawn_http_echo().await;
    let bind_port = free_port().await;
    let cfg = extension_ref_config(bind_port, upstream_port, "stamp");
    let store = Store::new();
    let _ = store.apply(&cfg);

    let mut registry = Registry::new();
    registry.register("stamp", Arc::new(StampBuilder)).unwrap();

    let (stop, watch) = drain::channel();
    let gw = Gateway::new(store).with_extensions(registry);
    let gw_handle = tokio::spawn(async move { gw.run(watch).await.unwrap() });
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .get(format!("http://127.0.0.1:{bind_port}/").parse().unwrap())
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-stamped")
            .and_then(|v| v.to_str().ok()),
        Some("by-extension"),
    );

    drop(stop);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

/// A route referencing a plugin nobody registered must not serve —
/// skipping the member silently would be worse than failing.
#[tokio::test]
async fn unregistered_extension_ref_answers_500() {
    let upstream_port = spawn_http_echo().await;
    let bind_port = free_port().await;
    let cfg = extension_ref_config(bind_port, upstream_port, "absent");
    let store = Store::new();
    let _ = store.apply(&cfg);

    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .get(format!("http://127.0.0.1:{bind_port}/").parse().unwrap())
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

// =================== body gate ===================

/// What a body probe saw at each hook call.
#[derive(Debug, PartialEq, Eq, Clone)]
struct SeenChunk {
    len: usize,
    end_of_stream: bool,
    buffered: Option<usize>,
}

/// Test extension with a configurable body mode. Records every body
/// hook call; optionally answers 429 at a given call index.
struct BodyProbeBuilder {
    mode: BodyMode,
    respond_at: Option<usize>,
    seen: Arc<StdMutex<Vec<SeenChunk>>>,
}

struct BodyProbe {
    respond_at: Option<usize>,
    seen: Arc<StdMutex<Vec<SeenChunk>>>,
}

impl ExtensionBuilder for BodyProbeBuilder {
    fn request_body(&self) -> BodyMode {
        self.mode
    }

    fn build(&self) -> Box<dyn Extension> {
        Box::new(BodyProbe {
            respond_at: self.respond_at,
            seen: Arc::clone(&self.seen),
        })
    }
}

#[async_trait]
impl Extension for BodyProbe {
    async fn on_request_start(
        &mut self,
        _head: &mut http::request::Parts,
        _cx: &mut Cx<'_>,
    ) -> Result<Action, ExtensionError> {
        Ok(Action::Continue)
    }

    async fn on_request_body(
        &mut self,
        chunk: &[u8],
        end_of_stream: bool,
        cx: &mut Cx<'_>,
    ) -> Result<Action, ExtensionError> {
        let mut seen = self.seen.lock().unwrap();
        seen.push(SeenChunk {
            len: chunk.len(),
            end_of_stream,
            buffered: cx.request_buffer().map(<[u8]>::len),
        });
        if self.respond_at == Some(seen.len() - 1) {
            return Ok(Action::Respond(LocalResponse {
                status: StatusCode::TOO_MANY_REQUESTS,
                headers: http::HeaderMap::new(),
                body: Bytes::from_static(b"limited"),
            }));
        }
        Ok(Action::Continue)
    }
}

/// A None-mode member whose body hook must never run.
struct NoBodyBuilder;
struct NoBody;

impl ExtensionBuilder for NoBodyBuilder {
    fn build(&self) -> Box<dyn Extension> {
        Box::new(NoBody)
    }
}

#[async_trait]
impl Extension for NoBody {
    async fn on_request_start(
        &mut self,
        _head: &mut http::request::Parts,
        _cx: &mut Cx<'_>,
    ) -> Result<Action, ExtensionError> {
        Ok(Action::Continue)
    }

    async fn on_request_body(
        &mut self,
        _chunk: &[u8],
        _end_of_stream: bool,
        _cx: &mut Cx<'_>,
    ) -> Result<Action, ExtensionError> {
        panic!("body hook ran for a member that declared no body access");
    }
}

/// Echo that also reports the request framing it saw:
/// `x-recv-content-length` and `x-recv-transfer-encoding` (or "none").
async fn spawn_framing_echo() -> u16 {
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
                    let framing = |name: http::header::HeaderName| {
                        req.headers()
                            .get(name)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("none")
                            .to_owned()
                    };
                    let cl = framing(http::header::CONTENT_LENGTH);
                    let te = framing(http::header::TRANSFER_ENCODING);
                    let body = req
                        .into_body()
                        .collect()
                        .await
                        .map(http_body_util::Collected::to_bytes)
                        .unwrap_or_default();
                    let resp = http::Response::builder()
                        .status(StatusCode::OK)
                        .header("x-recv-content-length", cl)
                        .header("x-recv-transfer-encoding", te)
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

struct GatedRoute {
    bind_port: u16,
    seen: Arc<StdMutex<Vec<SeenChunk>>>,
    _gw: tokio::task::JoinHandle<()>,
    _stop: drain::Signal,
}

/// Gateway with one route through a body probe of the given mode.
async fn spawn_gated_route(
    upstream_port: u16,
    mode: BodyMode,
    respond_at: Option<usize>,
) -> GatedRoute {
    let bind_port = free_port().await;
    let cfg = extension_ref_config(bind_port, upstream_port, "probe");
    let store = Store::new();
    let _ = store.apply(&cfg);

    let seen = Arc::new(StdMutex::new(Vec::new()));
    let mut registry = Registry::new();
    registry
        .register(
            "probe",
            Arc::new(BodyProbeBuilder {
                mode,
                respond_at,
                seen: Arc::clone(&seen),
            }),
        )
        .unwrap();

    let (stop, watch) = drain::channel();
    let gw = Gateway::new(store).with_extensions(registry);
    let gw_handle = tokio::spawn(async move {
        gw.run(watch).await.unwrap();
    });
    wait_for_listening(bind_port).await;
    GatedRoute {
        bind_port,
        seen,
        _gw: gw_handle,
        _stop: stop,
    }
}

#[tokio::test]
async fn stream_member_sees_chunks_and_framing_survives() {
    let upstream = spawn_framing_echo().await;
    let gated = spawn_gated_route(upstream, BodyMode::Stream, None).await;

    // Fixed-length client body: the content-length must pass through.
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{}/", gated.bind_port))
        .body(Full::new(Bytes::from_static(b"streamed body")))
        .unwrap();
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-recv-content-length").unwrap(), "13");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, Bytes::from_static(b"streamed body"));

    let seen = gated.seen.lock().unwrap();
    assert!(!seen.is_empty());
    assert!(seen.last().unwrap().end_of_stream);
    // Nothing retained on the stream tier.
    assert!(seen.iter().all(|c| c.buffered.is_none()));
}

#[tokio::test]
async fn stream_member_responding_mid_upload_answers_the_client() {
    let upstream = spawn_framing_echo().await;
    let gated = spawn_gated_route(upstream, BodyMode::Stream, Some(0)).await;

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{}/", gated.bind_port))
        .body(Full::new(Bytes::from_static(b"denied payload")))
        .unwrap();
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, Bytes::from_static(b"limited"));
}

#[tokio::test]
async fn oversized_upload_answers_413_on_the_buffer_tier() {
    let upstream = spawn_framing_echo().await;
    let gated = spawn_gated_route(upstream, BodyMode::Buffer, None).await;

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{}/", gated.bind_port))
        .body(Full::new(Bytes::from(vec![0u8; 9 * 1024 * 1024])))
        .unwrap();
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // Rejected from the declared length, before any chunk reached a hook.
    assert!(gated.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn routes_without_body_members_never_read_a_frame() {
    let upstream = spawn_framing_echo().await;
    let bind_port = free_port().await;
    let cfg = extension_ref_config(bind_port, upstream, "no-body");
    let store = Store::new();
    let _ = store.apply(&cfg);

    let mut registry = Registry::new();
    registry
        .register("no-body", Arc::new(NoBodyBuilder))
        .unwrap();

    let (stop, watch) = drain::channel();
    let gw = Gateway::new(store).with_extensions(registry);
    let gw_handle = tokio::spawn(async move { gw.run(watch).await.unwrap() });
    wait_for_listening(bind_port).await;

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{bind_port}/"))
        .body(Full::new(Bytes::from_static(b"passthrough")))
        .unwrap();
    // A panic in the body hook would kill the connection; a clean 200
    // with the echoed body proves the hook never ran.
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, Bytes::from_static(b"passthrough"));

    drop(stop);
    let _ = tokio::time::timeout(Duration::from_secs(2), gw_handle).await;
}

#[tokio::test]
async fn chunked_upload_through_the_buffer_tier_gets_a_content_length() {
    let upstream = spawn_framing_echo().await;
    let gated = spawn_gated_route(upstream, BodyMode::Buffer, None).await;

    // A multi-frame body with no size hint: the client sends chunked.
    let frames: Vec<Result<http_body::Frame<Bytes>, Infallible>> = vec![
        Ok(http_body::Frame::data(Bytes::from_static(b"chun"))),
        Ok(http_body::Frame::data(Bytes::from_static(b"ked"))),
    ];
    let body = http_body_util::StreamBody::new(futures::stream::iter(frames));
    let client: Client<_, http_body_util::StreamBody<_>> =
        Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{}/", gated.bind_port))
        .body(body)
        .unwrap();
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    // Buffering turned the chunked upload into a fixed-length one.
    assert_eq!(resp.headers().get("x-recv-content-length").unwrap(), "7");
    assert_eq!(
        resp.headers().get("x-recv-transfer-encoding").unwrap(),
        "none"
    );
    let echoed = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(echoed, Bytes::from_static(b"chunked"));

    // Two data frames, then the terminal empty call.
    let seen = gated.seen.lock().unwrap();
    assert_eq!(
        *seen,
        vec![
            SeenChunk {
                len: 4,
                end_of_stream: false,
                buffered: Some(4)
            },
            SeenChunk {
                len: 3,
                end_of_stream: false,
                buffered: Some(7)
            },
            SeenChunk {
                len: 0,
                end_of_stream: true,
                buffered: Some(7)
            },
        ]
    );
}
