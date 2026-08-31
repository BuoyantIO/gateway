//! Backend credentials, end to end: a real `Gateway` in front of a
//! recording upstream that stands in for an external provider, so
//! what the provider receives is what is asserted rather than what
//! the config resolved to.
//!
//! The upstream is plaintext here. In production a credential belongs
//! on a TLS connection — the store warns when it isn't — but the
//! header the gateway attaches is the same either way, and TLS
//! origination has its own tests.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use bytes::Bytes;
use gateway_config::backend::{ApiKeyAuth, Backend, BackendAuth, DialableBackend};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::config::GatewayConfig;
use gateway_config::extension::{FailureMode, Limits};
use gateway_config::filter::{HeaderOps, HeaderPair, HttpFilter};
use gateway_config::listener::{HttpListener as SchemaHttpListener, Listener};
use gateway_config::route::{HttpMatch, HttpRoute, PathMatch};
use gateway_config::secret::{OpaqueSecret, Secret, SecretRef, SecretValue};
use gateway_runtime::extension::Registry;
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

/// The headers of one request, lowercased names paired with values.
type RequestHeaders = Vec<(String, String)>;

/// Every request one upstream received, as the header values that
/// matter to these tests.
#[derive(Clone, Default)]
struct Received(Arc<StdMutex<Vec<RequestHeaders>>>);

impl Received {
    /// Every value seen for `name`, across every request, in arrival
    /// order — so "exactly one" is a claim about the wire and not
    /// about `HeaderMap::get`, which would hide a second value.
    fn values(&self, name: &str) -> Vec<String> {
        self.0
            .lock()
            .expect("upstream record")
            .iter()
            .flatten()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn request_count(&self) -> usize {
        self.0.lock().expect("upstream record").len()
    }
}

/// An upstream that records the headers of every request it answers.
/// Non-UTF-8 values cannot reach it: they are not valid in a header.
async fn spawn_recording_upstream() -> (u16, Received) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Received::default();
    let record = received.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let record = record.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let record = record.clone();
                    async move {
                        let headers = req
                            .headers()
                            .iter()
                            .map(|(k, v)| {
                                (
                                    k.as_str().to_owned(),
                                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                                )
                            })
                            .collect();
                        record.0.lock().expect("upstream record").push(headers);
                        Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from("ok"))))
                    }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    (port, received)
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

fn spawn_gateway(store: Store) -> (tokio::task::JoinHandle<()>, drain::Signal) {
    let (stop, watch) = drain::channel();
    let mut registry = Registry::new();
    gateway_extension_impls::register_builtins(&mut registry);
    let gw = Gateway::new(store).with_classes(registry);
    let handle = tokio::spawn(async move {
        gw.run(watch).await.unwrap();
    });
    (handle, stop)
}

/// A credential secret under `name`, holding `value` at `apiKey`.
fn credential(name: &str, value: &str) -> Secret {
    OpaqueSecret::new(
        "",
        name,
        [("apiKey".to_string(), SecretValue::new(value))]
            .into_iter()
            .collect(),
    )
    .into()
}

/// The provider backend: dialed by name, authenticating with the
/// `apiKey` of `secret`. `header` and `prefix` are `None` for the
/// defaults.
fn provider_backend(
    port: u16,
    secret: &str,
    header: Option<&str>,
    prefix: Option<&str>,
) -> Backend {
    Backend::Dialable(DialableBackend {
        name: "provider".into(),
        host: "localhost".into(),
        port,
        path_prefix: None,
        tls: None,
        auth: Some(Box::new(BackendAuth::ApiKey(ApiKeyAuth {
            secret_ref: SecretRef::new("", secret, "apiKey"),
            header: header.map_or(http::header::AUTHORIZATION, |h| {
                http::HeaderName::from_bytes(h.as_bytes()).expect("valid header name")
            }),
            prefix: prefix.unwrap_or("Bearer ").to_string(),
        }))),
    })
}

/// One HTTP listener routing everything at the provider backend,
/// through `filters`.
fn config(
    bind_port: u16,
    backend: Backend,
    secrets: Vec<Secret>,
    filters: Vec<HttpFilter>,
) -> GatewayConfig {
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
                    backend_refs: vec![gateway_config::backend::BackendRef {
                        name: "provider".into(),
                        weight: 1,
                    }],
                    filters,
                }],
            })],
        }],
        backends: vec![backend],
        secrets,
        extensions: vec![],
    }
}

/// A `request_header_modifier` extension setting `authorization`,
/// which is the header the credential occupies: whatever a filter
/// puts there, the credential replaces it.
fn authorization_setter(value: &str) -> gateway_config::extension::Extension {
    gateway_config::extension::Extension {
        namespace: String::new(),
        name: "set-auth".into(),
        class: "request_header_modifier".into(),
        failure_mode: FailureMode::default(),
        limits: Limits::default(),
        config: gateway_config::extension::to_value(&HeaderOps {
            set: vec![HeaderPair {
                name: "authorization".into(),
                value: value.into(),
            }],
            ..Default::default()
        })
        .expect("header ops serialize"),
    }
}

// =================== tests ===================

/// The invariant the whole feature rests on: the provider receives
/// exactly one credential header, the configured one, even though the
/// client sent one of its own under the same name.
#[tokio::test]
async fn provider_receives_exactly_one_credential() {
    let (upstream_port, received) = spawn_recording_upstream().await;
    let bind_port = free_port().await;
    let cfg = config(
        bind_port,
        provider_backend(upstream_port, "provider-key", None, None),
        vec![credential("provider-key", "sk-test")],
        vec![],
    );
    let store = Store::new();
    let _ = store.apply(&cfg);
    let (gw_handle, shutdown_tx) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .uri(format!("http://127.0.0.1:{bind_port}/v1/chat"))
        // The client's own credential, which must not reach the
        // provider and must not be sent beside the gateway's.
        .header("authorization", "Bearer client-token")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(received.values("authorization"), vec!["Bearer sk-test"]);

    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

/// The credential is attached after the route's filters have run, so
/// a filter cannot dictate what the gateway authenticates as — by
/// accident or otherwise.
#[tokio::test]
async fn a_route_filter_cannot_displace_the_credential() {
    let (upstream_port, received) = spawn_recording_upstream().await;
    let bind_port = free_port().await;
    let mut cfg = config(
        bind_port,
        provider_backend(upstream_port, "provider-key", None, None),
        vec![credential("provider-key", "sk-test")],
        vec![HttpFilter::ExtensionRef {
            name: "set-auth".into(),
            namespace: String::new(),
        }],
    );
    cfg.extensions = vec![authorization_setter("Bearer filter-token")];
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

    assert_eq!(received.values("authorization"), vec!["Bearer sk-test"]);

    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

/// A provider that names its own header and wants the key bare gets
/// exactly that, and nothing lands in `authorization`.
#[tokio::test]
async fn a_configured_header_and_empty_prefix_reach_the_provider() {
    let (upstream_port, received) = spawn_recording_upstream().await;
    let bind_port = free_port().await;
    let cfg = config(
        bind_port,
        provider_backend(upstream_port, "provider-key", Some("x-api-key"), Some("")),
        vec![credential("provider-key", "sk-test")],
        vec![],
    );
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

    assert_eq!(received.values("x-api-key"), vec!["sk-test"]);
    assert!(received.values("authorization").is_empty());

    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

/// A credential the gateway does not have fails the request instead
/// of reaching the provider without it: unauthenticated is not a
/// degraded version of authenticated, it is a different request.
#[tokio::test]
async fn an_unresolved_credential_fails_the_request_unsent() {
    let (upstream_port, received) = spawn_recording_upstream().await;
    let bind_port = free_port().await;
    // The backend names a secret; no secret is registered.
    let cfg = config(
        bind_port,
        provider_backend(upstream_port, "provider-key", None, None),
        vec![],
        vec![],
    );
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
    assert_eq!(
        received.request_count(),
        0,
        "the provider must not be dialed"
    );

    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

/// The credential the secret carries at the time of the request, not
/// the one that was there when the backend was applied.
#[tokio::test]
async fn a_rotated_credential_is_what_the_next_request_carries() {
    let (upstream_port, received) = spawn_recording_upstream().await;
    let bind_port = free_port().await;
    let cfg = config(
        bind_port,
        provider_backend(upstream_port, "provider-key", None, None),
        vec![credential("provider-key", "sk-old")],
        vec![],
    );
    let store = Store::new();
    let _ = store.apply(&cfg);
    let (gw_handle, shutdown_tx) = spawn_gateway(store.clone());
    wait_for_listening(bind_port).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let url = format!("http://127.0.0.1:{bind_port}/");
    let resp = client.get(url.parse().unwrap()).await.expect("request");
    assert_eq!(resp.status(), StatusCode::OK);
    resp.into_body().collect().await.expect("drain body");

    store.upsert_secret(credential("provider-key", "sk-new"));

    let resp = client.get(url.parse().unwrap()).await.expect("request");
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(
        received.values("authorization"),
        vec!["Bearer sk-old", "Bearer sk-new"]
    );

    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}
