//! The client-credentials grant, end to end: a real `Gateway` between
//! a mock token endpoint and a recording upstream, so what the
//! provider receives is the token the endpoint actually issued rather
//! than what the config resolved to.
//!
//! Both mocks are plaintext. In production the client secret and the
//! token belong on TLS connections — the gateway warns when they are
//! not — but what is asserted here is which credential goes where,
//! and that is the same either way; TLS origination has its own tests.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use gateway_config::backend::{
    Backend, BackendAuth, BackendRef, ClientAuthMethod, DialableBackend, OAuth2Auth,
};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::config::GatewayConfig;
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

/// Stands in for a client secret; no test may print it, and no
/// provider may receive it.
const CLIENT_SECRET: &str = "cs-not-a-real-secret";

// =================== the provider ===================

/// Every `authorization` header one upstream received, in arrival
/// order — so "exactly one" is a claim about the wire and not about
/// `HeaderMap::get`, which would hide a second value.
#[derive(Clone, Default)]
struct Received(Arc<StdMutex<Vec<Vec<String>>>>);

impl Received {
    fn credentials(&self) -> Vec<String> {
        self.0
            .lock()
            .expect("upstream record")
            .iter()
            .flatten()
            .cloned()
            .collect()
    }

    fn request_count(&self) -> usize {
        self.0.lock().expect("upstream record").len()
    }
}

/// An upstream that records what it was authenticated with.
async fn spawn_provider() -> (u16, Received) {
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
                let svc = service_fn(move |req: Request<Incoming>| {
                    let record = record.clone();
                    async move {
                        let credentials = req
                            .headers()
                            .get_all(http::header::AUTHORIZATION)
                            .iter()
                            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                            .collect();
                        record.0.lock().expect("upstream record").push(credentials);
                        Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from("ok"))))
                    }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (port, received)
}

// =================== the token endpoint ===================

/// How a mock token endpoint answers.
#[derive(Clone)]
struct Issuer {
    /// Seconds of life it claims for the tokens it issues.
    expires_in: u64,
    /// How long it takes to answer, which is what makes a refresh
    /// observable while it is still in flight.
    delay: Duration,
    /// `Some` refuses every request with this status instead of
    /// issuing anything.
    refuse: Option<StatusCode>,
    /// One entry per request the endpoint received.
    requests: Arc<StdMutex<Vec<AskedFor>>>,
    issued: Arc<AtomicUsize>,
}

impl Default for Issuer {
    fn default() -> Self {
        Self {
            expires_in: 3600,
            delay: Duration::ZERO,
            refuse: None,
            requests: Arc::default(),
            issued: Arc::default(),
        }
    }
}

impl Issuer {
    fn request_count(&self) -> usize {
        self.requests.lock().expect("token endpoint record").len()
    }

    fn requests(&self) -> Vec<AskedFor> {
        self.requests.lock().expect("token endpoint record").clone()
    }
}

/// One request the token endpoint received: what it was
/// authenticated with, and the form body it carried.
#[derive(Clone)]
struct AskedFor {
    authorization: Option<String>,
    form: String,
}

/// A token endpoint that issues `token-1`, `token-2`, … so that which
/// token a provider was shown says which fetch it came from.
async fn spawn_token_endpoint(issuer: Issuer) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let issuer = issuer.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let issuer = issuer.clone();
                    async move {
                        let authorization = req
                            .headers()
                            .get(http::header::AUTHORIZATION)
                            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        issuer.requests.lock().expect("record").push(AskedFor {
                            authorization,
                            form: String::from_utf8_lossy(&body).into_owned(),
                        });
                        tokio::time::sleep(issuer.delay).await;
                        if let Some(status) = issuer.refuse {
                            return Ok::<_, Infallible>(
                                http::Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::from(r#"{"error":"invalid_client"}"#)))
                                    .unwrap(),
                            );
                        }
                        let n = issuer.issued.fetch_add(1, Ordering::SeqCst) + 1;
                        let json = format!(
                            r#"{{"access_token":"token-{n}","token_type":"Bearer","expires_in":{}}}"#,
                            issuer.expires_in
                        );
                        Ok::<_, Infallible>(
                            http::Response::builder()
                                .header(http::header::CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from(json)))
                                .unwrap(),
                        )
                    }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    port
}

// =================== the gateway ===================

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

/// A credential secret under `name`, holding the client secret at
/// `clientSecret`.
fn credential(name: &str) -> Secret {
    OpaqueSecret::new(
        "",
        name,
        [("clientSecret".to_string(), SecretValue::new(CLIENT_SECRET))]
            .into_iter()
            .collect(),
    )
    .into()
}

/// A provider backend authenticating with the client-credentials
/// grant.
fn oauth2_backend(
    name: &str,
    provider_port: u16,
    token_port: u16,
    client_id: &str,
    secret: &str,
    method: ClientAuthMethod,
) -> Backend {
    Backend::Dialable(DialableBackend {
        name: name.into(),
        host: "localhost".into(),
        port: provider_port,
        path_prefix: None,
        tls: None,
        auth: Some(Box::new(BackendAuth::OAuth2(OAuth2Auth {
            token_url: format!("http://127.0.0.1:{token_port}/oauth2/token"),
            client_id: client_id.into(),
            client_secret_ref: SecretRef::new("", secret, "clientSecret"),
            scopes: vec![],
            client_auth_method: method,
        }))),
    })
}

/// One HTTP listener routing `/<backend name>` at each backend.
fn config(bind_port: u16, backends: Vec<Backend>, secrets: Vec<Secret>) -> GatewayConfig {
    let routes = backends
        .iter()
        .map(|b| HttpRoute {
            name: format!("r-{}", b.name()),
            matches: vec![HttpMatch {
                host: None,
                path: PathMatch::PathPrefix {
                    value: format!("/{}", b.name()),
                },
                method: None,
                headers: vec![],
                query_params: vec![],
            }],
            backend_refs: vec![BackendRef {
                name: b.name().to_string(),
                weight: 1,
            }],
            filters: vec![],
        })
        .collect();
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
                routes,
            })],
        }],
        backends,
        secrets,
        extensions: vec![],
    }
}

/// A gateway serving `cfg`, and the client that drives it.
struct Harness {
    port: u16,
    gateway: tokio::task::JoinHandle<()>,
    shutdown: drain::Signal,
}

impl Harness {
    async fn start(cfg: GatewayConfig) -> Self {
        let port = cfg.binds[0].port;
        let store = Store::new();
        let _ = store.apply(&cfg);
        let (gateway, shutdown) = spawn_gateway(store);
        wait_for_listening(port).await;
        Self {
            port,
            gateway,
            shutdown,
        }
    }

    /// One request through the gateway, carrying a credential of the
    /// client's own — which must never reach the provider.
    async fn get(&self, path: &str) -> StatusCode {
        let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let req = Request::builder()
            .uri(format!("http://127.0.0.1:{}{path}", self.port))
            .header("authorization", "Bearer client-token")
            .body(Empty::<Bytes>::new())
            .unwrap();
        client.request(req).await.expect("request failed").status()
    }

    async fn stop(self) {
        drop(self.shutdown);
        tokio::time::timeout(Duration::from_secs(2), self.gateway)
            .await
            .expect("gateway did not shut down")
            .unwrap();
    }
}

// =================== tests ===================

/// The invariant the whole scheme rests on: the provider receives
/// exactly one credential, and it is the token the endpoint issued —
/// not the client's own, and not the client secret.
#[tokio::test]
async fn the_provider_receives_the_token_the_endpoint_issued() {
    let (provider_port, provider) = spawn_provider().await;
    let issuer = Issuer::default();
    let token_port = spawn_token_endpoint(issuer.clone()).await;
    let bind_port = free_port().await;

    let gw = Harness::start(config(
        bind_port,
        vec![oauth2_backend(
            "provider",
            provider_port,
            token_port,
            "gateway",
            "provider-creds",
            ClientAuthMethod::ClientSecretBasic,
        )],
        vec![credential("provider-creds")],
    ))
    .await;

    assert_eq!(gw.get("/provider/v1/chat").await, StatusCode::OK);
    assert_eq!(provider.credentials(), vec!["Bearer token-1"]);

    gw.stop().await;
}

/// A token is fetched once and spent many times. Anything else would
/// put a round trip to the token endpoint on every proxied request.
#[tokio::test]
async fn the_token_is_fetched_once_and_reused() {
    let (provider_port, provider) = spawn_provider().await;
    let issuer = Issuer::default();
    let token_port = spawn_token_endpoint(issuer.clone()).await;
    let bind_port = free_port().await;

    let gw = Harness::start(config(
        bind_port,
        vec![oauth2_backend(
            "provider",
            provider_port,
            token_port,
            "gateway",
            "provider-creds",
            ClientAuthMethod::ClientSecretBasic,
        )],
        vec![credential("provider-creds")],
    ))
    .await;

    for _ in 0..5 {
        assert_eq!(gw.get("/provider/").await, StatusCode::OK);
    }

    assert_eq!(issuer.request_count(), 1, "one fetch for five requests");
    assert_eq!(provider.credentials(), vec!["Bearer token-1"; 5]);

    gw.stop().await;
}

/// A cold start under load is still one fetch: the requests that
/// arrive while the first one is in flight wait for its token instead
/// of each asking for one of their own.
#[tokio::test]
async fn concurrent_first_requests_fetch_one_token_between_them() {
    let (provider_port, provider) = spawn_provider().await;
    let issuer = Issuer {
        delay: Duration::from_millis(200),
        ..Issuer::default()
    };
    let token_port = spawn_token_endpoint(issuer.clone()).await;
    let bind_port = free_port().await;

    let gw = Arc::new(
        Harness::start(config(
            bind_port,
            vec![oauth2_backend(
                "provider",
                provider_port,
                token_port,
                "gateway",
                "provider-creds",
                ClientAuthMethod::ClientSecretBasic,
            )],
            vec![credential("provider-creds")],
        ))
        .await,
    );

    let mut requests = Vec::new();
    for _ in 0..5 {
        let gw = Arc::clone(&gw);
        requests.push(tokio::spawn(async move { gw.get("/provider/").await }));
    }
    for request in requests {
        assert_eq!(request.await.unwrap(), StatusCode::OK);
    }

    assert_eq!(issuer.request_count(), 1, "five requests, one fetch");
    assert_eq!(provider.credentials(), vec!["Bearer token-1"; 5]);

    Arc::into_inner(gw)
        .expect("no requests outstanding")
        .stop()
        .await;
}

/// A token that is about to expire is replaced while requests keep flowing.
/// One request pays for the refresh; the rest are answered with the token
/// that is still valid, and none of them fails.
#[tokio::test]
async fn an_expiring_token_is_replaced_without_failing_a_request() {
    let (provider_port, provider) = spawn_provider().await;
    let issuer = Issuer {
        // Stale after a second, dead after two.
        expires_in: 2,
        // Long enough that the refresh is observably still in flight
        // while the other requests are answered.
        delay: Duration::from_millis(250),
        ..Issuer::default()
    };
    let token_port = spawn_token_endpoint(issuer.clone()).await;
    let bind_port = free_port().await;

    let gw = Arc::new(
        Harness::start(config(
            bind_port,
            vec![oauth2_backend(
                "provider",
                provider_port,
                token_port,
                "gateway",
                "provider-creds",
                ClientAuthMethod::ClientSecretBasic,
            )],
            vec![credential("provider-creds")],
        ))
        .await,
    );

    assert_eq!(gw.get("/provider/").await, StatusCode::OK);
    // Past the refresh window, and well short of expiry.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let mut requests = Vec::new();
    for _ in 0..5 {
        let gw = Arc::clone(&gw);
        requests.push(tokio::spawn(async move { gw.get("/provider/").await }));
    }
    for request in requests {
        assert_eq!(
            request.await.unwrap(),
            StatusCode::OK,
            "a refresh must not fail a request in flight"
        );
    }

    assert_eq!(
        issuer.request_count(),
        2,
        "one refresh, not one per request"
    );
    let credentials = provider.credentials();
    assert!(
        credentials.contains(&"Bearer token-1".to_string()),
        "the token still valid was spent while the refresh was in flight: {credentials:?}"
    );
    assert_eq!(
        credentials.last().map(String::as_str),
        Some("Bearer token-2"),
        "and the refreshed one afterwards: {credentials:?}"
    );

    Arc::into_inner(gw)
        .expect("no requests outstanding")
        .stop()
        .await;
}

/// Two backends, two credentials, two tokens. Sharing one would send
/// a provider a token minted for someone else.
#[tokio::test]
async fn two_backends_with_different_credentials_never_share_a_token() {
    let (first_port, first) = spawn_provider().await;
    let (second_port, second) = spawn_provider().await;
    let issuer = Issuer::default();
    let token_port = spawn_token_endpoint(issuer.clone()).await;
    let bind_port = free_port().await;

    let gw = Harness::start(config(
        bind_port,
        vec![
            oauth2_backend(
                "first",
                first_port,
                token_port,
                "client-one",
                "first-creds",
                ClientAuthMethod::ClientSecretBasic,
            ),
            oauth2_backend(
                "second",
                second_port,
                token_port,
                "client-two",
                "second-creds",
                ClientAuthMethod::ClientSecretBasic,
            ),
        ],
        vec![credential("first-creds"), credential("second-creds")],
    ))
    .await;

    assert_eq!(gw.get("/first/").await, StatusCode::OK);
    assert_eq!(gw.get("/second/").await, StatusCode::OK);

    assert_eq!(issuer.request_count(), 2, "one fetch per credential");
    assert_eq!(first.credentials(), vec!["Bearer token-1"]);
    assert_eq!(second.credentials(), vec!["Bearer token-2"]);
    // And each asked as itself.
    let client_ids: Vec<String> = issuer
        .requests()
        .iter()
        .map(|r| r.authorization.clone().expect("a Basic header"))
        .collect();
    assert_eq!(client_ids[0], basic("client-one"));
    assert_eq!(client_ids[1], basic("client-two"));

    gw.stop().await;
}

/// `ClientSecretBasic` is the default: the credentials are a header,
/// and the body says nothing about the client.
#[tokio::test]
async fn client_secret_basic_authenticates_with_a_header() {
    let (provider_port, _provider) = spawn_provider().await;
    let issuer = Issuer::default();
    let token_port = spawn_token_endpoint(issuer.clone()).await;
    let bind_port = free_port().await;

    let gw = Harness::start(config(
        bind_port,
        vec![oauth2_backend(
            "provider",
            provider_port,
            token_port,
            "gateway",
            "provider-creds",
            ClientAuthMethod::ClientSecretBasic,
        )],
        vec![credential("provider-creds")],
    ))
    .await;
    assert_eq!(gw.get("/provider/").await, StatusCode::OK);

    let asked = issuer.requests().pop().expect("a token request");
    assert_eq!(
        asked.authorization.as_deref(),
        Some(basic("gateway").as_str())
    );
    assert_eq!(asked.form, "grant_type=client_credentials");
    assert!(!asked.form.contains(CLIENT_SECRET));

    gw.stop().await;
}

/// `ClientSecretPost` is the other half: the same credentials, in the
/// body, and no header at all.
#[tokio::test]
async fn client_secret_post_authenticates_in_the_body() {
    let (provider_port, _provider) = spawn_provider().await;
    let issuer = Issuer::default();
    let token_port = spawn_token_endpoint(issuer.clone()).await;
    let bind_port = free_port().await;

    let gw = Harness::start(config(
        bind_port,
        vec![oauth2_backend(
            "provider",
            provider_port,
            token_port,
            "gateway",
            "provider-creds",
            ClientAuthMethod::ClientSecretPost,
        )],
        vec![credential("provider-creds")],
    ))
    .await;
    assert_eq!(gw.get("/provider/").await, StatusCode::OK);

    let asked = issuer.requests().pop().expect("a token request");
    assert!(asked.authorization.is_none());
    assert_eq!(
        asked.form,
        format!("grant_type=client_credentials&client_id=gateway&client_secret={CLIENT_SECRET}")
    );

    gw.stop().await;
}

/// A token endpoint that refuses is a request the gateway cannot
/// make: reaching the provider unauthenticated is a different request
/// than the one that was asked for, so it is not made at all.
#[tokio::test]
async fn a_refused_token_fails_the_request_and_never_dials_the_provider() {
    let (provider_port, provider) = spawn_provider().await;
    let issuer = Issuer {
        refuse: Some(StatusCode::UNAUTHORIZED),
        ..Issuer::default()
    };
    let token_port = spawn_token_endpoint(issuer.clone()).await;
    let bind_port = free_port().await;

    let gw = Harness::start(config(
        bind_port,
        vec![oauth2_backend(
            "provider",
            provider_port,
            token_port,
            "gateway",
            "provider-creds",
            ClientAuthMethod::ClientSecretBasic,
        )],
        vec![credential("provider-creds")],
    ))
    .await;

    assert_eq!(
        gw.get("/provider/").await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(provider.request_count(), 0);

    // And the second request does not ask again: a token endpoint
    // that is failing is backed off, not hammered once per request.
    assert_eq!(
        gw.get("/provider/").await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(issuer.request_count(), 1);

    gw.stop().await;
}

/// A client secret that never resolved is not spent: there is nothing
/// to authenticate the token request with, so no token request is
/// made.
#[tokio::test]
async fn an_unresolved_client_secret_asks_for_no_token() {
    let (provider_port, provider) = spawn_provider().await;
    let issuer = Issuer::default();
    let token_port = spawn_token_endpoint(issuer.clone()).await;
    let bind_port = free_port().await;

    let gw = Harness::start(config(
        bind_port,
        vec![oauth2_backend(
            "provider",
            provider_port,
            token_port,
            "gateway",
            "provider-creds",
            ClientAuthMethod::ClientSecretBasic,
        )],
        // The secret the backend names is not here.
        vec![],
    ))
    .await;

    assert_eq!(
        gw.get("/provider/").await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(issuer.request_count(), 0);
    assert_eq!(provider.request_count(), 0);

    gw.stop().await;
}

/// The `Authorization` header a client authenticating with HTTP Basic
/// sends, as the endpoint should see it.
fn basic(client_id: &str) -> String {
    use base64::Engine;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{CLIENT_SECRET}"));
    format!("Basic {encoded}")
}
