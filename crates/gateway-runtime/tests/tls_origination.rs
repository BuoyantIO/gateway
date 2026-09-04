//! TLS origination integration tests. A plaintext client reaches a
//! `Gateway` on an HTTP bind, which dials a real TLS server upstream
//! as a dialable backend: verification against a locally generated CA,
//! the SNI override, the insecure switch, and the HTTP version ALPN
//! settles on. The failure cases assert what the client is told and
//! what the gateway counted.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use gateway_config::backend::{
    AlpnProtocol, Backend, BackendRef, BackendTls, DialableBackend, TrustRoots,
};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::config::GatewayConfig;
use gateway_config::listener::{HttpListener, Listener};
use gateway_config::route::{HttpMatch, HttpRoute, PathMatch};
use gateway_config::secret::{Secret, TlsSecret};
use gateway_runtime::{Gateway, Metrics, drain};
use gateway_state::Store;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

// A locally generated CA and the leaf it signed, for
// `localhost` / `api.test`. Both are valid for a century, so no test
// run ever sees an expired chain.
const CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBsjCCAVmgAwIBAgIUAqZNnOsD0G5WuwUP/VAqg1pioKowCgYIKoZIzj0EAwIw\n\
JjEkMCIGA1UEAwwbZ2F0ZXdheS1vcmlnaW5hdGlvbi10ZXN0LWNhMCAXDTI2MDgy\n\
NzE0NDYzMVoYDzIxMjYwODAzMTQ0NjMxWjAmMSQwIgYDVQQDDBtnYXRld2F5LW9y\n\
aWdpbmF0aW9uLXRlc3QtY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATHgF+C\n\
6usYwYsp3HUehFK4Ru6DLVd++3/EQJM2XjDM2RNV8cXplEJpa4H7Agcaz3Dfq06O\n\
gOEf6xHpjE9bYRX6o2MwYTAdBgNVHQ4EFgQUmmXyVJdN4bk40OiR5xOwOQ7g018w\n\
HwYDVR0jBBgwFoAUmmXyVJdN4bk40OiR5xOwOQ7g018wDwYDVR0TAQH/BAUwAwEB\n\
/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDRwAwRAIgQjTSJ8Ka7Y8znUK2\n\
JmS1VOAC/qDna5hhngFX3Xo2HO4CIEwQcUUqHmydr7a881ReF9mfw2A2/ZZU4rjn\n\
8V48OIbq\n\
-----END CERTIFICATE-----\n";

const LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIB1TCCAXugAwIBAgIUVLTPUUWjrU7KocTsDVnTRLzg++4wCgYIKoZIzj0EAwIw\n\
JjEkMCIGA1UEAwwbZ2F0ZXdheS1vcmlnaW5hdGlvbi10ZXN0LWNhMCAXDTI2MDgy\n\
NzE0NDYzMVoYDzIxMjYwODAzMTQ0NjMxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3Qw\n\
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQUDCA32PJSGujpUsM+sLBoL/iKNNAc\n\
P771SzU047Y6/GT0Yd0NoYosJXYRWmwW7rbmuaQP+9Hv0OWOtDeTnW8Uo4GWMIGT\n\
MB4GA1UdEQQXMBWCCWxvY2FsaG9zdIIIYXBpLnRlc3QwDAYDVR0TAQH/BAIwADAO\n\
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFFjh\n\
tqmJEwNoRYJXLOrsjgAWYR5yMB8GA1UdIwQYMBaAFJpl8lSXTeG5ONDokecTsDkO\n\
4NNfMAoGCCqGSM49BAMCA0gAMEUCIQD0Qxnf+dlFtUdXSW6S6du4Ha8N7g54I4j4\n\
0xXTenSg+gIgNuSajDRruKN+wcp5gPEbcZ1lzgOt28293yPj5DBqJ4M=\n\
-----END CERTIFICATE-----\n";

const LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9E9CybOoAv5nunPY\n\
G+2BYNpApQ5oWbsrNL3i2TXPyn6hRANCAAQUDCA32PJSGujpUsM+sLBoL/iKNNAc\n\
P771SzU047Y6/GT0Yd0NoYosJXYRWmwW7rbmuaQP+9Hv0OWOtDeTnW8U\n\
-----END PRIVATE KEY-----\n";

// An unrelated self-signed cert (the pair the other suites use), to
// stand in as a CA the upstream chain does not descend from.
const OTHER_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBgjCCASmgAwIBAgIUW/OT9NoEgpMEra4i2ttY/oSsRe0wCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMZ2F0ZXdheS10ZXN0MB4XDTI2MDYyNjEwNTEyOFoXDTM2MDYy\n\
MzEwNTEyOFowFzEVMBMGA1UEAwwMZ2F0ZXdheS10ZXN0MFkwEwYHKoZIzj0CAQYI\n\
KoZIzj0DAQcDQgAEZoF6gHnR0OJdILhqvT75ZE5oX/NkCobjCPRKQmQAvEFeN8ku\n\
f+C449e9U2Gq6S7C72DJWjcsr8gaxjiMRie0H6NTMFEwHQYDVR0OBBYEFKmMFFZT\n\
6oW/R893bFKGDqRaBuoRMB8GA1UdIwQYMBaAFKmMFFZT6oW/R893bFKGDqRaBuoR\n\
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgEdjQ6EJUY9QMrNQy\n\
YhAYK89fjb5J6TE0AJY4QnmcFR0CIHo7A7WYP2hT7rr6orgxEqAVx7DGbd0aCCqe\n\
GkIpYyxV\n\
-----END CERTIFICATE-----\n";

// =================== upstream ===================

/// Spawn a TLS server on loopback serving the leaf certificate, with
/// `alpn` offered in the handshake. Two paths:
///
/// * anything but `/stream` answers `"{METHOD} {PATH}"` and reports
///   the wire version it was reached over in `x-server-version`,
///   which is how a test sees what ALPN settled on;
/// * `/stream` answers in chunks with a gap before the first one, the
///   shape a streamed completion has.
async fn spawn_tls_upstream(alpn: &[AlpnProtocol]) -> u16 {
    spawn_counting_tls_upstream(alpn).await.0
}

/// The same upstream, plus a count of the connections it accepted:
/// how a test sees whether the gateway reused a pooled connection or
/// made a new one.
async fn spawn_counting_tls_upstream(alpn: &[AlpnProtocol]) -> (u16, Arc<AtomicUsize>) {
    let secret = TlsSecret::new("", "leaf", LEAF_CERT_PEM, LEAF_KEY_PEM).expect("valid leaf");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(secret.certs.clone(), secret.key.unwrap())
        .expect("server config");
    config.alpn_protocols = alpn.iter().map(|p| p.as_wire().to_vec()).collect();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let io = TokioIo::new(tls);
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service_fn(upstream_service))
                    .await;
            });
        }
    });
    (port, accepted)
}

async fn upstream_service(
    req: Request<Incoming>,
) -> Result<http::Response<UpstreamBody>, Infallible> {
    let version = format!("{:?}", req.version());
    if req.uri().path() == "/stream" {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
        tokio::spawn(async move {
            for token in ["data: one\n\n", "data: two\n\n", "data: [DONE]\n\n"] {
                tokio::time::sleep(Duration::from_millis(30)).await;
                if tx.send(Ok(Frame::data(Bytes::from(token)))).await.is_err() {
                    return;
                }
            }
        });
        let body = http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx));
        return Ok(http::Response::builder()
            .status(StatusCode::OK)
            .header("x-server-version", version)
            .header(http::header::CONTENT_TYPE, "text/event-stream")
            .body(UpstreamBody::Stream(body))
            .unwrap());
    }
    // However the gateway addressed us: the `Host` header on H1, the
    // `:authority` hyper folded into the URI on H2.
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| req.uri().authority().map(ToString::to_string))
        .unwrap_or_default();
    let body = format!("{} {}", req.method(), req.uri().path());
    Ok(http::Response::builder()
        .status(StatusCode::OK)
        .header("x-server-version", version)
        .header("x-echo-host", host)
        .body(UpstreamBody::Full(http_body_util::Full::new(Bytes::from(
            body,
        ))))
        .unwrap())
}

/// The upstream's two body shapes under one type, since a
/// `service_fn` has to return just the one.
enum UpstreamBody {
    Full(http_body_util::Full<Bytes>),
    Stream(
        http_body_util::StreamBody<
            tokio_stream::wrappers::ReceiverStream<Result<Frame<Bytes>, Infallible>>,
        >,
    ),
}

impl hyper::body::Body for UpstreamBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Full(b) => std::pin::Pin::new(b).poll_frame(cx),
            Self::Stream(b) => std::pin::Pin::new(b).poll_frame(cx),
        }
    }
}

// =================== gateway config ===================

/// One HTTP bind, one route, one dialable backend reached over TLS.
fn tls_config(bind_port: u16, upstream: TlsBackend) -> GatewayConfig {
    GatewayConfig {
        name: "test".into(),
        binds: vec![Bind {
            name: "b".into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: bind_port,
            bind_protocol: BindProtocol::Http,
            listeners: vec![Listener::Http(HttpListener {
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
                        name: "provider".into(),
                        weight: 1,
                    }],
                    filters: vec![],
                }],
            })],
        }],
        backends: vec![Backend::Dialable(DialableBackend {
            name: "provider".into(),
            host: upstream.host.into(),
            port: upstream.port,
            path_prefix: None,
            tls: Some(BackendTls {
                ca: upstream.ca,
                sni: upstream.sni.map(str::to_owned),
                alpn: upstream.alpn,
                insecure_skip_verify: upstream.insecure,
            }),
            auth: None,
        })],
        secrets: upstream.secrets,
        extensions: vec![],
    }
}

/// What one test wants the backend's TLS block (and the secrets
/// behind it) to say.
struct TlsBackend {
    host: &'static str,
    port: u16,
    ca: TrustRoots,
    sni: Option<&'static str>,
    alpn: Vec<AlpnProtocol>,
    insecure: bool,
    secrets: Vec<Secret>,
}

impl TlsBackend {
    /// The common case: dial `localhost`, verifying against the test
    /// CA, offering both protocols.
    fn trusting_the_test_ca(port: u16) -> Self {
        Self {
            host: "localhost",
            port,
            ca: TrustRoots::Secret {
                namespace: String::new(),
                name: "provider-ca".into(),
            },
            sni: None,
            alpn: vec![AlpnProtocol::H2, AlpnProtocol::Http11],
            insecure: false,
            secrets: vec![
                TlsSecret::ca("", "provider-ca", CA_PEM)
                    .expect("valid CA")
                    .into(),
            ],
        }
    }
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn wait_for_listening(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("gateway never started listening on {port}");
}

/// Bring up a gateway on `bind_port` with `cfg` applied, and hand back
/// the metrics it records against.
async fn spawn_gateway(
    cfg: &GatewayConfig,
    bind_port: u16,
) -> (drain::Signal, Arc<Metrics>, tokio::task::JoinHandle<()>) {
    let store = Store::new();
    let _ = store.apply(cfg);
    spawn_gateway_on(store, bind_port).await
}

/// The same, on a store the caller keeps a handle to, for a test that
/// applies more config while the gateway is running.
async fn spawn_gateway_on(
    store: Store,
    bind_port: u16,
) -> (drain::Signal, Arc<Metrics>, tokio::task::JoinHandle<()>) {
    let metrics = Metrics::new();
    let gw = Gateway::with_metrics(store, Arc::clone(&metrics));
    let (stop, watch) = drain::channel();
    let handle = tokio::spawn(async move { gw.run(watch).await.unwrap() });
    wait_for_listening(bind_port).await;
    (stop, metrics, handle)
}

fn client() -> Client<hyper_util::client::legacy::connect::HttpConnector, Empty<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

/// The `requests_total` series the runtime recorded, as text.
fn scrape(metrics: &Metrics) -> String {
    let mut registry = prometheus_client::registry::Registry::with_prefix("gateway");
    metrics.register(&mut registry);
    let mut out = String::new();
    prometheus_client::encoding::text::encode(&mut out, &registry).expect("encode");
    out
}

// =================== tests ===================

#[tokio::test]
async fn tls_round_trip_against_a_local_ca() {
    let upstream = spawn_tls_upstream(&[AlpnProtocol::H2, AlpnProtocol::Http11]).await;
    let bind_port = free_port().await;
    let cfg = tls_config(bind_port, TlsBackend::trusting_the_test_ca(upstream));
    let (stop, _metrics, gw) = spawn_gateway(&cfg, bind_port).await;

    let resp = client()
        .get(
            format!("http://127.0.0.1:{bind_port}/chat")
                .parse()
                .unwrap(),
        )
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    // Addressed as itself. Over h2 that is `:authority`, with no
    // stale `Host` beside it to contradict it.
    assert_eq!(
        resp.headers().get("x-echo-host").unwrap(),
        &format!("localhost:{upstream}")
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"GET /chat");

    stop.drain().await;
    gw.await.unwrap();
}

/// A streamed completion: the first token has to reach the client
/// while the upstream stream is still open, not after it closes.
#[tokio::test]
async fn streamed_completion_round_trips_over_tls() {
    let upstream = spawn_tls_upstream(&[AlpnProtocol::H2, AlpnProtocol::Http11]).await;
    let bind_port = free_port().await;
    let cfg = tls_config(bind_port, TlsBackend::trusting_the_test_ca(upstream));
    let (stop, _metrics, gw) = spawn_gateway(&cfg, bind_port).await;

    let resp = client()
        .get(
            format!("http://127.0.0.1:{bind_port}/stream")
                .parse()
                .unwrap(),
        )
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body = resp.into_body();
    let mut chunks: Vec<String> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("upstream frame");
        if let Ok(data) = frame.into_data() {
            // Observed before the body ended: this loop is still
            // running.
            chunks.push(String::from_utf8(data.to_vec()).unwrap());
            if chunks.len() == 1 {
                assert_eq!(chunks[0], "data: one\n\n", "first token arrives on its own");
            }
        }
    }
    assert_eq!(
        chunks.concat(),
        "data: one\n\ndata: two\n\ndata: [DONE]\n\n"
    );

    stop.drain().await;
    gw.await.unwrap();
}

/// A chain that does not descend from the configured CA fails the
/// dial, and is counted as a dial failure like any other.
#[tokio::test]
async fn untrusted_chain_fails_the_dial() {
    let upstream = spawn_tls_upstream(&[AlpnProtocol::Http11]).await;
    let bind_port = free_port().await;
    let mut backend = TlsBackend::trusting_the_test_ca(upstream);
    backend.secrets = vec![
        TlsSecret::ca("", "provider-ca", OTHER_CA_PEM)
            .expect("valid CA")
            .into(),
    ];
    let cfg = tls_config(bind_port, backend);
    let (stop, metrics, gw) = spawn_gateway(&cfg, bind_port).await;

    let resp = client()
        .get(
            format!("http://127.0.0.1:{bind_port}/chat")
                .parse()
                .unwrap(),
        )
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(
        scrape(&metrics).contains(r#"reason="dial_failure""#),
        "a rejected chain is counted as a dial failure"
    );

    stop.drain().await;
    gw.await.unwrap();
}

/// The certificate covers `localhost`, not the loopback address. The
/// name the gateway dials is the name it verifies, so this fails.
#[tokio::test]
async fn a_name_the_certificate_does_not_cover_fails_the_dial() {
    let upstream = spawn_tls_upstream(&[AlpnProtocol::Http11]).await;
    let bind_port = free_port().await;
    let mut backend = TlsBackend::trusting_the_test_ca(upstream);
    backend.host = "127.0.0.1";
    let cfg = tls_config(bind_port, backend);
    let (stop, metrics, gw) = spawn_gateway(&cfg, bind_port).await;

    let resp = client()
        .get(
            format!("http://127.0.0.1:{bind_port}/chat")
                .parse()
                .unwrap(),
        )
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(scrape(&metrics).contains(r#"reason="dial_failure""#));

    stop.drain().await;
    gw.await.unwrap();
}

/// The same backend with an SNI override succeeds: the address is
/// still dialed, but the handshake asks for — and verifies — the name
/// the certificate carries.
#[tokio::test]
async fn sni_override_verifies_the_overridden_name() {
    let upstream = spawn_tls_upstream(&[AlpnProtocol::Http11]).await;
    let bind_port = free_port().await;
    let mut backend = TlsBackend::trusting_the_test_ca(upstream);
    backend.host = "127.0.0.1";
    backend.sni = Some("api.test");
    let cfg = tls_config(bind_port, backend);
    let (stop, _metrics, gw) = spawn_gateway(&cfg, bind_port).await;

    let resp = client()
        .get(
            format!("http://127.0.0.1:{bind_port}/chat")
                .parse()
                .unwrap(),
        )
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);

    stop.drain().await;
    gw.await.unwrap();
}

/// The development switch: an untrusted chain and a name nothing
/// covers both go through.
#[tokio::test]
async fn insecure_skip_verify_accepts_anything() {
    let upstream = spawn_tls_upstream(&[AlpnProtocol::Http11]).await;
    let bind_port = free_port().await;
    let mut backend = TlsBackend::trusting_the_test_ca(upstream);
    backend.host = "127.0.0.1";
    backend.insecure = true;
    let cfg = tls_config(bind_port, backend);
    let (stop, _metrics, gw) = spawn_gateway(&cfg, bind_port).await;

    let resp = client()
        .get(
            format!("http://127.0.0.1:{bind_port}/chat")
                .parse()
                .unwrap(),
        )
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);

    stop.drain().await;
    gw.await.unwrap();
}

/// ALPN decides the version upstream: a server that takes h2 is
/// spoken to over h2, even though the client downstream was HTTP/1.1
/// and the backend names no protocol.
#[tokio::test]
async fn alpn_negotiates_http2_upstream() {
    let upstream = spawn_tls_upstream(&[AlpnProtocol::H2, AlpnProtocol::Http11]).await;
    let bind_port = free_port().await;
    let cfg = tls_config(bind_port, TlsBackend::trusting_the_test_ca(upstream));
    let (stop, _metrics, gw) = spawn_gateway(&cfg, bind_port).await;

    let resp = client()
        .get(
            format!("http://127.0.0.1:{bind_port}/chat")
                .parse()
                .unwrap(),
        )
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-server-version").unwrap(),
        "HTTP/2.0",
        "the server offered h2 and got h2"
    );

    stop.drain().await;
    gw.await.unwrap();
}

/// The same gateway config against a server that only offers
/// http/1.1 settles on HTTP/1.1 — one client per backend, the version
/// per handshake.
#[tokio::test]
async fn alpn_settles_on_http1_when_that_is_all_the_server_offers() {
    let upstream = spawn_tls_upstream(&[AlpnProtocol::Http11]).await;
    let bind_port = free_port().await;
    let cfg = tls_config(bind_port, TlsBackend::trusting_the_test_ca(upstream));
    let (stop, _metrics, gw) = spawn_gateway(&cfg, bind_port).await;

    let resp = client()
        .get(
            format!("http://127.0.0.1:{bind_port}/chat")
                .parse()
                .unwrap(),
        )
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-server-version").unwrap(), "HTTP/1.1");
    // On H1 the `Host` is the backend's own origin, filled in from
    // the upstream URI once the client's was dropped.
    assert_eq!(
        resp.headers().get("x-echo-host").unwrap(),
        &format!("localhost:{upstream}")
    );

    stop.drain().await;
    gw.await.unwrap();
}

/// A control-plane resync re-sends every object, identical config
/// included. The backend's revision does not move, so the client and
/// its pooled connection survive: the upstream sees one connection
/// across both requests. Changing the backend for real is what
/// replaces the client, and the upstream sees a second connection.
#[tokio::test]
async fn identical_config_reuses_the_connection_and_a_change_replaces_it() {
    let (upstream, accepted) = spawn_counting_tls_upstream(&[AlpnProtocol::Http11]).await;
    let bind_port = free_port().await;
    let cfg = tls_config(bind_port, TlsBackend::trusting_the_test_ca(upstream));
    let store = Store::new();
    let _ = store.apply(&cfg);
    let (stop, _metrics, gw) = spawn_gateway_on(store.clone(), bind_port).await;

    let get = || async {
        let resp = client()
            .get(
                format!("http://127.0.0.1:{bind_port}/chat")
                    .parse()
                    .unwrap(),
            )
            .await
            .expect("request failed");
        assert_eq!(resp.status(), StatusCode::OK);
        // Drain the body so the connection goes back to the pool.
        let _ = resp.into_body().collect().await.unwrap();
    };

    get().await;
    assert_eq!(accepted.load(Ordering::SeqCst), 1);

    // What a resync looks like: the same secret and the same backend,
    // re-sent as new objects.
    for backend in &cfg.backends {
        store.upsert_backend(backend.clone());
    }
    for secret in &cfg.secrets {
        store.upsert_secret(secret.clone());
    }
    get().await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "identical config must not rebuild the client"
    );

    // A real change to the TLS block does.
    let Backend::Dialable(mut dialable) = cfg.backends[0].clone() else {
        unreachable!("built as dialable");
    };
    dialable.tls.as_mut().expect("tls block").sni = Some("localhost".into());
    store.upsert_backend(Backend::Dialable(dialable));
    get().await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "changed settings must rebuild the client"
    );

    stop.drain().await;
    gw.await.unwrap();
}

/// An unregistered CA secret is a config problem, not an upstream
/// one: the request fails as unresolved rather than dialing with the
/// system store instead.
#[tokio::test]
async fn an_unregistered_ca_secret_fails_the_request() {
    let upstream = spawn_tls_upstream(&[AlpnProtocol::Http11]).await;
    let bind_port = free_port().await;
    let mut backend = TlsBackend::trusting_the_test_ca(upstream);
    backend.secrets = vec![];
    let cfg = tls_config(bind_port, backend);
    let (stop, metrics, gw) = spawn_gateway(&cfg, bind_port).await;

    let resp = client()
        .get(
            format!("http://127.0.0.1:{bind_port}/chat")
                .parse()
                .unwrap(),
        )
        .await
        .expect("request failed");
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let scraped = scrape(&metrics);
    assert!(scraped.contains(r#"reason="backend_unresolved""#));
    assert!(
        !scraped.contains(r#"reason="dial_failure""#),
        "nothing was dialed"
    );

    stop.drain().await;
    gw.await.unwrap();
}
