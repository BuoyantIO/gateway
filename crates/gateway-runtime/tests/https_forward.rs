//! HTTPS termination integration tests. A real TLS client connects to
//! a `Gateway` serving a `BindProtocol::Tls` bind; the gateway
//! terminates TLS and forwards plaintext to an in-process echo. Covers
//! HTTP/1.1 and ALPN-negotiated HTTP/2, plus the "secret absent" case.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use gateway_config::backend::{Backend, BackendProtocol, Endpoint, StaticBackend};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::config::GatewayConfig;
use gateway_config::listener::{CertRef, HttpsListener, Listener, TlsConfig, TlsMode};
use gateway_config::route::{HttpMatch, HttpRoute, PathMatch};
use gateway_config::secret::TlsSecret;
use gateway_runtime::Gateway;
use gateway_state::Store;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;

// Throwaway self-signed EC cert + PKCS#8 key (same pair the
// gateway-config / store tests use).
const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
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

const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcB/ubr8b5gfbp97H\n\
/hzgYBDdRqvQrz6jRyF1kz8TrcChRANCAARmgXqAedHQ4l0guGq9PvlkTmhf82QK\n\
huMI9EpCZAC8QV43yS5/4Ljj171TYarpLsLvYMlaNyyvyBrGOIxGJ7Qf\n\
-----END PRIVATE KEY-----\n";

// =================== harness ===================

/// Plaintext HTTP echo: responds with `"{METHOD} {PATH}"`.
async fn spawn_http_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let body = format!("{} {}", req.method(), req.uri().path());
                    Ok::<_, Infallible>(http::Response::new(http_body_util::Full::new(
                        Bytes::from(body),
                    )))
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    port
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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

/// A TLS bind with one HTTPS listener (cert ref `app-tls`), one route,
/// one backend pointing at `upstream_port`. `with_secret` controls
/// whether the `app-tls` secret is present.
fn https_config(bind_port: u16, upstream_port: u16, with_secret: bool) -> GatewayConfig {
    let listener = Listener::Https(HttpsListener {
        name: "l".into(),
        hostname: None,
        tls: TlsConfig {
            mode: TlsMode::Terminate,
            certificates: vec![CertRef {
                name: "app-tls".into(),
                kind: "Secret".into(),
            }],
        },
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
                name: "be".into(),
                weight: 1,
            }],
            filters: vec![],
        }],
    });
    GatewayConfig {
        name: "test".into(),
        binds: vec![Bind {
            name: "b".into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: bind_port,
            bind_protocol: BindProtocol::Tls,
            listeners: vec![listener],
        }],
        backends: vec![Backend::Static(StaticBackend {
            name: "be".into(),
            endpoints: vec![Endpoint {
                name: "e0".into(),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: upstream_port,
            }],
            protocol: BackendProtocol::Http1,
        })],
        secrets: if with_secret {
            vec![TlsSecret::new("app-tls", CERT_PEM, KEY_PEM).unwrap()]
        } else {
            vec![]
        },
    }
}

// Test-only verifier: trust any server cert (the throwaway cert has no
// SANs and we connect to 127.0.0.1).
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config(alpn: &[&[u8]]) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

async fn tls_connect(bind_port: u16, alpn: &[&[u8]]) -> tokio_rustls::client::TlsStream<TcpStream> {
    let connector = TlsConnector::from(Arc::new(client_config(alpn)));
    let tcp = TcpStream::connect(("127.0.0.1", bind_port)).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    connector.connect(name, tcp).await.expect("TLS handshake")
}

// =================== tests ===================

#[tokio::test]
async fn https_h1_round_trip() {
    let upstream = spawn_http_echo().await;
    let bind_port = free_port().await;
    let store = Store::new();
    let _ = store.apply(&https_config(bind_port, upstream, true));
    let (gw, shutdown) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let tls = tls_connect(bind_port, &[b"http/1.1"]).await;
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = send
        .send_request(
            Request::builder()
                .uri("/hello")
                .header("host", "example.com")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"GET /hello");

    let _ = shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), gw).await;
}

#[tokio::test]
async fn https_h2_round_trip_via_alpn() {
    let upstream = spawn_http_echo().await;
    let bind_port = free_port().await;
    let store = Store::new();
    let _ = store.apply(&https_config(bind_port, upstream, true));
    let (gw, shutdown) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let tls = tls_connect(bind_port, &[b"h2"]).await;
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "ALPN should negotiate h2"
    );
    let (mut send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = send
        .send_request(
            Request::builder()
                .uri("/h2")
                .header("host", "example.com")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"GET /h2");

    let _ = shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), gw).await;
}

#[tokio::test]
async fn https_not_served_when_secret_absent() {
    let upstream = spawn_http_echo().await;
    let bind_port = free_port().await;
    let store = Store::new();
    // Secret absent: the HTTPS listener stays pending, so the bind has
    // no TLS config and drops connections before/at the handshake.
    let _ = store.apply(&https_config(bind_port, upstream, false));
    let (gw, shutdown) = spawn_gateway(store);
    wait_for_listening(bind_port).await;

    let connector = TlsConnector::from(Arc::new(client_config(&[b"http/1.1"])));
    let tcp = TcpStream::connect(("127.0.0.1", bind_port)).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), connector.connect(name, tcp)).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "handshake must fail when the cert secret is absent"
    );

    let _ = shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), gw).await;
}
