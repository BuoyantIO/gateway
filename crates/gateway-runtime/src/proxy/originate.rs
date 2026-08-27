//! TLS origination to a dialable backend.
//!
//! An endpoint set is reached in the clear through the process-wide
//! clients in [`crate::proxy::http`]. A dialable backend that carries
//! a TLS block gets a client of its own, built here and cached per
//! backend: the client config is compiled once from that backend's
//! settings, and the connections it pools are only ever reused for
//! requests to that same backend under that same config. Two backends
//! on the same host with different roots, SNI or ALPN therefore never
//! share a connection.
//!
//! The HTTP version upstream is the server's choice, not the config's.
//! The connector reports what ALPN settled on to hyper's pool, which
//! speaks h2 or http/1.1 over the one client accordingly — the same
//! negotiation the gateway's own listeners do on the way in.
//!
//! What it takes to reach the backend and what it takes to trust it
//! are kept apart: an unresolved CA or an unusable name fails the
//! request rather than dialing with weaker verification than the
//! operator asked for.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use gateway_config::backend::AlpnProtocol;
use gateway_state::{ActiveBackendTls, ActiveTrustRoots, BackendKey};
use http::Uri;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tower_service::Service;

use crate::proxy::body::UpstreamBody;

/// The upstream client for one dialable backend.
pub(super) type TlsClient = Client<OriginateTls, UpstreamBody>;

/// The per-backend upstream clients, keyed by backend.
///
/// An entry survives until the backend's TLS settings change, so a
/// backend keeps its pooled connections across re-applied config that
/// says the same thing. Entries for a backend the config drops are
/// left behind — one client struct, whose idle connections the pool
/// closes on its own.
pub(super) struct TlsClients {
    clients: Mutex<HashMap<BackendKey, Cached>>,
}

impl TlsClients {
    pub(super) fn new() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
        }
    }

    /// The client for `backend`, built on first use.
    ///
    /// # Errors
    /// Returns [`OriginateError`] when the backend's TLS block does
    /// not compile to a client config: an unregistered CA secret, an
    /// SNI that is not a server name, an unreadable platform trust
    /// store.
    pub(super) fn client_for(
        &self,
        backend: &BackendKey,
        tls: &Arc<ActiveBackendTls>,
    ) -> Result<TlsClient, OriginateError> {
        let mut clients = self.clients.lock();
        if let Some(cached) = clients.get(backend)
            && cached.tls.same_config(tls)
        {
            return Ok(cached.client.clone());
        }
        let client = Client::builder(TokioExecutor::new()).build(OriginateTls::new(tls)?);
        clients.insert(
            backend.clone(),
            Cached {
                tls: Arc::clone(tls),
                client: client.clone(),
            },
        );
        Ok(client)
    }
}

/// A backend's client plus the settings it was built from, which is
/// what says whether it can be reused.
struct Cached {
    tls: Arc<ActiveBackendTls>,
    client: TlsClient,
}

/// Connector for one dialable backend: dial the host, then hand the
/// socket to rustls with this backend's config.
///
/// The name verified is the SNI override when there is one, and the
/// dialed host otherwise. That split is the point of the override: a
/// backend addressed by an IP or an internal name can still be
/// verified against the certificate the provider actually serves.
#[derive(Clone)]
pub(super) struct OriginateTls {
    http: HttpConnector,
    config: Arc<ClientConfig>,
    sni: Option<ServerName<'static>>,
}

impl OriginateTls {
    fn new(tls: &ActiveBackendTls) -> Result<Self, OriginateError> {
        let sni = match &tls.sni {
            Some(name) => Some(
                ServerName::try_from(name.clone())
                    .map_err(|_| OriginateError::ServerName(name.clone()))?,
            ),
            None => None,
        };
        let mut http = HttpConnector::new();
        // The upstream URI is `https`, which the inner connector
        // would otherwise refuse: this connector is the one that
        // answers for the scheme.
        http.enforce_http(false);
        Ok(Self {
            http,
            config: client_config(tls)?,
            sni,
        })
    }
}

impl Service<Uri> for OriginateTls {
    type Response = TokioIo<TlsUpstream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.config));
        let sni = self.sni.clone();
        let host = uri.host().map(str::to_owned);
        let connecting = self.http.call(uri);
        Box::pin(async move {
            let name = if let Some(name) = sni {
                name
            } else {
                let host = host.ok_or("upstream uri has no host")?;
                ServerName::try_from(host.clone()).map_err(|_| OriginateError::ServerName(host))?
            };
            let tcp = connecting.await?;
            let stream = connector.connect(name, tcp.into_inner()).await?;
            Ok(TokioIo::new(TlsUpstream::new(stream)))
        })
    }
}

/// The TLS stream as hyper's client pool sees it: a byte stream plus
/// the one thing the pool needs to know about the handshake — whether
/// ALPN settled on h2. Reporting that is what leaves the HTTP version
/// to the server.
pub(super) struct TlsUpstream {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    negotiated_h2: bool,
}

impl TlsUpstream {
    fn new(stream: tokio_rustls::client::TlsStream<TcpStream>) -> Self {
        let negotiated_h2 = stream.get_ref().1.alpn_protocol() == Some(AlpnProtocol::H2.as_wire());
        Self {
            stream,
            negotiated_h2,
        }
    }
}

impl Connection for TlsUpstream {
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        if self.negotiated_h2 {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

impl AsyncRead for TlsUpstream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsUpstream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum OriginateError {
    #[error("building the client TLS config: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("platform trust store unusable: {0}")]
    SystemRoots(String),
    #[error("CA secret `{0}` is not registered")]
    UnresolvedCa(String),
    #[error("`{0}` is not a valid server name")]
    ServerName(String),
}

/// Compile a backend's TLS block to a client config. Called once per
/// applied version of the backend, not per request.
fn client_config(tls: &ActiveBackendTls) -> Result<Arc<ClientConfig>, OriginateError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?;
    let mut config = if tls.insecure_skip_verify {
        // Development and integration testing only, and it overrides
        // the configured roots: nothing about the peer is checked.
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(VerifyNothing(provider)))
            .with_no_client_auth()
    } else {
        builder
            .with_root_certificates(trust_roots(&tls.roots)?)
            .with_no_client_auth()
    };
    config.alpn_protocols = tls
        .alpn
        .iter()
        .map(|protocol| protocol.as_wire().to_vec())
        .collect();
    Ok(Arc::new(config))
}

/// The roots an upstream chain is verified against. A CA secret
/// replaces the platform store rather than adding to it: the operator
/// named the one issuer this backend is expected to chain to.
fn trust_roots(roots: &ActiveTrustRoots) -> Result<Arc<RootCertStore>, OriginateError> {
    match roots {
        ActiveTrustRoots::System => system_roots(),
        ActiveTrustRoots::Secret { key, secret } => {
            let secret = secret
                .as_ref()
                .ok_or_else(|| OriginateError::UnresolvedCa(key.to_string()))?;
            let mut store = RootCertStore::empty();
            for cert in &secret.certs {
                store.add(cert.clone())?;
            }
            Ok(Arc::new(store))
        }
    }
}

/// The platform trust store, loaded once for the process. Reading it
/// is I/O, and it does not change under a running gateway; every
/// backend on system roots shares the one store.
fn system_roots() -> Result<Arc<RootCertStore>, OriginateError> {
    static ROOTS: OnceLock<Result<Arc<RootCertStore>, String>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let loaded = rustls_native_certs::load_native_certs();
            // A single unreadable file in the trust directory is
            // normal and survivable; nothing at all is not.
            for error in &loaded.errors {
                tracing::warn!(%error, "reading the platform trust store");
            }
            if loaded.certs.is_empty() {
                return Err("no certificates found".to_owned());
            }
            let mut store = RootCertStore::empty();
            let (added, ignored) = store.add_parsable_certificates(loaded.certs);
            tracing::debug!(added, ignored, "loaded the platform trust store");
            Ok(Arc::new(store))
        })
        .clone()
        .map_err(OriginateError::SystemRoots)
}

/// Verifier for `insecureSkipVerify`: accepts every chain, for every
/// name. Signatures are still checked with the provider's algorithms
/// — that is what makes the handshake complete, not a trust decision.
#[derive(Debug)]
struct VerifyNothing(Arc<CryptoProvider>);

impl ServerCertVerifier for VerifyNothing {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
