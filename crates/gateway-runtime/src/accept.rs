use std::net::SocketAddr;
use std::sync::Arc;

use gateway_config::bind::BindProtocol;
use gateway_config::secret::TlsSecret;
use gateway_state::{BindKey, Store};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::lb::LoadBalancer;
use crate::proxy::http;
use crate::proxy::http::HttpClient;

/// Per-bind accept task. Opens a `TcpListener` on `addr`, loops on
/// accept, and hands each accepted connection to the HTTP handler —
/// directly for an `Http` bind, or after terminating TLS for a `Tls`
/// bind.
///
/// Exits when the task is aborted (typically because the bind was
/// removed or its listening address changed).
///
/// TODO: add a shutdown signal so we can drain in-flight connections
/// instead of dropping them on shutdown.
pub(crate) async fn run_bind(
    store: Store,
    bind_key: BindKey,
    addr: SocketAddr,
    protocol: BindProtocol,
    lb: Arc<LoadBalancer>,
    http_client: HttpClient,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(bind = %bind_key, %addr, error = %e, "failed to bind");
            return;
        }
    };
    let local_addr = listener.local_addr().unwrap_or(addr);
    tracing::info!(bind = %bind_key, %local_addr, ?protocol, "bind listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(bind = %bind_key, error = %e, "accept failed");
                continue;
            }
        };
        let store = store.clone();
        let bind_key = bind_key.clone();
        let lb = Arc::clone(&lb);
        let http_client = http_client.clone();

        match protocol {
            BindProtocol::Http => {
                tokio::spawn(async move {
                    http::handle_connection(store, bind_key, stream, peer, lb, http_client).await;
                });
            }
            BindProtocol::Tls => {
                tokio::spawn(async move {
                    let Some(config) = server_config(&store, &bind_key) else {
                        tracing::debug!(bind = %bind_key, %peer,
                            "no TLS config for bind (cert not present?); dropping connection");
                        return;
                    };
                    match TlsAcceptor::from(config).accept(stream).await {
                        Ok(tls) => {
                            http::handle_connection(store, bind_key, tls, peer, lb, http_client)
                                .await;
                        }
                        Err(e) => {
                            tracing::debug!(bind = %bind_key, %peer, error = %e,
                                "TLS handshake failed");
                        }
                    }
                });
            }
            BindProtocol::Tcp => {
                tracing::warn!(bind = %bind_key, "TCP binds are not served; dropping connection");
            }
        }
    }
}

/// Build the `ServerConfig` for a TLS bind from its (single, in this
/// version) terminating listener's certificate. Returns `None` when the
/// bind has no active TLS listener yet — e.g. its secret hasn't landed.
fn server_config(store: &Store, bind_key: &BindKey) -> Option<Arc<ServerConfig>> {
    let bind = store.read().bind(bind_key)?;
    let secret = bind
        .listeners
        .iter()
        .find_map(|l| l.tls.as_ref())
        .and_then(|tls| tls.secrets.first())?;
    match build_server_config(secret) {
        Ok(config) => Some(config),
        Err(e) => {
            tracing::error!(bind = %bind_key, error = %e, "failed to build TLS server config");
            None
        }
    }
}

fn build_server_config(secret: &TlsSecret) -> Result<Arc<ServerConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(secret.certs.clone(), secret.key.clone_key())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
