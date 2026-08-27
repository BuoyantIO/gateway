use std::net::SocketAddr;
use std::sync::Arc;

use gateway_config::bind::BindProtocol;
use gateway_config::secret::TlsSecret;
use gateway_state::{BindKey, Store};
use rustls::ServerConfig;
use rustls::server::Acceptor;
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;

use crate::drain;
use crate::gateway::ProxyCtx;
use crate::proxy::http;
use crate::proxy::http::pick_listener_by_hostname;

/// Per-bind accept task. Opens a `TcpListener` on `addr`, loops on
/// accept, and hands each accepted connection to the HTTP handler —
/// directly for an `Http` bind, or after terminating TLS for a `Tls`
/// bind.
///
/// Exits when the task is aborted (typically because the bind was
/// removed or its listening address changed). Aborting only stops new
/// accepts: every accepted connection runs in its own task holding the
/// drain watch (process shutdown merged with this bind's teardown) and
/// closes gracefully when it fires.
pub(crate) async fn run_bind(
    ctx: ProxyCtx,
    addr: SocketAddr,
    protocol: BindProtocol,
    drain: drain::Watch,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(bind = %ctx.bind_key, %addr, error = %e, "failed to bind");
            return;
        }
    };
    let local_addr = listener.local_addr().unwrap_or(addr);
    tracing::info!(bind = %ctx.bind_key, %local_addr, ?protocol, "bind listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(bind = %ctx.bind_key, error = %e, "accept failed");
                continue;
            }
        };
        let ctx = ctx.clone();
        let drain = drain.clone();

        match protocol {
            BindProtocol::Http => {
                tokio::spawn(async move {
                    http::handle_connection(ctx, stream, peer, drain).await;
                });
            }
            BindProtocol::Tls => {
                tokio::spawn(async move {
                    // Read the ClientHello (incl. SNI) before choosing a
                    // certificate, so the SNI picks the listener.
                    let start = match LazyConfigAcceptor::new(Acceptor::default(), stream).await {
                        Ok(start) => start,
                        Err(e) => {
                            tracing::debug!(bind = %ctx.bind_key, %peer, error = %e,
                                "TLS ClientHello read failed");
                            return;
                        }
                    };
                    let sni = start.client_hello().server_name().map(str::to_owned);
                    let Some(config) = server_config(&ctx.store, &ctx.bind_key, sni.as_deref())
                    else {
                        tracing::debug!(bind = %ctx.bind_key, %peer, sni = ?sni,
                            "no TLS listener matched (cert absent or unknown SNI); dropping");
                        return;
                    };
                    match start.into_stream(config).await {
                        Ok(tls) => {
                            http::handle_connection(ctx, tls, peer, drain).await;
                        }
                        Err(e) => {
                            tracing::debug!(bind = %ctx.bind_key, %peer, error = %e,
                                "TLS handshake failed");
                        }
                    }
                });
            }
            BindProtocol::Tcp => {
                tracing::warn!(bind = %ctx.bind_key, "TCP binds are not served; dropping connection");
            }
        }
    }
}

/// Build the `ServerConfig` for a connection: pick the bind's listener
/// whose hostname matches the `ClientHello` `sni` (exact > wildcard >
/// catch-all) and use its certificate. Returns `None` when no listener
/// matches (unknown SNI with no catch-all) or the matched listener's
/// cert secret isn't present yet.
fn server_config(
    store: &Store,
    bind_key: &BindKey,
    sni: Option<&str>,
) -> Option<Arc<ServerConfig>> {
    let bind = store.read().bind(bind_key)?;
    let listener = pick_listener_by_hostname(&bind.listeners, sni)?;
    // One certificate per listener for now (multiple cert refs is a
    // later change); the bind-protocol guard ensures it's a TLS listener.
    let secret = listener.tls.as_ref()?.secrets.first()?;
    // The store only promotes a listener whose secrets carry a key,
    // so this is belt and braces: a CA-only secret terminates nothing.
    if secret.key.is_none() {
        tracing::error!(bind = %bind_key, secret = %secret.name, "cert secret has no private key");
        return None;
    }
    match build_server_config(secret) {
        Ok(config) => Some(config),
        Err(e) => {
            tracing::error!(bind = %bind_key, error = %e, "failed to build TLS server config");
            None
        }
    }
}

/// # Panics
/// Panics if `secret` carries no private key; callers check first.
fn build_server_config(secret: &TlsSecret) -> Result<Arc<ServerConfig>, rustls::Error> {
    let key = secret
        .key
        .as_ref()
        .expect("caller checked the secret has a key")
        .clone_key();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(secret.certs.clone(), key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
