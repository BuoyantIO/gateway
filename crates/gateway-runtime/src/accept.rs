use std::net::SocketAddr;
use std::sync::Arc;

use gateway_config::bind::BindProtocol;
use gateway_state::{BindKey, Store};
use tokio::net::TcpListener;

use crate::lb::LoadBalancer;
use crate::proxy;
use crate::proxy::http::HttpClient;

/// Per-bind accept task. Opens a `TcpListener` on `addr`, loops on
/// accept, and hands off each accepted socket to a per-connection task
/// whose shape depends on `bind_protocol`:
///
/// - `Tcp` → `proxy::tcp::handle_connection` (raw byte splice).
/// - `Http` → `proxy::http::handle_connection` (hyper `auto::Builder`
///   for H1/H2 selection via preface peek).
/// - `Tls` → warn + drop the connection. TLS termination is not yet
///   implemented; per the architecture doc HTTPS is the next iteration.
///
/// Exits when the task is aborted (typically because the bind was
/// removed or its listening address / protocol changed).
///
/// TODO: add a shutdown signal so we can drain in-flight connections
/// instead of dropping them on shutdown.
pub(crate) async fn run_bind(
    store: Store,
    bind_key: BindKey,
    addr: SocketAddr,
    bind_protocol: BindProtocol,
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
    tracing::info!(
        bind = %bind_key,
        %local_addr,
        protocol = ?bind_protocol,
        "bind listening"
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let store = store.clone();
                let bind_key = bind_key.clone();
                let lb = Arc::clone(&lb);
                let http_client = http_client.clone();
                match bind_protocol {
                    BindProtocol::Tcp => {
                        tokio::spawn(async move {
                            proxy::tcp::handle_connection(store, bind_key, stream, peer, lb).await;
                        });
                    }
                    BindProtocol::Http => {
                        tokio::spawn(async move {
                            proxy::http::handle_connection(
                                store,
                                bind_key,
                                stream,
                                peer,
                                lb,
                                http_client,
                            )
                            .await;
                        });
                    }
                    BindProtocol::Tls => {
                        tracing::warn!(
                            bind = %bind_key,
                            %peer,
                            "TLS bind protocol not implemented; dropping connection"
                        );
                        drop(stream);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(bind = %bind_key, error = %e, "accept failed");
            }
        }
    }
}
