use std::net::SocketAddr;
use std::sync::Arc;

use gateway_state::{BindKey, Store};
use tokio::net::TcpListener;

use crate::lb::LoadBalancer;
use crate::proxy;

/// Per-bind accept task. Opens a `TcpListener` on `addr`, loops on accept,
/// and hands off each accepted socket to a per-connection task. Exits when
/// the task is aborted (typically because the bind was removed or updated
/// to a new address).
///
/// TODO: add a shutdown signal so we can drain in-flight connections instead
/// of dropping them on shutdown.
pub(crate) async fn run_bind(
    store: Store,
    bind_key: BindKey,
    addr: SocketAddr,
    lb: Arc<LoadBalancer>,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(bind = %bind_key, %addr, error = %e, "failed to bind");
            return;
        }
    };
    let local_addr = listener.local_addr().unwrap_or(addr);
    tracing::info!(bind = %bind_key, %local_addr, "bind listening");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let store = store.clone();
                let bind_key = bind_key.clone();
                let lb = Arc::clone(&lb);
                tokio::spawn(async move {
                    proxy::handle_tcp_connection(store, bind_key, stream, peer, lb).await;
                });
            }
            Err(e) => {
                tracing::warn!(bind = %bind_key, error = %e, "accept failed");
            }
        }
    }
}
