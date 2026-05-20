use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use gateway_config::backend::{Backend, BackendRef, Endpoint, StaticBackend};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::listener::{Listener, TcpListener as SchemaTcpListener};
use gateway_config::route::TcpRoute;
use gateway_runtime::Gateway;
use gateway_runtime::lb::{EndpointStateConfig, LoadBalancer, P2cConfig, P2cEwma};
use gateway_state::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Echo server that counts received connections. Returns the bound port,
/// the shared counter, and a handle that can be aborted to "kill" it.
async fn spawn_counting_echo() -> (u16, Arc<AtomicU64>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let counter = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&counter);
    let h = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            c.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (port, counter, h)
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

fn cfg_two_endpoints(bind_port: u16, p1: u16, p2: u16) -> gateway_config::GatewayConfig {
    use gateway_config::config::GatewayConfig;
    GatewayConfig {
        name: "test".into(),
        binds: vec![Bind {
            name: "b".into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: bind_port,
            bind_protocol: BindProtocol::Tcp,
            listeners: vec![Listener::Tcp(SchemaTcpListener {
                name: "l".into(),
                routes: vec![TcpRoute {
                    name: "r".into(),
                    backend_refs: vec![BackendRef {
                        name: "be".into(),
                        weight: 1,
                    }],
                    filters: vec![],
                }],
            })],
        }],
        backends: vec![Backend::Static(StaticBackend {
            name: "be".into(),
            endpoints: vec![
                Endpoint {
                    name: "e0".into(),
                    address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: p1,
                },
                Endpoint {
                    name: "e1".into(),
                    address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: p2,
                },
            ],
        })],
        secrets: vec![],
    }
}

async fn open_connect(bind_port: u16) -> std::io::Result<TcpStream> {
    let mut retries = 0;
    loop {
        match TcpStream::connect(("127.0.0.1", bind_port)).await {
            Ok(s) => return Ok(s),
            Err(e) if retries < 20 => {
                retries += 1;
                tokio::time::sleep(Duration::from_millis(25)).await;
                let _ = e;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn round_trip(bind_port: u16) -> std::io::Result<()> {
    let mut s = open_connect(bind_port).await?;
    s.write_all(b"hi\n").await?;
    let mut buf = [0u8; 3];
    s.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"hi\n");
    Ok(())
}

#[tokio::test]
async fn p2c_distributes_then_evicts_failing_endpoint() {
    let (p1, c1, h1) = spawn_counting_echo().await;
    let (p2, c2, _h2) = spawn_counting_echo().await;
    let bind_port = free_port().await;

    let cfg = cfg_two_endpoints(bind_port, p1, p2);
    let store = Store::new();
    let _ = store.apply(&cfg);

    let picker = Arc::new(P2cEwma::new(P2cConfig {
        load_penalty: 0.1,
        latency_penalty_ms: 0.001,
    }));
    let state_cfg = EndpointStateConfig {
        ewma_alpha: 0.5,
        failure_threshold: 1,
        eviction_duration: Duration::from_secs(5),
    };
    let lb = LoadBalancer::with_picker(picker, state_cfg);
    let gateway = Gateway::with_lb(store, lb);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let gw_handle = tokio::spawn(async move {
        gateway
            .run(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    // Phase 1: both endpoints up. Open enough connections that P2C
    // should sprinkle traffic across both.
    for _ in 0..20 {
        round_trip(bind_port).await.unwrap();
    }
    let c1_pre = c1.load(Ordering::Relaxed);
    let c2_pre = c2.load(Ordering::Relaxed);
    assert!(c1_pre > 0, "endpoint 1 saw no traffic in phase 1: {c1_pre}");
    assert!(c2_pre > 0, "endpoint 2 saw no traffic in phase 1: {c2_pre}");
    assert_eq!(c1_pre + c2_pre, 20);

    // Phase 2: kill endpoint 1. Open more connections. After
    // failure_threshold=1, endpoint 1 should be evicted and all
    // subsequent connections should land on endpoint 2.
    h1.abort();

    // Give the abort a moment to actually close the listener.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut failures = 0;
    for _ in 0..30 {
        if round_trip(bind_port).await.is_err() {
            failures += 1;
        }
    }
    let c2_after = c2.load(Ordering::Relaxed) - c2_pre;
    let c1_after = c1.load(Ordering::Relaxed) - c1_pre;

    // Endpoint 1 is dead, so its counter can't increase even if a connection
    // races onto it (the connection would fail before the echo server's
    // accept-counter increments). Allow up to a small number of failures
    // before eviction kicks in.
    assert!(failures <= 3, "too many failed connections: {failures}");
    assert_eq!(
        c1_after, 0,
        "endpoint 1 accepted connections after being killed"
    );
    assert!(
        c2_after >= 25,
        "endpoint 2 didn't pick up the load: c2_after={c2_after}, failures={failures}"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}
