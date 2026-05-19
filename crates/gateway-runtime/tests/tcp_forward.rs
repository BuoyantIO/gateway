use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use gateway_config::backend::{Backend, BackendRef, Endpoint, StaticBackend};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::listener::{Listener, TcpListener as SchemaTcpListener};
use gateway_config::route::TcpRoute;
use gateway_runtime::Gateway;
use gateway_state::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Spawn a minimal echo server. Returns the bound port.
async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// Pick a free TCP port by binding to :0 and reading the assigned port,
/// then dropping the listener. There's a tiny race window before the
/// gateway re-binds the same port, but it's robust enough for tests.
async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

fn tcp_config(bind_port: u16, upstream_port: u16) -> gateway_config::GatewayConfig {
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
            endpoints: vec![Endpoint {
                name: "e0".into(),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: upstream_port,
            }],
        })],
        secrets: vec![],
    }
}

#[tokio::test]
async fn tcp_round_trip() {
    let upstream_port = spawn_echo().await;
    let bind_port = free_port().await;

    let cfg = tcp_config(bind_port, upstream_port);
    let store = Store::new();
    let _ = store.apply(&cfg);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let gw = Gateway::new(store);
    let gw_handle = tokio::spawn(async move {
        gw.run(async {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });

    // Wait briefly for the accept task to bind. A few retries cover the
    // race between free_port releasing :N and the gateway binding it.
    let mut stream = None;
    for _ in 0..20 {
        match TcpStream::connect(("127.0.0.1", bind_port)).await {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
    let mut stream = stream.expect("gateway did not start listening in time");

    stream.write_all(b"hello\n").await.unwrap();
    let mut buf = [0u8; 6];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello\n");

    drop(stream);
    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}

#[tokio::test]
async fn unreachable_backend_does_not_panic() {
    // Point at a port that nothing is listening on.
    let bind_port = free_port().await;
    let cfg = tcp_config(bind_port, 1); // port 1 is reserved, dial should fail

    let store = Store::new();
    let _ = store.apply(&cfg);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let gw = Gateway::new(store);
    let gw_handle = tokio::spawn(async move {
        gw.run(async {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });

    let mut stream = None;
    for _ in 0..20 {
        match TcpStream::connect(("127.0.0.1", bind_port)).await {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
    let mut stream = stream.expect("gateway did not start listening in time");

    // Writing may succeed (downstream socket is open); reading should EOF
    // because the gateway closes the downstream after dial fails.
    let _ = stream.write_all(b"hello\n").await;
    let mut buf = [0u8; 4];
    let _ = stream.read(&mut buf).await; // returns 0 (EOF) or error

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), gw_handle)
        .await
        .expect("gateway did not shut down")
        .unwrap();
}
