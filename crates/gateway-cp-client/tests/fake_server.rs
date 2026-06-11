//! In-process `tonic` server scripted per `client_id`, driven by the
//! real `gateway_cp_client::run`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use gateway_cp_proto::v1 as pb;
use gateway_cp_proto::v1::config_stream_server::{ConfigStream, ConfigStreamServer};
use gateway_state::{BackendKey, BindKey, ListenerKey, RouteKey, Store};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};
use tokio::time::{sleep, timeout};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Endpoint, Server};
use tonic::{Request, Response, Status, Streaming};

// ---------------- fake server ----------------

/// Batches emitted after Hello on one connection.
type Script = Vec<pb::ConfigUpdate>;

#[derive(Default)]
struct ServerState {
    /// Per-`client_id` queue; each Stream call pops the front.
    scripts: HashMap<String, Vec<Script>>,
    last_client_id: Option<String>,
    connect_count: usize,
}

struct FakeCp {
    state: Arc<Mutex<ServerState>>,
}

#[tonic::async_trait]
impl ConfigStream for FakeCp {
    type WatchStream = ReceiverStream<Result<pb::ConfigUpdate, Status>>;

    async fn watch(
        &self,
        request: Request<Streaming<pb::ConfigRequest>>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let mut req_stream = request.into_inner();
        let state = self.state.clone();

        let first = req_stream.message().await?;
        let client_id = match first.and_then(|r| r.kind) {
            Some(pb::config_request::Kind::Hello(h)) => h.client_id,
            _ => return Err(Status::invalid_argument("expected Hello first")),
        };

        let script: Script = {
            let mut state = state.lock().await;
            state.last_client_id = Some(client_id.clone());
            state.connect_count += 1;
            state
                .scripts
                .get_mut(&client_id)
                .and_then(|queue| {
                    if queue.is_empty() {
                        None
                    } else {
                        Some(queue.remove(0))
                    }
                })
                .unwrap_or_default()
        };

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            for update in script {
                if tx.send(Ok(update)).await.is_err() {
                    return;
                }
            }
            // Dropping tx closes the stream and the client reconnects.
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

async fn spawn_server(state: Arc<Mutex<ServerState>>) -> (Endpoint, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc = ConfigStreamServer::new(FakeCp { state });

    tokio::spawn(async move {
        Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
            .unwrap();
    });

    sleep(Duration::from_millis(50)).await;

    let endpoint = Endpoint::from_shared(format!("http://{addr}")).unwrap();
    (endpoint, shutdown_tx)
}

// ---------------- fixture builders ----------------

fn bind_upsert(name: &str, port: u32) -> pb::Upsert {
    pb::Upsert {
        body: Some(pb::upsert::Body::Bind(pb::BindUpsert {
            name: name.into(),
            address: "0.0.0.0".into(),
            port,
            bind_protocol: pb::BindProtocol::Http as i32,
        })),
    }
}

fn listener_upsert(bind: &str, name: &str) -> pb::Upsert {
    pb::Upsert {
        body: Some(pb::upsert::Body::Listener(pb::ListenerUpsert {
            key: Some(pb::ListenerKey {
                bind: bind.into(),
                name: name.into(),
            }),
            hostname: String::new(),
            has_hostname: false,
        })),
    }
}

fn route_upsert(bind: &str, listener: &str, name: &str, backend: &str) -> pb::Upsert {
    pb::Upsert {
        body: Some(pb::upsert::Body::HttpRoute(pb::HttpRouteUpsert {
            key: Some(pb::RouteKey {
                bind: bind.into(),
                listener: listener.into(),
                name: name.into(),
            }),
            matches: vec![pb::HttpMatch {
                host: String::new(),
                has_host: false,
                path: Some(pb::PathMatch {
                    kind: pb::PathMatchKind::PathPrefix as i32,
                    value: "/".into(),
                }),
                method: pb::HttpMethod::Unspecified as i32,
                header_matches: vec![],
                query_param_matches: vec![],
            }],
            backend_refs: vec![pb::BackendRef {
                name: backend.into(),
                weight: 1,
            }],
            filters: vec![],
        })),
    }
}

fn backend_upsert(name: &str, ip: &str, port: u32) -> pb::Upsert {
    pb::Upsert {
        body: Some(pb::upsert::Body::Backend(pb::BackendUpsert {
            name: name.into(),
            endpoints: vec![pb::Endpoint {
                name: format!("{name}/0"),
                address: ip.into(),
                port,
            }],
            protocol: pb::BackendProtocol::Http1 as i32,
        })),
    }
}

fn batch(upserts: Vec<pb::Upsert>, removes: Vec<pb::Remove>, sync: bool) -> pb::ConfigUpdate {
    pb::ConfigUpdate {
        upserts,
        removes,
        sync_complete: sync,
    }
}

/// Drive the client until `condition(store)` holds or `deadline`
/// expires. The returned `Sender` shuts the client task down.
async fn run_until<F>(
    endpoint: Endpoint,
    client_id: &str,
    store: Store,
    condition: F,
    deadline: Duration,
) -> oneshot::Sender<()>
where
    F: Fn(&Store) -> bool + Send + 'static,
{
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let cid = client_id.to_string();
    let store_clone = store.clone();
    tokio::spawn(async move {
        let _ = gateway_cp_client::run(endpoint, cid, store_clone, async {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    let polled = timeout(deadline, async {
        loop {
            if condition(&store) {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    polled.expect("condition not met within deadline");
    shutdown_tx
}

// ---------------- tests ----------------

#[tokio::test]
async fn bootstrap_converges_store() {
    let state = Arc::new(Mutex::new(ServerState::default()));
    {
        let mut s = state.lock().await;
        s.scripts.insert(
            "demo/api-gw".to_string(),
            vec![vec![batch(
                vec![
                    bind_upsert("demo/api-gw/http", 80),
                    listener_upsert("demo/api-gw/http", "demo/api-gw/http"),
                    route_upsert(
                        "demo/api-gw/http",
                        "demo/api-gw/http",
                        "demo/app/rule0",
                        "demo/api-svc:8080",
                    ),
                    backend_upsert("demo/api-svc:8080", "10.96.0.1", 8080),
                ],
                vec![],
                true,
            )]],
        );
    }

    let (endpoint, server_stop) = spawn_server(state.clone()).await;
    let store = Store::new();

    let client_stop = run_until(
        endpoint,
        "demo/api-gw",
        store.clone(),
        |s| s.read().bind(&BindKey::new("demo/api-gw/http")).is_some(),
        Duration::from_secs(5),
    )
    .await;

    let bind = store
        .read()
        .bind(&BindKey::new("demo/api-gw/http"))
        .expect("bind active");
    assert_eq!(bind.port, 80);
    assert_eq!(bind.listeners.len(), 1);
    assert_eq!(bind.listeners[0].routes.len(), 1);

    let _ = client_stop.send(());
    let _ = server_stop.send(());
}

#[tokio::test]
async fn client_id_is_forwarded_to_server() {
    let state = Arc::new(Mutex::new(ServerState::default()));
    {
        let mut s = state.lock().await;
        s.scripts.insert(
            "ns/the-gw".to_string(),
            vec![vec![batch(vec![], vec![], true)]],
        );
    }

    let (endpoint, server_stop) = spawn_server(state.clone()).await;
    let store = Store::new();

    let client_stop = run_until(
        endpoint,
        "ns/the-gw",
        store.clone(),
        {
            let state = state.clone();
            move |_| {
                state
                    .try_lock()
                    .is_ok_and(|s| s.connect_count >= 1 && s.last_client_id.is_some())
            }
        },
        Duration::from_secs(5),
    )
    .await;

    let seen = state.lock().await.last_client_id.clone();
    assert_eq!(seen.as_deref(), Some("ns/the-gw"));

    let _ = client_stop.send(());
    let _ = server_stop.send(());
}

#[tokio::test]
async fn empty_initial_snapshot_leaves_store_empty() {
    let state = Arc::new(Mutex::new(ServerState::default()));
    {
        let mut s = state.lock().await;
        s.scripts.insert(
            "ns/missing".to_string(),
            vec![vec![batch(vec![], vec![], true)]],
        );
    }

    let (endpoint, server_stop) = spawn_server(state.clone()).await;
    let store = Store::new();

    let client_stop = run_until(
        endpoint,
        "ns/missing",
        store.clone(),
        {
            let state = state.clone();
            move |_| state.try_lock().is_ok_and(|s| s.connect_count >= 1)
        },
        Duration::from_secs(5),
    )
    .await;

    sleep(Duration::from_millis(100)).await;
    assert_eq!(store.read().binds().count(), 0);

    let _ = client_stop.send(());
    let _ = server_stop.send(());
}

#[tokio::test]
async fn stale_entities_purged_after_reconnect() {
    let state = Arc::new(Mutex::new(ServerState::default()));
    {
        let mut s = state.lock().await;
        let session_one = batch(
            vec![
                bind_upsert("demo/gw/http", 80),
                listener_upsert("demo/gw/http", "demo/gw/http"),
                route_upsert(
                    "demo/gw/http",
                    "demo/gw/http",
                    "demo/app/rule0",
                    "demo/api-svc:8080",
                ),
                backend_upsert("demo/api-svc:8080", "10.96.0.1", 8080),
            ],
            vec![],
            true,
        );
        let session_two = batch(
            vec![
                bind_upsert("demo/gw/http", 80),
                listener_upsert("demo/gw/http", "demo/gw/http"),
            ],
            vec![],
            true,
        );
        s.scripts.insert(
            "demo/gw".to_string(),
            vec![vec![session_one], vec![session_two]],
        );
    }

    let (endpoint, server_stop) = spawn_server(state.clone()).await;
    let store = Store::new();

    // Two connects = one reconnect = session_two's sync_complete absorbed.
    let client_stop = run_until(
        endpoint,
        "demo/gw",
        store.clone(),
        {
            let state = state.clone();
            let store = store.clone();
            move |_| {
                let connected_twice = state.try_lock().is_ok_and(|s| s.connect_count >= 2);
                let backend_gone = store
                    .read()
                    .backend(&BackendKey::new("demo/api-svc:8080"))
                    .is_none();
                connected_twice && backend_gone
            }
        },
        Duration::from_secs(10),
    )
    .await;

    let read = store.read();
    assert!(
        read.backend(&BackendKey::new("demo/api-svc:8080"))
            .is_none()
    );
    assert!(!read.is_route_active(&RouteKey::new(
        ListenerKey::new(BindKey::new("demo/gw/http"), "demo/gw/http"),
        "demo/app/rule0"
    )));
    assert!(read.bind(&BindKey::new("demo/gw/http")).is_some());

    let _ = client_stop.send(());
    let _ = server_stop.send(());
}
