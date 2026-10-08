//! Mock OpenAI-compatible inference provider.
//!
//! Stands in for a hosted provider on the far side of a
//! `GatewayBackend`: it terminates the TLS the gateway originates,
//! refuses any request whose credential is not the one it was
//! configured with, and answers a chat completion as
//! `text/event-stream` with a deliberate gap before the first token
//! and a long tail after it. That shape is the whole point — it is
//! what makes "the first token reached the client while the stream
//! was still open" observable rather than indistinguishable from a
//! response the gateway buffered and released at once.
//!
//! Three routes, all under whatever path prefix the `baseURL`
//! contributes:
//!
//! * `*/ping` answers `pong` without streaming, which is a routable
//!   readiness signal that still proves TLS and the credential;
//! * `*/chat/completions` streams the completion;
//! * anything else is a 404.
//!
//! A second, plaintext port serves `/__stats`: one JSON record per
//! request, carrying what the provider saw (the joined path, whether
//! the credential matched, the wire version) and what it managed to
//! send (chunks, bytes, and whether the stream ran to its end).
//! `complete: false` is how a test sees a client disconnect arrive
//! all the way back here.
//!
//! The script is per-request, on the query string: `ttft-ms` is the
//! gap before the first token, `tokens` how many follow, `gap-ms` the
//! gap between them.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use gateway_config::secret::TlsSecret;
use gateway_e2e::certs::{PROVIDER_CERT_PEM, PROVIDER_KEY_PEM};
use http::{Request, Response, StatusCode};
use http_body_util::{Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;

/// Default script. The gap before the first token is long enough that
/// no scheduling noise explains it away, and the tail long enough
/// that the stream is still open when a test asserts on the first
/// chunk it received.
const DEFAULT_TTFT: Duration = Duration::from_millis(500);
const DEFAULT_TOKENS: u64 = 16;
const DEFAULT_GAP: Duration = Duration::from_millis(100);

/// Ceilings, so a malformed query cannot park a connection forever.
const MAX_DELAY: Duration = Duration::from_secs(30);
const MAX_TOKENS: u64 = 512;

/// What the provider demands of every request it serves.
struct Credential {
    /// Lowercased header name the credential is read from.
    header: String,
    /// The exact value that header must carry, prefix included.
    expected: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let credential = Arc::new(Credential {
        header: std::env::var("MOCK_CREDENTIAL_HEADER")
            .unwrap_or_else(|_| "authorization".into())
            .to_ascii_lowercase(),
        expected: std::env::var("MOCK_CREDENTIAL").unwrap_or_else(|_| "Bearer s3cr3t".into()),
    });
    let stats = Arc::new(Stats::default());

    let stats_bind = std::env::var("MOCK_STATS_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let stats_listener = TcpListener::bind(&stats_bind).await?;
    tracing::info!(bind = %stats_bind, "stats server listening");
    tokio::spawn(serve_stats(stats_listener, Arc::clone(&stats)));

    let acceptor = TlsAcceptor::from(Arc::new(tls_config()?));
    let tls_bind = std::env::var("MOCK_TLS_LISTEN").unwrap_or_else(|_| "0.0.0.0:8443".into());
    let listener = TcpListener::bind(&tls_bind).await?;
    tracing::info!(bind = %tls_bind, "provider listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let credential = Arc::clone(&credential);
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                    return;
                }
            };
            let svc = service_fn(move |req: Request<Incoming>| {
                std::future::ready(Ok::<_, Infallible>(serve(&req, &credential, &stats)))
            });
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), svc)
                .await
            {
                tracing::debug!(%peer, error = %e, "provider connection terminated");
            }
        });
    }
}

/// Serve the baked leaf, offering both protocols so the ALPN the
/// gateway settles on is the gateway's choice to make.
fn tls_config() -> anyhow::Result<ServerConfig> {
    let secret = TlsSecret::new("", "provider", PROVIDER_CERT_PEM, PROVIDER_KEY_PEM)
        .map_err(|e| anyhow::anyhow!("baked leaf does not parse: {e}"))?;
    let key = secret
        .key
        .ok_or_else(|| anyhow::anyhow!("baked leaf has no private key"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(secret.certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

// =================== the API ===================

fn serve(
    req: &Request<Incoming>,
    credential: &Credential,
    stats: &Arc<Stats>,
) -> Response<MockBody> {
    let version = format!("{:?}", req.version());
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();

    let presented = req
        .headers()
        .get(&credential.header)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let authorized = presented == credential.expected;
    let id = stats.open(&method, &path, &version, authorized);

    if !authorized {
        // Shaped like a provider's own rejection, and saying nothing
        // about what was expected.
        return stats.full(
            id,
            StatusCode::UNAUTHORIZED,
            "application/json",
            r#"{"error":{"message":"invalid api key","type":"invalid_request_error"}}"#,
            &version,
        );
    }
    if path.ends_with("/ping") {
        return stats.full(id, StatusCode::OK, "text/plain", "pong", &version);
    }
    if !path.ends_with("/chat/completions") {
        return stats.full(
            id,
            StatusCode::NOT_FOUND,
            "application/json",
            r#"{"error":{"message":"unknown route","type":"invalid_request_error"}}"#,
            &version,
        );
    }

    let script = Script::from_query(req.uri().query());
    // Capacity one: the provider's own count then stays within a
    // frame of what the client actually received, which is what lets
    // a test compare the two.
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(1);
    tokio::spawn(stream_completion(tx, script, Arc::clone(stats), id));

    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "text/event-stream")
        .header(http::header::CACHE_CONTROL, "no-cache")
        .header("x-server-version", &version)
        .body(MockBody::Stream(StreamBody::new(ReceiverStream::new(rx))))
        .expect("well-formed")
}

/// How one completion is paced.
struct Script {
    ttft: Duration,
    tokens: u64,
    gap: Duration,
}

impl Script {
    fn from_query(query: Option<&str>) -> Self {
        let param = |key: &str| -> Option<u64> {
            query?
                .split('&')
                .find_map(|p| p.strip_prefix(key))?
                .parse()
                .ok()
        };
        Self {
            ttft: param("ttft-ms=")
                .map_or(DEFAULT_TTFT, Duration::from_millis)
                .min(MAX_DELAY),
            tokens: param("tokens=").unwrap_or(DEFAULT_TOKENS).min(MAX_TOKENS),
            gap: param("gap-ms=")
                .map_or(DEFAULT_GAP, Duration::from_millis)
                .min(MAX_DELAY),
        }
    }
}

/// Pace the completion into `tx`, counting what goes in. Returns
/// early the moment the receiver is gone: that is the client
/// disconnect, and leaving the record's `complete` false is how the
/// test sees it.
async fn stream_completion(
    tx: mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
    script: Script,
    stats: Arc<Stats>,
    id: usize,
) {
    tokio::time::sleep(script.ttft).await;
    for index in 0..script.tokens {
        if index > 0 {
            tokio::time::sleep(script.gap).await;
        }
        if !send(&tx, &stats, id, token_chunk(index)).await {
            return;
        }
    }
    if !send(&tx, &stats, id, stop_chunk()).await {
        return;
    }
    if !send(&tx, &stats, id, "data: [DONE]\n\n".to_owned()).await {
        return;
    }
    stats.complete(id);
}

async fn send(
    tx: &mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
    stats: &Stats,
    id: usize,
    chunk: String,
) -> bool {
    let len = chunk.len() as u64;
    if tx.send(Ok(Frame::data(Bytes::from(chunk)))).await.is_err() {
        tracing::debug!(id, "client went away mid-stream");
        return false;
    }
    stats.sent(id, len);
    true
}

fn token_chunk(index: u64) -> String {
    chunk(&serde_json::json!({
        "index": 0,
        "delta": { "content": format!("token-{index} ") },
        "finish_reason": serde_json::Value::Null,
    }))
}

fn stop_chunk() -> String {
    chunk(&serde_json::json!({
        "index": 0,
        "delta": {},
        "finish_reason": "stop",
    }))
}

fn chunk(choice: &serde_json::Value) -> String {
    let payload = serde_json::json!({
        "id": "chatcmpl-e2e",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "e2e-mock",
        "choices": [choice],
    });
    format!("data: {payload}\n\n")
}

/// The two body shapes under one type, since a `service_fn` returns
/// just the one.
enum MockBody {
    Full(Full<Bytes>),
    Stream(StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>),
}

impl hyper::body::Body for MockBody {
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

// =================== what the provider saw ===================

/// One request, as the provider experienced it.
#[derive(Clone, Serialize)]
struct Record {
    id: usize,
    method: String,
    /// The path as it arrived, so a test can see the `baseURL` path
    /// the gateway joined ahead of the client's.
    path: String,
    http_version: String,
    authorized: bool,
    chunks_sent: u64,
    bytes_sent: u64,
    /// True only once the whole scripted response was handed over.
    complete: bool,
}

#[derive(Default)]
struct Stats {
    records: Mutex<Vec<Record>>,
}

impl Stats {
    /// Register a request and return its id. Panics only if a
    /// previous holder of the lock panicked, which would already have
    /// failed the run.
    fn open(&self, method: &str, path: &str, http_version: &str, authorized: bool) -> usize {
        let mut records = self.records.lock().expect("stats lock");
        let id = records.len();
        records.push(Record {
            id,
            method: method.to_owned(),
            path: path.to_owned(),
            http_version: http_version.to_owned(),
            authorized,
            chunks_sent: 0,
            bytes_sent: 0,
            complete: false,
        });
        id
    }

    fn sent(&self, id: usize, bytes: u64) {
        let mut records = self.records.lock().expect("stats lock");
        if let Some(record) = records.get_mut(id) {
            record.chunks_sent += 1;
            record.bytes_sent += bytes;
        }
    }

    fn complete(&self, id: usize) {
        let mut records = self.records.lock().expect("stats lock");
        if let Some(record) = records.get_mut(id) {
            record.complete = true;
        }
    }

    fn snapshot(&self) -> Vec<Record> {
        self.records.lock().expect("stats lock").clone()
    }

    /// Answer in one shot, counting the body as sent and the request
    /// as complete — nothing about a buffered response can be cut
    /// short here.
    fn full(
        &self,
        id: usize,
        status: StatusCode,
        content_type: &str,
        body: &str,
        version: &str,
    ) -> Response<MockBody> {
        self.sent(id, body.len() as u64);
        self.complete(id);
        Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, content_type)
            .header("x-server-version", version)
            .body(MockBody::Full(Full::new(Bytes::from(body.to_owned()))))
            .expect("well-formed")
    }
}

/// Plaintext side channel. Not behind the gateway, and not TLS:
/// tests reach it through the apiserver's pod proxy, which is how
/// they see the far end of the path they just drove.
async fn serve_stats(listener: TcpListener, stats: Arc<Stats>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let stats = Arc::clone(&stats);
                async move {
                    let body = if req.uri().path() == "/__stats" {
                        serde_json::to_string(&serde_json::json!({
                            "requests": stats.snapshot(),
                        }))
                        .unwrap_or_else(|e| format!(r#"{{"error":"{e}"}}"#))
                    } else {
                        r#"{"error":"unknown route"}"#.to_owned()
                    };
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(http::header::CONTENT_TYPE, "application/json")
                            .body(Full::new(Bytes::from(body)))
                            .expect("well-formed"),
                    )
                }
            });
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}
