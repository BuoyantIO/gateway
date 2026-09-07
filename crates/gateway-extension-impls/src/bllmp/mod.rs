//! The bllmp selector: streams the request body to a Buoyant LLM
//! Picker, dispatches to the endpoint it picks with the body it
//! returns, and reports how the request went.

pub mod proto {
    #![allow(clippy::pedantic, clippy::nursery, clippy::all, missing_docs)]
    tonic::include_proto!("bllmp.v1");
}

mod usage;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use gateway_config::extension::{ConfigValue, from_value};
use gateway_extension::{
    BodyMode, BodySource, Cx, Declarations, Error, Extension, ExtensionBuilder, ExtensionClass,
    Held, LocalResponse, ResponseEnd, ResponseMode, Selected, Selection, Target, async_trait,
};
use http::{HeaderMap, StatusCode};
use http_body_util::BodyExt;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use proto::picker_client::PickerClient;
use proto::{
    AbortRequest, BodyChunk, InferencePoolRef, PickRequest, PullBodyRequest, PushBodyResponse,
    ReportFinalTokenRequest, ReportFirstTokenRequest,
};

/// The class name routes reference through `Extension` objects.
pub const BLLMP_SELECTOR: &str = "bllmp_selector";

/// Log target, stable across crate moves: filter on `extension=debug`.
const LOG: &str = "extension::bllmp_selector";

/// Protocol cap: one oversized chunk fails the whole push.
const MAX_CHUNK_BYTES: usize = 1024 * 1024;
const PUSH_CHANNEL_CAPACITY: usize = 4;

// Deadlines. The streaming calls — PushBody while the body flows,
// PullBody once it streams — get none: they last as long as the body
// they carry, and a dead peer mid-stream is caught by h2 keepalive
// on the channel instead. Everything a request waits on point-wise
// is bounded below.

/// TCP connect bound for the picker channel.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Keepalive ping cadence on the picker channel, and how long a ping
/// may go unanswered before the connection is condemned.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Deadline for each call a request waits on: the `PushBody` tail
/// after the body is fully sent, Pick, and opening the `PullBody`
/// stream.
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for one report rpc; reports are best-effort and nothing
/// waits on them.
const REPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// Idle bound on handing one body chunk to the picker. Backpressure
/// from a picker reading slowly is deliberate; a picker that stopped
/// reading altogether is not, and without this it would hold the
/// request forever.
const BODY_SEND_TIMEOUT: Duration = Duration::from_secs(15);

/// Reports queued behind a slow picker before new ones are dropped.
const REPORT_QUEUE_CAPACITY: usize = 256;

/// The object's opaque config.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    /// The picker's gRPC target, `host:port`.
    service: String,
    /// Absent means the picker picks across everything it serves.
    #[serde(default)]
    pool: Option<PoolRef>,
    /// Request header carrying the tenant; `""` sent when absent.
    #[serde(default)]
    tenant_header: Option<String>,
    #[serde(default)]
    qos: Qos,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PoolRef {
    namespace: String,
    name: String,
}

#[derive(Deserialize, Clone, Copy, Default)]
enum Qos {
    #[default]
    Interactive,
    Batch,
    Deferrable,
}

impl Qos {
    fn wire(self) -> i32 {
        match self {
            Self::Interactive => proto::pick_request::QosClass::Interactive as i32,
            Self::Batch => proto::pick_request::QosClass::Batch as i32,
            Self::Deferrable => proto::pick_request::QosClass::Deferrable as i32,
        }
    }
}

/// Everything `configure` prepared, shared by every instance.
struct Prepared {
    pool: Option<InferencePoolRef>,
    tenant_header: Option<http::HeaderName>,
    qos: i32,
    /// [`RPC_TIMEOUT`] and [`BODY_SEND_TIMEOUT`] in production;
    /// carried as data so tests can shrink them to milliseconds.
    rpc_timeout: Duration,
    body_send_timeout: Duration,
}

/// `bllmp_selector` as an extension class.
pub struct BllmpSelectorClass;

impl ExtensionClass for BllmpSelectorClass {
    fn configure(&self, config: &ConfigValue) -> Result<Arc<dyn ExtensionBuilder>, Error> {
        let cfg: Config = from_value(config)?;
        if cfg.service.is_empty() {
            return Err("`service` must not be empty".into());
        }
        let tenant_header = cfg
            .tenant_header
            .as_deref()
            .map(http::HeaderName::try_from)
            .transpose()
            .map_err(|e| format!("`tenantHeader` is not a valid header name: {e}"))?;
        let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{}", cfg.service))
            .map_err(|e| format!("`service` is not a valid gRPC target: {e}"))?
            .connect_timeout(CONNECT_TIMEOUT)
            .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
            .keep_alive_timeout(KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(true);
        // One channel per configured object: every call for a
        // request must reach the same picker instance.
        let client = PickerClient::new(endpoint.connect_lazy());
        let reporter = Reporter::spawn(client.clone());
        tracing::info!(target: LOG, service = %cfg.service, "bllmp selector configured");
        Ok(Arc::new(BllmpSelectorBuilder {
            client,
            reporter,
            prepared: Arc::new(Prepared {
                pool: cfg.pool.map(|p| InferencePoolRef {
                    namespace: p.namespace,
                    name: p.name,
                    resource_version: String::new(),
                }),
                tenant_header,
                qos: cfg.qos.wire(),
                rpc_timeout: RPC_TIMEOUT,
                body_send_timeout: BODY_SEND_TIMEOUT,
            }),
        }))
    }
}

struct BllmpSelectorBuilder {
    client: PickerClient<Channel>,
    reporter: Reporter,
    prepared: Arc<Prepared>,
}

impl ExtensionBuilder for BllmpSelectorBuilder {
    fn declares(&self) -> Declarations {
        Declarations {
            request_body: BodyMode::Stream,
            response: ResponseMode::Tap,
            selects_targets: true,
        }
    }

    fn build(&self) -> Box<dyn Extension> {
        Box::new(BllmpSelector {
            client: self.client.clone(),
            reporter: self.reporter.clone(),
            prepared: Arc::clone(&self.prepared),
            push: None,
            tenant: String::new(),
            client_request_id: String::new(),
            response_id: 0,
            dispatched_at: None,
            upstream_status: 0,
            ttft_reported: false,
            itl: usage::Itl::default(),
            capture: usage::Capture::default(),
        })
    }
}

/// The in-flight `PushBody` call.
struct Push {
    tx: mpsc::Sender<BodyChunk>,
    task: JoinHandle<Result<PushBodyResponse, tonic::Status>>,
}

struct BllmpSelector {
    client: PickerClient<Channel>,
    reporter: Reporter,
    prepared: Arc<Prepared>,
    push: Option<Push>,
    tenant: String,
    client_request_id: String,
    /// 0 until a Pick succeeds — the picker never assigns 0.
    response_id: u64,
    dispatched_at: Option<Instant>,
    upstream_status: i32,
    ttft_reported: bool,
    itl: usage::Itl,
    capture: usage::Capture,
}

#[async_trait]
impl Extension for BllmpSelector {
    async fn on_request_start(
        &mut self,
        head: &mut http::request::Parts,
        _cx: &mut Cx,
    ) -> Result<gateway_extension::Action, Error> {
        self.prepared
            .tenant_header
            .clone()
            .as_ref()
            .and_then(|h| head.headers.get(h))
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .clone_into(&mut self.tenant);
        head.headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .clone_into(&mut self.client_request_id);

        let (tx, rx) = mpsc::channel(PUSH_CHANNEL_CAPACITY);
        let mut request = tonic::Request::new(ReceiverStream::new(rx));
        if let Ok(id) = tonic::metadata::MetadataValue::try_from(&self.client_request_id) {
            request.metadata_mut().insert("bllmp-client-request-id", id);
        }
        if let Some(len) = head
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| tonic::metadata::MetadataValue::try_from(v).ok())
        {
            request.metadata_mut().insert("bllmp-declared-length", len);
        }
        tracing::debug!(target: LOG,
            request_id = %self.client_request_id,
            tenant = %self.tenant,
            "bllmp: opening PushBody"
        );
        let mut client = self.client.clone();
        let task = tokio::spawn(async move {
            client
                .push_body(request)
                .await
                .map(tonic::Response::into_inner)
        });
        self.push = Some(Push { tx, task });
        Ok(gateway_extension::Action::Continue)
    }

    async fn on_request_body(
        &mut self,
        chunk: Bytes,
        _end_of_stream: bool,
        _cx: &mut Cx,
    ) -> Result<gateway_extension::Action, Error> {
        let Some(push) = self.push.as_ref() else {
            return Err("request body before request start".into());
        };
        let mut rest = chunk;
        while !rest.is_empty() {
            let piece = rest.split_to(rest.len().min(MAX_CHUNK_BYTES));
            // Awaited send: picker backpressure reaches the client,
            // bounded so a picker that stopped reading does not hold
            // the request forever.
            let send = push.tx.send(BodyChunk { chunk: piece });
            match tokio::time::timeout(self.prepared.body_send_timeout, send).await {
                Err(_) => return Err("picker stalled pulling the request body".into()),
                Ok(Err(_)) => return Err("picker closed the body stream".into()),
                Ok(Ok(())) => {}
            }
        }
        Ok(gateway_extension::Action::Continue)
    }

    async fn select(&mut self, _held: Held<'_>, cx: &mut Cx) -> Result<Selected, Error> {
        use proto::pick_response::Outcome;

        let push = self
            .push
            .take()
            .ok_or("select without a pushed request body")?;
        // The half-close that marks the body complete.
        drop(push.tx);
        let mut task = push.task;
        let pushed = match tokio::time::timeout(self.prepared.rpc_timeout, &mut task).await {
            Err(_) => {
                task.abort();
                return Err("PushBody timed out".into());
            }
            Ok(joined) => joined
                .map_err(|e| format!("push task failed: {e}"))?
                .map_err(|s| format!("PushBody failed: {s}"))?,
        };
        tracing::debug!(target: LOG,
            stream_id = pushed.stream_id,
            bytes = pushed.total_bytes,
            "bllmp: body pushed"
        );

        let mut client = self.client.clone();
        let pick = client.pick(PickRequest {
            body_stream_id: pushed.stream_id,
            client_request_id: self.client_request_id.clone(),
            inference_pool: self.prepared.pool.clone(),
            qos_class: self.prepared.qos,
            tenant: self.tenant.clone(),
        });
        let pick = tokio::time::timeout(self.prepared.rpc_timeout, pick)
            .await
            .map_err(|_| "Pick timed out")?
            .map_err(|s| format!("Pick failed: {s}"))?
            .into_inner();

        match Outcome::try_from(pick.outcome) {
            Ok(Outcome::Ok | Outcome::Degraded) => {}
            Ok(outcome @ (Outcome::NoWorkers | Outcome::BadRequest | Outcome::PolicyRejected)) => {
                tracing::debug!(target: LOG, ?outcome, reason = %pick.reason, "bllmp: pick answered locally");
                let status = match outcome {
                    Outcome::NoWorkers => StatusCode::SERVICE_UNAVAILABLE,
                    Outcome::BadRequest => StatusCode::BAD_REQUEST,
                    _ => StatusCode::FORBIDDEN,
                };
                return Ok(respond(status, &pick.reason));
            }
            Ok(Outcome::Unspecified) | Err(_) => {
                return Err(format!("picker returned outcome {}", pick.outcome).into());
            }
        }

        // The pick counted a dispatch; the terminal hook settles it.
        self.response_id = pick.response_id;
        self.dispatched_at = Some(Instant::now());

        let target = pick_target(pick.destination, cx)?;

        tracing::debug!(target: LOG,
            response_id = pick.response_id,
            ?target,
            body_total_bytes = pick.body_total_bytes,
            "bllmp: dispatching pick"
        );
        // Bounded while opening the stream; the stream itself lasts
        // as long as the body it carries.
        let mut client = self.client.clone();
        let pull = client.pull_body(PullBodyRequest {
            response_id: pick.response_id,
        });
        let pull = tokio::time::timeout(self.prepared.rpc_timeout, pull)
            .await
            .map_err(|_| "PullBody timed out")?
            .map_err(|s| format!("PullBody failed: {s}"))?
            .into_inner();
        let frames = pull.map(|item| match item {
            Ok(c) => Ok(http_body::Frame::data(c.chunk)),
            Err(s) => Err(Error::from(format!("PullBody stream failed: {s}"))),
        });
        let body = http_body_util::StreamBody::new(frames).boxed();

        Ok(Selected::Target(Selection {
            target,
            body: BodySource::Stream(body, Some(pick.body_total_bytes)),
        }))
    }

    fn on_response_start(&mut self, head: &mut http::response::Parts, _cx: &mut Cx) {
        self.upstream_status = i32::from(head.status.as_u16());
    }

    fn on_response_body(&mut self, chunk: Bytes, _end_of_stream: bool, _cx: &mut Cx) {
        if self.response_id == 0 || chunk.is_empty() {
            return;
        }
        let now = Instant::now();
        if !self.ttft_reported {
            self.ttft_reported = true;
            let ttft_ms = self
                .dispatched_at
                .map(|t| u32::try_from(now.duration_since(t).as_millis()).unwrap_or(u32::MAX))
                .unwrap_or_default();
            tracing::debug!(target: LOG,
                response_id = self.response_id,
                ttft_ms,
                status = self.upstream_status,
                "bllmp: first response chunk"
            );
            self.reporter.send(Report::First(ReportFirstTokenRequest {
                response_id: self.response_id,
                observed_ttft_ms: ttft_ms,
                upstream_status: self.upstream_status,
            }));
        }
        self.itl.record(now);
        self.capture.feed(&chunk);
    }

    fn on_response_end(&mut self, end: &ResponseEnd, _cx: &mut Cx) {
        if self.response_id == 0 {
            return;
        }
        let response_id = std::mem::take(&mut self.response_id);
        if end.upstream {
            let prompt = self.capture.prompt_tokens();
            let completion = self.capture.completion_tokens();
            let counts = self.itl.counts();
            // Nothing measured, nothing to report.
            if prompt.is_none() && completion.is_none() && counts.is_empty() {
                tracing::debug!(target: LOG,
                    response_id,
                    "bllmp: no usage and no inter-token data; skipping ReportFinalToken"
                );
                return;
            }
            let cached = self.capture.cached_tokens();
            let model = self.capture.model();
            tracing::debug!(target: LOG,
                response_id,
                %model,
                prompt_tokens = prompt.unwrap_or(0),
                completion_tokens = completion.unwrap_or(0),
                cached_tokens = cached.unwrap_or(0),
                itl_samples = counts.iter().sum::<u32>(),
                "bllmp: reporting final token"
            );
            self.reporter.send(Report::Final(ReportFinalTokenRequest {
                response_id,
                model,
                prompt_tokens: clamp_u32(prompt.unwrap_or(0)),
                completion_tokens: clamp_u32(completion.unwrap_or(0)),
                cached_tokens: cached.map(clamp_u32),
                itl_bucket_layout: if counts.is_empty() {
                    0
                } else {
                    usage::ITL_LAYOUT
                },
                itl_bucket_counts: counts,
            }));
        } else {
            tracing::debug!(target: LOG,
                response_id,
                complete = end.complete,
                "bllmp: aborting undispatched pick"
            );
            self.reporter.send(Report::Abort(AbortRequest {
                response_id,
                reason: proto::abort_request::Reason::NotDispatched as i32,
                detail: String::new(),
                client_request_id: self.client_request_id.clone(),
            }));
        }
    }
}

impl Drop for BllmpSelector {
    fn drop(&mut self) {
        // Abandoned before selection: reset so the picker discards.
        if let Some(push) = self.push.take() {
            push.task.abort();
        }
    }
}

/// The dispatch target a pick's destination names, validated against
/// the rule's backendRefs.
fn pick_target(
    destination: Option<proto::pick_response::Destination>,
    cx: &Cx,
) -> Result<Target, Error> {
    use proto::pick_response::Destination;

    match destination {
        Some(Destination::Local(local)) => {
            let addr: SocketAddr = local
                .endpoint
                .parse()
                .map_err(|_| format!("picker endpoint `{}` is not host:port", local.endpoint))?;
            let backend = cx
                .targets()
                .backends()
                .iter()
                .find(|tb| {
                    tb.endpoints()
                        .iter()
                        .any(|e| e.address == addr.ip() && e.port == addr.port())
                })
                .ok_or_else(|| {
                    format!("picker chose {addr}, which no backendRef of the rule lists")
                })?;
            Ok(Target::Endpoint {
                backend: backend.name().to_owned(),
                addr,
            })
        }
        Some(Destination::Provider(_)) => {
            Err("picker chose a provider backend; provider dispatch is not wired".into())
        }
        None => Err("picker returned OK without a destination".into()),
    }
}

fn clamp_u32(n: u64) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn respond(status: StatusCode, reason: &str) -> Selected {
    Selected::Respond(LocalResponse {
        status,
        headers: HeaderMap::new(),
        body: Bytes::from(reason.to_owned()),
    })
}

/// A report queued from the sync response hooks.
enum Report {
    First(ReportFirstTokenRequest),
    Final(ReportFinalTokenRequest),
    Abort(AbortRequest),
}

/// Fire-and-forget report delivery; the client's stream never waits
/// on a report rpc. The queue is bounded and each rpc has a deadline,
/// so a picker that stopped answering costs dropped reports, not
/// memory.
#[derive(Clone)]
struct Reporter {
    tx: mpsc::Sender<Report>,
}

impl Reporter {
    fn spawn(client: PickerClient<Channel>) -> Self {
        let (tx, mut rx) = mpsc::channel(REPORT_QUEUE_CAPACITY);
        tokio::spawn(async move {
            while let Some(report) = rx.recv().await {
                let mut client = client.clone();
                let call = async {
                    match report {
                        Report::First(r) => client.report_first_token(r).await.map(|_| ()),
                        Report::Final(r) => client.report_final_token(r).await.map(|_| ()),
                        Report::Abort(r) => client.abort(r).await.map(|_| ()),
                    }
                };
                match tokio::time::timeout(REPORT_TIMEOUT, call).await {
                    Err(_) => tracing::debug!(target: LOG, "bllmp report timed out"),
                    Ok(Err(status)) => tracing::debug!(target: LOG, %status, "bllmp report failed"),
                    Ok(Ok(())) => {}
                }
            }
        });
        Self { tx }
    }

    fn send(&self, report: Report) {
        if self.tx.try_send(report).is_err() {
            tracing::debug!(target: LOG, "bllmp report dropped: queue full");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<Config, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    #[test]
    fn config_defaults() {
        let cfg = parse("service: bllmp.default.svc:50051").expect("minimal config");
        assert!(cfg.pool.is_none());
        assert!(cfg.tenant_header.is_none());
        assert!(matches!(cfg.qos, Qos::Interactive));
    }

    #[test]
    fn config_full() {
        let cfg = parse(
            "
service: bllmp.default.svc:50051
pool: { namespace: inference, name: p }
tenantHeader: x-tenant
qos: Batch
",
        )
        .expect("full config");
        let pool = cfg.pool.expect("pool set");
        assert_eq!(pool.namespace, "inference");
        assert_eq!(pool.name, "p");
        assert_eq!(cfg.tenant_header.as_deref(), Some("x-tenant"));
        assert!(matches!(cfg.qos, Qos::Batch));
    }

    #[test]
    fn config_rejects_unknown_fields() {
        assert!(parse("service: s\nserivce: typo").is_err());
        assert!(parse("service: s\npool: { namespace: n, name: p, extra: 1 }").is_err());
    }

    #[test]
    fn config_requires_service() {
        assert!(parse("pool: { namespace: n, name: p }").is_err());
    }

    /// A picker that accepts TCP and never speaks: the connection
    /// never finishes its handshake, so every rpc against it hangs
    /// until a deadline says otherwise.
    async fn silent_picker() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                held.push(sock);
            }
        });
        addr.to_string()
    }

    /// The deadlines the hang tests wait out, shrunk from the
    /// production constants so the suite runs in milliseconds.
    const TEST_TIMEOUT: Duration = Duration::from_millis(200);

    /// A selector wired by hand: the client points at `service`, and
    /// every deadline is [`TEST_TIMEOUT`]. `push` pre-seeds the
    /// in-flight `PushBody`, for tests that stage it directly.
    fn selector_for(service: &str, push: Option<Push>) -> BllmpSelector {
        let endpoint =
            tonic::transport::Endpoint::from_shared(format!("http://{service}")).unwrap();
        let client = PickerClient::new(endpoint.connect_lazy());
        BllmpSelector {
            client: client.clone(),
            reporter: Reporter::spawn(client),
            prepared: Arc::new(Prepared {
                pool: None,
                tenant_header: None,
                qos: 0,
                rpc_timeout: TEST_TIMEOUT,
                body_send_timeout: TEST_TIMEOUT,
            }),
            push,
            tenant: String::new(),
            client_request_id: String::new(),
            response_id: 0,
            dispatched_at: None,
            upstream_status: 0,
            ttft_reported: false,
            itl: usage::Itl::default(),
            capture: usage::Capture::default(),
        }
    }

    fn request_parts() -> http::request::Parts {
        http::Request::builder()
            .uri("/v1/chat")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[tokio::test]
    async fn a_silent_picker_fails_select_within_its_deadline() {
        let service = silent_picker().await;
        let mut ext = selector_for(&service, None);
        let mut cx = Cx::new();
        let mut parts = request_parts();
        ext.on_request_start(&mut parts, &mut cx).await.unwrap();

        let selected =
            tokio::time::timeout(Duration::from_secs(5), ext.select(Held::Nothing, &mut cx))
                .await
                .expect("select must fail by deadline, not hang");
        let Err(err) = selected else {
            panic!("a silent picker cannot answer");
        };
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    /// The send timeout in isolation: a push channel whose receiver
    /// is alive but never read fills up, and the next send must time
    /// out rather than hold the request. (Through the real gRPC
    /// stack the encoder buffers an unspecified amount ahead of the
    /// channel, so the stall is staged here directly.)
    #[tokio::test]
    async fn a_picker_that_stops_reading_fails_the_body_send() {
        let (tx, _rx) = mpsc::channel(PUSH_CHANNEL_CAPACITY);
        let task = tokio::spawn(async {
            std::future::pending::<Result<PushBodyResponse, tonic::Status>>().await
        });
        let mut ext = selector_for("127.0.0.1:1", Some(Push { tx, task }));

        let mut cx = Cx::new();
        let chunk = Bytes::from_static(b"{}");
        let mut outcome = Ok(());
        for _ in 0..=PUSH_CHANNEL_CAPACITY {
            outcome = ext
                .on_request_body(chunk.clone(), false, &mut cx)
                .await
                .map(|_| ());
            if outcome.is_err() {
                break;
            }
        }
        let err = outcome.expect_err("a full push channel must not block forever");
        assert!(err.to_string().contains("stalled"), "{err}");
    }
}
