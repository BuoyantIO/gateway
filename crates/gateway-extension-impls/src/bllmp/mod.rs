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
use std::time::Instant;

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
            .map_err(|e| format!("`service` is not a valid gRPC target: {e}"))?;
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
            // Awaited send: picker backpressure reaches the client.
            if push.tx.send(BodyChunk { chunk: piece }).await.is_err() {
                return Err("picker closed the body stream".into());
            }
        }
        Ok(gateway_extension::Action::Continue)
    }

    async fn select(&mut self, _held: Held<'_>, cx: &mut Cx) -> Result<Selected, Error> {
        use proto::pick_response::{Destination, Outcome};

        let push = self
            .push
            .take()
            .ok_or("select without a pushed request body")?;
        // The half-close that marks the body complete.
        drop(push.tx);
        let pushed = push
            .task
            .await
            .map_err(|e| format!("push task failed: {e}"))?
            .map_err(|s| format!("PushBody failed: {s}"))?;
        tracing::debug!(target: LOG,
            stream_id = pushed.stream_id,
            bytes = pushed.total_bytes,
            "bllmp: body pushed"
        );

        let pick = self
            .client
            .clone()
            .pick(PickRequest {
                body_stream_id: pushed.stream_id,
                client_request_id: self.client_request_id.clone(),
                inference_pool: self.prepared.pool.clone(),
                qos_class: self.prepared.qos,
                tenant: self.tenant.clone(),
            })
            .await
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

        let target = match pick.destination {
            Some(Destination::Local(local)) => {
                let addr: SocketAddr = local.endpoint.parse().map_err(|_| {
                    format!("picker endpoint `{}` is not host:port", local.endpoint)
                })?;
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
                Target::Endpoint {
                    backend: backend.name().to_owned(),
                    addr,
                }
            }
            Some(Destination::Provider(_)) => {
                return Err(
                    "picker chose a provider backend; provider dispatch is not wired".into(),
                );
            }
            None => return Err("picker returned OK without a destination".into()),
        };

        tracing::debug!(target: LOG,
            response_id = pick.response_id,
            ?target,
            body_total_bytes = pick.body_total_bytes,
            "bllmp: dispatching pick"
        );
        let pull = self
            .client
            .clone()
            .pull_body(PullBodyRequest {
                response_id: pick.response_id,
            })
            .await
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
/// on a report rpc.
#[derive(Clone)]
struct Reporter {
    tx: mpsc::UnboundedSender<Report>,
}

impl Reporter {
    fn spawn(client: PickerClient<Channel>) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(report) = rx.recv().await {
                let mut client = client.clone();
                let result = match report {
                    Report::First(r) => client.report_first_token(r).await.map(|_| ()),
                    Report::Final(r) => client.report_final_token(r).await.map(|_| ()),
                    Report::Abort(r) => client.abort(r).await.map(|_| ()),
                };
                if let Err(status) = result {
                    tracing::debug!(target: LOG, %status, "bllmp report failed");
                }
            }
        });
        Self { tx }
    }

    fn send(&self, report: Report) {
        let _ = self.tx.send(report);
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
}
