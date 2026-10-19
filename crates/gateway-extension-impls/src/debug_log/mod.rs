//! The `debug_log` extension: logs each request's and response's head
//! and a capped prefix of each body, to show what a route actually
//! carries.
//!
//! By default credentials are redacted before anything is formatted:
//! the values of the headers in [`CREDENTIAL_HEADERS`] (an
//! `authorization` value keeps its scheme, so `Bearer` and `Basic`
//! stay tellable apart) and of the query parameters in
//! [`CREDENTIAL_PARAMS`]. `redactCredentials: false` turns both lists
//! off and logs those values in the clear, for following a flow end
//! to end on a cluster whose logs are the operator's own; it warns
//! once at configure time. The names in `redactHeaders` are redacted
//! either way. Bodies are not inspected for secrets; a body is logged
//! as its first `maxBodyBytes` bytes, lossily decoded and escaped
//! onto one line.
//!
//! A response event stream in a format `destream` understands
//! (Anthropic Messages or chat completions) is logged instead as the
//! document the same call would have answered without streaming,
//! reassembled from its events and written as one line of JSON, with
//! its text capped at `maxBodyBytes`. `destream: false` logs the raw
//! prefix of every stream instead. A stream in any other format logs
//! its raw prefix either way.
//!
//! What it sees is what the filter chain hands it at its position:
//! the head after the filters ahead of it, and the request body as
//! the client sent it. A selector on the same rule may rewrite the
//! request line in `select` and forward a body of its own (the
//! kinference selector forwards the body its picker returns), and
//! neither passes through here. The data plane's `forwarding
//! upstream` debug line has the URI actually dispatched. A provider
//! credential is attached after every extension has run, so it is
//! never seen here at all.
//!
//! One request logs up to four lines, tied together by `seq`, a
//! process-local sequence number: `request` at request start,
//! `request body` when the body ends, `response` at response headers,
//! and `response end` when the response does. A request answered
//! before any upstream response logs no `response` line, and one
//! whose body never ended logs its body with the end line, marked
//! incomplete. Lines go to the `extension::debug_log` target at info,
//! so attaching the extension is the opt-in;
//! `extension::debug_log=off` silences it without detaching it.
//!
//! Each request holds at most `maxBodyBytes` of each body; a
//! reassembled stream also holds its document's structure, up to a
//! fixed allowance, and the stream's current event.
//! `maxBodyBytes: 0` logs heads only and declares no body access, so
//! attaching it does not change how a rule's bodies are handled.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use gateway_config::extension::{ConfigValue, from_value};
use gateway_extension::{
    Action, BodyMode, Cx, Declarations, Error, Extension, ExtensionBuilder, ExtensionClass,
    ResponseEnd, ResponseMode, async_trait,
};
use http::{HeaderMap, HeaderName, Uri};
use serde::Deserialize;

use destream::{Destream, Ordered};

mod destream;

/// The class name `Extension` objects name.
pub const DEBUG_LOG: &str = "debug_log";

/// Log target: filter on `extension::debug_log`.
const LOG: &str = "extension::debug_log";

const DEFAULT_MAX_BODY_BYTES: usize = 4 * 1024;
/// Ceiling on `maxBodyBytes`; each request holds this much of each
/// body at most.
const MAX_BODY_BYTES_CEILING: usize = 1024 * 1024;

const REDACTED: &str = "[redacted]";

/// Headers whose values are redacted by default: the ones clients
/// and providers carry credentials and sessions in.
const CREDENTIAL_HEADERS: [&str; 8] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "x-amz-security-token",
];

/// Query parameters whose values are redacted by default, compared
/// without regard to case.
const CREDENTIAL_PARAMS: [&str; 6] = [
    "key",
    "api_key",
    "api-key",
    "apikey",
    "access_token",
    "token",
];

/// The headers whose redaction keeps the value's leading scheme.
const SCHEMED_HEADERS: [&str; 2] = ["authorization", "proxy-authorization"];

/// Ties one request's lines together.
static SEQ: AtomicU64 = AtomicU64::new(1);

/// The object's opaque config.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    /// Bytes of each body to log; 0 logs heads only.
    #[serde(default = "default_max_body_bytes")]
    max_body_bytes: usize,
    /// Whether [`CREDENTIAL_HEADERS`] and [`CREDENTIAL_PARAMS`] are
    /// redacted.
    #[serde(default = "default_redact_credentials")]
    redact_credentials: bool,
    /// Header names to redact on top of [`CREDENTIAL_HEADERS`], and
    /// regardless of `redact_credentials`.
    #[serde(default)]
    redact_headers: Vec<String>,
    /// Whether a response event stream is logged reassembled.
    #[serde(default = "default_destream")]
    destream: bool,
}

fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

fn default_redact_credentials() -> bool {
    true
}

fn default_destream() -> bool {
    true
}

/// `debug_log` as an extension class.
pub struct DebugLogClass;

impl ExtensionClass for DebugLogClass {
    fn configure(&self, config: &ConfigValue) -> Result<Arc<dyn ExtensionBuilder>, Error> {
        // An object with no config at all takes every default.
        let cfg: Config = if config.is_null() {
            Config {
                max_body_bytes: DEFAULT_MAX_BODY_BYTES,
                redact_credentials: true,
                redact_headers: Vec::new(),
                destream: true,
            }
        } else {
            from_value(config)?
        };
        Ok(Arc::new(DebugLogBuilder::try_new(&cfg)?))
    }
}

struct DebugLogBuilder {
    prepared: Arc<Prepared>,
}

/// Everything `configure` prepared, shared by every instance.
struct Prepared {
    max_body_bytes: usize,
    /// [`CREDENTIAL_HEADERS`] unless credential redaction is off, and
    /// the configured extras, parsed.
    redact: Vec<HeaderName>,
    /// Whether [`CREDENTIAL_PARAMS`] are redacted from the URI.
    redact_params: bool,
    destream: bool,
}

impl DebugLogBuilder {
    fn try_new(cfg: &Config) -> Result<Self, Error> {
        if cfg.max_body_bytes > MAX_BODY_BYTES_CEILING {
            return Err(format!(
                "`maxBodyBytes` is {}, over the ceiling of {MAX_BODY_BYTES_CEILING}",
                cfg.max_body_bytes
            )
            .into());
        }
        let mut redact: Vec<HeaderName> = if cfg.redact_credentials {
            CREDENTIAL_HEADERS
                .iter()
                .map(|name| HeaderName::from_static(name))
                .collect()
        } else {
            Vec::new()
        };
        for name in &cfg.redact_headers {
            let parsed = HeaderName::try_from(name.as_str())
                .map_err(|_| format!("`redactHeaders` entry `{name}` is not a header name"))?;
            if !redact.contains(&parsed) {
                redact.push(parsed);
            }
        }
        if !cfg.redact_credentials {
            tracing::warn!(target: LOG,
                "debug_log: credential redaction is off; credential headers and query \
                 parameters will be logged in the clear"
            );
        }
        tracing::info!(target: LOG,
            max_body_bytes = cfg.max_body_bytes,
            redact_credentials = cfg.redact_credentials,
            redacted_headers = redact.len(),
            destream = cfg.destream,
            "debug_log configured"
        );
        Ok(Self {
            prepared: Arc::new(Prepared {
                max_body_bytes: cfg.max_body_bytes,
                redact,
                redact_params: cfg.redact_credentials,
                destream: cfg.destream,
            }),
        })
    }
}

impl ExtensionBuilder for DebugLogBuilder {
    fn declares(&self) -> Declarations {
        let bodies = self.prepared.max_body_bytes > 0;
        Declarations {
            request_body: if bodies {
                BodyMode::Stream
            } else {
                BodyMode::None
            },
            response: if bodies {
                ResponseMode::Tap
            } else {
                ResponseMode::End
            },
            selects_targets: false,
        }
    }

    fn build(&self) -> Box<dyn Extension> {
        Box::new(DebugLog {
            prepared: Arc::clone(&self.prepared),
            seq: SEQ.fetch_add(1, Ordering::Relaxed),
            request: Prefix::default(),
            response: Prefix::default(),
            destream: None,
            request_logged: false,
        })
    }
}

struct DebugLog {
    prepared: Arc<Prepared>,
    seq: u64,
    request: Prefix,
    response: Prefix,
    /// Set at response start for an event stream, when reassembly is
    /// on and bodies are logged.
    destream: Option<Destream>,
    /// The `request body` line went out.
    request_logged: bool,
}

#[async_trait]
impl Extension for DebugLog {
    async fn on_request_start(
        &mut self,
        head: &mut http::request::Parts,
        _cx: &mut Cx,
    ) -> Result<Action, Error> {
        tracing::info!(target: LOG,
            seq = self.seq,
            request_id = head
                .headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            method = %head.method,
            uri = %shown_uri(&head.uri, self.prepared.redact_params),
            version = ?head.version,
            headers = %Headers {
                map: &head.headers,
                redact: &self.prepared.redact,
            },
            "request"
        );
        Ok(Action::Continue)
    }

    async fn on_request_body(
        &mut self,
        chunk: Bytes,
        end_of_stream: bool,
        _cx: &mut Cx,
    ) -> Result<Action, Error> {
        self.request.feed(&chunk, self.prepared.max_body_bytes);
        if end_of_stream {
            self.log_request_body(true);
        }
        Ok(Action::Continue)
    }

    fn on_response_start(&mut self, head: &mut http::response::Parts, _cx: &mut Cx) {
        if self.prepared.destream
            && self.prepared.max_body_bytes > 0
            && is_event_stream(&head.headers)
        {
            self.destream = Some(Destream::new(self.prepared.max_body_bytes));
        }
        tracing::info!(target: LOG,
            seq = self.seq,
            status = head.status.as_u16(),
            version = ?head.version,
            headers = %Headers {
                map: &head.headers,
                redact: &self.prepared.redact,
            },
            "response"
        );
    }

    fn on_response_body(&mut self, chunk: Bytes, _end_of_stream: bool, _cx: &mut Cx) {
        if let Some(destream) = &mut self.destream {
            destream.feed(&chunk);
            // The raw prefix is only the fallback for a stream that
            // turns out not to be one it reassembles.
            if destream.understood() {
                return;
            }
        }
        self.response.feed(&chunk, self.prepared.max_body_bytes);
    }

    fn on_response_end(&mut self, end: &ResponseEnd, _cx: &mut Cx) {
        if self.prepared.max_body_bytes == 0 {
            tracing::info!(target: LOG,
                seq = self.seq,
                status = end.status.as_u16(),
                upstream = end.upstream,
                complete = end.complete,
                body_failed = end.body_failed,
                body_bytes = end.body_bytes,
                "response end"
            );
            return;
        }
        if !self.request_logged {
            self.log_request_body(false);
        }
        if let Some(r) = self.destream.take().and_then(Destream::finish) {
            tracing::info!(target: LOG,
                seq = self.seq,
                status = end.status.as_u16(),
                upstream = end.upstream,
                complete = end.complete,
                body_failed = end.body_failed,
                body_bytes = end.body_bytes,
                destreamed = r.format,
                events = r.events,
                truncated = r.truncated,
                body = %Ordered(&r.document),
                "response end"
            );
            return;
        }
        tracing::info!(target: LOG,
            seq = self.seq,
            status = end.status.as_u16(),
            upstream = end.upstream,
            complete = end.complete,
            body_failed = end.body_failed,
            body_bytes = end.body_bytes,
            truncated = self.response.truncated(),
            body = ?self.response.text(),
            "response end"
        );
    }
}

impl DebugLog {
    /// `complete` is false when the body never reached its end: the
    /// request was answered, or failed, partway through it.
    fn log_request_body(&mut self, complete: bool) {
        self.request_logged = true;
        tracing::info!(target: LOG,
            seq = self.seq,
            complete,
            body_bytes = self.request.total,
            truncated = self.request.truncated(),
            body = ?self.request.text(),
            "request body"
        );
    }
}

/// The first bytes of one body, and how long the whole was.
#[derive(Default)]
struct Prefix {
    kept: Vec<u8>,
    total: u64,
}

impl Prefix {
    fn feed(&mut self, chunk: &[u8], cap: usize) {
        let room = cap.saturating_sub(self.kept.len());
        self.kept.extend_from_slice(&chunk[..chunk.len().min(room)]);
        self.total += chunk.len() as u64;
    }

    fn truncated(&self) -> bool {
        self.total > self.kept.len() as u64
    }

    /// Lossy: a body is not promised to be text, and a cut can land
    /// mid-character.
    fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.kept)
    }
}

/// Whether a response's `content-type` is an event stream.
fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|ct| ct.split(';').next())
        .is_some_and(|ct| ct.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// A header map formatted as `name: value` pairs, with the values of
/// the redacted names replaced.
struct Headers<'a> {
    map: &'a HeaderMap,
    redact: &'a [HeaderName],
}

impl fmt::Display for Headers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("{")?;
        for (i, (name, value)) in self.map.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            let shown = if self.redact.contains(name) {
                Cow::Owned(redact_value(
                    name,
                    &String::from_utf8_lossy(value.as_bytes()),
                ))
            } else {
                String::from_utf8_lossy(value.as_bytes())
            };
            write!(f, "{name}: {shown:?}")?;
        }
        f.write_str("}")
    }
}

/// A redacted header value. An `authorization` value keeps its
/// scheme, the part before the first space; everything else is
/// replaced whole.
fn redact_value(name: &HeaderName, value: &str) -> String {
    if SCHEMED_HEADERS.contains(&name.as_str())
        && let Some((scheme, _)) = value.split_once(' ')
    {
        return format!("{scheme} {REDACTED}");
    }
    REDACTED.to_owned()
}

/// The request target as logged: path and query, with credential
/// parameter values redacted when `redact` is set.
fn shown_uri(uri: &Uri, redact: bool) -> Cow<'_, str> {
    if redact {
        redact_uri(uri)
    } else {
        Cow::Borrowed(
            uri.path_and_query()
                .map_or_else(|| uri.path(), http::uri::PathAndQuery::as_str),
        )
    }
}

/// The request target with the values of credential query parameters
/// replaced. Names are matched as sent, without percent-decoding.
fn redact_uri(uri: &Uri) -> Cow<'_, str> {
    let Some(query) = uri.query() else {
        return Cow::Borrowed(uri.path());
    };
    let params: Vec<Cow<'_, str>> = query
        .split('&')
        .map(|param| match param.split_once('=') {
            Some((name, _))
                if CREDENTIAL_PARAMS
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(name)) =>
            {
                Cow::Owned(format!("{name}={REDACTED}"))
            }
            _ => Cow::Borrowed(param),
        })
        .collect();
    Cow::Owned(format!("{}?{}", uri.path(), params.join("&")))
}

#[cfg(test)]
mod tests {
    use super::*;

    use http::StatusCode;

    fn parse(yaml: &str) -> Result<Arc<dyn ExtensionBuilder>, Error> {
        DebugLogClass.configure(&serde_yaml::from_str(yaml).unwrap())
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(HeaderName::try_from(*name).unwrap(), value.parse().unwrap());
        }
        map
    }

    fn redacted(map: &HeaderMap, extra: &[&str]) -> String {
        let mut redact: Vec<HeaderName> = CREDENTIAL_HEADERS
            .iter()
            .map(|n| HeaderName::from_static(n))
            .collect();
        redact.extend(extra.iter().map(|n| HeaderName::try_from(*n).unwrap()));
        Headers {
            map,
            redact: &redact,
        }
        .to_string()
    }

    #[test]
    fn config_defaults_and_validation() {
        // No config at all, and an empty one, both take the defaults.
        for yaml in ["~", "{}"] {
            let builder = parse(yaml).expect("defaults");
            let decl = builder.declares();
            assert_eq!(decl.request_body, BodyMode::Stream);
            assert_eq!(decl.response, ResponseMode::Tap);
            assert!(!decl.selects_targets);
        }
        assert!(parse("maxBodyBytes: 1048577").is_err(), "over the ceiling");
        assert!(parse("redactHeaders: [\"bad name\"]").is_err());
        assert!(
            parse("maxBodyByte: 10").is_err(),
            "unknown fields are rejected"
        );
    }

    /// Heads only: no body access is declared, so the rule's body
    /// handling is whatever it was without the extension.
    #[test]
    fn zero_max_body_bytes_declares_no_body_access() {
        let decl = parse("maxBodyBytes: 0").unwrap().declares();
        assert_eq!(decl.request_body, BodyMode::None);
        assert_eq!(decl.response, ResponseMode::End);
    }

    #[test]
    fn credential_headers_are_redacted() {
        let map = headers(&[
            ("authorization", "Bearer sk-secret"),
            ("x-api-key", "sk-ant-secret"),
            ("cookie", "session=abc"),
            ("x-tenant-token", "t0k3n"),
            ("content-type", "application/json"),
            ("anthropic-version", "2023-06-01"),
        ]);
        let shown = redacted(&map, &["x-tenant-token"]);
        for secret in ["sk-secret", "sk-ant-secret", "session=abc", "t0k3n"] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
        // The scheme survives; everything else is shown as sent.
        assert!(
            shown.contains("authorization: \"Bearer [redacted]\""),
            "{shown}"
        );
        assert!(shown.contains("x-api-key: \"[redacted]\""), "{shown}");
        assert!(
            shown.contains("content-type: \"application/json\""),
            "{shown}"
        );
        assert!(
            shown.contains("anthropic-version: \"2023-06-01\""),
            "{shown}"
        );
    }

    /// Redaction off: the credential headers and parameters are shown
    /// as sent, and only the names listed in `redactHeaders` are
    /// still hidden.
    #[tokio::test(flavor = "current_thread")]
    async fn redaction_off_logs_credentials_in_the_clear() {
        let (log, _guard) = capture();
        let mut ext = parse("redactCredentials: false\nredactHeaders: [x-tenant-token]")
            .unwrap()
            .build();
        let mut cx = Cx::new();
        let (mut req, ()) = http::Request::builder()
            .uri("/v1/messages?key=qsecret")
            .header("authorization", "Bearer sk-secret")
            .header("x-api-key", "sk-ant-secret")
            .header("x-tenant-token", "t0k3n")
            .body(())
            .unwrap()
            .into_parts();
        ext.on_request_start(&mut req, &mut cx).await.unwrap();

        let out = log.contents();
        assert!(out.contains("credential redaction is off"), "{out}");
        assert!(out.contains("uri=/v1/messages?key=qsecret"), "{out}");
        assert!(
            out.contains(r#"authorization: "Bearer sk-secret""#),
            "{out}"
        );
        assert!(out.contains(r#"x-api-key: "sk-ant-secret""#), "{out}");
        assert!(out.contains(r#"x-tenant-token: "[redacted]""#), "{out}");
        assert!(!out.contains("t0k3n"), "{out}");
    }

    /// A schemeless credential has nothing to keep.
    #[test]
    fn a_bare_authorization_value_is_redacted_whole() {
        let shown = redacted(&headers(&[("authorization", "sk-secret")]), &[]);
        assert_eq!(shown, "{authorization: \"[redacted]\"}");
    }

    #[test]
    fn credential_query_params_are_redacted() {
        let uri: Uri = "/v1/models/gemini:generate?alt=sse&KEY=secret&api_key=s2&beta=true"
            .parse()
            .unwrap();
        assert_eq!(
            redact_uri(&uri),
            "/v1/models/gemini:generate?alt=sse&KEY=[redacted]&api_key=[redacted]&beta=true"
        );
        let plain: Uri = "/v1/messages".parse().unwrap();
        assert_eq!(redact_uri(&plain), "/v1/messages");
    }

    #[test]
    fn a_prefix_keeps_the_cap_and_counts_the_whole() {
        let mut p = Prefix::default();
        p.feed(b"hello ", 8);
        p.feed(b"world", 8);
        assert_eq!(p.text(), "hello wo");
        assert_eq!(p.total, 11);
        assert!(p.truncated());

        let mut short = Prefix::default();
        short.feed(b"hi", 8);
        assert!(!short.truncated());
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);

    impl Capture {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Capture {
            self.clone()
        }
    }

    /// Installs a capturing subscriber as the thread default; the
    /// guard must outlive the events.
    fn capture() -> (Capture, tracing::subscriber::DefaultGuard) {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        (capture, tracing::subscriber::set_default(subscriber))
    }

    fn served(complete: bool, body_bytes: u64) -> ResponseEnd {
        ResponseEnd {
            status: StatusCode::OK,
            body_bytes,
            complete,
            body_failed: false,
            upstream: true,
        }
    }

    /// The hooks end to end, read back from the log: four lines, the
    /// prefixes capped, and no credential anywhere in them.
    #[tokio::test(flavor = "current_thread")]
    async fn the_log_carries_capped_prefixes_and_no_credentials() {
        let (log, _guard) = capture();
        let mut ext = parse("maxBodyBytes: 4").unwrap().build();
        let mut cx = Cx::new();
        let (mut req, ()) = http::Request::builder()
            .method("POST")
            .uri("/v1/messages?key=qsecret&beta=true")
            .header("authorization", "Bearer sk-secret")
            .header("x-api-key", "sk-ant-secret")
            .header("anthropic-version", "2023-06-01")
            .body(())
            .unwrap()
            .into_parts();
        ext.on_request_start(&mut req, &mut cx).await.unwrap();
        ext.on_request_body(Bytes::from_static(b"{\"model\""), false, &mut cx)
            .await
            .unwrap();
        ext.on_request_body(Bytes::new(), true, &mut cx)
            .await
            .unwrap();

        let (mut resp, ()) = http::Response::builder()
            .header("set-cookie", "session=s3cret")
            .body(())
            .unwrap()
            .into_parts();
        ext.on_response_start(&mut resp, &mut cx);
        ext.on_response_body(Bytes::from_static(b"event: ping\n"), false, &mut cx);
        ext.on_response_end(&served(true, 12), &mut cx);

        let out = log.contents();
        for secret in ["qsecret", "sk-secret", "sk-ant-secret", "s3cret"] {
            assert!(!out.contains(secret), "{secret} leaked:\n{out}");
        }
        for line in [
            " request ",
            " request body ",
            " response ",
            " response end ",
        ] {
            assert!(out.contains(line), "missing{line}line:\n{out}");
        }
        assert!(
            out.contains("uri=/v1/messages?key=[redacted]&beta=true"),
            "{out}"
        );
        assert!(
            out.contains(r#"authorization: "Bearer [redacted]""#),
            "{out}"
        );
        assert!(out.contains(r#"anthropic-version: "2023-06-01""#), "{out}");
        assert!(out.contains(r#"body="{\"mo""#), "request prefix:\n{out}");
        assert!(out.contains(r#"body="even""#), "response prefix:\n{out}");
        assert!(
            out.contains("body_bytes=8"),
            "the whole request is counted:\n{out}"
        );
        assert_eq!(out.matches("request body").count(), 1, "{out}");
    }

    /// A request answered partway through its body still logs what
    /// arrived, with the end line, marked incomplete.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unfinished_request_body_is_logged_at_the_end() {
        let (log, _guard) = capture();
        let mut ext = parse("{}").unwrap().build();
        let mut cx = Cx::new();
        ext.on_request_body(Bytes::from_static(b"partial"), false, &mut cx)
            .await
            .unwrap();
        ext.on_response_end(&served(false, 0), &mut cx);

        let out = log.contents();
        let line = out
            .lines()
            .find(|l| l.contains("request body"))
            .expect("the body is logged at the end");
        assert!(line.contains("complete=false"), "{line}");
        assert!(line.contains(r#"body="partial""#), "{line}");
    }

    /// An Anthropic stream, split mid-event by the second chunk.
    const STREAM: [&[u8]; 2] = [
        b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":\
          {\"id\":\"msg_1\",\"type\":\"message\",\"content\":[]}}\n\n\
          event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,",
        b"\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
          event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\
          \"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\\nworld\"}}\n\n",
    ];

    /// The `response end` line for [`STREAM`] served as `content_type`.
    fn stream_end_line(config: &str, content_type: &str) -> String {
        let (log, _guard) = capture();
        let mut ext = parse(config).unwrap().build();
        let mut cx = Cx::new();
        let (mut resp, ()) = http::Response::builder()
            .header("content-type", content_type)
            .body(())
            .unwrap()
            .into_parts();
        ext.on_response_start(&mut resp, &mut cx);
        ext.on_response_body(Bytes::from_static(STREAM[0]), false, &mut cx);
        ext.on_response_body(Bytes::from_static(STREAM[1]), true, &mut cx);
        ext.on_response_end(&served(true, 0), &mut cx);
        log.contents()
            .lines()
            .find(|l| l.contains("response end"))
            .expect("a response end line")
            .to_owned()
    }

    /// By default an event stream logs as the message it built, as
    /// JSON on one line.
    #[test]
    fn an_event_stream_logs_reassembled() {
        let line = stream_end_line("{}", "text/event-stream; charset=utf-8");
        assert!(line.contains(r#"destreamed="anthropic""#), "{line}");
        assert!(line.contains("events=3"), "{line}");
        assert!(line.contains("truncated=false"), "{line}");
        assert!(
            line.contains(
                r#"body={"type":"message","id":"msg_1","content":[{"type":"text","text":"Hello\nworld"}]}"#
            ),
            "{line}"
        );
    }

    /// `destream: false` logs the raw prefix, and so does a body that
    /// is not an event stream, whatever it holds.
    #[test]
    fn a_raw_stream_and_a_non_stream_log_their_prefix() {
        for (config, content_type) in [
            ("destream: false", "text/event-stream"),
            ("{}", "application/json"),
        ] {
            let line = stream_end_line(config, content_type);
            assert!(!line.contains("destreamed"), "{line}");
            assert!(
                line.contains(r#"body="event: message_start\ndata: "#),
                "{line}"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn heads_only_logs_no_body_fields() {
        let (log, _guard) = capture();
        let mut ext = parse("maxBodyBytes: 0").unwrap().build();
        let mut cx = Cx::new();
        ext.on_response_end(&served(true, 12), &mut cx);
        let out = log.contents();
        assert!(out.contains("response end"), "{out}");
        assert!(!out.contains("body="), "{out}");
        assert!(!out.contains("request body"), "{out}");
    }
}
