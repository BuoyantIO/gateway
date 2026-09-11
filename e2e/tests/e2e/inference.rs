//! An inference provider on the far side of the gateway: a mock
//! OpenAI-compatible server reached as a `GatewayBackend` over TLS
//! the gateway originates, with an API key the provider checks before
//! it answers anything.
//!
//! What is new here, over `egress.rs`, is the *shape of the
//! response*. A completion arrives as `text/event-stream`: a gap
//! while the model thinks, then tokens for as long as it keeps
//! generating. Nothing in the request path may hold that back, so
//! these tests assert on when bytes arrived and not only on what they
//! were — a gateway that buffered the response would satisfy every
//! content assertion and none of the timing ones.
//!
//! Three endings are covered, and each is read from two sides. The
//! client sees what it received and when; the provider's `/__stats`
//! side channel says what it managed to send; the data plane's access
//! log says how the request ended (`bytes` and `complete` on the
//! `stream end` line, which is the only place either is written
//! down). A claim made by all three is not an artifact of one.

use std::time::Duration;

use anyhow::{Context, Result};
use gateway_e2e::certs::PROVIDER_CA_PEM;
use gateway_e2e::fixtures::{
    apply_gateway, apply_gateway_backend, apply_http_route, deploy_ca_secret,
    deploy_credential_secret, deploy_provider_mock, dp_logs, gateway_backend_tls_api_key,
    provider_base_url, provider_stats,
};
use gateway_e2e::{Scope, gateway, gateway_address, http_route, post_sse, wait_until_routed};
use http::StatusCode;
use kube::Client;

/// The virtual host the route matches on.
const HOST: &str = "inference.example";
/// Header the provider reads its credential from; also what the
/// `GatewayBackend` is told to send it in.
const CREDENTIAL_HEADER: &str = "authorization";
/// The key the operator provisioned. The gateway prepends the
/// default `Bearer ` prefix, so the provider is configured to expect
/// that whole string.
const KEY: &str = "sk-e2e-not-a-real-key";

const POLL: Duration = Duration::from_millis(250);
const DEADLINE: Duration = Duration::from_mins(1);

/// Stand up the whole path: provider, gateway, trust root,
/// credential, backend, route. `provisioned_key` is what goes in the
/// Secret, which is not always what the provider will accept.
///
/// Returns the gateway's address. Callers gate on their own first
/// request rather than here, since what "ready" means differs between
/// a working credential and a rejected one.
async fn provider_path(scope: &Scope, provisioned_key: &str) -> Result<String> {
    let ns = scope.name();
    let client = scope.client();

    deploy_provider_mock(
        client,
        ns,
        "provider",
        CREDENTIAL_HEADER,
        &format!("Bearer {KEY}"),
    )
    .await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;

    deploy_ca_secret(client, ns, "provider-ca", PROVIDER_CA_PEM).await?;
    deploy_credential_secret(client, ns, "provider-key", "apiKey", provisioned_key).await?;
    apply_gateway_backend(
        client,
        &gateway_backend_tls_api_key(
            ns,
            "provider",
            &provider_base_url(ns, "provider"),
            "provider-ca",
            "provider-key",
            "apiKey",
            CREDENTIAL_HEADER,
        ),
    )
    .await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames([HOST])
            .path_prefix("/")
            .dialable_backend("provider")
            .build(),
    )
    .await?;

    Ok(addr)
}

/// A completion request body. The provider never reads it; it is here
/// because a gateway that mishandled a request body would not get far
/// enough for anything else to be true.
fn completion_request() -> serde_json::Value {
    serde_json::json!({
        "model": "e2e-mock",
        "stream": true,
        "messages": [{ "role": "user", "content": "hello" }],
    })
}

/// Poll the data plane's access log for the `stream end` line of a
/// request for `path`, and return it. The line appears when the
/// response body finishes, which is after the client has its last
/// byte, so it is worth waiting for rather than reading once.
async fn wait_for_stream_end(client: &Client, ns: &str, gw: &str, path: &str) -> Result<String> {
    let deadline = std::time::Instant::now() + DEADLINE;
    loop {
        let logs = dp_logs(client, ns, gw).await?;
        if let Some(line) = logs
            .lines()
            .find(|l| l.contains("stream end") && l.contains(&format!("path={path}")))
        {
            return Ok(line.to_owned());
        }
        if std::time::Instant::now() >= deadline {
            // The tail, because the interesting failure is the line
            // being there and saying something else.
            let tail: Vec<&str> = logs.lines().rev().take(10).collect();
            anyhow::bail!("no `stream end` line for path={path}; last lines: {tail:#?}");
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Read one `key=value` field out of a tracing text-format line.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|f| f.strip_prefix(&format!("{key}=")))
}

/// The core claim: tokens reach the client as the provider produces
/// them, and the request ends having delivered exactly what was sent.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn tokens_arrive_while_the_stream_is_open() -> Result<()> {
    let scope = Scope::new("inference").await?;
    let ns = scope.name();
    let client = scope.client();
    let addr = provider_path(&scope, KEY).await?;

    // Proves the whole chain before anything is timed: route, TLS
    // origination against the CA, and the credential the provider
    // accepts.
    let ready = wait_until_routed(&addr, HOST, "/ping", StatusCode::OK).await?;
    assert_eq!(ready.text().await?, "pong");

    // A deliberate gap before the first token, then a tail long
    // enough that a buffered response could not disguise itself as a
    // streamed one.
    let sse = post_sse(
        &addr,
        HOST,
        "/chat/completions?ttft-ms=800&tokens=12&gap-ms=120",
        completion_request(),
        None,
    )
    .await?;

    assert_eq!(sse.status, StatusCode::OK);
    assert_eq!(
        sse.headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream"),
        "the provider's content type should reach the client unaltered"
    );
    assert!(sse.complete, "the body should have run to its end");
    assert!(
        sse.body.ends_with("data: [DONE]\n\n"),
        "the stream should end on the sentinel: {:?}",
        sse.body.chars().rev().take(40).collect::<String>()
    );

    // The timing claim. The script spans 800ms + 11 * 120ms, so the
    // first and last frames are ~1.3s apart at the source; anything
    // that held the response back would collapse that to nothing.
    // The bound is loose because a loaded cluster stretches the tail,
    // never shortens it.
    let first = sse.first_chunk.context("no body frame ever arrived")?;
    let last = sse.last_chunk.context("no body frame ever arrived")?;
    assert!(
        last.saturating_sub(first) >= Duration::from_millis(500),
        "frames should have been spread over the stream, not delivered at once: \
         first={first:?} last={last:?} chunks={}",
        sse.chunks
    );
    assert!(
        first >= Duration::from_millis(600),
        "the first frame cannot predate the provider's own delay: first={first:?}"
    );

    // What the provider says it sent, including the path it was
    // reached at: the `/v1` from the baseURL, joined ahead of the
    // client's path.
    let stats = provider_stats(client, ns, "provider").await?;
    let record = stats
        .requests
        .iter()
        .find(|r| r.path.ends_with("/chat/completions"))
        .context("the provider recorded no completion request")?;
    assert!(
        record.authorized,
        "the credential should have been accepted"
    );
    assert_eq!(record.path, "/v1/chat/completions");
    assert_eq!(record.method, "POST");
    assert!(record.complete, "the provider should have finished sending");
    assert_eq!(
        record.bytes_sent, sse.bytes,
        "every byte the provider sent should have reached the client"
    );

    // And what the gateway counted on its way past.
    let line = wait_for_stream_end(client, ns, "gw", "/chat/completions").await?;
    assert_eq!(
        field(&line, "bytes"),
        Some(sse.bytes.to_string().as_str()),
        "the access log's byte count should agree with the client: {line}"
    );
    assert_eq!(
        field(&line, "complete"),
        Some("true"),
        "the request should have ended cleanly: {line}"
    );

    Ok(())
}

/// The other ending: the client walks away mid-stream. The request
/// has to end — at the gateway, which says so, and at the provider,
/// which stops generating rather than talking to no one.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn a_mid_stream_disconnect_ends_the_request() -> Result<()> {
    /// The full script, which the client will not stay for.
    const TOKENS: u64 = 64;

    let scope = Scope::new("inference-cut").await?;
    let ns = scope.name();
    let client = scope.client();
    let addr = provider_path(&scope, KEY).await?;

    wait_until_routed(&addr, HOST, "/ping", StatusCode::OK).await?;

    // A tail far longer than the two frames the client will take, so
    // the disconnect is unambiguously mid-stream.
    let sse = post_sse(
        &addr,
        HOST,
        &format!("/chat/completions?ttft-ms=300&tokens={TOKENS}&gap-ms=200"),
        completion_request(),
        Some(2),
    )
    .await?;
    assert_eq!(sse.status, StatusCode::OK);
    assert_eq!(
        sse.chunks, 2,
        "the client should have stopped where it said"
    );
    assert!(!sse.complete, "the client left the stream unfinished");

    // The gateway ends the request and says it was cut short.
    let line = wait_for_stream_end(client, ns, "gw", "/chat/completions").await?;
    assert_eq!(
        field(&line, "complete"),
        Some("false"),
        "an abandoned response should not be logged as complete: {line}"
    );

    // The provider stopped generating. Its count going nowhere across
    // a window several token gaps wide is what "stopped" looks like
    // from outside; a provider still streaming would add ~5 chunks.
    let completion = |stats: gateway_e2e::fixtures::ProviderStats| {
        stats
            .requests
            .into_iter()
            .find(|r| r.path.ends_with("/chat/completions"))
    };
    let first = completion(provider_stats(client, ns, "provider").await?)
        .context("the provider recorded no completion request")?;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let second = completion(provider_stats(client, ns, "provider").await?)
        .context("the completion request vanished from the provider's records")?;

    assert_eq!(
        first.chunks_sent, second.chunks_sent,
        "the provider should have stopped generating once the client left"
    );
    assert!(
        second.chunks_sent < TOKENS,
        "it should have stopped well short of the script: {} of {TOKENS}",
        second.chunks_sent
    );
    assert!(
        !second.complete,
        "and never reached the end of the completion"
    );

    Ok(())
}

/// The provider's own check is real: give it a credential it does not
/// accept and its refusal is what the client gets, unaltered.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn a_credential_the_provider_rejects_reaches_the_client() -> Result<()> {
    let scope = Scope::new("inference-401").await?;
    let ns = scope.name();
    let client = scope.client();
    let addr = provider_path(&scope, "sk-the-wrong-key").await?;

    let resp = wait_until_routed(&addr, HOST, "/ping", StatusCode::UNAUTHORIZED).await?;
    let body = resp.text().await?;
    assert!(
        body.contains("invalid api key"),
        "the provider's own error body should pass through: {body}"
    );

    let stats = provider_stats(client, ns, "provider").await?;
    let record = stats
        .requests
        .last()
        .context("the provider recorded no request")?;
    assert!(
        !record.authorized,
        "the provider should have seen a credential it does not accept"
    );

    Ok(())
}
