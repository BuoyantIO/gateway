//! HTTP driver used by tests to send requests through the data
//! plane and assert responses.
//!
//! Every entrypoint takes the gateway address the test read from
//! `Gateway.status.addresses` (see `fixtures::gateway_address`) —
//! the same way an external client finds the gateway. All e2e
//! listeners bind port 80, so URLs carry the bare address.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use http::StatusCode;
use reqwest::header::HeaderMap;
use tokio_stream::StreamExt;

/// Outer deadline for the wait loops. Generous because a fresh
/// cluster's first test pays every cold start at once: data-plane
/// pod, config bootstrap, and the `LoadBalancer` proxy behind the
/// gateway address.
const WAIT_DEADLINE: Duration = Duration::from_mins(1);

/// Thin wrapper over `reqwest::Client` targeting one gateway
/// address. Each request sets a custom `Host` header so the gateway
/// can listener-match by hostname.
pub struct Driver {
    client: reqwest::Client,
    addr: String,
}

impl Driver {
    #[allow(clippy::missing_panics_doc)]
    pub fn new(gateway_addr: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client builds");
        Self {
            client,
            addr: gateway_addr.to_string(),
        }
    }

    /// Build a GET against the gateway with the given virtual `Host`
    /// header and request path.
    ///
    /// # Errors
    /// Returns an error if the request fails to send (network or
    /// connect error). HTTP-level non-2xx is NOT an error — inspect
    /// the response status.
    pub async fn get(
        &self,
        host: &str,
        path: &str,
        extra_headers: HeaderMap,
    ) -> Result<reqwest::Response> {
        let url = format!("http://{}{path}", self.addr);
        let resp = self
            .client
            .get(&url)
            .header(reqwest::header::HOST, host)
            .headers(extra_headers)
            .send()
            .await
            .with_context(|| format!("GET {url} (host {host})"))?;
        Ok(resp)
    }

    /// Build a request with arbitrary method.
    ///
    /// # Errors
    /// Returns an error on transport failure.
    pub async fn request(
        &self,
        method: reqwest::Method,
        host: &str,
        path: &str,
        extra_headers: HeaderMap,
    ) -> Result<reqwest::Response> {
        let url = format!("http://{}{path}", self.addr);
        let resp = self
            .client
            .request(method.clone(), &url)
            .header(reqwest::header::HOST, host)
            .headers(extra_headers)
            .send()
            .await
            .with_context(|| format!("{method} {url} (host {host})"))?;
        Ok(resp)
    }
}

/// Every outcome a wait loop saw before giving up, grouped by what
/// happened, in first-seen order.
///
/// A timeout used to report only the last status and the last error,
/// which hides the sequence that tells the failures apart: "503, then
/// resets from then on" is a path that worked and broke, while "resets
/// throughout" is one that never worked.
struct Attempts {
    started: Instant,
    outcomes: Vec<Outcome>,
}

struct Outcome {
    what: String,
    count: u32,
    first: Duration,
    last: Duration,
}

impl Attempts {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            outcomes: Vec::new(),
        }
    }

    fn record(&mut self, what: String) {
        let at = self.started.elapsed();
        if let Some(o) = self.outcomes.iter_mut().find(|o| o.what == what) {
            o.count += 1;
            o.last = at;
        } else {
            self.outcomes.push(Outcome {
                what,
                count: 1,
                first: at,
                last: at,
            });
        }
    }
}

impl fmt::Display for Attempts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total: u32 = self.outcomes.iter().map(|o| o.count).sum();
        write!(f, "after {total} unexpected outcome(s):")?;
        for o in &self.outcomes {
            write!(
                f,
                "\n  {}x between +{:.1}s and +{:.1}s: {}",
                o.count,
                o.first.as_secs_f64(),
                o.last.as_secs_f64(),
                o.what
            )?;
        }
        Ok(())
    }
}

/// Poll the gateway until a GET for `(host, path)` returns
/// `expected_status`. Retries with backoff until [`WAIT_DEADLINE`].
///
/// # Errors
/// Returns an error if the gateway doesn't reach the expected state
/// within the deadline.
pub async fn wait_until_routed(
    gateway_addr: &str,
    host: &str,
    path: &str,
    expected_status: StatusCode,
) -> Result<reqwest::Response> {
    let driver = Driver::new(gateway_addr);
    let mut attempts = Attempts::new();
    let deadline = attempts.started + WAIT_DEADLINE;
    let mut backoff = Duration::from_millis(250);
    loop {
        match driver.get(host, path, HeaderMap::new()).await {
            Ok(resp) if resp.status() == expected_status => return Ok(resp),
            Ok(resp) => attempts.record(resp.status().to_string()),
            Err(e) => attempts.record(format!("error: {e:#}")),
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "wait_until_routed timed out: host={host} path={path} \
                 wanted={expected_status} {attempts}"
            );
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(2));
    }
}

/// Poll the gateway until a plaintext GET for `(host, path)` returns
/// `expected_status` **without following the redirect**, then hand back
/// the response so the caller can inspect the `Location` header. Used
/// for `RequestRedirect`, which answers with a 3xx.
///
/// # Errors
/// Returns an error if the gateway doesn't reach the expected state
/// within the deadline.
pub async fn wait_until_redirected(
    gateway_addr: &str,
    host: &str,
    path: &str,
    expected_status: StatusCode,
) -> Result<reqwest::Response> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        // Return the 3xx instead of chasing it (the target is https, so
        // following it would just fail to connect).
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building no-redirect reqwest client")?;
    let url = format!("http://{gateway_addr}{path}");
    let mut attempts = Attempts::new();
    let deadline = attempts.started + WAIT_DEADLINE;
    let mut backoff = Duration::from_millis(250);
    loop {
        match client
            .get(&url)
            .header(reqwest::header::HOST, host)
            .send()
            .await
        {
            Ok(resp) if resp.status() == expected_status => return Ok(resp),
            Ok(resp) => attempts.record(resp.status().to_string()),
            Err(e) => attempts.record(format!("error: {e:#}")),
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "wait_until_redirected timed out: host={host} path={path} \
                 wanted={expected_status} {attempts}"
            );
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(2));
    }
}

/// An HTTPS client that resolves `host` to the gateway address and
/// trusts any server cert. The connection sends `host` as SNI (so
/// the gateway selects the matching TLS listener) and as the `Host`
/// authority (the gateway strips the port before matching).
fn tls_client(host: &str, gateway_addr: &str) -> Result<reqwest::Client> {
    let ip: IpAddr = gateway_addr
        .parse()
        .with_context(|| format!("gateway address {gateway_addr} is not an IP"))?;
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        // Tests use a throwaway self-signed cert; the point is to
        // prove termination, not chain validation.
        .danger_accept_invalid_certs(true)
        // The port comes from the request URL; resolve only pins the IP.
        .resolve(host, SocketAddr::from((ip, 0)))
        .build()
        .context("building TLS reqwest client")
}

/// Poll the gateway until an HTTPS GET for `(host, path)` terminates
/// and returns `expected_status`. Same retry/backoff shape as
/// [`wait_until_routed`], over TLS. The e2e HTTPS listeners bind
/// port 80, hence the explicit port in the URL.
///
/// # Errors
/// Returns an error if the gateway doesn't reach the expected state
/// within the deadline.
pub async fn wait_until_routed_tls(
    gateway_addr: &str,
    host: &str,
    path: &str,
    expected_status: StatusCode,
) -> Result<reqwest::Response> {
    let client = tls_client(host, gateway_addr)?;
    let url = format!("https://{host}:80{path}");
    let mut attempts = Attempts::new();
    let deadline = attempts.started + WAIT_DEADLINE;
    let mut backoff = Duration::from_millis(250);
    loop {
        match client.get(&url).send().await {
            Ok(resp) if resp.status() == expected_status => return Ok(resp),
            Ok(resp) => attempts.record(resp.status().to_string()),
            Err(e) => attempts.record(format!("error: {e:#}")),
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "wait_until_routed_tls timed out: host={host} path={path} \
                 wanted={expected_status} {attempts}"
            );
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(2));
    }
}

/// What a streamed response looked like as it arrived.
///
/// The timings are what make "the tokens streamed" an assertion
/// rather than a hope: [`Sse::first_chunk`] is the moment the first
/// body frame reached the client, and a response the gateway had
/// buffered would show it indistinguishable from [`Sse::last_chunk`].
pub struct Sse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    /// Body bytes received, concatenated.
    pub body: String,
    pub bytes: u64,
    /// Frames the client was handed, which is not the number of SSE
    /// events: nothing promises they line up one to one.
    pub chunks: u64,
    /// Time from sending the request to the first and last body
    /// frames. `None` when no frame ever arrived.
    pub first_chunk: Option<Duration>,
    pub last_chunk: Option<Duration>,
    /// Whether the body ran to its end, as opposed to the caller
    /// walking away from it.
    pub complete: bool,
}

/// A client for responses that outlive a normal request. The usual
/// `timeout` bounds the whole exchange, body included, which a long
/// completion is meant to exceed; `read_timeout` bounds the gap
/// between frames instead, so a stalled stream still fails fast.
fn stream_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(Duration::from_secs(10))
        .build()
        .context("building streaming reqwest client")
}

/// POST `body` as JSON and consume the response body frame by frame,
/// timing each one.
///
/// `take` bounds how many frames are read: `None` reads to the end of
/// the stream, and `Some(n)` stops after `n` and drops the response,
/// which is how a test disconnects mid-stream.
///
/// # Errors
/// Returns an error on transport failure, or if a frame fails to
/// arrive within the read timeout.
pub async fn post_sse(
    gateway_addr: &str,
    host: &str,
    path: &str,
    body: serde_json::Value,
    take: Option<u64>,
) -> Result<Sse> {
    let url = format!("http://{gateway_addr}{path}");
    let started = Instant::now();
    let resp = stream_client()?
        .post(&url)
        .header(reqwest::header::HOST, host)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url} (host {host})"))?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let mut sse = Sse {
        status,
        headers,
        body: String::new(),
        bytes: 0,
        chunks: 0,
        first_chunk: None,
        last_chunk: None,
        complete: false,
    };

    let mut stream = Box::pin(resp.bytes_stream());
    loop {
        if take.is_some_and(|n| sse.chunks >= n) {
            // Drop the stream, and with it the connection: the
            // gateway sees the client go away mid-response.
            break;
        }
        let Some(frame) = stream.next().await else {
            sse.complete = true;
            break;
        };
        let frame = frame.with_context(|| format!("reading body of POST {url}"))?;
        let elapsed = started.elapsed();
        sse.first_chunk.get_or_insert(elapsed);
        sse.last_chunk = Some(elapsed);
        sse.chunks += 1;
        sse.bytes += frame.len() as u64;
        sse.body.push_str(&String::from_utf8_lossy(&frame));
    }
    Ok(sse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_group_repeats_in_first_seen_order() {
        let mut attempts = Attempts::new();
        attempts.record("503 Service Unavailable".into());
        attempts.record("error: reset".into());
        attempts.record("error: reset".into());

        let report = attempts.to_string();
        let lines: Vec<&str> = report.lines().collect();
        assert_eq!(lines[0], "after 3 unexpected outcome(s):");
        assert!(lines[1].starts_with("  1x ") && lines[1].ends_with(": 503 Service Unavailable"));
        assert!(lines[2].starts_with("  2x ") && lines[2].ends_with(": error: reset"));
        assert_eq!(lines.len(), 3);
    }
}
