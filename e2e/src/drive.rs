//! HTTP driver used by tests to send requests through the data
//! plane and assert responses.
//!
//! Every entrypoint takes the gateway address the test read from
//! `Gateway.status.addresses` (see `fixtures::gateway_address`) —
//! the same way an external client finds the gateway. All e2e
//! listeners bind port 80, so URLs carry the bare address.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use http::StatusCode;
use reqwest::header::HeaderMap;

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

/// Poll the gateway until a GET for `(host, path)` returns
/// `expected_status`. Retries with backoff for up to ~30 seconds.
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
    let deadline = std::time::Instant::now() + WAIT_DEADLINE;
    let mut backoff = Duration::from_millis(250);
    let mut last_seen: Option<StatusCode> = None;
    let mut last_err: Option<String> = None;
    loop {
        match driver.get(host, path, HeaderMap::new()).await {
            Ok(resp) if resp.status() == expected_status => return Ok(resp),
            Ok(resp) => last_seen = Some(resp.status()),
            Err(e) => last_err = Some(format!("{e:#}")),
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "wait_until_routed timed out: host={host} path={path} \
                 wanted={expected_status} last_seen={last_seen:?} last_err={last_err:?}"
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
    let deadline = std::time::Instant::now() + WAIT_DEADLINE;
    let mut backoff = Duration::from_millis(250);
    let mut last_seen: Option<StatusCode> = None;
    let mut last_err: Option<String> = None;
    loop {
        match client
            .get(&url)
            .header(reqwest::header::HOST, host)
            .send()
            .await
        {
            Ok(resp) if resp.status() == expected_status => return Ok(resp),
            Ok(resp) => last_seen = Some(resp.status()),
            Err(e) => last_err = Some(format!("{e:#}")),
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "wait_until_redirected timed out: host={host} path={path} \
                 wanted={expected_status} last_seen={last_seen:?} last_err={last_err:?}"
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
    let deadline = std::time::Instant::now() + WAIT_DEADLINE;
    let mut backoff = Duration::from_millis(250);
    let mut last_seen: Option<StatusCode> = None;
    let mut last_err: Option<String> = None;
    loop {
        match client.get(&url).send().await {
            Ok(resp) if resp.status() == expected_status => return Ok(resp),
            Ok(resp) => last_seen = Some(resp.status()),
            Err(e) => last_err = Some(format!("{e:#}")),
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "wait_until_routed_tls timed out: host={host} path={path} \
                 wanted={expected_status} last_seen={last_seen:?} last_err={last_err:?}"
            );
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(2));
    }
}
