//! HTTP driver used by tests to send requests through the data
//! plane and assert responses.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use http::StatusCode;
use reqwest::header::HeaderMap;

use crate::{NODE_HOST, NODE_PORT};

/// Thin wrapper over `reqwest::Client` that always targets the kind
/// cluster's `NodePort`. Each request sets a custom `Host` header so
/// the gateway can listener-match by hostname.
pub struct Driver {
    client: reqwest::Client,
}

impl Driver {
    #[allow(clippy::missing_panics_doc)]
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client builds");
        Self { client }
    }

    /// Build a GET against the gateway's `NodePort` with the given
    /// virtual `Host` header and request path.
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
        let url = format!("http://{NODE_HOST}:{NODE_PORT}{path}");
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
        let url = format!("http://{NODE_HOST}:{NODE_PORT}{path}");
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

impl Default for Driver {
    fn default() -> Self {
        Self::new()
    }
}

/// Poll the gateway until a GET for `(host, path)` returns
/// `expected_status`. Retries with backoff for up to ~30 seconds.
///
/// Until the control plane writes back `.status.conditions` on
/// `Gateway` / `HTTPRoute`, tests don't have a `Programmed` signal
/// to wait on, so we probe the data path directly. When status
/// writeback lands, callers can switch to condition-based waits.
///
/// # Errors
/// Returns an error if the gateway doesn't reach the expected state
/// within the deadline.
pub async fn wait_until_routed(
    host: &str,
    path: &str,
    expected_status: StatusCode,
) -> Result<reqwest::Response> {
    let driver = Driver::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut backoff = Duration::from_millis(250);
    let mut last_seen: Option<StatusCode> = None;
    loop {
        match driver.get(host, path, HeaderMap::new()).await {
            Ok(resp) if resp.status() == expected_status => return Ok(resp),
            Ok(resp) => last_seen = Some(resp.status()),
            Err(_) => {}
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "wait_until_routed timed out: host={host} path={path} \
                 wanted={expected_status} last_seen={last_seen:?}"
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
    let url = format!("http://{NODE_HOST}:{NODE_PORT}{path}");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut backoff = Duration::from_millis(250);
    let mut last_seen: Option<StatusCode> = None;
    loop {
        match client
            .get(&url)
            .header(reqwest::header::HOST, host)
            .send()
            .await
        {
            Ok(resp) if resp.status() == expected_status => return Ok(resp),
            Ok(resp) => last_seen = Some(resp.status()),
            Err(_) => {}
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "wait_until_redirected timed out: host={host} path={path} \
                 wanted={expected_status} last_seen={last_seen:?}"
            );
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(2));
    }
}

/// An HTTPS client that resolves `host` to the cluster's loopback
/// `NodePort` and trusts any server cert. The connection sends `host`
/// as SNI (so the gateway selects the matching TLS listener) and as the
/// `Host` authority (the gateway strips the port before matching).
fn tls_client(host: &str) -> Result<reqwest::Client> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, NODE_PORT));
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        // Tests use a throwaway self-signed cert; the point is to
        // prove termination, not chain validation.
        .danger_accept_invalid_certs(true)
        .resolve(host, addr)
        .build()
        .context("building TLS reqwest client")
}

/// Poll the gateway until an HTTPS GET for `(host, path)` terminates
/// and returns `expected_status`. Same retry/backoff shape as
/// [`wait_until_routed`], over TLS.
///
/// # Errors
/// Returns an error if the gateway doesn't reach the expected state
/// within the deadline.
pub async fn wait_until_routed_tls(
    host: &str,
    path: &str,
    expected_status: StatusCode,
) -> Result<reqwest::Response> {
    let client = tls_client(host)?;
    let url = format!("https://{host}:{NODE_PORT}{path}");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut backoff = Duration::from_millis(250);
    let mut last_seen: Option<StatusCode> = None;
    loop {
        match client.get(&url).send().await {
            Ok(resp) if resp.status() == expected_status => return Ok(resp),
            Ok(resp) => last_seen = Some(resp.status()),
            Err(_) => {}
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "wait_until_routed_tls timed out: host={host} path={path} \
                 wanted={expected_status} last_seen={last_seen:?}"
            );
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(2));
    }
}
