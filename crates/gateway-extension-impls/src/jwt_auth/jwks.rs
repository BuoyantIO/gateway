//! The issuer's signing keys: fetched from its JWKS URL, cached, and
//! looked up by `kid`.
//!
//! Issuers rotate keys and keep the previous ones published for a
//! while (Dex rotates every six hours), so a cached set goes stale only
//! when a token arrives signed by a key published since the last
//! fetch. That is the one trigger for refetching, and it is bounded:
//!
//! * With keys cached, an unknown `kid` refetches at most once every
//!   [`REFETCH_INTERVAL`]. Inside the window it is an unknown key, a
//!   401, without asking the issuer: a stream of tokens with made-up
//!   `kid`s costs one request a minute, not one per token.
//! * With nothing cached, every request needs keys, and the issuer is
//!   asked at most once every [`EMPTY_RETRY_INTERVAL`]. A request that
//!   still finds none is answered 503: the gateway cannot tell a good
//!   token from a bad one.
//!
//! Fetches are single-flight: callers queue on one lock, and each
//! re-reads the set after acquiring it, so a burst of tokens with a
//! new `kid` costs one fetch. A successful fetch replaces the whole
//! set, so a key the issuer stopped publishing stops verifying. A
//! failed one keeps the old set.
//!
//! The clock is a parameter so the windows are testable without
//! waiting them out.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use gateway_extension::Error;
use http::{Request, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;

use super::LOG;
use super::token::RsaKey;

/// How often an unknown `kid` may trigger a refetch while keys are
/// cached.
pub(crate) const REFETCH_INTERVAL: Duration = Duration::from_mins(1);
/// How often an empty cache may retry the issuer.
pub(crate) const EMPTY_RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// Bound on one fetch, connect through body.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// A key set is a few kilobytes; anything near this is not one.
const MAX_JWKS_BYTES: usize = 1024 * 1024;

/// What a lookup found.
pub(crate) enum Lookup {
    Found(Arc<RsaKey>),
    /// Keys are cached, and none has this `kid`.
    Unknown,
    /// No keys at all: the issuer has not answered since start.
    Unavailable,
}

/// The cached key set for one issuer, and how to refresh it.
pub(crate) struct Keys {
    source: Source,
    set: RwLock<Arc<HashMap<String, Arc<RsaKey>>>>,
    fetch: tokio::sync::Mutex<Attempts>,
}

/// When the issuer was last asked, per trigger.
#[derive(Default)]
struct Attempts {
    /// Last fetch made while the cache was empty.
    empty: Option<Instant>,
    /// Last refetch an unknown `kid` caused.
    refetch: Option<Instant>,
}

impl Keys {
    pub(crate) fn new(url: Uri) -> Result<Self, Error> {
        Ok(Self {
            source: Source::new(url)?,
            set: RwLock::new(Arc::default()),
            fetch: tokio::sync::Mutex::new(Attempts::default()),
        })
    }

    /// Fill an empty cache, under the same window a request would use.
    /// Run in the background at configure time, so the first request
    /// usually finds keys waiting.
    pub(crate) async fn prefetch(&self, now: Instant) {
        let _ = self.key("", now).await;
    }

    /// The key published under `kid`, refetching per the rules above
    /// when it is not cached.
    pub(crate) async fn key(&self, kid: &str, now: Instant) -> Lookup {
        if let Some(key) = self.cached(kid) {
            return Lookup::Found(key);
        }
        let mut attempts = self.fetch.lock().await;
        // Whoever held the lock may have fetched the key we want.
        if let Some(key) = self.cached(kid) {
            return Lookup::Found(key);
        }
        let empty = self.current().is_empty();
        let (last, window) = if empty {
            (&mut attempts.empty, EMPTY_RETRY_INTERVAL)
        } else {
            (&mut attempts.refetch, REFETCH_INTERVAL)
        };
        if last.is_none_or(|t| now.saturating_duration_since(t) >= window) {
            *last = Some(now);
            match self.source.fetch().await {
                Ok(keys) => {
                    tracing::info!(target: LOG,
                        keys = keys.len(),
                        url = %self.source.url,
                        "jwt_auth: fetched signing keys"
                    );
                    *self
                        .set
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(keys);
                }
                Err(error) => {
                    tracing::warn!(target: LOG,
                        %error,
                        url = %self.source.url,
                        cached = !empty,
                        "jwt_auth: fetching signing keys failed"
                    );
                }
            }
        }
        drop(attempts);
        if let Some(key) = self.cached(kid) {
            Lookup::Found(key)
        } else if self.current().is_empty() {
            Lookup::Unavailable
        } else {
            Lookup::Unknown
        }
    }

    fn current(&self) -> Arc<HashMap<String, Arc<RsaKey>>> {
        Arc::clone(
            &self
                .set
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    fn cached(&self, kid: &str) -> Option<Arc<RsaKey>> {
        self.current().get(kid).cloned()
    }
}

/// The JWKS endpoint and the client that reaches it.
struct Source {
    url: Uri,
    client: Transport,
}

enum Transport {
    Plain(Client<HttpConnector, Empty<Bytes>>),
    Tls(Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>),
}

impl Source {
    fn new(url: Uri) -> Result<Self, Error> {
        let mut http = HttpConnector::new();
        http.set_connect_timeout(Some(CONNECT_TIMEOUT));
        let client = match url.scheme_str() {
            Some("http") => Transport::Plain(Client::builder(TokioExecutor::new()).build(http)),
            Some("https") => {
                http.enforce_http(false);
                let tls = hyper_rustls::HttpsConnectorBuilder::new()
                    .with_provider_and_native_roots(rustls::crypto::ring::default_provider())
                    .map_err(|e| format!("loading the platform's trust roots failed: {e}"))?
                    .https_only()
                    .enable_http1()
                    .wrap_connector(http);
                Transport::Tls(Client::builder(TokioExecutor::new()).build(tls))
            }
            _ => return Err("`jwksUrl` must be an http or https URL".into()),
        };
        Ok(Self { url, client })
    }

    async fn fetch(&self) -> Result<HashMap<String, Arc<RsaKey>>, Error> {
        let request = Request::get(self.url.clone())
            .header(http::header::ACCEPT, "application/json")
            .body(Empty::new())?;
        let fetched = async {
            let response = match &self.client {
                Transport::Plain(c) => c.request(request).await?,
                Transport::Tls(c) => c.request(request).await?,
            };
            if response.status() != StatusCode::OK {
                return Err(Error::from(format!("status {}", response.status())));
            }
            let body = Limited::new(response.into_body(), MAX_JWKS_BYTES)
                .collect()
                .await?
                .to_bytes();
            Ok(body)
        };
        let body = tokio::time::timeout(FETCH_TIMEOUT, fetched)
            .await
            .map_err(|_| "timed out")??;
        parse(&body)
    }
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// One published key. Only RSA signing keys for RS256 are kept.
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

/// The RS256 signing keys in a JWKS document, by `kid`. Keys of any
/// other type, use or algorithm, and keys without a `kid`, are skipped
/// rather than failing the set: issuers publish encryption keys and
/// other algorithms beside the ones that matter here.
fn parse(body: &[u8]) -> Result<HashMap<String, Arc<RsaKey>>, Error> {
    let jwks: Jwks =
        serde_json::from_slice(body).map_err(|e| format!("not a JWKS document: {e}"))?;
    let mut keys = HashMap::new();
    for jwk in jwks.keys {
        if jwk.kty != "RSA"
            || jwk.usage.as_deref().is_some_and(|u| u != "sig")
            || jwk.alg.as_deref().is_some_and(|a| a != "RS256")
        {
            continue;
        }
        let (Some(kid), Some(n), Some(e)) = (jwk.kid, jwk.n, jwk.e) else {
            continue;
        };
        let (Ok(n), Ok(e)) = (URL_SAFE_NO_PAD.decode(n), URL_SAFE_NO_PAD.decode(e)) else {
            continue;
        };
        keys.insert(kid, Arc::new(RsaKey { n, e }));
    }
    Ok(keys)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::jwt_auth::token::tests::TestKey;

    /// A JWKS endpoint the test controls: it serves whatever document
    /// is current and counts the GETs it answered.
    pub(crate) struct FakeIssuer {
        pub(crate) url: Uri,
        document: Arc<Mutex<Value>>,
        hits: Arc<AtomicUsize>,
    }

    impl FakeIssuer {
        pub(crate) async fn serving(keys: &[&TestKey]) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/dex/keys", listener.local_addr().unwrap())
                .parse()
                .unwrap();
            let issuer = Self {
                url,
                document: Arc::new(Mutex::new(Value::Null)),
                hits: Arc::new(AtomicUsize::new(0)),
            };
            issuer.publish(keys);
            let (document, hits) = (Arc::clone(&issuer.document), Arc::clone(&issuer.hits));
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    // One request per connection; the client's pool
                    // reopens.
                    let mut buf = vec![0; 4096];
                    let _ = sock.read(&mut buf).await;
                    hits.fetch_add(1, Ordering::SeqCst);
                    let body = document.lock().unwrap().to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                }
            });
            issuer
        }

        /// Replace the published set: a key rotation.
        pub(crate) fn publish(&self, keys: &[&TestKey]) {
            *self.document.lock().unwrap() =
                json!({ "keys": keys.iter().map(|k| k.jwk()).collect::<Vec<_>>() });
        }

        pub(crate) fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    fn found(lookup: &Lookup) -> bool {
        matches!(lookup, Lookup::Found(_))
    }

    #[tokio::test]
    async fn a_rotated_key_costs_exactly_one_refetch() {
        let (a, b) = (TestKey::a(), TestKey::b());
        let issuer = FakeIssuer::serving(&[&a]).await;
        let keys = Keys::new(issuer.url.clone()).unwrap();
        let t0 = Instant::now();

        assert!(
            found(&keys.key(a.kid, t0).await),
            "first use fills the cache"
        );
        assert_eq!(issuer.hits(), 1);
        assert!(
            found(&keys.key(a.kid, t0).await),
            "a cached key costs nothing"
        );
        assert_eq!(issuer.hits(), 1);

        // The issuer rotates: B is published beside A.
        issuer.publish(&[&a, &b]);
        let t1 = t0 + Duration::from_secs(1);
        let (first, second) = tokio::join!(keys.key(b.kid, t1), keys.key(b.kid, t1));
        assert!(found(&first) && found(&second), "the rotated key verifies");
        assert_eq!(issuer.hits(), 2, "two callers, one refetch");

        // A made-up kid inside the window is unknown without asking.
        let t2 = t1 + Duration::from_secs(30);
        assert!(matches!(keys.key("made-up", t2).await, Lookup::Unknown));
        assert_eq!(issuer.hits(), 2, "no refetch inside the minute");

        // Past the window, one more refetch, and still unknown.
        let t3 = t1 + REFETCH_INTERVAL + Duration::from_secs(1);
        assert!(matches!(keys.key("made-up", t3).await, Lookup::Unknown));
        assert_eq!(issuer.hits(), 3);
        assert!(
            found(&keys.key(b.kid, t3).await),
            "cached keys still verify"
        );
    }

    /// A fetch replaces the set: a key the issuer dropped stops
    /// verifying once the next refetch lands.
    #[tokio::test]
    async fn a_dropped_key_leaves_the_cache_on_refetch() {
        let (a, b) = (TestKey::a(), TestKey::b());
        let issuer = FakeIssuer::serving(&[&a]).await;
        let keys = Keys::new(issuer.url.clone()).unwrap();
        let t0 = Instant::now();
        assert!(found(&keys.key(a.kid, t0).await));

        issuer.publish(&[&b]);
        assert!(found(&keys.key(b.kid, t0 + Duration::from_secs(1)).await));
        assert!(matches!(
            keys.key(a.kid, t0 + Duration::from_secs(2)).await,
            Lookup::Unknown
        ));
    }

    /// Nothing listening and nothing cached: unavailable, retried on
    /// the short window rather than per request.
    #[tokio::test]
    async fn an_unreachable_issuer_with_no_cache_is_unavailable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: Uri = format!("http://{}/keys", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        drop(listener);
        let keys = Keys::new(url).unwrap();
        let t0 = Instant::now();
        assert!(matches!(keys.key("key-a", t0).await, Lookup::Unavailable));
        let attempted = keys.fetch.lock().await.empty;
        assert_eq!(attempted, Some(t0));
        // Inside the retry window nothing is attempted.
        assert!(matches!(
            keys.key("key-a", t0 + Duration::from_secs(1)).await,
            Lookup::Unavailable
        ));
        assert_eq!(keys.fetch.lock().await.empty, Some(t0));
    }

    #[test]
    fn parse_keeps_only_rs256_signing_keys() {
        let a = TestKey::a();
        let mut enc = a.jwk();
        enc["kid"] = json!("enc");
        enc["use"] = json!("enc");
        let mut ps = a.jwk();
        ps["kid"] = json!("ps");
        ps["alg"] = json!("PS256");
        let mut bare = a.jwk();
        bare["kid"] = json!("bare");
        bare.as_object_mut().unwrap().remove("alg");
        bare.as_object_mut().unwrap().remove("use");
        let doc = json!({ "keys": [
            a.jwk(),
            enc,
            ps,
            bare,
            { "kty": "EC", "kid": "ec", "crv": "P-256", "x": "AA", "y": "AA" },
            { "kty": "RSA", "n": "AQAB", "e": "AQAB" },
        ] });
        let keys = parse(doc.to_string().as_bytes()).unwrap();
        let mut kids: Vec<_> = keys.keys().map(String::as_str).collect();
        kids.sort_unstable();
        assert_eq!(kids, ["bare", "key-a"]);
        assert_eq!(*keys["key-a"], a.public());

        assert!(parse(b"<html>").is_err());
    }

    #[test]
    fn only_http_and_https_urls_are_accepted() {
        assert!(Source::new("ftp://dex/keys".parse().unwrap()).is_err());
        assert!(Source::new("/dex/keys".parse().unwrap()).is_err());
    }
}
