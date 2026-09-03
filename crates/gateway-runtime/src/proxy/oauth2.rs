//! `OAuth2` client-credentials tokens for a dialable backend.
//!
//! An API key is the whole credential and is resolved when config is
//! applied. A token is not: it comes from a call the gateway makes on
//! its own account, and it expires. That call is what lives here,
//! together with the token it produced, cached per backend.
//!
//! What the request path sees is still one header value. Everything
//! that can be settled before a request arrives is settled when the
//! cache entry is built — the endpoint parsed, the body encoded, the
//! client secret spent into an `Authorization` header — so that
//! fetching a token is a network question and never a config one.
//!
//! Three properties shape the rest:
//!
//! * A cache belongs to one resolved auth block. Two backends with
//!   different credentials get different caches and therefore
//!   different tokens; the same backend re-applied with the same
//!   credential keeps the token it had, even when something else
//!   about it changed and moved its revision.
//! * A token is replaced before it expires, not after. The request
//!   that discovers a stale token refreshes it while every other
//!   request keeps using the one that is still valid, so a refresh
//!   never fails a request in flight.
//! * A token endpoint that is failing is asked again on a backoff,
//!   not once per request.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use bytes::Bytes;
use gateway_config::backend::ClientAuthMethod;
use gateway_state::{ActiveOAuth2, BackendKey, ClientSecret};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::uri::Scheme;
use http::{HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use parking_lot::RwLock;
use serde::Deserialize;

use crate::proxy::body::{BoxError, UpstreamBody};
use crate::proxy::originate;

/// How long before expiry a token is replaced. The window is what
/// keeps a refresh off the critical path: the old token is still
/// valid throughout, so every request but the one doing the refresh
/// is answered from the cache.
const REFRESH_SKEW: Duration = Duration::from_secs(30);

/// Lifetime assumed when the token endpoint does not say. RFC 6749
/// only recommends `expires_in`, and something has to be chosen; a
/// short lifetime costs an occasional extra fetch, a long one would
/// send a token the provider has already forgotten.
const DEFAULT_LIFETIME: Duration = Duration::from_mins(5);

/// Longest lifetime honoured, whatever the endpoint claims. A token
/// held for a day is already generous, and this is a number from
/// outside the gateway.
const MAX_LIFETIME: Duration = Duration::from_hours(24);

/// How long a token fetch may take before the request that triggered
/// it gives up.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a failed fetch is left alone. Without it a token endpoint
/// that is down is asked once per proxied request, which is the
/// gateway making an outage worse.
const RETRY_BACKOFF: Duration = Duration::from_secs(5);

/// Most of a token response the gateway will read. A token endpoint
/// answers with a small JSON object; anything larger is not one.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Every backend's token, keyed by backend and validated by the
/// resolved auth block the token was fetched for.
///
/// Entries for a backend the config drops are left behind, as the
/// upstream clients are: one small struct per backend that ever
/// existed, holding a token nothing will ask for again.
pub(super) struct TokenCaches {
    caches: RwLock<HashMap<BackendKey, Entry>>,
    /// Reaches token endpoints named with an `http` URL. Separate
    /// from the clients that carry proxied traffic: this pool is the
    /// gateway's own calls, to hosts no request chose.
    cleartext: Client<HttpConnector, UpstreamBody>,
}

impl TokenCaches {
    /// The `Authorization` header for `backend`, from the cached
    /// token or from a fetch.
    ///
    /// # Errors
    /// [`TokenFailure::Unresolved`] when the client secret is not
    /// usable, which is a config problem; [`TokenFailure::Unavailable`]
    /// when the token endpoint could not be reached or did not answer
    /// with a token, which is not.
    pub(super) async fn header(
        &self,
        backend: &BackendKey,
        oauth: &ActiveOAuth2,
    ) -> Result<HeaderValue, TokenFailure> {
        self.cache_for(backend, oauth)?.header(self, backend).await
    }

    /// The cache for `backend` under this exact auth block, built on
    /// first use and on the first request after the credential
    /// changed.
    ///
    /// Identity is the resolved block itself, compared by value:
    /// nothing else says both "this is the credential the token was
    /// fetched with" and "this is not". A revision would be wrong in
    /// both directions — it moves when an unrelated field of the
    /// backend changes, which would throw away a good token, and two
    /// backends have unrelated revisions.
    fn cache_for(
        &self,
        backend: &BackendKey,
        oauth: &ActiveOAuth2,
    ) -> Result<Arc<TokenCache>, TokenFailure> {
        let hit = {
            let caches = self.caches.read();
            caches
                .get(backend)
                .and_then(|e| (e.spec == *oauth).then(|| e.cache.clone()))
        };
        if let Some(cache) = hit {
            return cache;
        }

        let cache = TokenRequest::build(oauth).map(|request| Arc::new(TokenCache::new(request)));
        let cache = cache.map_err(|e| {
            // A credential that cannot even be turned into a request:
            // decided and logged once here, then answered from the
            // entry for every request after it, the way an
            // uncompilable TLS block is. Fixing the config is what
            // replaces the entry.
            match e {
                BuildError::Unresolved => {
                    tracing::debug!(
                        %backend,
                        secret = %oauth.client_secret_ref,
                        "backend client secret is unresolved; not fetching a token"
                    );
                    TokenFailure::Unresolved
                }
                e => {
                    tracing::error!(%backend, error = %e, "cannot build a token request for backend");
                    TokenFailure::Unavailable
                }
            }
        });
        self.caches.write().insert(
            backend.clone(),
            Entry {
                spec: oauth.clone(),
                cache: cache.clone(),
            },
        );
        cache
    }

    /// Send one token request, over the transport its URL names.
    ///
    /// `https` is verified against the platform trust store. A token
    /// endpoint is a public provider or, in a local config, a mock;
    /// neither case is served by the backend's own trust roots, which
    /// are about a different host.
    async fn send(&self, req: Request<UpstreamBody>) -> Result<Response<Incoming>, BoxError> {
        if req.uri().scheme() == Some(&Scheme::HTTPS) {
            let client =
                originate::system_client().map_err(|e| -> BoxError { e.to_string().into() })?;
            Ok(client.request(req).await?)
        } else {
            Ok(self.cleartext.request(req).await?)
        }
    }
}

impl Default for TokenCaches {
    fn default() -> Self {
        Self {
            caches: RwLock::default(),
            cleartext: Client::builder(TokioExecutor::new()).build_http::<UpstreamBody>(),
        }
    }
}

impl std::fmt::Debug for TokenCaches {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenCaches").finish_non_exhaustive()
    }
}

/// Why the gateway has no token to send.
///
/// The two are answered alike by the request path and counted apart,
/// because they are fixed by different people: one is the config, the
/// other is the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TokenFailure {
    /// The client secret has not resolved.
    Unresolved,
    /// The token endpoint could not be reached, or did not answer
    /// with a usable token.
    Unavailable,
}

/// One backend's cache, and the auth block it belongs to.
struct Entry {
    spec: ActiveOAuth2,
    cache: Result<Arc<TokenCache>, TokenFailure>,
}

/// The token held for one credential, and what it takes to fetch
/// another.
///
/// Deliberately not `Debug`: the request carries the client secret.
struct TokenCache {
    request: TokenRequest,
    state: RwLock<State>,
    /// Held by whoever is fetching. Making the fetch single-flight is
    /// what keeps a cold start, or an expiry under load, from turning
    /// one token endpoint call into one per in-flight request.
    fetching: tokio::sync::Mutex<()>,
}

impl TokenCache {
    fn new(request: TokenRequest) -> Self {
        Self {
            request,
            state: RwLock::new(State::default()),
            fetching: tokio::sync::Mutex::new(()),
        }
    }

    /// The header to send upstream: the cached token while it is
    /// good, a fresh one when it is not.
    async fn header(
        &self,
        caches: &TokenCaches,
        backend: &BackendKey,
    ) -> Result<HeaderValue, TokenFailure> {
        // Bound, not matched in place: the guard must not be held
        // across the refresh below.
        let usable = self.state.read().usable(Instant::now());
        match usable {
            Usable::Fresh(value) => return Ok(value),
            Usable::Stale(value) => {
                // Expiring, but still good. One request refreshes and
                // the rest carry on with it, so no request waits on a
                // token it does not need yet. The one that refreshes
                // pays a round trip; the skew window is what keeps
                // that from being a request that would otherwise have
                // failed.
                let Ok(_guard) = self.fetching.try_lock() else {
                    return Ok(value);
                };
                return Ok(self.fetch(caches, backend).await.unwrap_or(value));
            }
            Usable::None => {}
        }

        // No token at all: every request needs this one, so they wait
        // on it rather than each fetching their own.
        let _guard = self.fetching.lock().await;
        let usable = self.state.read().usable(Instant::now());
        if let Usable::Fresh(value) | Usable::Stale(value) = usable {
            // Someone else fetched while we queued.
            return Ok(value);
        }
        self.fetch(caches, backend).await
    }

    /// Ask the token endpoint, and keep what it says.
    ///
    /// The caller holds `fetching`, so this runs once at a time per
    /// credential.
    async fn fetch(
        &self,
        caches: &TokenCaches,
        backend: &BackendKey,
    ) -> Result<HeaderValue, TokenFailure> {
        let retry_at = self.state.read().retry_at;
        if retry_at.is_some_and(|at| Instant::now() < at) {
            // Still backing off from the last failure.
            return Err(TokenFailure::Unavailable);
        }

        let result = tokio::time::timeout(FETCH_TIMEOUT, self.request.send(caches)).await;
        let token = match result {
            Err(_) => Err(FetchError::Timeout),
            Ok(r) => r,
        };
        let now = Instant::now();
        match token {
            Ok(token) => {
                let value = token.value.clone();
                tracing::info!(
                    %backend,
                    token_url = %self.request.url,
                    expires_in_s = token.expires_at.saturating_duration_since(now).as_secs(),
                    "fetched an access token for backend"
                );
                *self.state.write() = State {
                    token: Some(token),
                    retry_at: None,
                };
                Ok(value)
            }
            Err(e) => {
                // Warned rather than debugged: the gateway's own call
                // failed, which is an event about the deployment and
                // not about the request that happened to trigger it.
                // The backoff is what bounds how often this is said.
                tracing::warn!(
                    %backend,
                    token_url = %self.request.url,
                    error = %e,
                    "cannot fetch an access token for backend"
                );
                self.state.write().retry_at = Some(now + RETRY_BACKOFF);
                Err(TokenFailure::Unavailable)
            }
        }
    }
}

/// What one credential's cache holds between fetches.
#[derive(Default)]
struct State {
    token: Option<Token>,
    /// Earliest the endpoint may be asked again, after a failure.
    retry_at: Option<Instant>,
}

impl State {
    /// What the cached token is worth at `now`.
    fn usable(&self, now: Instant) -> Usable {
        let Some(token) = &self.token else {
            return Usable::None;
        };
        if now >= token.expires_at {
            Usable::None
        } else if now >= token.stale_at && self.retry_at.is_none_or(|at| now >= at) {
            Usable::Stale(token.value.clone())
        } else {
            // Either good, or expiring while a failed refresh is
            // still backing off — in which case there is nothing to
            // be gained by trying again for it now.
            Usable::Fresh(token.value.clone())
        }
    }
}

/// The three answers the cache can give without going anywhere.
enum Usable {
    /// Good, and not yet worth replacing.
    Fresh(HeaderValue),
    /// Still good, and worth replacing now.
    Stale(HeaderValue),
    /// Nothing to send.
    None,
}

/// One access token, as the gateway holds it.
///
/// The value is the finished header, marked sensitive, so the token
/// itself is never held anywhere the API-key path would not hold a
/// credential.
struct Token {
    value: HeaderValue,
    /// When the gateway stops sending it.
    expires_at: Instant,
    /// When the gateway starts trying to replace it.
    stale_at: Instant,
}

impl Token {
    /// Build a token from what the endpoint answered, or reject the
    /// answer.
    ///
    /// `now` is passed in rather than read here so that the lifetime
    /// arithmetic is testable without waiting for it.
    fn new(response: &TokenResponse, now: Instant) -> Result<Self, FetchError> {
        // A token type the gateway cannot send is not a token it can
        // use. Absent means bearer: it is the only type this grant is
        // ever answered with, and some providers leave it out.
        if let Some(kind) = &response.token_type
            && !kind.eq_ignore_ascii_case("bearer")
        {
            return Err(FetchError::TokenType(kind.clone()));
        }
        let access_token = response.access_token.trim();
        if access_token.is_empty() {
            return Err(FetchError::NoToken);
        }
        let mut value = HeaderValue::from_str(&format!("Bearer {access_token}"))
            .map_err(|_| FetchError::NotAHeaderValue)?;
        // Keeps the token out of `HeaderValue`'s debug output and, on
        // HTTP/2, out of the HPACK index the upstream connection
        // shares with every other request on it.
        value.set_sensitive(true);

        let lifetime = match response.expires_in {
            // Already expired on arrival. Accepting it would be a
            // fetch per request, so it is refused as an answer.
            Some(0) => return Err(FetchError::Expired),
            Some(seconds) => Duration::from_secs(seconds).min(MAX_LIFETIME),
            None => DEFAULT_LIFETIME,
        };
        // Half the lifetime for a short-lived token, so that even one
        // shorter than the skew window is replaced before it expires
        // rather than after.
        let skew = REFRESH_SKEW.min(lifetime / 2);
        Ok(Self {
            value,
            expires_at: now + lifetime,
            stale_at: now + lifetime.saturating_sub(skew),
        })
    }
}

/// One credential's token request, built once and sent whenever a
/// token is needed.
///
/// Deliberately not `Debug`: `form` carries the client secret when
/// the client authenticates that way.
struct TokenRequest {
    url: Uri,
    /// `Basic ...`, for a client authenticating with a header.
    authorization: Option<HeaderValue>,
    /// The urlencoded request body.
    form: Bytes,
}

impl TokenRequest {
    /// Everything the token endpoint will be asked, worked out once.
    fn build(oauth: &ActiveOAuth2) -> Result<Self, BuildError> {
        let secret = oauth.client_secret.as_ref().ok_or(BuildError::Unresolved)?;
        let url: Uri = oauth
            .token_url
            .parse()
            .map_err(|_| BuildError::TokenUrl(oauth.token_url.clone()))?;
        if url.host().is_none() {
            return Err(BuildError::TokenUrl(oauth.token_url.clone()));
        }
        if url.scheme() != Some(&Scheme::HTTPS) {
            // The client secret goes out in the clear, to whoever is
            // on the path. Not refused, for the same reason a
            // credential over a cleartext backend connection is not:
            // a local config or an integration test against a mock
            // endpoint has every reason to do it.
            tracing::warn!(
                token_url = %url,
                "token endpoint is not https; the client secret is sent unencrypted"
            );
        }

        let mut form = form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "client_credentials");
        if !oauth.scopes.is_empty() {
            form.append_pair("scope", &oauth.scopes.join(" "));
        }
        let authorization = match oauth.client_auth_method {
            ClientAuthMethod::ClientSecretBasic => Some(basic_auth(&oauth.client_id, secret)?),
            ClientAuthMethod::ClientSecretPost => {
                form.append_pair("client_id", &oauth.client_id);
                form.append_pair("client_secret", secret.expose());
                None
            }
        };
        Ok(Self {
            url,
            authorization,
            form: Bytes::from(form.finish()),
        })
    }

    /// Ask the endpoint, and read the answer.
    async fn send(&self, caches: &TokenCaches) -> Result<Token, FetchError> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(self.url.clone())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .body(UpstreamBody::Full(Full::new(self.form.clone())))
            .map_err(|_| FetchError::NotARequest)?;
        if let Some(authorization) = &self.authorization {
            req.headers_mut()
                .insert(AUTHORIZATION, authorization.clone());
        }

        let resp = caches
            .send(req)
            .await
            .map_err(|e| FetchError::Unreachable(e.to_string()))?;
        let status = resp.status();
        // Bounded: this is a response from outside the gateway, and
        // nothing here needs more than a small JSON object.
        let body = Limited::new(resp.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|_| FetchError::Body(status))?
            .to_bytes();

        if status != StatusCode::OK {
            // RFC 6749 §5.2 gives the failure a code from a fixed
            // vocabulary. That code is the diagnostic; the rest of
            // the response is not read, and nothing from the body is
            // logged beyond it.
            let code = serde_json::from_slice::<TokenErrorResponse>(&body)
                .ok()
                .map(|e| e.error);
            return Err(FetchError::Rejected { status, code });
        }
        // The parse error is not reported: what it would say about a
        // response holding an access token is not worth the chance of
        // quoting one. The status and the endpoint are enough to go
        // and look.
        let response: TokenResponse =
            serde_json::from_slice(&body).map_err(|_| FetchError::NotATokenResponse)?;
        Token::new(&response, Instant::now())
    }
}

/// The token endpoint's answer (RFC 6749 §5.1), as much of it as this
/// grant uses.
///
/// Deliberately not `Debug`: it holds the token.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    /// Seconds. Only recommended by the RFC, so absence is a case
    /// rather than an error; see [`DEFAULT_LIFETIME`].
    #[serde(default)]
    expires_in: Option<u64>,
}

/// The token endpoint's refusal (RFC 6749 §5.2). Only the code is
/// read.
#[derive(Deserialize)]
struct TokenErrorResponse {
    error: String,
}

/// Why a credential could not be turned into a token request. Every
/// one of these is a config problem, decided once per applied
/// credential rather than per request.
#[derive(Debug, thiserror::Error)]
enum BuildError {
    #[error("client secret is unresolved")]
    Unresolved,
    #[error("`{0}` is not a URL the gateway can dial")]
    TokenUrl(String),
    #[error("client id or secret cannot be sent in an Authorization header")]
    NotAHeaderValue,
}

/// Why one token fetch did not produce a token.
#[derive(Debug, thiserror::Error)]
enum FetchError {
    #[error("token endpoint is unreachable: {0}")]
    Unreachable(String),
    #[error("token endpoint did not answer within {}s", FETCH_TIMEOUT.as_secs())]
    Timeout,
    #[error("token endpoint answered {status}{}", .code.as_ref().map(|c| format!(": {c}")).unwrap_or_default())]
    Rejected {
        status: StatusCode,
        code: Option<String>,
    },
    #[error("token endpoint answered {0} with a body that could not be read")]
    Body(StatusCode),
    #[error("token endpoint answered with something that is not a token response")]
    NotATokenResponse,
    #[error("token endpoint answered with no access token")]
    NoToken,
    #[error("token endpoint answered with an access token that is not a header value")]
    NotAHeaderValue,
    #[error("token endpoint answered with token type `{0}`, which is not Bearer")]
    TokenType(String),
    #[error("token endpoint answered with a token that has already expired")]
    Expired,
    #[error("the token request could not be built")]
    NotARequest,
}

/// The `Authorization` header a client authenticating with HTTP Basic
/// sends (RFC 6749 §2.3.1).
///
/// The id and secret are form-urlencoded before they are joined and
/// encoded, which is what the RFC asks for and what a provider whose
/// client secret contains a `:` depends on. For the credentials most
/// providers issue the encoding changes nothing.
fn basic_auth(client_id: &str, secret: &ClientSecret) -> Result<HeaderValue, BuildError> {
    let encode = |s: &str| form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let credentials = format!("{}:{}", encode(client_id), encode(secret.expose()));
    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
    let mut value = HeaderValue::from_str(&format!("Basic {encoded}"))
        .map_err(|_| BuildError::NotAHeaderValue)?;
    value.set_sensitive(true);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_config::secret::{OpaqueSecret, SecretRef, SecretValue};
    use gateway_state::ActiveBackendAuth;

    /// Stands in for a client secret; no test may print it.
    const SECRET: &str = "cs-not-a-real-secret";

    /// A resolved `OAuth2` block, the way the store hands one over.
    fn oauth2(client_id: &str, method: ClientAuthMethod, scopes: &[&str]) -> ActiveOAuth2 {
        let secret = OpaqueSecret::new(
            "",
            "provider-creds",
            [("clientSecret".to_string(), SecretValue::new(SECRET))]
                .into_iter()
                .collect(),
        );
        let auth = gateway_config::backend::OAuth2Auth {
            token_url: "https://idp.example/oauth2/token".into(),
            client_id: client_id.into(),
            client_secret_ref: SecretRef::new("", "provider-creds", "clientSecret"),
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            client_auth_method: method,
        };
        match ActiveBackendAuth::resolve(
            &gateway_config::backend::BackendAuth::OAuth2(auth),
            Some(&Arc::new(secret)),
        ) {
            ActiveBackendAuth::OAuth2(o) => o,
            ActiveBackendAuth::ApiKey(_) => unreachable!("built as OAuth2"),
        }
    }

    fn response(token: &str, token_type: Option<&str>, expires_in: Option<u64>) -> TokenResponse {
        TokenResponse {
            access_token: token.into(),
            token_type: token_type.map(str::to_owned),
            expires_in,
        }
    }

    // ---- the request the endpoint is asked ----

    /// Basic is the default, and the RFC's encoding of it: the id and
    /// the secret, joined by a colon, base64 of the whole. Nothing
    /// about the client is in the body.
    #[test]
    fn client_secret_basic_sends_the_credentials_in_a_header() {
        let request =
            TokenRequest::build(&oauth2("gw", ClientAuthMethod::ClientSecretBasic, &[])).unwrap();
        let expected = base64::engine::general_purpose::STANDARD.encode(format!("gw:{SECRET}"));
        assert_eq!(
            request.authorization.as_ref().expect("a Basic header"),
            format!("Basic {expected}").as_str()
        );
        assert!(
            request.authorization.as_ref().unwrap().is_sensitive(),
            "the client secret must not reach a debug line or an HPACK index"
        );
        let form = String::from_utf8(request.form.to_vec()).unwrap();
        assert_eq!(form, "grant_type=client_credentials");
    }

    /// Post is the other half: the same credentials, in the body,
    /// and no header at all.
    #[test]
    fn client_secret_post_sends_the_credentials_in_the_body() {
        let request =
            TokenRequest::build(&oauth2("gw", ClientAuthMethod::ClientSecretPost, &[])).unwrap();
        assert!(request.authorization.is_none());
        let form = String::from_utf8(request.form.to_vec()).unwrap();
        assert_eq!(
            form,
            format!("grant_type=client_credentials&client_id=gw&client_secret={SECRET}")
        );
    }

    /// Scopes are one space-separated field, and absent when there
    /// are none — a provider that scopes by client identity is not
    /// asked for an empty scope.
    #[test]
    fn scopes_travel_as_one_space_separated_field() {
        let request = TokenRequest::build(&oauth2(
            "gw",
            ClientAuthMethod::ClientSecretBasic,
            &["read", "write"],
        ))
        .unwrap();
        let form = String::from_utf8(request.form.to_vec()).unwrap();
        assert_eq!(form, "grant_type=client_credentials&scope=read+write");
    }

    /// A secret with a colon in it would be ambiguous if it were not
    /// encoded first, and the RFC says to encode it.
    #[test]
    fn basic_credentials_are_form_encoded_before_they_are_joined() {
        let value = basic_auth("id:with:colons", &client_secret("s p:ace")).unwrap();
        let encoded = value.to_str().unwrap().strip_prefix("Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            "id%3Awith%3Acolons:s+p%3Aace"
        );
    }

    /// A client secret that never resolved is not a token request,
    /// and is told apart from one that could not be built: the first
    /// recovers when the secret lands.
    #[test]
    fn an_unresolved_client_secret_builds_no_request() {
        let mut oauth = oauth2("gw", ClientAuthMethod::ClientSecretBasic, &[]);
        oauth.client_secret = None;
        assert!(matches!(
            TokenRequest::build(&oauth),
            Err(BuildError::Unresolved)
        ));
    }

    #[test]
    fn a_token_url_that_is_not_a_url_builds_no_request() {
        let mut oauth = oauth2("gw", ClientAuthMethod::ClientSecretBasic, &[]);
        oauth.token_url = "not a url".into();
        assert!(matches!(
            TokenRequest::build(&oauth),
            Err(BuildError::TokenUrl(_))
        ));
    }

    // ---- the answer the endpoint gives ----

    #[test]
    fn a_token_becomes_the_bearer_header() {
        let now = Instant::now();
        let token = Token::new(&response("tok", Some("Bearer"), Some(3600)), now).unwrap();
        assert_eq!(token.value, "Bearer tok");
        assert!(
            token.value.is_sensitive(),
            "the token must not reach a debug line or an HPACK index"
        );
        assert_eq!(token.expires_at - now, Duration::from_hours(1));
        assert_eq!(
            token.stale_at - now,
            Duration::from_hours(1).saturating_sub(REFRESH_SKEW)
        );
    }

    /// Every provider spells it differently; all of them mean the
    /// same type.
    #[test]
    fn token_type_is_matched_case_insensitively_and_may_be_absent() {
        let now = Instant::now();
        assert!(Token::new(&response("tok", Some("bearer"), None), now).is_ok());
        assert!(Token::new(&response("tok", None, None), now).is_ok());
        assert!(matches!(
            Token::new(&response("tok", Some("mac"), None), now),
            Err(FetchError::TokenType(_))
        ));
    }

    /// A token shorter than the refresh window is still replaced
    /// before it expires, not after: the window shrinks to fit.
    #[test]
    fn a_short_lived_token_goes_stale_before_it_expires() {
        let now = Instant::now();
        let token = Token::new(&response("tok", None, Some(10)), now).unwrap();
        assert_eq!(token.stale_at - now, Duration::from_secs(5));
        assert!(token.stale_at < token.expires_at);
    }

    /// Two numbers from outside the gateway that it will not take at
    /// face value: none at all, and one that would pin a token
    /// forever.
    #[test]
    fn a_lifetime_is_defaulted_when_absent_and_capped_when_absurd() {
        let now = Instant::now();
        let defaulted = Token::new(&response("tok", None, None), now).unwrap();
        assert_eq!(defaulted.expires_at - now, DEFAULT_LIFETIME);

        let capped = Token::new(&response("tok", None, Some(u64::MAX)), now).unwrap();
        assert_eq!(capped.expires_at - now, MAX_LIFETIME);
    }

    /// An answer that carries nothing usable is refused rather than
    /// cached: a token that has already expired would be one fetch
    /// per request.
    #[test]
    fn an_unusable_answer_is_not_a_token() {
        let now = Instant::now();
        assert!(matches!(
            Token::new(&response("", None, Some(60)), now),
            Err(FetchError::NoToken)
        ));
        assert!(matches!(
            Token::new(&response("tok", None, Some(0)), now),
            Err(FetchError::Expired)
        ));
        assert!(matches!(
            Token::new(&response("tok\nInjected: x", None, Some(60)), now),
            Err(FetchError::NotAHeaderValue)
        ));
    }

    // ---- what the cache does between fetches ----

    fn state_with(lifetime: u64, now: Instant) -> State {
        State {
            token: Some(Token::new(&response("tok", None, Some(lifetime)), now).unwrap()),
            retry_at: None,
        }
    }

    #[test]
    fn a_token_is_fresh_then_stale_then_gone() {
        let now = Instant::now();
        let state = state_with(100, now);
        assert!(matches!(state.usable(now), Usable::Fresh(_)));
        assert!(matches!(
            state.usable(now + Duration::from_secs(71)),
            Usable::Stale(_)
        ));
        assert!(matches!(
            state.usable(now + Duration::from_secs(100)),
            Usable::None
        ));
    }

    /// A stale token whose refresh just failed is sent, not retried:
    /// it is still valid, and the endpoint has already said no once.
    #[test]
    fn a_stale_token_is_used_while_a_failed_refresh_backs_off() {
        let now = Instant::now();
        let mut cached = state_with(100, now);
        let expiring = now + Duration::from_secs(71);
        cached.retry_at = Some(expiring + Duration::from_secs(1));
        assert!(matches!(cached.usable(expiring), Usable::Fresh(_)));
        assert!(matches!(
            cached.usable(expiring + Duration::from_secs(2)),
            Usable::Stale(_)
        ));
    }

    #[test]
    fn no_token_is_never_usable() {
        assert!(matches!(
            State::default().usable(Instant::now()),
            Usable::None
        ));
    }

    // ---- which cache a backend gets ----

    fn backend(name: &str) -> BackendKey {
        BackendKey::new(name)
    }

    /// The invariant the whole scheme rests on: a cache belongs to
    /// one resolved credential. Two backends never share one, and one
    /// backend whose credential changed does not keep the old one.
    #[test]
    fn a_cache_belongs_to_one_credential() {
        let caches = TokenCaches::default();
        let gw = oauth2("gw", ClientAuthMethod::ClientSecretBasic, &[]);
        let other = oauth2("other", ClientAuthMethod::ClientSecretBasic, &[]);

        let cache = |key: &BackendKey, oauth: &ActiveOAuth2| {
            caches.cache_for(key, oauth).expect("a token cache")
        };
        let first = cache(&backend("a"), &gw);
        assert!(
            Arc::ptr_eq(&first, &cache(&backend("a"), &gw)),
            "the same backend under the same credential keeps its cache"
        );
        assert!(
            !Arc::ptr_eq(&first, &cache(&backend("b"), &gw)),
            "two backends never share a cache, however alike their credentials"
        );
        assert!(
            !Arc::ptr_eq(&first, &cache(&backend("a"), &other)),
            "a changed credential gets a new cache, not the old token"
        );
    }

    /// A credential that cannot be turned into a request answers from
    /// the entry, and says which of the two kinds of wrong it is.
    #[test]
    fn a_credential_that_builds_no_request_is_answered_from_the_cache() {
        let caches = TokenCaches::default();
        let mut oauth = oauth2("gw", ClientAuthMethod::ClientSecretBasic, &[]);
        oauth.client_secret = None;
        assert_eq!(
            caches.cache_for(&backend("a"), &oauth).err(),
            Some(TokenFailure::Unresolved)
        );

        let mut oauth = oauth2("gw", ClientAuthMethod::ClientSecretBasic, &[]);
        oauth.token_url = "not a url".into();
        assert_eq!(
            caches.cache_for(&backend("a"), &oauth).err(),
            Some(TokenFailure::Unavailable)
        );
    }

    fn client_secret(material: &str) -> ClientSecret {
        let secret = OpaqueSecret::new(
            "",
            "s",
            [("k".to_string(), SecretValue::new(material))]
                .into_iter()
                .collect(),
        );
        let auth = gateway_config::backend::OAuth2Auth {
            token_url: "https://idp.example/token".into(),
            client_id: "gw".into(),
            client_secret_ref: SecretRef::new("", "s", "k"),
            scopes: vec![],
            client_auth_method: ClientAuthMethod::ClientSecretBasic,
        };
        ActiveOAuth2::resolve(&auth, Some(&Arc::new(secret)))
            .client_secret
            .expect("resolved")
    }
}
