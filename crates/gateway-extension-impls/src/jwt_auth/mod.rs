//! The `jwt_auth` extension: bearer-token authentication against an
//! OIDC issuer's signing keys, attached per route.
//!
//! The token is read from `Authorization: Bearer <jwt>`, or from
//! `X-Api-Key` when there is no `Authorization` header (the header
//! Anthropic's SDKs send their key in). It must be an RS256 JWT signed
//! by a key the issuer publishes at `jwksUrl`, from the configured
//! `issuer`, for the configured `audience`, unexpired, and with
//! `email_verified: true`; `token` has the rules and `jwks` the key
//! cache. Nothing here is specific to Dex.
//!
//! A token that passes ends as an [`Identity`] in the request head's
//! `extensions` (the tenant from `tenantClaim`, `email` by default,
//! and `sub`), which a selector on the rule reads: the kinference
//! selector picks for that tenant. The header the token came from is
//! removed, so no upstream ever sees the caller's credential.
//!
//! Anything else is answered here and never forwarded: 401 with a
//! `WWW-Authenticate: Bearer` challenge naming a short reason, or 503
//! when the issuer's keys have never been fetched and the gateway
//! cannot tell a good token from a bad one. The hook never returns an
//! error, so no token problem becomes a 500 and `failureMode: Open`
//! cannot let one through.
//!
//! The token is never logged, put in a response, or held by a type
//! that formats it. Rejections log their reason, and `sub` and `email`
//! once the signature has verified; before that the claims are
//! whatever the caller wrote.

mod jwks;
mod token;

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use gateway_config::extension::{ConfigValue, from_value};
use gateway_extension::{
    Action, Cx, Error, Extension, ExtensionBuilder, ExtensionClass, Identity, LocalResponse,
    async_trait,
};
use http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use serde::Deserialize;

use jwks::{Keys, Lookup};
use token::{Reject, Settings, Unverified};

/// The class name `Extension` objects name.
pub const JWT_AUTH: &str = "jwt_auth";

/// Log target: filter on `extension::jwt_auth`.
const LOG: &str = "extension::jwt_auth";

/// The fallback header a token is read from.
const X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");

/// A token is a few kilobytes; anything past this is not one.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// The object's opaque config.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    /// Must equal the token's `iss` exactly: the issuer's public URL,
    /// which need not be the URL the keys are fetched from.
    issuer: String,
    /// Must be the token's `aud`, or one of them.
    audience: String,
    /// Where the issuer publishes its signing keys, http or https.
    jwks_url: String,
    /// The claim the tenant is read from.
    #[serde(default = "default_tenant_claim")]
    tenant_claim: String,
    #[serde(default = "default_require_email_verified")]
    require_email_verified: bool,
}

fn default_tenant_claim() -> String {
    "email".to_owned()
}

fn default_require_email_verified() -> bool {
    true
}

/// `jwt_auth` as an extension class.
pub struct JwtAuthClass;

impl ExtensionClass for JwtAuthClass {
    fn configure(&self, config: &ConfigValue) -> Result<Arc<dyn ExtensionBuilder>, Error> {
        let cfg: Config = from_value(config)?;
        Ok(Arc::new(JwtAuthBuilder::try_new(cfg)?))
    }
}

struct JwtAuthBuilder {
    prepared: Arc<Prepared>,
}

/// Everything `configure` prepared, shared by every instance.
struct Prepared {
    settings: Settings,
    keys: Keys,
}

impl JwtAuthBuilder {
    fn try_new(cfg: Config) -> Result<Self, Error> {
        if cfg.issuer.is_empty() {
            return Err("`issuer` must not be empty".into());
        }
        if cfg.audience.is_empty() {
            return Err("`audience` must not be empty".into());
        }
        // The name is echoed in a reason, and so in a header value.
        if cfg.tenant_claim.is_empty()
            || !cfg
                .tenant_claim
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
        {
            return Err(format!("`tenantClaim` `{}` is not a claim name", cfg.tenant_claim).into());
        }
        let url: Uri = cfg
            .jwks_url
            .parse()
            .map_err(|e| format!("`jwksUrl` is not a URL: {e}"))?;
        if url.host().is_none() {
            return Err("`jwksUrl` must be an absolute URL".into());
        }
        let keys = Keys::new(url)?;
        tracing::info!(target: LOG,
            issuer = %cfg.issuer,
            audience = %cfg.audience,
            jwks_url = %cfg.jwks_url,
            tenant_claim = %cfg.tenant_claim,
            require_email_verified = cfg.require_email_verified,
            "jwt_auth configured"
        );
        let prepared = Arc::new(Prepared {
            settings: Settings {
                issuer: cfg.issuer,
                audience: cfg.audience,
                tenant_claim: cfg.tenant_claim,
                require_email_verified: cfg.require_email_verified,
            },
            keys,
        });
        // Fetch the keys before the first request needs them. Off a
        // runtime (unit tests) the first request fetches instead.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let prepared = Arc::clone(&prepared);
            runtime.spawn(async move { prepared.keys.prefetch(Instant::now()).await });
        }
        Ok(Self { prepared })
    }
}

impl ExtensionBuilder for JwtAuthBuilder {
    fn build(&self) -> Box<dyn Extension> {
        Box::new(JwtAuth {
            prepared: Arc::clone(&self.prepared),
        })
    }
}

struct JwtAuth {
    prepared: Arc<Prepared>,
}

#[async_trait]
impl Extension for JwtAuth {
    async fn on_request_start(
        &mut self,
        head: &mut http::request::Parts,
        _cx: &mut Cx,
    ) -> Result<Action, Error> {
        Ok(match self.authenticate(&head.headers).await {
            Ok((identity, source)) => {
                tracing::debug!(target: LOG,
                    sub = %identity.subject,
                    tenant = %identity.tenant,
                    "jwt_auth: authenticated"
                );
                head.headers.remove(source);
                head.extensions.insert(identity);
                Action::Continue
            }
            Err(Denied::Unauthorized(reason)) => Action::Respond(unauthorized(reason.as_ref())),
            Err(Denied::Unavailable) => Action::Respond(keys_unavailable()),
        })
    }
}

/// Why a request was turned away.
enum Denied {
    /// A token problem: `None` when there was no token at all.
    Unauthorized(Option<Reject>),
    /// The issuer's keys have never been fetched.
    Unavailable,
}

impl JwtAuth {
    /// The caller's identity, and the header the token came from.
    async fn authenticate(&self, headers: &HeaderMap) -> Result<(Identity, HeaderName), Denied> {
        let (token, source) = match read_token(headers) {
            Ok(Some(found)) => found,
            Ok(None) => {
                tracing::info!(target: LOG, reason = "missing token", "jwt_auth: rejected");
                return Err(Denied::Unauthorized(None));
            }
            Err(reason) => return Err(reject_unverified(reason, &source_name(headers))),
        };
        let unverified =
            Unverified::parse(token).map_err(|r| reject_unverified(r, source.as_str()))?;
        let key = match self
            .prepared
            .keys
            .key(unverified.kid(), Instant::now())
            .await
        {
            Lookup::Found(key) => key,
            Lookup::Unknown => {
                tracing::info!(target: LOG,
                    reason = %Reject::UnknownKey,
                    kid = %truncated(unverified.kid()),
                    "jwt_auth: rejected"
                );
                return Err(Denied::Unauthorized(Some(Reject::UnknownKey)));
            }
            Lookup::Unavailable => {
                tracing::warn!(target: LOG,
                    "jwt_auth: no signing keys from the issuer; answering 503"
                );
                return Err(Denied::Unavailable);
            }
        };
        let claims = unverified
            .verify(&key)
            .map_err(|r| reject_unverified(r, source.as_str()))?;
        let caller = claims
            .validate(&self.prepared.settings, unix_now())
            .map_err(|reason| {
                tracing::info!(target: LOG,
                    reason = %reason,
                    sub = %claims.string("sub"),
                    email = %claims.string("email"),
                    "jwt_auth: rejected"
                );
                Denied::Unauthorized(Some(reason))
            })?;
        Ok((
            Identity {
                tenant: caller.tenant,
                subject: caller.subject,
            },
            source,
        ))
    }
}

/// Log a rejection made before the signature verified: the reason
/// only, since nothing in the token can be trusted yet.
fn reject_unverified(reason: Reject, source: &str) -> Denied {
    tracing::info!(target: LOG, reason = %reason, header = source, "jwt_auth: rejected");
    Denied::Unauthorized(Some(reason))
}

/// The token and the header it came from. `Ok(None)` when neither
/// header is present. An `Authorization` header that is not a bearer
/// token is refused outright rather than falling back: the caller
/// presented a credential, just not one this accepts.
fn read_token(headers: &HeaderMap) -> Result<Option<(&str, HeaderName)>, Reject> {
    let (value, source) = if let Some(v) = headers.get(AUTHORIZATION) {
        let v = v.to_str().map_err(|_| Reject::Malformed)?;
        let (scheme, token) = v.split_once(' ').ok_or(Reject::Malformed)?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(Reject::Malformed);
        }
        (token, AUTHORIZATION)
    } else if let Some(v) = headers.get(X_API_KEY) {
        (v.to_str().map_err(|_| Reject::Malformed)?, X_API_KEY)
    } else {
        return Ok(None);
    };
    let token = value.trim();
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(Reject::Malformed);
    }
    Ok(Some((token, source)))
}

/// Which header a token would have come from, for a log line.
fn source_name(headers: &HeaderMap) -> String {
    if headers.contains_key(AUTHORIZATION) {
        AUTHORIZATION.to_string()
    } else {
        X_API_KEY.to_string()
    }
}

/// 401 with an RFC 6750 challenge. A request with no token gets no
/// error code; a token that was presented and failed gets
/// `invalid_token`. The reason is fixed text, safe in a header.
fn unauthorized(reason: Option<&Reject>) -> LocalResponse {
    let (challenge, body) = match reason {
        None => (
            r#"Bearer error_description="missing token""#.to_owned(),
            "missing token\n".to_owned(),
        ),
        Some(reason) => (
            format!(r#"Bearer error="invalid_token", error_description="{reason}""#),
            format!("invalid token: {reason}\n"),
        ),
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        WWW_AUTHENTICATE,
        HeaderValue::try_from(challenge)
            .unwrap_or_else(|_| HeaderValue::from_static(r#"Bearer error="invalid_token""#)),
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    LocalResponse {
        status: StatusCode::UNAUTHORIZED,
        headers,
        body: Bytes::from(body),
    }
}

/// 503: no keys to check a token against. Not a 401, which would tell
/// a caller with a good token that the token is the problem.
fn keys_unavailable() -> LocalResponse {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    headers.insert(http::header::RETRY_AFTER, HeaderValue::from_static("5"));
    LocalResponse {
        status: StatusCode::SERVICE_UNAVAILABLE,
        headers,
        body: Bytes::from_static(b"token signing keys unavailable\n"),
    }
}

/// An untrusted `kid`, cut short for a log field.
fn truncated(kid: &str) -> &str {
    let end = kid.char_indices().nth(64).map_or(kid.len(), |(i, _)| i);
    &kid[..end]
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use serde_json::json;

    use jwks::tests::FakeIssuer;
    use token::tests::{AUDIENCE, ISSUER, TestKey, good_claims};

    /// A configured instance against `issuer`'s keys.
    fn auth_for(issuer: &FakeIssuer) -> Box<dyn Extension> {
        let config = serde_yaml::to_value(json!({
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwksUrl": issuer.url.to_string(),
        }))
        .unwrap();
        JwtAuthClass
            .configure(&config)
            .expect("valid config")
            .build()
    }

    /// Claims valid now, by the wall clock the hook reads.
    fn live_claims() -> serde_json::Value {
        let now = unix_now();
        let mut claims = good_claims();
        claims["exp"] = json!(now + 3600.0);
        claims["iat"] = json!(now - 10.0);
        claims
    }

    fn request(headers: &[(&str, &str)]) -> http::request::Parts {
        let mut builder = http::Request::builder().uri("/v1/messages");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    async fn run(ext: &mut Box<dyn Extension>, head: &mut http::request::Parts) -> Action {
        ext.on_request_start(head, &mut Cx::new())
            .await
            .expect("the hook never errors")
    }

    fn rejected(action: Action) -> LocalResponse {
        match action {
            Action::Respond(resp) => resp,
            Action::Continue => panic!("expected a local response"),
        }
    }

    fn challenge(resp: &LocalResponse) -> &str {
        resp.headers[WWW_AUTHENTICATE].to_str().unwrap()
    }

    #[tokio::test]
    async fn a_valid_bearer_token_passes_and_yields_the_email() {
        let key = TestKey::a();
        let issuer = FakeIssuer::serving(&[&key]).await;
        let mut ext = auth_for(&issuer);
        let token = key.sign(&live_claims());
        let mut head = request(&[
            ("authorization", &format!("Bearer {token}")),
            ("anthropic-version", "2023-06-01"),
        ]);

        assert!(matches!(run(&mut ext, &mut head).await, Action::Continue));
        let identity = head.extensions.get::<Identity>().expect("an identity");
        assert_eq!(identity.tenant, "alice@example.com");
        assert!(identity.subject.starts_with("CiQ"));
        // The credential stops here; everything else goes on.
        assert!(head.headers.get(AUTHORIZATION).is_none());
        assert_eq!(head.headers["anthropic-version"], "2023-06-01");
    }

    #[tokio::test]
    async fn the_scheme_is_case_insensitive() {
        let key = TestKey::a();
        let issuer = FakeIssuer::serving(&[&key]).await;
        let mut ext = auth_for(&issuer);
        let token = key.sign(&live_claims());
        let mut head = request(&[("authorization", &format!("bearer {token}"))]);
        assert!(matches!(run(&mut ext, &mut head).await, Action::Continue));
    }

    #[tokio::test]
    async fn x_api_key_is_the_fallback() {
        let key = TestKey::a();
        let issuer = FakeIssuer::serving(&[&key]).await;
        let mut ext = auth_for(&issuer);
        let token = key.sign(&live_claims());
        let mut head = request(&[("x-api-key", &token)]);

        assert!(matches!(run(&mut ext, &mut head).await, Action::Continue));
        assert_eq!(
            head.extensions.get::<Identity>().unwrap().tenant,
            "alice@example.com"
        );
        assert!(head.headers.get(X_API_KEY).is_none(), "stripped");
    }

    /// No credential at all: a challenge with no error code.
    #[tokio::test]
    async fn a_missing_token_is_challenged_without_an_error_code() {
        let issuer = FakeIssuer::serving(&[&TestKey::a()]).await;
        let mut ext = auth_for(&issuer);
        let resp = rejected(run(&mut ext, &mut request(&[])).await);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            challenge(&resp),
            r#"Bearer error_description="missing token""#
        );
        assert_eq!(issuer.hits(), 0, "no token, no key fetch");
    }

    /// Every way a presented token fails is a 401 with
    /// `invalid_token`, never a 403 or a 500, and nothing is
    /// forwarded.
    #[tokio::test]
    async fn bad_tokens_are_401_invalid_token() {
        let (a, b) = (TestKey::a(), TestKey::b());
        let issuer = FakeIssuer::serving(&[&a]).await;
        let mut ext = auth_for(&issuer);
        let now = unix_now();
        let with = |field: &str, value: serde_json::Value| {
            let mut claims = live_claims();
            claims[field] = value;
            claims
        };
        let tampered = {
            let token = a.sign(&live_claims());
            let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
            parts[1] = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                with("email", json!("mallory@example.com")).to_string(),
            );
            parts.join(".")
        };
        let none = format!(
            "{}.{}.",
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                json!({ "alg": "none", "kid": a.kid }).to_string()
            ),
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                live_claims().to_string()
            ),
        );
        let cases = [
            (a.sign(&with("exp", json!(now - 3600.0))), "expired"),
            (
                a.sign(&with("iss", json!("https://evil.example.com"))),
                "wrong issuer",
            ),
            (
                a.sign(&with("aud", json!("someone-else"))),
                "wrong audience",
            ),
            (
                a.sign(&with("email_verified", json!(false))),
                "email not verified",
            ),
            (tampered, "bad signature"),
            (none, "unsupported algorithm"),
            ("garbage".to_owned(), "malformed token"),
        ];
        for (token, reason) in cases {
            let resp = rejected(
                run(
                    &mut ext,
                    &mut request(&[("authorization", &format!("Bearer {token}"))]),
                )
                .await,
            );
            assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{reason}");
            assert_eq!(
                challenge(&resp),
                format!(r#"Bearer error="invalid_token", error_description="{reason}""#)
            );
            assert_eq!(resp.body, format!("invalid token: {reason}\n"));
        }

        // Signed by a key the issuer never published.
        let resp = rejected(
            run(
                &mut ext,
                &mut request(&[(
                    "authorization",
                    &format!("Bearer {}", b.sign(&live_claims())),
                )]),
            )
            .await,
        );
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
        assert!(challenge(&resp).contains("unknown signing key"));
    }

    #[tokio::test]
    async fn a_non_bearer_authorization_is_refused_without_fallback() {
        let key = TestKey::a();
        let issuer = FakeIssuer::serving(&[&key]).await;
        let mut ext = auth_for(&issuer);
        // A valid token in x-api-key does not rescue a Basic header.
        let token = key.sign(&live_claims());
        let resp = rejected(
            run(
                &mut ext,
                &mut request(&[
                    ("authorization", "Basic YWxpY2U6c2VjcmV0"),
                    ("x-api-key", &token),
                ]),
            )
            .await,
        );
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
        assert!(challenge(&resp).contains("invalid_token"));
    }

    /// The identity is the token's, whatever was on the head before.
    #[tokio::test]
    async fn an_earlier_identity_is_replaced() {
        let key = TestKey::a();
        let issuer = FakeIssuer::serving(&[&key]).await;
        let mut ext = auth_for(&issuer);
        let token = key.sign(&live_claims());
        let mut head = request(&[("authorization", &format!("Bearer {token}"))]);
        head.extensions.insert(Identity {
            tenant: "mallory@example.com".into(),
            subject: "forged".into(),
        });
        assert!(matches!(run(&mut ext, &mut head).await, Action::Continue));
        assert_eq!(
            head.extensions.get::<Identity>().unwrap().tenant,
            "alice@example.com"
        );
    }

    #[tokio::test]
    async fn no_keys_at_all_is_503_not_401() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/keys", listener.local_addr().unwrap());
        drop(listener);
        let config = serde_yaml::to_value(json!({
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwksUrl": url,
        }))
        .unwrap();
        let mut ext = JwtAuthClass.configure(&config).unwrap().build();
        // Let the background prefetch fail first.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let token = TestKey::a().sign(&live_claims());
        let resp = rejected(
            run(
                &mut ext,
                &mut request(&[("authorization", &format!("Bearer {token}"))]),
            )
            .await,
        );
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers.get(WWW_AUTHENTICATE).is_none());
    }

    /// Nothing a response carries comes from the token.
    #[tokio::test]
    async fn the_token_never_appears_in_a_response() {
        let key = TestKey::a();
        let issuer = FakeIssuer::serving(&[&key]).await;
        let mut ext = auth_for(&issuer);
        let token = key.sign(&json!({ "iss": ISSUER, "aud": "nope", "exp": 0 }));
        let resp = rejected(
            run(
                &mut ext,
                &mut request(&[("authorization", &format!("Bearer {token}"))]),
            )
            .await,
        );
        let shown = format!("{:?} {:?}", resp.headers, resp.body);
        for part in token.split('.') {
            assert!(!shown.contains(part), "{shown}");
        }
    }

    #[test]
    fn config_is_validated() {
        let parse =
            |v: serde_json::Value| JwtAuthClass.configure(&serde_yaml::to_value(v).unwrap());
        let base = json!({ "issuer": ISSUER, "audience": AUDIENCE, "jwksUrl": "http://dex.dex.svc:5556/dex/keys" });
        assert!(parse(base.clone()).is_ok());
        let mut https = base.clone();
        https["jwksUrl"] = json!("https://llm.example.com/dex/keys");
        assert!(parse(https).is_ok());
        for (field, value) in [
            ("issuer", json!("")),
            ("audience", json!("")),
            ("jwksUrl", json!("/dex/keys")),
            ("jwksUrl", json!("ftp://dex/keys")),
            ("tenantClaim", json!("bad\"claim")),
            ("typo", json!(1)),
        ] {
            let mut cfg = base.clone();
            cfg[field] = value;
            assert!(parse(cfg).is_err(), "{field}");
        }
        let mut missing = base;
        missing.as_object_mut().unwrap().remove("audience");
        assert!(parse(missing).is_err());
    }
}
