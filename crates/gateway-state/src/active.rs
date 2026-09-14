use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use gateway_config::backend::{
    AlpnProtocol, ApiKeyAuth, BackendAuth, BackendOrigin, BackendProtocol, ClientAuthMethod,
    Endpoint, OAuth2Auth,
};
use gateway_config::bind::BindProtocol;
use gateway_config::extension::Extension;
use gateway_config::filter::HttpFilter;
use gateway_config::route::HttpMatch;
use gateway_config::secret::{OpaqueSecret, SecretRef, TlsSecret};
use http::{HeaderName, HeaderValue};

use crate::key::{BackendKey, BindKey, ExtensionKey, ListenerKey, RouteKey, SecretKey};

#[derive(Debug, Clone)]
pub struct ActiveBind {
    pub key: BindKey,
    pub address: IpAddr,
    pub port: u16,
    /// Protocol family the operator declared for this bind. The runtime
    /// dispatches the accept path on it (`Http` plaintext vs `Tls`
    /// termination).
    pub bind_protocol: BindProtocol,
    pub listeners: Vec<Arc<ActiveListener>>,
}

/// A listener with one or more active routes that serves HTTP — either
/// plaintext, or after terminating TLS (`tls.is_some()`). Route
/// selection happens per-request in the runtime by matching against
/// `ActiveHttpRoute::matches`. Active when at least one route is under
/// it (and, for TLS, its certificate secrets are present).
///
/// TLS passthrough is a different data path (no HTTP routes) and is not
/// represented here.
#[derive(Debug, Clone)]
pub struct ActiveListener {
    pub key: ListenerKey,
    /// Optional hostname filter for this listener. When set, the
    /// request's `:authority` (HTTP/2) or `Host` (HTTP/1.1) must
    /// match. `None` means catch-all.
    pub hostname: Option<String>,
    /// Active routes under this listener. Order is by route name
    /// (deterministic from the store's placement logic); the runtime
    /// is responsible for picking the longest-prefix path match.
    pub routes: Vec<Arc<ActiveHttpRoute>>,
    /// `Some` for an HTTPS (terminating) listener — the resolved
    /// certificate material the runtime builds a TLS server config
    /// from. `None` for plaintext HTTP.
    pub tls: Option<ActiveTls>,
}

/// Resolved TLS material for a terminating listener. Holds the parsed
/// secrets (cert chain + key as DER); the runtime turns these into a
/// `rustls::ServerConfig`.
#[derive(Debug, Clone)]
pub struct ActiveTls {
    pub secrets: Vec<Arc<TlsSecret>>,
}

#[derive(Debug, Clone)]
pub struct ActiveHttpRoute {
    pub key: RouteKey,
    pub revision: u64,
    pub matches: Vec<HttpMatch>,
    pub filters: Vec<HttpFilter>,
    pub backends: Vec<ActiveBackendRef>,
    /// One entry per `ExtensionRef` filter, in filter order.
    pub extensions: Vec<ActiveExtensionRef>,
}

/// One `ExtensionRef` of a route: the name from the filter, plus the
/// object it resolved to. `None` while the named `Extension` is not
/// registered — requests through this route answer 500.
#[derive(Debug, Clone)]
pub struct ActiveExtensionRef {
    pub key: ExtensionKey,
    pub object: Option<Arc<Extension>>,
}

#[derive(Debug, Clone)]
pub struct ActiveBackendRef {
    /// The backend this ref names, registered or not.
    pub key: BackendKey,
    /// `None` while the named backend is not registered — traffic
    /// destined to this ref is answered with a synthesized 500.
    pub backend: Option<Arc<ActiveBackend>>,
    pub weight: u32,
    pub origin: Option<Arc<BackendOrigin>>,
}

/// A registered backend. The key is common to both kinds; what it
/// takes to reach the backend is in [`ActiveBackendKind`].
#[derive(Debug, Clone)]
pub struct ActiveBackend {
    pub key: BackendKey,
    /// Monotonic stamp, fresh every time the resolved backend
    /// changes and *only* then: a re-applied backend that says the
    /// same thing keeps the revision it had. Anything the request
    /// path derives from a backend and caches (the upstream client
    /// and its connection pool) is valid for exactly one revision,
    /// which is what lets a control-plane resync re-send identical
    /// config without dropping upstream connections.
    pub revision: u64,
    pub kind: ActiveBackendKind,
}

impl ActiveBackend {
    /// The endpoints to balance over. Empty for a dialable backend,
    /// which names a host instead of a set of addresses: callers
    /// that can only route to an endpoint (the balanced pick, the
    /// by-address lookup, the target listing an extension sees) get
    /// nothing to choose from, which is the same answer they already
    /// give for an endpoint set with no ready members.
    pub fn endpoints(&self) -> &[Endpoint] {
        match &self.kind {
            ActiveBackendKind::Endpoints(e) => &e.endpoints,
            ActiveBackendKind::Dialable(_) => &[],
        }
    }

    /// Application protocol the gateway speaks to this backend. A
    /// dialable backend carries no protocol setting yet, so it takes
    /// the same `Http1` default an endpoint set does.
    pub fn protocol(&self) -> BackendProtocol {
        match &self.kind {
            ActiveBackendKind::Endpoints(e) => e.protocol,
            ActiveBackendKind::Dialable(_) => BackendProtocol::default(),
        }
    }
}

/// What the request path has to do to reach a backend: pick one of a
/// set of resolved endpoints, or dial a host.
///
/// `PartialEq` is the store's "did this actually change" test, and so
/// compares resolved material by value, down to the bytes of a CA
/// secret's certificates. It is an apply-time comparison; nothing on
/// the request path performs it.
#[derive(Debug, Clone, PartialEq)]
pub enum ActiveBackendKind {
    Endpoints(ActiveEndpointSet),
    Dialable(ActiveDialable),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActiveEndpointSet {
    pub endpoints: Vec<Endpoint>,
    /// Application protocol the gateway speaks to this backend
    /// (`Http1` default, `Http2` = h2c origination). Independent of
    /// the client-side protocol served downstream.
    pub protocol: BackendProtocol,
}

/// A host the gateway resolves and dials itself.
#[derive(Debug, Clone, PartialEq)]
pub struct ActiveDialable {
    pub host: String,
    pub port: u16,
    pub path_prefix: Option<String>,
    /// `Some` originates TLS to this host; `None` dials it in the
    /// clear.
    pub tls: Option<Arc<ActiveBackendTls>>,
    /// `Some` authenticates every request the gateway sends here,
    /// with its credential resolved against the registered secrets.
    pub auth: Option<Arc<ActiveBackendAuth>>,
}

/// A dialable backend's TLS settings, with its trust roots resolved
/// against the registered secrets.
///
/// Shared behind an `Arc` so the request path can hold on to the
/// settings its upstream client was built from without copying them
/// per request; whether that client is still current is the
/// backend's revision, not this pointer.
#[derive(Debug, Clone, PartialEq)]
pub struct ActiveBackendTls {
    pub roots: ActiveTrustRoots,
    pub sni: Option<String>,
    pub alpn: Vec<AlpnProtocol>,
    pub insecure_skip_verify: bool,
}

/// Where the trust roots for an upstream chain come from, resolved.
#[derive(Debug, Clone)]
pub enum ActiveTrustRoots {
    /// The platform trust store.
    System,
    /// The CA-only secret the backend names. `secret` is `None`
    /// while that secret is not registered: the request path fails
    /// the dial rather than falling back to the system store, since
    /// trusting more than the operator asked for is the one answer
    /// that must not happen.
    Secret {
        key: SecretKey,
        secret: Option<Arc<TlsSecret>>,
    },
}

// Hand-written because a `TlsSecret` is not comparable as a whole (it
// may carry a private key, which has no equality) and because
// identity is the wrong test: a resync re-sends the same certificates
// as a new object, and that must read as unchanged. Only the
// certificates matter to a trust decision, so only those are
// compared.
impl PartialEq for ActiveTrustRoots {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::System, Self::System) => true,
            (
                Self::Secret {
                    key: a,
                    secret: this,
                },
                Self::Secret {
                    key: b,
                    secret: that,
                },
            ) => {
                a == b
                    && match (this, that) {
                        (Some(this), Some(that)) => this.certs == that.certs,
                        (None, None) => true,
                        _ => false,
                    }
            }
            _ => false,
        }
    }
}

/// A dialable backend's credential, resolved against the registered
/// secrets.
///
/// One variant per scheme, mirroring `BackendAuth`, and both resolve
/// against the one secret the block names. What differs is how far
/// resolution gets: an API key is the whole credential and is shaped
/// into its header here, while a client secret is what the gateway
/// spends to obtain a credential, so resolving it settles that the
/// material is usable and leaves the token to the request path.
///
/// Shared behind an `Arc` for the same reason the TLS settings are:
/// the request path holds on to it without copying per request.
#[derive(Debug, Clone, PartialEq)]
pub enum ActiveBackendAuth {
    ApiKey(ActiveApiKey),
    OAuth2(ActiveOAuth2),
}

impl ActiveBackendAuth {
    /// Resolve `auth` against the secret registered under the
    /// reference it names, or leave it unresolved.
    pub fn resolve(auth: &BackendAuth, secret: Option<&Arc<OpaqueSecret>>) -> Self {
        match auth {
            BackendAuth::ApiKey(api_key) => Self::ApiKey(ActiveApiKey::resolve(api_key, secret)),
            BackendAuth::OAuth2(oauth) => Self::OAuth2(ActiveOAuth2::resolve(oauth, secret)),
        }
    }

    /// The same credential re-read after its secret arrived, rotated
    /// or went away. Everything the operator wrote carries over
    /// untouched; only what was read out of the secret is built
    /// again.
    #[must_use]
    pub fn re_resolve(&self, secret: Option<&Arc<OpaqueSecret>>) -> Self {
        match self {
            Self::ApiKey(api_key) => Self::ApiKey(api_key.re_resolve(secret)),
            Self::OAuth2(oauth) => Self::OAuth2(oauth.re_resolve(secret)),
        }
    }

    /// The secret this block spends, whichever scheme it is: what the
    /// dependency index follows and what a diagnostic names it by.
    pub fn secret(&self) -> &SecretRef {
        match self {
            Self::ApiKey(a) => &a.secret,
            Self::OAuth2(a) => &a.client_secret_ref,
        }
    }
}

/// A credential the operator provisioned, resolved against the
/// registered secrets and already shaped into the header that goes
/// upstream.
///
/// The header value is built here, at apply time, rather than per
/// request: what a credential has to be — text, valid in a header,
/// present at all — is a property of the secret the operator
/// provisioned, so it is settled once when the secret lands and not
/// re-litigated on every request.
///
/// `value` is `None` while the credential is unusable: the secret is
/// not registered yet, carries no such data key, or holds something
/// no header can express. The first recovers when the secret lands,
/// the others do not, but the request path treats all three the
/// same and fails the request rather than reaching the provider
/// unauthenticated — the one outcome that must not happen, since an
/// unauthenticated call is a call the provider answers differently
/// rather than one that visibly breaks.
#[derive(Clone, PartialEq)]
pub struct ActiveApiKey {
    /// The secret and data key the credential came from. Kept so
    /// re-resolution after a rotation reads the same reference the
    /// operator wrote, and so a failure names it.
    pub secret: SecretRef,
    /// Header the credential is sent in.
    pub header: HeaderName,
    /// Prefix the value was built with, kept for re-resolution.
    pub prefix: String,
    /// The complete header value, marked sensitive, or `None` when
    /// the credential did not resolve.
    pub value: Option<HeaderValue>,
}

impl ActiveApiKey {
    /// Build the upstream header for `auth` from the secret
    /// registered under its reference, or leave it unresolved.
    ///
    /// The three ways it can fail to resolve are told apart here
    /// because they are diagnosed differently, not because the
    /// request path distinguishes them; see [`credential_header`] for
    /// what the material has to be.
    pub fn resolve(auth: &ApiKeyAuth, secret: Option<&Arc<OpaqueSecret>>) -> Self {
        Self::build(&auth.secret_ref, &auth.header, &auth.prefix, secret)
    }

    /// The same credential re-read after a secret arrived, rotated or
    /// went away. The reference, the header and the prefix are the
    /// operator's and carry over untouched; only the value is built
    /// again.
    #[must_use]
    pub fn re_resolve(&self, secret: Option<&Arc<OpaqueSecret>>) -> Self {
        Self::build(&self.secret, &self.header, &self.prefix, secret)
    }

    fn build(
        secret_ref: &SecretRef,
        header: &HeaderName,
        prefix: &str,
        secret: Option<&Arc<OpaqueSecret>>,
    ) -> Self {
        let value = material(secret_ref, secret).and_then(|material| {
            let value = credential_header(prefix, material);
            if value.is_none() {
                // Empty, or bytes no header can carry. Never the
                // material itself, and never its length.
                tracing::warn!(
                    secret = %secret_ref,
                    "credential is empty or not valid in a header value"
                );
            }
            value
        });
        Self {
            secret: secret_ref.clone(),
            header: header.clone(),
            prefix: prefix.to_string(),
            value,
        }
    }
}

// Hand-written so nothing prints the credential: a `HeaderValue`
// decides that for itself, and this does not depend on it deciding
// the way we asked. Whether the credential resolved is diagnostic and
// is printed; the material never is.
impl fmt::Debug for ActiveApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActiveApiKey")
            // `namespace/name#key`, the form a warning names it by.
            .field("secret", &format_args!("{}", self.secret))
            .field("header", &self.header)
            .field("prefix", &self.prefix)
            // Whether the credential resolved is the diagnostic, and
            // is the most a reader gets; the material is not printed
            // in any form, not even its length.
            .field(
                "value",
                &self.value.as_ref().map_or("<unresolved>", |_| "<redacted>"),
            )
            .finish()
    }
}

/// An `OAuth2` client-credentials block, with the client secret
/// resolved against the registered secrets.
///
/// Resolution stops at the client secret. The credential that reaches
/// the provider is a token from the endpoint named here, which no
/// amount of applying config produces: it takes a call, it expires,
/// and it is therefore the request path's to hold. What this settles
/// is everything that call is made of, so that a token fetch is a
/// network question and never a config one.
///
/// Everything an operator wrote is carried verbatim, including the
/// token URL, which is parsed where it is dialed rather than here:
/// `validate` has already rejected one that is not absolute.
#[derive(Debug, Clone, PartialEq)]
pub struct ActiveOAuth2 {
    /// The token endpoint, as written.
    pub token_url: String,
    pub client_id: String,
    /// The secret and data key the client secret came from. Kept so
    /// re-resolution reads the same reference, and so a failure
    /// names it.
    pub client_secret_ref: SecretRef,
    pub scopes: Vec<String>,
    pub client_auth_method: ClientAuthMethod,
    /// The client secret, or `None` while it is unusable — the same
    /// three states an API key has, diagnosed the same way and
    /// answered the same way by the request path.
    pub client_secret: Option<ClientSecret>,
}

impl ActiveOAuth2 {
    pub fn resolve(auth: &OAuth2Auth, secret: Option<&Arc<OpaqueSecret>>) -> Self {
        Self {
            token_url: auth.token_url.clone(),
            client_id: auth.client_id.clone(),
            client_secret_ref: auth.client_secret_ref.clone(),
            scopes: auth.scopes.clone(),
            client_auth_method: auth.client_auth_method,
            client_secret: ClientSecret::build(&auth.client_secret_ref, secret),
        }
    }

    /// The same block with only its client secret re-read.
    #[must_use]
    pub fn re_resolve(&self, secret: Option<&Arc<OpaqueSecret>>) -> Self {
        Self {
            client_secret: ClientSecret::build(&self.client_secret_ref, secret),
            ..self.clone()
        }
    }
}

/// A client secret the gateway presents to a token endpoint: the
/// material, already established to be text a token request can
/// carry.
///
/// Both ways of presenting it — an HTTP Basic header and a form
/// field — are text, so a client secret that is not is unusable, and
/// that is decided once here rather than at every token fetch. The
/// material is reachable only through [`ClientSecret::expose`], and
/// `Debug` redacts, so a struct holding one is safe to
/// `derive(Debug)`.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientSecret(String);

impl ClientSecret {
    /// The material, for the one place that puts it on the wire.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Read the client secret out of `secret`, or decide it is
    /// unusable.
    ///
    /// Trimmed of surrounding whitespace for the same reason an API
    /// key is: a Secret written from a file carries the newline the
    /// file ended with, which is not part of the credential.
    fn build(secret_ref: &SecretRef, secret: Option<&Arc<OpaqueSecret>>) -> Option<Self> {
        let material = material(secret_ref, secret)?;
        let Some(text) = std::str::from_utf8(material).ok().map(str::trim) else {
            // Never the material itself, and never its length.
            tracing::warn!(
                secret = %secret_ref,
                "client secret is not text and cannot be sent to a token endpoint"
            );
            return None;
        };
        if text.is_empty() {
            tracing::warn!(secret = %secret_ref, "client secret is empty");
            return None;
        }
        Some(Self(text.to_owned()))
    }
}

impl fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The material one credential reference names, or `None` when it is
/// not there to be read.
///
/// The two ways that happens are told apart here because they are
/// diagnosed differently, not because any caller distinguishes them:
/// a secret that has not been registered is an ordering fact that
/// resolves itself when it lands, and a data key the operator never
/// set is a typo that will not.
fn material<'a>(secret_ref: &SecretRef, secret: Option<&'a Arc<OpaqueSecret>>) -> Option<&'a [u8]> {
    // Not registered yet. Silent: the reference recovers when the
    // secret lands, exactly as an unresolved backend ref does, and
    // saying so on every apply would be noise.
    let secret = secret?;
    let Some(value) = secret.get(&secret_ref.key) else {
        // A data key the operator never set. The key names are not
        // material, so listing them is what makes the typo findable.
        tracing::warn!(
            secret = %secret_ref,
            keys = ?secret.keys().collect::<Vec<_>>(),
            "credential secret carries no such data key"
        );
        return None;
    };
    Some(value.expose())
}

/// The header value a credential goes upstream in: the configured
/// prefix, then the material.
///
/// The material is trimmed of surrounding ASCII whitespace first,
/// because a Secret written with `--from-file` or a heredoc carries a
/// trailing newline that is not part of the credential and that no
/// header may hold.
/// What is left has to be non-empty and legal in a header value, or
/// there is no credential here.
///
/// The value is marked sensitive, which keeps it out of `HeaderValue`
/// debug output and, on HTTP/2, out of the HPACK index the connection
/// shares with every other request on it.
fn credential_header(prefix: &str, material: &[u8]) -> Option<HeaderValue> {
    let material = material.trim_ascii();
    if material.is_empty() {
        return None;
    }
    let mut bytes = Vec::with_capacity(prefix.len() + material.len());
    bytes.extend_from_slice(prefix.as_bytes());
    bytes.extend_from_slice(material);
    let mut value = HeaderValue::from_bytes(&bytes).ok()?;
    value.set_sensitive(true);
    Some(value)
}
