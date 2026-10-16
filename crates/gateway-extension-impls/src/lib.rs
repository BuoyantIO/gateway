//! Built-in extensions: the Gateway API core filters expressed on the
//! `Extension` trait. Header config is parsed once at builder
//! construction, so the hooks are infallible.

pub mod debug_log;
pub mod kinference;

use std::sync::Arc;

use bytes::Bytes;
use gateway_config::extension::{ConfigValue, from_value};
use gateway_config::filter::{HeaderOps, HeaderPair, RedirectConfig, RedirectPath, Scheme};
use gateway_extension::{
    Action, Cx, Error, Extension, ExtensionBuilder, ExtensionClass, LocalResponse, Registry,
    async_trait,
};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

/// Reserved class names for the built-ins — the wire contract with
/// the CP, which synthesizes objects of these classes for Gateway
/// API core filters.
pub const REQUEST_HEADER_MODIFIER: &str = "request_header_modifier";
pub const RESPONSE_HEADER_MODIFIER: &str = "response_header_modifier";
pub const REQUEST_REDIRECT: &str = "request_redirect";

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("invalid header name `{0}`")]
    InvalidHeaderName(String),
    #[error("invalid header value for `{0}`")]
    InvalidHeaderValue(String),
}

/// `HeaderOps` with names and values parsed up front. Invalid `remove`
/// names are dropped at parse time, matching the runtime's silent-skip
/// behavior for them.
pub struct ParsedHeaderOps {
    set: Vec<(HeaderName, HeaderValue)>,
    add: Vec<(HeaderName, HeaderValue)>,
    remove: Vec<HeaderName>,
}

impl ParsedHeaderOps {
    /// # Errors
    /// A `set` or `add` entry with an invalid name or value.
    pub fn parse(ops: &HeaderOps) -> Result<Self, FilterError> {
        Ok(Self {
            set: parse_pairs(&ops.set)?,
            add: parse_pairs(&ops.add)?,
            remove: ops
                .remove
                .iter()
                .filter_map(|name| HeaderName::try_from(name.as_str()).ok())
                .collect(),
        })
    }

    /// Applies set, then add, then remove.
    pub fn apply(&self, headers: &mut HeaderMap) {
        for (name, value) in &self.set {
            headers.insert(name.clone(), value.clone());
        }
        for (name, value) in &self.add {
            headers.append(name.clone(), value.clone());
        }
        for name in &self.remove {
            headers.remove(name);
        }
    }
}

fn parse_pairs(pairs: &[HeaderPair]) -> Result<Vec<(HeaderName, HeaderValue)>, FilterError> {
    pairs
        .iter()
        .map(|HeaderPair { name, value }| {
            let header_name = HeaderName::try_from(name.as_str())
                .map_err(|_| FilterError::InvalidHeaderName(name.clone()))?;
            let header_value = HeaderValue::try_from(value.as_str())
                .map_err(|_| FilterError::InvalidHeaderValue(name.clone()))?;
            Ok((header_name, header_value))
        })
        .collect()
}

/// Register the built-in classes under their reserved names.
///
/// # Panics
/// A reserved name is already taken — a startup configuration bug.
pub fn register_builtins(registry: &mut Registry) {
    registry
        .register(
            REQUEST_HEADER_MODIFIER,
            Arc::new(RequestHeaderModifierClass),
        )
        .expect("reserved class name");
    registry
        .register(
            RESPONSE_HEADER_MODIFIER,
            Arc::new(ResponseHeaderModifierClass),
        )
        .expect("reserved class name");
    registry
        .register(REQUEST_REDIRECT, Arc::new(RequestRedirectClass))
        .expect("reserved class name");
}

/// Build the authority (`host` or `host:port`), omitting the port for
/// the scheme's well-known value per the Gateway API spec.
pub fn authority(host: &str, scheme: &str, port: Option<u16>) -> String {
    let Some(p) = port else {
        return host.to_owned();
    };
    let well_known = (scheme == "http" && p == 80) || (scheme == "https" && p == 443);
    if well_known {
        host.to_owned()
    } else {
        format!("{host}:{p}")
    }
}

/// Replace the matched `PathPrefix` of `path` with `replacement`,
/// segment-aware: `/foo` + `/foo/bar` → `<replacement>/bar`; `/foo` +
/// `/foo` → `<replacement>`. Trailing slashes on the prefix and
/// replacement are trimmed first (per Gateway API).
pub fn replace_prefix(path: &str, matched_prefix: &str, replacement: &str) -> String {
    let matched = matched_prefix.trim_end_matches('/');
    let replacement = replacement.trim_end_matches('/');
    let rest = path.strip_prefix(matched).unwrap_or("");
    if rest.is_empty() {
        if replacement.is_empty() {
            "/".to_owned()
        } else {
            replacement.to_owned()
        }
    } else {
        // `rest` begins with '/', so this yields e.g. "/xyz" + "/bar".
        format!("{replacement}{rest}")
    }
}

/// `RequestHeaderModifier` as an extension class.
pub struct RequestHeaderModifierClass;

impl ExtensionClass for RequestHeaderModifierClass {
    fn configure(&self, config: &ConfigValue) -> Result<Arc<dyn ExtensionBuilder>, Error> {
        let ops: HeaderOps = from_value(config)?;
        Ok(Arc::new(RequestHeaderModifierBuilder::try_new(&ops)?))
    }
}

pub struct RequestHeaderModifierBuilder {
    ops: Arc<ParsedHeaderOps>,
}

impl RequestHeaderModifierBuilder {
    /// # Errors
    /// Invalid header name or value in `ops`.
    pub fn try_new(ops: &HeaderOps) -> Result<Self, FilterError> {
        Ok(Self {
            ops: Arc::new(ParsedHeaderOps::parse(ops)?),
        })
    }
}

impl ExtensionBuilder for RequestHeaderModifierBuilder {
    fn build(&self) -> Box<dyn Extension> {
        Box::new(RequestHeaderModifier {
            ops: Arc::clone(&self.ops),
        })
    }
}

struct RequestHeaderModifier {
    ops: Arc<ParsedHeaderOps>,
}

#[async_trait]
impl Extension for RequestHeaderModifier {
    async fn on_request_start(
        &mut self,
        head: &mut http::request::Parts,
        _cx: &mut Cx,
    ) -> Result<Action, Error> {
        self.ops.apply(&mut head.headers);
        Ok(Action::Continue)
    }
}

/// `ResponseHeaderModifier` as an extension class.
pub struct ResponseHeaderModifierClass;

impl ExtensionClass for ResponseHeaderModifierClass {
    fn configure(&self, config: &ConfigValue) -> Result<Arc<dyn ExtensionBuilder>, Error> {
        let ops: HeaderOps = from_value(config)?;
        Ok(Arc::new(ResponseHeaderModifierBuilder::try_new(&ops)?))
    }
}

pub struct ResponseHeaderModifierBuilder {
    ops: Arc<ParsedHeaderOps>,
}

impl ResponseHeaderModifierBuilder {
    /// # Errors
    /// Invalid header name or value in `ops`.
    pub fn try_new(ops: &HeaderOps) -> Result<Self, FilterError> {
        Ok(Self {
            ops: Arc::new(ParsedHeaderOps::parse(ops)?),
        })
    }
}

impl ExtensionBuilder for ResponseHeaderModifierBuilder {
    fn build(&self) -> Box<dyn Extension> {
        Box::new(ResponseHeaderModifier {
            ops: Arc::clone(&self.ops),
        })
    }
}

struct ResponseHeaderModifier {
    ops: Arc<ParsedHeaderOps>,
}

#[async_trait]
impl Extension for ResponseHeaderModifier {
    fn on_response_start(&mut self, head: &mut http::response::Parts, _cx: &mut Cx) {
        self.ops.apply(&mut head.headers);
    }
}

/// `RequestRedirect` as an extension class.
pub struct RequestRedirectClass;

impl ExtensionClass for RequestRedirectClass {
    fn configure(&self, config: &ConfigValue) -> Result<Arc<dyn ExtensionBuilder>, Error> {
        let redirect: RedirectConfig = from_value(config)?;
        Ok(Arc::new(RequestRedirectBuilder::new(redirect)))
    }
}

pub struct RequestRedirectBuilder {
    config: Arc<RedirectConfig>,
}

impl RequestRedirectBuilder {
    pub fn new(config: RedirectConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl ExtensionBuilder for RequestRedirectBuilder {
    fn build(&self) -> Box<dyn Extension> {
        Box::new(RequestRedirect {
            config: Arc::clone(&self.config),
        })
    }
}

struct RequestRedirect {
    config: Arc<RedirectConfig>,
}

#[async_trait]
impl Extension for RequestRedirect {
    async fn on_request_start(
        &mut self,
        head: &mut http::request::Parts,
        cx: &mut Cx,
    ) -> Result<Action, Error> {
        let cfg = &self.config;

        // Scheme: explicit config wins; else the request's own scheme
        // (present on h2), else plain http.
        let scheme = cfg
            .scheme
            .map(Scheme::as_str)
            .or_else(|| head.uri.scheme_str())
            .unwrap_or("http");

        // Host: explicit config wins; else the request host (already
        // port-stripped by the host).
        let host = cfg
            .hostname
            .clone()
            .or_else(|| cx.request_host().map(str::to_owned))
            .unwrap_or_default();

        // Path: full replace, prefix replace against the matched
        // prefix, or the request path unchanged.
        let orig_path = head.uri.path();
        let new_path = match &cfg.path {
            None => orig_path.to_owned(),
            Some(RedirectPath::ReplaceFullPath(p)) => p.clone(),
            Some(RedirectPath::ReplacePrefixMatch(replacement)) => {
                if let Some(prefix) = cx.matched_path_prefix() {
                    replace_prefix(orig_path, prefix, replacement)
                } else {
                    tracing::warn!(
                        "RequestRedirect ReplacePrefixMatch on a non-prefix route; \
                         leaving path unchanged"
                    );
                    orig_path.to_owned()
                }
            }
        };

        let mut location = format!("{scheme}://{}", authority(&host, scheme, cfg.port));
        location.push_str(&new_path);
        if let Some(q) = head.uri.query() {
            location.push('?');
            location.push_str(q);
        }

        let location = HeaderValue::try_from(location)
            .map_err(|_| FilterError::InvalidHeaderValue("location".to_owned()))?;
        let status = StatusCode::from_u16(cfg.status_code.code()).unwrap_or(StatusCode::FOUND);
        let mut headers = HeaderMap::new();
        headers.insert(http::header::LOCATION, location);
        Ok(Action::Respond(LocalResponse {
            status,
            headers,
            body: Bytes::new(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_config::filter::RedirectStatus;

    fn ops(set: &[(&str, &str)], add: &[(&str, &str)], remove: &[&str]) -> HeaderOps {
        HeaderOps {
            set: set
                .iter()
                .map(|(n, v)| HeaderPair {
                    name: (*n).to_owned(),
                    value: (*v).to_owned(),
                })
                .collect(),
            add: add
                .iter()
                .map(|(n, v)| HeaderPair {
                    name: (*n).to_owned(),
                    value: (*v).to_owned(),
                })
                .collect(),
            remove: remove.iter().map(|n| (*n).to_owned()).collect(),
        }
    }

    fn request_parts(uri: &str, headers: &[(&str, &str)]) -> http::request::Parts {
        let mut builder = http::Request::builder().uri(uri);
        for (n, v) in headers {
            builder = builder.header(*n, *v);
        }
        builder.body(()).expect("request").into_parts().0
    }

    fn response_parts(headers: &[(&str, &str)]) -> http::response::Parts {
        let mut builder = http::Response::builder();
        for (n, v) in headers {
            builder = builder.header(*n, *v);
        }
        builder.body(()).expect("response").into_parts().0
    }

    async fn run_redirect(
        builder: &RequestRedirectBuilder,
        uri: &str,
        req_host: Option<&str>,
        matched_prefix: Option<&str>,
    ) -> (StatusCode, String) {
        let mut parts = request_parts(uri, &[]);
        let mut cx = Cx::new();
        cx.set_request_host(req_host);
        cx.set_matched_path_prefix(matched_prefix);
        match builder
            .build()
            .on_request_start(&mut parts, &mut cx)
            .await
            .expect("redirect ok")
        {
            Action::Respond(resp) => {
                let location = resp
                    .headers
                    .get(http::header::LOCATION)
                    .expect("location")
                    .to_str()
                    .expect("utf8")
                    .to_owned();
                (resp.status, location)
            }
            Action::Continue => panic!("expected a redirect response"),
        }
    }

    #[tokio::test]
    async fn request_header_modifier_sets_adds_and_removes() {
        let builder = RequestHeaderModifierBuilder::try_new(&ops(
            &[("x-env", "prod")],
            &[("x-tag", "a"), ("x-tag", "b")],
            &["x-drop"],
        ))
        .expect("valid ops");
        let mut parts = request_parts("/", &[("x-env", "stale"), ("x-drop", "1")]);
        let mut cx = Cx::new();

        let action = builder
            .build()
            .on_request_start(&mut parts, &mut cx)
            .await
            .expect("ok");
        assert!(matches!(action, Action::Continue));
        assert_eq!(parts.headers.get("x-env").unwrap(), "prod");
        let tags: Vec<_> = parts.headers.get_all("x-tag").iter().collect();
        assert_eq!(tags.len(), 2);
        assert!(parts.headers.get("x-drop").is_none());
    }

    #[tokio::test]
    async fn response_header_modifier_applies_on_response_only() {
        let builder = ResponseHeaderModifierBuilder::try_new(&ops(
            &[("x-frame-options", "DENY")],
            &[("x-csp", "default-src 'self'")],
            &["x-server-version"],
        ))
        .expect("valid ops");
        let mut ext = builder.build();
        let mut cx = Cx::new();

        let mut req = request_parts("/", &[]);
        let action = ext.on_request_start(&mut req, &mut cx).await.expect("ok");
        assert!(matches!(action, Action::Continue));
        assert!(req.headers.get("x-csp").is_none());

        let mut resp = response_parts(&[
            ("x-frame-options", "SAMEORIGIN"),
            ("x-server-version", "9.9"),
        ]);
        ext.on_response_start(&mut resp, &mut cx);
        assert_eq!(resp.headers.get("x-frame-options").unwrap(), "DENY");
        assert!(resp.headers.get("x-csp").is_some());
        assert!(resp.headers.get("x-server-version").is_none());
    }

    #[tokio::test]
    async fn redirect_scheme_only_keeps_host_and_path() {
        let builder = RequestRedirectBuilder::new(RedirectConfig {
            scheme: Some(Scheme::Https),
            status_code: RedirectStatus::MovedPermanently,
            ..Default::default()
        });
        let (status, location) =
            run_redirect(&builder, "/foo/bar?x=1", Some("app.example"), None).await;
        assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(location, "https://app.example/foo/bar?x=1");
    }

    #[tokio::test]
    async fn redirect_omits_well_known_port() {
        let builder = RequestRedirectBuilder::new(RedirectConfig {
            scheme: Some(Scheme::Https),
            port: Some(443),
            ..Default::default()
        });
        let (_, location) = run_redirect(&builder, "/p", Some("h.example"), None).await;
        assert_eq!(location, "https://h.example/p");

        let builder = RequestRedirectBuilder::new(RedirectConfig {
            scheme: Some(Scheme::Https),
            port: Some(8443),
            ..Default::default()
        });
        let (_, location) = run_redirect(&builder, "/p", Some("h.example"), None).await;
        assert_eq!(location, "https://h.example:8443/p");
    }

    #[tokio::test]
    async fn redirect_replace_full_path() {
        let builder = RequestRedirectBuilder::new(RedirectConfig {
            path: Some(RedirectPath::ReplaceFullPath("/new".to_owned())),
            ..Default::default()
        });
        let (status, location) =
            run_redirect(&builder, "/old/thing", Some("h.example"), None).await;
        assert_eq!(status, StatusCode::FOUND);
        assert_eq!(location, "http://h.example/new");
    }

    #[tokio::test]
    async fn redirect_replace_prefix_match() {
        let builder = RequestRedirectBuilder::new(RedirectConfig {
            path: Some(RedirectPath::ReplacePrefixMatch("/new".to_owned())),
            ..Default::default()
        });
        let (_, location) =
            run_redirect(&builder, "/foo/bar", Some("h.example"), Some("/foo")).await;
        assert_eq!(location, "http://h.example/new/bar");

        let (_, location) = run_redirect(&builder, "/foo", Some("h.example"), Some("/foo")).await;
        assert_eq!(location, "http://h.example/new");
    }

    #[tokio::test]
    async fn redirect_prefix_match_without_prefix_keeps_path() {
        let builder = RequestRedirectBuilder::new(RedirectConfig {
            path: Some(RedirectPath::ReplacePrefixMatch("/new".to_owned())),
            ..Default::default()
        });
        let (_, location) = run_redirect(&builder, "/foo/bar", Some("h.example"), None).await;
        assert_eq!(location, "http://h.example/foo/bar");
    }

    #[test]
    fn replace_prefix_helper_cases() {
        assert_eq!(replace_prefix("/foo/bar", "/foo", "/xyz"), "/xyz/bar");
        assert_eq!(replace_prefix("/foo", "/foo", "/xyz"), "/xyz");
        assert_eq!(replace_prefix("/foo/", "/foo", "/xyz"), "/xyz/");
        assert_eq!(replace_prefix("/foo/bar", "/foo", "/"), "/bar");
        assert_eq!(replace_prefix("/foo", "/foo", "/"), "/");
    }

    #[test]
    fn parse_rejects_bad_names_and_values_but_skips_bad_removes() {
        assert!(matches!(
            ParsedHeaderOps::parse(&ops(&[("bad name", "v")], &[], &[])),
            Err(FilterError::InvalidHeaderName(_))
        ));
        assert!(matches!(
            ParsedHeaderOps::parse(&ops(&[("x-ok", "bad\nvalue")], &[], &[])),
            Err(FilterError::InvalidHeaderValue(_))
        ));
        let parsed = ParsedHeaderOps::parse(&ops(&[], &[], &["bad remove", "x-ok"]))
            .expect("bad removes are skipped");
        assert_eq!(parsed.remove.len(), 1);
    }
}
