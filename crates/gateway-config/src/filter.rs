use serde::{Deserialize, Serialize};

/// One config carrier: every filter a route applies is a ref to an
/// `Extension` object, built-in classes included.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
pub enum HttpFilter {
    /// Runs the extension registered under `name`. `name` is also the
    /// filter's identity within the rule, so a rule references a
    /// given extension at most once.
    #[serde(rename_all = "camelCase")]
    ExtensionRef {
        name: String,
        /// Empty for a flat local config, which has no namespaces.
        #[serde(default)]
        namespace: String,
    },
}

/// A redirect's settings — the `request_redirect` class's config
/// type, shared with the CP that serializes it so the two cannot
/// drift.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectConfig {
    #[serde(default)]
    pub scheme: Option<Scheme>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    /// Gateway API defaults this to 302; the default lives on
    /// [`RedirectStatus`], not here.
    #[serde(default)]
    pub status_code: RedirectStatus,
    #[serde(default)]
    pub path: Option<RedirectPath>,
}

/// The scheme a redirect's `Location` uses. Gateway API restricts
/// this to `http` or `https`; an unset scheme keeps the request's
/// scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// HTTP status for a redirect. Gateway API restricts this to 301 or
/// 302 and defaults it to 302, both encoded here rather than in the
/// deserialization or conversion layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub enum RedirectStatus {
    /// 302 Found — the Gateway API default.
    #[default]
    Found,
    /// 301 Moved Permanently.
    MovedPermanently,
}

impl RedirectStatus {
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Self::Found => 302,
            Self::MovedPermanently => 301,
        }
    }
}

impl From<RedirectStatus> for u16 {
    fn from(status: RedirectStatus) -> Self {
        status.code()
    }
}

impl TryFrom<u16> for RedirectStatus {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            301 => Ok(Self::MovedPermanently),
            302 => Ok(Self::Found),
            other => Err(format!(
                "redirect statusCode must be 301 or 302, got {other}"
            )),
        }
    }
}

/// Path modifier for a [`RedirectConfig`]. At most one form applies
/// per redirect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RedirectPath {
    /// Replace the entire request path with this value.
    ReplaceFullPath(String),
    /// Replace the portion of the path that matched the route's
    /// `PathPrefix` with this value.
    ReplacePrefixMatch(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
pub enum TlsFilter {
    TlsClientHelloLog { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
pub enum TcpFilter {
    TcpConnectionLog { name: String },
}

/// The `request_header_modifier` / `response_header_modifier`
/// classes' config type, shared with the CP that serializes it so
/// the two cannot drift.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderOps {
    #[serde(default)]
    pub add: Vec<HeaderPair>,
    #[serde(default)]
    pub set: Vec<HeaderPair>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

impl HttpFilter {
    pub fn name(&self) -> &str {
        match self {
            Self::ExtensionRef { name, .. } => name,
        }
    }
}

impl TlsFilter {
    pub fn name(&self) -> &str {
        match self {
            Self::TlsClientHelloLog { name } => name,
        }
    }
}

impl TcpFilter {
    pub fn name(&self) -> &str {
        match self {
            Self::TcpConnectionLog { name } => name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_config_deserializes() {
        // `path` uses serde_yaml's enum tag — the same form
        // `to_string` emits when the CP serializes a synthesized
        // object's config.
        let yaml = "
scheme: https
statusCode: 301
path: !replacePrefixMatch /new
";
        let redirect: RedirectConfig = serde_yaml::from_str(yaml).expect("valid redirect config");
        assert_eq!(redirect.scheme, Some(Scheme::Https));
        assert_eq!(redirect.hostname, None);
        assert_eq!(redirect.port, None);
        assert_eq!(redirect.status_code, RedirectStatus::MovedPermanently);
        assert_eq!(
            redirect.path,
            Some(RedirectPath::ReplacePrefixMatch("/new".into()))
        );
    }

    #[test]
    fn redirect_config_status_defaults_to_302() {
        let redirect: RedirectConfig = serde_yaml::from_str("scheme: https").expect("valid");
        assert_eq!(redirect.status_code, RedirectStatus::Found);
        assert_eq!(redirect.status_code.code(), 302);
    }

    #[test]
    fn redirect_config_rejects_unsupported_status() {
        assert!(serde_yaml::from_str::<RedirectConfig>("statusCode: 307").is_err());
    }

    #[test]
    fn redirect_config_rejects_unsupported_scheme() {
        assert!(serde_yaml::from_str::<RedirectConfig>("scheme: ftp").is_err());
    }
}
