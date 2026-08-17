use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
pub enum HttpFilter {
    #[serde(rename_all = "camelCase")]
    RequestHeaderModifier {
        name: String,
        request_headers: HeaderOps,
    },
    #[serde(rename_all = "camelCase")]
    ResponseHeaderModifier {
        name: String,
        response_headers: HeaderOps,
    },
    #[serde(rename_all = "camelCase")]
    RequestRedirect {
        name: String,
        #[serde(default)]
        scheme: Option<Scheme>,
        #[serde(default)]
        hostname: Option<String>,
        #[serde(default)]
        port: Option<u16>,
        /// Gateway API defaults this to 302; the default lives on
        /// [`RedirectStatus`], not here.
        #[serde(default)]
        status_code: RedirectStatus,
        #[serde(default)]
        path: Option<RedirectPath>,
    },
    /// Runs the extension registered under `name`. `name` is also the
    /// filter's identity within the rule, so a rule references a
    /// given extension at most once.

    #[serde(rename_all = "camelCase")]
    ExtensionRef { name: String },
}

/// The scheme a redirect's `Location` uses. Gateway API restricts
/// this to `http` or `https`; an unset scheme (`None` on the filter)
/// keeps the request's scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(try_from = "u16")]
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

/// Path modifier for a [`HttpFilter::RequestRedirect`]. At most one
/// form applies per filter.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct HeaderOps {
    #[serde(default)]
    pub add: Vec<HeaderPair>,
    #[serde(default)]
    pub set: Vec<HeaderPair>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

impl HttpFilter {
    pub fn name(&self) -> &str {
        match self {
            Self::RequestHeaderModifier { name, .. }
            | Self::ResponseHeaderModifier { name, .. }
            | Self::RequestRedirect { name, .. }
            | Self::ExtensionRef { name } => name,
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
    fn request_redirect_deserializes() {
        let yaml = "
type: RequestRedirect
name: to-https
scheme: https
statusCode: 301
path:
  replacePrefixMatch: /new
";
        let f: HttpFilter = serde_yaml::from_str(yaml).expect("valid redirect filter");
        match f {
            HttpFilter::RequestRedirect {
                name,
                scheme,
                hostname,
                port,
                status_code,
                path,
            } => {
                assert_eq!(name, "to-https");
                assert_eq!(scheme, Some(Scheme::Https));
                assert_eq!(hostname, None);
                assert_eq!(port, None);
                assert_eq!(status_code, RedirectStatus::MovedPermanently);
                assert_eq!(path, Some(RedirectPath::ReplacePrefixMatch("/new".into())));
            }
            other => panic!("expected RequestRedirect, got {other:?}"),
        }
    }

    #[test]
    fn request_redirect_status_defaults_to_302() {
        let yaml = "
type: RequestRedirect
name: bounce
scheme: https
";
        let f: HttpFilter = serde_yaml::from_str(yaml).expect("valid redirect filter");
        let HttpFilter::RequestRedirect { status_code, .. } = f else {
            panic!("expected RequestRedirect");
        };
        assert_eq!(status_code, RedirectStatus::Found);
        assert_eq!(status_code.code(), 302);
    }

    #[test]
    fn request_redirect_rejects_unsupported_status() {
        let yaml = "
type: RequestRedirect
name: bad
statusCode: 307
";
        assert!(serde_yaml::from_str::<HttpFilter>(yaml).is_err());
    }

    #[test]
    fn request_redirect_rejects_unsupported_scheme() {
        let yaml = "
type: RequestRedirect
name: bad
scheme: ftp
";
        assert!(serde_yaml::from_str::<HttpFilter>(yaml).is_err());
    }
}
