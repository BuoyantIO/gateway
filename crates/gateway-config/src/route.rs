use serde::{Deserialize, Serialize};

use crate::backend::BackendRef;
use crate::filter::{HttpFilter, TcpFilter, TlsFilter};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsRoute {
    pub name: String,
    pub matches: Vec<SniMatch>,
    pub backend_refs: Vec<BackendRef>,
    #[serde(default)]
    pub filters: Vec<TlsFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpRoute {
    pub name: String,
    pub matches: Vec<HttpMatch>,
    pub backend_refs: Vec<BackendRef>,
    #[serde(default)]
    pub filters: Vec<HttpFilter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpRoute {
    pub name: String,
    pub backend_refs: Vec<BackendRef>,
    #[serde(default)]
    pub filters: Vec<TcpFilter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SniMatch {
    pub sni: String,
}

/// Single HTTP route match. Typed values throughout: `http::Method`
/// for method, `http::HeaderName` / `http::HeaderValue` for header
/// matches, and pre-compiled `regex::Regex` for regex variants.
/// Invalid input (bad header name, malformed regex, etc.) is
/// caught at deserialization / `TryFrom` time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpMatch {
    #[serde(default)]
    pub host: Option<String>,
    pub path: PathMatch,
    #[serde(default, with = "crate::serde_http::method_opt")]
    pub method: Option<http::Method>,
    /// Header matches. All entries must match for the rule to apply.
    /// Header names compare case-insensitively (`http::HeaderName`'s
    /// `==`); values per the variant.
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,
    /// Query-param matches. All entries must match for the rule to
    /// apply. Names are case-sensitive.
    #[serde(default)]
    pub query_params: Vec<QueryParamMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathMatch {
    #[serde(rename = "type")]
    pub kind: PathMatchKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathMatchKind {
    PathPrefix,
    Exact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderMatch {
    #[serde(with = "crate::serde_http::header_name")]
    pub name: http::HeaderName,
    pub value: HeaderValueMatch,
}

/// Header value match. `Regex` is anchored at both ends by the
/// resolver (`re.find(s).is_some_and(|m| m.start() == 0 &&
/// m.end() == s.len())`).
///
/// Internal tagging on `type` with a `value` field; serializes as
/// `{ type: Exact, value: "1" }` or `{ type: Regex, value: "^foo" }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "PascalCase")]
pub enum HeaderValueMatch {
    Exact {
        #[serde(with = "crate::serde_http::header_value")]
        value: http::HeaderValue,
    },
    Regex {
        #[serde(with = "serde_regex")]
        value: regex::Regex,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParamMatch {
    pub name: String,
    pub value: QueryValueMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "PascalCase")]
pub enum QueryValueMatch {
    Exact {
        value: String,
    },
    Regex {
        #[serde(with = "serde_regex")]
        value: regex::Regex,
    },
}
