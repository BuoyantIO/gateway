//! Pure functions that turn proto messages from `gateway_cp_proto::v1`
//! into the gateway's native `gateway_config` types and `gateway_state`
//! keys.
//!
//! No I/O, no Store interaction — `apply` calls these and feeds the
//! result into the Store. Each function fails closed on missing or
//! invalid input rather than silently defaulting, so translator-side
//! bugs surface as errors at the data plane.

use std::net::IpAddr;

use gateway_config::backend::{Backend, BackendProtocol, BackendRef, Endpoint, StaticBackend};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::filter::{HeaderOps, HeaderPair, HttpFilter};
use gateway_config::listener::{HttpListener, Listener};
use gateway_config::route::{
    HeaderMatch, HeaderValueMatch, HttpMatch, HttpRoute, PathMatch, QueryParamMatch,
    QueryValueMatch,
};
use gateway_config::secret::TlsSecret;
use gateway_cp_proto::v1 as pb;
use gateway_state::{BackendKey, BindKey, ListenerKey, RouteKey, SecretKey};

use crate::error::Error;

// ==================== Upserts ====================

/// # Errors
/// Returns [`Error::InvalidValue`] if `address` does not parse to an
/// [`IpAddr`] or if `port` is outside the `u16` range, or
/// [`Error::UnsupportedEnum`] if `bind_protocol` is not `HTTP`.
pub fn bind(msg: pb::BindUpsert) -> Result<Bind, Error> {
    let address: IpAddr = msg.address.parse().map_err(|_| Error::InvalidValue {
        field: "BindUpsert.address",
        value: msg.address.clone(),
    })?;
    let port: u16 = msg.port.try_into().map_err(|_| Error::InvalidValue {
        field: "BindUpsert.port",
        value: msg.port.to_string(),
    })?;
    let bind_protocol = bind_protocol(msg.bind_protocol)?;
    Ok(Bind {
        name: msg.name,
        address,
        port,
        bind_protocol,
        // Listeners arrive as their own ListenerUpsert messages, not
        // embedded — matches the proto's flat shape.
        listeners: Vec::new(),
    })
}

/// # Errors
/// Returns [`Error::MissingField`] if `key` is unset.
pub fn listener(msg: pb::ListenerUpsert) -> Result<(BindKey, Listener), Error> {
    let key = msg.key.ok_or(Error::MissingField("ListenerUpsert.key"))?;
    let parent = BindKey::new(key.bind);
    let hostname = if msg.has_hostname {
        Some(msg.hostname)
    } else {
        None
    };
    let http = HttpListener {
        name: key.name,
        hostname,
        // Routes arrive as their own HttpRouteUpsert messages.
        routes: Vec::new(),
    };
    Ok((parent, Listener::Http(http)))
}

/// # Errors
/// Returns [`Error::MissingField`] if `key` or any match's `path` is
/// unset, [`Error::UnsupportedEnum`] for an unrecognized path match
/// kind or HTTP method, [`Error::InvalidHeaderName`] /
/// [`Error::InvalidHeaderValue`] / [`Error::InvalidRegex`] if a
/// match value fails to parse / compile.
pub fn http_route(msg: pb::HttpRouteUpsert) -> Result<(ListenerKey, HttpRoute), Error> {
    let key = msg.key.ok_or(Error::MissingField("HttpRouteUpsert.key"))?;
    let parent = ListenerKey::new(BindKey::new(key.bind), key.listener);

    let matches: Result<Vec<HttpMatch>, Error> = msg.matches.into_iter().map(http_match).collect();
    let backend_refs: Vec<BackendRef> = msg.backend_refs.into_iter().map(backend_ref).collect();
    let filters: Vec<HttpFilter> = msg.filters.into_iter().filter_map(http_filter).collect();

    Ok((
        parent,
        HttpRoute {
            name: key.name,
            matches: matches?,
            backend_refs,
            filters,
        },
    ))
}

/// # Errors
/// Returns [`Error::InvalidValue`] for any endpoint with an
/// unparseable address or out-of-range port, or
/// [`Error::UnsupportedEnum`] if `protocol` is not `HTTP1` or `HTTP2`.
pub fn backend(msg: pb::BackendUpsert) -> Result<Backend, Error> {
    let endpoints: Result<Vec<Endpoint>, Error> = msg.endpoints.into_iter().map(endpoint).collect();
    let protocol = backend_protocol(msg.protocol)?;
    Ok(Backend::Static(StaticBackend {
        name: msg.name,
        endpoints: endpoints?,
        protocol,
    }))
}

/// # Errors
/// Returns [`Error::InvalidSecret`] if the cert chain / private key
/// PEM is malformed (parsed up front so a bad secret is rejected here
/// rather than at handshake time).
pub fn secret(msg: pb::SecretUpsert) -> Result<TlsSecret, Error> {
    let name = msg.name;
    TlsSecret::new(name.clone(), &msg.cert_pem, &msg.key_pem)
        .map_err(|source| Error::InvalidSecret { name, source })
}

// ==================== Remove keys ====================

pub fn bind_key(msg: pb::BindKey) -> BindKey {
    BindKey::new(msg.name)
}

pub fn listener_key(msg: pb::ListenerKey) -> ListenerKey {
    ListenerKey::new(BindKey::new(msg.bind), msg.name)
}

pub fn route_key(msg: pb::RouteKey) -> RouteKey {
    RouteKey::new(
        ListenerKey::new(BindKey::new(msg.bind), msg.listener),
        msg.name,
    )
}

pub fn backend_key(msg: pb::BackendKey) -> BackendKey {
    BackendKey::new(msg.name)
}

pub fn secret_key(msg: pb::SecretKey) -> SecretKey {
    SecretKey::new(msg.name)
}

// ==================== Pieces ====================

fn http_match(msg: pb::HttpMatch) -> Result<HttpMatch, Error> {
    let host = if msg.has_host { Some(msg.host) } else { None };
    let path_msg = msg.path.ok_or(Error::MissingField("HttpMatch.path"))?;
    let path = path_match(path_msg)?;
    let method = http_method(msg.method)?;
    let headers: Result<Vec<HeaderMatch>, Error> =
        msg.header_matches.into_iter().map(header_match).collect();
    let query_params: Result<Vec<QueryParamMatch>, Error> = msg
        .query_param_matches
        .into_iter()
        .map(query_param_match)
        .collect();
    Ok(HttpMatch {
        host,
        path,
        method,
        headers: headers?,
        query_params: query_params?,
    })
}

fn http_method(value: i32) -> Result<Option<http::Method>, Error> {
    match pb::HttpMethod::try_from(value) {
        Ok(pb::HttpMethod::Unspecified) => Ok(None),
        Ok(pb::HttpMethod::Get) => Ok(Some(http::Method::GET)),
        Ok(pb::HttpMethod::Head) => Ok(Some(http::Method::HEAD)),
        Ok(pb::HttpMethod::Post) => Ok(Some(http::Method::POST)),
        Ok(pb::HttpMethod::Put) => Ok(Some(http::Method::PUT)),
        Ok(pb::HttpMethod::Delete) => Ok(Some(http::Method::DELETE)),
        Ok(pb::HttpMethod::Connect) => Ok(Some(http::Method::CONNECT)),
        Ok(pb::HttpMethod::Options) => Ok(Some(http::Method::OPTIONS)),
        Ok(pb::HttpMethod::Trace) => Ok(Some(http::Method::TRACE)),
        Ok(pb::HttpMethod::Patch) => Ok(Some(http::Method::PATCH)),
        Err(_) => Err(Error::UnsupportedEnum {
            kind: "HttpMethod",
            value,
        }),
    }
}

fn header_match(msg: pb::HeaderMatch) -> Result<HeaderMatch, Error> {
    let name = http::HeaderName::from_bytes(msg.name.as_bytes()).map_err(|source| {
        Error::InvalidHeaderName {
            name: msg.name.clone(),
            source,
        }
    })?;
    let raw = msg.value.ok_or(Error::MissingField("HeaderMatch.value"))?;
    let value = match raw {
        pb::header_match::Value::Exact(s) => {
            let v =
                http::HeaderValue::try_from(&s).map_err(|source| Error::InvalidHeaderValue {
                    value: s.clone(),
                    source,
                })?;
            HeaderValueMatch::Exact { value: v }
        }
        pb::header_match::Value::Regex(pat) => {
            let re = regex::Regex::new(&pat).map_err(|source| Error::InvalidRegex {
                pattern: pat.clone(),
                source,
            })?;
            HeaderValueMatch::Regex { value: re }
        }
    };
    Ok(HeaderMatch { name, value })
}

fn query_param_match(msg: pb::QueryParamMatch) -> Result<QueryParamMatch, Error> {
    let raw = msg
        .value
        .ok_or(Error::MissingField("QueryParamMatch.value"))?;
    let value = match raw {
        pb::query_param_match::Value::Exact(s) => QueryValueMatch::Exact { value: s },
        pb::query_param_match::Value::Regex(pat) => {
            let re = regex::Regex::new(&pat).map_err(|source| Error::InvalidRegex {
                pattern: pat.clone(),
                source,
            })?;
            QueryValueMatch::Regex { value: re }
        }
    };
    Ok(QueryParamMatch {
        name: msg.name,
        value,
    })
}

fn path_match(msg: pb::PathMatch) -> Result<PathMatch, Error> {
    match pb::PathMatchKind::try_from(msg.kind) {
        Ok(pb::PathMatchKind::PathPrefix) => Ok(PathMatch::PathPrefix { value: msg.value }),
        Ok(pb::PathMatchKind::Exact) => Ok(PathMatch::Exact { value: msg.value }),
        Ok(pb::PathMatchKind::Regex) => {
            let re = regex::Regex::new(&msg.value).map_err(|source| Error::InvalidRegex {
                pattern: msg.value.clone(),
                source,
            })?;
            Ok(PathMatch::Regex { value: re })
        }
        Ok(pb::PathMatchKind::Unspecified) | Err(_) => Err(Error::UnsupportedEnum {
            kind: "PathMatchKind",
            value: msg.kind,
        }),
    }
}

fn backend_ref(msg: pb::BackendRef) -> BackendRef {
    BackendRef {
        name: msg.name,
        weight: msg.weight,
    }
}

/// Returns `None` for unknown / future filter kinds, with a warn-level
/// log. Mirrors the translator's behavior of dropping unsupported
/// `HTTPRoute` filter types instead of failing the route.
fn http_filter(msg: pb::HttpFilter) -> Option<HttpFilter> {
    let kind = msg.kind?;
    match kind {
        pb::http_filter::Kind::RequestHeaderModifier(rhm) => {
            let ops = rhm.request_headers.unwrap_or_default();
            Some(HttpFilter::RequestHeaderModifier {
                name: rhm.name,
                request_headers: header_ops(ops),
            })
        }
        pb::http_filter::Kind::ResponseHeaderModifier(rhm) => {
            let ops = rhm.response_headers.unwrap_or_default();
            Some(HttpFilter::ResponseHeaderModifier {
                name: rhm.name,
                response_headers: header_ops(ops),
            })
        }
    }
}

fn header_pair(msg: pb::HeaderPair) -> HeaderPair {
    HeaderPair {
        name: msg.name,
        value: msg.value,
    }
}

fn header_ops(msg: pb::HeaderOps) -> HeaderOps {
    HeaderOps {
        add: msg.add.into_iter().map(header_pair).collect(),
        set: msg.set.into_iter().map(header_pair).collect(),
        remove: msg.remove,
    }
}

fn endpoint(msg: pb::Endpoint) -> Result<Endpoint, Error> {
    let address: IpAddr = msg.address.parse().map_err(|_| Error::InvalidValue {
        field: "Endpoint.address",
        value: msg.address.clone(),
    })?;
    let port: u16 = msg.port.try_into().map_err(|_| Error::InvalidValue {
        field: "Endpoint.port",
        value: msg.port.to_string(),
    })?;
    Ok(Endpoint {
        name: msg.name,
        address,
        port,
    })
}

fn bind_protocol(value: i32) -> Result<BindProtocol, Error> {
    match pb::BindProtocol::try_from(value) {
        Ok(pb::BindProtocol::Http) => Ok(BindProtocol::Http),
        Ok(pb::BindProtocol::Tls) => Ok(BindProtocol::Tls),
        Ok(pb::BindProtocol::Unspecified) | Err(_) => Err(Error::UnsupportedEnum {
            kind: "BindProtocol",
            value,
        }),
    }
}

fn backend_protocol(value: i32) -> Result<BackendProtocol, Error> {
    match pb::BackendProtocol::try_from(value) {
        Ok(pb::BackendProtocol::Http1) => Ok(BackendProtocol::Http1),
        Ok(pb::BackendProtocol::Http2) => Ok(BackendProtocol::Http2),
        Ok(pb::BackendProtocol::Unspecified) | Err(_) => Err(Error::UnsupportedEnum {
            kind: "BackendProtocol",
            value,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_match_round_trips_path_prefix() {
        let out = path_match(pb::PathMatch {
            kind: pb::PathMatchKind::PathPrefix as i32,
            value: "/api".into(),
        })
        .expect("round-trip");
        match out {
            PathMatch::PathPrefix { value } => assert_eq!(value, "/api"),
            other => panic!("expected PathPrefix, got {other:?}"),
        }
    }

    #[test]
    fn path_match_round_trips_exact() {
        let out = path_match(pb::PathMatch {
            kind: pb::PathMatchKind::Exact as i32,
            value: "/healthz".into(),
        })
        .expect("round-trip");
        match out {
            PathMatch::Exact { value } => assert_eq!(value, "/healthz"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn path_match_round_trips_regex() {
        let out = path_match(pb::PathMatch {
            kind: pb::PathMatchKind::Regex as i32,
            value: r"^/api/v\d+$".into(),
        })
        .expect("round-trip");
        match out {
            PathMatch::Regex { value } => assert_eq!(value.as_str(), r"^/api/v\d+$"),
            other => panic!("expected Regex, got {other:?}"),
        }
    }

    #[test]
    fn path_match_regex_invalid_pattern_rejected() {
        let err = path_match(pb::PathMatch {
            kind: pb::PathMatchKind::Regex as i32,
            value: "[".into(),
        })
        .expect_err("invalid regex should fail");
        assert!(matches!(err, Error::InvalidRegex { .. }));
    }

    #[test]
    fn path_match_rejects_unspecified_kind() {
        let err = path_match(pb::PathMatch {
            kind: pb::PathMatchKind::Unspecified as i32,
            value: "/".into(),
        })
        .expect_err("unspecified should fail");
        assert!(matches!(
            err,
            Error::UnsupportedEnum {
                kind: "PathMatchKind",
                ..
            }
        ));
    }

    fn pb_match_with(
        method: pb::HttpMethod,
        headers: Vec<pb::HeaderMatch>,
        query_params: Vec<pb::QueryParamMatch>,
    ) -> pb::HttpMatch {
        pb::HttpMatch {
            host: String::new(),
            has_host: false,
            path: Some(pb::PathMatch {
                kind: pb::PathMatchKind::PathPrefix as i32,
                value: "/".into(),
            }),
            method: method as i32,
            header_matches: headers,
            query_param_matches: query_params,
        }
    }

    #[test]
    fn method_round_trips_through_http_match() {
        let m = http_match(pb_match_with(pb::HttpMethod::Post, vec![], vec![])).unwrap();
        assert_eq!(m.method, Some(http::Method::POST));
    }

    #[test]
    fn method_unspecified_yields_none() {
        let m = http_match(pb_match_with(pb::HttpMethod::Unspecified, vec![], vec![])).unwrap();
        assert!(m.method.is_none());
    }

    #[test]
    fn header_match_exact_round_trips() {
        let m = http_match(pb_match_with(
            pb::HttpMethod::Unspecified,
            vec![pb::HeaderMatch {
                name: "x-debug".into(),
                value: Some(pb::header_match::Value::Exact("1".into())),
            }],
            vec![],
        ))
        .unwrap();
        assert_eq!(m.headers.len(), 1);
        assert_eq!(m.headers[0].name.as_str(), "x-debug");
        assert!(matches!(m.headers[0].value, HeaderValueMatch::Exact { .. }));
    }

    #[test]
    fn header_match_regex_round_trips() {
        let m = http_match(pb_match_with(
            pb::HttpMethod::Unspecified,
            vec![pb::HeaderMatch {
                name: "x-version".into(),
                value: Some(pb::header_match::Value::Regex(r"^v\d+$".into())),
            }],
            vec![],
        ))
        .unwrap();
        assert!(matches!(m.headers[0].value, HeaderValueMatch::Regex { .. }));
    }

    #[test]
    fn header_match_missing_value_oneof_rejected() {
        let err = http_match(pb_match_with(
            pb::HttpMethod::Unspecified,
            vec![pb::HeaderMatch {
                name: "x".into(),
                value: None,
            }],
            vec![],
        ))
        .expect_err("must fail");
        assert!(matches!(err, Error::MissingField("HeaderMatch.value")));
    }

    #[test]
    fn header_match_invalid_regex_rejected() {
        let bad = pb::HttpRouteUpsert {
            key: Some(pb::RouteKey {
                bind: "b".into(),
                listener: "l".into(),
                name: "r".into(),
            }),
            matches: vec![pb_match_with(
                pb::HttpMethod::Unspecified,
                vec![pb::HeaderMatch {
                    name: "x".into(),
                    value: Some(pb::header_match::Value::Regex("[".into())),
                }],
                vec![],
            )],
            backend_refs: vec![],
            filters: vec![],
        };
        let err = http_route(bad).expect_err("must fail");
        assert!(matches!(err, Error::InvalidRegex { .. }));
    }

    #[test]
    fn header_match_invalid_name_rejected() {
        let bad = pb::HttpRouteUpsert {
            key: Some(pb::RouteKey {
                bind: "b".into(),
                listener: "l".into(),
                name: "r".into(),
            }),
            matches: vec![pb_match_with(
                pb::HttpMethod::Unspecified,
                vec![pb::HeaderMatch {
                    name: "bad name".into(),
                    value: Some(pb::header_match::Value::Exact("v".into())),
                }],
                vec![],
            )],
            backend_refs: vec![],
            filters: vec![],
        };
        let err = http_route(bad).expect_err("must fail");
        assert!(matches!(err, Error::InvalidHeaderName { .. }));
    }

    #[test]
    fn response_header_modifier_round_trips() {
        let filter = pb::HttpFilter {
            kind: Some(pb::http_filter::Kind::ResponseHeaderModifier(
                pb::ResponseHeaderModifier {
                    name: "rsp".into(),
                    response_headers: Some(pb::HeaderOps {
                        add: vec![pb::HeaderPair {
                            name: "x-csp".into(),
                            value: "default-src 'self'".into(),
                        }],
                        set: vec![pb::HeaderPair {
                            name: "x-frame-options".into(),
                            value: "sameorigin".into(),
                        }],
                        remove: vec!["x-server-version".into()],
                    }),
                },
            )),
        };
        let cfg = http_filter(filter).expect("known kind");
        match cfg {
            HttpFilter::ResponseHeaderModifier {
                name,
                response_headers,
            } => {
                assert_eq!(name, "rsp");
                assert_eq!(response_headers.add.len(), 1);
                assert_eq!(response_headers.add[0].name, "x-csp");
                assert_eq!(response_headers.set.len(), 1);
                assert_eq!(response_headers.set[0].name, "x-frame-options");
                assert_eq!(
                    response_headers.remove,
                    vec!["x-server-version".to_string()]
                );
            }
            v @ HttpFilter::RequestHeaderModifier { .. } => {
                panic!("expected ResponseHeaderModifier, got {v:?}")
            }
        }
    }
}
