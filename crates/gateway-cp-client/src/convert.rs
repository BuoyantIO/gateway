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
use gateway_config::filter::{HeaderPair, HttpFilter, RequestHeaderOps};
use gateway_config::listener::{HttpListener, Listener};
use gateway_config::route::{HttpMatch, HttpRoute, PathMatch, PathMatchKind};
use gateway_cp_proto::v1 as pb;
use gateway_state::{BackendKey, BindKey, ListenerKey, RouteKey};

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
/// unset, or [`Error::UnsupportedEnum`] if a path match `kind` is not
/// `PATH_PREFIX`.
pub fn http_route(msg: pb::HttpRouteUpsert) -> Result<(ListenerKey, HttpRoute), Error> {
    let key = msg.key.ok_or(Error::MissingField("HttpRouteUpsert.key"))?;
    let parent = ListenerKey::new(BindKey::new(key.bind), key.listener);

    let matches: Result<Vec<HttpMatch>, Error> = msg.matches.into_iter().map(http_match).collect();
    let backend_refs: Vec<BackendRef> = msg.backend_refs.into_iter().map(backend_ref).collect();
    let filters: Vec<HttpFilter> = msg.filters.into_iter().filter_map(http_filter).collect();

    let route = HttpRoute {
        name: key.name,
        matches: matches?,
        backend_refs,
        filters,
    };
    Ok((parent, route))
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

// ==================== Pieces ====================

fn http_match(msg: pb::HttpMatch) -> Result<HttpMatch, Error> {
    let host = if msg.has_host { Some(msg.host) } else { None };
    let path_msg = msg.path.ok_or(Error::MissingField("HttpMatch.path"))?;
    let path = path_match(path_msg)?;
    Ok(HttpMatch { host, path })
}

fn path_match(msg: pb::PathMatch) -> Result<PathMatch, Error> {
    let kind = match pb::PathMatchKind::try_from(msg.kind) {
        Ok(pb::PathMatchKind::PathPrefix) => PathMatchKind::PathPrefix,
        Ok(pb::PathMatchKind::Exact) => PathMatchKind::Exact,
        Ok(pb::PathMatchKind::Unspecified) | Err(_) => {
            return Err(Error::UnsupportedEnum {
                kind: "PathMatchKind",
                value: msg.kind,
            });
        }
    };
    Ok(PathMatch {
        kind,
        value: msg.value,
    })
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
                request_headers: RequestHeaderOps {
                    add: ops.add.into_iter().map(header_pair).collect(),
                    set: ops.set.into_iter().map(header_pair).collect(),
                    remove: ops.remove,
                },
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
        assert_eq!(out.kind, PathMatchKind::PathPrefix);
        assert_eq!(out.value, "/api");
    }

    #[test]
    fn path_match_round_trips_exact() {
        let out = path_match(pb::PathMatch {
            kind: pb::PathMatchKind::Exact as i32,
            value: "/healthz".into(),
        })
        .expect("round-trip");
        assert_eq!(out.kind, PathMatchKind::Exact);
        assert_eq!(out.value, "/healthz");
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
}
