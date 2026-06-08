use std::collections::HashSet;
use std::fmt;

use thiserror::Error;

use crate::backend::Backend;
use crate::bind::{Bind, BindProtocol};
use crate::config::GatewayConfig;
use crate::filter::{HttpFilter, RequestHeaderOps};
use crate::listener::{HttpsListener, Listener, TcpListener, TlsConfig, TlsListener, TlsMode};
use crate::route::{HttpMatch, HttpRoute, PathMatch, QueryParamMatch, TcpRoute, TlsRoute};

#[derive(Debug, Error)]
#[error("{key}: {reason}")]
pub struct Rejection {
    pub key: String,
    pub reason: RejectionReason,
}

#[derive(Debug, Error)]
pub enum RejectionReason {
    #[error("duplicate name `{0}`")]
    DuplicateName(String),
    #[error("TLS mode Terminate requires at least one certificate")]
    TerminateWithoutCert,
    #[error("TLS mode Passthrough must have no certificates")]
    PassthroughWithCert,
    #[error("BindProtocol {bind} is incompatible with listener protocol {listener}")]
    BindListenerProtocolMismatch {
        bind: BindProtocol,
        listener: &'static str,
    },
    #[error("path `{0}` must start with `/`")]
    PathNotSlash(String),
    #[error("RequestHeaderModifier filter has no add/set/remove operations")]
    EmptyHeaderModifier,
    #[error("header `{0}` appears in more than one RequestHeaderModifier operation")]
    HeaderInMultipleOps(String),
    #[error("static backend must have at least one endpoint")]
    StaticBackendNoEndpoints,
    #[error("TCP listener must have exactly one route, found {0}")]
    TcpListenerRouteCount(usize),
    /// A query-param match has an empty `name`. (Header-match
    /// names are `http::HeaderName` and rejected at deserialization
    /// time — empty / malformed names can't reach validation.)
    #[error("query param match `name` must not be empty")]
    EmptyQueryParamName,
}

impl fmt::Display for BindProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls => f.write_str("TLS"),
            Self::Http => f.write_str("HTTP"),
            Self::Tcp => f.write_str("TCP"),
        }
    }
}

/// Validate every object in `cfg` against its structural rules.
/// Cross-reference resolution is not performed here.
///
/// # Errors
///
/// Returns one or more [`Rejection`]s, each carrying the object's
/// hierarchical key (e.g. `binds[0]/listeners[1]/routes[0]`) and the
/// reason it was rejected.
pub fn validate(cfg: &GatewayConfig) -> Result<(), Vec<Rejection>> {
    let mut rejections = Vec::new();

    check_unique(
        "binds",
        cfg.binds.iter().map(|b| b.name.as_str()),
        &mut rejections,
    );
    check_unique(
        "backends",
        cfg.backends.iter().map(Backend::name),
        &mut rejections,
    );
    check_unique(
        "secrets",
        cfg.secrets.iter().map(crate::secret::Secret::name),
        &mut rejections,
    );

    for (i, bind) in cfg.binds.iter().enumerate() {
        validate_bind(&format!("binds[{i}]"), bind, &mut rejections);
    }
    for (i, backend) in cfg.backends.iter().enumerate() {
        validate_backend(&format!("backends[{i}]"), backend, &mut rejections);
    }

    if rejections.is_empty() {
        Ok(())
    } else {
        Err(rejections)
    }
}

fn validate_bind(key: &str, bind: &Bind, out: &mut Vec<Rejection>) {
    check_unique(
        &format!("{key}/listeners"),
        bind.listeners.iter().map(Listener::name),
        out,
    );

    for (i, listener) in bind.listeners.iter().enumerate() {
        let lkey = format!("{key}/listeners[{i}]");
        let listener_proto = match listener {
            Listener::Tls(_) => "TLS",
            Listener::Https(_) => "HTTPS",
            Listener::Http(_) => "HTTP",
            Listener::Tcp(_) => "TCP",
        };

        let compatible = matches!(
            (bind.bind_protocol, listener),
            (BindProtocol::Tls, Listener::Tls(_) | Listener::Https(_))
                | (BindProtocol::Http, Listener::Http(_))
                | (BindProtocol::Tcp, Listener::Tcp(_))
        );
        if !compatible {
            out.push(Rejection {
                key: lkey.clone(),
                reason: RejectionReason::BindListenerProtocolMismatch {
                    bind: bind.bind_protocol,
                    listener: listener_proto,
                },
            });
        }

        match listener {
            Listener::Tls(l) => validate_tls_listener(&lkey, l, out),
            Listener::Https(l) => validate_https_listener(&lkey, l, out),
            Listener::Http(l) => {
                check_unique(
                    &format!("{lkey}/routes"),
                    l.routes.iter().map(|r| r.name.as_str()),
                    out,
                );
                for (j, route) in l.routes.iter().enumerate() {
                    validate_http_route(&format!("{lkey}/routes[{j}]"), route, out);
                }
            }
            Listener::Tcp(l) => validate_tcp_listener(&lkey, l, out),
        }
    }
}

fn validate_tls_listener(key: &str, l: &TlsListener, out: &mut Vec<Rejection>) {
    validate_tls_config(&format!("{key}/tls"), &l.tls, out);
    check_unique(
        &format!("{key}/routes"),
        l.routes.iter().map(|r| r.name.as_str()),
        out,
    );
    for (i, route) in l.routes.iter().enumerate() {
        validate_tls_route(&format!("{key}/routes[{i}]"), route, out);
    }
}

fn validate_https_listener(key: &str, l: &HttpsListener, out: &mut Vec<Rejection>) {
    validate_tls_config(&format!("{key}/tls"), &l.tls, out);
    check_unique(
        &format!("{key}/routes"),
        l.routes.iter().map(|r| r.name.as_str()),
        out,
    );
    for (i, route) in l.routes.iter().enumerate() {
        validate_http_route(&format!("{key}/routes[{i}]"), route, out);
    }
}

fn validate_tls_config(key: &str, tls: &TlsConfig, out: &mut Vec<Rejection>) {
    match tls.mode {
        TlsMode::Terminate if tls.certificates.is_empty() => {
            out.push(Rejection {
                key: key.to_string(),
                reason: RejectionReason::TerminateWithoutCert,
            });
        }
        TlsMode::Passthrough if !tls.certificates.is_empty() => {
            out.push(Rejection {
                key: key.to_string(),
                reason: RejectionReason::PassthroughWithCert,
            });
        }
        _ => {}
    }
}

fn validate_tls_route(key: &str, route: &TlsRoute, out: &mut Vec<Rejection>) {
    check_unique(
        &format!("{key}/filters"),
        route.filters.iter().map(crate::filter::TlsFilter::name),
        out,
    );
}

fn validate_tcp_listener(key: &str, l: &TcpListener, out: &mut Vec<Rejection>) {
    if l.routes.len() != 1 {
        out.push(Rejection {
            key: key.to_string(),
            reason: RejectionReason::TcpListenerRouteCount(l.routes.len()),
        });
    }
    check_unique(
        &format!("{key}/routes"),
        l.routes.iter().map(|r| r.name.as_str()),
        out,
    );
    for (i, route) in l.routes.iter().enumerate() {
        validate_tcp_route(&format!("{key}/routes[{i}]"), route, out);
    }
}

fn validate_tcp_route(key: &str, route: &TcpRoute, out: &mut Vec<Rejection>) {
    check_unique(
        &format!("{key}/filters"),
        route.filters.iter().map(crate::filter::TcpFilter::name),
        out,
    );
}

fn validate_http_route(key: &str, route: &HttpRoute, out: &mut Vec<Rejection>) {
    for (i, m) in route.matches.iter().enumerate() {
        validate_http_match(&format!("{key}/matches[{i}]"), m, out);
    }
    check_unique(
        &format!("{key}/filters"),
        route.filters.iter().map(HttpFilter::name),
        out,
    );
    for (i, f) in route.filters.iter().enumerate() {
        match f {
            HttpFilter::RequestHeaderModifier {
                request_headers, ..
            } => {
                validate_request_header_ops(&format!("{key}/filters[{i}]"), request_headers, out);
            }
        }
    }
}

fn validate_http_match(key: &str, m: &HttpMatch, out: &mut Vec<Rejection>) {
    match &m.path {
        // `PathPrefix` and `Exact` require an absolute path per
        // Gateway API. `Regex` patterns are validated by
        // `serde_regex` at deserialization time; no slash
        // constraint applies.
        PathMatch::PathPrefix { value } | PathMatch::Exact { value } => {
            if !value.starts_with('/') {
                out.push(Rejection {
                    key: format!("{key}/path"),
                    reason: RejectionReason::PathNotSlash(value.clone()),
                });
            }
        }
        PathMatch::Regex { .. } => {}
    }
    // Header name/value and regex validity are enforced at
    // deserialization time by the typed match shapes — nothing to
    // re-check here. Query-param names are `String` so check
    // emptiness manually.
    for (i, q) in m.query_params.iter().enumerate() {
        validate_query_param_match(&format!("{key}/queryParams[{i}]"), q, out);
    }
}

fn validate_query_param_match(key: &str, q: &QueryParamMatch, out: &mut Vec<Rejection>) {
    if q.name.is_empty() {
        out.push(Rejection {
            key: format!("{key}/name"),
            reason: RejectionReason::EmptyQueryParamName,
        });
    }
}

fn validate_request_header_ops(key: &str, ops: &RequestHeaderOps, out: &mut Vec<Rejection>) {
    if ops.add.is_empty() && ops.set.is_empty() && ops.remove.is_empty() {
        out.push(Rejection {
            key: key.to_string(),
            reason: RejectionReason::EmptyHeaderModifier,
        });
        return;
    }
    let mut seen: HashSet<String> = HashSet::new();
    let mut report_dup = |name: &str, out: &mut Vec<Rejection>| {
        if !seen.insert(name.to_ascii_lowercase()) {
            out.push(Rejection {
                key: key.to_string(),
                reason: RejectionReason::HeaderInMultipleOps(name.to_string()),
            });
        }
    };
    for h in &ops.add {
        report_dup(&h.name, out);
    }
    for h in &ops.set {
        report_dup(&h.name, out);
    }
    for h in &ops.remove {
        report_dup(h, out);
    }
}

fn validate_backend(key: &str, backend: &Backend, out: &mut Vec<Rejection>) {
    match backend {
        Backend::Static(s) => {
            if s.endpoints.is_empty() {
                out.push(Rejection {
                    key: key.to_string(),
                    reason: RejectionReason::StaticBackendNoEndpoints,
                });
            }
            check_unique(
                &format!("{key}/endpoints"),
                s.endpoints.iter().map(|e| e.name.as_str()),
                out,
            );
        }
    }
}

fn check_unique<'a, I>(key: &str, names: I, out: &mut Vec<Rejection>)
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen: HashSet<&str> = HashSet::new();
    for name in names {
        if !seen.insert(name) {
            out.push(Rejection {
                key: key.to_string(),
                reason: RejectionReason::DuplicateName(name.to_string()),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_yaml;

    fn parse(src: &str) -> GatewayConfig {
        parse_yaml(src).expect("yaml should parse")
    }

    #[test]
    fn http_bind_with_https_listener_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 443
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTPS
          tls: { mode: Terminate, certificates: [{ name: s, kind: Secret }] }
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(errs.iter().any(|r| matches!(
            r.reason,
            RejectionReason::BindListenerProtocolMismatch { .. }
        )));
    }

    #[test]
    fn tcp_listener_with_multiple_routes_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 5432
      bindProtocol: TCP
      listeners:
        - name: l
          listenerProtocol: TCP
          routes:
            - { name: r0, backendRefs: [{ name: be0 }] }
            - { name: r1, backendRefs: [{ name: be1 }] }
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(
            errs.iter()
                .any(|r| matches!(r.reason, RejectionReason::TcpListenerRouteCount(2)))
        );
    }

    #[test]
    fn duplicate_tcp_filter_name_within_route_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 5432
      bindProtocol: TCP
      listeners:
        - name: l
          listenerProtocol: TCP
          routes:
            - name: r
              backendRefs: [{ name: be }]
              filters:
                - { name: same, type: TcpConnectionLog }
                - { name: same, type: TcpConnectionLog }
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(
            errs.iter()
                .any(|r| matches!(&r.reason, RejectionReason::DuplicateName(n) if n == "same"))
        );
    }

    #[test]
    fn tcp_listener_with_no_routes_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 5432
      bindProtocol: TCP
      listeners:
        - { name: l, listenerProtocol: TCP }
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(
            errs.iter()
                .any(|r| matches!(r.reason, RejectionReason::TcpListenerRouteCount(0)))
        );
    }

    #[test]
    fn tcp_bind_with_http_listener_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 5432
      bindProtocol: TCP
      listeners:
        - name: l
          listenerProtocol: HTTP
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(errs.iter().any(|r| matches!(
            r.reason,
            RejectionReason::BindListenerProtocolMismatch { .. }
        )));
    }

    #[test]
    fn tls_bind_with_http_listener_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 443
      bindProtocol: TLS
      listeners:
        - name: l
          listenerProtocol: HTTP
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(errs.iter().any(|r| matches!(
            r.reason,
            RejectionReason::BindListenerProtocolMismatch { .. }
        )));
    }

    #[test]
    fn terminate_without_certs_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 443
      bindProtocol: TLS
      listeners:
        - name: l
          listenerProtocol: HTTPS
          tls: { mode: Terminate }
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(
            errs.iter()
                .any(|r| matches!(r.reason, RejectionReason::TerminateWithoutCert))
        );
    }

    #[test]
    fn passthrough_with_certs_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 443
      bindProtocol: TLS
      listeners:
        - name: l
          listenerProtocol: TLS
          tls:
            mode: Passthrough
            certificates: [{ name: s, kind: Secret }]
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(
            errs.iter()
                .any(|r| matches!(r.reason, RejectionReason::PassthroughWithCert))
        );
    }

    #[test]
    fn path_prefix_without_slash_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 80
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTP
          routes:
            - name: r
              matches: [{ path: { type: PathPrefix, value: api } }]
              backendRefs: [{ name: be }]
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(
            errs.iter()
                .any(|r| matches!(r.reason, RejectionReason::PathNotSlash(_)))
        );
    }

    #[test]
    fn regex_path_match_accepted() {
        // Regex patterns are not subject to the `starts_with('/')`
        // rule (their `value` is a `regex::Regex`, not a path
        // string). A well-formed regex passes validate.
        let cfg = parse(
            r#"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 80
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTP
          routes:
            - name: r
              matches: [{ path: { type: Regex, value: "^/api/v\\d+$" } }]
              backendRefs: [{ name: be }]
"#,
        );
        validate(&cfg).expect("valid regex path should pass validation");
    }

    #[test]
    fn regex_path_invalid_pattern_rejected_at_parse_time() {
        // Malformed regex patterns are rejected by `serde_regex`
        // during YAML deserialization, before `validate()` ever runs.
        let err = crate::parse_yaml(
            r#"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 80
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTP
          routes:
            - name: r
              matches: [{ path: { type: Regex, value: "[" } }]
              backendRefs: [{ name: be }]
"#,
        )
        .expect_err("invalid regex pattern should fail YAML parse");
        let _ = format!("{err}"); // shape varies; existence is the assertion
    }

    #[test]
    fn empty_header_modifier_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 80
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTP
          routes:
            - name: r
              matches: [{ path: { type: PathPrefix, value: / } }]
              backendRefs: [{ name: be }]
              filters:
                - { name: hdr, type: RequestHeaderModifier, requestHeaders: {} }
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(
            errs.iter()
                .any(|r| matches!(r.reason, RejectionReason::EmptyHeaderModifier))
        );
    }

    #[test]
    fn header_in_multiple_ops_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 80
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTP
          routes:
            - name: r
              matches: [{ path: { type: PathPrefix, value: / } }]
              backendRefs: [{ name: be }]
              filters:
                - name: hdr
                  type: RequestHeaderModifier
                  requestHeaders:
                    add: [{ name: x-dup, value: a }]
                    remove: [x-dup]
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(
            errs.iter()
                .any(|r| matches!(r.reason, RejectionReason::HeaderInMultipleOps(_)))
        );
    }

    #[test]
    fn empty_static_backend_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds: []
  backends:
    - { name: be, type: Static, endpoints: [] }
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(
            errs.iter()
                .any(|r| matches!(r.reason, RejectionReason::StaticBackendNoEndpoints))
        );
    }

    #[test]
    fn duplicate_listener_name_within_bind_rejected() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 80
      bindProtocol: HTTP
      listeners:
        - { name: same, listenerProtocol: HTTP }
        - { name: same, listenerProtocol: HTTP }
",
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(
            errs.iter()
                .any(|r| matches!(&r.reason, RejectionReason::DuplicateName(n) if n == "same"))
        );
    }

    #[test]
    fn same_listener_name_across_binds_is_fine() {
        let cfg = parse(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b0
      port: 80
      bindProtocol: HTTP
      listeners: [{ name: shared, listenerProtocol: HTTP }]
    - name: b1
      port: 8080
      bindProtocol: HTTP
      listeners: [{ name: shared, listenerProtocol: HTTP }]
",
        );
        validate(&cfg).expect("listener names are scoped to their parent bind");
    }

    #[test]
    fn header_match_invalid_name_rejected_at_parse_time() {
        // Invalid header names are caught by the deserializer (via
        // `http::HeaderName::from_bytes`), not by `validate()`.
        let err = crate::parse_yaml(
            r#"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 80
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTP
          routes:
            - name: r
              matches:
                - path: { type: PathPrefix, value: / }
                  headers:
                    - { name: "bad name", value: { type: Exact, value: v } }
              backendRefs: [{ name: be }]
"#,
        )
        .expect_err("invalid header name should fail YAML parse");
        let msg = format!("{err}");
        assert!(msg.contains("invalid HTTP header name"), "got: {msg}");
    }

    #[test]
    fn header_match_invalid_regex_rejected_at_parse_time() {
        // Invalid regexes are caught by `serde_regex` at deserialize.
        let err = crate::parse_yaml(
            r#"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 80
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTP
          routes:
            - name: r
              matches:
                - path: { type: PathPrefix, value: / }
                  headers:
                    - { name: x-id, value: { type: Regex, value: "[" } }
              backendRefs: [{ name: be }]
"#,
        )
        .expect_err("invalid regex should fail YAML parse");
        let _ = format!("{err}"); // shape varies; existence is the assertion
    }

    #[test]
    fn query_param_empty_name_rejected() {
        let cfg = parse(
            r#"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 80
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTP
          routes:
            - name: r
              matches:
                - path: { type: PathPrefix, value: / }
                  queryParams:
                    - { name: "", value: { type: Exact, value: v } }
              backendRefs: [{ name: be }]
"#,
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(
            errs.iter()
                .any(|r| matches!(r.reason, RejectionReason::EmptyQueryParamName))
        );
    }

    #[test]
    fn method_and_headers_valid_config_accepted() {
        let cfg = parse(
            r#"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 80
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTP
          routes:
            - name: r
              matches:
                - path: { type: PathPrefix, value: / }
                  method: GET
                  headers:
                    - { name: x-debug, value: { type: Exact, value: "1" } }
                    - { name: x-version, value: { type: Regex, value: "^v\\d+$" } }
                  queryParams:
                    - { name: preview, value: { type: Exact, value: "true" } }
              backendRefs: [{ name: be }]
"#,
        );
        validate(&cfg).expect("valid config with all match dims should accept");
    }

    #[test]
    fn duplicate_filter_name_within_route_rejected() {
        let cfg = parse(
            r#"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 80
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTP
          routes:
            - name: r
              matches: [{ path: { type: PathPrefix, value: / } }]
              backendRefs: [{ name: be }]
              filters:
                - { name: same, type: RequestHeaderModifier, requestHeaders: { add: [{ name: a, value: "1" }] } }
                - { name: same, type: RequestHeaderModifier, requestHeaders: { add: [{ name: b, value: "2" }] } }
"#,
        );
        let errs = validate(&cfg).unwrap_err();
        assert!(
            errs.iter()
                .any(|r| matches!(&r.reason, RejectionReason::DuplicateName(n) if n == "same"))
        );
    }
}
