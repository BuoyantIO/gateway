use serde::Deserialize;

use crate::config::GatewayConfig;
use crate::error::ParseError;

#[derive(Debug, Deserialize)]
struct Document {
    #[serde(rename = "gatewayConfig")]
    gateway_config: GatewayConfig,
}

/// Parse a YAML document into a [`GatewayConfig`].
///
/// The document is expected to have a single top-level `gatewayConfig:`
/// key.
///
/// # Errors
///
/// Returns [`ParseError::Yaml`] if the input is not valid YAML or does
/// not match the expected schema.
pub fn parse_yaml(src: &str) -> Result<GatewayConfig, ParseError> {
    let doc: Document = serde_yaml::from_str(src)?;
    Ok(doc.gateway_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;
    use crate::bind::BindProtocol;
    use crate::filter::{HttpFilter, TcpFilter, TlsFilter};
    use crate::listener::{Listener, TlsMode};
    use crate::route::PathMatchKind;

    #[test]
    fn multiple_binds() {
        let cfg = parse_yaml(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b0
      port: 443
      bindProtocol: TLS
    - name: b1
      port: 80
      bindProtocol: HTTP
",
        )
        .unwrap();
        assert_eq!(cfg.binds.len(), 2);
        assert_eq!(cfg.binds[0].bind_protocol, BindProtocol::Tls);
        assert_eq!(cfg.binds[1].bind_protocol, BindProtocol::Http);
    }

    #[test]
    fn multiple_listeners_per_bind() {
        let cfg = parse_yaml(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b0
      port: 443
      bindProtocol: TLS
      listeners:
        - name: l0
          listenerProtocol: HTTPS
          tls: { mode: Terminate, certificates: [{ name: s, kind: Secret }] }
        - name: l1
          listenerProtocol: TLS
          tls: { mode: Passthrough }
",
        )
        .unwrap();
        assert_eq!(cfg.binds[0].listeners.len(), 2);
        assert!(matches!(cfg.binds[0].listeners[0], Listener::Https(_)));
        assert!(matches!(cfg.binds[0].listeners[1], Listener::Tls(_)));
    }

    #[test]
    fn http_bind_with_http_listener() {
        let cfg = parse_yaml(
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
",
        )
        .unwrap();
        assert!(matches!(cfg.binds[0].listeners[0], Listener::Http(_)));
    }

    #[test]
    fn tls_terminate_with_certs() {
        let cfg = parse_yaml(
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
          tls:
            mode: Terminate
            certificates:
              - name: s
                kind: Secret
",
        )
        .unwrap();
        let Listener::Https(l) = &cfg.binds[0].listeners[0] else {
            panic!("expected HTTPS listener");
        };
        assert_eq!(l.tls.mode, TlsMode::Terminate);
        assert_eq!(l.tls.certificates.len(), 1);
        assert_eq!(l.tls.certificates[0].name, "s");
    }

    #[test]
    fn tls_passthrough_without_certs() {
        let cfg = parse_yaml(
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
          tls: { mode: Passthrough }
",
        )
        .unwrap();
        let Listener::Tls(l) = &cfg.binds[0].listeners[0] else {
            panic!("expected TLS listener");
        };
        assert_eq!(l.tls.mode, TlsMode::Passthrough);
        assert!(l.tls.certificates.is_empty());
    }

    #[test]
    fn sni_route_under_tls_listener() {
        let cfg = parse_yaml(
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
          tls: { mode: Passthrough }
          routes:
            - name: r
              matches: [{ sni: app.example.com }]
              backendRefs: [{ name: be }]
",
        )
        .unwrap();
        let Listener::Tls(l) = &cfg.binds[0].listeners[0] else {
            panic!("expected TLS listener");
        };
        assert_eq!(l.routes.len(), 1);
        assert_eq!(l.routes[0].matches[0].sni, "app.example.com");
    }

    #[test]
    fn http_host_path_route_under_http_listener() {
        let cfg = parse_yaml(
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
              matches:
                - host: app.example.com
                  path:
                    type: PathPrefix
                    value: /api
              backendRefs: [{ name: be }]
",
        )
        .unwrap();
        let Listener::Http(l) = &cfg.binds[0].listeners[0] else {
            panic!("expected HTTP listener");
        };
        let m = &l.routes[0].matches[0];
        assert_eq!(m.host.as_deref(), Some("app.example.com"));
        assert_eq!(m.path.kind, PathMatchKind::PathPrefix);
        assert_eq!(m.path.value, "/api");
    }

    #[test]
    fn static_backend_with_endpoints() {
        let cfg = parse_yaml(
            r"
gatewayConfig:
  name: g
  binds: []
  backends:
    - name: be
      type: Static
      endpoints:
        - { name: e0, address: 10.0.0.1, port: 8080 }
        - { name: e1, address: 10.0.0.2, port: 8080 }
        - { name: e2, address: 10.0.0.3, port: 8080 }
",
        )
        .unwrap();
        let Backend::Static(b) = &cfg.backends[0];
        assert_eq!(b.endpoints.len(), 3);
        assert_eq!(b.endpoints[0].port, 8080);
    }

    #[test]
    fn tls_client_hello_log_filter() {
        let cfg = parse_yaml(
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
          tls: { mode: Passthrough }
          routes:
            - name: r
              matches: [{ sni: x }]
              backendRefs: [{ name: be }]
              filters:
                - { name: log, type: TlsClientHelloLog }
",
        )
        .unwrap();
        let Listener::Tls(l) = &cfg.binds[0].listeners[0] else {
            panic!()
        };
        assert!(matches!(
            l.routes[0].filters[0],
            TlsFilter::TlsClientHelloLog { .. }
        ));
    }

    #[test]
    fn request_header_modifier_filter() {
        let cfg = parse_yaml(
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
                    add:
                      - { name: x-add, value: a }
                    set:
                      - { name: x-set, value: s }
                    remove:
                      - x-rm
",
        )
        .unwrap();
        let Listener::Http(l) = &cfg.binds[0].listeners[0] else {
            panic!()
        };
        let HttpFilter::RequestHeaderModifier {
            request_headers, ..
        } = &l.routes[0].filters[0];
        assert_eq!(request_headers.add.len(), 1);
        assert_eq!(request_headers.set.len(), 1);
        assert_eq!(request_headers.remove, vec!["x-rm".to_string()]);
    }

    #[test]
    fn sni_match_under_https_listener_fails() {
        let err = parse_yaml(
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
          tls: { mode: Terminate, certificates: [{ name: s, kind: Secret }] }
          routes:
            - name: r
              matches: [{ sni: app.example.com }]
              backendRefs: [{ name: be }]
",
        );
        assert!(
            err.is_err(),
            "SNI match under HTTPS listener should fail to parse"
        );
    }

    #[test]
    fn request_header_modifier_under_tls_listener_fails() {
        let err = parse_yaml(
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
          tls: { mode: Passthrough }
          routes:
            - name: r
              matches: [{ sni: x }]
              backendRefs: [{ name: be }]
              filters:
                - name: hdr
                  type: RequestHeaderModifier
                  requestHeaders: { add: [{ name: x, value: y }] }
",
        );
        assert!(
            err.is_err(),
            "RequestHeaderModifier under TLS listener should fail to parse"
        );
    }

    #[test]
    fn non_path_prefix_match_kind_fails() {
        let err = parse_yaml(
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
              matches: [{ path: { type: Exact, value: /api } }]
              backendRefs: [{ name: be }]
",
        );
        assert!(
            err.is_err(),
            "non-PathPrefix path kind should fail to parse"
        );
    }

    #[test]
    fn tcp_bind_with_tcp_listener_and_route() {
        let cfg = parse_yaml(
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
",
        )
        .unwrap();
        let Listener::Tcp(l) = &cfg.binds[0].listeners[0] else {
            panic!("expected TCP listener");
        };
        assert_eq!(l.routes.len(), 1);
        assert_eq!(l.routes[0].name, "r");
        assert_eq!(l.routes[0].backend_refs[0].name, "be");
    }

    #[test]
    fn tcp_connection_log_filter() {
        let cfg = parse_yaml(
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
                - { name: log, type: TcpConnectionLog }
",
        )
        .unwrap();
        let Listener::Tcp(l) = &cfg.binds[0].listeners[0] else {
            panic!()
        };
        assert!(matches!(
            l.routes[0].filters[0],
            TcpFilter::TcpConnectionLog { .. }
        ));
    }

    #[test]
    fn http_filter_under_tcp_listener_fails() {
        let err = parse_yaml(
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
                - name: hdr
                  type: RequestHeaderModifier
                  requestHeaders: { add: [{ name: x, value: y }] }
",
        );
        assert!(
            err.is_err(),
            "RequestHeaderModifier under TCP listener should fail to parse"
        );
    }

    #[test]
    fn filter_ordering_preserved() {
        let cfg = parse_yaml(
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
                - { name: f0, type: RequestHeaderModifier, requestHeaders: { add: [{ name: a, value: "0" }] } }
                - { name: f1, type: RequestHeaderModifier, requestHeaders: { add: [{ name: a, value: "1" }] } }
                - { name: f2, type: RequestHeaderModifier, requestHeaders: { add: [{ name: a, value: "2" }] } }
"#,
        )
        .unwrap();
        let Listener::Http(l) = &cfg.binds[0].listeners[0] else {
            panic!()
        };
        let names: Vec<&str> = l.routes[0].filters.iter().map(HttpFilter::name).collect();
        assert_eq!(names, vec!["f0", "f1", "f2"]);
    }
}
