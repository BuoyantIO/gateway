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
    use crate::route::PathMatch;

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
        match &m.path {
            PathMatch::PathPrefix { value } => assert_eq!(value, "/api"),
            other => panic!("expected PathPrefix, got {other:?}"),
        }
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
        let Backend::Static(b) = &cfg.backends[0] else {
            panic!("expected a static backend");
        };
        assert_eq!(b.endpoints.len(), 3);
        assert_eq!(b.endpoints[0].port, 8080);
    }

    #[test]
    fn dialable_backend() {
        let cfg = parse_yaml(
            r"
gatewayConfig:
  name: g
  binds: []
  backends:
    - name: provider
      type: Dialable
      host: api.example.com
      port: 443
      pathPrefix: /v1
",
        )
        .unwrap();
        let Backend::Dialable(b) = &cfg.backends[0] else {
            panic!("expected a dialable backend");
        };
        assert_eq!(b.host, "api.example.com");
        assert_eq!(b.port, 443);
        assert_eq!(b.path_prefix.as_deref(), Some("/v1"));
    }

    #[test]
    fn dialable_backend_path_prefix_is_optional() {
        let cfg = parse_yaml(
            r"
gatewayConfig:
  name: g
  binds: []
  backends:
    - { name: provider, type: Dialable, host: api.example.com, port: 443 }
",
        )
        .unwrap();
        let Backend::Dialable(b) = &cfg.backends[0] else {
            panic!("expected a dialable backend");
        };
        assert!(b.path_prefix.is_none());
    }

    #[test]
    fn extension_object() {
        let cfg = parse_yaml(
            r"
gatewayConfig:
  name: g
  binds: []
  extensions:
    - name: chat-picker
      class: bllmp_selector
      failureMode: Open
      limits: { requestBody: Buffer, maxBufferBytes: 1048576 }
      config:
        service: bllmp.inference-d.svc:50051
        pool: { namespace: inference, name: my-pool }
",
        )
        .unwrap();
        let ext = &cfg.extensions[0];
        assert_eq!(ext.name, "chat-picker");
        assert_eq!(ext.class, "bllmp_selector");
        assert_eq!(ext.failure_mode, crate::extension::FailureMode::Open);
        assert_eq!(
            ext.limits.request_body,
            Some(crate::extension::RequestBodyLimit::Buffer)
        );
        assert_eq!(ext.limits.max_buffer_bytes, Some(1_048_576));
        // The opaque config keeps its nested shape verbatim.
        assert_eq!(ext.config["service"], "bllmp.inference-d.svc:50051");
        assert_eq!(ext.config["pool"]["namespace"], "inference");
    }

    #[test]
    fn extension_object_defaults() {
        let cfg = parse_yaml(
            r"
gatewayConfig:
  name: g
  binds: []
  extensions:
    - { name: x, class: c }
",
        )
        .unwrap();
        let ext = &cfg.extensions[0];
        assert_eq!(ext.failure_mode, crate::extension::FailureMode::Closed);
        assert!(ext.limits.request_body.is_none());
        assert!(ext.limits.max_buffer_bytes.is_none());
        assert!(ext.config.is_null());
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
    fn extension_ref_filter() {
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
                  type: ExtensionRef
",
        )
        .unwrap();
        let Listener::Http(l) = &cfg.binds[0].listeners[0] else {
            panic!()
        };
        let HttpFilter::ExtensionRef { name, namespace } = &l.routes[0].filters[0];
        assert_eq!(name, "hdr");
        assert_eq!(namespace, "");
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
    fn http_filter_under_tls_listener_fails() {
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
                  type: ExtensionRef
",
        );
        assert!(
            err.is_err(),
            "an HTTP filter under a TLS listener should fail to parse"
        );
    }

    #[test]
    fn exact_path_match_kind_parses() {
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
              matches: [{ path: { type: Exact, value: /api } }]
              backendRefs: [{ name: be }]
",
        )
        .expect("Exact path match kind should parse");
        let Listener::Http(http) = &cfg.binds[0].listeners[0] else {
            panic!("expected HTTP listener");
        };
        let m = &http.routes[0].matches[0];
        match &m.path {
            PathMatch::Exact { value } => assert_eq!(value, "/api"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn unknown_path_match_kind_fails() {
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
              matches: [{ path: { type: Wibble, value: /api } }]
              backendRefs: [{ name: be }]
",
        );
        assert!(err.is_err(), "unknown path kind should fail to parse");
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
                  type: ExtensionRef
",
        );
        assert!(
            err.is_err(),
            "an HTTP filter under a TCP listener should fail to parse"
        );
    }

    #[test]
    fn filter_ordering_preserved() {
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
                - { name: f0, type: ExtensionRef }
                - { name: f1, type: ExtensionRef }
                - { name: f2, type: ExtensionRef }
",
        )
        .unwrap();
        let Listener::Http(l) = &cfg.binds[0].listeners[0] else {
            panic!()
        };
        let names: Vec<&str> = l.routes[0].filters.iter().map(HttpFilter::name).collect();
        assert_eq!(names, vec!["f0", "f1", "f2"]);
    }
}
