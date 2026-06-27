use gateway_config::{parse_yaml, validate};

const DEMO: &str = include_str!("fixtures/demo.yaml");

#[test]
fn demo_fixture_parses_and_validates() {
    let cfg = parse_yaml(DEMO).expect("demo fixture should parse");
    assert_eq!(cfg.name, "demo-gateway-config");
    assert_eq!(cfg.binds.len(), 1);
    assert_eq!(cfg.backends.len(), 2);
    assert_eq!(cfg.secrets.len(), 1);
    assert_eq!(cfg.secrets[0].name, "app-tls");

    validate(&cfg).expect("demo fixture should validate");
}
