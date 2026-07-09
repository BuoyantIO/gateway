//! Micro-benchmark backing `docs/research/beating-agentgateway.md`:
//! cost of applying one route upsert to the DP store when N routes
//! are already active.
//!   `cargo test --release -p gateway-state --test dp_apply_cost -- --nocapture`

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use gateway_config::backend::{Backend, BackendProtocol, BackendRef, Endpoint, StaticBackend};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::listener::{HttpListener, Listener};
use gateway_config::route::{HttpMatch, HttpRoute, PathMatch};
use gateway_state::{ListenerKey, Store};

fn bench_route(i: usize) -> HttpRoute {
    HttpRoute {
        name: format!("default/{i}-route/rule0"),
        matches: vec![HttpMatch {
            host: Some(format!("{i}-route.example.com")),
            path: PathMatch::PathPrefix {
                value: format!("/{i}"),
            },
            method: None,
            headers: vec![],
            query_params: vec![],
        }],
        backend_refs: vec![BackendRef {
            name: "default/backend:80".into(),
            weight: 1,
        }],
        filters: vec![],
    }
}

#[test]
fn dp_apply_cost() {
    for n in [20usize, 2000, 10000] {
        let store = Store::new();
        store
            .upsert_bind(Bind {
                name: "b".into(),
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 80,
                bind_protocol: BindProtocol::Http,
                listeners: vec![],
            })
            .unwrap();
        let lkey = ListenerKey::new(gateway_state::BindKey::new("b"), "http");
        store
            .upsert_listener(
                &gateway_state::BindKey::new("b"),
                Listener::Http(HttpListener {
                    name: "http".into(),
                    hostname: None,
                    routes: vec![],
                }),
            )
            .unwrap();
        store.upsert_backend(Backend::Static(StaticBackend {
            name: "default/backend:80".into(),
            endpoints: vec![Endpoint {
                name: "e1".into(),
                address: "10.0.0.1".parse().unwrap(),
                port: 8080,
            }],
            protocol: BackendProtocol::default(),
        }));

        for i in 0..n {
            store.upsert_http_route(&lkey, bench_route(i));
        }

        // Time upserting 20 fresh routes on top of N and average.
        let t = Instant::now();
        for i in n..n + 20 {
            store.upsert_http_route(&lkey, bench_route(i));
        }
        let per = t.elapsed().as_secs_f64() * 1000.0 / 20.0;
        println!("N = {n:>6}: upsert one route = {per:9.3} ms");
    }
}
