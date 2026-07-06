# gateway-e2e

End-to-end test harness. Stands up a real kind cluster with the
control plane + CRDs, then each test applies its own Gateway,
HTTPRoute, and backend in a unique namespace and drives HTTP
through. The control plane provisions the data plane from the
Gateway; the harness only adds a fixed-`NodePort` Service over the
provisioned pods so tests can reach them from the host.

## Prerequisites

- `docker`
- `kind`
- `kubectl`
- `just` (`cargo install just`)
- A Rust toolchain (pinned by `rust-toolchain.toml`).

## Running locally

```sh
just up        # build images, create kind cluster, deploy CP + CRDs
just test      # run the e2e suite (currently 6 tests)
just down      # tear everything down
```

For a single test:

```sh
cargo test -p gateway-e2e --test routing -- --ignored exact_beats_prefix
```

All tests are `#[ignore]`d so they're not run by
`cargo test --workspace`. The justfile passes `--ignored` for you.

## How tests are structured

Each test follows the same shape:

```rust
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn my_feature_works() -> Result<()> {
    // 1. Per-test namespace. Auto-deleted on scope drop, including
    //    on panic from a failed assertion.
    let scope = Scope::new("my-feature").await?;
    let ns = scope.name();
    let client = scope.client();

    // 2. Expose the (to-be-provisioned) DP on the host NodePort and
    //    deploy an echo backend.
    expose_dp(client, ns, "gw").await?;
    deploy_echo(client, ns, "echo", None).await?;

    // 3. Apply the Gateway. Typed; no YAML. The CP provisions the
    //    gatewayd Deployment + Service from it.
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;

    // 4. Apply the HTTPRoute via the chainable builder.
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    // 5. Poll until the data path is wired. (No status writeback
    //    in the gateway yet, so we probe the data path directly.)
    //    Returns the first response that matches the expected
    //    status.
    let resp = wait_until_routed("app.example", "/", StatusCode::OK).await?;

    // 6. Assert. The echo replies "{method} {path}" and reflects
    //    `X-Test-*` request headers as `X-Echo-*` response
    //    headers, so most assertions go through that mechanism.
    assert_eq!(resp.text().await?, "GET /");
    Ok(())
}
```

The namespace lives only for the test. On `Drop` it's deleted
cascade-style by the apiserver, which GCs every resource the test
created.
