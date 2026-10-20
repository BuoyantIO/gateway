# gateway-e2e

End-to-end test harness. Stands up a real kind cluster with the
control plane + CRDs, then each test applies its own Gateway,
HTTPRoute, and backend in a unique namespace and drives HTTP
through. The control plane provisions the data plane from the
Gateway; the harness only adds a fixed-`NodePort` Service over the
provisioned pods so tests can reach them from the host.

## Test backends

All three live in the one `gateway-test-echo:e2e` image, selected by
the container's `command`:

- `echo` — replies `"{method} {path}"` and reflects `X-Test-*`
  request headers as `X-Echo-*`. Most tests assert through it.
- `grpc_echo` — the same idea over gRPC, behind a Service whose
  `appProtocol: grpc` makes the gateway dial h2c.
- `openai_mock` — a mock inference provider for the egress path. It
  terminates the TLS the gateway originates, checks the credential
  the `GatewayBackend` presents, and streams a completion as
  `text/event-stream` with a configurable gap before the first token
  (`ttft-ms`) and a configurable tail (`tokens`, `gap-ms`). A
  plaintext side port serves `/__stats`, one record per request
  saying what it saw and how much of the response it got to send;
  `fixtures::provider_stats` reads it through the apiserver pod
  proxy.

## Prerequisites

- `docker`
- `kind`
- `kubectl`
- `just` (`cargo install just`)
- A Rust toolchain (pinned by `rust-toolchain.toml`).

`just up` also starts a
[cloud-provider-kind](https://github.com/kubernetes-sigs/cloud-provider-kind)
container so `LoadBalancer` Services in the cluster get IPs from the
docker network. Those IPs are host-routable on Linux; on macOS
cloud-provider-kind needs its sudo tunnel mode instead of the
container, which this setup doesn't automate — Linux is the primary
target.

## Running locally

```sh
just up        # build images, create kind cluster, deploy CP + CRDs
just test      # run the e2e suite
just down      # tear everything down
```

For a single test:

```sh
cargo test -p gateway-e2e --test routing -- --ignored exact_beats_prefix
```

All tests are `#[ignore]`d so they're not run by
`cargo test --workspace`. The justfile passes `--ignored` for you.

## Debugging failures

A test's namespace, and with it its gatewayd and backend logs, is
deleted when the test ends. Set `E2E_LOG_DIR` to keep them: each test
then saves its pods' logs and its namespace's events to
`$E2E_LOG_DIR/<namespace>/` before deleting it.

Traffic reaches a Gateway through a cloud-provider-kind Envoy
container (`kindccm-*`) that lives outside the cluster. `just up`
starts cloud-provider-kind with log dumping on, so the Envoy log of
every deleted `LoadBalancer` Service lands in
`/tmp/cloud-provider-kind-logs/<namespace>_<service>.log`; live ones
are in `docker logs`.

CI does all of this and, when the suite fails, uploads it with the
`kind export logs` output as the `kind-logs` artifact.

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
