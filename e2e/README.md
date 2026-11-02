# gateway-e2e

End-to-end tests for the gateway on a kind cluster. Each test creates
its own namespace, applies a `Gateway`, an `HTTPRoute` and a backend as
typed objects, and drives HTTP through the `LoadBalancer` address that
the Gateway's status reports. The control plane provisions the data
plane from the `Gateway`, the same way that it does outside the tests.
[docs/local-development.md](../docs/local-development.md) says how to
bring the cluster up, how to run the suite or one test, and where the
logs go when a test fails.

## Test backends

All three backends live in the one `gateway-test-echo:e2e` image, and
the container's `command` selects one:

- `echo` replies with `"{method} {path}"` and reflects every `X-Test-*`
  request header as an `X-Echo-*` response header. Most tests assert
  through it.
- `grpc_echo` does the same over gRPC, behind a Service whose
  `appProtocol: grpc` makes the gateway dial h2c.
- `openai_mock` is a mock inference provider for the egress path. It
  terminates the TLS that the gateway originates, checks the credential
  that the `GatewayBackend` presents, and streams a completion as
  `text/event-stream`. Its flags set the gap before the first token
  (`ttft-ms`) and the tail (`tokens`, `gap-ms`). A plaintext side port
  serves `/__stats`, one record per request, which says what the mock
  saw and how much of the response it sent; the fixtures read it
  through the apiserver pod proxy.

## How tests are structured

Each test follows the same shape:

```rust
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster, run via just test-e2e"]
async fn my_feature_works() -> Result<()> {
    // 1. A namespace for this test alone. The scope deletes it on
    //    drop, including when an assertion panics.
    let scope = Scope::new("my-feature").await?;
    let ns = scope.name();
    let client = scope.client();

    // 2. An echo backend.
    deploy_echo(client, ns, "echo", None).await?;

    // 3. The Gateway, as a typed object. The control plane provisions
    //    the gatewayd Deployment and Service from it, and the status
    //    reports the address once the Service has one.
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;

    // 4. The HTTPRoute, through the chainable builder.
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    // 5. Poll until the data path answers with the expected status.
    //    The call returns the first response that matches.
    let resp = wait_until_routed(&addr, "app.example", "/", StatusCode::OK).await?;

    // 6. Assert. The echo replies "{method} {path}" and reflects
    //    X-Test-* request headers as X-Echo-* response headers.
    assert_eq!(resp.text().await?, "GET /");
    Ok(())
}
```

The namespace lives only for the test. When the scope drops, the
apiserver deletes the namespace and garbage-collects every resource
that the test created in it.
