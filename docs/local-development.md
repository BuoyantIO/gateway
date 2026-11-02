# Local development

How to run the gateway on a kind cluster on your own machine, apply a
`Gateway` and an `HTTPRoute`, watch the control plane provision the data
plane, and send traffic through it. CI runs the same loop, through the
recipes in the [justfile](../justfile).

## What you need

`docker`, `kind`, `kubectl`, `helm` and `just`. Docker builds the images,
so you need the Rust toolchain only for `just lint`, `just test-unit` and
`just test-e2e`, which run on the host. Host builds also need `protoc`,
because two crates compile protos in `build.rs`.

Linux is the primary target. `just up` starts a cloud-provider-kind
container that assigns docker-network IPs to `LoadBalancer` Services, and
only Linux routes those IPs from the host. On macOS cloud-provider-kind
needs its sudo tunnel mode instead, which the recipe does not automate;
the section "When it does not" says how to reach the gateway there.

## Bring it up

```sh
just up
```

The recipe builds the data-plane, control-plane and test-echo images,
creates the kind cluster `gateway-e2e`, loads the images into the
cluster, starts cloud-provider-kind, applies the Gateway API CRDs,
installs `charts/gateway-crds` and then `charts/gateway` into the
`gateway-system` namespace from source, and waits until the `gateway-cp`
Deployment is Available. kind makes `kind-gateway-e2e` the current
kubectl context. The chart runs two control-plane replicas: leader
election picks the one that writes status and provisions data planes,
and both serve data planes.

To do the same by hand on a cluster of your own, install the Gateway API
CRDs, then the two charts in this order. The control plane watches the
gateway's own CRDs at startup, so the `gateway-crds` chart must come
first:

```sh
kubectl apply --server-side --force-conflicts -f \
    https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/standard-install.yaml
helm upgrade --install gateway-crds charts/gateway-crds \
    --namespace gateway-system --create-namespace
helm upgrade --install gateway charts/gateway \
    --namespace gateway-system \
    --set controlPlane.image.repository=gateway-control-plane \
    --set controlPlane.image.tag=latest \
    --set dataPlane.image.repository=gateway-data-plane \
    --set dataPlane.image.tag=latest
```

The image overrides point the chart at the local builds. Without them
the chart pulls the published images at its `appVersion`. To run the
published charts instead of a local build, follow
[the getting started guide](https://kinference.ai/getting-started/).

## See it work

Apply the sample app. It creates the `demo` namespace, an echo backend,
a `Gateway` named `api-gateway` with one HTTP listener on port 80, and
an `HTTPRoute` for `app.example.com`:

```sh
kubectl apply -f examples/sample-app/
kubectl -n demo wait --for=condition=available deployment/api-gateway-gatewayd --timeout=120s
```

The control plane provisions a gatewayd `Deployment`, a `LoadBalancer`
`Service` and a `ServiceAccount`, all named `api-gateway-gatewayd`, in
the Gateway's namespace. Each one carries an owner reference, so
deleting the `Gateway` deletes them. The Gateway's status reports the
address that cloud-provider-kind assigned:

```sh
kubectl -n demo get gateway api-gateway
GATEWAY_IP=$(kubectl -n demo get gateway api-gateway -o jsonpath='{.status.addresses[0].value}')
```

The sample route declares two rules, `Exact /healthz` and
`PathPrefix /`:

```sh
curl -H 'Host: app.example.com' http://$GATEWAY_IP/          # hello from echo, PathPrefix rule
curl -H 'Host: app.example.com' http://$GATEWAY_IP/healthz   # hello from echo, Exact rule
curl -H 'Host: app.example.com' http://$GATEWAY_IP/healthzz  # hello from echo, PathPrefix rule
curl -H 'Host: other.example.com' http://$GATEWAY_IP/        # 404
```

The third request shows that an `Exact` match does not match a prefix:
`/healthzz` falls through to the `PathPrefix` rule. The fourth fails
because the hostname that the client sent is not in the route's
`spec.hostnames`.

`kubectl get gateway -A` shows the address and the `Programmed`
condition, each listener's status carries `attachedRoutes`, and the
`GatewayClass` is `Accepted`. The control plane does not write
`HTTPRoute.status.parents` yet.

Every control-plane replica serves data planes, so read every replica's
log:

```sh
kubectl -n gateway-system logs -l app=gateway-cp --prefix -f
kubectl -n demo logs deployment/api-gateway-gatewayd -f
```

The `gateway.buoyant.io/dp-log-filter` annotation on a `Gateway` sets
the `RUST_LOG` filter of its provisioned data plane:

```sh
kubectl -n demo annotate gateway api-gateway \
    gateway.buoyant.io/dp-log-filter='info,gateway_runtime=debug' --overwrite
```

The data plane's admin port, 15021 by default, serves `/healthz/ready`
and `/metrics`:

```sh
kubectl -n demo port-forward deployment/api-gateway-gatewayd 15021:15021 &
curl -s localhost:15021/metrics | grep '^gateway_'
```

Other annotations steer provisioning: `gateway.buoyant.io/service-type`
picks `ClusterIP`, `NodePort` or `LoadBalancer` for the Service, with
`LoadBalancer` as the default; `gateway.buoyant.io/dp-replicas` and the
`dp-cpu-request`, `dp-memory-request`, `dp-cpu-limit` and
`dp-memory-limit` annotations size the Deployment; and
`gateway.buoyant.io/provisioning: disabled` opts a `Gateway` out, so
that you deploy gatewayd yourself with `--client-id={namespace}/{name}`.

## Iterate

A code change means a new image, which you load into the cluster, and a
restart. Both the chart and the provisioner pull `IfNotPresent` on a
fixed tag, so loading the same tag again replaces the image:

```sh
just images
kind load docker-image gateway-data-plane:latest gateway-control-plane:latest --name gateway-e2e
kubectl -n gateway-system rollout restart deployment/gateway-cp
kubectl -n demo rollout restart deployment/api-gateway-gatewayd
```

To build images for both architectures:

```sh
docker buildx build --platform linux/amd64,linux/arm64 -f Dockerfile \
    -t gateway-data-plane:latest .
docker buildx build --platform linux/amd64,linux/arm64 -f Dockerfile.cp \
    -t gateway-control-plane:latest .
```

To change the chart's values, upgrade the release:

```sh
helm upgrade gateway charts/gateway --namespace gateway-system \
    --reuse-values --set controlPlane.replicas=1
```

The lints and the unit tests run on the host:

```sh
just lint         # cargo fmt --check and clippy with -D warnings
just lint-chart   # helm lint on both charts
just test-unit    # cargo test --workspace
```

One unit test:

```sh
cargo test -p gateway-cp diff::tests::value_change_yields_upsert
```

The end-to-end suite runs against the cluster that `just up` created.
Every e2e test is `#[ignore]`d, so `cargo test --workspace` skips the
suite and the recipe passes `--ignored`:

```sh
just test-e2e
```

The suite is one test binary named `e2e`, so one test is a module path
behind a `--test e2e` filter:

```sh
cargo test -p gateway-e2e --test e2e -- --ignored routing::exact_beats_prefix
```

A test deletes its namespace when it ends, and with the namespace its
gatewayd and backend logs. Set `E2E_LOG_DIR` to keep them: each test
then saves its pods' logs and its namespace's events under
`$E2E_LOG_DIR/<namespace>/` before the delete. `just ci` runs `up`,
`test-e2e` and `down` in one go.

## When it does not

- The `Gateway` has no address: cloud-provider-kind is not running.
  `docker ps --filter name=cloud-provider-kind` shows the container. On
  macOS the address exists but the host cannot reach it; use
  `kubectl -n demo port-forward svc/api-gateway-gatewayd 8080:80` and
  send the requests to `localhost:8080`.
- `gateway-cp` never becomes ready: its `/healthz/ready` answers 503 and
  names the kinds that are still waiting. Usually the `gateway-crds`
  chart is not installed. `kubectl get crd | grep gateway.linkerd.io`
  lists the three CRDs when it is.
- Every request answers 404: the `Host` header does not match the
  route's `spec.hostnames`, or the route has not attached yet. The
  listener's `attachedRoutes` count in the Gateway status says whether
  it has.
- Requests answer 503: the backend Service has no ready pods. The data
  plane reads endpoints from the Service's `EndpointSlice`s, so
  `kubectl -n demo get endpointslices` shows what it sees.
- An e2e test failed: traffic reaches a `Gateway` through a
  cloud-provider-kind Envoy container, `kindccm-*`, outside the cluster.
  `just up` starts cloud-provider-kind with log dumping on, so the Envoy
  log of every deleted `LoadBalancer` Service lands in
  `/tmp/cloud-provider-kind-logs/<namespace>_<service>.log`, and
  `docker logs` holds the live ones. `just diagnostics` prints a cluster
  summary and collects the kind and cloud-provider-kind logs; CI uploads
  them as the `kind-logs` artifact when the suite fails.

## A full request path

To send an inference request through the gateway and Kinference,
follow [kinference-manual-verification.md](kinference-manual-verification.md).
It uses the cluster that `just up` created, loads the Kinference image
into it, installs the Kinference charts with `extension.enabled=true`,
and sends a chat completion through the gateway to a dummy vLLM worker.

## Tear down

```sh
just down
```

The recipe deletes the kind cluster and the cloud-provider-kind
container.
