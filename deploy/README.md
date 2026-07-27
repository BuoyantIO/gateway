# Deploy

Helm chart and sample manifests for running the gateway control
plane and a sample data plane on a Kubernetes cluster (kind or any
standard distribution).

## Layout

```
deploy/
├── README.md
├── chart/
│   └── gateway/                             # Helm chart: CP Deployment, RBAC,
│       ├── Chart.yaml                       # headless Service, GatewayClass
│       ├── values.yaml                      # controlPlane.image / dataPlane.image
│       └── templates/
└── manifests/
    └── examples/
        └── sample-app/
            ├── namespace.yaml               # demo namespace
            ├── gateway.yaml                 # demo/api-gateway, HTTP :80
            ├── httproute.yaml               # PathPrefix / -> echo:8080
            └── echo.yaml                    # hashicorp/http-echo backend
```

The data plane is not part of the chart: the control plane
provisions a gatewayd `Deployment` + `Service`
(`api-gateway-gatewayd`) in the Gateway's namespace when the Gateway
is applied. The chart pins the gatewayd image the provisioner
deploys via `dataPlane.image` (rendered into the CP's `--dp-image`
flag).

## Install from local builds

From the repo root:

```sh
docker build -f Dockerfile     -t gateway-data-plane:latest    .
docker build -f Dockerfile.cp  -t gateway-control-plane:latest .
```

For kind:

```sh
kind load docker-image gateway-data-plane:latest gateway-control-plane:latest
```

Install the Gateway API CRDs, the chart (pointed at the local
images), and the sample app:

```sh
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/standard-install.yaml
helm upgrade --install gateway deploy/chart/gateway \
    --namespace gateway-system --create-namespace \
    --set controlPlane.image.repository=gateway-control-plane \
    --set controlPlane.image.tag=latest \
    --set dataPlane.image.repository=gateway-data-plane \
    --set dataPlane.image.tag=latest
kubectl apply -f deploy/manifests/examples/sample-app/
```

Image values default to the published `ghcr.io/buoyantio` images at
the chart's `appVersion`; the overrides above are only needed for
locally built images.

## Verify

```sh
kubectl -n demo wait --for=condition=available deployment/api-gateway-gatewayd --timeout=120s
kubectl -n demo port-forward svc/api-gateway-gatewayd 8080:80
curl -H 'Host: app.example.com'   http://localhost:8080/         # -> "hello from echo" (catch-all PathPrefix `/`)
curl -H 'Host: app.example.com'   http://localhost:8080/healthz  # -> "hello from echo" (Exact `/healthz`)
curl -H 'Host: app.example.com'   http://localhost:8080/healthzz # -> "hello from echo" (falls back to PathPrefix, NOT Exact)
curl -H 'Host: other.example.com' http://localhost:8080/         # -> 404 (hostname not matched)
```

The sample `HTTPRoute` is scoped to `app.example.com` via
`spec.hostnames` and declares two rules:

- `Exact /healthz` — wins over the catch-all for that one path.
- `PathPrefix /` — catch-all.

`/healthzz` is the critical case: it confirms `Exact` doesn't
prefix-match (it falls through to the PathPrefix instead).

## Notes

- The control plane provisions the data plane: applying an owned
  `Gateway` yields a gatewayd `Deployment`, `Service`, and
  `ServiceAccount` named `{gateway}-gatewayd` in the Gateway's
  namespace, owner-referenced so deleting the Gateway cleans them
  up. Two per-Gateway annotations steer it:
  `gateway.buoyant.io/service-type: ClusterIP|NodePort|LoadBalancer`
  (default `LoadBalancer`) and
  `gateway.buoyant.io/provisioning: disabled` to opt a Gateway out
  and deploy gatewayd by hand (`--client-id={ns}/{gw-name}`).
- The controller writes status: `kubectl get gtw` shows ADDRESS
  (from the provisioned Service) and PROGRAMMED, listener entries
  carry `attachedRoutes`, and the GatewayClass is marked `Accepted`.
  `HTTPRoute.status.parents` is not written yet.
- The control plane resolves backend endpoints from `EndpointSlice`s
  (one endpoint per ready pod address); the data plane balances
  across them per request. A Service with no ready pods answers 503.
