# Charts

Helm charts for running the gateway control plane on a Kubernetes
cluster. The sample manifests live in `examples/` at the repo root.

## Layout

```
charts/
├── README.md
├── gateway-crds/                            # Helm chart: the gateway.linkerd.io
│   ├── Chart.yaml                           # CRDs, installed before the gateway
│   └── templates/                           # chart and upgraded like any release
└── gateway/                                 # Helm chart: CP Deployment, RBAC,
    ├── Chart.yaml                           # headless Service, GatewayClass
    ├── values.yaml                          # controlPlane.image / dataPlane.image
    └── templates/
examples/
└── sample-app/                              # numbered so `kubectl apply -f` creates
    ├── 00-namespace.yaml                    # the demo namespace first
    ├── 10-echo.yaml                         # hashicorp/http-echo backend
    ├── 20-gateway.yaml                      # demo/api-gateway, HTTP :80
    └── 30-httproute.yaml                    # Exact /healthz, PathPrefix / -> echo:8080
```

The data plane is not part of the chart. When a `Gateway` is applied,
the control plane provisions a gatewayd `Deployment` and `Service` in
the Gateway's namespace. The chart pins the gatewayd image that the
provisioner deploys through `dataPlane.image`, which it renders into the
control plane's `--dp-image` flag.

## Install

[docs/local-development.md](../docs/local-development.md) walks through
an install from local builds on a kind cluster, with the sample app and
the requests that verify it.

The `gateway-crds` chart must be installed before the `gateway` chart,
because the control plane watches those CRDs at startup. On a cluster
that installed a pre-split `gateway` chart, the CRDs already exist
without Helm ownership metadata, so the first
`helm install gateway-crds` there needs `--take-ownership`, or a
one-time label and annotate of the three CRDs with the release
metadata.

The image values default to `cr.kinference.ai/buoyantio/gateway-cp` and
`cr.kinference.ai/buoyantio/gatewayd` at the chart's `appVersion`. The
overrides in the local-development guide are needed only for locally
built images.

## Notes

- The control plane provisions the data plane. Applying an owned
  `Gateway` yields a gatewayd `Deployment`, `Service` and
  `ServiceAccount` named `{gateway}-gatewayd` in the Gateway's
  namespace, each with an owner reference, so deleting the `Gateway`
  cleans them up. Two per-Gateway annotations steer it:
  `gateway.buoyant.io/service-type` picks `ClusterIP`, `NodePort` or
  `LoadBalancer`, with `LoadBalancer` as the default, and
  `gateway.buoyant.io/provisioning: disabled` opts a `Gateway` out so
  that you deploy gatewayd by hand with `--client-id={ns}/{gw-name}`.
- The controller writes status. `kubectl get gtw` shows the address
  from the provisioned Service and the `Programmed` condition, each
  listener entry carries `attachedRoutes`, and the `GatewayClass` is
  marked `Accepted`. The controller also writes its own entries in each
  `HTTPRoute`'s `status.parents`, which report attachment and backend
  resolution.
- The control plane resolves backend endpoints from `EndpointSlice`s,
  one endpoint per ready pod address, and the data plane balances
  across them per request. A Service with no ready pods answers 503.
