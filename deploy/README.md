# Deploy

Manifests for running the gateway control plane and a sample data
plane on a Kubernetes cluster (kind or any standard distribution).

## Layout

```
deploy/
├── README.md
└── manifests/
    ├── gatewayclass.yaml                    # GatewayClass with our controllerName
    ├── controlplane/
    │   ├── serviceaccount.yaml              # gateway-system namespace + SA
    │   ├── clusterrole.yaml                 # watch on Gateway-API + Services
    │   ├── clusterrolebinding.yaml
    │   ├── deployment.yaml                  # replicas: 1
    │   └── service.yaml                     # headless :8443
    └── examples/
        └── sample-app/
            ├── namespace.yaml               # demo namespace
            ├── gateway.yaml                 # demo/api-gateway, HTTP :80
            ├── httproute.yaml               # PathPrefix / -> echo:8080
            ├── echo.yaml                    # hashicorp/http-echo backend
            └── dataplane.yaml               # gatewayd Deployment + Service
```

## Build the images

From the repo root:

```sh
docker build -f Dockerfile     -t gateway-data-plane:latest    .
docker build -f Dockerfile.cp  -t gateway-control-plane:latest .
```

For kind:

```sh
kind load docker-image gateway-data-plane:latest gateway-control-plane:latest
```

## Apply

```sh
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml
kubectl apply -f deploy/manifests/gatewayclass.yaml
kubectl apply -f deploy/manifests/controlplane/
kubectl apply -f deploy/manifests/examples/sample-app/
```

## Verify

```sh
kubectl -n demo port-forward svc/api-gateway 8080:80
curl http://localhost:8080/   # -> "hello from echo"
```

## Notes

- v0 expects the user to pre-deploy a data-plane `Deployment` per
  `Gateway`, with `--client-id={ns}/{gw-name}` matching the Gateway's
  K8s reference. Operator-managed Deployment creation is deferred
  (see the deferred-work section of the plan).
- Status writeback is **not** implemented in v0; `Gateway.status` will
  not be populated by this controller.
- The control plane reads `Service.spec.clusterIP` to resolve backend
  endpoints. `EndpointSlice` watching and per-pod LB land later.
