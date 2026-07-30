# gateway

A Kubernetes Gateway API implementation: a control plane (`gateway-cp`)
that watches `Gateway`/`HTTPRoute` resources and provisions the data
plane (`gatewayd`) that serves the traffic.

## Set up a kind cluster

Requires `docker`, `kind`, `kubectl`, and `helm`.

```sh
kind create cluster --name gateway
docker run -d --name cloud-provider-kind --network kind \
    -v /var/run/docker.sock:/var/run/docker.sock \
    registry.k8s.io/cloud-provider-kind/cloud-controller-manager:v0.9.0
kubectl apply --server-side --force-conflicts -f \
    https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/standard-install.yaml
```

`cloud-provider-kind` assigns IPs to `LoadBalancer` Services in the
cluster (host-routable on Linux).

## Install from published images

```sh
helm upgrade --install gateway oci://ghcr.io/buoyantio/charts/gateway \
    --version 0.1.0-alpha.2 \
    --namespace gateway-system --create-namespace
```

## Install from source

```sh
docker build -f Dockerfile    -t gateway-data-plane:latest    .
docker build -f Dockerfile.cp -t gateway-control-plane:latest .
kind load docker-image gateway-data-plane:latest gateway-control-plane:latest --name gateway
helm upgrade --install gateway deploy/chart/gateway \
    --namespace gateway-system --create-namespace \
    --set controlPlane.image.repository=gateway-control-plane \
    --set controlPlane.image.tag=latest \
    --set dataPlane.image.repository=gateway-data-plane \
    --set dataPlane.image.tag=latest
```

## Deploy an example

Applying the `Gateway` makes the control plane provision a gatewayd
`Deployment` and `LoadBalancer` `Service` in the `demo` namespace:

```sh
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: demo
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: api-gateway
  namespace: demo
spec:
  gatewayClassName: buoyant-gateway
  listeners:
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app-route
  namespace: demo
spec:
  parentRefs:
    - name: api-gateway
  hostnames:
    - app.example.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: echo
          port: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
  namespace: demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
        - name: echo
          image: hashicorp/http-echo:latest
          args:
            - -text=hello from echo
            - -listen=:8080
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: demo
spec:
  selector:
    app: echo
  ports:
    - port: 8080
      targetPort: 8080
EOF
```

Send traffic to the Gateway's LoadBalancer address:

```sh
kubectl -n demo wait --for=condition=available deployment/api-gateway-gatewayd --timeout=120s
GATEWAY_IP=$(kubectl -n demo get gateway api-gateway -o jsonpath='{.status.addresses[0].value}')
curl -H 'Host: app.example.com' http://$GATEWAY_IP/    # hello from echo
curl -H 'Host: other.example.com' http://$GATEWAY_IP/  # 404
```

## Tear down

```sh
kind delete cluster --name gateway
docker rm -f cloud-provider-kind
```

## Development

Requires the Rust toolchain (pinned via `rust-toolchain.toml`) and
[`just`](https://github.com/casey/just).

```sh
just lint       # fmt + clippy
just test-unit  # workspace unit tests
just up         # build images + kind cluster for e2e
just test-e2e   # e2e tests against that cluster
```
