# kinference manual verification

Drives a real request through the full path: client → gateway DP →
`kinference_selector` extension → kinference Picker → dummy vLLM → streamed
response + reports.

## 1. Gateway cluster

From the `gateway` repo root:

```bash
just up
```

Builds the DP/CP/echo images (the DP registers `kinference_selector` at
startup), creates kind cluster `gateway-e2e` (kubectl context
`kind-gateway-e2e`), installs the Gateway API CRDs, the chart (the
`Extension` CRD ships in its `crds/`), and cloud-provider-kind so
`LoadBalancer` Services get host-routable IPs.

## 2. Get kinference into the cluster

From the `llm-monitor` repo root:

```bash
make -C k8s/kinference build TARGET=local TAG=dev
```

```bash
kind load docker-image kinference:dev --name gateway-e2e
```


```bash
kubectl --context kind-gateway-e2e label nodes --all role=system --overwrite
```

CRDs, then the deployment:

```bash
make -C k8s/kinference crds TARGET=local KUBE_CONTEXT=kind-gateway-e2e
```

```bash
make -C k8s/kinference deploy TARGET=local TAG=dev KUBE_CONTEXT=kind-gateway-e2e
```

The picker now listens at `kinference.default.svc:50051`. The gateway's
`service` target must resolve to a single picker instance — the one
replica deployed here, or a single pod's DNS name. The picker holds
per-request state, so a Service balancing across replicas would break
any request whose calls land on different ones.

## 3. Dummy worker + demo config

Still from the `llm-monitor` repo root. The dummy vLLM is CPU-only
and answers nonsense:

```bash
kubectl --context kind-gateway-e2e apply -f k8s/examples/dummy-vllm/dummy-vllm.yaml
```

```bash
kubectl --context kind-gateway-e2e apply -f k8s/examples/demo-configs/
```

Wait for the vLLM pod to become Ready (it downloads
SmolLM2-135M on first start), then check kinference sees the worker:

```bash
kubectl --context kind-gateway-e2e logs deploy/kinference | tail -20
```

## 4. Gateway objects

The route's `backendRef` names the `dummy-vllm` Service — the rule's
refs are the allowlist the selector's pick is validated against.

```bash
kubectl --context kind-gateway-e2e apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: llm-gw
  namespace: default
spec:
  gatewayClassName: buoyant-gateway
  listeners:
    - name: http
      protocol: HTTP
      port: 80
---
apiVersion: gateway.linkerd.io/v1alpha1
kind: Extension
metadata:
  name: chat-picker
  namespace: default
spec:
  class: kinference_selector
  config:
    service: kinference.default.svc:50051
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: chat
  namespace: default
spec:
  parentRefs:
    - name: llm-gw
  rules:
    - matches:
        - path: { type: PathPrefix, value: / }
      filters:
        - type: ExtensionRef
          extensionRef:
            group: gateway.linkerd.io
            kind: Extension
            name: chat-picker
      backendRefs:
        - name: dummy-vllm
          port: 8000
EOF
```

Optional: turn on the extension's per-request debug logs:

```bash
kubectl --context kind-gateway-e2e -n default annotate gateway llm-gw gateway.buoyant.io/dp-log-filter='info,extension=debug' --overwrite
```

## 5. Test the traffic

```bash
GW=$(kubectl --context kind-gateway-e2e -n default get svc llm-gw-gatewayd -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
```

```bash
curl -sN "http://$GW/v1/chat/completions" \
  -H 'content-type: application/json' \
  -H 'x-request-id: manual-1' \
  -d '{"model": "HuggingFaceTB/SmolLM2-135M-Instruct", "max_tokens": 64, "stream": true, "stream_options": {"include_usage": true}, "messages": [{"role": "user", "content": "say hi"}]}'
```

## 6. Observe the gateway deployment logs for the kinference extension doing its magic:

```bash
kubectl --context kind-gateway-e2e logs  deploy/llm-gw-gatewayd      -f
```

## 7. Teardown

```bash
just down
```
