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
`kind-gateway-e2e`), installs the Gateway API CRDs, the `gateway-crds`
chart (the `Extension` and `BackendBinding` CRDs ship there, not in the
`gateway` chart), the `gateway` chart, and cloud-provider-kind so
`LoadBalancer` Services get host-routable IPs.

## 2. kinference into the cluster, via its charts

From the `llm-monitor` repo root. Build the image and load it:

```bash
just image
```

```bash
kind load docker-image kinference:latest --name gateway-e2e
```

Install the CRD chart, then the workload chart into `default` — the
namespace the chart's default config names in `[policy]` and
`[kubernetes]`:

```bash
helm install kinference-crds charts/kinference-crds \
    --kube-context kind-gateway-e2e
```

```bash
helm install kinference charts/kinference \
    --kube-context kind-gateway-e2e \
    --set image.repository=kinference --set image.tag=latest \
    --set extension.enabled=true
```

```bash
kubectl --context kind-gateway-e2e wait --for=condition=available \
    deployment/kinference --timeout=180s
```

`extension.enabled=true` has the chart create the `chat-picker`
`Extension` (class `kinference_selector`, pointing at
`kinference.default.svc:50051`) — the gateway cluster must exist first,
since `Extension` is the gateway's CRD. The picker holds per-request
state, so that `service` target must resolve to a single instance; the
chart's one replica does.

The chart's default config also sets `[policy] backend_bindings = true`:
kinference publishes one `BackendBinding` per `InferencePool`, each
listing `chat-picker`, so no gateway plumbing is written by hand below.

## 3. Dummy worker + pool

Still from the `llm-monitor` repo root, apply the smoke-test fixtures:
the real CPU-only dummy vLLM, the `dummy` worker set that discovers it,
and the single-destination `smoke` pool:

```bash
kubectl --context kind-gateway-e2e apply -f tests/e2e/manifests
```

Wait for the engine (first run pulls the CPU image and fetches the
model config/tokenizer):

```bash
kubectl --context kind-gateway-e2e rollout status deployment/dummy-vllm --timeout=420s
```

Then check kinference discovered the worker and published the binding
for the pool:

```bash
kubectl --context kind-gateway-e2e logs deploy/kinference | tail -20
```

```bash
kubectl --context kind-gateway-e2e get backendbindings
```

The `smoke` binding must show `Accepted: True`.

## 4. Gateway objects

Only the objects under test are applied by hand. The route's
`backendRef` names the `InferencePool` — a kind the gateway has no
schema for; kinference's `BackendBinding` claims it, resolves it to the
`dummy-vllm` Service the picker's endpoint picks are validated against,
and prepends `chat-picker` to the rule's chain. The selector reads the
pool off the substituted refs and sends it with the Pick; the picker
resolves the pool itself.

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
      backendRefs:
        - group: kinference.buoyant.io
          kind: InferencePool
          name: smoke
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

The reply is valid OpenAI-format JSON with garbage text: the dummy
engine runs random-init weights.

## 6. Observe the gateway deployment logs for the kinference extension doing its magic:

```bash
kubectl --context kind-gateway-e2e logs  deploy/llm-gw-gatewayd      -f
```

## 7. Teardown

```bash
just down
```
