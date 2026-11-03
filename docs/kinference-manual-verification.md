# Kinference manual verification

How to drive a real inference request through the full path. The client
sends a chat completion to the gateway data plane, the
`kinference_selector` extension streams the body to the Kinference
Picker, the Picker picks a dummy vLLM worker, and the response streams
back while the extension reports the first and the final token.

## 1. Gateway cluster

From the `gateway` repo root:

```bash
just up
```

The recipe builds the data-plane, control-plane and echo images, creates
the kind cluster `gateway-e2e` with the kubectl context
`kind-gateway-e2e`, installs the Gateway API CRDs, the `gateway-crds`
chart, the `gateway` chart and cloud-provider-kind, so that
`LoadBalancer` Services get host-routable IPs. The data plane registers
`kinference_selector` at startup. The `Extension` and `BackendBinding`
CRDs ship in the `gateway-crds` chart, not in the `gateway` chart.

Then apply the `Gateway` and read its IP, which the requests below use:

```bash
kubectl --context kind-gateway-e2e apply -f examples/kinference/gateway.yml
# Wait a little until the IP is provisioned
GW=$(kubectl --context kind-gateway-e2e -n default get svc llm-gw-gatewayd -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
```

## 2. Get Kinference into the cluster

From the Kinference repo root:

```bash
just image
```

```bash
kind load docker-image kinference:latest --name gateway-e2e
```

Install the CRD chart, then the workload chart, into `default`. That is
the namespace that the chart's default config names in `[policy]` and
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

`extension.enabled=true` makes the chart create the `chat-picker`
`Extension`, of class `kinference_selector`, pointing at
`kinference.default.svc:50051`. The gateway cluster must exist first,
because `Extension` is the gateway's CRD. The picker holds per-request
state, so the `service` target must resolve to a single instance, and
the chart's one replica does.

The chart's default config also sets `[policy] backend_bindings = true`.
Kinference then publishes one `BackendBinding` per `InferencePool`, each
listing `chat-picker`, so none of the steps below writes gateway
plumbing by hand.

## 3. Dummy worker

Still from the Kinference repo root. The dummy vLLM runs on the CPU
and answers nonsense:

```bash
kubectl --context kind-gateway-e2e apply -f tests/e2e/manifests/dummy-vllm.yaml
```

Wait for the engine. The first run pulls the CPU image and fetches the
model config and tokenizer:

```bash
kubectl --context kind-gateway-e2e rollout status deployment/dummy-vllm --timeout=420s
```

## 4. Tests

To see the extension's per-request debug logs, set the data plane's
log filter through the Gateway annotation:

```bash
kubectl --context kind-gateway-e2e -n default annotate gateway llm-gw gateway.buoyant.io/dp-log-filter='info,extension=debug' --overwrite
```

Then follow the data plane's log:

```bash
kubectl --context kind-gateway-e2e logs deploy/llm-gw-gatewayd -f
```

### Option A: Only test the dummy worker

Apply the `InferenceWorkerSet` that wraps the dummy worker, and the
single-destination `InferencePool` that points to it:

```bash
kubectl --context kind-gateway-e2e apply -f tests/e2e/manifests/workerset.yaml
kubectl --context kind-gateway-e2e apply -f tests/e2e/manifests/pool.yaml
```

Then check that Kinference discovered the worker and published the
binding for the pool:

```bash
kubectl --context kind-gateway-e2e logs deploy/kinference | tail -20
```

```bash
kubectl --context kind-gateway-e2e get backendbindings
```

The `smoke` binding must show `Accepted: True`.

#### Deploy the route and send traffic

Back in the `gateway` repo, apply the `HTTPRoute` that points to the
`smoke` `InferencePool`:

```bash
kubectl --context kind-gateway-e2e apply -f examples/kinference/httproute-smoke.yml
```

Then send a request:

```bash
curl -sN "http://$GW/v1/chat/completions" \
  -H 'content-type: application/json' \
  -H 'x-request-id: manual-1' \
  -d '{"model": "HuggingFaceTB/SmolLM2-135M-Instruct", "max_tokens": 64, "stream": true, "stream_options": {"include_usage": true}, "messages": [{"role": "user", "content": "say hi"}]}'
```

### Option B: Load-balance between the dummy worker and a Databricks provider

This option needs access to a Databricks instance. Put its credentials
in these environment variables:

- `DATABRICKS_SUBDOMAIN`
- `DATABRICKS_CLIENT_ID`
- `DATABRICKS_SECRET`

Back in the `gateway` repo, apply the manifests:

```bash
# InferencePool pointing to the dummy and databricks destinations
kubectl --context kind-gateway-e2e apply -f examples/kinference/inferencepool.yml
# InferenceWorkerSet wrapping the dummy worker
kubectl --context kind-gateway-e2e apply -f examples/kinference/inferenceworkerset-dummy.yml
# InferenceProvider wrapping the databricks gateway backend
kubectl --context kind-gateway-e2e apply -f examples/kinference/inferenceprovider-databricks.yml
# GatewayBackend providing URL and OAuth2 setup for Databricks
envsubst < examples/kinference/gatewaybackend-databricks.yml | kubectl --context kind-gateway-e2e apply -f -
# InferencePolicy for load-balancing between the dummy worker and the Databricks instance
kubectl --context kind-gateway-e2e apply -f examples/kinference/inferencepolicy-split.yml
```

Create the secret that authenticates against Databricks:

```bash
kubectl -n default create secret generic databricks-oauth --from-literal=client-secret=${DATABRICKS_SECRET}
```

#### Deploy the route and send traffic

Apply the `HTTPRoute` that points to the `inference-all`
`InferencePool`:

```bash
kubectl --context kind-gateway-e2e apply -f examples/kinference/httproute-all.yml
```

Repeat this request a few times. About half of the requests land on
the local vLLM and the other half on Databricks. The first request that
lands on Databricks takes several minutes to warm up, so it answers
with an error first and then stabilizes:

```bash
curl -sN "http://$GW/v1/chat/completions" \
  -H 'content-type: application/json' \
  -H 'x-request-id: manual-1' \
  -d '{"model": "HuggingFaceTB/SmolLM2-135M-Instruct", "max_tokens": 64, "messages": [{"role": "user", "content": "say hi"}]}'
```

## 5. Teardown

```bash
just down
```
