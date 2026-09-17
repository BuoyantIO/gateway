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

And then deploy the Gateway CR and retrieve the gateway's IP, used in the tests
further down below:

```bash
kubectl --context kind-gateway-e2e apply -f examples/gateway.yml
# Wait a little bit until the IP is provisioned
GW=$(kubectl --context kind-gateway-e2e -n default get svc llm-gw-gatewayd -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
```

## 2. Get kinference into the cluster

From the `llm-monitor` repo root:

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

## 3. Dummy worker

Still from the `llm-monitor` repo root. The dummy vLLM is CPU-only
and answers nonsense:

```bash
kubectl --context kind-gateway-e2e apply -f tests/e2e/manifests/dummy-vllm.yaml
```

Wait for the engine (first run pulls the CPU image and fetches the
model config/tokenizer):

```bash
kubectl --context kind-gateway-e2e rollout status deployment/dummy-vllm --timeout=420s
```

## 4. Tests!

If you want, you can enable the extension's per-request debug logs:

```bash
kubectl --context kind-gateway-e2e -n default annotate gateway llm-gw gateway.buoyant.io/dp-log-filter='info,extension=debug' --overwrite
```

And see them with:
```bash
kubectl --context kind-gateway-e2e logs deploy/llm-gw-gatewayd -f
```

### Option A: Only test the dummy worker

Deploy the InferenceWokerSet that wraps the dummy worker, and the
single-destination InferencePool pointing to it:

```bash
kubectl --context kind-gateway-e2e apply -f tests/e2e/manifests/workerset.yaml
kubectl --context kind-gateway-e2e apply -f tests/e2e/manifests/pool.yaml
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

#### Deploy route and test traffic

Now back into the current repo, deploy the HTTPRoute pointing to the `smoke`
InferencePool:

```bash
kubectl --context kind-gateway-e2e apply -f examples/httproute-smoke.yml
```

And test the traffic with:

```bash
curl -sN "http://$GW/v1/chat/completions" \
  -H 'content-type: application/json' \
  -H 'x-request-id: manual-1' \
  -d '{"model": "HuggingFaceTB/SmolLM2-135M-Instruct", "max_tokens": 64, "stream": true, "stream_options": {"include_usage": true}, "messages": [{"role": "user", "content": "say hi"}]}'
```

### Option B: Test load-balance between dummy worker and Databricks provider

The following assumes you have access to a Databricks instance. Set its
credentials in the following env vars:

- `DATABRICKS_SUBDOMAIN`
- `DATABRICKS_CLIENT_ID`
- `DATABRICKS_SECRET`

And back into the current repo, apply the following manifests:

```bash
# InferencePool pointing to the dummy and databricks destinations
kubectl --context kind-gateway-e2e apply -f examples/inferencepool.yml
# InferenceWorkerSet wrapping the dummy worker
kubectl --context kind-gateway-e2e apply -f examples/inferenceworkerset-dummy.yml
# InferenceProvider wrapping the databricks gateway backend
kubectl --context kind-gateway-e2e apply -f examples/inferenceprovider-databricks.yml
# GatewayBackend providing URL and OAuth2 setup for Databricks
envsubst < examples/gatewaybackend-databricks.yml | kubectl --context kind-gateway-e2e apply -f -
# InferencePolicy for load-balancing between the dummy worker and the Databricks instance
kubectl --context kind-gateway-e2e apply -f examples/inferencepolicy-split.yml
```

Set up the secret to authenticate against Databricks:

```bash
kubectl -n default create secret generic databricks-oauth --from-literal=client-secret=${DATABRICKS_SECRET}
```

#### Deploy route and test traffic

Deploy the HTTPRoute pointing to the `inference-all` InferencePool:

```bash
kubectl --context kind-gateway-e2e apply -f examples/httproute-all.yml
```

Repeat this request a few times; it should land on the local vLLM about half
the time and on Databricks the other half. Note that when landing on Databricks
the first time, it'll take several minutes to warm up, responding with an error
first, but then stabilizing:

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
