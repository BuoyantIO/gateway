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

From the `llm-monitor` repo root, on the branch `alpeb/pick-path`:

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
make -C k8s/kinference deploy TARGET=local TAG=dev KUBE_CONTEXT=kind-gateway-e2e DEMO_MANIFESTS=
```

The picker now listens at `kinference.default.svc:50051`. The gateway's
`service` target must resolve to a single picker instance — the one
replica deployed here, or a single pod's DNS name. The picker holds
per-request state, so a Service balancing across replicas would break
any request whose calls land on different ones.

## 3. Dummy worker

Still from the `llm-monitor` repo root. The dummy vLLM is CPU-only
and answers nonsense:

```bash
kubectl --context kind-gateway-e2e apply -f k8s/examples/dummy-vllm/dummy-vllm.yaml
```

Wait for the vLLM pod to become Ready (it downloads
SmolLM2-135M on first start), then check kinference sees the worker:

```bash
kubectl --context kind-gateway-e2e logs deploy/kinference | tail -20
```

## 4. Demo config

Now back into the current repo. First set the proper values for the following env vars:

- `DATABRICKS_SUBDOMAIN`
- `DATABRICKS_CLIENT_ID`
- `DATABRICKS_SECRET`

```bash
kubectl --context kind-gateway-e2e apply -f examples/inferencepool.yml
kubectl --context kind-gateway-e2e apply -f examples/inferenceworkerset-dummy.yml
kubectl --context kind-gateway-e2e apply -f examples/inferenceprovider-databricks.yml
envsubst < examples/gatewaybackend-databricks.yml | kubectl --context kind-gateway-e2e apply -f -
kubectl --context kind-gateway-e2e apply -f examples/inferencepolicy-split.yml
```

Set up the secret to authenticate against Databricks:

```bash
kubectl -n default create secret generic databricks-oauth --from-literal=client-secret=${DATABRICKS_SECRET}
```

## 5. Gateway objects

```bash
kubectl --context kind-gateway-e2e apply -f examples/gateway.yml
kubectl --context kind-gateway-e2e apply -f examples/extension.yml
kubectl --context kind-gateway-e2e apply -f examples/httproute.yml
```

Optional: turn on the extension's per-request debug logs:

```bash
kubectl --context kind-gateway-e2e -n default annotate gateway llm-gw gateway.buoyant.io/dp-log-filter='info,extension=debug' --overwrite
```

## 6. Test the traffic

```bash
GW=$(kubectl --context kind-gateway-e2e -n default get svc llm-gw-gatewayd -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
```

Repeat this request a few times; it should land on the local vLLM about half
the time and on Databricks the other half (note that you need to warm up the
Databricks endpoint beforehand):

```bash
curl -sN "http://$GW/v1/chat/completions" \
  -H 'content-type: application/json' \
  -H 'x-request-id: manual-1' \
  -d '{"model": "HuggingFaceTB/SmolLM2-135M-Instruct", "max_tokens": 64, "messages": [{"role": "user", "content": "say hi"}]}'
```

## 7. Observe the gateway deployment logs for the kinference extension doing its magic:

```bash
kubectl --context kind-gateway-e2e logs  deploy/llm-gw-gatewayd      -f
```

## 8. Teardown

```bash
just down
```
