# Repo-root orchestration for the e2e harness.
#
# Common entry points:
#   just up        bring up kind + load images + deploy the CP
#   just test      run the e2e suite (cluster must be up)
#   just down      tear down the cluster
#   just ci        one-shot: up + test + down (used by CI)
#
# Prerequisites: docker, kind, kubectl, just, cargo.

set shell := ["bash", "-eo", "pipefail", "-c"]

CLUSTER := "gateway-e2e"
# Tags must match what the in-tree manifests reference
# (`:latest` for CP/DP, `:e2e` for the test echo backend).
DP_IMAGE := "gateway-data-plane:latest"
CP_IMAGE := "gateway-control-plane:latest"
ECHO_IMAGE := "gateway-test-echo:e2e"
GATEWAY_API_CRDS := "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml"

default: list

# Show available recipes.
list:
    @just --list

# Build the data-plane, control-plane, and echo images.
images:
    docker build -f Dockerfile          -t {{DP_IMAGE}}   .
    docker build -f Dockerfile.cp       -t {{CP_IMAGE}}   .
    docker build -f e2e/Dockerfile.echo -t {{ECHO_IMAGE}} .

# Create the kind cluster, load images, install CRDs + CP.
# The `kubectl create namespace` step ensures `gateway-system`
# exists before the apply walks the controlplane/ directory —
# the namespace lives in serviceaccount.yaml which sorts after
# deployment.yaml / service.yaml, so apply would race the apiserver.
up: images
    kind create cluster --name {{CLUSTER}} --config e2e/kind.yaml
    kind load docker-image {{DP_IMAGE}} {{CP_IMAGE}} {{ECHO_IMAGE}} --name {{CLUSTER}}
    kubectl apply -f {{GATEWAY_API_CRDS}}
    kubectl apply -f deploy/manifests/gatewayclass.yaml
    kubectl create namespace gateway-system --dry-run=client -o yaml | kubectl apply -f -
    kubectl apply -f deploy/manifests/controlplane/
    kubectl -n gateway-system wait --for=condition=available deployment/gateway-cp --timeout=120s

# Delete the kind cluster.
down:
    kind delete cluster --name {{CLUSTER}}

# Run the e2e suite. Cluster must be up. Tests run serially
# because every test's DP Service binds the same NodePort.
test:
    cargo test -p gateway-e2e -- --ignored --test-threads=1

# One-shot for CI: up + test + down.
ci: up test down
