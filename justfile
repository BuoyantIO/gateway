set shell := ["bash", "-eo", "pipefail", "-c"]

CLUSTER := "gateway-e2e"
DP_IMAGE := "gateway-data-plane:latest"
CP_IMAGE := "gateway-control-plane:latest"
ECHO_IMAGE := "gateway-test-echo:e2e"
GATEWAY_API_CRDS := "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml"

default: list

list:
    @just --list

[group('check')]
check-fmt:
    cargo fmt --all -- --check

[group('check')]
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

[group('check')]
lint: check-fmt clippy

[group('test')]
test-unit:
    cargo test --workspace

[group('test')]
test-e2e:
    cargo test -p gateway-e2e -- --ignored --test-threads=1

[group('e2e')]
image-dp:
    docker build -f Dockerfile -t {{DP_IMAGE}} .

[group('e2e')]
image-cp:
    docker build -f Dockerfile.cp -t {{CP_IMAGE}} .

[group('e2e')]
image-echo:
    docker build -f e2e/Dockerfile.echo -t {{ECHO_IMAGE}} .

[group('e2e')]
images: image-dp image-cp image-echo

[group('e2e')]
up: images
    kind create cluster --name {{CLUSTER}} --config e2e/kind.yaml
    kind load docker-image {{DP_IMAGE}} {{CP_IMAGE}} {{ECHO_IMAGE}} --name {{CLUSTER}}
    kubectl apply -f {{GATEWAY_API_CRDS}}
    kubectl apply -f deploy/manifests/gatewayclass.yaml
    kubectl create namespace gateway-system --dry-run=client -o yaml | kubectl apply -f -
    kubectl apply -f deploy/manifests/controlplane/
    kubectl -n gateway-system wait --for=condition=available deployment/gateway-cp --timeout=120s

[group('e2e')]
down:
    kind delete cluster --name {{CLUSTER}}

[group('e2e')]
ci: up test-e2e down
