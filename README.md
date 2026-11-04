# Buoyant Gateway

The Buoyant Gateway is a Kubernetes Gateway API implementation in Rust.
It is built to serve inference traffic alongside
[Kinference](https://github.com/Kinference-AI/kinference), and it works
as a plain HTTP gateway without it.

The gateway has two parts. The control plane, gateway-cp, watches
`Gateway` and `HTTPRoute` resources and provisions one data-plane
Deployment for each `Gateway` that it owns. The data plane, gatewayd,
terminates TLS, matches each request to a route, runs the route's
filters and proxies the request to a backend.

Config flows one way, from the control plane to the data planes, over a
streaming gRPC channel. Nothing in the data plane reads Kubernetes.

Everything that touches a request is an extension, including the
Gateway API core filters. Kinference attaches as the
`kinference_selector` extension: the data plane streams the request body
to the Kinference Picker and dispatches the request to the endpoint that
the Picker returns.

## Quick start

See [the Kinference getting started
guide](https://kinference.ai/docs/getting-started/), which installs the
gateway charts and Kinference together.

## Documentation

- [Architecture](ARCHITECTURE.md): the map of the code. Vocabulary,
  what each crate owns, and where new code goes.
- [Request flow](docs/request-flow.md): how each binary boots, one
  request from the accepted socket to the end of the response, and the
  loops that keep the config current.
- [Local development](docs/local-development.md): how to build, run and
  test the gateway on a kind cluster.
- [Contributing](CONTRIBUTING.md): how to contribute to the project.

## CRDs

The gateway configures itself from the Gateway API resources and from
three custom resources of its own in the `gateway.linkerd.io` group.
`GatewayBackend` names a destination outside the cluster, `Extension`
names a filter implementation and its config, and `BackendBinding`
resolves a backend ref of a kind that the gateway has no schema for. The
schemas are in [charts/gateway-crds](charts/gateway-crds/templates). See
[the Kinference CRD reference](https://kinference.ai/docs/reference/crds/)
for the `GatewayBackend` documentation.

## Known limitations

The gateway is alpha software. It has not seen sustained production
exposure. Run at your own risk.

The current implementation lacks several parts of the Gateway API,
including:

* `TCPRoute`, `TLSRoute` and `GRPCRoute`. The control plane watches
  `HTTPRoute` only.
* `allowedRoutes` enforcement. A route attaches to any listener that
  its parentRef selects.
* `ReferenceGrant` enforcement. A cross-namespace certificateRef is
  accepted without a grant.

## Copyright and license

The Buoyant Gateway is copyright 2026 Buoyant, Inc.

The Buoyant Gateway is licensed under the Apache License, Version 2.0
(the "License"); you may not use these files except in compliance with
the License. You may obtain a copy of the License at
https://www.apache.org/licenses/LICENSE-2.0 .

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
