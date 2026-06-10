# syntax=docker/dockerfile:1.4
FROM rust:1-bookworm AS builder
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
ENV CARGO_NET_RETRY=10
ENV RUSTUP_MAX_RETRIES=10
ENV CARGO_INCREMENTAL=0
COPY . .
RUN --mount=type=cache,id=cargo,target=/usr/local/cargo/registry \
    cargo build --release --locked -p gateway-cp \
    && cp /src/target/release/gateway-cp /usr/local/bin/gateway-cp

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/gateway-cp /usr/local/bin/gateway-cp
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/gateway-cp"]
