# syntax=docker/dockerfile:1.4
FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates protobuf-compiler \
        gcc-x86-64-linux-gnu libc6-dev-amd64-cross \
        gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
    && rm -rf /var/lib/apt/lists/*
ENV CARGO_NET_RETRY=10
ENV RUSTUP_MAX_RETRIES=10
ENV CARGO_INCREMENTAL=0
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
COPY . .
ARG TARGETARCH

RUN --mount=type=cache,id=cargo-$TARGETARCH,target=/usr/local/cargo/registry \
    target=$(case "$TARGETARCH" in \
        amd64) echo x86_64-unknown-linux-gnu ;; \
        arm64) echo aarch64-unknown-linux-gnu ;; \
        *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac) \
    && rustup target add "$target" \
    && cargo build --release --locked -p gatewayd --target "$target" \
    && cp "/src/target/$target/release/gatewayd" /usr/local/bin/gatewayd

FROM debian:bookworm-slim
# The platform trust store a dialable backend verifies its upstream
# against by default.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/local/bin/gatewayd /usr/local/bin/gatewayd
ENTRYPOINT ["/usr/local/bin/gatewayd"]
