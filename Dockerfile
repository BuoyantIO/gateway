FROM rust:1-bookworm AS builder
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release --locked -p gatewayd

FROM debian:bookworm-slim
COPY --from=builder /src/target/release/gatewayd /usr/local/bin/gatewayd
ENTRYPOINT ["/usr/local/bin/gatewayd"]
