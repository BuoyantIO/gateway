FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p gatewayd

FROM debian:bookworm-slim
COPY --from=builder /src/target/release/gatewayd /usr/local/bin/gatewayd
EXPOSE 7000
ENTRYPOINT ["/usr/local/bin/gatewayd"]
