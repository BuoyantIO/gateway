//! gRPC through the gateway, end to end: trailers carry the status
//! across both hops, a 100 MB unary message round-trips, and a
//! long-lived server stream is untouched by unrelated route churn.
//! The backend is a real tonic server (`grpc_echo` in the echo test
//! image) reached over h2c via `appProtocol: grpc`.

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use gateway_e2e::fixtures::{apply_gateway, apply_http_route};
use gateway_e2e::grpc::grpc_echo_client::GrpcEchoClient;
use gateway_e2e::grpc::{Empty, Payload, StreamRequest};
use gateway_e2e::{
    Scope, delete_http_route, deploy_grpc_echo, gateway, gateway_address, http_route,
};
use tonic::Code;
use tonic::transport::Channel;

/// Matches the server's raised limit; the large-message test sends
/// 100 MB and tonic's default cap is 4 MB.
const MAX_MESSAGE_BYTES: usize = 128 * 1024 * 1024;

/// Provision gateway + route + gRPC backend in the scope's namespace
/// and return a connected client. Retries the first RPC path by
/// waiting for the route via a cheap unary call.
async fn setup(scope: &Scope) -> Result<GrpcEchoClient<Channel>> {
    let ns = scope.name();
    let client = scope.client();

    deploy_grpc_echo(client, ns, "grpc-echo").await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .path_prefix("/")
            .backend("grpc-echo", 8080)
            .build(),
    )
    .await?;

    let channel = Channel::from_shared(format!("http://{addr}"))
        .context("channel endpoint")?
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await
        .context("connecting gRPC channel through the gateway")?;
    let mut grpc = GrpcEchoClient::new(channel)
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES);

    // Wait until the route is programmed and the backend is up: a
    // small echo either succeeds or we retry until the deadline.
    let deadline = std::time::Instant::now() + Duration::from_mins(1);
    loop {
        match grpc
            .unary_echo(Payload {
                data: b"ping".to_vec(),
            })
            .await
        {
            Ok(_) => return Ok(grpc),
            Err(e) if std::time::Instant::now() < deadline => {
                tracing::debug!(error = %e, "gRPC not routable yet; retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e).context("gRPC route never became reachable"),
        }
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn grpc_status_travels_in_trailers() -> Result<()> {
    let scope = Scope::new("grpc-trailers").await?;
    let mut grpc = setup(&scope).await?;

    // A successful tonic response requires `grpc-status: 0` in the
    // trailers — if the gateway dropped trailer frames this call
    // would fail with a transport error, not succeed.
    let payload = b"trailer proof".to_vec();
    let echoed = grpc
        .unary_echo(Payload {
            data: payload.clone(),
        })
        .await?
        .into_inner();
    ensure!(echoed.data == payload, "echo payload mismatch");

    // Trailer *content* crosses too: code and message from the
    // backend's Status arrive intact at the client.
    let err = grpc
        .fail(Empty {})
        .await
        .expect_err("Fail must surface the backend status");
    ensure!(
        err.code() == Code::Internal,
        "expected INTERNAL, got {:?}",
        err.code()
    );
    ensure!(
        err.message() == "boom",
        "expected status message 'boom', got {:?}",
        err.message()
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn large_unary_round_trips() -> Result<()> {
    let scope = Scope::new("grpc-large").await?;
    let mut grpc = setup(&scope).await?;

    // 100 MB, patterned so a corruption shows up in the checksum.
    let size = 100 * 1024 * 1024;
    let data: Vec<u8> = (0..size).map(|i| u8::try_from(i % 251).unwrap()).collect();
    let sum_sent: u64 = data.iter().map(|b| u64::from(*b)).sum();

    let echoed = grpc.unary_echo(Payload { data }).await?.into_inner();
    ensure!(
        echoed.data.len() == size,
        "expected {size} bytes back, got {}",
        echoed.data.len()
    );
    let sum_back: u64 = echoed.data.iter().map(|b| u64::from(*b)).sum();
    ensure!(sum_back == sum_sent, "payload corrupted in transit");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn stream_survives_route_churn() -> Result<()> {
    let scope = Scope::new("grpc-churn").await?;
    let ns = scope.name();
    let client = scope.client();
    let mut grpc = setup(&scope).await?;

    // ~10s of ticks, consumed concurrently with config churn.
    let mut stream = grpc
        .server_stream(StreamRequest {
            ticks: 40,
            interval_ms: 250,
        })
        .await?
        .into_inner();
    let consumer = tokio::spawn(async move {
        let mut expected = 0u64;
        while let Some(tick) = stream.message().await? {
            anyhow::ensure!(
                tick.seq == expected,
                "tick out of order: got {}, expected {expected}",
                tick.seq
            );
            expected += 1;
        }
        Ok::<u64, anyhow::Error>(expected)
    });

    // Unrelated route churn while the stream runs: each create and
    // delete round-trips CP translate -> config push -> DP apply.
    for i in 0..4 {
        let name = format!("churn-{i}");
        apply_http_route(
            client,
            &http_route(ns, "gw", &name)
                .path_prefix(&format!("/churn-{i}"))
                .backend("grpc-echo", 8080)
                .build(),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(600)).await;
        delete_http_route(client, ns, &name).await?;
        tokio::time::sleep(Duration::from_millis(600)).await;
    }

    let ticks = consumer.await?.context("stream died during route churn")?;
    ensure!(ticks == 40, "expected 40 ticks, got {ticks}");
    Ok(())
}
