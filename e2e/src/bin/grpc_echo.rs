//! Test gRPC backend. Serves the `echo.v1.GrpcEcho` service on h2c:
//! a unary echo (sized for large-message tests), a paced server
//! stream, and an always-failing method whose status must reach the
//! client in trailers.

use std::time::Duration;

use gateway_e2e::grpc::grpc_echo_server::{GrpcEcho, GrpcEchoServer};
use gateway_e2e::grpc::{Empty, Payload, StreamRequest, Tick};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

/// Well above the 100 MB the large-message test sends.
const MAX_MESSAGE_BYTES: usize = 128 * 1024 * 1024;

struct EchoService;

#[tonic::async_trait]
impl GrpcEcho for EchoService {
    async fn unary_echo(&self, req: Request<Payload>) -> Result<Response<Payload>, Status> {
        Ok(Response::new(req.into_inner()))
    }

    type ServerStreamStream = ReceiverStream<Result<Tick, Status>>;

    async fn server_stream(
        &self,
        req: Request<StreamRequest>,
    ) -> Result<Response<Self::ServerStreamStream>, Status> {
        let req = req.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            for seq in 0..u64::from(req.ticks) {
                if tx.send(Ok(Tick { seq })).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(u64::from(req.interval_ms))).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn fail(&self, _req: Request<Empty>) -> Result<Response<Empty>, Status> {
        Err(Status::internal("boom"))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let addr = "0.0.0.0:8080".parse()?;
    tracing::info!(%addr, "grpc echo listening");
    Server::builder()
        .add_service(
            GrpcEchoServer::new(EchoService)
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
        )
        .serve(addr)
        .await?;
    Ok(())
}
