fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/gateway/controlplane/v1/config_stream.proto";
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto], &["proto"])?;
    println!("cargo:rerun-if-changed={proto}");
    Ok(())
}
