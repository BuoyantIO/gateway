fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/bllmp.proto";
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        // Body chunks as `Bytes`: the hooks hand chunks over without
        // copying into a Vec.
        .bytes(".")
        .compile_protos(&[proto], &["proto"])?;
    println!("cargo:rerun-if-changed={proto}");
    Ok(())
}
