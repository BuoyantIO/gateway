fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/bllmp.proto";
    tonic_prost_build::configure()
        // Server code is test-only (the fake picker the tests run
        // against); codegen cannot be gated per-cfg, so it is always
        // generated and compiled.
        .build_server(true)
        .build_client(true)
        // Body chunks as `Bytes`: the hooks hand chunks over without
        // copying into a Vec.
        .bytes(".")
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&[proto], &["proto"])?;
    println!("cargo:rerun-if-changed={proto}");
    Ok(())
}
