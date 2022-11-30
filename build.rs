use prost_build::Config;
fn main() -> std::io::Result<()> {
    Config::new()
        .compile_protos(
            &["proto/nvdcve.proto", "proto/cpe_match_cve.proto"],
            &["proto/"],
        )
        .unwrap();
    Ok(())
}
