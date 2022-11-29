use prost_build::Config;
fn main() -> std::io::Result<()> {
    Config::new()
        .compile_protos(&["proto/nvdcve.proto"], &["proto/"])
        .unwrap();
    Ok(())
}
