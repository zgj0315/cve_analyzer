mod cve;
mod lib;
mod nvd_cve;
use cve::{cve_match, download_cve, read_nvdcve, Cpe23};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    download_cve().await?;
    println!("read nvdcve file...");
    let json = read_nvdcve();
    println!("read nvdcve file finished");

    // 2 and
    let mut cpe23_vec = Vec::new();
    let cpe23 = Cpe23 {
        part: "a".to_string(),
        vendor: "amazon".to_string(),
        product: "log4jhotpatch".to_string(),
        version: "1.1-16".to_string(),
        update: "".to_string(),
        edition: "".to_string(),
        language: "".to_string(),
        sw_edition: "".to_string(),
        target_sw: "".to_string(),
        target_hw: "".to_string(),
        other: "".to_string(),
    };
    cpe23_vec.push(&cpe23);
    let cpe23 = Cpe23 {
        part: "a".to_string(),
        vendor: "linux".to_string(),
        product: "linux_kernel".to_string(),
        version: "-".to_string(),
        update: "".to_string(),
        edition: "".to_string(),
        language: "".to_string(),
        sw_edition: "".to_string(),
        target_sw: "".to_string(),
        target_hw: "".to_string(),
        other: "".to_string(),
    };
    cpe23_vec.push(&cpe23);
    cve_match(&cpe23_vec, &json).await?;

    // or
    let mut cpe23_vec = Vec::new();
    let cpe23 = Cpe23 {
        part: "o".to_string(),
        vendor: "microsoft".to_string(),
        product: "windows_server_2012".to_string(),
        version: "r2".to_string(),
        update: "".to_string(),
        edition: "".to_string(),
        language: "".to_string(),
        sw_edition: "".to_string(),
        target_sw: "".to_string(),
        target_hw: "".to_string(),
        other: "".to_string(),
    };
    cpe23_vec.push(&cpe23);
    cve_match(&cpe23_vec, &json).await?;

    Ok(())
}
