use chrono::Datelike;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufReader, Read, Write},
    path::PathBuf,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_line_number(true).init();
    // nvd
    let raw_data_path = PathBuf::from("./data/nvd_raw_data/");
    fs::create_dir_all(&raw_data_path)?;
    let start_year = 2002;
    let end_year = chrono::Utc::now().year();
    for year in start_year..=end_year {
        let url_meta = format!(
            "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.meta",
            year
        );
        let rsp = reqwest::get(&url_meta).await?;
        if rsp.status().is_success() {
            let meta = rsp.text().await?;
            if let Some((_, sha256_lastest)) = meta.trim_end().split_once("sha256:") {
                let file_name_gz = format!("nvdcve-1.1-{}.json.gz", year);
                let path_gz = raw_data_path.join(&file_name_gz);
                if path_gz.exists() {
                    let file_gz = File::open(&path_gz)?;
                    let gz_decoder = flate2::read::GzDecoder::new(file_gz);
                    let mut buf_reader = BufReader::new(gz_decoder);
                    let mut buf = Vec::new();
                    buf_reader.read_to_end(&mut buf)?;
                    let sha256_local = hex::encode_upper(Sha256::digest(buf));
                    let sha256_local = sha256_local.as_str();
                    if sha256_local == sha256_lastest {
                        log::info!("{} is lastest", file_name_gz);
                        continue;
                    }
                }
                let url_gz = format!("https://nvd.nist.gov/feeds/json/cve/1.1/{}", file_name_gz);
                log::info!("download {}", &file_name_gz);
                let rsp = reqwest::get(&url_gz).await?;
                let rsp_bytes = rsp.bytes().await?;
                let mut file_gz = File::create(path_gz)?;
                file_gz.write_all(&rsp_bytes)?;
                log::info!("save {}", &file_name_gz);
            };
        } else {
            log::error!("download meta err: {:?}", rsp);
        }
    }

    // // cve
    // let cve_data_path = PathBuf::from("./data/cve_raw_data/");
    // fs::create_dir_all(&cve_data_path)?;
    // let cve_zip = cve_data_path.join("cvelistV5-main.zip");
    // let url_cve = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip";
    // let rsp = reqwest::get(url_cve).await?;
    // let rsp_bytes = rsp.bytes().await?;
    // let mut file = File::create(&cve_zip)?;
    // file.write_all(&rsp_bytes)?;
    // log::info!("save {:?}", &cve_zip.file_name());
    Ok(())
}
