use chrono::{Datelike, Duration, Timelike};
use cve_analyzer::{CVE_DATA_PATH, NVD_DATA_PATH};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufReader, Read, Write},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_line_number(true).init();
    let _ = tokio::join!(download_from_nvd(), download_from_cve());
    Ok(())
}

async fn download_from_cve() -> anyhow::Result<()> {
    let cve_zip = CVE_DATA_PATH.join("cves.zip.zip");
    let mut dt = chrono::Utc::now();
    if dt.hour() == 0 {
        dt -= Duration::hours(1);
    }
    let now_year = dt.year();
    let now_month = dt.month();
    let now_day = dt.day();
    let now_hour = dt.hour() - 1;

    let yyyy_mm_dd = format!("{}-{:02}-{:02}", now_year, now_month, now_day);
    // https://github.com/CVEProject/cvelistV5/releases/download/cve_2024-12-09_0500Z/2024-12-09_all_CVEs_at_midnight.zip.zip
    let url = format!("https://github.com/CVEProject/cvelistV5/releases/download/cve_{}_{:02}00Z/{}_all_CVEs_at_midnight.zip.zip",
            yyyy_mm_dd, now_hour, yyyy_mm_dd);
    log::info!("downloading {url}");
    let rsp = reqwest::get(url).await?;
    let rsp_bytes = rsp.bytes().await?;
    let mut file = File::create(&cve_zip)?;
    file.write_all(&rsp_bytes)?;
    log::info!("save {:?}", &cve_zip.file_name());
    Ok(())
}

async fn download_from_nvd() -> anyhow::Result<()> {
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
                let path_gz = NVD_DATA_PATH.join(&file_name_gz);
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
                log::info!("downloading {}", &url_gz);
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
    Ok(())
}
