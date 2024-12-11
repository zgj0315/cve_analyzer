use std::{fs, path::PathBuf};

use once_cell::sync::Lazy;
use serde::Serialize;
use time::OffsetDateTime;

pub static CVE_DATA_PATH: Lazy<PathBuf> = Lazy::new(|| {
    let cve_data_path = PathBuf::from("./data/cve_raw_data/");
    fs::create_dir_all(&cve_data_path).unwrap_or_default();
    cve_data_path
});
pub static NVD_DATA_PATH: Lazy<PathBuf> = Lazy::new(|| {
    let nvd_data_path = PathBuf::from("./data/nvd_raw_data/");
    fs::create_dir_all(&nvd_data_path).unwrap_or_default();
    nvd_data_path
});

#[derive(clickhouse::Row, Serialize, Debug)]
pub struct CveRow {
    pub data_type: String,
    pub data_version: String,

    // cveMetadata
    pub cve_id: String,
    pub assigner_org_id: String,
    pub state: String,
    pub assigner_short_name: String,
    #[serde(with = "clickhouse::serde::time::datetime")]
    pub date_reserved: OffsetDateTime,
    #[serde(with = "clickhouse::serde::time::datetime")]
    pub date_published: OffsetDateTime,
    #[serde(with = "clickhouse::serde::time::datetime")]
    pub date_updated: OffsetDateTime,

    // containers.cna
    pub cna_provider_metadata: String,
    pub cna_title: String,
    #[serde(rename = "cna_affected.vendor")]
    pub cna_affected_vendor: Vec<String>,
    #[serde(rename = "cna_affected.product")]
    pub cna_affected_product: Vec<String>,
    #[serde(rename = "cna_affected.versions")]
    pub cna_affected_versions: Vec<String>,

    // containers.adp
    #[serde(rename = "adp.provider_metadata")]
    pub adp_provider_metadata: Vec<String>,
    #[serde(rename = "adp.title")]
    pub adp_title: Vec<String>,
    #[serde(rename = "adp.references")]
    pub adp_references: Vec<String>,
    #[serde(rename = "adp.affected")]
    pub adp_affected: Vec<String>,
    #[serde(rename = "adp.metrics")]
    pub adp_metrics: Vec<String>,
}

#[derive(clickhouse::Row, Serialize, Debug)]
pub struct NvdRow {
    pub cve_id: String,
    pub cve: String,
    pub configurations: String,
    pub impact: String,
    #[serde(with = "clickhouse::serde::time::datetime")]
    pub published_date: OffsetDateTime,
    #[serde(with = "clickhouse::serde::time::datetime")]
    pub last_modified_date: OffsetDateTime,
}
