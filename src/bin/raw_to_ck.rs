use std::{
    fs::{self, File},
    io::BufReader,
    path::Path,
};

use clickhouse::Client;
use cve_analyzer::{CveRow, CVE_DATA_PATH};
use serde_json::Value;
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use walkdir::WalkDir;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_line_number(true).init();
    let client = clickhouse::Client::default()
        .with_url("http://127.0.0.1:8123")
        .with_database("analyze_ck_db")
        .with_user("username_cyberkl")
        .with_password("password_cyberkl");
    ddl(&client).await?;
    cve_json_to_ck(&client).await?;
    Ok(())
}

async fn ddl(client: &Client) -> anyhow::Result<()> {
    let sql_path = if let Some(parent_path) = Path::new(file!()).parent() {
        parent_path.join("ck_ddl.sql")
    } else {
        log::error!("parent_path is none");
        return Err(anyhow::anyhow!("parent_path is none"));
    };
    let ddl_sql = fs::read_to_string(sql_path)?;
    let ddl_sqls: Vec<_> = ddl_sql.split(';').collect();
    for sql in ddl_sqls {
        if !sql.trim().is_empty() {
            client.query(sql).execute().await?;
        }
    }
    Ok(())
}

async fn cve_json_to_ck(client: &Client) -> anyhow::Result<()> {
    let mut insert_cve = client.insert("tbl_cve")?;
    for entry in WalkDir::new(CVE_DATA_PATH.as_path()) {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .map(|s| s.starts_with("CVE-") && s.ends_with(".json"))
            .unwrap_or(false)
        {
            let file = File::open(entry.path())?;
            let reader = BufReader::new(file);
            let json: Value = serde_json::from_reader(reader)?;
            let mut vendors = Vec::new();
            let mut products = Vec::new();
            let mut versions = Vec::new();

            if let Some(affected) = json["containers"]["cna"]["affected"].as_array() {
                for v in affected {
                    vendors.push(v["vendor"].as_str().map(String::from).unwrap_or_default());
                    products.push(v["product"].as_str().map(String::from).unwrap_or_default());
                    versions.push(v["versions"].as_str().map(String::from).unwrap_or_default());
                }
            }
            let mut adp_provider_metadatas = Vec::new();
            let mut adp_titles = Vec::new();
            let mut adp_references = Vec::new();
            let mut adp_affecteds = Vec::new();
            let mut adp_meterics = Vec::new();
            if let Some(adp) = json["containers"]["cna"]["adp"].as_array() {
                for v in adp {
                    adp_provider_metadatas.push(
                        v["providerMetadata"]
                            .as_str()
                            .map(String::from)
                            .unwrap_or_default(),
                    );
                    adp_titles.push(v["title"].as_str().map(String::from).unwrap_or_default());
                    adp_references.push(
                        v["references"]
                            .as_str()
                            .map(String::from)
                            .unwrap_or_default(),
                    );
                    adp_affecteds
                        .push(v["affected"].as_str().map(String::from).unwrap_or_default());
                    adp_meterics.push(v["meterics"].as_str().map(String::from).unwrap_or_default());
                }
            }
            let data_type = json["dataType"]
                .as_str()
                .map(String::from)
                .unwrap_or_default();
            let data_version = json["dataVersion"]
                .as_str()
                .map(String::from)
                .unwrap_or_default();
            let cve_id = json["cveMetadata"]["cveId"]
                .as_str()
                .map(String::from)
                .unwrap_or_default();
            if cve_id.is_empty() {
                log::warn!("illegal file: {:?}", entry.path());
                continue;
            }
            // log::info!("cve_id: {cve_id}");
            let assigner_org_id = json["cveMetadata"]["assignerOrgId"]
                .as_str()
                .map(String::from)
                .unwrap_or_default();
            let state = json["cveMetadata"]["state"]
                .as_str()
                .map(String::from)
                .unwrap_or_default();
            let assigner_short_name = json["cveMetadata"]["assignerShortName"]
                .as_str()
                .map(String::from)
                .unwrap_or_default();
            let date_reserved = json["cveMetadata"]["dateReserved"]
                .as_str()
                .map(String::from)
                .unwrap_or_default();
            let date_reserved =
                OffsetDateTime::parse(&clean_datetime(date_reserved), &Iso8601::DEFAULT)?;
            let date_published = json["cveMetadata"]["datePublished"]
                .as_str()
                .map(String::from)
                .unwrap_or_default();
            let date_published =
                OffsetDateTime::parse(&clean_datetime(date_published), &Iso8601::DEFAULT)?;
            let date_updated = json["cveMetadata"]["dateUpdated"]
                .as_str()
                .map(String::from)
                .unwrap_or_default();
            let date_updated =
                OffsetDateTime::parse(&clean_datetime(date_updated), &Iso8601::DEFAULT)?;
            let cna_provider_metadata = json["containers"]["cna"]["providerMetadata"]
                .as_str()
                .map(String::from)
                .unwrap_or_default();
            let cna_title = json["containers"]["cna"]["title"]
                .as_str()
                .map(String::from)
                .unwrap_or_default();
            let cve_row = CveRow {
                data_type,
                data_version,
                cve_id,
                assigner_org_id,
                state,
                assigner_short_name,
                date_reserved,
                date_published,
                date_updated,
                cna_provider_metadata,
                cna_title,
                cna_affected_vendor: vendors,
                cna_affected_product: products,
                cna_affected_versions: versions,
                adp_provider_metadata: adp_provider_metadatas,
                adp_title: adp_titles,
                adp_references: adp_references,
                adp_affected: adp_affecteds,
                adp_metrics: adp_meterics,
            };
            insert_cve.write(&cve_row).await?;
        }
    }
    insert_cve.end().await?;
    Ok(())
}

fn clean_datetime(mut input: String) -> String {
    if input.is_empty() {
        return "1970-01-01T00:00:00.000Z".to_string();
    }
    if input.ends_with('Z') {
        return input;
    } else {
        if input.contains('.') {
            input.push_str("Z");
        } else {
            input.push_str(".000Z");
        }
        return input;
    }
}
