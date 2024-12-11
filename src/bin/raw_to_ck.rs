use clickhouse::Client;
use cve_analyzer::{CveRow, NvdRow, CVE_DATA_PATH, NVD_DATA_PATH};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::{BufReader, Cursor, Read},
    path::Path,
    thread,
};
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use tokio::sync::mpsc::Sender;
use zip::ZipArchive;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_line_number(true).init();
    let client = clickhouse::Client::default()
        .with_url("http://127.0.0.1:8123")
        .with_database("analyze_ck_db")
        .with_user("username_cyberkl")
        .with_password("password_cyberkl");
    ddl(&client).await?;
    let _ = tokio::join!(cve_json_to_ck(&client), nvd_json_to_ck(&client));
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

fn read_cve_json(tx: Sender<CveRow>) -> anyhow::Result<()> {
    let path = CVE_DATA_PATH.join("cves.zip.zip");
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut archive = ZipArchive::new(reader)?;
    let mut cves_zip = archive.by_name("cves.zip")?;
    let mut buf = Vec::new();
    cves_zip.read_to_end(&mut buf)?;
    let mut archive = ZipArchive::new(Cursor::new(buf))?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.is_file() && file.name().starts_with("cves/") && file.name().ends_with(".json") {
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            let json: Value = serde_json::from_slice(&buf)?;
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
                // log::warn!("illegal file: {:?}", file.name());
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
            // if state.eq("REJECTED") {
            //     // log::info!("ignore rejected cve: {}", cve_id);
            //     continue;
            // }
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
                adp_references,
                adp_affected: adp_affecteds,
                adp_metrics: adp_meterics,
            };
            tx.blocking_send(cve_row)?;
        }
    }
    Ok(())
}

async fn cve_json_to_ck(client: &Client) -> anyhow::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    thread::spawn(|| read_cve_json(tx));
    let mut insert = client.insert("tbl_cve")?;
    let mut count = 0;
    let mut ts_last = chrono::Utc::now().timestamp_millis();
    while let Some(row) = rx.recv().await {
        insert.write(&row).await?;
        count += 1;
        let ts_now = chrono::Utc::now().timestamp_millis();
        let ts_delta = ts_now - ts_last;
        if count % 10 == 0 && ts_delta >= 3_000 {
            log::info!(
                "cve speed {}, channel: {}",
                (count * 1_000) / ts_delta,
                rx.capacity()
            );
            ts_last = ts_now;
            count = 0;
        }
    }
    insert.end().await?;
    Ok(())
}

fn clean_datetime(mut input: String) -> String {
    if input.is_empty() {
        return "1970-01-01T00:00:00.000Z".to_string();
    }
    if input.ends_with('Z') {
        input
    } else {
        if input.contains('.') {
            input.push('Z');
        } else {
            input.push_str(".000Z");
        }
        input
    }
}

async fn nvd_json_to_ck(client: &Client) -> anyhow::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    thread::spawn(|| read_nvd_json(tx));
    let mut insert = client.insert("tbl_nvd")?;
    let mut count = 0;
    let mut ts_last = chrono::Utc::now().timestamp_millis();
    while let Some(row) = rx.recv().await {
        insert.write(&row).await?;
        count += 1;
        let ts_now = chrono::Utc::now().timestamp_millis();
        let ts_delta = ts_now - ts_last;
        if count % 10 == 0 && ts_delta >= 3_000 {
            log::info!(
                "nvd speed {}, channel: {}",
                (count * 1_000) / ts_delta,
                rx.capacity()
            );
            ts_last = ts_now;
            count = 0;
        }
    }
    insert.end().await?;
    Ok(())
}

fn read_nvd_json(tx: Sender<NvdRow>) -> anyhow::Result<()> {
    for entry in fs::read_dir(NVD_DATA_PATH.as_path())? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name().into_string().unwrap_or_default();
        if path.is_file() && file_name.starts_with("nvdcve-1.1-") && file_name.ends_with(".json.gz")
        {
            let file_gz = File::open(&path)?;
            let gz_decoder = flate2::read::GzDecoder::new(file_gz);
            let v: Value = serde_json::from_reader(gz_decoder).unwrap();
            if let Some(cve_items) = v["CVE_Items"].as_array() {
                for cve_item in cve_items {
                    let cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
                        .as_str()
                        .map(String::from)
                        .unwrap_or_default();
                    let cve = cve_item["cve"]
                        .as_str()
                        .map(String::from)
                        .unwrap_or_default();
                    let configurations = cve_item["configurations"]
                        .as_str()
                        .map(String::from)
                        .unwrap_or_default();
                    let impact = cve_item["impact"]
                        .as_str()
                        .map(String::from)
                        .unwrap_or_default();
                    let published_date = cve_item["publishedDate"]
                        .as_str()
                        .map(String::from)
                        .unwrap_or_default();
                    let published_date =
                        OffsetDateTime::parse(&clean_datetime(published_date), &Iso8601::DEFAULT)?;
                    let last_modified_date = cve_item["lastModifiedDate"]
                        .as_str()
                        .map(String::from)
                        .unwrap_or_default();
                    let last_modified_date = OffsetDateTime::parse(
                        &clean_datetime(last_modified_date),
                        &Iso8601::DEFAULT,
                    )?;
                    let nvd_row = NvdRow {
                        cve_id,
                        cve,
                        configurations,
                        impact,
                        published_date,
                        last_modified_date,
                    };
                    tx.blocking_send(nvd_row)?;
                }
            };
        }
    }
    Ok(())
}
