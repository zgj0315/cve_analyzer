use proto::{Configurations, CpeMatch, Cve, CveDataMeta, CveItem, Node, NvdCve};

mod proto {
    include!(concat!(env!("OUT_DIR"), "/cpe_match_cve.rs"));
}

impl NvdCve {
    fn new(json: &serde_json::Value) -> NvdCve {
        let cve_items = &json["CVE_Items"];
        let cve_items = CveItem::new(&cve_items);
        NvdCve { cve_items }
    }
}

impl CveItem {
    fn new(json: &serde_json::Value) -> Vec<CveItem> {
        let json = json.as_array().unwrap();
        let mut cve_items = Vec::new();
        for cve_item in json.iter() {
            let cve = &cve_item["cve"];
            let cve = Some(Cve::new(cve));
            let configurations = &cve_item["configurations"];
            let configurations = Some(Configurations::new(configurations));
            let cve_item = CveItem {
                cve,
                configurations,
            };
            cve_items.push(cve_item);
        }
        cve_items
    }
}

impl Cve {
    fn new(json: &serde_json::Value) -> Cve {
        let cve_data_meta = &json["CVE_data_meta"];
        let cve_data_meta = Some(CveDataMeta::new(cve_data_meta));
        Cve { cve_data_meta }
    }
}

impl CveDataMeta {
    fn new(json: &serde_json::Value) -> CveDataMeta {
        let id = json["ID"].as_str().unwrap().to_owned();
        CveDataMeta { id }
    }
}

impl Configurations {
    fn new(json: &serde_json::Value) -> Configurations {
        let nodes = &json["nodes"];
        let nodes = Node::new(nodes);
        Configurations { nodes }
    }
}

impl Node {
    fn new(json: &serde_json::Value) -> Vec<Node> {
        let json = json.as_array().unwrap();
        let mut node_vec = Vec::new();
        for node in json {
            let operator = node["operator"].as_str().unwrap().to_owned();
            let children = &node["children"];
            let children = Node::new(children);
            let cpe_match = &node["cpe_match"];
            let cpe_match = CpeMatch::new(cpe_match);
            node_vec.push(Node {
                operator,
                children,
                cpe_match,
            });
        }
        node_vec
    }
}

impl CpeMatch {
    fn new(json: &serde_json::Value) -> Vec<CpeMatch> {
        let json = json.as_array().unwrap();
        let mut cpe_match_vec = Vec::new();
        for cpe_match in json {
            let cpe23_uri = cpe_match["cpe23Uri"].as_str().unwrap().to_owned();
            let version_start_excluding = cpe_match["versionStartExcluding"]
                .as_str()
                .to_owned()
                .map(|s| s.to_string());
            let version_end_excluding = cpe_match["versionEndExcluding"]
                .as_str()
                .to_owned()
                .map(|s| s.to_string());
            cpe_match_vec.push(CpeMatch {
                cpe23_uri,
                version_start_excluding,
                version_end_excluding,
            });
        }
        cpe_match_vec
    }
}

fn read_nvdcve() -> serde_json::Value {
    let zip_file = std::fs::File::open("./data/nvdcve-1.1-2022.json.zip").unwrap();
    let mut archive = zip::ZipArchive::new(zip_file).unwrap();
    let file = archive.by_name("nvdcve-1.1-2022.json").unwrap();
    serde_json::from_reader(file).unwrap()
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{BufReader, Read, Write},
    };

    use prost::Message;
    use zip::write::FileOptions;

    use super::*;

    #[test]
    fn it_works() {
        let json = read_nvdcve();
        let cpe_match_cve = NvdCve::new(&json);
        let mut buf: Vec<u8> = Vec::new();
        cpe_match_cve.encode(&mut buf).unwrap();
        let zip_file = File::create("./data/cve_proto.cache.zip").unwrap();
        let mut zip_writer = zip::ZipWriter::new(zip_file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Bzip2)
            .unix_permissions(0o400);
        zip_writer.start_file("cve_proto.cache", options).unwrap();
        zip_writer.write_all(&buf).unwrap();
        zip_writer.finish().unwrap();

        println!("write to zip file");

        let zip_file = File::open("./data/cve_proto.cache.zip").unwrap();
        let mut zip_archive = zip::ZipArchive::new(zip_file).unwrap();
        let zip_file = zip_archive.by_name("cve_proto.cache").unwrap();
        let mut reader = BufReader::new(zip_file);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        let nvd_cve: NvdCve = prost::Message::decode(buf.as_slice()).unwrap();
        println!("nvd_cve read from file: {:?}", nvd_cve);
    }
}
