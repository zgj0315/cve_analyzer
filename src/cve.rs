use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

static CVE_DICT: &str = "./data/nvdcve-1.1-2022.json.zip";

pub async fn download_cve() -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new("./data");
    if !path.exists() {
        fs::create_dir(path).unwrap();
    }
    let path = Path::new(CVE_DICT);
    if path.exists() {
        println!(
            "{:?} exists, splitting download_cpe",
            path.file_name().unwrap()
        );
    } else {
        let mut file = match File::create(&path) {
            Err(e) => panic!("Error creating {}", e),
            Ok(file) => file,
        };
        let rsp = reqwest::get("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2022.json.zip")
            .await?;
        let rsp_bytes = rsp.bytes().await?;
        let _ = file.write_all(&rsp_bytes);
        println!("{:?} downloaded successfully", path.file_name().unwrap());
    }
    Ok(())
}

#[derive(Debug)]
pub struct Cpe23 {
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub update: String,
    pub edition: String,
    pub language: String,
    pub sw_edition: String,
    pub target_sw: String,
    pub target_hw: String,
    pub other: String,
}

impl Cpe23 {
    fn new(cpe23uri: &str) -> Cpe23 {
        let cpe23uri_vec: Vec<&str> = cpe23uri.split(":").collect();
        Cpe23 {
            part: cpe23uri_vec[2].to_owned(),
            vendor: cpe23uri_vec[3].to_owned(),
            product: cpe23uri_vec[4].to_owned(),
            version: cpe23uri_vec[5].to_owned(),
            update: cpe23uri_vec[6].to_owned(),
            edition: cpe23uri_vec[7].to_owned(),
            language: cpe23uri_vec[8].to_owned(),
            sw_edition: cpe23uri_vec[9].to_owned(),
            target_sw: cpe23uri_vec[10].to_owned(),
            target_hw: cpe23uri_vec[11].to_owned(),
            other: cpe23uri_vec[12].to_owned(),
        }
    }
}
fn match_node(cpe23_vec: &Vec<&Cpe23>, node: &serde_json::Value) -> bool {
    let operator = &node["operator"];
    let is_or = match operator.as_str().unwrap() {
        "OR" => true,
        _ => false,
    };
    // children存在是match_cpe为空，反之亦然
    match node["cpe_match"].as_array() {
        Some(cpe_match_vec) => {
            if cpe_match_vec.len() > 0 {
                let mut match_count = 0;
                for i in 0..cpe_match_vec.len() {
                    let cpe23uri = cpe_match_vec[i]["cpe23Uri"].as_str().unwrap();
                    let cpe23_node = Cpe23::new(cpe23uri);
                    for cpe23_input in cpe23_vec {
                        if cpe23_input.part == cpe23_node.part {
                            if cpe23_input.vendor == cpe23_node.vendor {
                                if cpe23_input.product == cpe23_node.product {
                                    let version_start_excluding =
                                        cpe_match_vec[i]["versionStartExcluding"].as_str();
                                    let version_end_excluding =
                                        cpe_match_vec[i]["versionEndExcluding"].as_str();
                                    // 没有标注开始结束版本
                                    if version_start_excluding == None
                                        && version_end_excluding == None
                                    {
                                        if cpe23_input.version == cpe23_node.version {
                                            if is_or {
                                                return true;
                                            } else {
                                                match_count += 1;
                                            }
                                        }
                                    }
                                    // 开始结束版本都标注
                                    if version_start_excluding != None
                                        && version_end_excluding != None
                                    {
                                        if cpe23_input
                                            .version
                                            .as_str()
                                            .ge(version_start_excluding.unwrap())
                                            && cpe23_input
                                                .version
                                                .as_str()
                                                .le(version_end_excluding.unwrap())
                                        {
                                            if is_or {
                                                return true;
                                            } else {
                                                match_count += 1;
                                            }
                                        }
                                    }
                                    // 只标注了开始版本
                                    if version_start_excluding != None {
                                        if cpe23_input
                                            .version
                                            .as_str()
                                            .ge(version_start_excluding.unwrap())
                                        {
                                            if is_or {
                                                return true;
                                            } else {
                                                match_count += 1;
                                            }
                                        }
                                    }
                                    // 只标注了结束版本
                                    if version_end_excluding != None {
                                        if cpe23_input
                                            .version
                                            .as_str()
                                            .le(version_end_excluding.unwrap())
                                        {
                                            if is_or {
                                                return true;
                                            } else {
                                                match_count += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // 如果是and，需要所有都匹配上
                if match_count == cpe_match_vec.len() {
                    return true;
                }
            }
        }
        None => {}
    }
    match node["children"].as_array() {
        Some(children) => {
            if children.len() > 0 {
                let mut match_count = 0;
                for i in 0..children.len() {
                    if match_node(cpe23_vec, &children[i]) {
                        if is_or {
                            return true;
                        } else {
                            match_count += 1;
                        }
                    }
                }
                // 如果是and，需要所有都匹配上
                if match_count == children.len() {
                    return true;
                }
            }
        }
        None => {}
    }
    false
}
pub async fn cve_match(
    cpe23_vec: &Vec<&Cpe23>,
    json: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("********* asset **********");
    for cpe23 in cpe23_vec {
        println!("{:?}", cpe23);
    }
    match json["CVE_Items"].as_array() {
        Some(cve_items) => {
            for i in 0..cve_items.len() {
                let nodes = &cve_items[i]["configurations"]["nodes"].as_array().unwrap();
                for j in 0..nodes.len() {
                    if match_node(&cpe23_vec, &nodes[j]) {
                        println!(
                            "matched cve: {}",
                            &cve_items[i]["cve"]["CVE_data_meta"]["ID"]
                        );
                    }
                }
            }
        }
        None => {
            println!("no CVE_Items");
        }
    }
    Ok(())
}

pub fn read_nvdcve() -> serde_json::Value {
    let zip_file = File::open(CVE_DICT).unwrap();
    let mut archive = zip::ZipArchive::new(zip_file).unwrap();
    let file = archive.by_name("nvdcve-1.1-2022.json").unwrap();
    serde_json::from_reader(file).unwrap()
}

#[derive(Debug)]
struct NvdCve {
    cve_data_type: String,
    cve_data_format: String,
    cve_data_version: String,
    cve_data_number_of_cves: String,
    cve_data_timestamp: String,
    cve_items: Vec<CveItem>,
}

#[derive(Debug)]
struct CveItem {
    cve: Cve,
    configurations: Configurations,
    impact: Impact,
    published_date: String,
    last_modified_date: String,
}

#[derive(Debug)]
struct Cve {
    data_type: String,
    data_format: String,
    data_version: String,
    cve_data_meta: CveDataMeta,
    problem_type: ProblemType,
    references: References,
    description: Description,
}

#[derive(Debug)]
struct CveDataMeta {
    id: String,
    assigner: String,
}

#[derive(Debug)]
struct ProblemType {
    problem_type_data: Vec<DescriptionData>,
}

#[derive(Debug)]
struct DescriptionData {
    lang: String,
    value: String,
}

#[derive(Debug)]
struct References {
    reference_data: Vec<ReferenceData>,
}

#[derive(Debug)]
struct ReferenceData {
    url: String,
    name: String,
    refsource: String,
    tags: Vec<String>,
}

#[derive(Debug)]
struct Description {
    description_data: Vec<DescriptionData>,
}

#[derive(Debug)]
struct Configurations {
    cve_data_version: String,
    nodes: Vec<Node>,
}

#[derive(Debug)]
struct Node {
    operator: String,
    children: Vec<Box<Node>>,
    cpe_match: Vec<CpeMatch>,
}

#[derive(Debug)]
struct CpeMatch {
    vulnerable: bool,
    cpe23_uri: String,
    cpe_name: Vec<String>,
}

#[derive(Debug)]
struct Impact {
    base_metric_v3: BaseMetricV3,
    base_metric_v2: BaseMetricV2,
}

#[derive(Debug)]
struct BaseMetricV3 {
    cvss_v3: CvssV3,
    exploitability_score: f64,
    impact_score: f64,
}

#[derive(Debug)]
struct CvssV3 {
    version: String,
    vector_string: String,
    attack_vector: String,
    attack_complexity: String,
    privileges_required: String,
    user_interaction: String,
    scope: String,
    confidentiality_impact: String,
    integrity_impact: String,
    availability_impact: String,
    base_score: f64,
    base_severity: String,
}

#[derive(Debug)]
struct BaseMetricV2 {
    cvss_v2: CvssV2,
    severity: String,
    exploitability_score: f64,
    impact_score: f64,
    ac_insuf_info: bool,
    obtain_all_privilege: bool,
    obtain_user_privilege: bool,
    obtain_other_privilege: bool,
    user_interaction_required: bool,
}

#[derive(Debug)]
struct CvssV2 {
    version: String,
    vector_string: String,
    attack_vector: String,
    attack_complexity: String,
    confidentiality_impact: String,
    integrity_impact: String,
    availability_impact: String,
    base_score: f64,
}

impl NvdCve {
    pub fn new(json: &serde_json::Value) -> NvdCve {
        let cve_data_type = json["CVE_data_type"].as_str().unwrap();
        let cve_data_format = json["CVE_data_format"].as_str().unwrap();
        let cve_data_version = json["CVE_data_version"].as_str().unwrap();
        let cve_data_number_of_cves = json["CVE_data_numberOfCVEs"].as_str().unwrap();
        let cve_data_timestamp = json["CVE_data_timestamp"].as_str().unwrap();
        let cve_items = json["CVE_Items"].as_array().unwrap();
        NvdCve {
            cve_data_type: cve_data_type.to_owned(),
            cve_data_format: cve_data_format.to_owned(),
            cve_data_version: cve_data_version.to_owned(),
            cve_data_number_of_cves: cve_data_number_of_cves.to_owned(),
            cve_data_timestamp: cve_data_timestamp.to_owned(),
            cve_items: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_download_cve() {
        let future = download_cve();
        let _ = tokio::join!(future);
    }

    #[tokio::test]
    async fn test_cve_match() {
        let json = read_nvdcve();
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
        let future = cve_match(&cpe23_vec, &json);
        let _ = tokio::join!(future);

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
        let future = cve_match(&cpe23_vec, &json);
        let _ = tokio::join!(future);
    }

    #[test]
    fn test_nvd_cve() {
        let json = read_nvdcve();
        let nvd_cve = NvdCve::new(&json);

        print!("nvd_cve: {:?}", nvd_cve);
    }
}
