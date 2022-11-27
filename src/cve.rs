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
pub struct NvdCve {
    pub cve_data_type: String,
    pub cve_data_format: String,
    pub cve_data_version: String,
    pub cve_data_number_of_cves: String,
    pub cve_data_timestamp: String,
    pub cve_items: Vec<CveItem>,
}

impl NvdCve {
    pub fn new(json: &serde_json::Value) -> NvdCve {
        let cve_data_type = json["CVE_data_type"].as_str().unwrap().to_owned();
        let cve_data_format = json["CVE_data_format"].as_str().unwrap().to_owned();
        let cve_data_version = json["CVE_data_version"].as_str().unwrap().to_owned();
        let cve_data_number_of_cves = json["CVE_data_numberOfCVEs"].as_str().unwrap().to_owned();
        let cve_data_timestamp = json["CVE_data_timestamp"].as_str().unwrap().to_owned();
        let cve_items = &json["CVE_Items"];
        let cve_items = CveItem::new(&cve_items);
        NvdCve {
            cve_data_type,
            cve_data_format,
            cve_data_version,
            cve_data_number_of_cves,
            cve_data_timestamp,
            cve_items,
        }
    }
}
#[derive(Debug)]
pub struct CveItem {
    pub cve: Cve,
    pub configurations: Configurations,
    pub impact: Impact,
    pub published_date: String,
    pub last_modified_date: String,
}

impl CveItem {
    pub fn new(json: &serde_json::Value) -> Vec<CveItem> {
        let json = json.as_array().unwrap();
        let mut cve_items = Vec::new();
        for cve_item in json.iter() {
            let cve = &cve_item["cve"];
            let cve = Cve::new(cve);
            let configurations = &cve_item["configurations"];
            let configurations = Configurations::new(configurations);
            let impact = &cve_item["impact"];
            let impact = Impact::new(impact);
            let published_date = cve_item["publishedDate"].as_str().unwrap().to_owned();
            let last_modified_date = cve_item["lastModifiedDate"].as_str().unwrap().to_owned();
            let cve_item = CveItem {
                cve,
                configurations,
                impact,
                published_date,
                last_modified_date,
            };
            cve_items.push(cve_item);
        }
        cve_items
    }
}
#[derive(Debug)]
pub struct Cve {
    pub data_type: String,
    pub data_format: String,
    pub data_version: String,
    pub cve_data_meta: CveDataMeta,
    pub problem_type: ProblemType,
    pub references: References,
    pub description: Description,
}

impl Cve {
    pub fn new(json: &serde_json::Value) -> Cve {
        let data_type = json["data_type"].as_str().unwrap().to_owned();
        let data_format = json["data_format"].as_str().unwrap().to_owned();
        let data_version = json["data_version"].as_str().unwrap().to_owned();
        let cve_data_meta = &json["CVE_data_meta"];
        let cve_data_meta = CveDataMeta::new(cve_data_meta);
        let problem_type = &json["problemtype"];
        let problem_type = ProblemType::new(problem_type);
        let references = &json["references"];
        let references = References::new(references);
        let description = &json["description"];
        let description = Description::new(description);
        Cve {
            data_type,
            data_format,
            data_version,
            cve_data_meta,
            problem_type,
            references,
            description,
        }
    }
}

#[derive(Debug)]
pub struct CveDataMeta {
    pub id: String,
    pub assigner: String,
}

impl CveDataMeta {
    pub fn new(json: &serde_json::Value) -> CveDataMeta {
        let id = json["ID"].as_str().unwrap().to_owned();
        let assigner = json["ASSIGNER"].as_str().unwrap().to_owned();
        CveDataMeta { id, assigner }
    }
}
#[derive(Debug)]
pub struct ProblemType {
    pub problem_type_data: Vec<Vec<DescriptionData>>,
}

impl ProblemType {
    pub fn new(json: &serde_json::Value) -> ProblemType {
        let json = json["problemtype_data"].as_array().unwrap();
        let mut problem_type_data = Vec::new();
        for description_list in json {
            let description_list = description_list["description"].as_array().unwrap();
            let mut description_vec = Vec::new();
            for description in description_list {
                let description = DescriptionData::new(description);
                description_vec.push(description);
            }
            problem_type_data.push(description_vec);
        }
        ProblemType { problem_type_data }
    }
}
#[derive(Debug)]
pub struct DescriptionData {
    pub lang: String,
    pub value: String,
}

impl DescriptionData {
    pub fn new(json: &serde_json::Value) -> DescriptionData {
        let lang = json["lang"].as_str().unwrap().to_owned();
        let value = json["value"].as_str().unwrap().to_owned();
        DescriptionData { lang, value }
    }
}
#[derive(Debug)]
pub struct References {
    pub reference_data: Vec<ReferenceData>,
}

impl References {
    pub fn new(json: &serde_json::Value) -> References {
        let json = json["reference_data"].as_array().unwrap();
        let mut reference_data = Vec::new();
        for reference in json {
            reference_data.push(ReferenceData::new(reference));
        }
        References { reference_data }
    }
}

#[derive(Debug)]
pub struct ReferenceData {
    pub url: String,
    pub name: String,
    pub refsource: String,
    pub tags: Vec<String>,
}

impl ReferenceData {
    pub fn new(json: &serde_json::Value) -> ReferenceData {
        let url = json["url"].as_str().unwrap().to_owned();
        let name = json["name"].as_str().unwrap().to_owned();
        let refsource = json["refsource"].as_str().unwrap().to_owned();
        let json = json["tags"].as_array().unwrap();
        let mut tags = Vec::new();
        for tag in json {
            tags.push(tag.as_str().unwrap().to_owned());
        }
        ReferenceData {
            url,
            name,
            refsource,
            tags,
        }
    }
}
#[derive(Debug)]
pub struct Description {
    pub description_data: Vec<DescriptionData>,
}

impl Description {
    pub fn new(json: &serde_json::Value) -> Description {
        let json = json["description_data"].as_array().unwrap();
        let mut description_data = Vec::new();
        for description in json {
            description_data.push(DescriptionData::new(description));
        }
        Description { description_data }
    }
}

#[derive(Debug)]
pub struct Configurations {
    pub cve_data_version: String,
    pub nodes: Vec<Box<Node>>,
}

impl Configurations {
    pub fn new(json: &serde_json::Value) -> Configurations {
        let cve_data_version = json["CVE_data_version"].as_str().unwrap().to_owned();
        let nodes = &json["nodes"];
        let nodes = Node::new(nodes);
        Configurations {
            cve_data_version,
            nodes,
        }
    }
}
#[derive(Debug)]
pub struct Node {
    pub operator: String,
    pub children: Vec<Box<Node>>,
    pub cpe_match: Vec<CpeMatch>,
}

impl Node {
    pub fn new(json: &serde_json::Value) -> Vec<Box<Node>> {
        let json = json.as_array().unwrap();
        let mut node_vec = Vec::new();
        for node in json {
            let operator = node["operator"].as_str().unwrap().to_owned();
            let children = &node["children"];
            let children = Node::new(children);
            let cpe_match = &node["cpe_match"];
            let cpe_match = CpeMatch::new(cpe_match);
            node_vec.push(Box::new(Node {
                operator,
                children,
                cpe_match,
            }));
        }
        node_vec
    }
}
#[derive(Debug)]
pub struct CpeMatch {
    pub vulnerable: bool,
    pub cpe23_uri: String,
    pub version_start_excluding: Option<String>,
    pub version_end_excluding: Option<String>,
    pub cpe_name: Vec<String>,
}

impl CpeMatch {
    pub fn new(json: &serde_json::Value) -> Vec<CpeMatch> {
        let json = json.as_array().unwrap();
        let mut cpe_match_vec = Vec::new();
        for cpe_match in json {
            let vulnerable = cpe_match["vulnerable"].as_bool().unwrap();
            let cpe23_uri = cpe_match["cpe23Uri"].as_str().unwrap().to_owned();
            let version_start_excluding = cpe_match["versionStartExcluding"]
                .as_str()
                .to_owned()
                .map(|s| s.to_string());
            let version_end_excluding = cpe_match["versionEndExcluding"]
                .as_str()
                .to_owned()
                .map(|s| s.to_string());
            let cpe_name_list = cpe_match["cpe_name"].as_array().unwrap();
            let mut cpe_name = Vec::new();
            for name in cpe_name_list {
                cpe_name.push(name.as_str().unwrap().to_owned());
            }
            cpe_match_vec.push(CpeMatch {
                vulnerable,
                cpe23_uri,
                version_start_excluding,
                version_end_excluding,
                cpe_name,
            });
        }
        cpe_match_vec
    }
}
#[derive(Debug)]
pub struct Impact {
    pub base_metric_v3: BaseMetricV3,
    pub base_metric_v2: BaseMetricV2,
}

impl Impact {
    pub fn new(json: &serde_json::Value) -> Impact {
        let base_metric_v3 = &json["baseMetricV3"];
        let base_metric_v3 = BaseMetricV3::new(base_metric_v3);
        let base_metric_v2 = &json["baseMetricV2"];
        let base_metric_v2 = BaseMetricV2::new(base_metric_v2);
        Impact {
            base_metric_v3,
            base_metric_v2,
        }
    }
}

#[derive(Debug)]
pub struct BaseMetricV3 {
    pub cvss_v3: CvssV3,
    pub exploitability_score: Option<f64>,
    pub impact_score: Option<f64>,
}
impl BaseMetricV3 {
    pub fn new(json: &serde_json::Value) -> BaseMetricV3 {
        let cvss_v3 = &json["cvssV3"];
        let cvss_v3 = CvssV3::new(cvss_v3);
        let exploitability_score = json["exploitabilityScore"].as_f64().to_owned();
        let impact_score = json["impactScore"].as_f64().to_owned();
        BaseMetricV3 {
            cvss_v3,
            exploitability_score,
            impact_score,
        }
    }
}
#[derive(Debug)]
pub struct CvssV3 {
    pub version: Option<String>,
    pub vector_string: Option<String>,
    pub attack_vector: Option<String>,
    pub attack_complexity: Option<String>,
    pub privileges_required: Option<String>,
    pub user_interaction: Option<String>,
    pub scope: Option<String>,
    pub confidentiality_impact: Option<String>,
    pub integrity_impact: Option<String>,
    pub availability_impact: Option<String>,
    pub base_score: Option<f64>,
    pub base_severity: Option<String>,
}

impl CvssV3 {
    pub fn new(json: &serde_json::Value) -> CvssV3 {
        let version = json["version"].as_str().to_owned().map(|s| s.to_string());
        let vector_string = json["vectorString"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let attack_vector = json["attackVector"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let attack_complexity = json["attackComplexity"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let privileges_required = json["privilegesRequired"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let user_interaction = json["userInteraction"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let scope = json["scope"].as_str().to_owned().map(|s| s.to_string());
        let confidentiality_impact = json["confidentialityImpact"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let integrity_impact = json["integrityImpact"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let availability_impact = json["availabilityImpact"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let base_score = json["baseScore"].as_f64().to_owned();
        let base_severity = json["baseSeverity"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        CvssV3 {
            version,
            vector_string,
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            scope,
            confidentiality_impact,
            integrity_impact,
            availability_impact,
            base_score,
            base_severity,
        }
    }
}
#[derive(Debug)]
pub struct BaseMetricV2 {
    pub cvss_v2: CvssV2,
    pub severity: Option<String>,
    pub exploitability_score: Option<f64>,
    pub impact_score: Option<f64>,
    pub ac_insuf_info: Option<bool>,
    pub obtain_all_privilege: Option<bool>,
    pub obtain_user_privilege: Option<bool>,
    pub obtain_other_privilege: Option<bool>,
    pub user_interaction_required: Option<bool>,
}

impl BaseMetricV2 {
    pub fn new(json: &serde_json::Value) -> BaseMetricV2 {
        let cvss_v2 = &json["cvssV2"];
        let cvss_v2 = CvssV2::new(cvss_v2);
        let severity = json["severity"].as_str().to_owned().map(|s| s.to_string());
        let exploitability_score = json["exploitabilityScore"].as_f64().to_owned();
        let impact_score = json["impactScore"].as_f64().to_owned();
        let ac_insuf_info = json["acInsufInfo"].as_bool().to_owned();
        let obtain_all_privilege = json["obtainAllPrivilege"].as_bool().to_owned();
        let obtain_user_privilege = json["obtainUserPrivilege"].as_bool().to_owned();
        let obtain_other_privilege = json["obtainOtherPrivilege"].as_bool().to_owned();
        let user_interaction_required = json["userInteractionRequired"].as_bool().to_owned();
        BaseMetricV2 {
            cvss_v2,
            severity,
            exploitability_score,
            impact_score,
            ac_insuf_info,
            obtain_all_privilege,
            obtain_user_privilege,
            obtain_other_privilege,
            user_interaction_required,
        }
    }
}
#[derive(Debug)]
pub struct CvssV2 {
    pub version: Option<String>,
    pub vector_string: Option<String>,
    pub attack_vector: Option<String>,
    pub attack_complexity: Option<String>,
    pub confidentiality_impact: Option<String>,
    pub integrity_impact: Option<String>,
    pub availability_impact: Option<String>,
    pub base_score: Option<f64>,
}

impl CvssV2 {
    pub fn new(json: &serde_json::Value) -> CvssV2 {
        let version = json["version"].as_str().to_owned().map(|s| s.to_string());
        let vector_string = json["vectorString"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let attack_vector = json["attackVector"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let attack_complexity = json["attackComplexity"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let confidentiality_impact = json["confidentialityImpact"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let integrity_impact = json["integrityImpact"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let availability_impact = json["availabilityImpact"]
            .as_str()
            .to_owned()
            .map(|s| s.to_string());
        let base_score = json["baseScore"].as_f64().to_owned();
        CvssV2 {
            version,
            vector_string,
            attack_vector,
            attack_complexity,
            confidentiality_impact,
            integrity_impact,
            availability_impact,
            base_score,
        }
    }
}

pub fn print_cpe23uri(node: &Node) {
    for cpe_match in &node.cpe_match {
        println!("{}", cpe_match.cpe23_uri);
    }
    for children in &node.children {
        print_cpe23uri(children);
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
        println!("cve_itmes len: {}", nvd_cve.cve_items.len());
        for item in nvd_cve.cve_items.iter() {
            for node in item.configurations.nodes.iter() {
                print_cpe23uri(node);
            }
        }
    }
}
