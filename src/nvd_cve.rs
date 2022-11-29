use self::proto::{
    BaseMetricV2, BaseMetricV3, Configurations, CpeMatch, Cve, CveDataMeta, CveItem, CvssV2,
    CvssV3, Description, DescriptionData, Impact, Node, NvdCve, ProblemType, ReferenceData,
    References,
};

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/nvdcve.rs"));
}

impl NvdCve {
    fn from(json: &serde_json::Value) -> NvdCve {
        let cve_data_type = json["CVE_data_type"].as_str().unwrap().to_owned();
        let cve_data_format = json["CVE_data_format"].as_str().unwrap().to_owned();
        let cve_data_version = json["CVE_data_version"].as_str().unwrap().to_owned();
        let cve_data_number_of_cves = json["CVE_data_numberOfCVEs"].as_str().unwrap().to_owned();
        let cve_data_timestamp = json["CVE_data_timestamp"].as_str().unwrap().to_owned();
        let cve_items = &json["CVE_Items"];
        let cve_items = CveItem::from(&cve_items);
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

impl CveItem {
    fn from(json: &serde_json::Value) -> Vec<CveItem> {
        let json = json.as_array().unwrap();
        let mut cve_items = Vec::new();
        for cve_item in json.iter() {
            let cve = &cve_item["cve"];
            let cve = Some(Cve::from(cve));
            let configurations = &cve_item["configurations"];
            let configurations = Some(Configurations::from(configurations));
            let impact = &cve_item["impact"];
            let impact = Some(Impact::from(impact));
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

impl Cve {
    fn from(json: &serde_json::Value) -> Cve {
        let data_type = json["data_type"].as_str().unwrap().to_owned();
        let data_format = json["data_format"].as_str().unwrap().to_owned();
        let data_version = json["data_version"].as_str().unwrap().to_owned();
        let cve_data_meta = &json["CVE_data_meta"];
        let cve_data_meta = Some(CveDataMeta::from(cve_data_meta));
        let problem_type = &json["problemtype"];
        let problem_type = Some(ProblemType::from(problem_type));
        let references = &json["references"];
        let references = Some(References::from(references));
        let description = &json["description"];
        let description = Some(Description::from(description));
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

impl CveDataMeta {
    fn from(json: &serde_json::Value) -> CveDataMeta {
        let id = json["ID"].as_str().unwrap().to_owned();
        let assigner = json["ASSIGNER"].as_str().unwrap().to_owned();
        CveDataMeta { id, assigner }
    }
}

impl ProblemType {
    fn from(json: &serde_json::Value) -> ProblemType {
        let json = json["problemtype_data"].as_array().unwrap();
        let mut problem_type_data = Vec::new();
        for description_list in json {
            let description_list = description_list["description"].as_array().unwrap();
            let mut description_vec = Vec::new();
            for description in description_list {
                let description = DescriptionData::from(description);
                description_vec.push(description);
            }
            problem_type_data.push(description_vec);
        }
        // ProblemType { problem_type_data }
        todo!();
        ProblemType::default()
    }
}

impl DescriptionData {
    fn from(json: &serde_json::Value) -> DescriptionData {
        let lang = json["lang"].as_str().unwrap().to_owned();
        let value = json["value"].as_str().unwrap().to_owned();
        DescriptionData { lang, value }
    }
}

impl References {
    fn from(json: &serde_json::Value) -> References {
        let json = json["reference_data"].as_array().unwrap();
        let mut reference_data = Vec::new();
        for reference in json {
            reference_data.push(ReferenceData::from(reference));
        }
        References { reference_data }
    }
}

impl ReferenceData {
    fn from(json: &serde_json::Value) -> ReferenceData {
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

impl Description {
    fn from(json: &serde_json::Value) -> Description {
        let json = json["description_data"].as_array().unwrap();
        let mut description_data = Vec::new();
        for description in json {
            description_data.push(DescriptionData::from(description));
        }
        Description { description_data }
    }
}

impl Configurations {
    fn from(json: &serde_json::Value) -> Configurations {
        let cve_data_version = json["CVE_data_version"].as_str().unwrap().to_owned();
        let nodes = &json["nodes"];
        let nodes = Node::from(nodes);
        Configurations {
            cve_data_version,
            nodes,
        }
    }
}

impl Node {
    fn from(json: &serde_json::Value) -> Vec<Node> {
        let json = json.as_array().unwrap();
        let mut node_vec = Vec::new();
        for node in json {
            let operator = node["operator"].as_str().unwrap().to_owned();
            let children = &node["children"];
            let children = Node::from(children);
            let cpe_match = &node["cpe_match"];
            let cpe_match = CpeMatch::from(cpe_match);
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
    fn from(json: &serde_json::Value) -> Vec<CpeMatch> {
        let json = json.as_array().unwrap();
        let mut cpe_match_vec = Vec::new();
        for cpe_match in json {
            let vulnerable = cpe_match["vulnerable"].as_bool().unwrap();
            let cpe23_uri = cpe_match["cpe23Uri"].as_str().unwrap().to_owned();
            let version_start_excluding = cpe_match["versionStartExcluding"]
                .as_str()
                .unwrap()
                .to_owned();
            let version_end_excluding = cpe_match["versionEndExcluding"]
                .as_str()
                .unwrap()
                .to_owned();
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

impl Impact {
    fn from(json: &serde_json::Value) -> Impact {
        let base_metric_v3 = &json["baseMetricV3"];
        let base_metric_v3 = Some(BaseMetricV3::from(base_metric_v3));
        let base_metric_v2 = &json["baseMetricV2"];
        let base_metric_v2 = Some(BaseMetricV2::from(base_metric_v2));
        Impact {
            base_metric_v3,
            base_metric_v2,
        }
    }
}

impl BaseMetricV3 {
    fn from(json: &serde_json::Value) -> BaseMetricV3 {
        let cvss_v3 = &json["cvssV3"];
        let cvss_v3 = Some(CvssV3::from(cvss_v3));
        let exploitability_score = json["exploitabilityScore"].as_f64().unwrap().to_owned();
        let impact_score = json["impactScore"].as_f64().unwrap().to_owned();
        BaseMetricV3 {
            cvss_v3,
            exploitability_score,
            impact_score,
        }
    }
}

impl CvssV3 {
    fn from(json: &serde_json::Value) -> CvssV3 {
        let version = json["version"].as_str().unwrap().to_owned();
        let vector_string = json["vectorString"].as_str().unwrap().to_owned();
        let attack_vector = json["attackVector"].as_str().unwrap().to_owned();
        let attack_complexity = json["attackComplexity"].as_str().unwrap().to_owned();
        let privileges_required = json["privilegesRequired"].as_str().unwrap().to_owned();
        let user_interaction = json["userInteraction"].as_str().unwrap().to_owned();
        let scope = json["scope"].as_str().unwrap().to_owned();
        let confidentiality_impact = json["confidentialityImpact"].as_str().unwrap().to_owned();
        let integrity_impact = json["integrityImpact"].as_str().unwrap().to_owned();
        let availability_impact = json["availabilityImpact"].as_str().unwrap().to_owned();
        let base_score = json["baseScore"].as_f64().unwrap().to_owned();
        let base_severity = json["baseSeverity"].as_str().unwrap().to_owned();
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

impl BaseMetricV2 {
    fn from(json: &serde_json::Value) -> BaseMetricV2 {
        let cvss_v2 = &json["cvssV2"];
        let cvss_v2 = Some(CvssV2::from(cvss_v2));
        let severity = json["severity"].as_str().unwrap().to_owned();
        let exploitability_score = json["exploitabilityScore"].as_f64().unwrap().to_owned();
        let impact_score = json["impactScore"].as_f64().unwrap().to_owned();
        let ac_insuf_info = json["acInsufInfo"].as_bool().unwrap().to_owned();
        let obtain_all_privilege = json["obtainAllPrivilege"].as_bool().unwrap().to_owned();
        let obtain_user_privilege = json["obtainUserPrivilege"].as_bool().unwrap().to_owned();
        let obtain_other_privilege = json["obtainOtherPrivilege"].as_bool().unwrap().to_owned();
        let user_interaction_required = json["userInteractionRequired"]
            .as_bool()
            .unwrap()
            .to_owned();
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

impl CvssV2 {
    fn from(json: &serde_json::Value) -> CvssV2 {
        let version = json["version"].as_str().unwrap().to_owned();
        let vector_string = json["vectorString"].as_str().unwrap().to_owned();
        let attack_vector = json["attackVector"].as_str().unwrap().to_owned();
        let attack_complexity = json["attackComplexity"].as_str().unwrap().to_owned();
        let confidentiality_impact = json["confidentialityImpact"].as_str().unwrap().to_owned();
        let integrity_impact = json["integrityImpact"].as_str().unwrap().to_owned();
        let availability_impact = json["availabilityImpact"].as_str().unwrap().to_owned();
        let base_score = json["baseScore"].as_f64().unwrap().to_owned();
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

fn read_nvdcve() -> serde_json::Value {
    let zip_file = std::fs::File::open("./data/nvdcve-1.1-2022.json.zip").unwrap();
    let mut archive = zip::ZipArchive::new(zip_file).unwrap();
    let file = archive.by_name("nvdcve-1.1-2022.json").unwrap();
    serde_json::from_reader(file).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::nvd_cve::{proto::NvdCve, read_nvdcve};

    #[test]
    fn it_works() {
        println!("it work");
        let json = read_nvdcve();
        let nvd_cve = NvdCve::from(&json);
        println!("nvd_cve: {:?}", nvd_cve);
    }
}
