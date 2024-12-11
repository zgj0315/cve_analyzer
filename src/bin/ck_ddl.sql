DROP TABLE IF EXISTS tbl_cve;

create table if not exists tbl_cve (
    data_type String,
    data_version String,
    cve_id String,
    assigner_org_id String,
    state String,
    assigner_short_name String,
    date_reserved DateTime ('UTC'),
    date_published DateTime ('UTC'),
    date_updated DateTime ('UTC'),
    cna_provider_metadata String,
    cna_title String,
    cna_affected Nested (vendor String, product String, versions String),
    adp Nested (
        provider_metadata String,
        title String,
        references String,
        affected String,
        metrics String
    )
) engine = MergeTree
order by
    (cve_id);

DROP TABLE IF EXISTS tbl_nvd;

create table if not exists tbl_nvd (
    cve_id String,
    cve String,
    configurations String,
    impact String,
    published_date DateTime ('UTC'),
    last_modified_date DateTime ('UTC')
) engine = MergeTree
order by
    (cve_id);