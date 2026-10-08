CREATE DATABASE IF NOT EXISTS threatintel;

CREATE TABLE IF NOT EXISTS threatintel.ics_advisories
(
    id UInt64,
    ics_number String,
    cve_id String,
    title String,
    vendor String,
    product String,
    cvss_score String,
    severity LowCardinality(String),
    release_date String,
    last_updated String,
    release_year Nullable(Int32),
    release_month Nullable(UInt8),
    update_year Nullable(Int32),
    update_month Nullable(UInt8),
    cve_year Nullable(Int32),
    advisory_url String,
    sector String,
    patch_availability String,
    poc_availability String,
    impact String,
    affected_version String,
    fixed_version String,
    cwe String,
    vendor_hq String,
    product_distribution String,
    kev_flag String,
    nist_url String,
    csaf_url String,
    data_source String,
    raw_data String,
    normalized_data String,
    nvd_cvss_v4_score String,
    nvd_enrichment_status LowCardinality(String),
    cve_published_date String,
    cve_updated_date String,
    cve_pub_year Nullable(Int32),
    cve_pub_month Nullable(UInt8),
    cvelist_status LowCardinality(String),
    ai_enriched UInt8,
    patch_available_bool String,
    poc_available_bool String,
    xtron_score Nullable(Int32),
    created_at DateTime64(3, 'UTC'),
    updated_at DateTime64(3, 'UTC'),
    version UInt64 DEFAULT toUnixTimestamp64Milli(now64(3)),
    deleted UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(version, deleted)
PARTITION BY toYYYYMM(coalesce(parseDateTime64BestEffortOrNull(cve_published_date), parseDateTime64BestEffortOrNull(release_date), updated_at))
ORDER BY (ics_number, cve_id);

CREATE TABLE IF NOT EXISTS threatintel.status_history
(
    id UInt64,
    target_type LowCardinality(String),
    target_id UInt64,
    name String,
    url String,
    status String,
    latency_ms Nullable(Int32),
    timestamp DateTime64(3, 'UTC')
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (target_type, target_id, timestamp);

CREATE TABLE IF NOT EXISTS threatintel.onion_sites
(
    id UInt64,
    group_name String,
    url String,
    description String,
    site_type LowCardinality(String),
    active UInt8,
    last_status String,
    last_checked Nullable(DateTime64(3, 'UTC')),
    page_title String,
    meta_generator String,
    screenshot_path String,
    created_at DateTime64(3, 'UTC'),
    updated_at DateTime64(3, 'UTC'),
    version UInt64 DEFAULT toUnixTimestamp64Milli(now64(3)),
    deleted UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(version, deleted)
ORDER BY (url);

CREATE TABLE IF NOT EXISTS threatintel.breach_markets
(
    id UInt64,
    name String,
    url String,
    description String,
    site_type LowCardinality(String),
    source LowCardinality(String),
    active UInt8,
    last_status String,
    last_checked Nullable(DateTime64(3, 'UTC')),
    screenshot_path String,
    created_at DateTime64(3, 'UTC'),
    updated_at DateTime64(3, 'UTC'),
    version UInt64 DEFAULT toUnixTimestamp64Milli(now64(3)),
    deleted UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(version, deleted)
ORDER BY (url);

CREATE TABLE IF NOT EXISTS threatintel.iocs
(
    id UInt64,
    ioc String,
    ioc_type LowCardinality(String),
    sources String,
    source_count UInt32,
    threat_actor String,
    malware String,
    confidence Float32,
    confidence_label LowCardinality(String),
    first_seen String,
    last_seen String,
    tags String,
    raw_data String,
    created_at DateTime64(3, 'UTC'),
    updated_at DateTime64(3, 'UTC'),
    version UInt64 DEFAULT toUnixTimestamp64Milli(now64(3)),
    deleted UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(version, deleted)
PARTITION BY toYYYYMM(updated_at)
ORDER BY (ioc_type, ioc);
