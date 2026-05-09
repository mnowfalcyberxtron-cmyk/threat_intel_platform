"""database/models.py — Complete SQLite schema v2.4"""

CREATE_IOCS_TABLE = """
CREATE TABLE IF NOT EXISTS iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc             TEXT NOT NULL,
    ioc_type        TEXT NOT NULL,
    sources         TEXT NOT NULL DEFAULT '[]',
    source_count    INTEGER DEFAULT 1,
    threat_actor    TEXT DEFAULT 'unknown',
    malware         TEXT DEFAULT '',
    malware_family  TEXT DEFAULT '',
    campaign        TEXT DEFAULT '',
    tags            TEXT DEFAULT '[]',
    confidence      REAL DEFAULT 0.5,
    confidence_label TEXT DEFAULT 'low',
    severity        TEXT DEFAULT 'medium',
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    raw_data        TEXT DEFAULT '{}',
    UNIQUE(ioc, ioc_type)
)"""

CREATE_THREATS_TABLE = """
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL, description TEXT DEFAULT '',
    threat_actor TEXT DEFAULT 'unknown', malware TEXT DEFAULT '',
    targeted_countries TEXT DEFAULT '[]', targeted_industries TEXT DEFAULT '[]',
    cves TEXT DEFAULT '[]', techniques TEXT DEFAULT '[]',
    source TEXT NOT NULL, source_url TEXT DEFAULT '',
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    confidence REAL DEFAULT 0.5, raw_data TEXT DEFAULT '{}'
)"""

CREATE_RANSOMWARE_VICTIMS_TABLE = """
CREATE TABLE IF NOT EXISTS ransomware_victims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_name TEXT NOT NULL, victim_name TEXT NOT NULL,
    description TEXT DEFAULT '', country TEXT DEFAULT '',
    industry TEXT DEFAULT '', website TEXT DEFAULT '',
    leak_date TEXT DEFAULT '', discovery_date TEXT NOT NULL,
    source TEXT DEFAULT '', source_url TEXT DEFAULT '',
    status TEXT DEFAULT 'published', data_size TEXT DEFAULT '',
    onion_url TEXT DEFAULT '',
    UNIQUE(group_name, victim_name)
)"""

CREATE_SOURCES_TABLE = """
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
    tier INTEGER DEFAULT 1, last_fetched TEXT DEFAULT NULL,
    last_success TEXT DEFAULT NULL, records_fetched INTEGER DEFAULT 0,
    total_records INTEGER DEFAULT 0, status TEXT DEFAULT 'pending',
    error_msg TEXT DEFAULT '', enabled INTEGER DEFAULT 1
)"""

CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL, title TEXT NOT NULL,
    description TEXT DEFAULT '', severity TEXT DEFAULT 'medium',
    ioc_id INTEGER DEFAULT NULL, victim_id INTEGER DEFAULT NULL,
    source TEXT DEFAULT '', created_at TEXT NOT NULL,
    acknowledged INTEGER DEFAULT 0, acknowledged_at TEXT DEFAULT NULL
)"""

CREATE_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL, level TEXT NOT NULL,
    source TEXT NOT NULL, message TEXT NOT NULL
)"""

CREATE_REPORTS_TABLE = """
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL, summary TEXT DEFAULT '',
    threat_actor TEXT DEFAULT '', malware TEXT DEFAULT '',
    targeted_countries TEXT DEFAULT '[]', targeted_industries TEXT DEFAULT '[]',
    cves TEXT DEFAULT '[]', impact TEXT DEFAULT '',
    iocs_json TEXT DEFAULT '[]', techniques TEXT DEFAULT '[]',
    generated_at TEXT NOT NULL, raw_markdown TEXT DEFAULT ''
)"""

CREATE_ONION_SITES_TABLE = """
CREATE TABLE IF NOT EXISTS onion_sites (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    group_name      TEXT NOT NULL,
    url             TEXT NOT NULL UNIQUE,
    description     TEXT DEFAULT '',
    page_title      TEXT DEFAULT '',
    meta_generator  TEXT DEFAULT '',
    full_html       TEXT DEFAULT '',
    last_content    TEXT DEFAULT '',
    screenshot_path TEXT DEFAULT '',
    active          INTEGER DEFAULT 1,
    site_type       TEXT DEFAULT 'ransomware',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_checked    TEXT DEFAULT NULL,
    last_status     TEXT DEFAULT 'pending'
)"""

CREATE_THREAT_FEED_TABLE = """
CREATE TABLE IF NOT EXISTS threat_feed (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL, summary TEXT DEFAULT '',
    url TEXT NOT NULL UNIQUE, source TEXT DEFAULT '',
    source_type TEXT DEFAULT 'web', category TEXT DEFAULT 'general',
    entities TEXT DEFAULT '[]', published TEXT DEFAULT '',
    fetched_at TEXT NOT NULL, relevance REAL DEFAULT 0.5
)"""

CREATE_ADVISORIES_TABLE = """
CREATE TABLE IF NOT EXISTS advisories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company TEXT NOT NULL, advisory_type TEXT DEFAULT 'official',
    source_name TEXT DEFAULT '', title TEXT NOT NULL,
    summary TEXT DEFAULT '', url TEXT NOT NULL UNIQUE,
    published TEXT DEFAULT '', fetched_at TEXT NOT NULL,
    cves TEXT DEFAULT '[]', iocs TEXT DEFAULT '{}',
    mitre_ttps TEXT DEFAULT '[]', severity TEXT DEFAULT 'medium',
    category TEXT DEFAULT 'advisory', ai_analysis TEXT DEFAULT ''
)"""
CREATE_SOCIAL_INTEL_TABLE = """
CREATE TABLE IF NOT EXISTS social_intel (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    platform    TEXT NOT NULL,
    source_url  TEXT NOT NULL UNIQUE,
    content     TEXT NOT NULL,
    author      TEXT DEFAULT '',
    threat_type TEXT DEFAULT 'emerging',
    published   TEXT NOT NULL,
    fetched_at  TEXT NOT NULL,
    entities    TEXT DEFAULT '[]',
    raw_json    TEXT DEFAULT '{}'
)"""

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,
    role        TEXT DEFAULT 'user',
    api_keys    TEXT DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
)"""

CREATE_TELEGRAM_CHANNELS_TABLE = """
CREATE TABLE IF NOT EXISTS telegram_channels (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    handle          TEXT NOT NULL UNIQUE,
    url             TEXT NOT NULL UNIQUE,
    description     TEXT DEFAULT '',
    category        TEXT DEFAULT 'general',
    active          INTEGER DEFAULT 1,
    last_status     TEXT DEFAULT 'pending',
    last_checked    TEXT DEFAULT NULL,
    subscriber_count INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
)"""

CREATE_USER_ACTIVITY_TABLE = """
CREATE TABLE IF NOT EXISTS user_activity (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    action      TEXT NOT NULL,
    details     TEXT DEFAULT '',
    ip_address  TEXT DEFAULT '',
    timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)"""

# All schemas in order
ALL_SCHEMAS = [
    CREATE_IOCS_TABLE,
    CREATE_THREATS_TABLE,
    CREATE_RANSOMWARE_VICTIMS_TABLE,
    CREATE_SOURCES_TABLE,
    CREATE_ALERTS_TABLE,
    CREATE_LOGS_TABLE,
    CREATE_REPORTS_TABLE,
    CREATE_ONION_SITES_TABLE,
    CREATE_THREAT_FEED_TABLE,
    CREATE_ADVISORIES_TABLE,
    CREATE_SOCIAL_INTEL_TABLE,
    CREATE_TELEGRAM_CHANNELS_TABLE,
    CREATE_USERS_TABLE,
    CREATE_USER_ACTIVITY_TABLE,
    # Indexes
    "CREATE INDEX IF NOT EXISTS idx_ioc_type       ON iocs(ioc_type)",
    "CREATE INDEX IF NOT EXISTS idx_ioc_confidence ON iocs(confidence DESC)",
    "CREATE INDEX IF NOT EXISTS idx_ioc_last_seen  ON iocs(last_seen DESC)",
    "CREATE INDEX IF NOT EXISTS idx_ioc_actor      ON iocs(threat_actor)",
    "CREATE INDEX IF NOT EXISTS idx_ioc_malware    ON iocs(malware)",
    "CREATE INDEX IF NOT EXISTS idx_ioc_updated    ON iocs(updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_rv_group       ON ransomware_victims(group_name)",
    "CREATE INDEX IF NOT EXISTS idx_rv_country     ON ransomware_victims(country)",
    "CREATE INDEX IF NOT EXISTS idx_rv_discovery   ON ransomware_victims(discovery_date DESC)",
    "CREATE INDEX IF NOT EXISTS idx_rv_source      ON ransomware_victims(source)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_acked   ON alerts(acknowledged, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_logs_ts        ON logs(timestamp DESC)",
    "CREATE INDEX IF NOT EXISTS idx_feed_fetched   ON threat_feed(fetched_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_feed_relevance ON threat_feed(relevance DESC)",
    "CREATE INDEX IF NOT EXISTS idx_adv_company    ON advisories(company)",
    "CREATE INDEX IF NOT EXISTS idx_adv_severity   ON advisories(severity)",
    "CREATE INDEX IF NOT EXISTS idx_adv_fetched    ON advisories(fetched_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_social_pub     ON social_intel(published DESC)",
    "CREATE INDEX IF NOT EXISTS idx_tg_handle      ON telegram_channels(handle)",
    "CREATE INDEX IF NOT EXISTS idx_tg_category    ON telegram_channels(category)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(acknowledged, alert_type)",
    "CREATE INDEX IF NOT EXISTS idx_bm_status        ON breach_markets(last_status)",
    "CREATE INDEX IF NOT EXISTS idx_ua_user         ON user_activity(user_id, timestamp DESC)",
]

DEFAULT_SOURCES = [
    ("urlhaus",           "URLHaus (Abuse.ch)",                1),
    ("threatfox",         "ThreatFox (Abuse.ch)",              1),
    ("feodo",             "Feodo Tracker (Abuse.ch)",          1),
    ("malwarebazaar",     "MalwareBazaar (Abuse.ch)",          1),
    ("ransomware_live",   "Ransomware.live",                   1),
    ("haveibeenransom",   "HaveIBeenRansom / RansomWatch",     1),
    ("circl_osint",       "CIRCL OSINT / CISA KEV",            1),
    ("rss",               "RSS Threat Intel Feeds",            1),
    ("github_intel",      "GitHub Threat Intel",               1),
    ("web_intel",         "Web Threat Intel (Live Feed)",      1),
    ("advisory_monitor",  "Top 25 Companies Advisory Monitor", 1),
    ("darkweb",           "Dark Web Monitor (Tor)",            1),
    ("hibr",              "HaveIBeenRansom (HIBR Pro)",        2),
    ("falconfeeds",       "FalconFeeds.io",                    2),
    ("hibp",              "HaveIBeenPwned",                    2),
    ("social_monitor",    "Social Media Threat Intelligence",  1),
    ("telegram_monitor",  "Telegram Threat Monitor",           1),
]
