"""config.py — ThreatIntel TIP v2.3 — Complete configuration"""
import os
from pathlib import Path
from dotenv import load_dotenv
from contextvars import ContextVar

load_dotenv()

request_api_keys = ContextVar("request_api_keys", default={})

def env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}

class Settings:
    def __getattribute__(self, name):
        try:
            if name.endswith("_API_KEY") or name in {"AI_PROVIDER", "RAPIDAPI_KEY"}:
                ctx_keys = request_api_keys.get()
                if ctx_keys and name in ctx_keys and ctx_keys[name]:
                    return ctx_keys[name]
        except Exception:
            pass
        return super().__getattribute__(name)

    PLATFORM_NAME = "ThreatIntel Threat Intelligence Platform"
    VERSION       = "2.3.0"
    HOST          = os.getenv("HOST", "0.0.0.0")
    PORT          = int(os.getenv("PORT", 8003))
    DB_ENGINE     = os.getenv("DB_ENGINE", "sqlite").strip().lower()
    DB_PATH       = os.getenv("DB_PATH", "data/threat_intel.db")
    POSTGRES_URL  = os.getenv("POSTGRES_URL", "")
    DATABASE_URL  = os.getenv("DATABASE_URL", POSTGRES_URL)
    CLICKHOUSE_HOST     = os.getenv("CLICKHOUSE_HOST", "localhost")
    CLICKHOUSE_PORT     = int(os.getenv("CLICKHOUSE_PORT", 8123))
    CLICKHOUSE_USERNAME = os.getenv("CLICKHOUSE_USERNAME", "default")
    CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
    CLICKHOUSE_DATABASE = os.getenv("CLICKHOUSE_DATABASE", "threatintel")
    CLICKHOUSE_SECURE   = env_bool("CLICKHOUSE_SECURE", False)
    LOG_DIR       = "logs"
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
    ADMIN_EMAIL    = os.getenv("ADMIN_EMAIL", "feedsautomate@gmail.com")
    ADMIN_PASS     = os.getenv("ADMIN_PASS", "")
    PASSWORD_SALT  = os.getenv("PASSWORD_SALT", "")

    # Signup notification email
    SMTP_HOST      = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT      = int(os.getenv("SMTP_PORT", 587))
    SMTP_USERNAME  = os.getenv("SMTP_USERNAME", ADMIN_EMAIL)
    SMTP_PASSWORD  = os.getenv("SMTP_PASSWORD", ADMIN_PASS)
    SMTP_FROM      = os.getenv("SMTP_FROM", ADMIN_EMAIL)
    SMTP_TO        = os.getenv("SMTP_TO", ADMIN_EMAIL)
    SMTP_USE_TLS   = env_bool("SMTP_USE_TLS", True)
    SMTP_USE_SSL   = env_bool("SMTP_USE_SSL", False)
    SMTP_TIMEOUT   = int(os.getenv("SMTP_TIMEOUT", 15))

    # ── AI Engine ─────────────────────────────────────────────────────────────
    AI_PROVIDER        = os.getenv("AI_PROVIDER", "ollama")
    GROQ_API_KEY       = os.getenv("GROQ_API_KEY", "")
    GROQ_API_KEYS      = os.getenv("GROQ_API_KEYS", "")
    GROQ_MODEL         = os.getenv("GROQ_MODEL", "llama3-70b-8192")
    OLLAMA_BASE_URL    = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL       = os.getenv("OLLAMA_MODEL", "llama3")
    OLLAMA_API_KEY     = os.getenv("OLLAMA_API_KEY", "")
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
    OPENROUTER_MODEL   = os.getenv("OPENROUTER_MODEL", "google/gemma-4-31b-it")
    OPENROUTER_HTTP_REFERER = os.getenv("OPENROUTER_HTTP_REFERER", "http://localhost:8002")
    OPENROUTER_X_TITLE      = os.getenv("OPENROUTER_X_TITLE", "ThreatIntel TIP")
    NVIDIA_API_KEY    = os.getenv("NVIDIA_API_KEY", "")
    NVIDIA_MODEL      = os.getenv("NVIDIA_MODEL", "openai/gpt-oss-20b")
    GEMINI_API_KEY     = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL       = os.getenv("GEMINI_MODEL", "gemini-flash-latest")
    ANTHROPIC_API_KEY  = os.getenv("ANTHROPIC_API_KEY", "")

    # ── Ransomware.live ───────────────────────────────────────────────────────
    RANSOMWARE_LIVE_API_KEY = os.getenv("RANSOMWARE_LIVE_API_KEY", "")
    ENABLE_RANSOMWARE_API   = os.getenv("ENABLE_RANSOMWARE_API", "false").lower() == "true"
    RANSOMWARE_INTERVAL     = int(os.getenv("RANSOMWARE_INTERVAL", 600))

    # ── HaveIBeenRansom (HIBR) ────────────────────────────────────────────────
    HIBR_API_KEY  = os.getenv("HIBR_API_KEY", "")
    HIBR_INTERVAL = int(os.getenv("HIBR_INTERVAL", 3600))
    ENABLE_HIBR   = os.getenv("ENABLE_HIBR", "false").lower() == "true"

    # ── FalconFeeds ───────────────────────────────────────────────────────────
    FALCONFEEDS_API_KEY  = os.getenv("FALCONFEEDS_API_KEY", "")
    ENABLE_FALCONFEEDS   = os.getenv("ENABLE_FALCONFEEDS", "false").lower() == "true"
    FALCONFEEDS_INTERVAL = int(os.getenv("FALCONFEEDS_INTERVAL", 1800))

    # ── Legacy HIBP ───────────────────────────────────────────────────────────
    HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
    ENABLE_HIBP  = os.getenv("ENABLE_HIBP", "false").lower() == "true"

    # ── Abuse.ch & AbuseIPDB ──────────────────────────────────────────────────
    ABUSEIPDB_API_KEY     = os.getenv("ABUSEIPDB_API_KEY", "")
    THREATFOX_API_KEY     = os.getenv("THREATFOX_API_KEY", "")
    OTX_API_KEY           = os.getenv("OTX_API_KEY", "")
    ENABLE_OTX            = os.getenv("ENABLE_OTX", "true").lower() == "true"
    MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "")

    # ── ICS / RapidAPI ────────────────────────────────────────────────────────
    RAPIDAPI_KEY              = os.getenv("RAPIDAPI_KEY", os.getenv("ICS_RAPIDAPI_KEY", ""))
    ICS_RAPIDAPI_LATEST_LIMIT = int(os.getenv("ICS_RAPIDAPI_LATEST_LIMIT", 100))
    ICS_CACHE_TTL_SECONDS     = int(os.getenv("ICS_CACHE_TTL_SECONDS", 900))
    # Token budget — 15K/month limit
    ICS_MONTHLY_BUDGET        = int(os.getenv("ICS_MONTHLY_BUDGET", 15000))
    ICS_TOKENS_USED           = int(os.getenv("ICS_TOKENS_USED", 0))
    ICS_BUDGET_MONTH          = os.getenv("ICS_BUDGET_MONTH", "")   # YYYY-MM; resets counter on change
    NVD_API_KEY               = os.getenv("NVD_API_KEY", "")
    GITHUB_TOKEN              = os.getenv("GITHUB_TOKEN", "")   # Optional: increases GitHub API rate limit 60→5000 req/hr

    # ── Dark Web / Tor ────────────────────────────────────────────────────────
    ENABLE_DARKWEB          = os.getenv("ENABLE_DARKWEB", "false").lower() == "true"
    TOR_SOCKS_HOST          = os.getenv("TOR_SOCKS_HOST", "127.0.0.1")
    TOR_SOCKS_PORT          = int(os.getenv("TOR_SOCKS_PORT", 9050))
    TOR_SOCKS_PORT_FALLBACK = int(os.getenv("TOR_SOCKS_PORT_FALLBACK", 0))     # Optional Tor Browser fallback, e.g. 9150
    TOR_AUTO_START          = env_bool("TOR_AUTO_START", False)                # Prefer manual Tor/Tor Browser by default
    TOR_AUTO_START_PORT     = int(os.getenv("TOR_AUTO_START_PORT", 9050))      # App-owned Tor port; do not use Tor Browser's 9150
    TOR_BOOTSTRAP_TIMEOUT   = int(os.getenv("TOR_BOOTSTRAP_TIMEOUT", 120))    # seconds
    DARKWEB_INTERVAL        = int(os.getenv("DARKWEB_INTERVAL", 3600))

    # ── Monitoring Intervals (seconds) ────────────────────────────────────────
    THREATFOX_INTERVAL     = int(os.getenv("THREATFOX_INTERVAL", 900))
    OTX_INTERVAL           = int(os.getenv("OTX_INTERVAL", 1800))
    URLHAUS_INTERVAL       = int(os.getenv("URLHAUS_INTERVAL", 900))
    FEODO_INTERVAL         = int(os.getenv("FEODO_INTERVAL", 1800))
    MALWAREBAZAAR_INTERVAL = int(os.getenv("MALWAREBAZAAR_INTERVAL", 900))
    CIRCL_INTERVAL         = int(os.getenv("CIRCL_INTERVAL", 1800))
    RSS_INTERVAL           = int(os.getenv("RSS_INTERVAL", 1800))
    GITHUB_INTERVAL        = int(os.getenv("GITHUB_INTERVAL", 3600))
    ONION_MONITOR_INTERVAL = int(os.getenv("ONION_MONITOR_INTERVAL", 1800))
    AUTO_RUN_ALL_ON_STARTUP = os.getenv("AUTO_RUN_ALL_ON_STARTUP", "true").lower() == "true"
    RUN_ONION_MONITOR_IN_RUN_ALL = env_bool("RUN_ONION_MONITOR_IN_RUN_ALL", False)

    # ── Excel OneDrive Ingestion ───────────────────────────────────────────────
    EXCEL_INGESTION_INTERVAL       = int(os.getenv("EXCEL_INGESTION_INTERVAL", 1800))
    EXCEL_INGESTION_ONEDRIVE_URL   = os.getenv("EXCEL_INGESTION_ONEDRIVE_URL", "https://1drv.ms/x/c/58897f49075b1bc5/IQCbQQAZ3G0DQ7m06TMh0ECXAeugC9AdA_q_3AWMmc2gyVc?e=Zf9Hoh&nav=MTVfezAwMDAwMDAwLTAwMDEtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMH0")
    EXCEL_INGESTION_LOCAL_PATH     = os.getenv("EXCEL_INGESTION_LOCAL_PATH", "")
    EXCEL_INGESTION_CHECK_STATUSES = env_bool("EXCEL_INGESTION_CHECK_STATUSES", True)

    # ── Excel Database Export ─────────────────────────────────────────────────
    EXCEL_EXPORT_PATH     = os.getenv("EXCEL_EXPORT_PATH", "data/exports")
    EXCEL_SHEET_MODE      = os.getenv("EXCEL_SHEET_MODE", "monthly")   # 'monthly' | 'fixed'
    EXCEL_EXPORT_INTERVAL = int(os.getenv("EXCEL_EXPORT_INTERVAL", 3600))  # 1 hour

    # ── Alerting ──────────────────────────────────────────────────────────────
    ALERT_MIN_CONFIDENCE = float(os.getenv("ALERT_MIN_CONFIDENCE", 0.65))
    REQUEST_TIMEOUT      = int(os.getenv("REQUEST_TIMEOUT", 30))
    MAX_RETRIES          = int(os.getenv("MAX_RETRIES", 3))

    # ── Source reliability weights ─────────────────────────────────────────────
    SOURCE_WEIGHTS = {
        "feodo":           0.95,
        "threatfox":       0.92,
        "haveibeenransom": 0.92,
        "hibr":            0.92,
        "falconfeeds":     0.90,
        "malwarebazaar":   0.88,
        "urlhaus":         0.87,
        "hibp":            0.85,
        "ransomware_live": 0.85,
        "circl_osint":     0.80,
        "darkweb":         0.75,
        "github_intel":    0.65,
        "rss":             0.55,
    }

    # ── RSS Feeds ──────────────────────────────────────────────────────────────
    RSS_FEEDS = [
        {"name": "CERT-UA", "url": "https://cert.gov.ua/api/articles/rss"},
        {"name": "CISA Alerts", "url": "https://www.cisa.gov/uscert/ncas/alerts.xml"},
        {"name": "CISA ICS Advisories", "url": "https://us-cert.cisa.gov/ics/advisories/advisories.xml"},
        {"name": "CERT-FR", "url": "https://www.cert.ssi.gouv.fr/feed/"},
        {"name": "JPCERT", "url": "https://www.jpcert.or.jp/english/rss/jpcert.rdf"},
        {"name": "GovCERT.ch", "url": "https://www.govcert.admin.ch/blog/feed.xml"},
        {"name": "AusCERT", "url": "https://www.cyber.gov.au/about-us/news/rss"},
        {"name": "USOM Threats", "url": "https://www.usom.gov.tr/rss/tehdit.rss"},
        {"name": "Bleeping Computer", "url": "https://www.bleepingcomputer.com/feed/"},
        {"name": "The Hacker News",   "url": "https://feeds.feedburner.com/TheHackersNews"},
        {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
        {"name": "SANS ISC",          "url": "https://isc.sans.edu/rssfeed_full.xml"},
        {"name": "Sophos Threat Research", "url": "https://news.sophos.com/en-us/category/threat-research/feed/"},
        {"name": "Unit 42",           "url": "https://unit42.paloaltonetworks.com/feed/"},
    ]

    # ── Known .onion ransomware leak sites ────────────────────────────────────
    ONION_SITES = [
        {"group": "LockBit",               "url": "http://lockbit3olp7oetlc4tl5zydnoluphh7fvdt5oa6arcp2757r7bd.onion"},
        {"group": "RansomHub",             "url": "http://ransomhubc2vdkpb4jgpvfrltnv4mnxvnmb23lk6jkfxwambluxhvw3yd.onion"},
        {"group": "Akira",                 "url": "http://akiral2iz6a7qgd3ayp3l6yub7xx7leg2c3rutdm2wp3hicaqm56bktid.onion"},
        {"group": "Play",                  "url": "http://mbrlkbtq5jonaqkurdefo7436ohf7v5ipkajhrkw7hgsxl4raxrmhfyd.onion"},
        {"group": "Medusa",                "url": "http://medusaxko7klbqtmru2dgmgbzbj2hczxw6fvjw6fbyvxoahmvkjwgqyd.onion"},
        {"group": "Hunters International", "url": "http://hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejyid.onion"},
        {"group": "Cl0p",                  "url": "http://santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion"},
        {"group": "INC Ransom",            "url": "http://incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpfull6p65qxmkyffhmnh7yd.onion"},
        {"group": "Qilin",                 "url": "http://qilin4kkont6jyiih4mdximt6fpzwlyxjhxcl5zvhkzqyjdoiupyq4yd.onion"},
        {"group": "DragonForce",           "url": "http://z3mjiusmgkf2gfkld6jfzp6mqbwqohmhompbnhru4xq4b6iogpxqq5oyd.onion"},
        {"group": "BlackSuit",             "url": "http://weg7sdx54bevnvulapqu6bpzwztryeflq3s23tegbmnhd3vssxxpwcyd.onion"},
        {"group": "Cactus",                "url": "http://cactusbloguuodvqjmnzlwetjlpj6aggapkstemwochyg7vufqlbhpsa.onion"},
        {"group": "BianLian",              "url": "http://bianlianlbc5an4kgnay3opdemgcryg2kpfcbgczopmm3dnbz3uaunad.onion"},
        {"group": "NoEscape",              "url": "http://noescape63q4z3hzw7q3xwpniuh4sckvxetkq3rh4gqdq4xjrwmbd5yd.onion"},
        {"group": "Rhysida",               "url": "http://rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad.onion"},
    ]

    def ensure_dirs(self):
        Path(self.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        Path(self.LOG_DIR).mkdir(parents=True, exist_ok=True)
        Path("data/backups").mkdir(parents=True, exist_ok=True)
        Path(self.EXCEL_EXPORT_PATH).mkdir(parents=True, exist_ok=True)
        Path("data/screenshots").mkdir(parents=True, exist_ok=True)


settings = Settings()
