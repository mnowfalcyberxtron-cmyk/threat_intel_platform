"""config.py — CyberXTron TIP v2.2 — Complete configuration"""
import os
from pathlib import Path
from dotenv import load_dotenv
from contextvars import ContextVar

load_dotenv()

request_api_keys = ContextVar("request_api_keys", default={})

class Settings:
    def __getattribute__(self, name):
        try:
            if name.endswith("_API_KEY") or name == "AI_PROVIDER":
                ctx_keys = request_api_keys.get()
                if ctx_keys and name in ctx_keys and ctx_keys[name]:
                    return ctx_keys[name]
        except Exception:
            pass
        return super().__getattribute__(name)

    PLATFORM_NAME = "CyberXTron Threat Intelligence Platform"
    VERSION       = "2.2.0"
    HOST          = os.getenv("HOST", "0.0.0.0")
    PORT          = int(os.getenv("PORT", 8001))
    DB_PATH       = os.getenv("DB_PATH", "data/threat_intel.db")
    LOG_DIR       = "logs"

    # ── AI Engine ─────────────────────────────────────────────────────────────
    AI_PROVIDER        = os.getenv("AI_PROVIDER", "groq")
    GROQ_API_KEY       = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL         = os.getenv("GROQ_MODEL", "llama3-70b-8192")
    OLLAMA_BASE_URL    = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL       = os.getenv("OLLAMA_MODEL", "llama3")
    OLLAMA_API_KEY     = os.getenv("OLLAMA_API_KEY", "")
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
    OPENROUTER_MODEL   = os.getenv("OPENROUTER_MODEL", "google/gemma-4-31b-it")
    OPENROUTER_HTTP_REFERER = os.getenv("OPENROUTER_HTTP_REFERER", "http://localhost:8002")
    OPENROUTER_X_TITLE      = os.getenv("OPENROUTER_X_TITLE", "CyberXTron TIP")
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

    # ── Legacy HIBP (different from HIBR above) ───────────────────────────────
    HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
    ENABLE_HIBP  = os.getenv("ENABLE_HIBP", "false").lower() == "true"
    
    # ── Abuse.ch & AbuseIPDB ──────────────────────────────────────────────────
    ABUSEIPDB_API_KEY     = os.getenv("ABUSEIPDB_API_KEY", "")
    THREATFOX_API_KEY     = os.getenv("THREATFOX_API_KEY", "")
    MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "")

    # ── Dark Web / Tor ────────────────────────────────────────────────────────
    ENABLE_DARKWEB  = os.getenv("ENABLE_DARKWEB", "false").lower() == "true"
    TOR_SOCKS_HOST  = os.getenv("TOR_SOCKS_HOST", "127.0.0.1")
    TOR_SOCKS_PORT  = int(os.getenv("TOR_SOCKS_PORT", 9050))
    DARKWEB_INTERVAL = int(os.getenv("DARKWEB_INTERVAL", 3600))

    # ── Monitoring Intervals (seconds) ────────────────────────────────────────
    THREATFOX_INTERVAL    = int(os.getenv("THREATFOX_INTERVAL", 900))
    URLHAUS_INTERVAL      = int(os.getenv("URLHAUS_INTERVAL", 900))
    FEODO_INTERVAL        = int(os.getenv("FEODO_INTERVAL", 1800))
    MALWAREBAZAAR_INTERVAL= int(os.getenv("MALWAREBAZAAR_INTERVAL", 900))
    CIRCL_INTERVAL        = int(os.getenv("CIRCL_INTERVAL", 1800))
    RSS_INTERVAL          = int(os.getenv("RSS_INTERVAL", 1200))
    GITHUB_INTERVAL       = int(os.getenv("GITHUB_INTERVAL", 3600))
    AUTO_RUN_ALL_ON_STARTUP = os.getenv("AUTO_RUN_ALL_ON_STARTUP", "false").lower() == "true"

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
        {"name": "Bleeping Computer", "url": "https://www.bleepingcomputer.com/feed/"},
        {"name": "The Hacker News",   "url": "https://feeds.feedburner.com/TheHackersNews"},
        {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
        {"name": "SANS ISC",          "url": "https://isc.sans.edu/rssfeed_full.xml"},
        {"name": "CISA Alerts",       "url": "https://www.cisa.gov/uscert/ncas/alerts.xml"},
        {"name": "Secureworks CTU",   "url": "https://www.secureworks.com/rss/research"},
        {"name": "Unit 42",           "url": "https://unit42.paloaltonetworks.com/feed/"},
    ]

    # ── Known .onion ransomware leak sites (public TI knowledge) ─────────────
    # Users can add/edit more via the Dark Web Manager tab in the dashboard
    ONION_SITES = [
        {"group": "LockBit",              "url": "http://lockbit3olp7oetlc4tl5zydnoluphh7fvdt5oa6arcp2757r7bd.onion"},
        {"group": "RansomHub",            "url": "http://ransomhubc2vdkpb4jgpvfrltnv4mnxvnmb23lk6jkfxwambluxhvw3yd.onion"},
        {"group": "Akira",                "url": "http://akiral2iz6a7qgd3ayp3l6yub7xx7leg2c3rutdm2wp3hicaqm56bktid.onion"},
        {"group": "Play",                 "url": "http://mbrlkbtq5jonaqkurdefo7436ohf7v5ipkajhrkw7hgsxl4raxrmhfyd.onion"},
        {"group": "Medusa",               "url": "http://medusaxko7klbqtmru2dgmgbzbj2hczxw6fvjw6fbyvxoahmvkjwgqyd.onion"},
        {"group": "Hunters International","url": "http://hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejyid.onion"},
        {"group": "Cl0p",                 "url": "http://santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion"},
        {"group": "INC Ransom",           "url": "http://incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpfull6p65qxmkyffhmnh7yd.onion"},
        {"group": "Qilin",                "url": "http://qilin4kkont6jyiih4mdximt6fpzwlyxjhxcl5zvhkzqyjdoiupyq4yd.onion"},
        {"group": "DragonForce",          "url": "http://z3mjiusmgkf2gfkld6jfzp6mqbwqohmhompbnhru4xq4b6iogpxqq5oyd.onion"},
        {"group": "BlackSuit",            "url": "http://weg7sdx54bevnvulapqu6bpzwztryeflq3s23tegbmnhd3vssxxpwcyd.onion"},
        {"group": "Cactus",               "url": "http://cactusbloguuodvqjmnzlwetjlpj6aggapkstemwochyg7vufqlbhpsa.onion"},
        {"group": "BianLian",             "url": "http://bianlianlbc5an4kgnay3opdemgcryg2kpfcbgczopmm3dnbz3uaunad.onion"},
        {"group": "NoEscape",             "url": "http://noescape63q4z3hzw7q3xwpniuh4sckvxetkq3rh4gqdq4xjrwmbd5yd.onion"},
        {"group": "Rhysida",              "url": "http://rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad.onion"},
    ]

    def ensure_dirs(self):
        Path(self.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        Path(self.LOG_DIR).mkdir(parents=True, exist_ok=True)
        Path("data/backups").mkdir(parents=True, exist_ok=True)


settings = Settings()
