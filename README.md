# 🛡️ CyberXTron Threat Intelligence Platform

> **Real-time Threat Intelligence | Dark Web Monitoring | Ransomware Tracking | AI-Powered Analysis**

[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](https://hub.docker.com)
[![Python](https://img.shields.io/badge/Python-3.11-green?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-teal?logo=fastapi)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## 🚀 Features

| Feature | Description |
|---|---|
| 🔍 **IOC Monitoring** | Threat indicators from ThreatFox, URLhaus, Feodo, MalwareBazaar |
| 🦠 **Ransomware Intelligence** | Live victim tracking via Ransomware.live + RansomWatch |
| 🌑 **Dark Web Monitor** | Tor-routed onion site scanning of 15+ ransomware leak sites |
| 🕵️ **Breach Market Intel** | RansomLook breach forum monitoring with screenshots |
| 📡 **Telegram Monitor** | Automated threat channel discovery & categorization |
| 🤖 **AI Analysis** | Groq (LLaMA-3.3), OpenRouter, Anthropic integration |
| 📊 **HIBR Integration** | HaveIBeenRansom API for victim breach data |
| 🌐 **OSINT Feeds** | CIRCL, RSS (BleepingComputer, THN, CISA, Krebs, SANS) |
| 📸 **Evidence Screenshots** | Automated Playwright Chromium browser screenshots |
| 📋 **Report Generation** | PDF/HTML threat intelligence reports |
| 🔐 **Auth System** | Admin login with JWT-based session management |

---

## 🐳 Quick Start with Docker (Recommended)

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running

### 1. Clone the repository
```bash
git clone https://github.com/mnowfalcyberxtron-cmyk/threat_intel_platform.git
cd threat_intel_platform
```

### 2. Configure environment
```bash
cp .env.example .env
# Edit .env with your API keys (see Configuration section below)
```

### 3. Launch the platform
```bash
docker-compose up -d
```

### 4. Access the platform
Open your browser → **http://localhost:8002**

> Default admin credentials are set via `ADMIN_EMAIL` and `ADMIN_PASS` in `.env`

---

## ⚙️ Configuration

Create a `.env` file with the following keys:

```env
# Server
PORT=8002
HOST=0.0.0.0
DB_PATH=data/threat_intel.db

# AI Engine (choose one or more)
AI_PROVIDER=groq
GROQ_API_KEY=your_groq_api_key
GROQ_MODEL=llama-3.3-70b-versatile
OPENROUTER_API_KEY=your_openrouter_key
OPENROUTER_MODEL=google/gemma-4-31b-it

# Threat Intelligence APIs
RANSOMWARE_LIVE_API_KEY=your_key
ENABLE_RANSOMWARE_API=true
HIBR_API_KEY=your_hibr_key
ENABLE_HIBR=true
ABUSEIPDB_API_KEY=your_key
THREATFOX_API_KEY=your_key

# Dark Web / Tor
ENABLE_DARKWEB=true
TOR_SOCKS_PORT=9050

# Admin
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASS=your_secure_password

# Auto-run all feeds on startup
AUTO_RUN_ALL_ON_STARTUP=true
```

---

## 🏗️ Architecture

```
cyberxtron_tip  (FastAPI + Uvicorn — port 8002)
      │
      └──► cyberxtron_tor  (Tor SOCKS Proxy — port 9050)
```

**Services started automatically by Docker:**
- ✅ Main platform (FastAPI)
- ✅ Tor proxy (for dark web monitoring)
- ✅ All intelligence schedulers (auto-run every 5–60 min)
- ✅ Playwright Chromium (for screenshots)

---

## 📡 API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/docs` | Interactive API documentation |
| `GET /api/health` | Platform health check |
| `GET /api/iocs` | IOC feed |
| `GET /api/victims` | Ransomware victim data |
| `GET /api/alerts` | Generated alerts |
| `POST /api/ai/analyze` | AI threat analysis |
| `GET /api/darkweb/status` | Tor + dark web status |
| `GET /api/breach/markets` | Breach market status |

---

## 🔧 Manual Setup (Without Docker)

```bash
# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser
playwright install chromium

# Run
python main.py
```

---

## 📁 Project Structure

```
threat_intel_platform/
├── api/                  # FastAPI route handlers
├── connectors/           # Intelligence source connectors
├── database/             # SQLite DB models & queries
├── engine/               # Scheduler, AI engine, validator
├── frontend/             # HTML dashboard (index.html, login.html)
├── reports/              # Report generator
├── utils/                # Utility helpers
├── data/                 # SQLite database (auto-created)
├── logs/                 # Application logs (auto-created)
├── screenshots/          # Evidence screenshots (auto-created)
├── Dockerfile            # Docker build configuration
├── docker-compose.yml    # Multi-service orchestration
├── main.py               # Application entrypoint
├── config.py             # Settings & configuration
└── requirements.txt      # Python dependencies
```

---

## 🔒 Security Notes

- Never commit your `.env` file (it's in `.gitignore`)
- Change `ADMIN_PASS` to a strong password before deploying
- The platform binds to `0.0.0.0` — use a firewall/reverse proxy in production

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with ❤️ by the CyberXTron Team*
