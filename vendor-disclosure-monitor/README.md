## Vendor Disclosure Monitoring Platform

Local-host cybersecurity vendor disclosure monitoring platform with:

- **Backend**: FastAPI + SQLite + APScheduler monitoring engine.
- **Frontend**: Next.js React dashboard.

### Prerequisites

- **Python**: 3.11 or 3.12 (recommended; 3.14 is too new for current Pydantic wheels).
- **Node.js**: 18+ and npm (or yarn/pnpm).

### 1. Backend setup (FastAPI + SQLite)

From the project root:

```bash
cd vendor-disclosure-monitor
python -m venv .venv  # or: py -3.11 -m venv .venv
# If PowerShell blocks script activation, install via explicit interpreter path:
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

Run the API:

```bash
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

On first start the app will:

- Create the SQLite database at `data/monitor.db`.
- Load vendors and sources from `config/vendors.yaml`.
- Start the monitoring scheduler to poll sources every few minutes.

You can trigger an immediate collection via:

- `POST http://localhost:8000/refresh`

and monitor basic health via:

- `GET http://localhost:8000/health`
- `GET http://localhost:8000/ai/health` (shows active provider: Ollama/OpenRouter/none)

### 2. Frontend setup (Next.js dashboard)

In a new terminal, from the project root:

```bash
cd vendor-disclosure-monitor\frontend
npm install
npm run dev
```

The dashboard will be available at:

- `http://localhost:3000`

By default it talks to the backend at `http://localhost:8000`. To change this, create `frontend/.env.local`:

```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

### 3. Docker deployment

From project root:

```bash
docker compose up -d --build
```

Services:

- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8000`
- Ollama API: `http://localhost:11434`

After first startup, pull your model inside the Ollama container:

```bash
docker exec -it vdm-ollama ollama pull mnowfalcyberxtron/er
```

Validate AI providers:

```bash
curl http://localhost:8000/ai/health
```

If you deploy with Docker and want backend to use containerized Ollama, set:

```bash
OLLAMA_BASE_URL=http://ollama:11434
```

### 4. Key features

- **Official Vendor Disclosures vs External Intelligence** clearly separated via `source_type`.
- **Monitoring engine**:
  - RSS, HTML, simple JSON APIs, and GitHub Security Advisories.
  - Normalisation of incidents with CVE extraction, IOC extraction (IPs, domains, hashes), and MITRE ATT&CK technique IDs.
  - De-duplication based on `(source_id, source_link)`.
- **Dashboard UI**:
  - Vendor sidebar with incident counts.
  - Global search, source-type filter, manual refresh button, and auto-refresh.
  - Timeline view grouped by date with newest incidents first.
  - Company-specific pages and incident detail pages with IOCs, CVEs, MITRE techniques, and source link.

### 5. AI summary generation (Ollama -> OpenRouter -> Groq fallback)

The ingestion pipeline generates advisory-style summaries using:

1. **Ollama first** (local), then
2. **OpenRouter fallback**, then
3. **Groq fallback**.

Configure in root `.env` (or shell env):

```bash
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
OLLAMA_API_KEY=

OPENROUTER_API_KEY=your_key
OPENROUTER_MODEL=openai/gpt-4o-mini
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
# Optional:
OPENROUTER_HTTP_REFERER=http://localhost:3000
OPENROUTER_X_TITLE=Vendor Disclosure Monitor

GROQ_API_KEY=your_key
GROQ_MODEL=llama-3.3-70b-versatile
GROQ_BASE_URL=https://api.groq.com/openai/v1
```

Use runtime provider switch:

- `POST /ai/provider?provider=auto|ollama|openrouter|groq`

Check provider status:

- `GET /ai/health`

### 6. Adding vendors and sources

To add a new vendor or source, edit `config/vendors.yaml`:

- Add a new entry under `companies:` with:
  - `name`, `slug`, `official_site`.
  - One or more `sources` with:
    - `name`, `type` (`OFFICIAL_VENDOR` or `EXTERNAL_INTEL`), `subtype` (`RSS`, `HTML_PAGE`, `API`, `GITHUB`), `url`, and optional `parser_hint`.

On the next backend restart, or after editing the file and calling `/refresh`, the new vendors/sources will be loaded automatically.

