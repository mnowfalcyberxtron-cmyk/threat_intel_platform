FROM python:3.11-bookworm

WORKDIR /app

# Prevent interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

# ── System dependencies ──────────────────────────────────────────────────────
# Minimal set for basics, Playwright will handle the rest via install-deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    gnupg \
    openssl \
    libssl3 \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ──────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Playwright: install Chromium browser binary + dependencies ───────────────
RUN playwright install chromium
RUN playwright install-deps chromium

# ── Application code ─────────────────────────────────────────────────────────
COPY . .

# ── Runtime directories ───────────────────────────────────────────────────────
RUN mkdir -p data logs screenshots reports

# ── Environment defaults ──────────────────────────────────────────────────────
ENV HOST=0.0.0.0
ENV PORT=8002
ENV DB_PATH=data/threat_intel.db
ENV ENABLE_DARKWEB=true
ENV TOR_SOCKS_HOST=tor
ENV TOR_SOCKS_PORT=9050
ENV AUTO_RUN_ALL_ON_STARTUP=true

# ── Expose port ───────────────────────────────────────────────────────────────
EXPOSE 8002

# ── Launch ────────────────────────────────────────────────────────────────────
CMD ["python", "main.py"]
