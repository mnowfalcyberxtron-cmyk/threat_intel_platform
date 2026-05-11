FROM python:3.11-slim

WORKDIR /app

# Prevent interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

# ── System dependencies ──────────────────────────────────────────────────────
# Full set for Playwright Chromium + screenshots + email SSL + Tor SOCKS
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core tools
    ca-certificates \
    curl \
    wget \
    gnupg \
    # Email sending (SMTP SSL/TLS)
    libssl3 \
    openssl \
    # NSS (network security)
    libnss3 \
    libnss3-dev \
    # ATK accessibility (required by Chromium)
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libatspi2.0-0 \
    # Pango + Cairo (TEXT RENDERING / SCREENSHOTS - was missing before)
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libcairo-gobject2 \
    # Cups
    libcups2 \
    # DRM & GPU rendering
    libdrm2 \
    libgbm1 \
    # X11 display
    libx11-6 \
    libxcb1 \
    libxcb-dri3-0 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    # Audio
    libasound2 \
    # GLib / GTK
    libglib2.0-0 \
    libgtk-3-0 \
    # Font rendering
    libfontconfig1 \
    fonts-liberation \
    # DBUS
    libdbus-1-3 \
    # Other shared libs
    libexpat1 \
    libfribidi0 \
    libjpeg62-turbo \
    libpng16-16 \
    # Networking (for Tor/SOCKS)
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ──────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Playwright: install Chromium browser binary ──────────────────────────────
# We manually install deps above so we skip playwright install-deps
# (which fails on Debian trixie due to renamed packages)
RUN playwright install chromium

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
