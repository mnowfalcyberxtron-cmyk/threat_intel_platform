#!/usr/bin/env bash
# ============================================================
# CyberXTron Threat Intelligence Platform — Setup Script
# ============================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${CYAN}========================================================${NC}"
echo -e "${CYAN}  CyberXTron TIP — Setup${NC}"
echo -e "${CYAN}========================================================${NC}"

# Python version check
PYTHON=$(command -v python3 || command -v python)
PY_VERSION=$($PYTHON --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✓ Python: $PY_VERSION${NC}"

# Create virtual environment
if [ ! -d "venv" ]; then
  echo -e "${CYAN}Creating virtual environment...${NC}"
  $PYTHON -m venv venv
fi

# Activate venv
source venv/bin/activate || . venv/Scripts/activate 2>/dev/null

# Upgrade pip
pip install --upgrade pip -q

# Install dependencies
echo -e "${CYAN}Installing dependencies...${NC}"
pip install -r requirements.txt -q

# Create .env from template
if [ ! -f ".env" ]; then
  cp .env.example .env
  echo -e "${GREEN}✓ Created .env from template${NC}"
  echo -e "${YELLOW}  → Edit .env to add API keys for Tier 2/3 connectors${NC}"
else
  echo -e "${GREEN}✓ .env already exists${NC}"
fi

# Create directories
mkdir -p data logs frontend/static

echo ""
echo -e "${GREEN}========================================================${NC}"
echo -e "${GREEN}  Setup complete!${NC}"
echo -e "${GREEN}========================================================${NC}"
echo ""
echo -e "Start the platform:"
echo -e "  ${CYAN}source venv/bin/activate${NC}"
echo -e "  ${CYAN}python main.py${NC}"
echo ""
echo -e "Dashboard: ${CYAN}http://localhost:8000${NC}"
echo -e "API docs:  ${CYAN}http://localhost:8000/api/docs${NC}"
echo ""
echo -e "${YELLOW}Optional:${NC}"
echo -e "  For dark web monitoring: sudo apt install tor && sudo systemctl start tor"
echo -e "  Edit .env to set: ENABLE_DARKWEB=true"
echo ""
