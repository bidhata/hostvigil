#!/bin/bash
# ============================================================================
# HostVigil — Quick Start (get scanning in 60 seconds)
# ============================================================================
# Prerequisites: Python 3.11+, nmap
# Optional: naabu (for enterprise-speed scanning), nuclei (vuln scanning)
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo '  _   _           _  __     ___       _ _ '
echo ' | | | | ___  ___| |_\ \   / (_) __ _(_) |'
echo ' | |_| |/ _ \/ __| __|\ \ / /| |/ _` | | |'
echo ' |  _  | (_) \__ \ |_  \ V / | | (_| | | |'
echo ' |_| |_|\___/|___/\__|  \_/  |_|\__, |_|_|'
echo '                                 |___/     '
echo -e "${NC}"
echo "=== Quick Start ==="
echo ""

# Determine script directory (works even if called from elsewhere)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Step 1: Check prerequisites
# ---------------------------------------------------------------------------
echo -e "${BLUE}[1/5] Checking prerequisites...${NC}"

FAIL=0

# Python 3.11+
PYTHON=""
for cmd in python3.13 python3.12 python3.11 python3; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -n "$PYTHON" ]; then
    echo -e "  ${GREEN}✓${NC} Python: $($PYTHON --version)"
else
    echo -e "  ${RED}✗${NC} Python 3.11+ required"
    echo "    Install: sudo apt install python3.11 python3.11-venv"
    FAIL=1
fi

# nmap
if command -v nmap &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} nmap: $(nmap --version 2>&1 | head -1 | sed 's/Nmap version //')"
else
    echo -e "  ${RED}✗${NC} nmap required"
    echo "    Install: sudo apt install nmap"
    FAIL=1
fi

# naabu (optional)
if command -v naabu &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} naabu: available (fast two-phase scanning)"
else
    echo -e "  ${YELLOW}–${NC} naabu: not installed (optional, for 200k+ hosts)"
fi

# nuclei (optional)
if command -v nuclei &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} nuclei: available (vuln scanning)"
else
    echo -e "  ${YELLOW}–${NC} nuclei: not installed (optional, for vulnerability scanning)"
fi

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo -e "${RED}Missing required dependencies. Install them and re-run.${NC}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 2: Setup Python environment
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[2/5] Setting up Python environment...${NC}"

if [ ! -d "venv" ]; then
    $PYTHON -m venv venv
    echo -e "  ${GREEN}✓${NC} Virtual environment created"
else
    echo -e "  ${GREEN}✓${NC} Virtual environment exists"
fi

source venv/bin/activate
pip install --upgrade pip -q 2>/dev/null
pip install -r requirements.txt -q
echo -e "  ${GREEN}✓${NC} Dependencies installed"

# ---------------------------------------------------------------------------
# Step 3: Initialize database
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[3/5] Initializing database...${NC}"

mkdir -p data/logs data/models data/scans data/reports plugins
python -c "
import sys; sys.path.insert(0, '.')
from hostvigil.utils import init_database
conn = init_database('data/hostvigil.db')
conn.close()
print('  ✓ Database ready: data/hostvigil.db')
"

# ---------------------------------------------------------------------------
# Step 4: Validate config
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[4/5] Validating configuration...${NC}"

python -c "
import sys; sys.path.insert(0, '.')
from hostvigil.config import Config
c = Config('config.yaml')
targets = c.discovery.get('target_ranges', [])
mode = c.scanner.get('mode', 'nmap_only')
delay = c.stealth.get('min_delay', 10)
print(f'  Target ranges: {targets}')
print(f'  Scanner mode:  {mode}')
print(f'  Stealth delay: {delay}s - {c.stealth.get(\"max_delay\", 45)}s')
print(f'  Threads:       {c.stealth.get(\"max_threads\", 3)}')
print(f'  Nuclei auto:   {c.nuclei.get(\"auto_run\", False)}')
"

# ---------------------------------------------------------------------------
# Step 5: Ready
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[5/5] Ready!${NC}"
echo ""
echo "============================================"
echo ""
echo -e "  ${GREEN}Start the daemon (scan + dashboard):${NC}"
echo "    source venv/bin/activate"
echo "    python run.py daemon"
echo ""
echo -e "  ${GREEN}Dashboard:${NC} http://127.0.0.1:5000"
echo "  Login: admin / hostvigil"
echo ""
echo "  ─── Other commands ───"
echo "    python run.py discover        # Discovery only"
echo "    python run.py scan            # Port scan only"
echo "    python run.py nuclei          # Vulnerability scan"
echo "    python run.py status          # Show status"
echo "    python run.py dashboard --host 0.0.0.0  # Expose dashboard"
echo ""
echo "  ─── Enterprise (200k+ hosts) ───"
echo "    python run.py -c entp_config.yaml daemon"
echo ""
echo "  ─── Edit config ───"
echo "    Edit config.yaml or use the Settings page in dashboard"
echo ""
echo "============================================"
echo -e "  ${YELLOW}⚠️  For SYN scans / ARP sweep, run as root${NC}"
echo "============================================"
