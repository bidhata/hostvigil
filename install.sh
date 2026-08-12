#!/usr/bin/env bash
# ============================================================================
# HostVigil - Host-Based Installation Script (Linux / macOS)
# ============================================================================
#
# Installs all dependencies and configures the environment for HostVigil.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# What it does:
#   1. Checks Python 3.11+ is available
#   2. Installs system dependencies (nmap, libpcap)
#   3. Optionally installs Nuclei vulnerability scanner
#   4. Optionally installs naabu port scanner (fast two-phase scanning)
#   5. Creates a Python virtual environment
#   6. Installs Python dependencies
#   7. Creates data directories
#   8. Initializes the database
#   8. Validates the installation
#
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BANNER='
  _   _           _  __     ___       _ _
 | | | | ___  ___| |_\ \   / (_) __ _(_) |
 | |_| |/ _ \/ __| __|\ \ / /| |/ _` | | |
 |  _  | (_) \__ \ |_  \ V / | | (_| | | |
 |_| |_|\___/|___/\__|  \_/  |_|\__, |_|_|
                                 |___/
        Stealth Internal Recon Platform
'

echo -e "${BLUE}${BANNER}${NC}"
echo -e "${BLUE}[*] HostVigil Installation Script${NC}"
echo "============================================"
echo ""

# ---------------------------------------------------------------------------
# 1. Check Python version
# ---------------------------------------------------------------------------
echo -e "${BLUE}[1/8] Checking Python version...${NC}"

PYTHON_CMD=""
for cmd in python3.13 python3.12 python3.11 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$($cmd --version 2>&1 | grep -oP '\d+\.\d+')
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}[!] Python 3.11+ is required but not found.${NC}"
    echo "    Install it with:"
    echo "      Ubuntu/Debian: sudo apt install python3.11 python3.11-venv"
    echo "      Fedora:        sudo dnf install python3.11"
    echo "      macOS:         brew install python@3.11"
    exit 1
fi

echo -e "${GREEN}    Found: $($PYTHON_CMD --version)${NC}"

# ---------------------------------------------------------------------------
# 2. Install system dependencies
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[2/8] Installing system dependencies...${NC}"

install_linux_deps() {
    if command -v apt-get &>/dev/null; then
        # Debian/Ubuntu
        echo "    Detected: Debian/Ubuntu"
        sudo apt-get update -qq
        sudo apt-get install -y -qq nmap libpcap-dev tcpdump wget unzip curl
    elif command -v dnf &>/dev/null; then
        # Fedora/RHEL
        echo "    Detected: Fedora/RHEL"
        sudo dnf install -y nmap libpcap-devel tcpdump wget unzip curl
    elif command -v yum &>/dev/null; then
        # CentOS/older RHEL
        echo "    Detected: CentOS/RHEL"
        sudo yum install -y nmap libpcap-devel tcpdump wget unzip curl
    elif command -v pacman &>/dev/null; then
        # Arch Linux
        echo "    Detected: Arch Linux"
        sudo pacman -S --noconfirm nmap libpcap tcpdump wget unzip curl
    elif command -v apk &>/dev/null; then
        # Alpine
        echo "    Detected: Alpine"
        sudo apk add nmap libpcap-dev tcpdump wget unzip curl
    else
        echo -e "${YELLOW}    [!] Unknown package manager. Please install manually:${NC}"
        echo "        - nmap"
        echo "        - libpcap-dev (or libpcap-devel)"
        echo "        - tcpdump"
    fi
}

install_macos_deps() {
    if command -v brew &>/dev/null; then
        echo "    Detected: macOS (Homebrew)"
        brew install nmap libpcap wget
    else
        echo -e "${YELLOW}    [!] Homebrew not found. Please install:${NC}"
        echo "        /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        echo "        Then: brew install nmap libpcap wget"
    fi
}

OS="$(uname -s)"
case "$OS" in
    Linux*)  install_linux_deps ;;
    Darwin*) install_macos_deps ;;
    *)       echo -e "${YELLOW}    [!] Unsupported OS: $OS. Install nmap manually.${NC}" ;;
esac

# Verify nmap
if command -v nmap &>/dev/null; then
    echo -e "${GREEN}    nmap: $(nmap --version 2>&1 | head -1)${NC}"
else
    echo -e "${YELLOW}    [!] nmap not found in PATH. Install it before running HostVigil.${NC}"
fi

# ---------------------------------------------------------------------------
# 3. Install Nuclei (optional)
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[3/8] Installing Nuclei vulnerability scanner (optional)...${NC}"

if command -v nuclei &>/dev/null; then
    echo -e "${GREEN}    Nuclei already installed: $(nuclei -version 2>&1 | head -1)${NC}"
else
    echo -n "    Install Nuclei? (recommended for vuln scanning) [Y/n]: "
    read -r INSTALL_NUCLEI
    INSTALL_NUCLEI=${INSTALL_NUCLEI:-Y}

    if [[ "$INSTALL_NUCLEI" =~ ^[Yy] ]]; then
        echo "    Downloading latest Nuclei release..."
        ARCH="$(uname -m)"
        case "$ARCH" in
            x86_64|amd64) NUCLEI_ARCH="amd64" ;;
            aarch64|arm64) NUCLEI_ARCH="arm64" ;;
            *) echo -e "${YELLOW}    [!] Unsupported arch: $ARCH. Download manually from:${NC}"
               echo "        https://github.com/projectdiscovery/nuclei/releases"
               NUCLEI_ARCH="" ;;
        esac

        if [ -n "$NUCLEI_ARCH" ]; then
            NUCLEI_OS="linux"
            [ "$OS" = "Darwin" ] && NUCLEI_OS="darwin"

            NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | cut -d'"' -f4 | tr -d v)
            NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${NUCLEI_OS}_${NUCLEI_ARCH}.zip"

            wget -q "$NUCLEI_URL" -O /tmp/nuclei.zip
            sudo unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei >/dev/null 2>&1
            sudo chmod +x /usr/local/bin/nuclei
            rm -f /tmp/nuclei.zip

            # Update templates
            echo "    Updating Nuclei templates..."
            nuclei -update-templates >/dev/null 2>&1 || true
            echo -e "${GREEN}    Nuclei installed: $(nuclei -version 2>&1 | head -1)${NC}"
        fi
    else
        echo "    Skipped. You can install later from: https://github.com/projectdiscovery/nuclei/releases"
    fi
fi

# ---------------------------------------------------------------------------
# 4. Install naabu (optional - for fast two-phase port scanning)
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[4/8] Installing naabu port scanner (optional)...${NC}"

if command -v naabu &>/dev/null; then
    echo -e "${GREEN}    naabu already installed: $(naabu -version 2>&1 | head -1)${NC}"
else
    echo -e "${YELLOW}    Installing naabu...${NC}"
    # Method 1: Go install (if Go is available)
    if command -v go &>/dev/null; then
        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
        # Symlink to /usr/local/bin if installed to ~/go/bin
        if [ -f "$HOME/go/bin/naabu" ] && [ ! -f "/usr/local/bin/naabu" ]; then
            sudo ln -sf "$HOME/go/bin/naabu" /usr/local/bin/naabu
        fi
    # Method 2: Download binary
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        NAABU_VERSION="2.3.3"
        wget -q "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip" -O /tmp/naabu.zip
        unzip -o /tmp/naabu.zip -d /tmp/naabu_extract
        sudo mv /tmp/naabu_extract/naabu /usr/local/bin/naabu
        sudo chmod +x /usr/local/bin/naabu
        rm -rf /tmp/naabu.zip /tmp/naabu_extract
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install naabu
    fi
    
    if command -v naabu &>/dev/null; then
        echo -e "${GREEN}    ✓ naabu installed successfully${NC}"
    else
        echo -e "${YELLOW}    ⚠ naabu installation failed (optional - two_phase mode won't work)${NC}"
    fi
fi

# ---------------------------------------------------------------------------
# 5. Create Python virtual environment
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[5/8] Setting up Python virtual environment...${NC}"

if [ -d "venv" ]; then
    echo "    Virtual environment already exists at ./venv"
    echo -n "    Recreate? [y/N]: "
    read -r RECREATE_VENV
    if [[ "$RECREATE_VENV" =~ ^[Yy] ]]; then
        rm -rf venv
        $PYTHON_CMD -m venv venv
        echo -e "${GREEN}    Virtual environment recreated.${NC}"
    fi
else
    $PYTHON_CMD -m venv venv
    echo -e "${GREEN}    Virtual environment created at ./venv${NC}"
fi

# Activate
source venv/bin/activate
echo "    Activated: $(python --version) @ $(which python)"

# ---------------------------------------------------------------------------
# 5. Install Python dependencies
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[6/8] Installing Python dependencies...${NC}"

pip install --upgrade pip setuptools wheel -q
pip install -r requirements.txt -q

echo -e "${GREEN}    All Python packages installed.${NC}"

# ---------------------------------------------------------------------------
# 6. Create data directories
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[7/8] Creating data directories...${NC}"

mkdir -p data/logs data/models data/scans data/reports plugins
echo -e "${GREEN}    Created: data/{logs,models,scans,reports}, plugins/${NC}"

# ---------------------------------------------------------------------------
# 7. Initialize database and validate
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[8/8] Initializing database and validating...${NC}"

python -c "from hostvigil.utils import init_database; init_database(); print('    Database initialized: data/hostvigil.db')"

# Quick validation
echo ""
echo "    Running validation checks..."
python -c "
from hostvigil.config import Config
from hostvigil.orchestrator import HostVigilOrchestrator
import shutil

checks_ok = 0
checks_total = 0

# Check nmap
checks_total += 1
nmap = shutil.which('nmap')
if nmap:
    print(f'      [OK] nmap: {nmap}')
    checks_ok += 1
else:
    print('      [!!] nmap: NOT FOUND')

# Check nuclei
checks_total += 1
nuclei = shutil.which('nuclei')
if nuclei:
    print(f'      [OK] nuclei: {nuclei}')
    checks_ok += 1
else:
    print('      [--] nuclei: not installed (optional)')
    checks_ok += 1  # optional

# Check naabu
checks_total += 1
naabu = shutil.which('naabu')
if naabu:
    print(f'      [OK] naabu: {naabu}')
    checks_ok += 1
else:
    print('      [--] naabu: not installed (optional, for two-phase mode)')
    checks_ok += 1  # optional

# Check config
checks_total += 1
try:
    Config('config.yaml')
    print('      [OK] config.yaml: valid')
    checks_ok += 1
except Exception as e:
    print(f'      [!!] config.yaml: {e}')

# Check modules
checks_total += 1
try:
    from hostvigil.discovery import StealthDiscovery
    from hostvigil.scanner import StealthScanner
    from hostvigil.ml_engine import AnomalyDetector
    from hostvigil.nuclei import NucleiRunner
    from hostvigil.dashboard import create_app
    print('      [OK] All modules import successfully')
    checks_ok += 1
except Exception as e:
    print(f'      [!!] Module import failed: {e}')

print(f'\n    Checks passed: {checks_ok}/{checks_total}')
"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo -e "${GREEN}[+] Installation complete!${NC}"
echo ""
echo "  To start HostVigil:"
echo "    source venv/bin/activate"
echo "    python run.py daemon"
echo ""
echo "  Dashboard will be available at:"
echo "    http://127.0.0.1:5000"
echo "    Login: admin / hostvigil"
echo ""
echo "  For 200k+ host networks:"
echo "    python run.py -c entp_config.yaml daemon"
echo ""
echo "  Other commands:"
echo "    python run.py --help"
echo "    python run.py status"
echo "    python run.py doctor"
echo ""
echo -e "${YELLOW}  ⚠️  For ARP/SYN scans, run with sudo or as root.${NC}"
echo "============================================"
