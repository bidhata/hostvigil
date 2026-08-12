# ============================================================================
# HostVigil - Windows Installation Script (PowerShell)
# ============================================================================
#
# Installs all dependencies and configures the environment for HostVigil.
#
# Usage (PowerShell as Administrator):
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# What it does:
#   1. Checks Python 3.11+ is available
#   2. Installs system dependencies (nmap) via winget/choco
#   3. Optionally installs Nuclei vulnerability scanner
#   4. Optionally installs naabu port scanner (fast two-phase scanning)
#   5. Creates a Python virtual environment
#   6. Installs Python dependencies
#   7. Creates data directories
#   8. Initializes the database
#   9. Validates the installation
#
# ============================================================================

$ErrorActionPreference = "Stop"

$BANNER = @"
  _   _           _  __     ___       _ _
 | | | | ___  ___| |_\ \   / (_) __ _(_) |
 | |_| |/ _ \/ __| __|\ \ / /| |/ _` | | |
 |  _  | (_) \__ \ |_  \ V / | | (_| | | |
 |_| |_|\___/|___/\__|  \_/  |_|\__, |_|_|
                                 |___/
        Stealth Internal Recon Platform
"@

Write-Host ""
Write-Host $BANNER -ForegroundColor Cyan
Write-Host "[*] HostVigil Installation Script" -ForegroundColor Cyan
Write-Host "============================================"
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Check Python version
# ---------------------------------------------------------------------------
Write-Host "[1/9] Checking Python version..." -ForegroundColor Cyan

$PYTHON_CMD = $null
foreach ($cmd in @("python3.13", "python3.12", "python3.11", "python")) {
    $candidate = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($candidate) {
        $verLine = & $candidate.Source --version 2>&1 | Select-Object -First 1
        if ($verLine -match '(\d+)\.(\d+)') {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 11)) {
                $PYTHON_CMD = $candidate.Source
                break
            }
        }
    }
}

if (-not $PYTHON_CMD) {
    Write-Host "[!] Python 3.11+ is required but not found." -ForegroundColor Red
    Write-Host "    Install it from: https://www.python.org/downloads/"
    Write-Host "    (Ensure 'Add Python to PATH' is checked during install)"
    exit 1
}

Write-Host "    Found: $(& $PYTHON_CMD --version)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2. Install system dependencies
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[2/9] Installing system dependencies (nmap)..." -ForegroundColor Cyan

if (Get-Command nmap -ErrorAction SilentlyContinue) {
    Write-Host "    nmap already installed: $(& nmap --version 2>&1 | Select-Object -First 1)" -ForegroundColor Green
} else {
    Write-Host "    nmap not found. Attempting to install via winget..." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Insecure.Nmap --accept-source-agreements --accept-package-agreements -e
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install nmap -y
    } else {
        Write-Host "[!] No winget or Chocolatey available. Install nmap manually:" -ForegroundColor Yellow
        Write-Host "    https://nmap.org/download.html"
    }
}

if (Get-Command nmap -ErrorAction SilentlyContinue) {
    Write-Host "    nmap: $(& nmap --version 2>&1 | Select-Object -First 1)" -ForegroundColor Green
} else {
    Write-Host "[!] nmap not in PATH. Install it before running HostVigil." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 3. Install Nuclei (optional)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[3/9] Installing Nuclei vulnerability scanner (optional)..." -ForegroundColor Cyan

# Tools directory added to the user PATH so `nuclei`/`naabu` resolve everywhere
$toolsDir = Join-Path $env:LOCALAPPDATA "Programs\HostVigil\bin"
New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null

if (Get-Command nuclei -ErrorAction SilentlyContinue) {
    Write-Host "    Nuclei already installed: $(& nuclei -version 2>&1 | Select-Object -First 1)" -ForegroundColor Green
} else {
    $installNuclei = Read-Host "    Install Nuclei? (recommended for vuln scanning) [Y/n]"
    if ($installNuclei -eq "" -or $installNuclei -match "^[Yy]") {
        Write-Host "    Downloading latest Nuclei release..."
        $arch = $env:PROCESSOR_ARCHITECTURE
        if ($arch -eq "AMD64") { $nucleiArch = "amd64" }
        elseif ($arch -eq "ARM64") { $nucleiArch = "arm64" }
        else {
            Write-Host "[!] Unsupported arch: $arch. Download manually from:" -ForegroundColor Yellow
            Write-Host "    https://github.com/projectdiscovery/nuclei/releases"
            $nucleiArch = ""
        }

        if ($nucleiArch) {
            try {
                $release = Invoke-RestMethod -Uri "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
                $nucleiVersion = $release.tag_name.TrimStart("v")
                $url = "https://github.com/projectdiscovery/nuclei/releases/download/v${nucleiVersion}/nuclei_${nucleiVersion}_windows_${nucleiArch}.zip"
                $zipPath = "$env:TEMP\nuclei.zip"
                $extractPath = "$env:TEMP\nuclei_extract"
                Invoke-WebRequest -Uri $url -OutFile $zipPath
                if (Test-Path $extractPath) { Remove-Item -Recurse -Force $extractPath }
                Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
                Copy-Item "$extractPath\nuclei.exe" $toolsDir -Force
                Remove-Item -Force $zipPath
                Remove-Item -Recurse -Force $extractPath
                Write-Host "    Nuclei installed to $toolsDir\nuclei.exe" -ForegroundColor Green
                Write-Host "    Update templates: nuclei -update-templates" -ForegroundColor Green
            } catch {
                Write-Host "[!] Nuclei download failed: $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "    Install manually from: https://github.com/projectdiscovery/nuclei/releases"
            }
        }
    } else {
        Write-Host "    Skipped. You can install later from: https://github.com/projectdiscovery/nuclei/releases"
    }
}

# ---------------------------------------------------------------------------
# 4. Install naabu (optional - for fast two-phase port scanning)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[4/9] Installing naabu port scanner (optional)..." -ForegroundColor Cyan

if (Get-Command naabu -ErrorAction SilentlyContinue) {
    Write-Host "    naabu already installed: $(& naabu -version 2>&1 | Select-Object -First 1)" -ForegroundColor Green
} else {
    Write-Host "    Downloading naabu v2.3.3..."
    try {
        $zipPath = "$env:TEMP\naabu.zip"
        $extractPath = "$env:TEMP\naabu_extract"
        Invoke-WebRequest -Uri "https://github.com/projectdiscovery/naabu/releases/download/v2.3.3/naabu_2.3.3_windows_amd64.zip" -OutFile $zipPath
        if (Test-Path $extractPath) { Remove-Item -Recurse -Force $extractPath }
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        Copy-Item "$extractPath\naabu.exe" $toolsDir -Force
        Remove-Item -Force $zipPath
        Remove-Item -Recurse -Force $extractPath
        Write-Host "    naabu installed to $toolsDir\naabu.exe" -ForegroundColor Green
    } catch {
        Write-Host "[!] naabu installation failed (optional - two_phase mode won't work)" -ForegroundColor Yellow
    }
}

# Add tools dir to the user PATH if not already present
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$toolsDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$toolsDir", "User")
    Write-Host "    Added $toolsDir to user PATH (new shells only)" -ForegroundColor Green
}
# Make it visible to the current process and subsequent steps
$env:Path = "$env:Path;$toolsDir"

# ---------------------------------------------------------------------------
# 5. Create Python virtual environment
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[5/9] Setting up Python virtual environment..." -ForegroundColor Cyan

if (Test-Path "venv") {
    Write-Host "    Virtual environment already exists at .\venv"
    $recreate = Read-Host "    Recreate? [y/N]"
    if ($recreate -match "^[Yy]") {
        Remove-Item -Recurse -Force "venv"
        & $PYTHON_CMD -m venv venv
        Write-Host "    Virtual environment recreated." -ForegroundColor Green
    }
} else {
    & $PYTHON_CMD -m venv venv
    Write-Host "    Virtual environment created at .\venv" -ForegroundColor Green
}

$venvPython = Join-Path (Get-Location) "venv\Scripts\python.exe"

# ---------------------------------------------------------------------------
# 6. Install Python dependencies
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[6/9] Installing Python dependencies..." -ForegroundColor Cyan

& $venvPython -m pip install --upgrade pip setuptools wheel -q
& $venvPython -m pip install -r requirements.txt -q

Write-Host "    All Python packages installed." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 7. Create data directories
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[7/9] Creating data directories..." -ForegroundColor Cyan

foreach ($dir in @("data\logs", "data\models", "data\scans", "data\reports", "plugins")) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
Write-Host "    Created: data\{logs,models,scans,reports}, plugins\" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 8. Initialize database
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[8/9] Initializing database..." -ForegroundColor Cyan

& $venvPython -c "from hostvigil.utils import init_database; init_database(); print('    Database initialized: data\hostvigil.db')"

# ---------------------------------------------------------------------------
# 9. Validate installation
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[9/9] Running validation checks..." -ForegroundColor Cyan

& $venvPython -c @"
import shutil

checks_ok = 0
checks_total = 0

checks_total += 1
nmap = shutil.which('nmap')
if nmap:
    print(f'      [OK] nmap: {nmap}')
    checks_ok += 1
else:
    print('      [!!] nmap: NOT FOUND')

checks_total += 1
nuclei = shutil.which('nuclei')
if nuclei:
    print(f'      [OK] nuclei: {nuclei}')
    checks_ok += 1
else:
    print('      [--] nuclei: not installed (optional)')
    checks_ok += 1

checks_total += 1
naabu = shutil.which('naabu')
if naabu:
    print(f'      [OK] naabu: {naabu}')
    checks_ok += 1
else:
    print('      [--] naabu: not installed (optional, for two-phase mode)')
    checks_ok += 1

checks_total += 1
try:
    from hostvigil.config import Config
    Config('config.yaml')
    print('      [OK] config.yaml: valid')
    checks_ok += 1
except Exception as e:
    print(f'      [!!] config.yaml: {e}')

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
"@

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "============================================"
Write-Host "[+] Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  To start HostVigil:"
Write-Host "    .\venv\Scripts\activate"
Write-Host "    python run.py daemon"
Write-Host ""
Write-Host "  Dashboard will be available at:"
Write-Host "    http://127.0.0.1:5000"
Write-Host "    Login: admin / hostvigil"
Write-Host ""
Write-Host "  For 200k+ host networks:"
Write-Host "    python run.py -c entp_config.yaml daemon"
Write-Host ""
Write-Host "  Other commands:"
Write-Host "    python run.py --help"
Write-Host "    python run.py status"
Write-Host "    python run.py doctor"
Write-Host ""
Write-Host "============================================"
