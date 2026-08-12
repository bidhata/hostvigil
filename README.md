<p align="center">
  <img src="images/logo.png" alt="HostVigil" width="200">
</p>

<h1 align="center">HostVigil</h1>

<p align="center">
  <strong>The ghost in your network. Stealth internal reconnaissance that learns.</strong>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
  <a href="#stealth-features"><img src="https://img.shields.io/badge/stealth-maximum-black.svg" alt="Stealth: Maximum"></a>
  <a href="#ml-engine"><img src="https://img.shields.io/badge/ML-self--learning-purple.svg" alt="ML: Self-Learning"></a>
  <a href="https://github.com/bidhata/HostVigil/stargazers"><img src="https://img.shields.io/github/stars/bidhata/HostVigil?style=social" alt="Stars"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#why-hostvigil">Why HostVigil</a> •
  <a href="#features">Features</a> •
  <a href="#dashboard">Dashboard</a> •
  <a href="#red-team-playbook">Red Team Playbook</a> •
  <a href="#ml-engine">ML Engine</a>
</p>

---

## 🎯 What is HostVigil?

HostVigil is a **self-learning stealth reconnaissance platform** built for red teamers, pentesters, and internal security teams. It continuously maps your internal network, identifies vulnerabilities, and learns what's normal — so it can alert you when something isn't.

**The difference?** It does all of this while remaining invisible to blue team defenses.

```
     You:  "Scan the entire 10.0.0.0/8"
     Nmap: *immediately sets off 47 IDS alerts*
HostVigil: *discovers 20,000 hosts over few hours, zero alerts triggered*
```

---

## 🚀 Why HostVigil?

| Problem | HostVigil's Answer |
|---------|-------------------|
| Network scanners trigger IDS/IPS alerts | Randomized timing, adaptive throttling, and decoy packets |
| Point-in-time scans miss changes | Continuous daemon mode with ML-powered drift detection |
| Manual recon doesn't scale to /8 networks | Automated pipeline handles millions of IPs |
| Scan results are just lists of ports | ML correlates findings, scores anomalies, classifies exploits |
| No context for prioritization | Red Team view groups findings by attack vector |
| Previous engagement data is lost | Full import/export — carry your intel forward |

---

## ⚡ Quick Start

```bash
git clone https://github.com/bidhata/HostVigil.git
cd HostVigil
python -m venv venv && source venv/bin/activate  # Linux/macOS
# Windows: python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt

# Start the daemon (continuous stealth recon + dashboard)
python run.py daemon
# → Dashboard at http://localhost:5000
```

That's it. HostVigil is now **automatically scanning** your network in continuous cycles — discovery, port scanning, service enumeration, TLS inspection, fingerprinting, and ML analysis all run on a loop with stealth timing. No manual triggering needed.

> **Monitor progress live:** Open the **Live Status** page in the dashboard to see real-time pipeline phase progress, a countdown to the next cycle, and per-phase results — all without touching the database (safe even with 200k+ hosts).

> **Pipeline order is optimized for fast actionable results:** Discovery (nmap first) → TCP scan → Service enum (low-hanging fruit) → TLS inspection → OS fingerprint → UDP scan → ML analysis.

> **Note:** Nuclei (vulnerability scanning) is disabled in the default config (`auto_run: false`) for maximum stealth. Trigger manually from the dashboard or with `python run.py nuclei`. To enable auto-run in daemon mode, set `auto_run: true` in config — it fires on its own interval (default 6h) once enough web targets are discovered (`min_targets: 20` threshold).

> **Note:** Deep service/version detection (`nmap -sV`) is also excluded from daemon mode — nmap's version probes have a recognizable signature. Trigger manually with `python run.py servicescan` or the dashboard button.

> **Passive-only observer mode:** When you need a baseline without touching the network, `python run.py observer` runs discovery using only listen/passive techniques (zero active probes) plus ML analysis on existing data — no port scans, no service connects, no nuclei.

> **Attack-chain correlation:** Each daemon cycle ends with the attack-path engine correlating findings into MITRE-mapped attack chains. Results are persisted to the `attack_chains` table and exported to `data/attack_chains.json` for downstream tooling.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           HostVigil Engine                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐ │
│  │  Discovery   │───▶│   Scanner    │───▶│  ML Engine   │───▶│  Nuclei  │ │
│  │              │    │              │    │              │    │(manual)  │ │
│  │ • Nmap -sn   │    │ • TCP Stealth│    │ • Anomaly    │    │          │ │
│  │ • ARP Sweep  │    │ • UDP Probes │    │ • Temporal   │    │ • Exploit│ │
│  │ • Passive    │    │ • OS Fingerp.│    │ • Correlation│    │ • Verify │ │
│  │ • mDNS/NBNS │    │ • TLS Inspect│    │ • Feedback   │    │ • Report │ │
│  │ • SNMP/SSDP │    │ • SMB/LDAP   │    │ • Evolution  │    │          │ │
│  │ • AD / DNS  │    │ • Service ID │    │ • Drift      │    │          │ │
│  │ • TCP SYN   │    │ • Cred Spray │    │              │    │          │ │
│  │ • DHCP Sniff│    │ • Adaptive   │    │              │    │          │ │
│  └──────────────┘    └──────────────┘    └──────────────┘    └──────────┘ │
│         │                   │                   │                   │       │
│         ▼                   ▼                   ▼                   ▼       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    SQLite Database (WAL mode)                        │   │
│  │   hosts • ports • vulns • anomalies • TLS • enum • attack_chains    │   │
│  │   credentials • api_keys • api_request_log                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │              Web Dashboard (Bootstrap 5 + ApexCharts)                │   │
│  │  Overview│Hosts│Vulns│Anomalies│RedTeam│AttackPaths│MITRE│Command    │   │
│  │  Center│ScanCtl│Live│Logs│NetworkMap│Diff│Notes│AD│Creds│Settings    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔥 Features

### 13 Discovery Techniques

| Technique | Method | Stealth Level |
|-----------|--------|:-------------:|
| **Nmap Discover** | nmap -sn with ICMP/TCP probes (first pass) | ⬛⬛⬜⬜⬜ |
| ARP Sweep *(disabled)* | Batched, randomized, with delays | ⬛⬛⬛⬜⬜ |
| NetBIOS/NBNS | Windows host discovery | ⬛⬛⬛⬜⬜ |
| mDNS Enum | .local service queries | ⬛⬛⬛⬛⬜ |
| SSDP/UPnP | Multicast discovery | ⬛⬛⬛⬛⬜ |
| TCP SYN Ping | Lightweight alive check | ⬛⬛⬛⬜⬜ |
| SNMP Sweep | Community string probes (45s+ delays) | ⬛⬛⬛⬛⬜ |
| DNS Reverse Walk | PTR lookups with heavy jitter | ⬛⬛⬛⬛⬜ |
| Passive Sniff | Zero packets sent — just listens | ⬛⬛⬛⬛⬛ |
| DHCP Passive | Captures DHCP traffic silently | ⬛⬛⬛⬛⬛ |
| Custom DNS | Use internal DNS for zone lookups | ⬛⬛⬛⬛⬜ |
| **AD Discovery** | LDAP queries to map the domain (zero scan packets) | ⬛⬛⬛⬛⬛ |
| **DNS Recon** | PTR walk, zone transfer, SRV records, cache snooping | ⬛⬛⬛⬛⬛ |

> **Discovery order is optimized for fast results:** nmap runs first (finds hosts in seconds), then fast active techniques (NBNS, mDNS, SSDP, TCP SYN), then slow/passive ones (DNS walk, sniffing) for background enrichment.

### Deep Scanning Suite

| Module | Capabilities |
|--------|-------------|
| **TCP Scanner** | Connect/SYN scan, 1000+ port profiles, adaptive throttle, decoy IPs |
| **UDP Scanner** | DNS, SNMP, NTP, SSDP, mDNS with protocol-specific probes |
| **OS Fingerprint** | Passive (banner/port analysis) + Active (TCP stack probing) |
| **TLS Inspector** | Certificate extraction, weak ciphers, expired certs, protocol version |
| **Service Enum** | SMB null sessions, LDAP anon bind, Redis/Docker/ES no-auth |
| **Service Version** | nmap -sV deep detection — structured product/version/CPE per port (operator-triggered) |
| **Nuclei Integration** | Rate-limited vuln scanning with red team classification |
| **Credential Spray** | SSH (paramiko), RDP (NLA/CredSSP), SMB (NTLMv2), WinRM, Redis, ES, MySQL, Postgres — 1 attempt/host/hour |
| **Credential Checker** | Async default/weak credential audit across 10 protocols (SSH, RDP, SMB, WinRM, FTP, HTTP Basic, MySQL, Postgres, MongoDB, Redis) with password-spray + lockout protection |
| **Silent Credential Audit** *(F5)* | Minimal single-packet Redis/ES probes — detects password-less access with no credential guessing |
| **AD Integration** | Users, groups, Kerberoastable, AS-REP roastable, trusts |
| **AD Discovery** | Map the entire domain via LDAP — computers, servers, DCs, trusts, OU structure, high-value accounts, RBCD/delegation flags, BloodHound export |
| **DNS Recon** | Zero-probe network mapping — PTR walk, zone transfer (AXFR), subdomain brute force, cache snooping, SRV records, DNS security posture |
| **Attack Path Engine** | Initial access → lateral movement → priv-esc chains, risk score, credential clusters |
| **Attack Chain Correlator** *(F4)* | Persists correlated chains to `attack_chains` table; exports `data/attack_chains.json` each cycle |
| **Enterprise Pipeline** | Wave-based processing for 200k+ hosts — /24 subnet expansion, priority subnet tiers, bounded memory, graceful interrupt/resume |

> **Port scan runtime note:** the default TCP scan is intentionally stealthy. It uses randomized delays, adaptive throttling, and a small worker pool, so scanning 19 hosts can take noticeable time even with a modest port profile. For faster operator-driven runs, lower `min_delay` / `max_delay`, raise `max_threads`, or switch to the `quick` port profile in `config.yaml`.

> **Enterprise (200k+ hosts):** Switch to `mode: 'two_phase'` in config to use naabu for fast port discovery followed by nmap for version detection. naabu can scan 200K+ hosts in minutes — but it is **not stealth**. Use only during authorized assessments where IDS alerts are acceptable. All scanner settings are configurable from the dashboard Settings page.

### 🕵️ Stealth Features

```
┌─────────────────────────────────────────────────────┐
│              EVASION TECHNIQUES                       │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ⏱️  Randomized Timing     10-45s + jitter          │
│  🎭  Adaptive Throttle     Backs off on RST spikes  │
│  👻  Decoy Packets         Configurable fake sources │
│  📦  Fragmentation         Split packets evade DPI   │
│  🔀  TTL Manipulation      Random hop appearance     │
│  📋  File-Only Logging     Zero console footprint    │
│  🔒  Local Dashboard       127.0.0.1 binding        │
│  🎲  Scan Order Shuffle    No sequential patterns    │
│  🎯  Adaptive Ordering      Scan high-value hosts first│
│  📉  Stealth Decay          Delays ramp as op ages    │
│  ⏰  Time Window           Blend with business hours  │
│  🧠  Conditional Nuclei    Only when triggers hit     │
│  📊  Traffic Budgeting     Daily packet limits        │
│  🎭  Persona Rotation      Different scan profiles    │
│  🍯  Honey Token Detection Skip canaries & traps     │
│  👀  Observer Mode          Passive-only baseline     │
│  💣  Self-Destruct         Wipe all trace on command  │
│  🎭  Stealth Profiles      ghost / shadow / wraith    │
│  🕸️  Wave-Based Pipeline   /24-subnet waves, bounded  │
│  ⏳  Phase Deadlines      Abort stuck phases          │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### 🎭 Stealth Profiles

Pre-tuned stealth configurations ship in `hostvigil/stealth_configs/` for different operational postures:

| Profile | File | Use Case |
|---------|------|----------|
| **Ghost Mode** | `ghost_mode.yaml` | Maximum stealth, minimal detail — 300–900s delays, business-hours only, passive techniques, wave-based processing, honeypot/blocking abort conditions |
| **Shadow Mode** | `shadow_mode.yaml` | Balanced stealth — moderate delays, active + passive mix |
| **Wraith Mode** | `wraith_mode.yaml` | Aggressive stealth pacing for long-running ops |

Load a profile with `-c`:
```bash
python run.py -c hostvigil/stealth_configs/ghost_mode.yaml daemon
```

---

## 📊 Dashboard

Premium Vuexy-inspired admin interface with ApexCharts, dark/light mode, and optimized for 500k+ hosts:

- **Dashboard** — Stat cards (hosts, ports, vulns, anomalies), ApexCharts area/donut charts, recent scans, top vulnerabilities
- **Hosts** — Server-side paginated DataTable (50/page), search with debounce, status/OS filters — handles 500k hosts without crashing
- **Host Detail** — Tabbed drill-down (Ports, Vulnerabilities, Anomalies, TLS, Info) with product/version/CPE from nmap -sV
- **Vulnerabilities** — Clickable severity summary cards, search + severity filter, DOM-limited rendering
- **Anomalies** — Score distribution bar chart, progress-bar confidence visualization, true/false positive feedback buttons
- **Red Team** — Exploit-ready targets, crown-jewel targets, credential findings, pivot footholds
- **Attack Paths** — Risk score cards, MITRE-mapped attack chain table
- **MITRE ATT&CK** — Color-coded grid heatmap of technique coverage across 14 tactics
- **Command Center** — Operator console: kill-chain view, passive DNS, egress review, terminal, traffic budget, persona rotation, honey tokens, nuclei rules
- **Scan Controls** — Card-based scan grid, DNS discovery, cron scheduling UI, live SSE log stream
- **Live Status** — Animated pipeline phase chips, daemon state, next-cycle countdown, last cycle results
- **Live Logs** — Real-time tail of `data/logs/hostvigil.log` (syslog-style) over SSE, with severity filters (ERROR/WARN/INFO/DEBUG) and search
- **Network Map** — Subnet-clustered vis.js graph (200k+ hosts → clusters), double-click to expand, theme-aware colors
- **Diff View** — Time-selectable changes view (new/disappeared hosts, new/closed ports)
- **Notes** — Engagement journal with CRUD
- **AD Discovery** — Domain mapping via LDAP: computers, servers, DCs, trusts, OU structure, high-value accounts, BloodHound export
- **Credentials** — Credential findings, default/weak cred checks, custom credential management
- **Settings** — Live config editing, engagement profiles, scheduler, webhooks

Features:
- 🎨 Vuexy-inspired design with Inter font, rounded cards, subtle shadows, gradient active states
- 🌓 Dark/light theme toggle (persists via localStorage)
- 📊 ApexCharts for all visualizations (area, donut, bar) with theme-aware rendering
- 🔄 Auto-refresh polling (15s stats, 5s scan status, 3s live status)
- 🔔 Toast notifications with slide-in animation on scan events
- 🔐 Login authentication (default: admin/hostvigil) with rate-limiting (5 attempts → 60s lockout)
- 🔑 API key authentication for programmatic access (create/revoke/expire, per-key permissions)
- 📜 API request audit logging (`api_request_log` table — method, endpoint, latency, sizes)
- ⏱️ Session timeout (30-min idle auto-logout)
- 📥 One-click export dropdown (JSON / CSV / ZIP / Markdown / HTML report / IPs / Targets / URLs)
- 🏷️ Host tagging with filter views (`/api/hosts/by-tag/<tag>`)
- 🎯 ML feedback buttons to train the anomaly model
- ⏰ Cron-based scan scheduling from the UI
- 📋 Engagement profiles (save/load config presets)
- 🪝 Webhook auto-alerts (Slack, Discord, Teams) — fires on critical vulns, new hosts, high anomalies, drift
- 🌐 Bind to all interfaces or localhost only
- 📜 Live Logs page tailing the real `hostvigil.log` file over SSE, with severity filters and search
- 🔄 Scan resume/checkpoint — daemon resumes mid-cycle after restart
- ⚡ Performance: server-side pagination, DOM-limited tables, subnet clustering — zero browser crashes at scale

---

## 🧠 ML Engine — It Gets Smarter

HostVigil's ML isn't a gimmick. It's a **self-improving detection system** that enriches itself through 5 mechanisms:

### How It Learns

```
                    ┌──────────────────┐
                    │   Scan Cycle     │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │  Temporal  │  │  Service   │  │  Network   │
     │  Baseline  │  │ Correlation│  │  Snapshot  │
     │            │  │            │  │            │
     │ Learns per │  │ Learns     │  │ Detects    │
     │ hour/week  │  │ combos     │  │ drift      │
     └────────────┘  └────────────┘  └────────────┘
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    ┌────────────────┐
                    │  Anomaly Score │
                    └────────┬───────┘
                             │
                    ┌────────▼───────┐
                    │  Operator      │
                    │  Feedback      │◄──── You confirm/dismiss
                    └────────┬───────┘
                             │
                    ┌────────▼───────┐
                    │  Supervised    │
                    │  Retraining   │
                    └────────────────┘
```

| Mechanism | What It Does | Impact |
|-----------|-------------|--------|
| **Feedback Loop** | You mark anomalies as true/false positive → trains GradientBoosting | Eliminates noise over time |
| **Temporal Baseline** | Learns what's normal per hour-of-week (168 time slots) | "New port at 3AM Sunday" scores higher |
| **Service Correlation** | Builds co-occurrence matrix of services | Detects unusual combos (port 4444 + port 80 = sus) |
| **Network Evolution** | Tracks host/port/service trends over time | Alerts on 30%+ changes (drift) |
| **Incremental Update** | All above run every cycle — no manual retraining | Gets better passively |

**Cold start?** No problem. Rule-based detection works immediately. ML kicks in after 50+ data points.

---

## 💀 Red Team Playbook

### Phase 1: Silent Mapping (Day 1-3)

```bash
# Start daemon — it will silently map the network + serve the dashboard
python run.py daemon
# → Dashboard at http://localhost:5000
```

HostVigil will automatically discover hosts, scan ports, fingerprint OS, inspect TLS, enumerate services — all with stealth timing in continuous cycles. Zero IDS alerts. No manual triggering needed.

### Phase 2: Intelligence Review (Day 3+)

Open **http://localhost:5000** (already running with daemon) and check:
- 🖥️ All discovered hosts with OS identification
- 🔓 Services with no authentication (Redis, Docker, ES)
- 🔑 SMB null sessions & signing disabled (relay attacks)
- 📜 Expired/self-signed certificates
- 👑 Crown-jewel targets and high-value pivot footholds
- 🔁 Credential reuse clusters that widen lateral reach
- 🤖 ML anomalies (new hosts, unusual ports, banner changes)

### Phase 3: Targeted Exploitation

```bash
# Trigger Nuclei only against suspicious targets
python run.py nuclei
```

Or use the dashboard button. Nuclei runs rate-limited with stealth settings against targets flagged by the ML engine.
The dashboard also exposes `GET /api/export/pivot-paths` for ranked footholds, crown jewels, pivot chains, and credential clusters as JSON.

### Phase 4: Report & Export

```bash
python run.py export --format json     # Machine-readable
python run.py export --format report   # Markdown for clients
python run.py export --format csv      # Spreadsheet-friendly
```

For operator workflows, `GET /api/export/pivot-paths` returns the ranked footholds, crown jewels, pivot chains, and credential clusters as JSON.

### OpSec Checklist

- [x] Keep `min_delay` at 30+s on SOC-monitored networks
- [x] Use `connect` scan (not SYN) to avoid raw packet detection
- [x] Dashboard on `127.0.0.1` — never expose to network
- [x] Daemon mode excludes Nuclei (too noisy for continuous runs)
- [x] Daemon mode excludes nmap -sV (recognizable probe signature)
- [x] Clear `data/logs/` after engagement
- [x] Import previous engagement data to jumpstart ML baseline
- [x] Rotate `jitter_factor` between sessions

---

## 🔫 Credential Spraying

### Credential Spraying (Stealth)

Built-in slow credential spray — 1 attempt per host per hour to avoid lockouts:
- SSH (paramiko), RDP (NLA/CredSSP), SMB (NTLMv2), WinRM, Redis, Elasticsearch, MySQL, PostgreSQL
- Default credential list + custom wordlist support
- Rate-limited and randomized to blend with normal auth failures

---

## 🌐 Network Graph

Interactive **vis.js network map** on the dashboard visualizes your entire network topology in real-time:
- Nodes colored by vulnerability severity (green → red)
- Node size scales with open port count
- Hosts grouped by subnet with automatic clustering
- Click any node to drill into host details, ports, and findings
- Hover for quick stats (IP, OS, port count, vuln count)

Access it from the dashboard navigation: **http://localhost:5000/network-graph**

---

## 🔌 Plugin System

Extend HostVigil by dropping Python files in `plugins/`:

```python
# plugins/my_scanner.py
from hostvigil.plugins import ScannerPlugin


class MyCustomScanner(ScannerPlugin):
    name = "my_scanner"
    description = "Custom port scanner"

    def scan(self, hosts, config):
        # Your logic here
        return [{"ip": "10.0.0.1", "port": 8080, "state": "open", "service": "HTTP"}]
```

Plugin types: `DiscoveryPlugin`, `ScannerPlugin`, `AnalysisPlugin`

---

## 🐳 Docker

```bash
docker-compose up -d
# → Dashboard at http://localhost:5000
# Scanner runs automatically in daemon mode
```

Requires `network_mode: host` and `NET_RAW`/`NET_ADMIN` capabilities for network scanning.

---

## 🛠️ All Commands

```bash
# ─── Discovery & Scanning ────────────────────────
python run.py discover        # 13 discovery techniques
python run.py observer        # Passive-only baseline (zero active probes)
python run.py scan            # TCP port scanning
python run.py udpscan         # UDP port scanning
python run.py fingerprint     # OS identification
python run.py tls             # TLS/SSL inspection
python run.py enumerate       # SMB/LDAP/Redis/Docker/ES (silent audit probes)
python run.py servicescan     # Deep service/version detection (nmap -sV)

# ─── Analysis & Exploitation ─────────────────────
python run.py analyze         # ML anomaly detection
python run.py nuclei          # Vulnerability scanning (manual trigger)
python run.py paths           # Attack path / chain analysis

# ─── Pipeline Modes ──────────────────────────────
python run.py full            # Single full pipeline run
python run.py daemon          # Continuous background recon + dashboard (no Nuclei)
python run.py kill            # Kill a running daemon process
python run.py wipe            # Self-destruct: securely wipe ALL data
python run.py wipe --force    # Skip confirmation
python run.py wipe --secure   # Zero-fill before delete (paranoid)

# ─── Interface ────────────────────────────────────
python run.py dashboard               # Web UI (default: 127.0.0.1:5000)
python run.py dashboard --host 0.0.0.0 --port 8080   # Expose on network

# ─── Data Management ─────────────────────────────
python run.py export --format json     # Full JSON export
python run.py export --format csv      # CSV per table
python run.py export --format report   # Markdown report
python run.py export --format ips      # Plain IP list (for nmap -iL)
python run.py export --format targets  # ip:port list (for nuclei -l)
python run.py export --format urls     # HTTP URLs (for httpx -l)
python run.py export --format c2       # All C2 formats (CS/MSF/Sliver/nmap)
python run.py export --output out.json # Custom output path
python run.py import data.json --mode merge
python run.py import data.json --mode replace
python run.py cleanup-reports --days 14           # Purge old exports
python run.py cleanup-reports --max-total-mb 500  # Cap report dir size

# ─── Analysis Tools ──────────────────────────────
python run.py diff --hours 24          # What changed in last 24h
python run.py init                     # Interactive config wizard
python run.py init --fresh             # Reset DB/logs/scans/reports and rebuild a clean DB
python run.py init --fresh --force     # Skip confirmation for the fresh reset

# ─── Status ──────────────────────────────────────
python run.py status
python run.py status --json
python run.py schema               # DB schema + applied migrations
python run.py schema --json        # Machine-readable schema
python run.py doctor               # Environment/config/db health check
python run.py doctor --verbose     # Includes scale analysis & phase time estimates

# ─── Options ─────────────────────────────────────
python run.py -c custom_config.yaml daemon   # Custom config
python run.py -c entp_config.yaml daemon     # Enterprise (200k+ hosts)
python run.py -v full                        # Verbose (reduces stealth)
```

`python run.py init --fresh` also clears Python bytecode caches (`__pycache__`, `*.pyc`, `*.pyo`) before recreating the database.

---

## ⚙️ Configuration

```yaml
hostvigil:
  dashboard:
    host: '127.0.0.1'             # Localhost only — never expose to network
    port: 5000
    refresh_interval: 30
    secret_key: change-this-in-production

  database:
    path: data/hostvigil.db

  discovery:
    target_ranges:
      - '192.168.0.0/16'          # Adjust to your actual network
    techniques:                   # Ordered: fast first, slow/passive last
      - nmap_discover             # nmap -sn (finds hosts in seconds)
      - nbns_query
      - mdns_enum
      - ssdp_discover
      - tcp_syn_discover
      - snmp_sweep
      - dns_reverse_walk
      - passive_sniff
      - dhcp_passive
      # - dns_custom              # Enable if you have internal DNS
    nmap_timing: 'T2'             # T2 = polite (slower, less detectable)
    nmap_extra_args: ['-PE', '-PS22,80,135,139,443,445,3389,5985', '-PU137', '--min-rate', '100', '--max-rate', '300', '--max-retries', '1', '-n']
    nmap_parallel_chunks: 1       # Single nmap process (quietest)
    nmap_disable_arp_ping: false
    nmap_scan_timeout: 1800       # 30 min timeout per chunk
    nmap_max_chunks: 256
    passive_sniff_duration: 120   # Listen for 2 minutes
    dhcp_sniff_duration: 60
    snmp_communities: ['public', 'private']
    snmp_delay: 45.0              # 45s+ between SNMP probes
    dns_custom_server: ''         # Internal DNS server IP (empty = disabled)
    dns_custom_domain: ''         # Domain for zone transfer attempts

  scanner:
    mode: 'nmap_only'             # 'nmap_only' (stealth) / 'two_phase' (naabu→nmap, fast)
    scan_type: 'connect'          # 'connect' (no root) or 'syn' (root, stealthier)
    port_profile: 'standard'      # quick / standard / full
    udp_scan_enabled: true
    udp_profile: 'standard'
    banner_grab: true
    banner_timeout: 2.0
    connect_timeout: 1.5
    naabu:                        # Only used when mode is 'two_phase'
      rate: 1000
      threads: 10
    nmap:
      version_detection: true
      os_detection: false
      timing: 'T2'
    ports:
      quick: [22, 80, 443, 445, 3389]
      standard: [22, 53, 80, 88, 135, 139, 389, 443, 445, 636, 1433, 3306, 3389, 5432, 5985, 5986, 8080, 8443, 9200]
      full: [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1080, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 8888, 9090, 9200, 9300, 11211, 27017]
    udp_ports:
      quick: [53, 123, 161, 500, 1900]
      standard: [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1900, 4500, 5353]

  service_scan:                    # nmap -sV deep detection (operator-triggered)
    enabled: true
    version_intensity: 5           # 0-9 (lower = quieter, higher = thorough)
    nmap_timing: 'T2'
    scan_delay: ''                 # e.g. '1s' for extra stealth
    parallel: 4                    # concurrent nmap processes (1 = quietest)
    scan_timeout: 300              # per-host subprocess timeout (seconds)

  stealth:
    min_delay: 10.0                # Seconds between probes (raise for stealth)
    max_delay: 45.0                # Maximum randomized delay
    jitter_factor: 0.3             # Timing randomization (0-1)
    max_threads: 3                 # Concurrent scan threads (raise for speed)
    packet_fragmentation: true     # Fragment packets to evade DPI
    randomize_scan_order: true     # No sequential patterns
    ttl_manipulation: true         # Random TTL values
    scan_window_enabled: false     # Only scan during business hours
    scan_window_start: 8
    scan_window_end: 18
    decoy_ips: ['10.0.0.1', '10.0.0.254', '172.16.0.1', '192.168.1.1', '100.64.0.1', '198.18.0.1']

  ml_engine:
    anomaly_threshold: 0.7
    min_training_samples: 50       # Rules work immediately; ML after 50 data points
    model_path: data/models/
    training_interval_hours: 24

  nuclei:
    auto_run: false                # Disabled by default (noisy); trigger from dashboard or CLI
    min_targets: 20                # Wait until this many web hosts discovered before firing
    binary_path: nuclei
    severity_filter: ['critical', 'high', 'medium']
    rate_limit: 10
    concurrency: 2
    bulk_size: 5
    retries: 1
    timeout: 15
    run_interval_hours: 6

  os_fingerprint:
    enabled: true
    active_probing: true           # Active TCP probes for better accuracy on small nets
    confidence_threshold: 0.4

  tls_inspection:
    enabled: true
    ports: [443, 636, 993, 995, 465, 8443, 5986, 2376, 9443]
    check_expiry: true
    check_weak_ciphers: true
    check_protocol_versions: true
    timeout: 5.0

  service_enum:
    enabled: true
    smb_enum: true
    ldap_enum: true
    redis_check: true
    elasticsearch_check: true
    docker_check: true
    winrm_check: true
    timeout: 5.0

  parallel_scan:                   # Enterprise: scan hosts AS they're discovered
    enabled: false                 # Enable for large networks (200k+ hosts)
    batch_size: 100                # Fire naabu every N newly-discovered hosts
    scan_interval_sec: 30          # Poll for new hosts every N seconds
    max_scan_threads: 2            # Concurrent scan batches

  scheduler:
    discovery_interval_hours: 4
    scan_interval_hours: 2
    service_enum_interval_hours: 8
    tls_inspection_interval_hours: 12
    os_fingerprint_interval_hours: 12
    nuclei_interval_hours: 6
```

---

### 🏢 Enterprise Config (200k+ Hosts)

For networks with **200,000–500,000+ hosts**, the default stealth settings will take weeks to complete a single pass. Use the included `entp_config.yaml` which is tuned for large-scale throughput:

```bash
python run.py -c entp_config.yaml daemon
```

**Other enterprise launch options:**
```bash
# Dashboard accessible from other machines (not just localhost)
python run.py -c entp_config.yaml daemon

# Single full pass (no continuous loop)
python run.py -c entp_config.yaml full

# Docker (edit docker-compose.yml to mount entp_config.yaml)
#   volumes:
#     - ./entp_config.yaml:/app/config.yaml:ro
docker-compose up -d
```

> **Requires naabu** for two-phase mode (`mode: 'two_phase'`). Install via `./install.sh` (step 4), Docker (included automatically), or manually:
> ```bash
> # Install naabu (Go required)
> go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
> sudo ln -sf ~/go/bin/naabu /usr/local/bin/naabu
> ```

Key differences from default:

| Setting | Default | Enterprise | Why |
|---------|---------|-----------|-----|
| `min_delay` | 10.0s | 0.5s | 10s × 200k hosts = 23 days/pass |
| `max_threads` | 3 | 15 | Parallelism needed at scale |
| `nmap --min-rate` | 100 | 10000 | Faster host discovery |
| `nmap_parallel_chunks` | 1 | 12 | More concurrent nmap processes |
| `nmap_max_chunks` | 256 | 2048 | Supports 500k+ hosts across multiple /8 ranges |
| `nmap_scan_timeout` | 1800s | 10800s | 3 hours for very large ranges |
| `scanner.mode` | nmap_only | two_phase | naabu for speed, nmap for depth |
| `naabu.rate` | 1000 | 10000 | Higher packet rate at scale |
| `naabu.threads` | 10 | 100 | More concurrent threads |
| `port_profile` | standard (19) | quick (5) | 200k × 19 ports is brutal |
| `udp_scan_enabled` | true | false | UDP at 200k is unrealistic for daemon |
| `parallel_scan` | disabled | enabled (batch=100) | Scan hosts AS they're discovered |
| `discovery_interval` | 4h | 8h | Give discovery time to finish |
| `scan_interval` | 2h | 4h | Give TCP scans time to complete |
| `os_fingerprint` | active | disabled | Active probing 200k hosts = days |
| `ml.min_training_samples` | 50 | 200 | Larger datasets need better baselines |
| `nuclei.auto_run` | false | true | Auto-trigger on web port discovery |
| `service_enum.silent_credential_audit` | — | enabled | Single-packet Redis/ES probes — smaller footprint, faster at scale |
| `stealth.decay_enabled` | false | false | Speed-first config keeps delays flat; set `true` on SOC-monitored networks |

Disabled at scale (too slow): `tcp_syn_discover`, `snmp_sweep`, `dns_reverse_walk`

> **Stealth on SOC-monitored enterprise networks?** The file includes commented conservative alternatives (`min_delay: 2.0`, `max_threads: 8`, `--min-rate 3000`). First full pass takes ~3 days instead of hours, but avoids tripping IDS thresholds.

---

## 📁 Project Structure

```
HostVigil/
├── run.py                          # CLI entry point (24+ commands)
├── config.yaml                     # Default configuration (stealth-focused)
├── entp_config.yaml                # Enterprise config for 200k+ host networks
├── requirements.txt                # Dependencies (pinned)
├── pyproject.toml                  # Python packaging (pip install .)
├── MANIFEST.in                     # sdist package data
├── Dockerfile                      # Container build
├── docker-compose.yml              # One-command deployment
├── .gitignore                      # Git ignore rules
├── install.sh                      # One-command installer (Linux/macOS)
├── quickstart.sh                   # 60-second quick start
├── test_full_pipeline.py           # End-to-end pipeline test
├── .github/
│   └── workflows/
│       ├── ci.yml                  # Lint + test (3.11/3.12/3.13) + build
│       └── release.yml             # Release pipeline
├── images/
│   └── logo.png                    # Project logo
├── plugins/                        # Drop-in plugin directory
│   ├── __init__.py
│   └── example_plugin.py           # Example scanner plugin
├── hostvigil/
│   ├── __init__.py
│   ├── __main__.py                 # python -m hostvigil
│   ├── orchestrator.py             # Pipeline coordinator & scheduler
│   ├── config.py                   # YAML config with defaults + profiles
│   ├── utils.py                    # DB init, logging, helpers
│   ├── export_import.py            # JSON/CSV export & import
│   ├── alerting.py                 # Webhook notifications (Slack, Discord, Teams)
│   ├── attack_paths.py             # Attack path analysis, chain correlation (F4)
│   ├── c2_export.py                # C2 framework export (CS/MSF/Sliver/nmap)
│   ├── pcap_export.py              # Packet capture export
│   ├── plugins.py                  # Plugin architecture
│   ├── report_generator.py         # PDF/HTML report generation
│   ├── scheduler.py                # Cron-based scheduling
│   ├── enterprise.py               # API keys, rate limiting, request audit logging
│   ├── enterprise_pipeline.py      # Wave-based 200k+ host processing
│   ├── stealth_configs/            # Pre-tuned stealth profiles
│   │   ├── ghost_mode.yaml         # Maximum stealth
│   │   ├── shadow_mode.yaml        # Balanced stealth
│   │   └── wraith_mode.yaml        # Aggressive stealth pacing
│   ├── discovery/
│   │   ├── stealth_discovery.py    # 11+ discovery techniques
│   │   ├── ad_discovery.py         # LDAP-based domain mapping (zero scan packets)
│   │   └── dns_recon.py            # DNS-only recon (PTR walk, AXFR, SRV)
│   ├── scanner/
│   │   ├── stealth_scanner.py      # TCP/UDP scanning + adaptive throttle
│   │   ├── nmap_service_scan.py    # Deep service/version detection (nmap -sV)
│   │   ├── os_fingerprint.py       # OS identification
│   │   ├── tls_inspector.py        # Certificate & cipher analysis
│   │   ├── service_enum.py         # SMB/LDAP/Redis/Docker enumeration
│   │   ├── credential_spray.py     # Stealth credential spraying
│   │   ├── cred_checker.py         # Async default/weak credential audit (10 protocols)
│   │   ├── ad_integration.py       # Active Directory enumeration
│   │   ├── scan_diff.py            # Network change detection
│   │   └── traffic_shaper.py       # Stealth timing & decay scheduler
│   ├── ml_engine/
│   │   ├── anomaly_detector.py     # IsolationForest + rule-based detection
│   │   └── enrichment.py           # Feedback loop, temporal, correlations
│   ├── nuclei/
│   │   └── nuclei_runner.py        # Rate-limited vulnerability scanning
│   ├── dashboard/
│   │   ├── app.py                  # Flask app factory + API endpoints
│   │   ├── exports.py              # Export API blueprint (JSON/CSV/Report/PDF/ZIP)
│   │   ├── templates/              # 20 dashboard pages (Bootstrap 5, dark theme)
│   │   │   ├── index.html          # Overview
│   │   │   ├── hosts.html          # Hosts table
│   │   │   ├── host_detail.html    # Host drill-down
│   │   │   ├── vulnerabilities.html
│   │   │   ├── anomalies.html
│   │   │   ├── redteam.html
│   │   │   ├── attack_paths.html
│   │   │   ├── mitre.html
│   │   │   ├── command_center.html # Operator console
│   │   │   ├── scan_controls.html
│   │   │   ├── live_status.html    # Real-time daemon pipeline monitoring
│   │   │   ├── logs.html           # Live log viewer with SSE streaming
│   │   │   ├── network_graph.html
│   │   │   ├── diff.html
│   │   │   ├── notes.html
│   │   │   ├── ad_discovery.html
│   │   │   ├── credentials.html
│   │   │   ├── settings.html
│   │   │   └── login.html
│   │   └── static/                 # CSS, vendor assets (ApexCharts, vis.js)
│   └── tests/
│       └── test_security.py        # Security-focused unit tests
└── data/                           # Runtime data (gitignored)
    ├── logs/                       # File-only stealth logs
    ├── models/                     # ML model artifacts
    ├── scans/                      # Raw scan data
    └── reports/                    # Generated exports
```

---

## 🔧 Installation

### Requirements

- Python 3.11+
- [Nmap](https://nmap.org/download.html) in PATH (primary host discovery engine)
- Admin/root for ARP sweep and SYN scan (optional — connect scan works without)
- [Nuclei](https://github.com/projectdiscovery/nuclei/releases) binary in PATH (optional — vulnerability scanning)
- [naabu](https://github.com/projectdiscovery/naabu/releases) binary in PATH (optional — fast two-phase scanning)

### Automated Install (Recommended)

One-command setup that handles everything — Python venv, system deps, Nuclei, naabu, database init:

```bash
# Linux / macOS
chmod +x install.sh
./install.sh

# Windows (PowerShell as Administrator)
powershell -ExecutionPolicy Bypass -File install.ps1
```

### Manual Install

```bash
git clone https://github.com/bidhata/HostVigil.git
cd HostVigil
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

### Dependencies

```
flask==3.1.3
pyyaml==6.0.3
numpy>=1.26,<3.0
scapy==2.7.0
paramiko==5.0.0
ldap3==2.9.1
dnspython==2.7.0
aiohttp==3.11.11
scikit-learn>=1.3,<2.0
APScheduler==3.11.3
psutil==7.2.2
```

Core dependencies pinned; ML libraries use conservative version ranges. No bloat. No telemetry. No cloud dependencies.

> `ldap3` enables the AD Discovery module; `scapy` powers raw packet crafting (ARP, SYN, passive sniff); `dnspython` powers DNS recon (PTR walk, AXFR, cache snooping); `aiohttp` powers async credential checking. All are installed by default via `requirements.txt`.

### Python Package

HostVigil is also installable as a Python package:

```bash
pip install .            # installs the `hostvigil` CLI
hostvigil daemon         # same as python run.py daemon
```

Dev extras (lint/test tooling) via `pip install .[dev]`.

---

## 🔄 Upgrading

Your scan data is preserved across upgrades — the database uses automatic migrations.

```bash
# 1. Stop the running daemon
python run.py kill

# 2. Pull / copy the new code over the old
#    (data/ is gitignored — your DB, models, and logs stay intact)

# 3. Install any new dependencies
pip install -r requirements.txt

# 4. Start the daemon — pending migrations apply automatically
python run.py daemon
```

> **How it works:** On startup, HostVigil checks the `schema_migrations` table and applies any pending migrations (e.g., `ALTER TABLE ADD COLUMN`). Existing rows are never deleted or modified — new columns get `NULL` until enriched by a scan.

> **Optional safety backup:**
> ```bash
> copy data\hostvigil.db data\hostvigil_backup.db   # Windows
> cp data/hostvigil.db data/hostvigil_backup.db     # Linux/macOS
> ```

> **Verify migrations:** `python run.py schema` shows all applied migration versions.

---

## 🧪 Testing

```bash
pip install .[dev]           # pytest + ruff
pytest -v                    # unit tests (hostvigil/tests + tests)
ruff check .                 # lint
ruff format --check .        # formatting
```

CI (`.github/workflows/ci.yml`) runs lint + tests on Python 3.11/3.12/3.13, then builds the sdist/wheel. `test_full_pipeline.py` at the repo root exercises the full pipeline end-to-end.

---

## 🤝 Contributing

PRs welcome. Please ensure:
- Stealth principles maintained (no noisy operations in default config)
- Tests pass
- No new external dependencies without justification

---

## ⚠️ Legal Disclaimer

> **This tool is designed exclusively for authorized internal security assessments.**
>
> Unauthorized use against networks you do not own or have explicit written permission to test is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.
>
> Users are solely responsible for compliance with applicable laws and organizational policies. The author assumes no liability for misuse.
>
> Always obtain written authorization before running HostVigil on any network.

---

## 📜 License

MIT — For authorized use only.

---

## 👤 Author

<table>
  <tr>
    <td>
      <strong>Krishnendu Paul</strong><br>
      <a href="https://github.com/bidhata">@bidhata</a><br><br>
      🌐 <a href="https://krishnendu.com">krishnendu.com</a><br>
      🐙 <a href="https://github.com/bidhata/HostVigil">GitHub</a><br>
      📧 <a href="mailto:me@krishnendu.com">me@krishnendu.com</a>
    </td>
  </tr>
</table>

---

<p align="center">
  <strong>If HostVigil helps your security assessments, drop a ⭐</strong><br>
  <sub>Built for the red team. Invisible to the blue team.</sub>
</p>
