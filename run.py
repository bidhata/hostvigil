#!/usr/bin/env python3
"""
HostVigil - Entry Point

Stealth network reconnaissance platform for authorized internal security assessments.

Usage:
    python run.py discover   - Run host discovery only
    python run.py scan       - Run port scanning only
    python run.py analyze    - Run ML anomaly analysis only
    python run.py nuclei     - Run Nuclei vulnerability scan only
    python run.py full       - Run the complete pipeline once
    python run.py daemon     - Run continuously in background
    python run.py kill       - Kill a running daemon process
    python run.py dashboard  - Start the web dashboard
    python run.py status     - Show current database status
    python run.py init --fresh [--force] - Reset DB/logs/scan results and start fresh
"""

import argparse
import json
import logging
import os
import secrets
import signal
import sys
from pathlib import Path

from hostvigil.orchestrator import HostVigilOrchestrator

BANNER = r"""
  _   _           _  __     ___       _ _
 | | | | ___  ___| |_\ \   / (_) __ _(_) |
 | |_| |/ _ \/ __| __|\ \ / /| |/ _` | | |
 |  _  | (_) \__ \ |_  \ V / | | (_| | | |
 |_| |_|\___/|___/\__|  \_/  |_|\__, |_|_|
                                 |___/
        Stealth Internal Recon Platform
"""


def cmd_discover(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Run host discovery only."""
    print("[*] Running host discovery...")
    results = orchestrator.run_discovery()
    print(f"[+] Discovery complete: {results.get('hosts_found', 0)} hosts found")
    if results.get("error"):
        print(f"[!] Error: {results['error']}")
        return 1
    return 0


def cmd_observer(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Run passive-only observer mode (no active probing)."""
    print("[*] Running passive observer mode (listening only, no active scans)...")
    results = orchestrator.run_observer()
    print(f"[+] Observer complete: {results.get('hosts_observed', 0)} host(s) observed")
    techniques = results.get("passive_techniques", [])
    if techniques:
        print(f"[*] Passive techniques: {', '.join(techniques)}")
    if results.get("analysis"):
        analysis = results["analysis"]
        print(
            f"[*] Analysis: {analysis.get('anomalies_detected', 0)} anomaly(ies), "
            f"max score {analysis.get('max_anomaly_score', 0.0):.2f}"
        )
    if results.get("error"):
        print(f"[!] Error: {results['error']}")
        return 1
    return 0


def cmd_scan(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Run port scanning only."""
    print("[*] Running port scan...")
    results = orchestrator.run_scan()
    print(f"[+] Scan complete: {results.get('ports_found', 0)} open ports found")
    if results.get("error"):
        print(f"[!] Error: {results['error']}")
        return 1
    return 0


def cmd_analyze(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Run ML anomaly analysis only."""
    print("[*] Running ML anomaly analysis...")
    results = orchestrator.run_analysis()
    print(f"[+] Analysis complete: {results.get('anomalies_detected', 0)} anomalies detected")
    if results.get("error"):
        print(f"[!] Error: {results['error']}")
        return 1
    return 0


def cmd_nuclei(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Run Nuclei vulnerability scan only."""
    print("[*] Running Nuclei vulnerability scan...")
    results = orchestrator.run_nuclei()
    print(f"[+] Nuclei complete: {results.get('vulnerabilities_found', 0)} vulnerabilities found")
    if results.get("error"):
        print(f"[!] Error: {results['error']}")
        return 1
    return 0


def cmd_udpscan(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Run UDP port scan only."""
    print("[*] Running UDP port scan...")
    results = orchestrator.run_udp_scan()
    print(f"[+] UDP scan complete: {results.get('ports_found', 0)} open/filtered ports found")
    if results.get("error"):
        print(f"[!] Error: {results['error']}")
        return 1
    return 0


def cmd_fingerprint(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Run OS fingerprinting only."""
    print("[*] Running OS fingerprinting...")
    results = orchestrator.run_os_fingerprint()
    print(f"[+] OS fingerprinting complete: {results.get('hosts_fingerprinted', 0)} hosts identified")
    if results.get("error"):
        print(f"[!] Error: {results['error']}")
        return 1
    return 0


def cmd_tls(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Run TLS inspection only."""
    print("[*] Running TLS/SSL inspection...")
    results = orchestrator.run_tls_inspection()
    print(f"[+] TLS inspection complete: {results.get('certs_inspected', 0)} certificates checked")
    if results.get("weak_certs", 0) > 0:
        print(f"[!] Found {results['weak_certs']} certificates with weaknesses")
    if results.get("error"):
        print(f"[!] Error: {results['error']}")
        return 1
    return 0


def cmd_enumerate(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Run service enumeration only."""
    print("[*] Running deep service enumeration (SMB/LDAP/Redis/Docker/ES)...")
    results = orchestrator.run_service_enum()
    print(f"[+] Enumeration complete: {results.get('services_enumerated', 0)} services checked")
    if results.get("critical_findings", 0) > 0:
        print(f"[!] Found {results['critical_findings']} critical/high risk findings")
    if results.get("error"):
        print(f"[!] Error: {results['error']}")
        return 1
    return 0


def cmd_servicescan(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Run deep service/version detection (nmap -sV) on known-open ports."""
    print("[*] Running deep service/version detection (nmap -sV)...")
    results = orchestrator.run_service_scan()
    if results.get("error"):
        print(f"[!] Error: {results['error']}")
        return 1
    if results.get("skipped"):
        print(f"[*] Skipped: {results.get('reason', 'disabled')}")
        return 0
    print(
        f"[+] Service scan complete: {results.get('ports_enriched', 0)} port(s) enriched "
        f"across {results.get('hosts_scanned', 0)} host(s)"
    )
    if results.get("message"):
        print(f"[*] {results['message']}")
    return 0


def cmd_full(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Run the full pipeline once."""
    print("[*] Running full pipeline (Discovery -> Scan -> ML -> Nuclei)...")
    print("[*] Stealth delays active between phases")
    orchestrator.install_signal_handlers()
    results = orchestrator.run_once()

    if results.get("success"):
        print("[+] Pipeline completed successfully")
        for phase, data in results.get("phases", {}).items():
            if isinstance(data, dict) and not data.get("skipped"):
                print(f"    {phase}: {data}")
    else:
        print(f"[!] Pipeline failed: {results.get('error', 'interrupted')}")
        return 1
    return 0


def _is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running."""
    if os.name == "nt":
        # Windows: use tasklist to check if PID exists
        import subprocess

        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True, timeout=5
            )
            return str(pid) in result.stdout
        except (subprocess.TimeoutExpired, OSError):
            return False
    else:
        # POSIX: use os.kill with signal 0 (doesn't actually kill)
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # Process exists but we lack permission


def _validate_hostvigil_pid(pid: int) -> bool:
    """Validate that the PID belongs to a HostVigil/Python process."""
    if os.name == "nt":
        # Windows: check process image name contains 'python'
        import subprocess

        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=5
            )
            output = result.stdout.lower()
            return "python" in output
        except (subprocess.TimeoutExpired, OSError):
            return False
    else:
        # POSIX: check /proc/PID/cmdline for 'hostvigil' or 'run.py'
        try:
            cmdline_path = Path(f"/proc/{pid}/cmdline")
            if cmdline_path.exists():
                cmdline = cmdline_path.read_bytes().decode("utf-8", errors="ignore").lower()
                return "hostvigil" in cmdline or "run.py" in cmdline
            # Fallback: check if it's a python process
            comm_path = Path(f"/proc/{pid}/comm")
            if comm_path.exists():
                comm = comm_path.read_text().strip().lower()
                return "python" in comm
            return False
        except (OSError, PermissionError):
            return False


def daemonize(log_path: str = "data/logs/hostvigil_daemon.log") -> int:
    """Detach the process into the background (POSIX double-fork).

    Returns the child PID (the running daemon). The parent exits immediately,
    so the shell prompt returns right away — no screen/tmux required.

    On Windows this is a no-op returning the current PID (no fork support).
    """
    if os.name == "nt":
        return os.getpid()

    # First fork: child continues, parent exits
    try:
        pid = os.fork()
    except OSError as e:
        print(f"[!] Failed to daemonize: {e}")
        raise
    if pid > 0:
        os._exit(0)  # parent exits — shell returns

    # Child: detach from controlling terminal
    os.setsid()

    # Second fork: ensure we can never reacquire a controlling terminal
    try:
        pid = os.fork()
    except OSError:
        pass
    if pid > 0:
        os._exit(0)

    # Redirect stdio to the daemon log so no terminal is held open
    log_dir = Path(log_path).parent
    log_dir.mkdir(parents=True, exist_ok=True)
    devnull = os.open(os.devnull, os.O_RDWR)
    try:
        logfd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    except OSError:
        logfd = devnull
    os.dup2(devnull, 0)  # stdin
    os.dup2(logfd, 1)  # stdout
    os.dup2(logfd, 2)  # stderr
    if logfd != devnull:
        os.close(logfd)
    if devnull > 2:
        os.close(devnull)

    return os.getpid()


def cmd_daemon(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Run continuously in daemon mode with dashboard."""
    # FIX #13: Real daemonization — fork into the background so the user
    # doesn't need screen/tmux. The parent returns, the child runs the daemon.
    background = getattr(args, "background", False)
    if background:
        print("[*] Forking into the background...")
        print("[*] PID file: data/.hostvigil.pid | Log: data/logs/hostvigil_daemon.log")
        print("[*] Use 'python run.py kill' to stop")
        daemonize()
        # Child continues below; stdio now goes to the daemon log

    print(BANNER)
    print("[*] Starting HostVigil in daemon mode")
    print("[*] Stealth timing active - randomized intervals between cycles")
    print("[*] Dashboard starting alongside daemon...")
    print()

    # FIX #11: Check for existing daemon
    pid_file = Path("data/.hostvigil.pid")
    pid_file.parent.mkdir(parents=True, exist_ok=True)

    if pid_file.exists():
        try:
            existing_pid = int(pid_file.read_text().strip())
            if _is_pid_alive(existing_pid):
                print(f"[!] HostVigil daemon is already running (PID: {existing_pid})")
                print("[*] Use 'python run.py kill' to stop it first")
                return 1
        except (ValueError, OSError):
            pass  # Stale/corrupt PID file, proceed

    # Write PID file for kill command
    pid_file.write_text(str(os.getpid()))

    orchestrator.install_signal_handlers()

    # Start the dashboard in a background thread
    import threading

    from hostvigil.dashboard import create_app

    dashboard_config = orchestrator.config.dashboard
    bind_host = dashboard_config.get("host", "0.0.0.0")
    bind_port = dashboard_config.get("port", 5000)

    # Auto-generate secret_key if using insecure defaults
    secret_key = dashboard_config.get("secret_key", "hostvigil-default-key")
    if secret_key in ("change-this-in-production", "hostvigil-default-key"):
        secret_key = secrets.token_hex(32)
        print("[!] WARNING: Using auto-generated secret_key. Set a permanent one in config.yaml.")

        logging.getLogger("hostvigil").warning(
            "Dashboard secret_key was a default value - auto-generated a random key for this session"
        )

    app = create_app(
        {
            "db_path": orchestrator.db_path,
            "secret_key": secret_key,
            "refresh_interval": dashboard_config.get("refresh_interval", 30),
            "orchestrator": orchestrator,
        }
    )

    # FIX #12: Wrap dashboard start in try/except for port-in-use errors
    # FIX #XX: Supervisor loop — if the dashboard thread dies (unhandled
    # exception, runtime error), restart it with exponential backoff instead
    # of silently losing the web UI while the daemon keeps scanning.
    dashboard_restarts = 0
    max_dashboard_restarts = 5
    dashboard_backoff = 5  # seconds, doubles each restart

    def _run_dashboard():
        nonlocal dashboard_restarts, dashboard_backoff
        while not orchestrator._shutdown_event.is_set():
            try:
                app.run(host=bind_host, port=bind_port, debug=False, use_reloader=False)
                # app.run() returned cleanly (server stopped) — nothing to restart
                return
            except OSError as e:
                print(f"[!] WARNING: Dashboard failed to start: {e}")
                print(f"[!] Port {bind_port} may already be in use. Daemon continues without dashboard.")
                return
            except Exception as e:
                dashboard_restarts += 1
                print(f"[!] Dashboard crashed ({e}) — restart {dashboard_restarts}/{max_dashboard_restarts}")
                logger = logging.getLogger("hostvigil")
                logger.error("Dashboard thread crashed: %s", e, exc_info=True)
                if dashboard_restarts >= max_dashboard_restarts:
                    print("[!] Dashboard restart limit reached — giving up on dashboard")
                    return
                # Backoff before restart; abort if shutdown is requested
                if orchestrator._shutdown_event.wait(timeout=dashboard_backoff):
                    return
                dashboard_backoff = min(dashboard_backoff * 2, 300)

    dashboard_thread = threading.Thread(
        target=_run_dashboard,
        name="hostvigil-dashboard",
        daemon=True,
    )
    dashboard_thread.start()
    print(f"[*] Dashboard: http://{bind_host}:{bind_port}")
    if not background:
        print("[*] Press Ctrl+C to stop gracefully")
    print()

    try:
        orchestrator.run_continuous()
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received")
        orchestrator.shutdown()

    print("[*] Daemon stopped")
    # Clean up PID file
    pid_file = Path("data/.hostvigil.pid")
    if pid_file.exists():
        pid_file.unlink()

    # Flush all log handlers before exit
    for handler in logging.getLogger("hostvigil").handlers:
        handler.flush()
        handler.close()

    return 0


def cmd_kill(orchestrator, args: argparse.Namespace) -> int:
    """Kill a running daemon process."""
    pid_file = Path("data/.hostvigil.pid")

    if not pid_file.exists():
        print("[!] No running daemon found (PID file missing)")
        print("[*] If the daemon is still running, use Ctrl+C in its terminal or kill the process manually")
        return 1

    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError) as e:
        print(f"[!] Corrupt PID file: {e}")
        pid_file.unlink(missing_ok=True)
        return 1
    print(f"[*] Found HostVigil daemon (PID: {pid})")

    # FIX #8: Validate the PID is actually a HostVigil/Python process before killing
    if not _validate_hostvigil_pid(pid):
        print(f"[!] PID {pid} does not appear to be a HostVigil process")
        print("[*] Cleaning up stale PID file")
        pid_file.unlink(missing_ok=True)
        return 1

    try:
        # Send SIGTERM (graceful shutdown)
        if os.name == "nt":
            # Windows: use taskkill
            import subprocess

            result = subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] Daemon (PID {pid}) terminated successfully")
            else:
                print(f"[!] Failed to kill process: {result.stderr.strip()}")
                pid_file.unlink(missing_ok=True)
                return 1
        else:
            # Unix: send SIGTERM for graceful shutdown
            os.kill(pid, signal.SIGTERM)
            print(f"[+] Sent SIGTERM to daemon (PID {pid})")
            print("[*] Daemon will shut down gracefully...")
    except ProcessLookupError:
        print(f"[!] Process {pid} not found (already stopped)")
    except PermissionError:
        print("[!] Permission denied - try running with elevated privileges")
        return 1

    # Clean up PID file
    pid_file.unlink(missing_ok=True)
    print("[+] PID file cleaned up")
    return 0


def _is_daemon_running() -> bool:
    """Return True if a HostVigil daemon appears to be running."""
    pid_file = Path("data/.hostvigil.pid")
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        return False
    return _is_pid_alive(pid)


def cmd_wipe(orchestrator, args: argparse.Namespace) -> int:
    """Securely wipe all HostVigil data — DB, logs, models, exports, PID files."""
    import shutil

    # Refuse to wipe underneath a live daemon — the daemon holds the DB open
    # and would recreate/corrupt state mid-operation.
    if _is_daemon_running():
        print("[!] A HostVigil daemon appears to be running.")
        print("[*] Stop it first with 'python run.py kill', then retry.")
        return 1

    print("[!] SELF-DESTRUCT: This will permanently delete ALL HostVigil data")
    print("[!] Including: database, logs, ML models, scan data, reports, PID files")
    print()

    if not args.force:
        confirm = input("[?] Type 'WIPE' to confirm: ")
        if confirm.strip() != "WIPE":
            print("[*] Aborted.")
            return 1

    print("[*] Wiping all data...")

    targets = [
        Path("data/hostvigil.db"),
        Path("data/.hostvigil.pid"),
    ]
    dirs_to_clean = [
        Path("data/logs"),
        Path("data/models"),
        Path("data/scans"),
        Path("data/reports"),
    ]

    # Delete individual files
    # When --secure is set, skip the DB here — it gets zero-filled + deleted below
    for f in targets:
        if args.secure and f == Path("data/hostvigil.db"):
            continue
        if f.exists():
            f.unlink()
            print(f"    [x] Deleted: {f}")

    # Clean directories (keep .gitkeep)
    for d in dirs_to_clean:
        if d.exists():
            for item in d.iterdir():
                if item.name == ".gitkeep":
                    continue
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
            print(f"    [x] Cleaned: {d}/")

    # Overwrite DB location with zeros if paranoid mode
    if args.secure:
        db_files = [
            Path("data/hostvigil.db"),
            Path("data/hostvigil.db-wal"),
            Path("data/hostvigil.db-shm"),
        ]
        any_existed = any(p.exists() for p in db_files)
        for db_path in db_files:
            if db_path.exists():
                try:
                    size = db_path.stat().st_size
                    if size > 0:
                        with open(db_path, "wb") as f:
                            f.write(b"\x00" * size)
                            f.flush()
                            os.fsync(f.fileno())
                    db_path.unlink()
                    print(f"    [x] Secure-wiped {db_path.name} (zeroed before delete)")
                except OSError as e:
                    print(f"    [!] Failed to secure-wipe {db_path.name}: {e}")
                    # Still try to delete
                    try:
                        db_path.unlink()
                    except OSError:
                        pass
        if not any_existed:
            print("    [x] DB files already absent (nothing to secure-wipe)")

    print()
    print("[+] All HostVigil data destroyed. No trace remains.")
    print("[*] To start fresh: python run.py daemon")
    return 0


def cmd_dashboard(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Start the web dashboard."""
    print(BANNER)
    host = args.host if hasattr(args, "host") and args.host else None
    port = args.port if hasattr(args, "port") and args.port else None

    orchestrator.install_signal_handlers()

    try:
        orchestrator.run_dashboard(host=host, port=port)
    except KeyboardInterrupt:
        print("\n[!] Dashboard stopped")
    return 0


def cmd_status(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Show current status."""
    status = orchestrator.get_status()

    print(BANNER)
    print("=" * 50)
    print("  HostVigil Status Report")
    print("=" * 50)

    # Orchestrator state
    orch = status["orchestrator"]
    print(f"\n  State:          {orch['state']}")
    print(f"  Current Phase:  {orch['current_phase'] or 'none'}")
    print(f"  Total Runs:     {orch['total_runs']}")
    print(f"  Total Errors:   {orch['total_errors']}")
    print(f"  Last Run:       {orch['last_run_end'] or 'never'}")
    print(f"  Last Result:    {orch['last_run_result'] or 'n/a'}")

    # Database stats
    db = status["database"]
    if "error" not in db:
        print("\n  Database:")
        print(f"    Hosts (active/total):  {db['active_hosts']}/{db['total_hosts']}")
        print(f"    Open Ports:            {db['total_ports']}")
        print(f"    Vulnerabilities:       {db['total_vulnerabilities']}")
        print(f"    Anomalies:             {db['total_anomalies']}")
        print(f"    Scans Completed:       {db['total_scans']}")

    # Config summary
    cfg = status["config"]
    print("\n  Schedule:")
    print(f"    Discovery every:  {cfg['discovery_interval_hours']}h")
    print(f"    Scan every:       {cfg['scan_interval_hours']}h")
    print(f"    Nuclei every:     {cfg['nuclei_interval_hours']}h")
    print(f"    Stealth delay:    {cfg['stealth_min_delay']}-{cfg['stealth_max_delay']}s")

    print("\n" + "=" * 50)

    if args.json:
        print("\nJSON output:")
        print(json.dumps(status, indent=2))

    return 0


def cmd_schema(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Print database schema and migration health."""
    import sqlite3

    conn = sqlite3.connect(orchestrator.db_path)
    conn.row_factory = sqlite3.Row
    try:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        indexes = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        # schema_migrations may not exist if DB was never initialized
        try:
            migrations = conn.execute(
                "SELECT version, description, applied_at FROM schema_migrations ORDER BY version"
            ).fetchall()
        except sqlite3.OperationalError:
            migrations = []

        if args.json:
            payload = {
                "db_path": orchestrator.db_path,
                "table_count": len(tables),
                "index_count": len(indexes),
                "migrations": [dict(row) for row in migrations],
                "tables": {},
            }
            for table in tables:
                # Sanitize table name: only allow alphanumeric and underscore
                tbl_name = table["name"]
                if not all(c.isalnum() or c == "_" for c in tbl_name):
                    continue
                cols = conn.execute(f"PRAGMA table_info([{tbl_name}])").fetchall()
                payload["tables"][tbl_name] = [dict(col) for col in cols]
            print(json.dumps(payload, indent=2, default=str))
            return 0

        print(BANNER)
        print(f"Database: {Path(orchestrator.db_path).resolve()}")
        print(f"Tables: {len(tables)} | Indexes: {len(indexes)}")
        print("\nMigrations:")
        for row in migrations:
            print(f"  {row['version']}  {row['description']}  {row['applied_at']}")
        print("\nTables:")
        for table in tables:
            tbl_name = table["name"]
            if not all(c.isalnum() or c == "_" for c in tbl_name):
                continue
            cols = conn.execute(f"PRAGMA table_info([{tbl_name}])").fetchall()
            col_text = ", ".join(f"{col['name']}:{col['type']}" for col in cols)
            print(f"  {tbl_name}: {col_text}")
        return 0
    finally:
        conn.close()


def cmd_doctor(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Check environment, configuration, and database readiness."""
    import ipaddress
    import shutil
    import sqlite3

    checks = []

    def add(name: str, ok: bool, detail: str):
        checks.append({"name": name, "ok": ok, "detail": detail})

    add("python", sys.version_info >= (3, 11), sys.version.split()[0])
    add("database", Path(orchestrator.db_path).exists(), str(Path(orchestrator.db_path).resolve()))

    try:
        conn = sqlite3.connect(orchestrator.db_path)
        conn.execute("SELECT COUNT(*) FROM hosts").fetchone()
        conn.close()
        add("database_query", True, "core tables query successfully")
    except Exception as exc:
        add("database_query", False, str(exc))
        try:
            conn.close()
        except Exception:
            pass

    for dirname in ("data/logs", "data/models", "data/scans", "data/reports"):
        path = Path(dirname)
        add(dirname, path.exists() and path.is_dir(), str(path.resolve()))

    nmap_path = shutil.which("nmap")
    nuclei_path = shutil.which(orchestrator.config.nuclei.get("binary_path", "nuclei"))
    add("nmap", bool(nmap_path), nmap_path or "not found in PATH")
    add("nuclei", bool(nuclei_path), nuclei_path or "not found in PATH")

    secret_key = orchestrator.config.dashboard.get("secret_key", "")
    add(
        "dashboard_secret",
        secret_key not in ("change-this-in-production", "hostvigil-default-key", ""),
        "configured"
        if secret_key not in ("change-this-in-production", "hostvigil-default-key", "")
        else "default/ephemeral",
    )

    noisy_ranges = []
    for cidr in orchestrator.config.discovery.get("target_ranges", []):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version == 4 and net.prefixlen <= 12:
                noisy_ranges.append(cidr)
        except ValueError:
            add("target_range", False, f"invalid CIDR: {cidr}")

    nmap_rate = " ".join(str(v) for v in orchestrator.config.discovery.get("nmap_extra_args", []))
    if noisy_ranges and "--min-rate" in nmap_rate:
        add("broad_scan_rate", False, f"broad ranges {noisy_ranges} with nmap_extra_args={nmap_rate}")
    else:
        add("broad_scan_rate", True, "no broad/noisy nmap combination detected")

    # Run centralized config validation
    config_errors = orchestrator.config.validate()
    for err in config_errors:
        add("config_validation", False, err)
    if not config_errors:
        add("config_validation", True, "all config values valid")

    if args.verbose:
        try:
            scale_warnings = orchestrator.config.validate_scale()
            if scale_warnings:
                for w in scale_warnings:
                    add("scale_warning", False, w)
            else:
                add("scale_check", True, "no scale misconfigurations detected")
        except Exception:
            pass

        try:
            conn = sqlite3.connect(orchestrator.db_path)
            host_count = conn.execute("SELECT COUNT(*) FROM hosts WHERE is_active = 1").fetchone()[0]
            port_count = conn.execute("SELECT COUNT(*) FROM ports WHERE state = 'open' AND is_active = 1").fetchone()[0]

            if host_count > 0:
                stealth = orchestrator.config.stealth
                min_d = stealth.get("min_delay", 0.5)
                max_d = stealth.get("max_delay", 2.0)
                avg_d = (min_d + max_d) / 2
                add("db_hosts", True, f"{host_count:,} active hosts in database")
                add("db_ports", True, f"{port_count:,} open ports in database")

                enum_hosts = min(host_count, int(host_count * 0.3))
                est_enum = enum_hosts * (avg_d + 1.0)
                add("est_service_enum", True, f"~{est_enum / 60:.0f}min ({enum_hosts:,} hosts x {avg_d:.1f}s delay)")

                if host_count < 50000:
                    tls_ports = conn.execute(
                        "SELECT COUNT(*) FROM ports WHERE port IN (443,8443,636,993,995,465,5986,2376,9443) "
                        "AND state='open' AND is_active=1"
                    ).fetchone()[0]
                else:
                    tls_ports = min(port_count, int(host_count * 0.1))
                est_tls = tls_ports * (avg_d + 3.0)
                add("est_tls_inspect", True, f"~{est_tls / 60:.0f}min ({tls_ports:,} TLS combos x {avg_d:.1f}s delay)")

                os_fp_enabled = orchestrator.config.hostvigil.get("os_fingerprint", {}).get("enabled", True)
                if os_fp_enabled:
                    est_osfp = host_count * (avg_d + 0.5)
                    add(
                        "est_os_fingerprint",
                        True,
                        f"~{est_osfp / 3600:.1f}h ({host_count:,} hosts x {avg_d:.1f}s delay)",
                    )
                else:
                    add("est_os_fingerprint", True, "disabled - zero cost")
            conn.close()
        except Exception:
            pass

    if args.json:
        print(json.dumps({"checks": checks, "ok": all(c["ok"] for c in checks)}, indent=2))
    else:
        print(BANNER)
        print("Doctor:")
        for check in checks:
            mark = "OK" if check["ok"] else "WARN"
            print(f"  [{mark}] {check['name']}: {check['detail']}")

    return 0 if all(c["ok"] for c in checks) else 1


def cmd_cleanup_reports(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Clean old generated report/export files."""
    from hostvigil.export_import import cleanup_old_reports

    result = cleanup_old_reports(
        max_age_days=args.days,
        max_total_mb=args.max_total_mb,
    )
    print(f"[+] Reports directory: {result['reports_dir']}")
    print(f"[+] Deleted {result['deleted_count']} file(s)")
    print(f"[+] Remaining files: {result['remaining_count']}")
    if args.json:
        print(json.dumps(result, indent=2))
    return 0


def cmd_export(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Export findings to JSON, CSV, or Markdown report."""
    from hostvigil.c2_export import C2Exporter
    from hostvigil.export_import import DataExporter

    exporter = DataExporter(orchestrator.db_path)
    c2 = C2Exporter(orchestrator.db_path)

    if args.format == "json":
        path = exporter.export_json(args.output)
        print(f"[+] Exported to: {path}")
    elif args.format == "csv":
        paths = exporter.export_csv(args.output)
        print(f"[+] Exported {len(paths)} CSV files")
        for p in paths:
            print(f"    {p}")
    elif args.format == "report":
        path = exporter.generate_report(args.output)
        print(f"[+] Report generated: {path}")
    elif args.format == "ips":
        path = c2.export_ips_only(args.output)
        print(f"[+] IPs exported to: {path}")
        print(f"    Usage: nmap -iL {path}")
    elif args.format == "targets":
        path = c2.export_targets_txt(args.output)
        print(f"[+] Targets (ip:port) exported to: {path}")
        print(f"    Usage: nuclei -l {path}")
    elif args.format == "urls":
        path = c2.export_urls(args.output)
        print(f"[+] URLs exported to: {path}")
        print(f"    Usage: httpx -l {path}")
    elif args.format == "c2":
        results = c2.export_all()
        print("[+] All C2 formats exported:")
        for name, path in results.items():
            print(f"    {name}: {path}")
    return 0


def cmd_import(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Import previous scan data from JSON or CSV."""
    from hostvigil.export_import import DataImporter

    if not Path(args.input_file).exists():
        print(f"[!] File not found: {args.input_file}")
        return 1

    importer = DataImporter(orchestrator.db_path)
    if args.input_file.endswith(".json"):
        result = importer.import_json(args.input_file, mode=args.mode)
    else:
        # Try to detect CSV type from filename
        if "host" in args.input_file.lower():
            result = importer.import_hosts_csv(args.input_file, mode=args.mode)
        elif "port" in args.input_file.lower():
            result = importer.import_ports_csv(args.input_file, mode=args.mode)
        elif "vuln" in args.input_file.lower():
            result = importer.import_vulns_csv(args.input_file, mode=args.mode)
        else:
            result = importer.import_json(args.input_file, mode=args.mode)
    print(f"[+] Import complete: {result}")
    return 0


def cmd_diff(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Show what changed since last scan cycle."""
    from hostvigil.scanner.scan_diff import ScanDiff

    hours = args.hours if hasattr(args, "hours") else 24
    diff = ScanDiff(orchestrator.db_path)
    result = diff.get_diff(hours)
    print(f"[*] Changes in last {hours} hours:")
    print(f"    New hosts:        {result['summary']['new_hosts_count']}")
    print(f"    Disappeared:      {result['summary']['disappeared_count']}")
    print(f"    New ports:        {result['summary']['new_ports_count']}")
    print(f"    Closed ports:     {result['summary']['closed_ports_count']}")
    if result["new_hosts"]:
        print("\n  New Hosts:")
        for h in result["new_hosts"][:20]:
            print(f"    + {h['ip']} ({h.get('hostname') or 'unknown'}) via {h.get('discovery_method', '?')}")
    if result["new_ports"]:
        print("\n  New Ports:")
        for p in result["new_ports"][:20]:
            print(f"    + {p['ip']}:{p['port']}/{p['protocol']} ({p.get('service', '?')})")
    return 0


def cmd_paths(orchestrator: HostVigilOrchestrator, args: argparse.Namespace) -> int:
    """Analyze and display attack paths."""
    from hostvigil.attack_paths import AttackPathEngine

    engine = AttackPathEngine(orchestrator.db_path)
    result = engine.analyze()
    print("\n  Attack Path Analysis")
    print(f"  {'=' * 40}")
    print(f"  Risk Score: {result['risk_score']:.0f}/100")
    print(f"  Initial Access Vectors: {len(result['initial_access'])}")
    print(f"  Lateral Movement Paths: {len(result['lateral_movement'])}")
    print(f"  Privilege Escalation: {len(result['privilege_escalation'])}")
    print(f"  Complete Chains: {len(result['attack_chains'])}")
    print(f"\n  Summary: {result['summary']}")
    if result["attack_chains"]:
        print("\n  Top Attack Chains:")
        for chain in result["attack_chains"][:5]:
            steps = " \u2192 ".join(f"{s['technique'][:25]} ({s.get('host', '?')})" for s in chain["steps"])
            print(f"    [{chain['severity'].upper()}] {steps}")
    return 0


def cmd_init(orchestrator_unused, args: argparse.Namespace) -> int:
    """Interactive config wizard or fresh-state reset."""
    if getattr(args, "fresh", False):
        import shutil

        from hostvigil.utils import init_database

        # Refuse to reset underneath a live daemon.
        if _is_daemon_running():
            print("[!] A HostVigil daemon appears to be running.")
            print("[*] Stop it first with 'python run.py kill', then retry.")
            return 1

        print("[!] FRESH INIT: This will delete all local HostVigil DB files, logs, and scan results.")
        print("[!] Targets include: data/*.db*, data/*.sqlite*, data/logs/, data/scans/, data/reports/, out.csv/")
        print("[!] Also removes Python caches: **/__pycache__/ and *.pyc/*.pyo")
        print()

        if not getattr(args, "force", False):
            confirm = input("[?] Type 'FRESH' to confirm: ").strip()
            if confirm != "FRESH":
                print("[*] Aborted.")
                return 1

        data_dir = Path("data")
        data_dir.mkdir(parents=True, exist_ok=True)

        deleted_files = 0
        cleaned_dirs = 0

        # Remove DB artifacts and SQLite snapshots/backups under data/.
        for pattern in ("*.db*", "*.sqlite*"):
            for file_path in data_dir.glob(pattern):
                if file_path.is_file():
                    file_path.unlink(missing_ok=True)
                    deleted_files += 1

        # Remove daemon pid marker if present.
        pid_file = data_dir / ".hostvigil.pid"
        if pid_file.exists():
            pid_file.unlink(missing_ok=True)
            deleted_files += 1

        # Clean scan/log output directories and recreate empty structure.
        output_dirs = [
            data_dir / "logs",
            data_dir / "scans",
            data_dir / "reports",
        ]
        for dir_path in output_dirs:
            if dir_path.exists():
                if dir_path.is_dir():
                    shutil.rmtree(dir_path)
                else:
                    dir_path.unlink(missing_ok=True)
            dir_path.mkdir(parents=True, exist_ok=True)
            cleaned_dirs += 1

        # Recreate a clean primary database.
        conn = init_database(data_dir / "hostvigil.db")
        conn.close()

        # Remove Python bytecode caches across the project.
        project_root = Path(".")
        pycache_dirs_removed = 0
        pyc_files_removed = 0

        for pycache_dir in project_root.rglob("__pycache__"):
            if pycache_dir.is_dir():
                shutil.rmtree(pycache_dir, ignore_errors=True)
                pycache_dirs_removed += 1

        for pattern in ("*.pyc", "*.pyo"):
            for pyc_file in project_root.rglob(pattern):
                if pyc_file.is_file():
                    pyc_file.unlink(missing_ok=True)
                    pyc_files_removed += 1

        print(f"[+] Fresh init complete. Deleted files: {deleted_files}, reset dirs: {cleaned_dirs}")
        print(
            f"[*] Python cache cleanup: removed {pycache_dirs_removed} __pycache__ dirs and {pyc_files_removed} bytecode files"
        )
        print("[*] Clean database created at data/hostvigil.db")
        print("[*] Start scanning with: python run.py daemon")
        return 0

    import yaml

    config_path = Path("config.yaml")
    if config_path.exists():
        overwrite = input("[?] config.yaml already exists. Overwrite? (y/N): ").strip().lower()
        if overwrite != "y":
            print("[*] Aborted.")
            return 0

    print()
    print("  HostVigil Configuration Wizard")
    print("  " + "=" * 35)
    print()

    # Target ranges
    print("[1/6] Target network ranges (CIDR notation)")
    print("       Examples: 10.0.0.0/8, 192.168.1.0/24")
    ranges_input = input("       Ranges (comma-separated): ").strip()
    if not ranges_input:
        ranges_input = "192.168.0.0/16"
    target_ranges = [r.strip() for r in ranges_input.split(",")]

    # Scan type
    print()
    print("[2/6] Scan type")
    print("       1. connect (no root needed, slightly more detectable)")
    print("       2. syn (requires root, stealthier)")
    scan_choice = input("       Choice [1]: ").strip()
    scan_type = "syn" if scan_choice == "2" else "connect"

    # Stealth level
    print()
    print("[3/6] Stealth level")
    print("       1. Low (5-15s delays) - faster but more detectable")
    print("       2. Medium (10-45s delays) - balanced")
    print("       3. High (30-90s delays) - very slow, very stealthy")
    stealth_choice = input("       Choice [2]: ").strip()
    if stealth_choice == "1":
        min_delay, max_delay = 5.0, 15.0
    elif stealth_choice == "3":
        min_delay, max_delay = 30.0, 90.0
    else:
        min_delay, max_delay = 10.0, 45.0

    # Dashboard
    print()
    print("[4/6] Dashboard binding")
    print("       1. localhost only (127.0.0.1) - stealth")
    print("       2. all interfaces (0.0.0.0) - accessible from network")
    dash_choice = input("       Choice [1]: ").strip()
    dash_host = "0.0.0.0" if dash_choice == "2" else "127.0.0.1"
    dash_port_input = input("       Port [5000]: ").strip()
    dash_port = int(dash_port_input) if dash_port_input else 5000

    # Nuclei
    print()
    print("[5/6] Nuclei vulnerability scanning")
    nuclei_enabled = input("       Enable auto Nuclei scans? (y/N): ").strip().lower() == "y"

    # Webhooks
    print()
    print("[6/6] Webhook notifications (optional)")
    webhook_url = input("       Webhook URL (blank to skip): ").strip()

    # Build config
    import secrets

    config = {
        "hostvigil": {
            "stealth": {
                "min_delay": min_delay,
                "max_delay": max_delay,
                "max_threads": 3,
                "jitter_factor": 0.3,
                "packet_fragmentation": True,
                "randomize_scan_order": True,
                "ttl_manipulation": True,
                "decoy_ips": ["10.0.0.1", "10.0.0.254", "172.16.0.1", "192.168.1.1", "100.64.0.1", "198.18.0.1"],
            },
            "discovery": {
                "techniques": [
                    "arp_sweep",
                    "passive_sniff",
                    "mdns_enum",
                    "nbns_query",
                    "dns_reverse_walk",
                    "snmp_sweep",
                    "ssdp_discover",
                    "tcp_syn_discover",
                    "dhcp_passive",
                ],
                "target_ranges": target_ranges,
            },
            "scanner": {
                "scan_type": scan_type,
                "port_profile": "standard",
                "udp_scan_enabled": True,
                "timeout": 1.5,
                "banner_grab": True,
                "service_detection": True,
            },
            "os_fingerprint": {"enabled": True},
            "tls_inspection": {"enabled": True},
            "service_enum": {"enabled": True},
            "ml_engine": {
                "model_path": "data/models/",
                "anomaly_threshold": 0.7,
                "min_training_samples": 50,
            },
            "nuclei": {
                "binary_path": "nuclei",
                "severity_filter": ["critical", "high", "medium"],
                "rate_limit": 10,
                "concurrency": 2,
                "auto_run": nuclei_enabled,
            },
            "dashboard": {
                "host": dash_host,
                "port": dash_port,
                "secret_key": secrets.token_hex(16),
                "refresh_interval": 15,
            },
            "scheduler": {
                "discovery_interval_hours": 4,
                "scan_interval_hours": 2,
                "nuclei_interval_hours": 6,
            },
            "database": {"path": "data/hostvigil.db"},
        }
    }

    if webhook_url:
        config["hostvigil"]["webhooks"] = {
            "enabled": True,
            "urls": [webhook_url],
            "notify_on": ["critical_vuln", "new_host", "high_anomaly"],
        }

    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print()
    print(f"[+] Configuration saved to {config_path}")
    print('[*] Run "python run.py daemon" to start scanning')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="hostvigil",
        description="HostVigil - Stealth Internal Recon Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="For authorized internal security assessments only.",
    )
    parser.add_argument(
        "-c",
        "--config",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose console output (reduces stealth)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # discover
    sub_discover = subparsers.add_parser("discover", help="Run host discovery only")
    sub_discover.set_defaults(func=cmd_discover)

    # observer (passive-only)
    sub_observer = subparsers.add_parser("observer", help="Passive-only observer mode (no active probing)")
    sub_observer.set_defaults(func=cmd_observer)

    # scan
    sub_scan = subparsers.add_parser("scan", help="Run port scanning only")
    sub_scan.set_defaults(func=cmd_scan)

    # analyze
    sub_analyze = subparsers.add_parser("analyze", help="Run ML anomaly analysis only")
    sub_analyze.set_defaults(func=cmd_analyze)

    # nuclei
    sub_nuclei = subparsers.add_parser("nuclei", help="Run Nuclei vulnerability scan only")
    sub_nuclei.set_defaults(func=cmd_nuclei)

    # udpscan
    sub_udp = subparsers.add_parser("udpscan", help="Run UDP port scan only")
    sub_udp.set_defaults(func=cmd_udpscan)

    # fingerprint
    sub_fp = subparsers.add_parser("fingerprint", help="Run OS fingerprinting only")
    sub_fp.set_defaults(func=cmd_fingerprint)

    # tls
    sub_tls = subparsers.add_parser("tls", help="Run TLS/SSL inspection only")
    sub_tls.set_defaults(func=cmd_tls)

    # enumerate
    sub_enum = subparsers.add_parser("enumerate", help="Run deep service enumeration (SMB/LDAP/etc)")
    sub_enum.set_defaults(func=cmd_enumerate)

    # servicescan (nmap -sV deep service/version detection)
    sub_svcscan = subparsers.add_parser("servicescan", help="Deep service/version detection with nmap -sV")
    sub_svcscan.set_defaults(func=cmd_servicescan)

    # full
    sub_full = subparsers.add_parser("full", help="Run complete pipeline once")
    sub_full.set_defaults(func=cmd_full)

    # daemon
    sub_daemon = subparsers.add_parser("daemon", help="Run continuously in background")
    sub_daemon.add_argument(
        "--background",
        "-b",
        action="store_true",
        help="Fork into the background (no screen/tmux needed). Use 'python run.py kill' to stop.",
    )
    sub_daemon.set_defaults(func=cmd_daemon)

    # kill
    sub_kill = subparsers.add_parser("kill", help="Kill a running daemon process")
    sub_kill.set_defaults(func=cmd_kill)

    # wipe (self-destruct)
    sub_wipe = subparsers.add_parser("wipe", help="Securely wipe all data (self-destruct)")
    sub_wipe.add_argument("--force", action="store_true", help="Skip confirmation prompt")
    sub_wipe.add_argument("--secure", action="store_true", help="Zero-fill before delete (paranoid mode)")
    sub_wipe.set_defaults(func=cmd_wipe)

    # dashboard
    sub_dashboard = subparsers.add_parser("dashboard", help="Start web dashboard")
    sub_dashboard.add_argument("--host", default=None, help="Dashboard bind address")
    sub_dashboard.add_argument("--port", type=int, default=None, help="Dashboard port")
    sub_dashboard.set_defaults(func=cmd_dashboard)

    # status
    sub_status = subparsers.add_parser("status", help="Show current status")
    sub_status.add_argument("--json", action="store_true", help="Output as JSON")
    sub_status.set_defaults(func=cmd_status)

    # schema
    sub_schema = subparsers.add_parser("schema", help="Show database schema and migrations")
    sub_schema.add_argument("--json", action="store_true", help="Output as JSON")
    sub_schema.set_defaults(func=cmd_schema)

    # doctor
    sub_doctor = subparsers.add_parser("doctor", help="Check environment, config, and database health")
    sub_doctor.add_argument("--json", action="store_true", help="Output as JSON")
    sub_doctor.add_argument(
        "--verbose", "-vv", action="store_true", help="Include scaling analysis and phase estimates"
    )
    sub_doctor.set_defaults(func=cmd_doctor)

    # cleanup-reports
    sub_cleanup = subparsers.add_parser("cleanup-reports", help="Delete old generated reports/exports")
    sub_cleanup.add_argument("--days", type=int, default=14, help="Delete reports older than this many days")
    sub_cleanup.add_argument("--max-total-mb", type=int, default=500, help="Keep report directory under this size")
    sub_cleanup.add_argument("--json", action="store_true", help="Output cleanup details as JSON")
    sub_cleanup.set_defaults(func=cmd_cleanup_reports)

    # export
    sub_export = subparsers.add_parser("export", help="Export findings to JSON/CSV/IPs/targets")
    sub_export.add_argument(
        "--format",
        choices=["json", "csv", "report", "ips", "targets", "urls", "c2"],
        default="json",
        help="Export format (ips=plain IP list, targets=ip:port, urls=HTTP URLs, c2=all C2 formats)",
    )
    sub_export.add_argument("--output", "-o", default=None, help="Output path")
    sub_export.set_defaults(func=cmd_export)

    # import
    sub_import = subparsers.add_parser("import", help="Import previous scan data")
    sub_import.add_argument("input_file", help="Path to JSON or CSV file to import")
    sub_import.add_argument("--mode", choices=["merge", "replace"], default="merge", help="Import mode")
    sub_import.set_defaults(func=cmd_import)

    # diff
    sub_diff = subparsers.add_parser("diff", help="Show what changed since last scan cycle")
    sub_diff.add_argument("--hours", type=int, default=24, help="Hours to look back")
    sub_diff.set_defaults(func=cmd_diff)

    # paths
    sub_paths = subparsers.add_parser("paths", help="Analyze and display attack paths")
    sub_paths.set_defaults(func=cmd_paths)

    # init
    sub_init = subparsers.add_parser("init", help="Interactive configuration wizard")
    sub_init.add_argument("--fresh", action="store_true", help="Delete DBs/logs/scan results and recreate a clean DB")
    sub_init.add_argument("--force", action="store_true", help="Skip confirmation prompt when used with --fresh")
    sub_init.set_defaults(func=cmd_init)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Handle 'init', 'kill', and 'wipe' specially - they don't need a valid config or orchestrator
    if args.command in ("init", "kill", "wipe"):
        return args.func(None, args)

    # Validate config exists
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[!] Config file not found: {config_path}")
        print("[*] Create config.yaml or specify path with -c")
        return 1

    # Initialize orchestrator
    try:
        orchestrator = HostVigilOrchestrator(config_path=str(config_path))
    except Exception as e:
        print(f"[!] Failed to initialize HostVigil: {e}")
        return 1

    # Verbose mode warning
    if args.verbose:
        import logging

        logging.getLogger("hostvigil").addHandler(logging.StreamHandler())
        print("[!] Verbose mode enabled - console output reduces stealth")

    # Execute command
    return args.func(orchestrator, args)


if __name__ == "__main__":
    sys.exit(main())
