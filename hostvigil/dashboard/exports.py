"""Export API blueprint for the HostVigil dashboard."""

import csv
import io
import json
import os
import zipfile
from pathlib import Path
from typing import Callable

from flask import Blueprint, jsonify, send_file


def create_export_blueprint(
    db_path_getter: Callable[[], str],
    query_db: Callable,
    get_stats: Callable[[], dict],
    now_iso: Callable[[], str],
) -> Blueprint:
    """Create dashboard export routes with explicit app dependencies."""
    bp = Blueprint("exports", __name__)

    @bp.route("/api/export/json")
    def api_export_json():
        """Export all findings as a JSON file download."""
        from hostvigil.export_import import DataExporter

        exporter = DataExporter(db_path_getter())
        path = os.path.abspath(exporter.export_json())
        return send_file(path, as_attachment=True, download_name=Path(path).name)

    @bp.route("/api/export/csv")
    def api_export_csv():
        """Export all findings as a ZIP of CSV files."""
        from hostvigil.export_import import DataExporter

        exporter = DataExporter(db_path_getter())
        paths = exporter.export_csv()
        memory_file = io.BytesIO()
        try:
            with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
                for path in paths:
                    zf.write(path, Path(path).name)
        finally:
            # Clean up temporary CSV files
            for path in paths:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        memory_file.seek(0)
        return send_file(
            memory_file,
            as_attachment=True,
            download_name="hostvigil_export.zip",
            mimetype="application/zip",
        )

    @bp.route("/api/export/report")
    def api_export_report():
        """Generate and download a Markdown summary report."""
        from hostvigil.export_import import DataExporter

        exporter = DataExporter(db_path_getter())
        path = os.path.abspath(exporter.generate_report())
        return send_file(path, as_attachment=True, download_name=Path(path).name)

    @bp.route("/api/export/ips")
    def api_export_ips():
        """Export plain IP list."""
        from hostvigil.c2_export import C2Exporter

        c2 = C2Exporter(db_path_getter())
        path = os.path.abspath(c2.export_ips_only())
        return send_file(path, as_attachment=True, download_name="hostvigil_ips.txt")

    @bp.route("/api/export/targets")
    def api_export_targets():
        """Export ip:port target list."""
        from hostvigil.c2_export import C2Exporter

        c2 = C2Exporter(db_path_getter())
        path = os.path.abspath(c2.export_targets_txt())
        return send_file(path, as_attachment=True, download_name="hostvigil_targets.txt")

    @bp.route("/api/export/urls")
    def api_export_urls():
        """Export HTTP URLs."""
        from hostvigil.c2_export import C2Exporter

        c2 = C2Exporter(db_path_getter())
        path = os.path.abspath(c2.export_urls())
        return send_file(path, as_attachment=True, download_name="hostvigil_urls.txt")

    @bp.route("/api/export/c2")
    def api_export_c2():
        """Export all C2 framework formats."""
        from hostvigil.c2_export import C2Exporter

        return jsonify(C2Exporter(db_path_getter()).export_all())

    @bp.route("/api/export/pivot-paths")
    def api_export_pivot_paths():
        """Export ranked pivot targets and paths."""
        from hostvigil.attack_paths import AttackPathEngine

        analysis = AttackPathEngine(db_path_getter()).analyze()
        return jsonify(
            {
                "best_footholds": analysis.get("best_footholds", []),
                "crown_jewels": analysis.get("crown_jewels", []),
                "pivot_paths": analysis.get("pivot_paths", []),
                "credential_clusters": analysis.get("credential_clusters", []),
                "risk_score": analysis.get("risk_score", 0),
                "summary": analysis.get("summary", ""),
            }
        )

    @bp.route("/api/export/pdf_report")
    def api_export_pdf_report():
        """Generate and download a print-ready HTML report."""
        from hostvigil.report_generator import ReportGenerator

        path = os.path.abspath(ReportGenerator(db_path_getter()).generate_pdf_report())
        return send_file(path, as_attachment=True, download_name="hostvigil_report.html")

    @bp.route("/api/export/zip")
    def api_export_zip():
        """Export all findings as a ZIP with JSON + CSV + Markdown."""
        hosts = query_db("SELECT * FROM hosts")
        ports = query_db("SELECT p.*, h.ip FROM ports p JOIN hosts h ON h.id = p.host_id")
        vulns = query_db("SELECT v.*, h.ip FROM vulnerabilities v JOIN hosts h ON h.id = v.host_id")
        anomalies_data = query_db("SELECT a.*, h.ip FROM anomalies a JOIN hosts h ON h.id = a.host_id")

        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
            export_data = {
                "hosts": hosts,
                "ports": ports,
                "vulnerabilities": vulns,
                "anomalies": anomalies_data,
                "exported_at": now_iso(),
            }
            zf.writestr("hostvigil_export.json", json.dumps(export_data, indent=2, default=str))

            for name, rows in (
                ("hosts.csv", hosts),
                ("ports.csv", ports),
                ("vulnerabilities.csv", vulns),
            ):
                if not rows:
                    continue
                csv_buf = io.StringIO()
                writer = csv.DictWriter(csv_buf, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
                zf.writestr(name, csv_buf.getvalue())

            stats = get_stats()
            md = "# HostVigil Report\n\n"
            md += f"**Generated:** {now_iso()}\n\n"
            md += "## Summary\n\n"
            md += f"- **Total Hosts:** {stats['total_hosts']}\n"
            md += f"- **Total Ports:** {stats['total_ports']}\n"
            md += f"- **Critical Vulns:** {stats['vulnerabilities']['critical']}\n"
            md += f"- **High Vulns:** {stats['vulnerabilities']['high']}\n"
            md += f"- **Active Anomalies:** {stats['active_anomalies']}\n\n"
            md += "## Hosts\n\n"
            for host in hosts[:50]:
                md += f"- {host.get('ip', '?')} ({host.get('hostname') or 'unknown'})\n"
            if len(hosts) > 50:
                md += f"\n... and {len(hosts) - 50} more\n"
            md += "\n## Vulnerabilities\n\n"
            for vuln in vulns[:50]:
                md += f"- [{vuln.get('severity', '?').upper()}] {vuln.get('name', '?')} on {vuln.get('ip', '?')}\n"
            zf.writestr("report.md", md)

        memory_file.seek(0)
        return send_file(
            memory_file,
            as_attachment=True,
            download_name="hostvigil_full_export.zip",
            mimetype="application/zip",
        )

    return bp
