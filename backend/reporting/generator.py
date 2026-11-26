from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

try:
    from fpdf import FPDF
except Exception:  # pragma: no cover
    FPDF = None  # type: ignore

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import Asset, Evidence, Finding, ScanJob
from database.models.entities import Port, Service


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


async def collect_job_data(db: AsyncSession, job_id: int) -> dict[str, Any]:
    job = (await db.execute(select(ScanJob).where(ScanJob.id == job_id))).scalar_one_or_none()
    if not job:
        raise ValueError(f"Job {job_id} not found")
    assets = list((await db.execute(select(Asset).where(Asset.scan_job_id == job_id))).scalars().all())
    findings = list((await db.execute(select(Finding).where(Finding.scan_job_id == job_id))).scalars().all())
    evidence = list((await db.execute(select(Evidence).where(Evidence.scan_job_id == job_id))).scalars().all())

    asset_rows = []
    for a in assets:
        ports = list((await db.execute(select(Port).where(Port.asset_id == a.id))).scalars().all())
        port_rows = []
        for p in ports:
            services = list((await db.execute(select(Service).where(Service.port_id == p.id))).scalars().all())
            port_rows.append({
                "port": p.port, "protocol": p.protocol, "state": p.state,
                "services": [{
                    "name": s.name, "product": s.product, "version": s.version,
                    "extrainfo": s.extrainfo, "cpes": s.cpe,
                } for s in services],
            })
        asset_rows.append({
            "id": a.id, "ip": a.ip_address, "hostname": a.hostname, "mac": a.mac_address,
            "os": a.os_name, "os_accuracy": a.os_accuracy, "status": a.status, "ports": port_rows,
        })

    finding_rows = [{
        "id": f.id, "title": f.title, "description": f.description, "state": f.state.value,
        "severity": f.severity.value, "cvss": f.cvss_score, "cve_ids": f.cve_ids, "cwe_ids": f.cwe_ids,
        "epss": f.epss_score, "kev": f.kev, "evidence_summary": f.evidence_summary,
        "remediation": f.remediation, "references": f.references, "mitre_attack": f.mitre_attack,
        "correlation": f.correlation,
    } for f in findings]

    evidence_rows = [{
        "id": e.id, "kind": e.kind, "path": e.path, "content_type": e.content_type, "metadata": e.metadata_,
    } for e in evidence]

    return {
        "generated_at": _utc(),
        "job": {
            "id": job.id, "profile": job.profile, "status": job.status.value, "targets": job.targets,
            "scope_name": job.scope_name, "requested_by": job.requested_by,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "summary": job.summary, "error": job.error,
        },
        "assets": asset_rows,
        "findings": finding_rows,
        "evidence": evidence_rows,
    }


def write_json_report(data: dict[str, Any], out_dir: Path, job_id: int) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"job-{job_id}-report.json"
    p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return p


def write_csv_report(data: dict[str, Any], out_dir: Path, job_id: int) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"job-{job_id}-findings.csv"
    fields = ["id", "title", "state", "severity", "cvss", "cve_ids", "cwe_ids", "kev", "evidence_summary", "remediation"]
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in data.get("findings", []):
            w.writerow({k: json.dumps(row.get(k), default=str) if isinstance(row.get(k), (list, dict)) else row.get(k) for k in fields})
    return p


def write_html_report(data: dict[str, Any], out_dir: Path, job_id: int) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"job-{job_id}-report.html"
    job = data["job"]
    findings = data.get("findings", [])
    assets = data.get("assets", [])
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    def row(cells: list[str]) -> str:
        return "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"

    finding_rows = "\n".join(row([
        str(f["id"]), escape(f["title"]), escape(f["state"]), escape(f["severity"]),
        escape(", ".join(f.get("cve_ids") or [])), escape((f.get("evidence_summary") or "")[:200]),
    ]) for f in findings)

    asset_rows = "\n".join(row([
        escape(str(a.get("ip") or "")), escape(str(a.get("hostname") or "")), escape(str(a.get("os") or "")),
        escape(", ".join(f"{p['port']}/{p['protocol']}" for p in a.get("ports", []))),
    ]) for a in assets)

    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>NR Report - Job {job_id}</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;margin:24px;background:#f8fafc;color:#111827}}
.card{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:16px}}
table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top}}
th{{background:#f3f4f6}} .warn{{color:#92400e}} .muted{{color:#6b7280}}
</style></head><body>
<h1>Network Reconnaissance Report</h1>
<div class="card"><h2>Executive Summary</h2>
<p><strong>Job:</strong> {job_id} | <strong>Profile:</strong> {escape(str(job.get('profile')))} | <strong>Status:</strong> {escape(str(job.get('status')))}</p>
<p><strong>Targets:</strong> {escape(', '.join(job.get('targets') or []))}</p>
<p><strong>Generated:</strong> {escape(data.get('generated_at',''))}</p>
<p><strong>Finding severity counts:</strong> {escape(json.dumps(sev_counts))}</p>
<p class="warn"><strong>Safety note:</strong> Findings marked suspected/detected require manual validation in authorized lab environments. No automatic exploitation was performed.</p>
</div>
<div class="card"><h2>Scope & Authorization</h2>
<p><strong>Scope/Engagement:</strong> {escape(str(job.get('scope_name') or 'N/A'))}</p>
<p><strong>Requested by:</strong> {escape(str(job.get('requested_by')))}</p>
<p><strong>Started:</strong> {escape(str(job.get('started_at')))} | <strong>Finished:</strong> {escape(str(job.get('finished_at')))}</p>
</div>
<div class="card"><h2>Asset & Port Inventory</h2>
<table><thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Open Ports</th></tr></thead><tbody>{asset_rows}</tbody></table></div>
<div class="card"><h2>Findings</h2>
<table><thead><tr><th>ID</th><th>Title</th><th>State</th><th>Severity</th><th>CVEs</th><th>Evidence</th></tr></thead><tbody>{finding_rows}</tbody></table></div>
<div class="card"><h2>Evidence Artifacts</h2>
<ul>{"".join(f"<li>{escape(e['kind'])}: {escape(e['path'])}</li>" for e in data.get('evidence', []))}</ul></div>
<div class="card"><h2>Remediation Guidance</h2>
<ul>{"".join(f"<li><strong>{escape(f['title'])}</strong>: {escape(f.get('remediation') or 'Review manually and remediate per asset owner policy.')}</li>" for f in findings) or '<li>No findings recorded. Validate scan coverage and scope.</li>'}</ul>
</div>
<p class="muted">Generated for authorized lab use only.</p>
</body></html>"""
    p.write_text(html, encoding="utf-8")
    return p


def _pdf_safe(text: str, width: int = 95) -> str:
    text = str(text).replace("\t", " ")
    # Break very long tokens so fpdf can wrap.
    out = []
    for token in text.split(" "):
        if len(token) <= width:
            out.append(token)
        else:
            out.extend([token[i:i+width] for i in range(0, len(token), width)])
    return " ".join(out)


def write_pdf_report(data: dict[str, Any], out_dir: Path, job_id: int) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"job-{job_id}-report.pdf"
    if FPDF is None:
        p.write_bytes(b"%PDF-1.4\n% Network Reconnaissance\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n")
        return p
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.multi_cell(0, 10, _pdf_safe(f"Network Reconnaissance Report - Job {job_id}"))
    pdf.set_font("Helvetica", "", 10)
    job = data["job"]
    lines = [
        f"Generated: {data.get('generated_at','')}",
        f"Profile: {job.get('profile')} | Status: {job.get('status')}",
        f"Targets: {', '.join(job.get('targets') or [])}",
        f"Scope: {job.get('scope_name') or 'N/A'} | Requested by: {job.get('requested_by')}",
        "Safety: Authorized lab use only. Findings are suspected/detected until manually validated.",
        "",
        "Assets:",
    ]
    for a in data.get("assets", []):
        ports = ", ".join(f"{p_['port']}/{p_['protocol']}" for p_ in a.get("ports", []))
        lines.append(f"- {a.get('ip') or a.get('hostname')} os={a.get('os')} ports=[{ports}]")
    lines.append("")
    lines.append("Findings:")
    for f in data.get("findings", []):
        lines.append(f"- [{f.get('severity')}/{f.get('state')}] {f.get('title')} CVEs={','.join(f.get('cve_ids') or [])}")
    for line in lines:
        safe = _pdf_safe(line).encode("latin-1", "replace").decode("latin-1")
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 6, safe)
    pdf.output(str(p))
    return p


async def generate_reports(db: AsyncSession, job_id: int, out_dir: str | Path, formats: list[str] | None = None) -> dict[str, str]:
    formats = formats or ["json", "csv", "html"]
    data = await collect_job_data(db, job_id)
    out = Path(out_dir)
    results: dict[str, str] = {}
    if "json" in formats:
        results["json"] = str(write_json_report(data, out, job_id))
    if "csv" in formats:
        results["csv"] = str(write_csv_report(data, out, job_id))
    if "html" in formats:
        results["html"] = str(write_html_report(data, out, job_id))
    if "pdf" in formats:
        results["pdf"] = str(write_pdf_report(data, out, job_id))
    return results
