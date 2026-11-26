from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import Asset, Finding
from database.models.entities import Port, Service


async def build_topology(db: AsyncSession, job_id: int) -> dict[str, Any]:
    assets = list((await db.execute(select(Asset).where(Asset.scan_job_id == job_id))).scalars().all())
    findings = list((await db.execute(select(Finding).where(Finding.scan_job_id == job_id))).scalars().all())
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    nodes.append({"data": {"id": "lab", "label": "Authorized Lab", "type": "network"}})

    finding_by_asset: dict[int, list[Finding]] = {}
    for f in findings:
        if f.asset_id:
            finding_by_asset.setdefault(f.asset_id, []).append(f)

    for a in assets:
        aid = f"asset-{a.id}"
        label = a.ip_address or a.hostname or a.asset_key
        vuln_count = len(finding_by_asset.get(a.id, []))
        nodes.append({"data": {"id": aid, "label": label, "type": "host", "os": a.os_name, "vuln_count": vuln_count}})
        edges.append({"data": {"id": f"e-lab-{aid}", "source": "lab", "target": aid, "type": "contains"}})
        ports = list((await db.execute(select(Port).where(Port.asset_id == a.id))).scalars().all())
        for p in ports:
            pid = f"port-{p.id}"
            nodes.append({"data": {"id": pid, "label": f"{p.port}/{p.protocol}", "type": "port", "state": p.state}})
            edges.append({"data": {"id": f"e-{aid}-{pid}", "source": aid, "target": pid, "type": "exposes"}})
            svcs = list((await db.execute(select(Service).where(Service.port_id == p.id))).scalars().all())
            for s in svcs:
                sid = f"svc-{s.id}"
                slabel = " ".join(x for x in [s.name, s.product, s.version] if x) or "service"
                nodes.append({"data": {"id": sid, "label": slabel, "type": "service"}})
                edges.append({"data": {"id": f"e-{pid}-{sid}", "source": pid, "target": sid, "type": "runs"}})

    for f in findings:
        fid = f"finding-{f.id}"
        nodes.append({"data": {"id": fid, "label": f.title, "type": "finding", "severity": f.severity.value, "state": f.state.value}})
        if f.asset_id:
            edges.append({"data": {"id": f"e-asset-{f.asset_id}-{fid}", "source": f"asset-{f.asset_id}", "target": fid, "type": "has_finding"}})

    return {"job_id": job_id, "elements": {"nodes": nodes, "edges": edges}}
