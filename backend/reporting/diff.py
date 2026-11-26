from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import Asset, Finding, ScanJob
from database.models.entities import Port


async def diff_jobs(db: AsyncSession, base_job_id: int, compare_job_id: int) -> dict[str, Any]:
    base = (await db.execute(select(ScanJob).where(ScanJob.id == base_job_id))).scalar_one_or_none()
    comp = (await db.execute(select(ScanJob).where(ScanJob.id == compare_job_id))).scalar_one_or_none()
    if not base or not comp:
        raise ValueError("Both jobs must exist")

    async def snapshot(job_id: int):
        assets = list((await db.execute(select(Asset).where(Asset.scan_job_id == job_id))).scalars().all())
        host_keys = {a.ip_address or a.hostname or a.asset_key for a in assets}
        ports = set()
        for a in assets:
            for p in list((await db.execute(select(Port).where(Port.asset_id == a.id))).scalars().all()):
                ports.add(f"{a.ip_address or a.asset_key}:{p.protocol}/{p.port}/{p.state}")
        findings = list((await db.execute(select(Finding).where(Finding.scan_job_id == job_id))).scalars().all())
        finding_keys = {f"{f.title}|{f.severity.value}|{f.state.value}" for f in findings}
        return host_keys, ports, finding_keys

    b_hosts, b_ports, b_findings = await snapshot(base_job_id)
    c_hosts, c_ports, c_findings = await snapshot(compare_job_id)
    return {
        "base_job_id": base_job_id,
        "compare_job_id": compare_job_id,
        "hosts_added": sorted(c_hosts - b_hosts),
        "hosts_removed": sorted(b_hosts - c_hosts),
        "ports_added": sorted(c_ports - b_ports),
        "ports_removed": sorted(b_ports - c_ports),
        "findings_added": sorted(c_findings - b_findings),
        "findings_removed": sorted(b_findings - c_findings),
    }
