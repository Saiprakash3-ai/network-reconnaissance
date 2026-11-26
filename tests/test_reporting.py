from __future__ import annotations

import pytest

from backend.reporting.diff import diff_jobs
from backend.reporting.generator import generate_reports
from backend.reporting.topology import build_topology
from database.models import Asset, Finding, FindingState, Severity
from database.repositories.scans import ScanRepository
from database.session import SessionLocal, init_db


@pytest.mark.asyncio
async def test_report_and_topology_generation(tmp_path):
    await init_db()
    async with SessionLocal() as db:
        repo = ScanRepository(db)
        job = await repo.create_job(
            profile="discovery", targets=["127.0.0.1"], options={}, scope_name="Test Lab", requested_by="pytest", timeout_seconds=30
        )
        db.add(Asset(scan_job_id=job.id, asset_key="127.0.0.1", ip_address="127.0.0.1", status="up", details={}))
        await db.commit()
        db.add(Finding(
            scan_job_id=job.id,
            title="Test suspected finding",
            description="desc",
            state=FindingState.suspected,
            severity=Severity.low,
            evidence_summary="evidence",
            remediation="validate",
            correlation={"ip": "127.0.0.1"},
            raw={},
        ))
        await db.commit()

        paths = await generate_reports(db, job.id, tmp_path, formats=["json", "csv", "html", "pdf"])
        assert "json" in paths and "csv" in paths and "html" in paths and "pdf" in paths
        for p in paths.values():
            assert tmp_path.joinpath(p.split("/")[-1]).exists() or __import__("pathlib").Path(p).exists()

        topo = await build_topology(db, job.id)
        assert topo["job_id"] == job.id
        assert len(topo["elements"]["nodes"]) >= 2


@pytest.mark.asyncio
async def test_diff_jobs(tmp_path):
    await init_db()
    async with SessionLocal() as db:
        repo = ScanRepository(db)
        j1 = await repo.create_job(profile="discovery", targets=["127.0.0.1"], options={}, scope_name="Test", requested_by="pytest", timeout_seconds=30)
        j2 = await repo.create_job(profile="discovery", targets=["127.0.0.1"], options={}, scope_name="Test", requested_by="pytest", timeout_seconds=30)
        db.add(Asset(scan_job_id=j1.id, asset_key="10.0.0.1", ip_address="10.0.0.1", status="up", details={}))
        db.add(Asset(scan_job_id=j2.id, asset_key="10.0.0.2", ip_address="10.0.0.2", status="up", details={}))
        await db.commit()
        d = await diff_jobs(db, j1.id, j2.id)
        assert "10.0.0.2" in d["hosts_added"]
        assert "10.0.0.1" in d["hosts_removed"]
