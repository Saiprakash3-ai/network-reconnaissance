from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from engines.base import EngineContext
from engines.dns_intelligence.engine import DNSIntelligenceEngine
from engines.vulnerability_assessment.engine import VulnerabilityAssessmentEngine
from integrations.base import SafeCommandRunner
from database.session import init_db, SessionLocal
from database.repositories.scans import ScanRepository
from database.models import Asset
from database.models.entities import Port, Service


class DummyRunner(SafeCommandRunner):
    def __init__(self):
        pass


@pytest.mark.asyncio
async def test_dns_engine_handles_empty_resolution(monkeypatch):
    async def fake_resolve(host, rdtype):
        return []
    monkeypatch.setattr("engines.dns_intelligence.engine._resolve", fake_resolve)
    ctx = EngineContext(runner=DummyRunner(), settings={}, timeout=5, artifact_prefix="t")
    eng = DNSIntelligenceEngine(ctx)
    res = await eng.run(["example.local"], {})
    assert res["engine"] == "dns_intelligence"
    assert "dns" in res["normalized"]


@pytest.mark.asyncio
async def test_vuln_engine_creates_suspected_findings(tmp_path):
    await init_db()
    async with SessionLocal() as db:
        repo = ScanRepository(db)
        job = await repo.create_job(profile="vuln_assessment", targets=["127.0.0.1"], options={}, scope_name="Test", requested_by="pytest", timeout_seconds=30)
        asset = Asset(scan_job_id=job.id, asset_key="127.0.0.1", ip_address="127.0.0.1", status="up", details={})
        db.add(asset)
        await db.flush()
        port = Port(asset_id=asset.id, port=21, protocol="tcp", state="open", details={})
        db.add(port)
        await db.flush()
        db.add(Service(port_id=port.id, name="ftp", product="vsftpd", version="2.3.4", details={}))
        await db.commit()
        job_id = job.id

    ctx = EngineContext(runner=DummyRunner(), settings={"integrations": {"nuclei": {"enabled": False}}}, timeout=5, artifact_prefix="t")
    eng = VulnerabilityAssessmentEngine(ctx)
    res = await eng.run(["127.0.0.1"], {"job_id": job_id})
    assert res["normalized"]["findings_created"] >= 1

    async with SessionLocal() as db:
        from sqlalchemy import select
        from database.models import Finding
        findings = list((await db.execute(select(Finding).where(Finding.scan_job_id == job_id))).scalars().all())
        assert any(f.state.value == "suspected" for f in findings)
