from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.authorization.scope import ScopeValidator, ScopeViolation
from backend.orchestration.service import OrchestrationService
from backend.reporting.diff import diff_jobs
from backend.reporting.generator import generate_reports
from backend.reporting.topology import build_topology
from config.loader import load_settings
from database.models import Asset, Finding, ScanJob
from database.repositories.scans import ScanRepository
from database.session import get_db

router = APIRouter()


def _get_settings() -> dict[str, Any]:
    return load_settings()


def _get_orchestrator() -> OrchestrationService:
    return OrchestrationService(_get_settings())


def _get_scope() -> ScopeValidator:
    return ScopeValidator.from_settings(_get_settings())


class ScanRequest(BaseModel):
    profile: str = Field(..., examples=["discovery", "port_scan", "service_enum"])
    targets: list[str] = Field(..., min_length=1)
    options: dict[str, Any] = Field(default_factory=dict)
    requested_by: str = "api-user"


class ScopeCheckRequest(BaseModel):
    targets: list[str]
    profile: str | None = None


@router.get("/health")
async def health() -> dict[str, Any]:
    settings = _get_settings()
    return {"status": "ok", "app": settings.get("app", {}).get("name", "Network Reconnaissance")}


@router.post("/scope/validate")
async def validate_scope(req: ScopeCheckRequest) -> dict[str, Any]:
    scope = _get_scope()
    if req.profile:
        try:
            scope.validate_profile(req.profile)
        except ScopeViolation as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
    decisions = []
    for t in req.targets:
        d = scope.evaluate(t)
        decisions.append(d.__dict__)
    return {"decisions": decisions}


@router.post("/jobs")
async def create_job(req: ScanRequest, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    try:
        orchestrator = _get_orchestrator()
        job = await orchestrator.create_and_run_job(
            profile=req.profile, targets=req.targets, options=req.options, requested_by=req.requested_by
        )
    except ScopeViolation as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"job_id": job.id, "status": job.status.value, "profile": job.profile, "targets": job.targets}


@router.get("/jobs")
async def list_jobs(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    repo = ScanRepository(db)
    jobs = await repo.list_jobs()
    return {
        "jobs": [
            {
                "id": j.id,
                "profile": j.profile,
                "status": j.status.value,
                "targets": j.targets,
                "created_at": j.created_at.isoformat() if j.created_at else None,
                "started_at": j.started_at.isoformat() if j.started_at else None,
                "finished_at": j.finished_at.isoformat() if j.finished_at else None,
                "error": j.error,
                "summary": j.summary,
            }
            for j in jobs
        ]
    }


@router.get("/jobs/{job_id}")
async def get_job(job_id: int, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    repo = ScanRepository(db)
    job = await repo.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    assets_res = await db.execute(select(Asset).where(Asset.scan_job_id == job_id))
    assets = list(assets_res.scalars().all())
    findings_res = await db.execute(select(Finding).where(Finding.scan_job_id == job_id))
    findings = list(findings_res.scalars().all())
    return {
        "id": job.id,
        "profile": job.profile,
        "status": job.status.value,
        "targets": job.targets,
        "options": job.options,
        "error": job.error,
        "summary": job.summary,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "assets": [
            {"id": a.id, "ip": a.ip_address, "hostname": a.hostname, "mac": a.mac_address, "os": a.os_name, "status": a.status}
            for a in assets
        ],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "state": f.state.value,
                "severity": f.severity.value,
                "cve_ids": f.cve_ids,
                "evidence_summary": f.evidence_summary,
            }
            for f in findings
        ],
    }


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: int) -> dict[str, Any]:
    orchestrator = _get_orchestrator()
    ok = await orchestrator.cancel_job(job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job_id": job_id, "cancelled": True}


@router.get("/jobs/{job_id}/assets")
async def get_assets(job_id: int, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    res = await db.execute(select(Asset).where(Asset.scan_job_id == job_id))
    assets = list(res.scalars().all())
    return {"job_id": job_id, "assets": [
        {"id": a.id, "ip": a.ip_address, "hostname": a.hostname, "mac": a.mac_address, "os": a.os_name, "status": a.status, "details": a.details}
        for a in assets
    ]}


@router.get("/jobs/{job_id}/findings")
async def get_findings(job_id: int, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    res = await db.execute(select(Finding).where(Finding.scan_job_id == job_id))
    findings = list(res.scalars().all())
    return {"job_id": job_id, "findings": [
        {
            "id": f.id, "title": f.title, "description": f.description, "state": f.state.value,
            "severity": f.severity.value, "cvss": f.cvss_score, "cve_ids": f.cve_ids, "cwe_ids": f.cwe_ids,
            "epss": f.epss_score, "kev": f.kev, "evidence_summary": f.evidence_summary,
            "remediation": f.remediation, "mitre_attack": f.mitre_attack, "correlation": f.correlation,
        } for f in findings
    ]}


@router.post("/jobs/{job_id}/report")
async def create_report(job_id: int, formats: list[str] | None = None, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    settings = _get_settings()
    out_dir = settings.get("app", {}).get("report_dir", "./reports/output")
    try:
        paths = await generate_reports(db, job_id, out_dir, formats=formats)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return {"job_id": job_id, "reports": paths}


@router.get("/jobs/{job_id}/topology")
async def get_topology(job_id: int, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    return await build_topology(db, job_id)


@router.get("/jobs/diff")
async def get_diff(base: int, compare: int, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    try:
        return await diff_jobs(db, base, compare)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
