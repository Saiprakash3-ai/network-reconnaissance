from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database.models import AuditEvent, Evidence, Finding, JobStatus, ScanJob


class ScanRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_job(self, *, profile: str, targets: list[str], options: dict, scope_name: str | None, requested_by: str, timeout_seconds: int) -> ScanJob:
        job = ScanJob(
            profile=profile,
            targets=targets,
            options=options,
            scope_name=scope_name,
            requested_by=requested_by,
            timeout_seconds=timeout_seconds,
            status=JobStatus.queued,
        )
        self.db.add(job)
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def get_job(self, job_id: int) -> ScanJob | None:
        stmt = (
            select(ScanJob)
            .options(
                selectinload(ScanJob.assets),
                selectinload(ScanJob.findings),
                selectinload(ScanJob.evidence),
                selectinload(ScanJob.audit_events),
            )
            .where(ScanJob.id == job_id)
        )
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def list_jobs(self, limit: int = 50) -> list[ScanJob]:
        res = await self.db.execute(select(ScanJob).order_by(ScanJob.id.desc()).limit(limit))
        return list(res.scalars().all())

    async def set_status(self, job: ScanJob, status: JobStatus, error: str | None = None) -> ScanJob:
        job.status = status
        job.error = error
        now = datetime.now(timezone.utc)
        if status == JobStatus.running:
            job.started_at = now
        if status in {JobStatus.completed, JobStatus.failed, JobStatus.cancelled, JobStatus.timed_out}:
            job.finished_at = now
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def add_audit(self, *, job_id: int | None, actor: str, action: str, target: str | None, outcome: str, details: dict) -> AuditEvent:
        evt = AuditEvent(scan_job_id=job_id, actor=actor, action=action, target=target, outcome=outcome, details=details)
        self.db.add(evt)
        await self.db.commit()
        await self.db.refresh(evt)
        return evt

    async def add_evidence(self, *, job_id: int, kind: str, path: str, content_type: str | None = None, metadata: dict | None = None, finding_id: int | None = None) -> Evidence:
        ev = Evidence(scan_job_id=job_id, finding_id=finding_id, kind=kind, path=path, content_type=content_type, metadata_=metadata or {})
        self.db.add(ev)
        await self.db.commit()
        await self.db.refresh(ev)
        return ev

    async def add_finding(self, finding: Finding) -> Finding:
        self.db.add(finding)
        await self.db.commit()
        await self.db.refresh(finding)
        return finding
