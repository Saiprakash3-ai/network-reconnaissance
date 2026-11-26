from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from backend.authorization.audit import append_audit_log
from backend.authorization.scope import ScopeValidator, ScopeViolation
from config.loader import load_settings
from database.models import Asset, Finding, FindingState, JobStatus, ScanJob, Service, Severity
from database.models.entities import Port
from database.repositories.scans import ScanRepository
from database.session import SessionLocal
from engines.base import EngineContext
from engines.dns_intelligence.engine import DNSIntelligenceEngine
from engines.host_discovery.engine import HostDiscoveryEngine
from engines.network_mapping.engine import NetworkMappingEngine
from engines.osint.engine import OSINTEngine
from engines.port_scanner.engine import PortScanEngine
from engines.protocol_analysis.engine import ProtocolAnalysisEngine
from engines.service_detection.engine import ServiceDetectionEngine
from engines.vulnerability_assessment.engine import VulnerabilityAssessmentEngine
from integrations.base import SafeCommandRunner


PROFILE_ENGINES = {
    "discovery": [HostDiscoveryEngine],
    "port_scan": [HostDiscoveryEngine, PortScanEngine],
    "service_enum": [HostDiscoveryEngine, PortScanEngine, ServiceDetectionEngine],
    "dns_enum": [DNSIntelligenceEngine],
    "osint_passive": [OSINTEngine],
    "vuln_assessment": [HostDiscoveryEngine, PortScanEngine, ServiceDetectionEngine, VulnerabilityAssessmentEngine],
    "pcap_analysis": [ProtocolAnalysisEngine],
    "full_lab_assessment": [HostDiscoveryEngine, PortScanEngine, ServiceDetectionEngine, VulnerabilityAssessmentEngine, NetworkMappingEngine],
}


class OrchestrationService:
    def __init__(self, settings: dict[str, Any] | None = None):
        self.settings = settings or load_settings()
        self.scope = ScopeValidator.from_settings(self.settings)
        self.artifact_dir = Path(self.settings.get("app", {}).get("artifact_dir", "./lab/evidence/artifacts"))
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log_path = self.settings.get("app", {}).get("audit_log_path", "./lab/evidence/audit.log")
        self.max_concurrent = int(self.settings.get("app", {}).get("max_concurrent_jobs", 2))
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._tasks: dict[int, asyncio.Task] = {}
        self._cancel_flags: set[int] = set()

    def _audit(self, event: dict[str, Any]) -> None:
        append_audit_log(self.audit_log_path, event)

    async def create_and_run_job(self, *, profile: str, targets: list[str], options: dict[str, Any] | None = None, requested_by: str = "local-user") -> ScanJob:
        options = options or {}
        self.scope.validate_profile(profile)
        decisions = [self.scope.validate(t) for t in targets]
        timeout = int(options.get("timeout", self.settings.get("app", {}).get("default_scan_timeout_seconds", 300)))
        timeout = min(timeout, int(self.settings.get("app", {}).get("max_scan_timeout_seconds", 900)))

        async with SessionLocal() as db:
            repo = ScanRepository(db)
            job = await repo.create_job(
                profile=profile,
                targets=targets,
                options={**options, "scope_decisions": [d.__dict__ for d in decisions]},
                scope_name=self.scope.scope_config.get("engagement", {}).get("name"),
                requested_by=requested_by,
                timeout_seconds=timeout,
            )
            await repo.add_audit(job_id=job.id, actor=requested_by, action="job.created", target=",".join(targets), outcome="ok", details={"profile": profile})
            self._audit({"job_id": job.id, "action": "job.created", "targets": targets, "profile": profile, "actor": requested_by})
            job_id = job.id

        task = asyncio.create_task(self._run_job(job_id))
        self._tasks[job_id] = task
        async with SessionLocal() as db:
            repo = ScanRepository(db)
            job = await repo.get_job(job_id)
            assert job is not None
            return job

    async def run_job_sync(self, *, profile: str, targets: list[str], options: dict[str, Any] | None = None, requested_by: str = "local-user") -> ScanJob:
        job = await self.create_and_run_job(profile=profile, targets=targets, options=options, requested_by=requested_by)
        task = self._tasks.get(job.id)
        if task:
            await task
        async with SessionLocal() as db:
            repo = ScanRepository(db)
            refreshed = await repo.get_job(job.id)
            assert refreshed is not None
            return refreshed

    async def cancel_job(self, job_id: int, actor: str = "local-user") -> bool:
        self._cancel_flags.add(job_id)
        task = self._tasks.get(job_id)
        if task and not task.done():
            task.cancel()
        async with SessionLocal() as db:
            repo = ScanRepository(db)
            job = await repo.get_job(job_id)
            if not job:
                return False
            await repo.set_status(job, JobStatus.cancelled, error="Cancelled by user")
            await repo.add_audit(job_id=job_id, actor=actor, action="job.cancelled", target=None, outcome="ok", details={})
        self._audit({"job_id": job_id, "action": "job.cancelled", "actor": actor})
        return True

    async def _run_job(self, job_id: int) -> None:
        async with self._semaphore:
            async with SessionLocal() as db:
                repo = ScanRepository(db)
                job = await repo.get_job(job_id)
                if not job:
                    return
                await repo.set_status(job, JobStatus.running)
                self._audit({"job_id": job_id, "action": "job.started", "profile": job.profile})

            try:
                await asyncio.wait_for(self._execute(job_id), timeout=(await self._get_timeout(job_id)))
            except asyncio.CancelledError:
                await self._mark(job_id, JobStatus.cancelled, "Cancelled")
            except asyncio.TimeoutError:
                await self._mark(job_id, JobStatus.timed_out, "Job timed out")
            except ScopeViolation as e:
                await self._mark(job_id, JobStatus.failed, f"Scope violation: {e}")
            except Exception as e:  # noqa: BLE001
                await self._mark(job_id, JobStatus.failed, f"{type(e).__name__}: {e}")

    async def _get_timeout(self, job_id: int) -> int:
        async with SessionLocal() as db:
            job = await ScanRepository(db).get_job(job_id)
            return int(job.timeout_seconds) if job else 300

    async def _mark(self, job_id: int, status: JobStatus, error: str | None) -> None:
        async with SessionLocal() as db:
            repo = ScanRepository(db)
            job = await repo.get_job(job_id)
            if job:
                await repo.set_status(job, status, error=error)
                await repo.add_audit(job_id=job_id, actor="system", action=f"job.{status.value}", target=None, outcome="ok" if status == JobStatus.completed else "error", details={"error": error})
        self._audit({"job_id": job_id, "action": f"job.{status.value}", "error": error})

    async def _execute(self, job_id: int) -> None:
        async with SessionLocal() as db:
            repo = ScanRepository(db)
            job = await repo.get_job(job_id)
            if not job:
                return
            if job_id in self._cancel_flags:
                await repo.set_status(job, JobStatus.cancelled, error="Cancelled")
                return
            profile = job.profile
            targets = list(job.targets)
            options = dict(job.options or {})
            options.setdefault("job_id", job_id)

        engines = PROFILE_ENGINES.get(profile)
        if not engines:
            raise ValueError(f"Unsupported profile: {profile}")

        runner = SafeCommandRunner(self.artifact_dir)
        results: list[dict[str, Any]] = []
        for engine_cls in engines:
            if job_id in self._cancel_flags:
                await self._mark(job_id, JobStatus.cancelled, "Cancelled")
                return
            ctx = EngineContext(
                runner=runner,
                settings=self.settings,
                timeout=int(options.get("timeout", self.settings.get("app", {}).get("default_scan_timeout_seconds", 300))),
                artifact_prefix=f"job-{job_id}-{engine_cls.name}",
            )
            engine = engine_cls(ctx)
            result = await engine.run(targets, options)
            results.append(result)
            await self._persist_engine_result(job_id, result)

        async with SessionLocal() as db:
            repo = ScanRepository(db)
            job = await repo.get_job(job_id)
            if job:
                job.summary = {
                    "profile": profile,
                    "target_count": len(targets),
                    "engines": [r.get("engine") for r in results],
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                }
                await db.commit()
                await repo.set_status(job, JobStatus.completed)
                await repo.add_audit(job_id=job_id, actor="system", action="job.completed", target=None, outcome="ok", details=job.summary)
        self._audit({"job_id": job_id, "action": "job.completed", "engines": [r.get("engine") for r in results]})

    async def _persist_engine_result(self, job_id: int, result: dict[str, Any]) -> None:
        async with SessionLocal() as db:
            repo = ScanRepository(db)
            raw = result.get("raw", {})
            artifact_path = raw.get("artifact_path")
            if artifact_path:
                await repo.add_evidence(job_id=job_id, kind="raw_output", path=artifact_path, content_type="text/plain", metadata={"engine": result.get("engine"), "command": raw.get("command")})

            normalized = result.get("normalized", {})
            hosts = normalized.get("hosts", [])
            for h in hosts:
                ip = h.get("ip") or (h.get("hostnames") or [None])[0]
                if not ip:
                    continue
                asset_key = str(ip)
                existing_asset = await db.execute(
                    select(Asset).where(Asset.scan_job_id == job_id, Asset.asset_key == asset_key)
                )
                asset = existing_asset.scalar_one_or_none()
                if asset is None:
                    asset = Asset(
                        scan_job_id=job_id,
                        asset_key=asset_key,
                        asset_type="host",
                        ip_address=h.get("ip"),
                        hostname=(h.get("hostnames") or [None])[0] if isinstance(h.get("hostnames"), list) else None,
                        mac_address=h.get("mac"),
                        os_name=((h.get("os") or {}).get("name")),
                        os_accuracy=((h.get("os") or {}).get("accuracy")),
                        status=h.get("status", "up"),
                        details=h,
                    )
                    db.add(asset)
                    await db.flush()
                else:
                    # Merge richer data from later engines.
                    if h.get("mac"):
                        asset.mac_address = h.get("mac")
                    os_info = h.get("os") or {}
                    if os_info.get("name"):
                        asset.os_name = os_info.get("name")
                        asset.os_accuracy = os_info.get("accuracy")
                    details = dict(asset.details or {})
                    details.update(h)
                    asset.details = details

                # Persist ports/services when present
                for svc in h.get("services", []) or []:
                    port_num = svc.get("port")
                    proto = svc.get("protocol", "tcp")
                    if port_num is None:
                        continue
                    port_obj = Port(asset_id=asset.id, port=int(port_num), protocol=str(proto), state=str(svc.get("state", "unknown")), details=svc)
                    db.add(port_obj)
                    await db.flush()
                    db.add(Service(
                        port_id=port_obj.id,
                        name=svc.get("service"),
                        product=svc.get("product"),
                        version=svc.get("version"),
                        extrainfo=svc.get("extrainfo"),
                        cpe=svc.get("cpes", []),
                        details={"scripts": svc.get("scripts", [])},
                    ))

                for p in h.get("ports", []) or []:
                    # port_scan engine shape
                    if "service" in p and "port" in p and "product" not in p and isinstance(p.get("service"), (str, type(None))):
                        port_num = p.get("port")
                        if port_num is None:
                            continue
                        existing = await db.execute(select(Port).where(Port.asset_id == asset.id, Port.port == int(port_num), Port.protocol == str(p.get("protocol", "tcp"))))
                        if existing.scalar_one_or_none():
                            continue
                        port_obj = Port(asset_id=asset.id, port=int(port_num), protocol=str(p.get("protocol", "tcp")), state=str(p.get("state", "unknown")), details=p)
                        db.add(port_obj)
                        await db.flush()
                        db.add(Service(port_id=port_obj.id, name=p.get("service"), details={}))

                # Basic suspected findings from scripts/banners - marked suspected, never confirmed
                for script in h.get("host_scripts", []) or []:
                    out = (script.get("output") or "").lower()
                    if "vulnerable" in out or "cve-" in out:
                        db.add(Finding(
                            scan_job_id=job_id,
                            asset_id=asset.id,
                            title=f"Script indicator: {script.get('id', 'unknown')}",
                            description=script.get("output", "")[:2000],
                            state=FindingState.suspected,
                            severity=Severity.medium,
                            evidence_summary="NSE script output indicates potential issue; manual validation required.",
                            remediation="Validate manually in authorized lab before taking action.",
                            correlation={"ip": asset.ip_address, "script": script.get("id")},
                            raw=script,
                        ))
            await db.commit()
