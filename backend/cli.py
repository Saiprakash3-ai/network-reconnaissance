from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from backend.authorization.scope import ScopeValidator, ScopeViolation
from backend.orchestration.service import OrchestrationService
from backend.reporting.diff import diff_jobs
from backend.reporting.generator import generate_reports
from config.loader import load_settings
from database.session import SessionLocal, init_db
from database.repositories.scans import ScanRepository

app = typer.Typer(name="nr", help="Network Reconnaissance - local-first recon lab CLI", no_args_is_help=True)
jobs_app = typer.Typer(help="Inspect scan jobs")
app.add_typer(jobs_app, name="jobs")
console = Console()


@app.command("init-db")
def init_db_cmd() -> None:
    """Initialize the local SQLite database."""
    asyncio.run(init_db())
    console.print("[green]Database initialized.[/green]")


@app.command("scope-check")
def scope_check(
    targets: list[str] = typer.Argument(..., help="Targets to validate"),
    profile: Optional[str] = typer.Option(None, "--profile", help="Scan profile to validate"),
) -> None:
    """Validate targets against scope and private-lab-only policy."""
    settings = load_settings()
    validator = ScopeValidator.from_settings(settings)
    if profile:
        try:
            validator.validate_profile(profile)
        except ScopeViolation as e:
            console.print(f"[red]Profile denied:[/red] {e}")
            raise typer.Exit(code=2)

    table = Table(title="Scope Decisions")
    table.add_column("Target")
    table.add_column("Allowed")
    table.add_column("Type")
    table.add_column("Reason")
    table.add_column("Resolved IPs")
    failed = False
    for t in targets:
        d = validator.evaluate(t)
        failed = failed or (not d.allowed)
        table.add_row(t, "yes" if d.allowed else "no", d.target_type, d.reason, ", ".join(d.resolved_ips))
    console.print(table)
    if failed:
        raise typer.Exit(code=1)


@app.command("scan")
def scan(
    profile: str = typer.Option(..., "--profile", "-p", help="discovery|port_scan|service_enum|full_lab_assessment"),
    target: list[str] = typer.Option(..., "--target", "-t", help="Target IP/CIDR/hostname (repeatable)"),
    ports: Optional[str] = typer.Option(None, "--ports", help="Port spec, e.g. 22,80,443 or 1-1024"),
    top_ports: int = typer.Option(100, "--top-ports", help="Top ports for port scan"),
    timeout: int = typer.Option(300, "--timeout", help="Timeout seconds (capped by settings)"),
    os_detection: bool = typer.Option(False, "--os-detection", help="Enable OS detection where supported"),
    requested_by: str = typer.Option("cli-user", "--requested-by"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON result"),
) -> None:
    """Run a scoped scan job synchronously and persist results."""
    settings = load_settings()
    asyncio.run(init_db())
    svc = OrchestrationService(settings)
    options = {"ports": ports, "top_ports": top_ports, "timeout": timeout, "os_detection": os_detection}

    async def _run():
        return await svc.run_job_sync(profile=profile, targets=list(target), options=options, requested_by=requested_by)

    try:
        job = asyncio.run(_run())
    except ScopeViolation as e:
        console.print(f"[red]Scope violation:[/red] {e}")
        raise typer.Exit(code=2)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Scan failed:[/red] {e}")
        raise typer.Exit(code=1)

    if json_out:
        console.print_json(json.dumps({
            "id": job.id, "status": job.status.value, "profile": job.profile, "targets": job.targets,
            "summary": job.summary, "error": job.error,
        }, default=str))
        return

    console.print(f"[bold]Job {job.id}[/bold] status={job.status.value} profile={job.profile}")
    if job.error:
        console.print(f"[red]Error:[/red] {job.error}")
    console.print(job.summary or {})


@jobs_app.command("list")
def jobs_list(limit: int = typer.Option(20, "--limit")) -> None:
    """List recent jobs."""
    asyncio.run(init_db())

    async def _run():
        async with SessionLocal() as db:
            repo = ScanRepository(db)
            return await repo.list_jobs(limit=limit)

    jobs = asyncio.run(_run())
    table = Table(title="Scan Jobs")
    table.add_column("ID")
    table.add_column("Profile")
    table.add_column("Status")
    table.add_column("Targets")
    table.add_column("Created")
    for j in jobs:
        table.add_row(str(j.id), j.profile, j.status.value, ", ".join(j.targets), str(j.created_at))
    console.print(table)


@jobs_app.command("show")
def jobs_show(job_id: int = typer.Argument(...)) -> None:
    """Show job details."""
    asyncio.run(init_db())

    async def _run():
        async with SessionLocal() as db:
            repo = ScanRepository(db)
            return await repo.get_job(job_id)

    job = asyncio.run(_run())
    if not job:
        console.print("[red]Job not found[/red]")
        raise typer.Exit(code=1)
    console.print_json(json.dumps({
        "id": job.id,
        "profile": job.profile,
        "status": job.status.value,
        "targets": job.targets,
        "options": job.options,
        "summary": job.summary,
        "error": job.error,
        "created_at": str(job.created_at),
        "started_at": str(job.started_at),
        "finished_at": str(job.finished_at),
        "asset_count": len(job.assets),
        "finding_count": len(job.findings),
        "evidence_count": len(job.evidence),
    }, default=str))


@app.command("serve")
def serve(host: str = "127.0.0.1", port: int = 8000, reload: bool = False) -> None:
    """Run the FastAPI dashboard/API server."""
    import uvicorn

    uvicorn.run("backend.app:app", host=host, port=port, reload=reload)


@app.command("report")
def report_cmd(
    job_id: int = typer.Argument(..., help="Job ID"),
    fmt: list[str] = typer.Option(["json", "csv", "html", "pdf"], "--format", "-f", help="Report formats"),
    out_dir: str = typer.Option("./reports/output", "--out-dir"),
) -> None:
    """Generate report artifacts for a scan job."""
    asyncio.run(init_db())

    async def _run():
        async with SessionLocal() as db:
            return await generate_reports(db, job_id, out_dir, formats=list(fmt))

    try:
        paths = asyncio.run(_run())
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Report failed:[/red] {e}")
        raise typer.Exit(code=1)
    console.print_json(json.dumps({"job_id": job_id, "reports": paths}, indent=2))


@app.command("diff")
def diff_cmd(base: int = typer.Argument(...), compare: int = typer.Argument(...)) -> None:
    """Diff two scan jobs (hosts/ports/findings)."""
    asyncio.run(init_db())

    async def _run():
        async with SessionLocal() as db:
            return await diff_jobs(db, base, compare)

    try:
        result = asyncio.run(_run())
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Diff failed:[/red] {e}")
        raise typer.Exit(code=1)
    console.print_json(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    app()
