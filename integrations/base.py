from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    artifact_path: str | None = None


class IntegrationError(RuntimeError):
    pass


class SafeCommandRunner:
    """Runs external tools with argument lists only - never shell=True."""

    def __init__(self, artifact_dir: str | Path):
        self.artifact_dir = Path(artifact_dir)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

    def resolve_binary(self, binary: str) -> str:
        path = shutil.which(binary)
        if not path:
            raise IntegrationError(f"Required binary not found in PATH: {binary}")
        return path

    async def run(
        self,
        args: Sequence[str],
        *,
        timeout: int = 300,
        cwd: str | Path | None = None,
        artifact_name: str | None = None,
    ) -> CommandResult:
        if not args:
            raise IntegrationError("Empty command")
        cmd = [str(a) for a in args]
        # Enforce argument-list execution only.
        proc = await asyncio.create_subprocess_exec(
            cmd[0],
            *cmd[1:],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
        )
        timed_out = False
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            timed_out = True
            proc.kill()
            stdout_b, stderr_b = await proc.communicate()
        stdout = stdout_b.decode("utf-8", errors="replace")
        stderr = stderr_b.decode("utf-8", errors="replace")
        artifact_path = None
        if artifact_name:
            p = self.artifact_dir / artifact_name
            p.write_text(stdout + ("\n[stderr]\n" + stderr if stderr else ""), encoding="utf-8")
            artifact_path = str(p)
        return CommandResult(cmd, proc.returncode or 0, stdout, stderr, timed_out=timed_out, artifact_path=artifact_path)
