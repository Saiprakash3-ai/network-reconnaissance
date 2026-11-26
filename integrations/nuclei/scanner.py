from __future__ import annotations

import json
from typing import Any

from integrations.base import CommandResult, SafeCommandRunner


class NucleiScanner:
    def __init__(self, runner: SafeCommandRunner, binary: str = "nuclei"):
        self.runner = runner
        self.binary = binary

    async def scan_targets(self, targets: list[str], *, timeout: int = 600, artifact_name: str = "nuclei.jsonl.txt", severity: str | None = None, templates: list[str] | None = None) -> dict[str, Any]:
        resolved = self.runner.resolve_binary(self.binary)
        # -jsonl for machine-readable output; -duc disable update check for determinism in lab
        cmd = [resolved, "-duc", "-jsonl", "-silent"]
        if severity:
            cmd += ["-severity", severity]
        for t in templates or []:
            cmd += ["-t", t]
        for t in targets:
            cmd += ["-u", t if "://" in t else f"http://{t}"]
        result: CommandResult = await self.runner.run(cmd, timeout=timeout, artifact_name=artifact_name)
        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {
            "command": result.command,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "stderr": result.stderr,
            "artifact_path": result.artifact_path,
            "raw": result.stdout,
            "parsed": findings,
        }
