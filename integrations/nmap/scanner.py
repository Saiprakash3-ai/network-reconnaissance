from __future__ import annotations

from pathlib import Path
from typing import Any

from integrations.base import CommandResult, SafeCommandRunner
from integrations.nmap.parser import parse_nmap_xml


class NmapScanner:
    def __init__(self, runner: SafeCommandRunner, binary: str = "nmap"):
        self.runner = runner
        self.binary = binary

    async def _run_nmap(self, extra_args: list[str], *, timeout: int, artifact_name: str) -> dict[str, Any]:
        resolved = self.runner.resolve_binary(self.binary)
        cmd = [resolved, *extra_args, "-oX", "-"]
        result: CommandResult = await self.runner.run(cmd, timeout=timeout, artifact_name=artifact_name)
        parsed = parse_nmap_xml(result.stdout)
        return {
            "command": result.command,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "stderr": result.stderr,
            "artifact_path": result.artifact_path,
            "raw_xml": result.stdout,
            "parsed": parsed,
        }

    async def host_discovery(self, targets: list[str], timeout: int = 300, artifact_name: str = "nmap-discovery.xml.txt") -> dict[str, Any]:
        # -sn: ping scan/no port scan; -PE/PP/PS optional in lab; keep default safe/lightweight.
        args = ["-sn", "-T3", *targets]
        return await self._run_nmap(args, timeout=timeout, artifact_name=artifact_name)

    async def port_scan(self, targets: list[str], ports: str | None = None, top_ports: int | None = 100, udp: bool = False, timeout: int = 600, artifact_name: str = "nmap-portscan.xml.txt") -> dict[str, Any]:
        args = ["-sU" if udp else "-sS" if False else "-sT", "-T3"]
        # Use -sT by default for non-root/local compatibility; -sS can be enabled by privileged profile.
        if udp:
            args = ["-sU", "-T3"]
        if ports:
            args += ["-p", ports]
        elif top_ports:
            args += ["--top-ports", str(top_ports)]
        args += ["-Pn", *targets]
        return await self._run_nmap(args, timeout=timeout, artifact_name=artifact_name)

    async def service_detection(self, targets: list[str], ports: str | None = None, os_detection: bool = False, timeout: int = 900, artifact_name: str = "nmap-services.xml.txt") -> dict[str, Any]:
        args = ["-sT", "-sV", "-T3", "-Pn"]
        if os_detection:
            args.append("-O")
        if ports:
            args += ["-p", ports]
        args += ["--version-light", *targets]
        return await self._run_nmap(args, timeout=timeout, artifact_name=artifact_name)
