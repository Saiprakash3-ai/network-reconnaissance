from __future__ import annotations

from typing import Any

from engines.base import BaseEngine
from integrations.nmap.scanner import NmapScanner


class HostDiscoveryEngine(BaseEngine):
    name = "host_discovery"

    async def run(self, targets: list[str], options: dict[str, Any]) -> dict[str, Any]:
        scanner = NmapScanner(self.ctx.runner, binary=self.ctx.settings.get("integrations", {}).get("nmap", {}).get("binary", "nmap"))
        result = await scanner.host_discovery(
            targets=targets,
            timeout=int(options.get("timeout", self.ctx.timeout)),
            artifact_name=f"{self.ctx.artifact_prefix}-discovery.xml.txt",
        )
        hosts = result["parsed"].get("hosts", [])
        normalized = []
        for h in hosts:
            if h.get("status") != "up":
                continue
            normalized.append(
                {
                    "ip": h.get("ip"),
                    "mac": h.get("mac"),
                    "hostnames": [x.get("name") for x in h.get("hostnames", []) if x.get("name")],
                    "status": h.get("status"),
                    "source": "nmap",
                }
            )
        return {
            "engine": self.name,
            "targets": targets,
            "raw": result,
            "normalized": {"hosts": normalized, "stats": result["parsed"].get("stats", {})},
        }
