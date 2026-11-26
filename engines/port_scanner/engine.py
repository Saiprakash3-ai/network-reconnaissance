from __future__ import annotations

from typing import Any

from engines.base import BaseEngine
from integrations.nmap.scanner import NmapScanner


class PortScanEngine(BaseEngine):
    name = "port_scan"

    async def run(self, targets: list[str], options: dict[str, Any]) -> dict[str, Any]:
        scanner = NmapScanner(self.ctx.runner, binary=self.ctx.settings.get("integrations", {}).get("nmap", {}).get("binary", "nmap"))
        result = await scanner.port_scan(
            targets=targets,
            ports=options.get("ports"),
            top_ports=options.get("top_ports", 100),
            udp=bool(options.get("udp", False)),
            timeout=int(options.get("timeout", self.ctx.timeout)),
            artifact_name=f"{self.ctx.artifact_prefix}-portscan.xml.txt",
        )
        hosts = []
        for h in result["parsed"].get("hosts", []):
            ports = []
            for p in h.get("ports", []):
                if p.get("state") not in {"open", "open|filtered"}:
                    continue
                ports.append(
                    {
                        "port": p.get("port"),
                        "protocol": p.get("protocol"),
                        "state": p.get("state"),
                        "service": p.get("service", {}).get("name"),
                    }
                )
            hosts.append({"ip": h.get("ip"), "hostnames": h.get("hostnames", []), "ports": ports})
        return {"engine": self.name, "targets": targets, "raw": result, "normalized": {"hosts": hosts}}
