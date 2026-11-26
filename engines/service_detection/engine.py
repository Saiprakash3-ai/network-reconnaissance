from __future__ import annotations

from typing import Any

from engines.base import BaseEngine
from integrations.nmap.scanner import NmapScanner


class ServiceDetectionEngine(BaseEngine):
    name = "service_detection"

    async def run(self, targets: list[str], options: dict[str, Any]) -> dict[str, Any]:
        scanner = NmapScanner(self.ctx.runner, binary=self.ctx.settings.get("integrations", {}).get("nmap", {}).get("binary", "nmap"))
        result = await scanner.service_detection(
            targets=targets,
            ports=options.get("ports"),
            os_detection=bool(options.get("os_detection", False)),
            timeout=int(options.get("timeout", self.ctx.timeout)),
            artifact_name=f"{self.ctx.artifact_prefix}-services.xml.txt",
        )
        hosts = []
        for h in result["parsed"].get("hosts", []):
            services = []
            for p in h.get("ports", []):
                svc = p.get("service", {})
                services.append(
                    {
                        "port": p.get("port"),
                        "protocol": p.get("protocol"),
                        "state": p.get("state"),
                        "service": svc.get("name"),
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "extrainfo": svc.get("extrainfo"),
                        "cpes": svc.get("cpes", []),
                        "scripts": p.get("scripts", []),
                    }
                )
            os_match = (h.get("os_matches") or [{}])[0]
            hosts.append(
                {
                    "ip": h.get("ip"),
                    "mac": h.get("mac"),
                    "hostnames": [x.get("name") for x in h.get("hostnames", []) if x.get("name")],
                    "os": {"name": os_match.get("name"), "accuracy": os_match.get("accuracy")},
                    "services": services,
                    "host_scripts": h.get("host_scripts", []),
                }
            )
        return {"engine": self.name, "targets": targets, "raw": result, "normalized": {"hosts": hosts}}
