from __future__ import annotations

import asyncio
import socket
from typing import Any

from engines.base import BaseEngine


RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


async def _resolve(host: str, rdtype: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        if rdtype == "A":
            infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
            return sorted({i[4][0] for i in infos})
        if rdtype == "AAAA":
            infos = await loop.getaddrinfo(host, None, family=socket.AF_INET6)
            return sorted({i[4][0] for i in infos})
    except Exception:
        return []
    # For other record types, try `dig`/`nslookup` via no-shell? Avoid shell; use getaddrinfo limitations.
    # Fallback: simple socket-based checks not possible for MX/TXT; return empty unless tool available.
    return []


class DNSIntelligenceEngine(BaseEngine):
    name = "dns_intelligence"

    async def run(self, targets: list[str], options: dict[str, Any]) -> dict[str, Any]:
        records: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for target in targets:
            host = target.strip().lower().rstrip(".")
            host_records: dict[str, Any] = {"target": host, "records": {}}
            for rdtype in ["A", "AAAA"]:
                vals = await _resolve(host, rdtype)
                if vals:
                    host_records["records"][rdtype] = vals
            # Reverse DNS for A records
            rev = []
            for ip in host_records["records"].get("A", []):
                try:
                    name, _, _ = await asyncio.get_running_loop().run_in_executor(None, socket.gethostbyaddr, ip)
                    rev.append({"ip": ip, "ptr": name})
                except Exception:
                    pass
            if rev:
                host_records["reverse"] = rev
            if host_records["records"] or host_records.get("reverse"):
                records.append(host_records)
            else:
                errors.append({"target": host, "error": "No DNS records resolved via stdlib resolver"})
        return {
            "engine": self.name,
            "targets": targets,
            "raw": {"method": "stdlib-socket", "errors": errors},
            "normalized": {"dns": records, "errors": errors},
        }
