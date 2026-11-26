from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

import httpx

from engines.base import BaseEngine


async def _crtsh(domain: str, timeout: int) -> list[dict[str, Any]]:
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.get(url, params=params)
            if r.status_code != 200:
                return []
            data = r.json()
            out = []
            seen = set()
            for row in data if isinstance(data, list) else []:
                name = str(row.get("name_value", "")).strip().lower()
                for n in name.splitlines():
                    n = n.strip().lstrip("*.")
                    if n and n not in seen:
                        seen.add(n)
                        out.append({"name": n, "source": "crt.sh", "issuer": row.get("issuer_name")})
            return out[:200]
    except Exception:
        return []


async def _rdap(domain: str, timeout: int) -> dict[str, Any]:
    # RDAP domain lookup - public bootstrap endpoint; passive query.
    url = f"https://rdap.org/domain/{domain}"
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.get(url, headers={"Accept": "application/rdap+json, application/json"})
            if r.status_code != 200:
                return {"status": r.status_code}
            data = r.json()
            return {
                "ldhName": data.get("ldhName"),
                "handle": data.get("handle"),
                "status": data.get("status"),
                "events": data.get("events", [])[:10],
                "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")],
            }
    except Exception as e:
        return {"error": str(e)}


async def _whois(domain: str, timeout: int) -> str:
    # Simple WHOIS over port 43 to whois.iana.org then referral; best-effort, passive.
    def _sync() -> str:
        try:
            with socket.create_connection(("whois.iana.org", 43), timeout=min(timeout, 10)) as s:
                s.sendall((domain + "\r\n").encode())
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 20000:
                        break
            text = data.decode("utf-8", errors="replace")
            refer = None
            for line in text.splitlines():
                if line.lower().startswith("refer:"):
                    refer = line.split(":", 1)[1].strip()
                    break
            if refer:
                with socket.create_connection((refer, 43), timeout=min(timeout, 10)) as s:
                    s.sendall((domain + "\r\n").encode())
                    data = b""
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > 20000:
                            break
                text = data.decode("utf-8", errors="replace")
            return text[:20000]
        except Exception as e:
            return f"WHOIS error: {e}"
    return await asyncio.get_running_loop().run_in_executor(None, _sync)


class OSINTEngine(BaseEngine):
    name = "osint"

    async def run(self, targets: list[str], options: dict[str, Any]) -> dict[str, Any]:
        timeout = int(options.get("timeout", self.ctx.timeout))
        passive_only = bool(options.get("passive_only", True))
        results = []
        for target in targets:
            domain = target.strip().lower().rstrip(".")
            item: dict[str, Any] = {"target": domain, "passive_only": passive_only}
            # Passive sources
            item["crtsh"] = await _crtsh(domain, min(timeout, 20))
            item["rdap"] = await _rdap(domain, min(timeout, 20))
            if options.get("whois", True):
                item["whois"] = await _whois(domain, min(timeout, 15))
            # DNS basics via stdlib
            try:
                loop = asyncio.get_running_loop()
                infos = await loop.getaddrinfo(domain, None)
                item["resolved_ips"] = sorted({i[4][0] for i in infos})
            except Exception:
                item["resolved_ips"] = []
            results.append(item)

        return {
            "engine": self.name,
            "targets": targets,
            "raw": {"passive_only": passive_only, "count": len(results)},
            "normalized": {"osint": results},
        }
