from __future__ import annotations

from typing import Any

from backend.reporting.topology import build_topology
from database.session import SessionLocal
from engines.base import BaseEngine


class NetworkMappingEngine(BaseEngine):
    name = "network_mapping"

    async def run(self, targets: list[str], options: dict[str, Any]) -> dict[str, Any]:
        job_id = options.get("job_id")
        if job_id is None:
            return {"engine": self.name, "targets": targets, "raw": {}, "normalized": {"error": "job_id required"}}
        async with SessionLocal() as db:
            topo = await build_topology(db, int(job_id))
        return {"engine": self.name, "targets": targets, "raw": {}, "normalized": {"topology": topo}}
