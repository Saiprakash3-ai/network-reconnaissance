from __future__ import annotations

import pytest

from database.repositories.scans import ScanRepository
from database.session import SessionLocal, init_db


@pytest.mark.asyncio
async def test_init_db_and_create_job():
    await init_db()
    async with SessionLocal() as db:
        repo = ScanRepository(db)
        job = await repo.create_job(
            profile="discovery",
            targets=["192.168.56.10"],
            options={"timeout": 30},
            scope_name="Test Lab",
            requested_by="pytest",
            timeout_seconds=30,
        )
        assert job.id > 0
        fetched = await repo.get_job(job.id)
        assert fetched is not None
        assert fetched.profile == "discovery"
        assert fetched.targets == ["192.168.56.10"]
