from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app import create_app


def test_health():
    app = create_app()
    with TestClient(app) as client:
        res = client.get("/api/health")
        assert res.status_code == 200
        assert res.json()["status"] == "ok"


def test_scope_validate_endpoint():
    app = create_app()
    with TestClient(app) as client:
        res = client.post("/api/scope/validate", json={"targets": ["192.168.56.10", "8.8.8.8"], "profile": "discovery"})
        assert res.status_code == 200
        data = res.json()
        decisions = {d["normalized_target"]: d["allowed"] for d in data["decisions"]}
        assert decisions["192.168.56.10"] is True
        assert decisions["8.8.8.8"] is False


def test_create_job_rejects_out_of_scope():
    app = create_app()
    with TestClient(app) as client:
        res = client.post("/api/jobs", json={"profile": "discovery", "targets": ["8.8.8.8"]})
        assert res.status_code == 403
