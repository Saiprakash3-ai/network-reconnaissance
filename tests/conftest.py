from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _test_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("NR_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    # Ensure artifacts/audit go to temp dir
    monkeypatch.chdir(tmp_path)
    # Write minimal settings/scope for tests
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "settings.yaml").write_text(
        """
app:
  name: Network Reconnaissance Test
  private_lab_only: true
  max_concurrent_jobs: 1
  default_scan_timeout_seconds: 30
  max_scan_timeout_seconds: 60
  audit_log_path: ./audit.log
  artifact_dir: ./artifacts
database:
  url: sqlite+aiosqlite:///./test.db
scope:
  config_path: ./config/scope.yaml
  allow_public_targets: false
  allowed_cidrs: ["192.168.56.0/24", "127.0.0.0/8", "10.0.0.0/8"]
  allowed_hosts: ["localhost", "metasploitable.local"]
  banned_targets: ["0.0.0.0/0", "::/0", "169.254.169.254"]
integrations:
  nmap:
    enabled: true
    binary: nmap
""".strip(),
        encoding="utf-8",
    )
    (cfg / "scope.yaml").write_text(
        """
engagement:
  name: Test Lab
  id: test-001
  authorized_by: tester
policy:
  private_lab_only: true
  allow_public_targets: false
  require_explicit_allowlist: true
  max_cidr_prefix_v4: 24
  max_cidr_prefix_v6: 64
allowed_targets:
  cidrs: ["192.168.56.0/24", "127.0.0.0/8", "10.0.0.0/8", "::1/128"]
  hosts: ["localhost", "metasploitable.local"]
banned_targets: ["0.0.0.0/0", "::/0"]
approved_scan_profiles: ["discovery", "port_scan", "service_enum", "full_lab_assessment"]
""".strip(),
        encoding="utf-8",
    )
    # Reset cached DB engine/sessionmaker between tests.
    try:
        from database.session import reset_db_state

        reset_db_state()
    except Exception:
        pass
    yield
    try:
        from database.session import reset_db_state

        reset_db_state()
    except Exception:
        pass
