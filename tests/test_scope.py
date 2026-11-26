from __future__ import annotations

import pytest

from backend.authorization.scope import ScopeValidator, ScopeViolation
from config.loader import load_settings


def test_private_ip_allowed():
    settings = load_settings("config/settings.yaml")
    v = ScopeValidator.from_settings(settings)
    d = v.validate("192.168.56.10")
    assert d.allowed
    assert d.target_type == "ip"


def test_public_ip_denied_in_private_lab_mode():
    settings = load_settings("config/settings.yaml")
    v = ScopeValidator.from_settings(settings)
    d = v.evaluate("8.8.8.8")
    assert not d.allowed
    assert "outside" in d.reason.lower() or "private" in d.reason.lower()


def test_banned_target_denied():
    settings = load_settings("config/settings.yaml")
    v = ScopeValidator.from_settings(settings)
    d = v.evaluate("0.0.0.0/0")
    assert not d.allowed


def test_broad_cidr_denied():
    settings = load_settings("config/settings.yaml")
    v = ScopeValidator.from_settings(settings)
    d = v.evaluate("192.168.0.0/16")
    assert not d.allowed
    assert "too broad" in d.reason.lower()


def test_hostname_allowlist():
    settings = load_settings("config/settings.yaml")
    v = ScopeValidator.from_settings(settings)
    # metasploitable.local may not resolve; in private lab unresolved is denied by default. localhost should resolve.
    d = v.evaluate("localhost")
    assert d.allowed


def test_unapproved_profile_denied():
    settings = load_settings("config/settings.yaml")
    v = ScopeValidator.from_settings(settings)
    with pytest.raises(ScopeViolation):
        v.validate_profile("exploit_everything")


def test_validate_many_raises_on_bad_target():
    settings = load_settings("config/settings.yaml")
    v = ScopeValidator.from_settings(settings)
    with pytest.raises(ScopeViolation):
        v.validate_many(["192.168.56.10", "1.1.1.1"])
