from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_yaml(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {p}")
    return data


def load_settings(config_path: str | Path | None = None) -> dict[str, Any]:
    default_path = Path(__file__).with_name("settings.yaml")
    path = Path(config_path) if config_path else default_path
    settings = load_yaml(path)

    env_db = os.getenv("NR_DATABASE_URL")
    if env_db:
        settings.setdefault("database", {})["url"] = env_db
    env_private = os.getenv("NR_PRIVATE_LAB_ONLY")
    if env_private is not None:
        settings.setdefault("app", {})["private_lab_only"] = env_private.lower() in {
            "1",
            "true",
            "yes",
        }
    env_scope = os.getenv("NR_SCOPE_CONFIG")
    if env_scope:
        settings.setdefault("scope", {})["config_path"] = env_scope
    return settings
