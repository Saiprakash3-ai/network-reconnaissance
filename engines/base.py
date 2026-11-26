from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from integrations.base import SafeCommandRunner


@dataclass
class EngineContext:
    runner: SafeCommandRunner
    settings: dict[str, Any]
    timeout: int = 300
    artifact_prefix: str = "scan"


class BaseEngine:
    name = "base"

    def __init__(self, ctx: EngineContext):
        self.ctx = ctx

    async def run(self, targets: list[str], options: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError
