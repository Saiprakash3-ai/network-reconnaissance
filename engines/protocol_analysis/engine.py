from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engines.base import BaseEngine


class ProtocolAnalysisEngine(BaseEngine):
    name = "protocol_analysis"

    async def run(self, targets: list[str], options: dict[str, Any]) -> dict[str, Any]:
        pcap = options.get("pcap")
        if not pcap:
            return {"engine": self.name, "targets": targets, "raw": {"error": "No pcap provided"}, "normalized": {"error": "Provide options.pcap path to an existing PCAP file"}}
        pcap_path = Path(str(pcap))
        if not pcap_path.exists():
            return {"engine": self.name, "targets": targets, "raw": {"error": "pcap not found"}, "normalized": {"error": f"PCAP not found: {pcap_path}"}}

        tshark = self.ctx.settings.get("integrations", {}).get("tshark", {}).get("binary", "tshark")
        try:
            resolved = self.ctx.runner.resolve_binary(tshark)
        except Exception as e:
            return {"engine": self.name, "targets": targets, "raw": {"error": str(e)}, "normalized": {"error": str(e), "pcap": str(pcap_path)}}

        # Protocol hierarchy stats (-q -z io,phs)
        cmd = [resolved, "-r", str(pcap_path), "-q", "-z", "io,phs"]
        result = await self.ctx.runner.run(cmd, timeout=int(options.get("timeout", self.ctx.timeout)), artifact_name=f"{self.ctx.artifact_prefix}-tshark-phs.txt")
        # Conversations (tcp/udp)
        conv_cmd = [resolved, "-r", str(pcap_path), "-q", "-z", "conv,tcp", "-z", "conv,udp"]
        conv_result = await self.ctx.runner.run(conv_cmd, timeout=int(options.get("timeout", self.ctx.timeout)), artifact_name=f"{self.ctx.artifact_prefix}-tshark-conv.txt")

        return {
            "engine": self.name,
            "targets": targets,
            "raw": {"phs": result.stdout, "conv": conv_result.stdout, "stderr": result.stderr + "\n" + conv_result.stderr},
            "normalized": {
                "pcap": str(pcap_path),
                "protocol_hierarchy_text": result.stdout[:20000],
                "conversations_text": conv_result.stdout[:20000],
                "timed_out": result.timed_out or conv_result.timed_out,
            },
        }
