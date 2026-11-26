from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from config.loader import load_yaml

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$")


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    normalized_target: str
    target_type: str
    resolved_ips: list[str] = field(default_factory=list)


class ScopeViolation(ValueError):
    pass


class ScopeValidator:
    def __init__(self, settings: dict[str, Any], scope_config: dict[str, Any] | None = None):
        self.settings = settings
        self.scope_config = scope_config or {}
        app = settings.get("app", {})
        scope = settings.get("scope", {})
        policy = self.scope_config.get("policy", {})

        self.private_lab_only = bool(
            policy.get("private_lab_only", scope.get("private_lab_only", app.get("private_lab_only", True)))
        )
        self.allow_public_targets = bool(
            policy.get("allow_public_targets", scope.get("allow_public_targets", False))
        )
        self.require_explicit_allowlist = bool(policy.get("require_explicit_allowlist", True))
        self.max_cidr_prefix_v4 = int(policy.get("max_cidr_prefix_v4", 24))
        self.max_cidr_prefix_v6 = int(policy.get("max_cidr_prefix_v6", 64))

        allowed_targets = self.scope_config.get("allowed_targets", {})
        self.allowed_cidrs = self._parse_networks(
            list(scope.get("allowed_cidrs", [])) + list(allowed_targets.get("cidrs", []))
        )
        self.allowed_hosts = {
            h.strip().lower().rstrip(".")
            for h in list(scope.get("allowed_hosts", [])) + list(allowed_targets.get("hosts", []))
            if isinstance(h, str) and h.strip()
        }
        self.banned_targets = {
            t.strip().lower()
            for t in list(scope.get("banned_targets", [])) + list(self.scope_config.get("banned_targets", []))
            if isinstance(t, str) and t.strip()
        }
        self.approved_scan_profiles = set(self.scope_config.get("approved_scan_profiles", []))

    @staticmethod
    def _parse_networks(values: list[str]) -> list[ipaddress._BaseNetwork]:
        networks: list[ipaddress._BaseNetwork] = []
        for value in values:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
        return networks

    @classmethod
    def from_settings(cls, settings: dict[str, Any]) -> "ScopeValidator":
        scope_path = settings.get("scope", {}).get("config_path", "./config/scope.example.yaml")
        p = Path(scope_path)
        if not p.is_absolute():
            # Resolve relative to repo root if present
            candidate = Path.cwd() / p
            p = candidate if candidate.exists() else Path(__file__).resolve().parents[2] / p
        scope_config = load_yaml(p)
        return cls(settings=settings, scope_config=scope_config)

    def validate_profile(self, profile: str) -> None:
        if self.approved_scan_profiles and profile not in self.approved_scan_profiles:
            raise ScopeViolation(
                f"Scan profile '{profile}' is not in approved_scan_profiles: {sorted(self.approved_scan_profiles)}"
            )

    def _is_banned(self, target: str) -> bool:
        return target.lower() in self.banned_targets

    def _is_private_or_local(self, ip: ipaddress._BaseAddress) -> bool:
        return bool(
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
        )

    def _network_allowed(self, network: ipaddress._BaseNetwork) -> bool:
        if self._is_banned(str(network)):
            return False
        if self.private_lab_only and not self.allow_public_targets:
            # Every address in network must be private/local.
            if not all(self._is_private_or_local(ip) for ip in [network.network_address, network.broadcast_address]):
                return False
        if self.require_explicit_allowlist:
            return any(network.subnet_of(allowed) for allowed in self.allowed_cidrs)
        if self.allowed_cidrs:
            return any(network.subnet_of(allowed) for allowed in self.allowed_cidrs)
        return self.private_lab_only

    def _ip_allowed(self, ip: ipaddress._BaseAddress) -> bool:
        if self._is_banned(str(ip)):
            return False
        if self.private_lab_only and not self.allow_public_targets and not self._is_private_or_local(ip):
            return False
        if self.require_explicit_allowlist or self.allowed_cidrs:
            return any(ip in net for net in self.allowed_cidrs)
        return self.private_lab_only

    def _resolve_host(self, host: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return []
        ips: list[str] = []
        for info in infos:
            sockaddr = info[4]
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        return ips

    def evaluate(self, target: str) -> ScopeDecision:
        raw = target.strip()
        if not raw:
            return ScopeDecision(False, "Empty target", raw, "invalid")
        normalized = raw.lower().rstrip(".")
        if self._is_banned(normalized) or self._is_banned(raw):
            return ScopeDecision(False, "Target is explicitly banned", raw, "banned")

        # CIDR/network
        if "/" in raw:
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                return ScopeDecision(False, "Invalid CIDR/network target", raw, "invalid")
            if net.version == 4 and net.prefixlen < self.max_cidr_prefix_v4:
                return ScopeDecision(False, f"IPv4 CIDR too broad; minimum /{self.max_cidr_prefix_v4}", str(net), "network")
            if net.version == 6 and net.prefixlen < self.max_cidr_prefix_v6:
                return ScopeDecision(False, f"IPv6 CIDR too broad; minimum /{self.max_cidr_prefix_v6}", str(net), "network")
            if self._network_allowed(net):
                return ScopeDecision(True, "Network target within authorized scope", str(net), "network")
            return ScopeDecision(False, "Network target outside authorized scope", str(net), "network")

        # IP address
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            ip = None
        if ip is not None:
            if self._ip_allowed(ip):
                return ScopeDecision(True, "IP target within authorized scope", str(ip), "ip", [str(ip)])
            return ScopeDecision(False, "IP target outside authorized scope", str(ip), "ip", [str(ip)])

        # Hostname
        if not HOST_RE.match(normalized):
            return ScopeDecision(False, "Invalid hostname", raw, "invalid")
        if self.require_explicit_allowlist and self.allowed_hosts and normalized not in self.allowed_hosts:
            return ScopeDecision(False, "Hostname not in explicit allowlist", normalized, "hostname")
        resolved = self._resolve_host(normalized)
        if self.private_lab_only and not self.allow_public_targets:
            if not resolved:
                # In private lab mode, unresolved hostnames are denied unless explicitly allowed and resolvable.
                if normalized in self.allowed_hosts and not self.require_explicit_allowlist:
                    return ScopeDecision(True, "Allowed hostname (unresolved)", normalized, "hostname")
                return ScopeDecision(False, "Hostname did not resolve; refusing unresolvable target in private-lab mode", normalized, "hostname")
            bad = [ip for ip in resolved if not self._ip_allowed(ipaddress.ip_address(ip))]
            if bad:
                return ScopeDecision(False, f"Hostname resolves outside authorized scope: {bad}", normalized, "hostname", resolved)
        elif resolved:
            bad = [ip for ip in resolved if not self._ip_allowed(ipaddress.ip_address(ip))]
            if bad and (self.require_explicit_allowlist or self.allowed_cidrs):
                return ScopeDecision(False, f"Hostname resolves outside authorized scope: {bad}", normalized, "hostname", resolved)
        if normalized in self.allowed_hosts or not self.require_explicit_allowlist:
            return ScopeDecision(True, "Hostname within authorized scope", normalized, "hostname", resolved)
        return ScopeDecision(False, "Hostname outside authorized scope", normalized, "hostname", resolved)

    def validate(self, target: str) -> ScopeDecision:
        decision = self.evaluate(target)
        if not decision.allowed:
            raise ScopeViolation(decision.reason + f": {target}")
        return decision

    def validate_many(self, targets: list[str]) -> list[ScopeDecision]:
        return [self.validate(t) for t in targets]
