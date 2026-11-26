# Licensing & Dependency Compatibility

## Project License

**Network Reconnaissance** is released under the **MIT License** (see `LICENSE`).

MIT is permissive, OSI-approved, and compatible with most open-source and proprietary downstream use, provided the copyright and license notice are preserved.

## Dependency / Integration Compatibility Notes

The core Python dependencies selected for the starter (FastAPI, Pydantic, SQLAlchemy, Typer, Rich, PyYAML, httpx, Jinja2, defusedxml, pytest, ruff) are permissively licensed or commonly MIT/BSD/Apache-compatible in typical Python distributions. Contributors should verify exact license metadata before release packaging (`pip show <pkg>` / package metadata).

External tools are **optional integrations** and are invoked as separate processes; they are not vendored into this repository. Their licenses apply to their own distribution/use:

| Tool | Typical License | Notes / Compatibility Guidance |
|---|---|---|
| Nmap | Nmap Public Source License (NPSL), based on GPLv2 with restrictions | Free for many uses but has special redistribution/commercial terms. Do **not** vendor Nmap binaries/source into MIT release without reviewing NPSL obligations. Invoke as external system binary. |
| Nmap NSE scripts | Mixed; many under Nmap/NPSL context | Review script provenance before copying into repo. |
| Naabu / Subfinder / DNSx / httpx (ProjectDiscovery) | MIT (verify per project/version) | Generally compatible as external tools; API/cloud services may have separate terms. |
| Nuclei | MIT (core) | Templates/community feeds may have separate terms; review template licenses before redistribution. |
| OWASP Amass | Apache 2.0 / project-specific (verify) | Generally compatible; confirm current upstream license before bundling. |
| testssl.sh | GPLv2 | GPL copyleft. Safe as optional external tool invocation; do not copy GPL code into MIT-licensed core without complying with GPL. |
| ssh-audit | MIT (verify current) | Generally compatible; verify before vendoring. |
| enum4linux-ng | GPLv3 | Copyleft. Use as optional external tool; avoid embedding code. |
| snmpwalk (Net-SNMP) | Mixed BSD-like/Copyleft components (verify) | Usually installed via OS packages; treat as external dependency. |
| TShark/Wireshark | GPLv2+ | Copyleft. External tool integration is fine; do not embed GPL code. |
| Greenbone/OpenVAS components | Mostly GPL/AGPL (component-dependent) | Strong copyleft/network-copyleft considerations. Keep optional/phased and external. Do not integrate code in ways that create unintended license obligations. |
| Scapy | GPLv2 | Copyleft. Optional dependency (`.[scapy]`) should be clearly labeled; avoid importing into core unless license implications are accepted. |
| Cytoscape.js | MIT | Compatible with frontend. |
| React/Tailwind/Vite/TS ecosystem | MIT/Apache/BSD (typical) | Verify lockfile/package metadata for release. |

## Project Policy

- **Core platform remains MIT.**
- **No GPL/AGPL code vendored into core.** Copyleft tools are integrated by external process invocation and documented as optional dependencies.
- **No proprietary/commercial-only dependencies required for core.** Shodan/Censys/SecurityTrails are optional, API-keyed, disabled by default, and isolated behind config.
- **No secrets in repo.** Use `.env.example`; never commit keys/tokens.
- **Contributors must document license** of any new dependency/integration in PRs and in this file.

## Release Checklist

- [ ] Verify all direct dependency licenses.
- [ ] Verify bundled frontend dependency licenses.
- [ ] Confirm no GPL/AGPL source copied into MIT core.
- [ ] Confirm optional copyleft tools are external-only and documented.
- [ ] Confirm no API keys/secrets/private lab data in git history.
- [ ] Include LICENSE, NOTICE (if needed), and third-party attribution updates.
