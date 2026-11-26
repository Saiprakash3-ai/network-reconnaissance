# Network Reconnaissance

**Network Reconnaissance** is an open-source, modular, local-first **Advanced Network Reconnaissance & Intelligence Laboratory** and Security Assessment Platform. It is designed for **authorized targets, isolated virtual lab networks, intentionally vulnerable machines, and local testing environments**—not as a wrapper around raw Nmap commands, but as an orchestration, normalization, evidence, intelligence, visualization, and reporting platform.

> **Safety first.** Private-lab-only by default. Explicit scope allowlisting, CIDR/hostname validation, rate/concurrency limits, timeouts, job cancellation, audit logging, and raw evidence preservation are enforced. **No arbitrary user-supplied shell commands. No automatic exploitation. No credential harvesting. No unauthorized access.**

## Demo

[▶ Terminal demo video](demo/network-reconnaissance-terminal.mp4)

## Core Workflow

```text
Discover → Enumerate → Analyze → Validate → Visualize → Report
```

## Repository Highlights

- **License:** MIT (`LICENSE`) with dependency/integration compatibility notes in `documentation/LICENSING.md`.
- **Safety policy:** `SECURITY.md` (responsible disclosure + authorized-use policy).
- **Contributor guide:** `CONTRIBUTING.md`.
- **Config templates:** `.env.example`, `config/settings.yaml`, `config/scope.example.yaml`.
- **Docs:** `documentation/ARCHITECTURE.md`, `documentation/SCHEMA.md`, `documentation/PHASE_VERIFICATION.md`, `documentation/LICENSING.md`.
- **Tests:** `pytest` unit/integration smoke tests for scope, DB, API, reporting.

## Functional Domains & Status

| Domain | Modules | Status | Key Tools/Integrations |
|---|---|---:|---|
| A. Advanced recon / discovery | A1-A7 | Starter | Nmap, ARP-scan/Scapy hooks, DNS/OSINT scaffolds |
| B. Port scan & service enumeration | B1-B12 | Starter | Nmap TCP scan, `-sV`, optional `-O`, NSE/script capture, raw XML preserved |
| C. Vulnerability assessment | C1-C7 | Starter | Heuristic suspected findings + optional Nuclei wrapper; CVE/CWE/CVSS/KEV/EPSS correlation fields; `suspected/detected/manually_validated` states |
| D. Packet analysis & intelligence | D1-D4 | Starter | TShark PCAP ingestion (`options.pcap`) with protocol hierarchy/conversation artifacts |
| E. OSINT & external attack surface | E1-E10 | Starter | Passive crt.sh/RDAP/WHOIS/DNS; Amass/Subfinder/DNSx/API connectors pluggable/config-gated |
| F. Protocol/infrastructure assessment | F1-F14 | Scaffold | ARP/DNS/DHCP/ICMP/TCP/UDP/HTTP/HTTPS/SSH/SMB/SNMP/LDAP/RDP/FTP/SMTP/NTP |
| G. Network visualization | G1-G7 | Starter | Topology endpoint + network mapping engine + Cytoscape.js frontend graph |
| H. Automated reporting | H1-H4 | Starter | JSON/CSV/HTML/PDF reports, scan diff, evidence/timestamps |

## Architecture

See [`documentation/ARCHITECTURE.md`](documentation/ARCHITECTURE.md) for the complete blueprint.

```text
CLI / React Dashboard
        │
    FastAPI API
        │
  Orchestration + Scope Gate + Audit
        │
 ┌──────┴──────────────────────────────┐
 │ Engines                             │
 │ discovery | port scan | service     │
 │ dns/osint | vuln | pcap | mapping   │
 └──────┬──────────────────────────────┘
        │
 Safe Integrations (arg-list only, no shell)
        │
 SQLite/PostgreSQL-ready DB + raw evidence artifacts + reports
```

## Directory Layout

```text
network-reconnaissance/
  backend/                 # FastAPI app, CLI, auth/authz, orchestration, reporting
  engines/                 # Domain engines
  integrations/            # Safe external tool wrappers/parsers
  database/                # SQLAlchemy models, migrations, repositories
  frontend/                # React + TS + Tailwind + Cytoscape scaffold
  lab/                     # networks, targets, scenarios, evidence
  reports/                 # generated report output
  tests/                   # pytest tests
  documentation/           # architecture, schema, licensing, phase verification
  config/                  # settings and scope config
  scripts/                 # setup/dev/test scripts
  LICENSE
  CONTRIBUTING.md
  SECURITY.md
  .env.example
  README.md
```

## Safety & Scope Guardrails (Mandatory)

- **No arbitrary user-supplied shell commands.** All integrations use argument lists (`asyncio.create_subprocess_exec`), never `shell=True`.
- **Explicit target allowlisting** and CIDR/hostname validation (`config/scope.example.yaml`).
- **Private-lab-only mode by default.** Public targets denied unless explicitly and deliberately enabled with scope changes.
- **Rate/concurrency limits, job cancellation, and timeouts.**
- **Audit logs** for every scan/action (`lab/evidence/audit.log`).
- **Raw evidence preserved** alongside normalized records (`lab/evidence/artifacts/`).
- **No automatic exploitation, no credential harvesting, no unauthorized access.**
- **Finding states:** `suspected`, `detected`, `manually_validated`, `false_positive`. A version match alone is never a confirmed vulnerability.

## Open-Source Licensing & Compatibility

- Project license: **MIT** (`LICENSE`).
- Core dependencies are permissive and local-first.
- External tools are invoked as separate binaries; copyleft tools (e.g., testssl.sh GPLv2, enum4linux-ng GPLv3, TShark/Wireshark GPLv2+, Greenbone components GPL/AGPL depending on component, Scapy GPLv2 optional) must remain **external/optional** and not vendored into MIT core.
- No API keys/secrets required for core. Optional OSINT APIs are config-isolated and disabled by default.
- See [`documentation/LICENSING.md`](documentation/LICENSING.md) for details.

## Quick Start (Windows 11 + Ubuntu WSL2 / Linux)

### 1. Prerequisites

- Python 3.11+
- Nmap installed and on PATH (`sudo apt install nmap`)
- Optional: Node.js 20+ for frontend
- Recommended: isolated virtual lab network (VirtualBox/VMware host-only/internal)

### 2. Setup

```bash
cd network-reconnaissance
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
cp .env.example .env
cp config/scope.example.yaml config/scope.local.yaml  # optional
# optional: export NR_SCOPE_CONFIG=./config/scope.local.yaml
```

Or use the script:

```bash
./scripts/setup_wsl.sh
```

### 3. Initialize DB

```bash
nr init-db
```

### 4. Validate Scope (Safety Check)

```bash
nr scope-check 127.0.0.1 192.168.56.10 --profile discovery
nr scope-check 8.8.8.8 --profile discovery   # denied in private-lab-only mode
```

### 5. Run Scans (Authorized Lab Targets Only)

```bash
# Discovery
nr scan --profile discovery --target 127.0.0.1 --timeout 60

# Port scan
nr scan --profile port_scan --target 127.0.0.1 --top-ports 100 --timeout 120

# Service enumeration
nr scan --profile service_enum --target 127.0.0.1 --ports 22,80,443 --timeout 180
```

### 6. Inspect Jobs, Reports, Diffs

```bash
nr jobs list
nr jobs show 1
nr report 1 --format json --format csv --format html
nr diff 1 2
```

### 7. Run API / Dashboard Backend

```bash
nr serve --host 127.0.0.1 --port 8000
# API docs: http://127.0.0.1:8000/docs
```

### 8. Run Frontend (Optional)

```bash
cd frontend
npm install
npm run dev
# http://127.0.0.1:5173 (proxies /api to 127.0.0.1:8000)
```

## CLI Reference

```bash
nr init-db
nr scope-check <targets...> [--profile PROFILE]
nr scan --profile discovery|port_scan|service_enum|full_lab_assessment --target <target> [--target ...] [--ports 22,80] [--top-ports 100] [--os-detection] [--timeout 300]
nr jobs list [--limit 20]
nr jobs show <job_id>
nr report <job_id> --format json --format csv --format html
nr diff <base_job_id> <compare_job_id>
nr serve [--host 127.0.0.1] [--port 8000] [--reload]
```

## API Examples

```bash
curl -s http://127.0.0.1:8000/api/health

curl -s -X POST http://127.0.0.1:8000/api/scope/validate \
  -H 'Content-Type: application/json' \
  -d '{"profile":"discovery","targets":["192.168.56.10","8.8.8.8"]}'

curl -s -X POST http://127.0.0.1:8000/api/jobs \
  -H 'Content-Type: application/json' \
  -d '{"profile":"discovery","targets":["127.0.0.1"],"options":{"timeout":60}}'

curl -s http://127.0.0.1:8000/api/jobs/1
curl -s http://127.0.0.1:8000/api/jobs/1/topology
curl -s -X POST http://127.0.0.1:8000/api/jobs/1/report -H 'Content-Type: application/json' -d '{"formats":["json","html"]}'
```

## Configuration

- `config/settings.yaml` - app/db/limits/integration toggles.
- `config/scope.example.yaml` - engagement, authorization, allowlists, banned targets, approved profiles.
- `.env.example` - environment variable template.

Key env vars:

- `NR_DATABASE_URL` - override DB URL (default SQLite).
- `NR_PRIVATE_LAB_ONLY=true|false` - keep `true` by default.
- `NR_SCOPE_CONFIG` - scope config path.

## Database Schema / Models

See [`documentation/SCHEMA.md`](documentation/SCHEMA.md). Core entities:

- `ScanJob` - profile, targets, status, timing, summary, raw artifact path.
- `Asset` - host/network identity, IP/MAC/hostname/OS.
- `Port` - port/protocol/state.
- `Service` - name/product/version/CPE/banner/TLS/HTTP details.
- `Finding` - suspected/detected/manually validated/false_positive, severity, CVE/CWE/CVSS/EPSS/KEV, MITRE ATT&CK, correlation.
- `Evidence` - raw outputs, PCAPs, logs, metadata.
- `AuditEvent` - who did what, when, against which target, outcome.
- `Report` - generated report artifacts.

## Framework Mapping

| Framework | Mapping |
|---|---|
| MITRE ATT&CK | `T1595`, `T1595.001`, `T1595.002`, `T1595.003`, `T1046`, `T1040` |
| OWASP | Web/service assessment context and reporting categories |
| NIST SP 800-115 | Assessment methodology and evidence handling |
| CIS Controls | Defensive prioritization and remediation alignment |
| CVSS / CWE / CVE | Severity scoring, weakness/vulnerability identifiers; CVE never auto-confirmed by version alone |

## 10-Phase Roadmap & Verification

See [`documentation/PHASE_VERIFICATION.md`](documentation/PHASE_VERIFICATION.md) for commands and expected outputs.

1. **Environment & lab prep** - settings, scope, DB, scripts. *(starter)*
2. **Recon/port scan engine** - Nmap discovery/scan, raw XML, normalized assets/ports. *(starter)*
3. **Service/OS/protocol enumeration** - `-sV`, optional `-O`, banners/scripts. *(starter)*
4. **OSINT engine** - passive-first Amass/Subfinder/DNSx/crt.sh/WHOIS/RDAP. *(scaffold)*
5. **Vulnerability engine** - Nuclei/NSE/OpenVAS, CVE/KEV/EPSS correlation. *(scaffold)*
6. **Packet/PCAP analysis** - TShark/Wireshark ingestion, protocol stats. *(scaffold)*
7. **Network visualization** - Cytoscape topology, relationships, risk overlays. *(starter scaffold)*
8. **Intelligence & CVE correlation** - evidence chains, risk scoring, ATT&CK mapping. *(scaffold)*
9. **Reporting & scan history** - HTML/JSON/CSV, diffs; PDF phased. *(starter)*
10. **Validation, scope hardening & tests** - unit/integration tests, CI, lab validation. *(in progress)*

## Lab Environment

Sample lab files are in `lab/`: `networks/lab-network.yaml`, `targets/targets.yaml`, `scenarios/scenarios.yaml`. Recommended isolated VMs: NR controller, Kali, Ubuntu Server, Windows evaluation, Metasploitable 2, OWASP Juice Shop, optional Security Onion.

## Testing

```bash
pytest
# or
./scripts/run_tests.sh
```

Current tests cover scope validation, DB initialization/repository behavior, API smoke/safety checks, report generation, topology, and scan diffs. External tool integration tests should mock command output.

## Development Notes

- Designed for **Windows 11 + Ubuntu WSL2, 16 GB RAM, no dedicated GPU**.
- Core engine is deterministic; no LLM required for scanning. Optional local Ollama integration may be added later for report summarization only.
- Keep heavy components (Greenbone/OpenVAS, Security Onion) optional/phased.
- Preserve raw tool output and evidence artifacts.

## Legal / Ethical Use

Use only on systems you own or have explicit written authorization to assess. The default configuration is intentionally restrictive. Do not disable safeguards for unauthorized targets.
