# Network Reconnaissance - Architectural Blueprint

## 1. Vision

**Network Reconnaissance** is a local-first, modular Advanced Network Reconnaissance & Intelligence Laboratory and Security Assessment Platform. It is not a thin wrapper around Nmap; it is an orchestration, normalization, evidence, intelligence, visualization, and reporting platform for **authorized** lab and assessment workflows.

### Primary Workflow

```text
Discover → Enumerate → Analyze → Validate → Visualize → Report
```

1. **Discover** - identify in-scope hosts, networks, DNS names, and passive attack-surface signals.
2. **Enumerate** - identify ports, services, versions, OS hints, protocol behaviors, and configs.
3. **Analyze** - parse raw outputs into normalized records; correlate assets/services/findings.
4. **Validate** - distinguish suspected, detected, and manually validated findings; preserve evidence.
5. **Visualize** - map assets, relationships, and risk indicators in an interactive topology.
6. **Report** - generate executive and technical outputs with remediation and scan diffs.

## 2. Design Principles

- **Safety by default**: private-lab-only, explicit allowlists, no arbitrary shell commands, no exploitation.
- **Evidence-first**: raw outputs are preserved alongside normalized data.
- **Deterministic core**: scanners/parsers are rule-based; no LLM required for scanning.
- **Modular engines**: each capability domain has an engine contract and integration adapters.
- **Local-first**: SQLite + filesystem artifacts; PostgreSQL migration path.
- **Extensible**: new integrations register through profiles and engine interfaces.

## 3. Component Architecture

```text
+---------------------------+        +------------------------------+
|      CLI (Typer/Rich)     |        |  React Dashboard (Cytoscape) |
+-------------+-------------+        +---------------+--------------+
              |                                      |
              +------------------+-------------------+
                                 |
                       +---------v----------+
                       |   FastAPI API      |
                       |  /api/jobs, scope  |
                       +---------+----------+
                                 |
                       +---------v----------+
                       | Orchestration      |
                       | - scope gate       |
                       | - job queue/state  |
                       | - audit logging    |
                       | - timeouts/cancel  |
                       +----+-----------+---+
                            |           |
            +---------------+           +------------------+
            |                                              |
   +--------v---------+                          +---------v---------+
   | Engines          |                          | Evidence/Reports  |
   | discovery/scan   |                          | raw XML/PCAP/logs |
   | service/osint    |                          | HTML/JSON/CSV/PDF |
   | vuln/pcap/map    |                          +---------+---------+
   +--------+---------+                                    |
            |                                              |
   +--------v---------+                          +---------v---------+
   | Integrations     |                          | SQLite/Postgres   |
   | nmap/nuclei/...  |                          | assets/findings   |
   | arg-list only    |                          | audit/jobs        |
   +------------------+                          +-------------------+
```

## 4. Module Map

### 4.1 Backend
- `backend/api` - REST endpoints for jobs, scope validation, assets, findings, reports.
- `backend/authentication` - local-user placeholder now; future token/session auth.
- `backend/authorization` - scope validator, policy enforcement, audit logging.
- `backend/orchestration` - job lifecycle, engine dispatch, concurrency/timeouts/cancellation.

### 4.2 Engines
- `host_discovery` - Nmap ping/ARP discovery, Scapy/ARP-scan adapters.
- `port_scanner` - TCP/UDP scan profiles, Naabu/Nmap adapters.
- `service_detection` - Nmap `-sV/-O`, banner collectors, HTTP/TLS/SMB/SNMP/SSH/FTP/DB probes.
- `dns_intelligence` - DNSx/Amass/Subfinder, record enumeration.
- `osint` - passive-first: crt.sh, WHOIS/RDAP, Shodan/Censys/SecurityTrails (API-keyed, optional).
- `protocol_analysis` - TShark/PCAP parsing and protocol stats.
- `vulnerability_assessment` - Nuclei/NSE/OpenVAS findings normalized as suspected/detected.
- `network_mapping` - graph model for Cytoscape.

### 4.3 Integrations
All integrations implement safe command execution:
- **No `shell=True`**.
- Argument arrays only.
- Binary allowlist from config.
- Timeouts and output size handling.
- Raw stdout/stderr/artifacts stored.

## 5. Data Model / Schema

### 5.1 Core Tables

#### `scan_jobs`
- `id`, `profile`, `status`, `targets`, `options`, `scope_name`, `requested_by`
- `started_at`, `finished_at`, `timeout_seconds`, `error`, `summary`, `raw_artifact_path`

#### `assets`
- `id`, `scan_job_id`, `asset_key`, `asset_type`, `ip_address`, `hostname`, `mac_address`
- `os_name`, `os_accuracy`, `status`, `labels`, `details`

#### `ports`
- `id`, `asset_id`, `port`, `protocol`, `state`, `details`
- Unique: `(asset_id, port, protocol)`

#### `services`
- `id`, `port_id`, `name`, `product`, `version`, `extrainfo`, `tunnel`
- `confidence`, `banner`, `cpe`, `http`, `tls`, `details`

#### `findings`
- `id`, `scan_job_id`, `asset_id`, `service_id`
- `title`, `description`, `state`, `severity`, `cvss_score`
- `cve_ids`, `cwe_ids`, `epss_score`, `kev`
- `evidence_summary`, `remediation`, `references`, `mitre_attack`
- `correlation` - `IP -> Port -> Service -> Version -> Potential CVE -> Evidence -> Risk`
- `raw`

#### `evidence`
- `id`, `scan_job_id`, `finding_id`, `kind`, `path`, `content_type`, `sha256`, `metadata`

#### `audit_events`
- `id`, `scan_job_id`, `actor`, `action`, `target`, `outcome`, `details`, timestamps

#### `reports`
- `id`, `scan_job_id`, `format`, `path`, `summary`, timestamps

### 5.2 Finding State Model

| State | Meaning | Rule |
|---|---|---|
| `suspected` | Indicator/version/CVE hint observed | **Never** treated as confirmed |
| `detected` | Tool/template produced direct detection evidence | Still requires review |
| `manually_validated` | Human validated in authorized lab | Can be reported as confirmed |
| `false_positive` | Reviewed and dismissed | Kept for audit/history |

## 6. Scope & Safety Validation Layer

### 6.1 Inputs
- `config/settings.yaml` - default app/scope behavior.
- `config/scope.example.yaml` - engagement record, allowlist, banned targets, approved profiles.
- Runtime target/profile from CLI/API.

### 6.2 Validation Rules
1. **Profile gate** - profile must be in `approved_scan_profiles` when configured.
2. **Target normalization** - parse IP, CIDR, or hostname.
3. **Banned targets** - explicit deny wins.
4. **CIDR breadth limit** - default min `/24` IPv4, `/64` IPv6.
5. **Private-lab-only** - public/non-local IPs denied by default.
6. **Explicit allowlist** - target/network must be inside allowed CIDRs/hosts.
7. **Hostname resolution check** - resolved IPs must also be in-scope.
8. **Audit** - every allow/deny decision logged.

### 6.3 Command Execution Safety
- Use `asyncio.create_subprocess_exec`.
- Never pass user input to a shell string.
- Build commands from allowlisted binaries and validated args.
- Enforce timeout and capture stdout/stderr.
- Store raw artifacts for traceability.

## 7. Scan Orchestration

### 7.1 Job Lifecycle
`queued → running → completed|failed|cancelled|timed_out`

### 7.2 Execution Flow
1. Receive scan request.
2. Validate profile and all targets.
3. Create `ScanJob` and audit event.
4. Acquire concurrency semaphore.
5. Run engines by profile.
6. Persist raw artifact paths and normalized entities.
7. Emit findings as `suspected` unless stronger evidence is manually validated.
8. Mark job status and write summary.

### 7.3 Profiles (Starter)
- `discovery` - host discovery.
- `port_scan` - discovery + port scan.
- `service_enum` - discovery + port scan + service detection.
- `full_lab_assessment` - starter equivalent to service enum; expands in later phases.

## 8. API Design

- `GET /api/health`
- `POST /api/scope/validate`
- `POST /api/jobs`
- `GET /api/jobs`
- `GET /api/jobs/{id}`
- `POST /api/jobs/{id}/cancel`

Planned:
- `/api/assets`, `/api/findings`, `/api/reports`, `/api/topology`, `/api/pcaps`, `/api/intel/cve`.

## 9. Frontend Blueprint

React + TypeScript + Tailwind + Cytoscape.js.

### Views
- **Dashboard** - recent jobs, status, risk summary.
- **Assets** - host inventory, filters by OS/service/port.
- **Topology** - Cytoscape graph: gateway/router/host/service/vuln nodes.
- **Findings** - evidence chain, state, CVE/CWE/ATT&CK mapping.
- **Reports** - generate/download, scan diffs.

## 10. Reporting Blueprint

Formats: HTML, PDF, JSON, CSV.

Report sections:
- Executive summary
- Scope and authorization record
- Host inventory and open ports
- OS/service details
- Vulnerability findings with CVE/CWE references
- Evidence and timestamps
- Risk classification
- Remediation recommendations
- Scan-to-scan comparison

## 11. Framework Mapping

| Framework | Usage |
|---|---|
| MITRE ATT&CK | Map recon techniques: T1595, T1595.001, T1595.002, T1595.003, T1046, T1040 |
| OWASP | Web/service assessment context and reporting categories |
| NIST SP 800-115 | Assessment methodology and evidence handling |
| CIS Controls | Defensive prioritization and remediation alignment |
| CVSS | Severity scoring |
| CWE/CVE | Weakness/vulnerability identifiers; CVE never auto-confirmed by version alone |

## 12. 10-Phase Implementation Roadmap

1. **Environment & lab prep** - repo layout, settings, scope config, setup scripts, sample lab. ✅ starter
2. **Recon/port scan engine** - Nmap discovery/scan, raw XML, normalized assets/ports. ✅ starter
3. **Service/OS/protocol enumeration** - service/OS fingerprinting, banners, NSE hooks. ✅ starter
4. **OSINT engine** - passive-first Amass/Subfinder/DNSx/crt.sh/WHOIS/RDAP. 🟡 scaffold
5. **Vulnerability engine** - Nuclei/NSE/OpenVAS optional, CVE/KEV/EPSS correlation. 🟡 scaffold
6. **Packet/PCAP analysis** - TShark ingest, protocol stats, DNS/HTTP/TLS metadata. 🟡 scaffold
7. **Network visualization** - Cytoscape topology, relationships, risk overlays. 🟡 scaffold
8. **Intelligence & CVE correlation** - evidence chains, risk scoring, ATT&CK mapping. 🟡 scaffold
9. **Reporting & scan history** - HTML/PDF/JSON/CSV, diffs, remediation tracking. 🟡 scaffold
10. **Validation, hardening & tests** - scope regression tests, integration tests, lab validation. 🟡 in progress

## 13. Local Lab Topology (Recommended)

Isolated virtual network only:
- **NR Controller** - WSL2/Ubuntu host running Network Reconnaissance.
- **Kali Linux** - optional operator VM.
- **Ubuntu Server** - SSH/HTTP/DNS/SNMP test services.
- **Windows Evaluation VM** - SMB/RDP/WinRM lab scenarios.
- **Metasploitable 2** - intentionally vulnerable target.
- **OWASP Juice Shop** - web app target.
- **Security Onion** (optional, later) - PCAP/NSM integration when resources allow.

## 14. Security Constraints Checklist

- [x] No arbitrary user-supplied shell commands
- [x] Explicit target allowlisting
- [x] CIDR and hostname scope validation
- [x] Private-lab-only mode by default
- [x] Rate limits/concurrency limits
- [x] Job cancellation and timeouts
- [x] Audit logs for every scan
- [x] Raw evidence artifacts preserved
- [x] No automatic exploitation / credential harvesting / unauthorized access
