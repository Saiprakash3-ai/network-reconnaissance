# Phase Verification Guide

All commands assume you are in `network-reconnaissance/` with the virtualenv activated and using **authorized lab targets only**.

## Phase 1 - Environment & Lab Prep

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
nr init-db
nr scope-check 127.0.0.1 --profile discovery
nr scope-check 8.8.8.8 --profile discovery  # should be denied
```

Expected: DB created, local/private target allowed, public target denied.

## Phase 2 - Recon / Port Scan Engine

```bash
nr scan --profile discovery --target 127.0.0.1 --timeout 60
nr scan --profile port_scan --target 127.0.0.1 --top-ports 50 --timeout 120
nr jobs list
nr jobs show 1
```

Expected: jobs complete (if nmap installed), raw XML artifact in `lab/evidence/artifacts/`, normalized assets/ports in DB.

## Phase 3 - Service / OS / Protocol Enumeration

```bash
nr scan --profile service_enum --target 127.0.0.1 --ports 22,80,443 --timeout 180
# OS detection may require privileges and compatible target:
# sudo -E nr scan --profile service_enum --target 192.168.56.40 --os-detection --timeout 300
```

Expected: service records with product/version/CPE where detected; raw artifact preserved.

## Phase 4 - OSINT Engine (Scaffold)

Passive-first integrations (Amass/Subfinder/DNSx/crt.sh/WHOIS/RDAP) are scaffolded. Before implementing/enabling:
- confirm target is in scope/authorized,
- keep API keys in `.env`,
- no active scanning in passive mode.

Verification once implemented: `nr scan --profile osint_passive --target example.lab` returns only passive records and audit logs.

## Phase 5 - Vulnerability Engine (Scaffold)

Nuclei/NSE/OpenVAS integrations are planned. Findings must be created as `suspected` or `detected`, never auto-confirmed from version alone.

Verification once implemented: import mocked Nuclei/NSE output and confirm `state=suspected|detected`, correlation fields populated.

## Phase 6 - Packet / PCAP Analysis (Scaffold)

TShark/Wireshark integration planned. PCAPs stored as evidence.

Verification once implemented: ingest sample PCAP, get protocol stats and DNS/HTTP/TLS metadata records.

## Phase 7 - Network Visualization (Scaffold)

```bash
nr serve --host 127.0.0.1 --port 8000
# in another terminal
cd frontend && npm install && npm run dev
```

Expected: dashboard loads, topology endpoint `/api/jobs/{id}/topology` returns Cytoscape elements.

## Phase 8 - Intelligence & CVE Correlation (Scaffold)

Planned: CVE/CISA KEV/EPSS enrichment with explicit correlation chain and `suspected` state.

Verification once implemented: mocked service version produces `potential CVE` finding with evidence and risk, not confirmed exploitability.

## Phase 9 - Reporting & Scan History

```bash
nr report 1 --format json --format csv --format html
nr diff 1 2
```

Expected: reports in `reports/output/`; diff shows hosts/ports/findings added/removed.

## Phase 10 - Validation, Scope Hardening & Tests

```bash
pytest
./scripts/run_tests.sh
```

Expected: scope, DB, API, reporting tests pass. Add integration tests with mocked nmap XML before enabling real lab scans in CI.
