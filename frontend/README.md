# Network Reconnaissance Frontend

React + TypeScript + Tailwind CSS + Cytoscape.js dashboard scaffold.

## Planned Views

- **Dashboard**: job status, risk summary, recent scans
- **Assets**: host/port/service inventory
- **Topology**: Cytoscape graph of gateways, hosts, services, findings
- **Findings**: evidence chain, CVE/CWE/ATT&CK, suspected/detected/validated state
- **Reports**: generate/download HTML/PDF/JSON/CSV, scan diffs

## Dev

```bash
npm install
npm run dev
```

Configure API proxy to `http://127.0.0.1:8000` during development.
