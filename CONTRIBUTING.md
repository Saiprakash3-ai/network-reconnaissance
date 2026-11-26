# Contributing to Network Reconnaissance

Thanks for contributing. This project is a local-first, authorized-lab security assessment platform. All contributions must preserve safety guardrails.

## Ground Rules

- **Authorized use only.** Do not add features for unauthorized scanning, exploitation, credential harvesting, or stealthy evasion of ownership/authorization controls.
- **No arbitrary shell execution.** Never use `shell=True`, string-concatenated shell commands, or unsanitized user input in commands. Use argument lists with `asyncio.create_subprocess_exec` or equivalent safe wrappers.
- **Preserve scope validation.** Any new scan/integration path must pass through scope validation and audit logging.
- **Preserve evidence.** Raw tool output should be stored alongside normalized records.
- **Mark findings responsibly.** Version/CVE matches are `suspected` unless directly detected and/or manually validated in an authorized lab.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
cp .env.example .env  # optional
nr init-db
pytest
```

## Project Layout

- `backend/` - API, CLI, orchestration, auth/authz, reporting.
- `engines/` - domain engines (discovery, scan, service detection, OSINT, vuln, PCAP, mapping).
- `integrations/` - safe wrappers/parsers for external tools.
- `database/` - SQLAlchemy models, migrations, repositories.
- `frontend/` - React + TypeScript + Tailwind + Cytoscape dashboard.
- `lab/` - sample networks, targets, scenarios, evidence.
- `tests/` - unit/integration tests.
- `documentation/` - architecture, schema, licensing, phase verification.

## Pull Requests

1. Create a focused branch.
2. Add/update tests for behavior changes.
3. Run `pytest` and ensure all tests pass.
4. Update docs/config examples when adding engines/integrations.
5. Describe security impact and scope/safety considerations in the PR.

## Adding an Integration

- Add wrapper in `integrations/<tool>/`.
- Use `SafeCommandRunner` or equivalent argument-list execution.
- Add config toggle in `config/settings.yaml` (disabled by default where appropriate).
- Parse output into normalized records; store raw artifact.
- Add tests with mocked command output (do not require external tools in unit tests).
- Document license/compatibility in `documentation/LICENSING.md`.

## Adding an Engine

- Implement `BaseEngine` in `engines/<domain>/engine.py`.
- Register in orchestration profile mapping only if safe and scoped.
- Emit normalized records and evidence metadata.
- Add tests and documentation.

## Code Style

- Python: type hints, small focused modules, explicit errors.
- Keep dependencies minimal; prefer stdlib for simple parsing/formatting.
- Avoid heavy runtime dependencies in core path.

## Reporting Security Issues

Do not open public issues for sensitive vulnerabilities. See [SECURITY.md](SECURITY.md).
