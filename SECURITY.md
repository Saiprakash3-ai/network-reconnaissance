# Security Policy

## Authorized Use

Network Reconnaissance is intended **only** for:

- systems you own,
- explicitly authorized assessments,
- isolated virtual lab networks,
- intentionally vulnerable machines,
- local testing environments.

**Do not use this project against unauthorized targets.** The default configuration enforces private-lab-only scope and explicit allowlisting. Disabling safeguards for unauthorized use is misuse of the project.

## Safety Guardrails

The project includes these mandatory controls:

- No arbitrary user-supplied shell commands.
- `subprocess` argument lists only (`shell=False` / `create_subprocess_exec`).
- Explicit target allowlisting and CIDR/hostname scope validation.
- Private-lab-only mode by default.
- Rate/concurrency limits, timeouts, and job cancellation.
- Audit logs for scans/actions.
- Raw evidence artifact preservation.
- No automatic exploitation, no credential harvesting, no unauthorized access.

## Reporting a Vulnerability

Please report security vulnerabilities responsibly.

- **Preferred:** Use GitHub private vulnerability reporting/security advisories if enabled for the repository.
- **If private reporting is unavailable:** Contact the maintainers through a private channel listed in the repository profile, or open a minimal public issue **without exploit details** requesting a secure contact method.

Include:

- affected component/file,
- impact and threat model,
- reproduction steps in an authorized lab,
- suggested remediation,
- whether the issue affects scope validation, command execution, audit logging, or evidence handling.

## Disclosure Expectations

- We aim to acknowledge reports within 7 days.
- We will work with reporters on a fix and coordinated disclosure timeline.
- Do not publish exploit details before a fix or mitigation is available.
- Do not include real credentials, private target data, or unauthorized scan results in reports.

## Out of Scope / Prohibited Contributions

- Exploitation payloads or automatic exploit chains.
- Credential harvesting/bruteforce automation.
- Evasion features intended to bypass authorization/scope controls.
- Features that execute arbitrary user shell commands.
