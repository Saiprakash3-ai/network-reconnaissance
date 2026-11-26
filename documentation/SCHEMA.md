# Database Schema & Models

The starter uses SQLAlchemy 2.0 ORM models with SQLite by default (`sqlite+aiosqlite`). Models are structured for future PostgreSQL migration (use standard types, JSON fields, enums, timestamps, FK constraints).

## Entity Relationship Summary

```text
ScanJob 1---* Asset 1---* Port 1---* Service 1---* Finding
   \            \                               \
    \            *---* Evidence (optional finding link)
     *---* AuditEvent
     *---* Report
```

## Tables

### `scan_jobs`
| Field | Type | Notes |
|---|---|---|
| id | int PK | |
| profile | str | discovery/port_scan/service_enum/... |
| status | enum | queued/running/completed/failed/cancelled/timed_out |
| targets | JSON list | requested targets |
| options | JSON dict | scan options, scope decisions |
| scope_name | str? | engagement name |
| requested_by | str | local-user/cli/api |
| started_at/finished_at | datetime tz | |
| timeout_seconds | int | capped by settings |
| error | text? | |
| summary | JSON dict | engine summary, counts |
| raw_artifact_path | text? | optional primary artifact |
| created_at/updated_at | datetime tz | |

### `assets`
| Field | Type | Notes |
|---|---|---|
| id | int PK | |
| scan_job_id | FK scan_jobs | cascade delete |
| asset_key | str | unique per job; IP/hostname/cidr |
| asset_type | str | host/network/service |
| ip_address | str? | indexed |
| hostname | str? | |
| mac_address | str? | |
| os_name | str? | |
| os_accuracy | float? | |
| status | str | up/down/unknown |
| labels/details | JSON | raw/normalized metadata |

### `ports`
| Field | Type | Notes |
|---|---|---|
| id | int PK | |
| asset_id | FK assets | cascade delete |
| port | int | |
| protocol | str | tcp/udp |
| state | str | open/closed/filtered |
| details | JSON | |
| Unique | (asset_id, port, protocol) | |

### `services`
| Field | Type | Notes |
|---|---|---|
| id | int PK | |
| port_id | FK ports | cascade delete |
| name/product/version/extrainfo/tunnel | str? | fingerprint fields |
| confidence | float? | |
| banner | text? | captured banner/evidence |
| cpe | JSON list | CPE identifiers |
| http/tls/details | JSON | protocol-specific metadata |

### `findings`
| Field | Type | Notes |
|---|---|---|
| id | int PK | |
| scan_job_id | FK scan_jobs | |
| asset_id | FK assets? | nullable |
| service_id | FK services? | nullable |
| title/description | str/text | |
| state | enum | `suspected`, `detected`, `manually_validated`, `false_positive` |
| severity | enum | info/low/medium/high/critical |
| cvss_score | float? | |
| cve_ids/cwe_ids/references/mitre_attack | JSON lists | |
| epss_score | float? | |
| kev | bool | CISA KEV flag |
| evidence_summary/remediation | text? | |
| correlation | JSON | `IP -> Port -> Service -> Version -> Potential CVE -> Evidence -> Risk` |
| raw | JSON | raw source object |

### `evidence`
| Field | Type | Notes |
|---|---|---|
| id | int PK | |
| scan_job_id | FK scan_jobs | |
| finding_id | FK findings? | optional |
| kind | str | raw_output/pcap/log/screenshot/report |
| path | text | artifact path |
| content_type/sha256 | str? | integrity/typing |
| metadata | JSON | command, engine, parser info |

### `audit_events`
| Field | Type | Notes |
|---|---|---|
| id | int PK | |
| scan_job_id | FK? | |
| actor | str | user/system |
| action | str | e.g. `job.created`, `scope.denied` |
| target | text? | |
| outcome | str | ok/denied/error |
| details | JSON | structured audit detail |
| timestamps | datetime | |

### `reports`
| Field | Type | Notes |
|---|---|---|
| id | int PK | |
| scan_job_id | FK? | |
| format | str | html/pdf/json/csv |
| path | text | |
| summary | JSON | counts/metadata |

## State & Correlation Rules

- **Suspected**: indicator only (version match, script hint, passive intel). Not confirmed.
- **Detected**: tool produced direct evidence; still review.
- **Manually validated**: human-confirmed in authorized lab.
- **False positive**: reviewed and dismissed.

Every finding should aim to include correlation fields:

```json
{
  "ip": "192.168.56.40",
  "port": 445,
  "protocol": "tcp",
  "service": "smb",
  "version": "Samba 3.x",
  "potential_cves": ["CVE-XXXX-YYYY"],
  "evidence": ["lab/evidence/artifacts/job-1-services.xml.txt"],
  "risk": "high",
  "attack_mapping": ["T1046"]
}
```
