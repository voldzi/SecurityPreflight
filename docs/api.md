# API Documentation

## Purpose

The SecurityPreflight API is the local control plane for the Web UI, CLI, and
worker. It manages projects, scan profiles, scan runs, findings, reports,
settings, and toolchain diagnostics.

## Source of Truth

The machine-readable OpenAPI specification is the binding contract:

```text
openapi/openapi.json
```

An optional YAML export, if present, is generated output only:

```text
openapi/openapi.yaml
```

## Base URLs

| Environment | URL |
| --- | --- |
| Local Docker Desktop | `http://localhost:8781` |
| Test | Not defined yet |
| Production | `https://stratos.zeleznalady.cz/sp/api` through nginx, mapped to internal `/api` paths |

## Authentication

`GET /health`, `GET /ready`, and `GET /api/v1/auth/status` are public. Other
`/api/v1/*` endpoints require bearer authentication when
`SECURITY_PREFLIGHT_AUTH_MODE` is `oidc` or `shared-token`.

If `SECURITY_PREFLIGHT_AUTH_MODE` is unset, development defaults to
`disabled`; `APP_ENV=production` defaults to `oidc` and fails closed until OIDC
issuer, client id, and audience are configured. For Keycloak, the JWKS URL is
derived from the issuer unless `SECURITY_PREFLIGHT_OIDC_JWKS_URL` is set
explicitly. OIDC tokens are validated with RS256/JWKS and checked against
configured viewer/operator roles.
`shared-token` is intended only as a controlled transition mode.

```bash
curl http://localhost:8781/api/v1/auth/status
curl -H "Authorization: Bearer $SECURITY_PREFLIGHT_TOKEN" \
  http://localhost:8781/api/v1/scan-profiles
```

## Versioning

The API uses path versioning:

```text
/api/v1/...
```

## Main Endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| GET | `/api/v1/auth/status` | Report API auth mode, OIDC public config, and RBAC roles without secrets |
| GET | `/api/v1/capabilities` | Report measured application capability readiness, maturity score, and open P0/P1 gaps without secrets |
| GET | `/api/v1/projects` | List registered local projects |
| POST | `/api/v1/projects` | Register a local project, validate its mounted path, and detect its stack |
| GET | `/api/v1/projects/{projectId}` | Get one registered project |
| PATCH | `/api/v1/projects/{projectId}` | Update project metadata and refresh stack detection when path changes |
| DELETE | `/api/v1/projects/{projectId}` | Delete a registered project |
| GET | `/api/v1/scan-profiles` | List built-in scan profiles |
| POST | `/api/v1/scans/plan` | Build a guarded scan execution plan without running scanners |
| POST | `/api/v1/scans/queue` | Queue an unblocked scan execution plan for worker execution |
| GET | `/api/v1/scans/runs` | List scan runs discovered under `REPORTS_PATH` |
| GET | `/api/v1/scans/runs/{scanRunId}` | Get redacted scan run detail, findings summary, steps, and evidence manifest |
| GET | `/api/v1/scans/runs/{scanRunId}/progress` | Get persisted live progress and recent scan events, with report-evidence fallback |
| PATCH | `/api/v1/scans/runs/{scanRunId}/findings/{findingId}/triage` | Update persisted finding triage state, owner/note/dates optional |
| GET | `/api/v1/scans/runs/{scanRunId}/report` | Read a generated markdown or JSON report artifact |
| POST | `/api/v1/reports/export` | Export a scan run report as base64 PDF or PPTX |
| POST | `/api/v1/reports/codex-remediation` | Export a redacted Markdown remediation package for Codex |
| GET | `/api/v1/akb/status` | Report AKB RAG configuration and storage boundaries without secrets |
| POST | `/api/v1/akb/ai/ask` | Ask AKB a cited, scan-run-scoped question |
| GET | `/api/v1/toolchain/doctor` | Check local toolchain availability |
| GET | `/api/v1/toolchain/requirements` | List scanner/evidence tools required for healthcare reference coverage |
| POST | `/api/v1/results/ingest` | Accept a redacted result envelope for central storage |

Scan run evidence manifests include booleans for `execution-result.json`,
`report.json`, `report.md`, `central-result-envelope.json`,
`defectdojo.sarif.json`, `central-telemetry-delivery.json`, and
`defectdojo-delivery.json`.

`GET /api/v1/capabilities` is the dashboard source for the capability audit.
It reports feature readiness from live configuration and product contracts such
as OIDC/RBAC, AKB RAG configuration, project autodiscovery, PostgreSQL/Redis
persistence, telemetry delivery settings, and the healthcare reference profile.
The response contains only signal IDs, booleans, counts, and statuses; it must
not include secrets, bearer tokens, raw scanner output, or configured token
values.

## Error Responses

All errors use the unified format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request data.",
    "details": [],
    "requestId": "req_abc123"
  }
}
```

## Usage Examples

### Health check

```bash
curl http://localhost:8781/health
```

### Scan profiles

```bash
curl http://localhost:8781/api/v1/scan-profiles
```

### Project registry

```bash
curl -X POST http://localhost:8781/api/v1/projects \
  -H 'content-type: application/json' \
  -d '{
    "name": "Hospital API",
    "path": "/workspace/projects/hospital-api",
    "publicUrl": "https://hospital-api.example.test",
    "dataClassification": "health-data",
    "owner": "Platform Security"
  }'

curl http://localhost:8781/api/v1/projects
curl http://localhost:8781/api/v1/projects/project_abc123
```

Project paths must be absolute container paths and, when configured roots such
as `PROJECTS_ROOT_CONTAINER` or `PROJECTS_ROOTS_CONTAINER` are set, must stay inside one of those mounts. The API validates
that the directory exists in the API container, detects the technology stack
from bounded file-name inspection, and persists the durable registry in
`REPORTS_PATH/projects.json`. Repository URLs are sanitized before persistence
so embedded credentials are stripped. A project can also store a `publicUrl`,
which the UI uses to prefill Web/API scans for profiles that need a running
web application or API target.

### Scan execution plan

```bash
curl -X POST http://localhost:8781/api/v1/scans/plan \
  -H 'content-type: application/json' \
  -d '{
    "profileId": "fast-local",
    "project": {
      "id": "local-demo",
      "name": "Local Demo",
      "path": "/path/to/project"
    }
  }'
```

`project.path` must be an absolute host path. CLI dry-run resolves relative
paths against the directory where the CLI command was invoked.

Web/API profiles such as `web-perimeter-safe`, `openapi-runtime-safe`,
`controlled-dast-local`, and `external-vps-safe` require an explicit `dast`
object:

```json
{
  "profileId": "web-perimeter-safe",
  "project": {
    "id": "hospital-api",
    "name": "Hospital API",
    "path": "/workspace/projects/hospital-api",
    "dataClassification": "health-data"
  },
  "dast": {
    "targetUrl": "https://staging.example.com",
    "allowedHosts": ["staging.example.com"],
    "allowActiveScan": true,
    "allowProductionTargets": false
  }
}
```

Guardrail failures, such as an active DAST target outside the allowlist, return
HTTP 200 with `blocked: true` and concrete `blockedReasons`. Invalid requests
and unknown scan profiles still use `ErrorResponse`.

### Queue a scan

```bash
curl -X POST http://localhost:8781/api/v1/scans/queue \
  -H 'content-type: application/json' \
  -d '{
    "profileId": "documentation-compliance",
    "project": {
      "id": "local-demo",
      "name": "Local Demo",
      "path": "/path/to/project"
    }
  }'
```

Only unblocked plans are queued. A blocked plan returns HTTP 409 with
`SCAN_PLAN_BLOCKED` and the guarded plan in `details`.

### Scan run history and report browser

```bash
curl http://localhost:8781/api/v1/scans/runs
curl http://localhost:8781/api/v1/scans/runs/scan_abc123
curl http://localhost:8781/api/v1/scans/runs/scan_abc123/progress
curl "http://localhost:8781/api/v1/scans/runs/scan_abc123/report?format=markdown"
```

Finding triage requires PostgreSQL persistence. Status values are `open`,
`accepted`, `false-positive`, `fixed`, and `suppressed`.
Each finding also carries `scope`:

- `application` means the issue belongs to the checked project, repository, or
  allowed web/API target.
- `platform` means the issue is a SecurityPreflight scanner/runtime readiness
  gap, such as missing Greenbone/OpenVAS, OpenSCAP, DefectDojo, external VPS, or
  scanner-runner configuration. Platform findings are reported for audit
  completeness but are not application vulnerabilities.

```bash
curl -X PATCH \
  http://localhost:8781/api/v1/scans/runs/scan_abc123/findings/finding_abc123/triage \
  -H 'content-type: application/json' \
  -d '{
    "status": "fixed",
    "note": "Patched and verified in staging."
  }'
```

The history endpoints are read-only over `REPORTS_PATH`. They expose redacted
report summaries, step status, finding summaries, and the evidence file
manifest. They do not expose raw scanner stdout/stderr command evidence.

### Export a PDF or PPTX report

```bash
curl -X POST http://localhost:8781/api/v1/reports/export \
  -H 'content-type: application/json' \
  -d '{
    "scanRunId": "scan_abc123",
    "format": "PDF",
    "locale": "cs"
  }'
```

The endpoint follows the STRATOS report export pattern: it returns a base64
payload with `fileName`, `mimeType`, `contentHash`, and `parametersJson`. The
export is generated from redacted report evidence only. It does not include raw
scanner stdout/stderr or source code.

### Export a Codex remediation package

```bash
curl -X POST http://localhost:8781/api/v1/reports/codex-remediation \
  -H 'content-type: application/json' \
  -d '{
    "scanRunId": "scan_abc123",
    "locale": "cs"
  }'
```

The endpoint returns a base64 encoded Markdown file with a focused Codex prompt,
prioritized findings, gate blockers, evidence file names, validation commands,
and safety boundaries. The payload is redacted and is intended to be attached to
a Codex remediation task together with the affected repository. It does not
replace human review for healthcare or other sensitive applications.

### AKB status and cited AI question

```bash
curl http://localhost:8781/api/v1/akb/status

curl -X POST http://localhost:8781/api/v1/akb/ai/ask \
  -H 'content-type: application/json' \
  -d '{
    "scanRunId": "scan_abc123",
    "question": "Shrn vysledek skenu pro zdravotnicky audit a uved citace."
  }'
```

AKB is the STRATOS document-grounded AI boundary. SecurityPreflight calls AKB
only from the backend and sends scan-run metadata, tags, data classification,
and `require_citations: true`. SecurityPreflight does not store AKB prompts,
answers, chunks, embeddings, or document text.

### Toolchain doctor

```bash
curl http://localhost:8781/api/v1/toolchain/doctor
```

The response includes overall `available`/`missing`/`error` counts and
healthcare-specific `healthcareAvailable`/`healthcareMissing`/`healthcareError`
counts. Optional tools such as controlled DAST/ZAP remain visible in the tool
list but do not make the healthcare summary fail when active DAST is disabled.

### Healthcare tool requirements

```bash
curl http://localhost:8781/api/v1/toolchain/requirements
```

The healthcare reference coverage requires runtime isolation, secret scanning,
SAST, SCA, SBOM, license, container, IaC, OpenAPI, controlled DAST readiness,
and central result export support.

### Central result envelope ingest

```bash
curl -X POST http://localhost:8781/api/v1/results/ingest \
  -H 'content-type: application/json' \
  -d @central-result-envelope.json
```

The envelope schema is `security-preflight.result.v1`. It must be redacted
(`evidence.redacted: true`) and is designed for central evidence storage
without uploading source code or raw scanner output.

## Client Generation

Client SDKs are generated from:

```text
openapi/openapi.json
```

## Validation

The OpenAPI specification is validated in the CI pipeline
(see `.github/workflows/ci.yml`).

## Developer Notes

- `openapi/openapi.json` is the binding API contract.
- YAML, if generated later, is export-only.
- Do not add undocumented endpoints.
- All errors use `ErrorResponse`.
- Active DAST controls and scanner safety decisions are represented in the scan
  execution plan contract before scanner execution is enabled.
- Central storage integrations should consume `CentralResultEnvelope` through
  the OpenAPI contract instead of scraping reports.
- STRATOS report exports should use `POST /api/v1/reports/export`; Codex
  remediation handoff should use `POST /api/v1/reports/codex-remediation`;
  document-grounded AI should use the AKB bridge, not a browser-side LLM call.
