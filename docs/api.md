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
| Production | Not applicable for MVP |

## Authentication

MVP uses no remote authentication because the API is local-only and intended to
bind to localhost. Remote access, team use, or central synchronization requires
authentication and authorization before enablement.

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
| GET | `/api/v1/projects` | List registered local projects |
| GET | `/api/v1/scan-profiles` | List built-in scan profiles |
| POST | `/api/v1/scans/plan` | Build a guarded scan execution plan without running scanners |
| POST | `/api/v1/scans/queue` | Queue an unblocked scan execution plan for worker execution |
| GET | `/api/v1/scans/runs` | List scan runs discovered under `REPORTS_PATH` |
| GET | `/api/v1/scans/runs/{scanRunId}` | Get redacted scan run detail, findings summary, steps, and evidence manifest |
| GET | `/api/v1/scans/runs/{scanRunId}/report` | Read a generated markdown or JSON report artifact |
| POST | `/api/v1/reports/export` | Export a scan run report as base64 PDF or PPTX |
| GET | `/api/v1/akb/status` | Report AKB RAG configuration and storage boundaries without secrets |
| POST | `/api/v1/akb/ai/ask` | Ask AKB a cited, scan-run-scoped question |
| GET | `/api/v1/toolchain/doctor` | Check local toolchain availability |
| GET | `/api/v1/toolchain/requirements` | List scanner/evidence tools required for healthcare reference coverage |
| POST | `/api/v1/results/ingest` | Accept a redacted result envelope for central storage |

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
curl "http://localhost:8781/api/v1/scans/runs/scan_abc123/report?format=markdown"
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
- STRATOS report exports should use `POST /api/v1/reports/export`; document-
  grounded AI should use the AKB bridge, not a browser-side LLM call.
