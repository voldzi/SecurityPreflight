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
| GET | `/api/v1/toolchain/doctor` | Check local toolchain availability |

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

### Toolchain doctor

```bash
curl http://localhost:8781/api/v1/toolchain/doctor
```

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
- Active DAST controls and scanner safety decisions belong in the API contract
  when those endpoints are implemented.
