# SecurityPreflight Documentation

## Purpose

This is the active documentation set for `SecurityPreflight`. Use this directory
for current-state documentation only. Historical materials belong in
`docs/archive/`.

## Mandatory Set

| Document | Covers |
| --- | --- |
| `architecture.md` | Purpose, context, components, data flows, integrations, deployment model |
| `api.md` | Human-readable API description; points to `openapi/openapi.json` |
| `security.md` | AuthN/AuthZ, secrets, input validation, audit logging |
| `operations.md` | Run, deploy, configure, scale, troubleshoot, rollback |
| `observability.md` | Logging, metrics, tracing, health/readiness, alerts |
| `runbook.md` | Concrete steps for operational incident scenarios |
| `adr/` | Architecture decision records |
| `archive/` | Historical and superseded documents |
| `reports/access-information-v2-impact-2026-07-12.md` | G2/G3 implementation impact and acceptance evidence |

The machine-readable API contract lives in `openapi/openapi.json`
(JSON-first standard).

## Documentation Rules

- Keep active docs aligned with the current repository state.
- Update this index when the active set changes.
- One topic has one active canonical document. Do not create duplicates such as
  `architecture 2.md`.
- Keep generated exports, temporary audits, scratch notes, and superseded
  designs in `archive/`.
- Add or update an ADR when a decision changes architecture, data model,
  storage, security boundaries, integrations, deployment, rollback, or prior
  decisions.
- If a code change affects API, config, deployment, testing, security, data
  handling, or operations, update the corresponding document in the same change.
- The full documentation standard lives in the chromadb tooling repository
  under `docs/standards/`.
