# ADR 0003: STRATOS Report Export and AKB Bridge

## Status

Accepted

## Context

SecurityPreflight is part of the STRATOS application group. STRATOS reference
applications expose audited report exports and use AKB as the boundary for
document-grounded AI. SecurityPreflight must provide comparable report and AI
surfaces without weakening its offline-first and sensitive-data safety model.

SecurityPreflight scan evidence can include sensitive file paths, scanner
output, findings, and project metadata. Any export or AI integration must avoid
uploading source code, raw scanner stdout/stderr, secrets, production `.env`
values, private keys, bearer tokens, chunks, embeddings, or RAG responses.

## Decision

SecurityPreflight implements:

- `POST /api/v1/reports/export` for STRATOS-style PDF and PPTX exports;
- `GET /api/v1/akb/status` for AKB configuration and boundary status without
  exposing secrets;
- `POST /api/v1/akb/ai/ask` as a server-side AKB RAG bridge scoped to a scan
  run.

Report exports are generated from redacted local report evidence under
`REPORTS_PATH`: `report.md`, `report.json`, step summaries, finding summaries,
gate data, and evidence manifests. The API returns a base64 payload with
filename, MIME type, SHA-256 content hash, generation time, and export
parameters.

AKB calls are backend-only. Browser clients call SecurityPreflight, not AKB
directly. SecurityPreflight sends scan-run metadata, tags, data classification,
subject metadata, `require_citations: true`, and a correlation id. AKB remains
the owner of document text, chunks, embeddings, citation context, RAG audit,
and generated AI answers.

SecurityPreflight does not persist AKB prompts, RAG answers, chunks, embeddings,
or citation source context. If AKB is not configured, the API fails closed with
`AKB_NOT_CONFIGURED`. If AKB cannot provide sufficient cited evidence, the API
returns AKB's explicit no-answer state rather than fabricating citations.

## Consequences

The application now follows the STRATOS report/export and AI integration model
while preserving the local evidence boundary. Production deployments can enable
AKB with OIDC client credentials or a controlled backend service token supplied
as runtime environment variables.

Future work should add contract tests against AKB OpenAPI, AKB document
registration for exported reports, delivery status timelines, retention
policies, and authenticated multi-user access before shared healthcare use.
