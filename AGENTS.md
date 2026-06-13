# Project Agent Guide

## Mission

This repository is an application workspace for SecurityPreflight, a planned security preflight tool for local checks, deployment readiness checks, configuration validation, dependency/security evidence, and operational guardrails before changes move toward GitHub and production environments.

The goal is to use Chroma to find relevant code and documentation before broad repository scanning, so development stays faster and cheaper in tokens.

Project name:

- `SecurityPreflight`

## Working Style

- Prefer retrieval-first workflow over broad file scanning.
- Before reading many files, use the available Chroma MCP tools:
  - `search_code` for implementation lookup
  - `search_docs` for documentation lookup
  - `search_all` when the location is unclear
  - `get_file_context` only after selecting a relevant hit
- If MCP tools are not exposed as native tools in the current agent session, use the CLI fallback:
  - `"/Users/voldzi/Documents/Development/18 2026/chromadb/tools/chroma-dev.sh" search-all "<query>" --root . --limit 5`
  - then read only the selected files or ranges directly
- CLI fallback is still compliant retrieval-first behavior. Mention it once if relevant; do not repeat it as a blocker when retrieval succeeded.
- If the index may be stale after meaningful repository changes, use `reindex_repo` when MCP tools are available, otherwise run:
  - `"/Users/voldzi/Documents/Development/18 2026/chromadb/tools/chroma-dev.sh" reindex --root .`
- If this repository ships a repo-local Chroma override such as `.chroma-dev.yaml`, use the standard wrapper command above and let the tool auto-load the local indexing scope.
- If retrieval tools are unavailable, Chroma is down, or the index returns no useful hits, fall back to direct repository inspection and state that retrieval was unavailable or insufficient.

## Source of Truth

- `README.md`
- `docs/README.md` and the flat mandatory documents in `docs/`
- `openapi/openapi.json` for the REST API contract, when the app provides one
- `src/` or the main application source tree
- `CLAUDE.md` and `AGENTS.md` should stay aligned unless a platform-specific difference is intentional.

## Environment

- Selected implementation stack:
  - pnpm workspaces with `apps/` and `packages/`
  - Next.js, React, TypeScript, Tailwind CSS, shadcn/ui for the Web UI
  - Node.js, TypeScript, Fastify, Zod, OpenAPI JSON-first for the API
  - Node.js worker with Redis-backed queue processing
  - PostgreSQL for durable local history
  - Redis for queue and scan state
  - Docker Desktop and Docker Compose for local runtime
- The application workspace has not been scaffolded yet, so stack-specific
  commands are not available until the relevant package files exist.
- The always-available scaffold validation command is:
  - `bash scripts/validate-skeleton.sh`
- Planned local ports:
  - Web UI: `http://localhost:8780`
  - API: `http://localhost:8781`
- Planned local services:
  - PostgreSQL
  - Redis
  - scanner-toolbox container/service
- Add exact run/build/test/lint/typecheck commands here after the application
  workspace is scaffolded.
- If retrieval depends on a repo-local Chroma scope, mention `.chroma-dev.yaml`.

## Permissions

- `git push` is allowed when the change has been intentionally prepared and the task requires publishing or syncing the branch.
- `ssh docker.home.cz` is allowed when the task requires access to the production or remote environment on that host.
- The correct production host name is `docker.home.cz`.
- Do not manipulate VPN, VLAN, firewall, or network segmentation.
- Do not place credentials, tokens, production `.env` values, private keys, certificates, vulnerability scanner tokens, or GitHub tokens in Git, documentation, shell history, scripts, or generated reports.

## Application Skeleton Standards

This repository follows the central application standards maintained in the
chromadb tooling repository under `docs/standards/`. Binding summary:

- The mandatory file set must stay present: `README.md`, `AGENTS.md`, `CLAUDE.md`,
  `.env.example`, `docs/architecture.md`, `docs/api.md`, `docs/security.md`,
  `docs/operations.md`, `docs/observability.md`, `docs/runbook.md`, `docs/adr/`.
- JSON-first OpenAPI: if this app provides a REST API, `openapi/openapi.json` is
  the only binding API contract. Never change the API without updating it.
  YAML may exist only as a generated export. Humans read `docs/api.md`.
- All error responses use the unified `ErrorResponse` format with
  `code`, `message`, `requestId`.
- Logging is structured JSON with `timestamp`, `level`, `service`, `message`,
  `requestId`, `environment`, `version`.
- Health (`/health`) and readiness (`/ready`) endpoints exist and are specified
  in the OpenAPI document.
- Never commit secrets; keep `.env.example` in sync with the configuration
  table in `docs/operations.md`.
- Do not create undocumented endpoints, delete documentation without
  replacement, or introduce an incompatible structure without an ADR.
- `scripts/validate-skeleton.sh` must pass; CI runs it.

## Documentation Rules

- Use the flat structure from `docs/README.md`: `architecture.md`, `api.md`,
  `security.md`, `operations.md`, `observability.md`, `runbook.md`, plus
  `docs/adr/` for decisions and `docs/archive/` for historical material.
- Keep active docs current-state only; one topic has one canonical document.
- Update `docs/README.md` when the active documentation set changes.
- Record significant technical decisions in `docs/adr/`.
- If a change affects API, config, deployment, testing, security, or
  operations, update the corresponding document in the same change.

## Validation

- Always available baseline:
  - `bash scripts/validate-skeleton.sh`
- Stack-specific validation commands will be added after the application
  workspace exists.
- If retrieval scope changed, include:
  - `"/Users/voldzi/Documents/Development/18 2026/chromadb/tools/chroma-dev.sh" reindex --root .`
- If Chroma-dependent retrieval behavior changed, include:
  - `"/Users/voldzi/Documents/Development/18 2026/chromadb/tools/chroma-dev.sh" search-all "<query>" --root . --limit 5`
- If a check cannot be run, say so explicitly.

## Change Discipline

- Do not silently change config semantics.
- Update docs when behavior changes.
- Keep documentation current-state, name where archived notes belong, and avoid mixing active runbooks with historical working notes.
- Do not invent production deployment behavior unless the repository explicitly defines it.
- Treat security findings, checks, and evidence as high-integrity outputs: cite source files, commands, versions, and limitations.
