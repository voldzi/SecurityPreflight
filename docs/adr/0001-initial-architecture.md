# ADR 0001: Initial Architecture

## Status

Proposed

## Context

SecurityPreflight will run local security preflight checks for application
projects owned by the developer. It must work through Docker Desktop on a
MacBook, stay offline-first by default, avoid uploading source code or reports,
and produce evidence suitable for release readiness and formal security review.

The tool must be safe for projects that may handle hospital, health, or other
highly sensitive data. It should orchestrate established scanners instead of
implementing its own vulnerability scanner. Controlled DAST and
penetration-test readiness checks are in scope, but exploit automation,
brute-force testing, denial-of-service testing, authentication bypass attempts,
data exfiltration, public internet scanning, and third-party target scanning
are out of scope.

## Decision

Adopt a TypeScript monorepo with pnpm workspaces:

- `apps/web`: Next.js, React, Tailwind CSS, and shadcn/ui.
- `apps/api`: Node.js, Fastify, Zod, and OpenAPI JSON-first.
- `apps/worker`: Node.js worker with Redis-backed queue processing.
- `apps/cli`: thin local CLI over the API and Docker Compose lifecycle.
- `packages/core`: shared models, validation, redaction, normalization, gate
  evaluation, and audit-event definitions.
- `packages/scanners`: scanner adapters and parsers.
- `packages/report`: Markdown and JSON report generation first, SARIF later.
- `packages/config`: global and project configuration schemas.

Use PostgreSQL for project metadata, scan history, findings, risk exceptions,
settings, and audit events. Use Redis for scan queues, progress, and ephemeral
worker state.

Run the application as a Docker Desktop Compose stack. The Web UI is planned on
`http://localhost:8780`; the API is planned on `http://localhost:8781`.

For MVP, use a constrained scanner-toolbox execution model without mounting
`/var/run/docker.sock` by default. Scanner workloads mount target projects
read-only, drop unnecessary privileges, disable network access unless required,
and use explicit timeouts. Future Docker socket based scanning must be an
explicit higher-risk mode.

OpenAPI remains JSON-first. The binding contract is `openapi/openapi.json`.

## Consequences

This architecture keeps the implementation aligned with the desired local,
offline-first product while allowing Web UI, API, worker, CLI, and scanner
logic to evolve independently.

Fastify keeps the API small and explicit. A shared TypeScript model layer
reduces drift between the API, worker, CLI, report generation, and tests.
PostgreSQL provides durable local history and Redis gives predictable queue
semantics without designing a custom queue.

Avoiding Docker socket access in MVP improves default safety but limits dynamic
container/image scanning. Container image scanning, Docker Compose scanning,
and more advanced scanner orchestration may require a carefully documented
socket-based mode or a host-side helper later.

The controlled DAST/pentest boundary must stay explicit. SecurityPreflight can
help prepare for human-led penetration testing and run safe local DAST checks,
but it must not become an exploit framework or scanner for systems the user
does not own.
