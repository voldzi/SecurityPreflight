# SecurityPreflight

SecurityPreflight is a prepared application workspace for building a security
preflight tool: local checks, deployment readiness checks, configuration
validation, dependency/security evidence, and operational guardrails before code
or infrastructure changes move toward GitHub and production environments.

Application repository scaffold prepared for Chroma-assisted development with
CODEX and Claude Code, following the central application standards
(chromadb tooling repo, `docs/standards/`).

## Main Features

- Security and configuration preflight checks.
- Deployment readiness checks for local, CI, and production-oriented workflows.
- Evidence-oriented reporting for issues, risks, and remediation status.
- Chroma-assisted development through the local `chromadb` tooling repository.

## Technology Stack

- Monorepo: pnpm workspaces with `apps/` and `packages/`.
- Web UI: Next.js, React, TypeScript, Tailwind CSS, shadcn/ui.
- API: Node.js, TypeScript, Fastify, Zod, OpenAPI JSON-first.
- Worker: Node.js, TypeScript, Redis-backed queue, scanner orchestration.
- Data: PostgreSQL for scan history, Redis for queue and scan state.
- Runtime: Docker Desktop with Docker Compose.
- Scanner execution: MVP uses a constrained scanner-toolbox container model
  without mounting the Docker socket by default.

## Run Locally

The application implementation has not been scaffolded yet. The always
available repository validation command is:

```bash
bash scripts/validate-skeleton.sh
```

After the application stack is scaffolded, the canonical local runtime will be
Docker Desktop and Docker Compose with the Web UI on `http://localhost:8780`.
Basic configuration is described in `docs/operations.md`; `.env.example` lists
every environment variable.

## Initial Setup

1. Review `AGENTS.md` and `CLAUDE.md`.
2. Review the initial architecture in `docs/architecture.md` and
   `docs/adr/0001-initial-architecture.md`.
3. Scaffold the pnpm workspace, Docker Compose stack, API, worker, Web UI, and
   CLI according to the architecture.
4. Add the real build, run, test, lint, and typecheck commands here and in the
   agent instruction files once they exist.
5. Start local Chroma on the development workstation if it is not already
   running, then reindex this repository:

```bash
"/Users/voldzi/Documents/Development/18 2026/chromadb/tools/chroma-dev.sh" reindex --root .
```

If the repository defines a repo-local Chroma scope in `.chroma-dev.yaml`, the
standard command above automatically uses it.

## Documentation

The active documentation set starts in `docs/README.md`:
`architecture.md`, `api.md`, `security.md`, `operations.md`,
`observability.md`, `runbook.md`, decisions in `docs/adr/`, history in
`docs/archive/`.

The machine-readable API contract, when the app provides a REST API, is
`openapi/openapi.json` (JSON-first standard).

## Validation

```bash
bash scripts/validate-skeleton.sh
```

CI (`.github/workflows/ci.yml`) runs the skeleton validation, OpenAPI lint,
and a secret scan; add stack-specific jobs as the application grows.

## Retrieval Workflow

This repository is intended to use retrieval-first development:

- search with Chroma before broad scanning
- read exact files after retrieval narrows the search
- refresh the index after meaningful repository changes
