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
- STRATOS-style report exports as redacted PDF and PPTX payloads.
- Server-side AKB bridge for cited, scan-run-scoped AI questions without
  storing prompts, answers, chunks, embeddings, or document text locally.
- Production API boundary with STRATOS OIDC/JWKS bearer validation, coarse RBAC,
  shared-token transition mode, explicit CORS allowlist, and UI bearer handoff.
- STRATOS Keycloak client provisioning for realm `stratos`, public client
  `security-preflight-web`, and `security-preflight.*` RBAC roles.
- Guarded scan execution planning with read-only mounts, evidence paths, and
  explicit controlled DAST allowlists.
- Healthcare reference profile with SBOM, SCA, SAST, IaC, OpenAPI, privacy,
  audit, encryption, retention, and central result envelope coverage.
- Chroma-assisted development through the local `chromadb` tooling repository.

## Technology Stack

- Monorepo: pnpm workspaces with `apps/` and `packages/`.
- Web UI: Next.js, React, TypeScript, Tailwind CSS, and `@voldzi/stratos-ui`.
- API: Node.js, TypeScript, Fastify, Zod, OpenAPI JSON-first.
- Worker: Node.js, TypeScript, Redis-backed queue, scanner orchestration.
- Data: PostgreSQL for scan history, Redis for queue and scan state.
- Runtime: Docker Desktop with Docker Compose.
- Scanner execution: worker/container runner for Gitleaks, Semgrep, Trivy,
  Syft, Grype, OSV Scanner, Checkov, Redocly, and controlled ZAP planning,
  without mounting the Docker socket by default.

## Run Locally

Install dependencies:

```bash
pnpm install
```

Run the local Web UI and API during development:

```bash
pnpm dev:web
pnpm dev:api
```

The Web UI runs on `http://localhost:8780`; the API runs on
`http://localhost:8781`.

Run the Docker Desktop stack:

```bash
docker compose up -d
```

Provision the STRATOS Keycloak client on the production host when deploying:

```bash
KEYCLOAK_USE_CONTAINER_BOOTSTRAP_PASSWORD=true \
SECURITY_PREFLIGHT_ENV_FILE=/srv/SecurityPreflight/.env \
SECURITY_PREFLIGHT_PUBLIC_BASE_URL=http://docker.home.cz:8780 \
./infra/keycloak/ensure-security-preflight-client.sh
```

Preview a scan execution plan without running scanners:

```bash
pnpm --filter @security-preflight/cli preflight scan --project . --profile fast-local --dry-run
```

Queue a supported scan through the API and worker:

```bash
pnpm --filter @security-preflight/cli preflight scan --project . --profile documentation-compliance
```

Preview the healthcare reference profile:

```bash
pnpm --filter @security-preflight/cli preflight scan --project . --profile healthcare-reference --dry-run
```

Basic configuration is described in `docs/operations.md`; `.env.example` lists
every environment variable.

## Initial Setup

1. Review `AGENTS.md` and `CLAUDE.md`.
2. Review the initial architecture in `docs/architecture.md` and
   `docs/adr/0001-initial-architecture.md`.
3. Install dependencies with `pnpm install`.
4. Run `pnpm validate`.
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
pnpm validate
```

CI (`.github/workflows/ci.yml`) runs skeleton validation, dependency install,
typecheck, tests, build, OpenAPI lint, and a secret scan.

## Retrieval Workflow

This repository is intended to use retrieval-first development:

- search with Chroma before broad scanning
- read exact files after retrieval narrows the search
- refresh the index after meaningful repository changes
