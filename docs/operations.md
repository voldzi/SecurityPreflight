# Operations

## Local Development

### Prerequisites

- macOS with Docker Desktop installed and running.
- Docker Compose available through Docker Desktop.
- Node.js 26 or newer.
- pnpm 10.
- Local Chroma tooling for retrieval-assisted development.

### Setup

```bash
pnpm install
bash scripts/validate-skeleton.sh
```

The Web UI depends on the restricted GitHub Packages package
`@voldzi/stratos-ui`. Configure a read-only package token outside Git, for
example in the user-local `~/.npmrc`:

```ini
@voldzi:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_READ_TOKEN}
```

The repository `.npmrc` contains only the registry mapping and must not contain
tokens.

### Run

```bash
pnpm dev:web
pnpm dev:api
pnpm dev:worker
```

The Web UI runs on `http://localhost:8780`; the API runs on
`http://localhost:8781`.

Docker Desktop stack:

```bash
docker compose up -d
docker compose down
```

The Web image uses the local `~/.npmrc` as a Docker BuildKit secret during
dependency installation so the `@voldzi/stratos-ui` token is not copied into the
image or committed files. If the token file is stored elsewhere, set `HOME` or
run the Web build with an equivalent BuildKit `npmrc` secret.

CLI wrapper examples:

```bash
pnpm --filter @security-preflight/cli preflight status
pnpm --filter @security-preflight/cli preflight doctor
pnpm --filter @security-preflight/cli preflight scan --project . --profile fast-local --dry-run
pnpm --filter @security-preflight/cli preflight scan --project . --profile documentation-compliance
pnpm --filter @security-preflight/cli preflight scan --project . --profile healthcare-reference --dry-run
```

Controlled local DAST dry-run example:

```bash
pnpm --filter @security-preflight/cli preflight scan \
  --project . \
  --profile controlled-dast-local \
  --dast-target http://localhost:3000 \
  --allow-active-dast \
  --dry-run
```

The dry-run command calls `POST /api/v1/scans/plan`. It does not run scanners.
It returns the planned commands, evidence paths, read-only project mount,
network mode, and any guardrail block reasons.
When invoked through pnpm, the CLI resolves relative `--project` paths against
the original shell directory, not the CLI package directory.

Without `--dry-run`, the CLI calls `POST /api/v1/scans/queue`. The API only
queues unblocked plans. The worker executes internal documentation, OpenAPI,
configuration, and forbidden-file checks plus configured external scanner
commands, then writes evidence under `REPORTS_PATH/<scanRunId>/`. Missing
scanner binaries, disabled runner policy, or scanner execution errors create
blocking tooling evidence rather than a false pass.

When the worker runs in Docker Compose, set `PROJECTS_ROOT_HOST` to a host
directory containing the projects to scan. The worker mounts it read-only at
`PROJECTS_ROOT_CONTAINER` and maps queued host paths under that root into the
container path before reading project files.

Completed worker jobs write `central-result-envelope.json` next to `report.json`
and `report.md`. A central storage service can implement or call
`POST /api/v1/results/ingest` using the OpenAPI schema. Do not send raw scanner
outputs or source code through this endpoint.

### Test, Lint, Typecheck

```bash
bash scripts/validate-skeleton.sh
pnpm typecheck
pnpm test
pnpm build
pnpm lint:openapi
```

Combined local validation:

```bash
pnpm validate
```

## Deployment

Primary deployment is local Docker Desktop on the developer workstation.
SecurityPreflight is offline-first and does not require a cloud service.

Production-like or centralized deployment is out of scope for MVP. Any future
central platform mode must introduce authentication, authorization, TLS,
central secret handling, and a documented export/synchronization model.

## Configuration

Configuration comes from environment variables. `.env.example` mirrors this
table and must stay in sync.

| Name | Required | Default | Purpose |
| --- | --- | --- | --- |
| `APP_ENV` | yes | `development` | Runtime environment |
| `APP_PORT` | yes | `8781` | API HTTP port |
| `WEB_PORT` | yes | `8780` | Web UI HTTP port |
| `LOG_LEVEL` | no | `info` | Log verbosity |
| `DATABASE_URL` | yes | unset | PostgreSQL connection string |
| `REDIS_URL` | yes | unset | Redis connection string |
| `REPORTS_PATH` | yes | `/reports` | Container path for generated reports and evidence |
| `PROJECTS_ROOT_HOST` | no | unset | Host directory containing projects that the Docker worker may read |
| `PROJECTS_ROOT_CONTAINER` | no | `/workspace/projects` | Container mount path for `PROJECTS_ROOT_HOST` |
| `SCANNER_NETWORK_MODE` | no | `none` | Default network mode for passive scanners |
| `SCANNER_RUNNER_ENABLED` | no | `true` | Enables worker execution of planned external scanner commands |
| `SCANNER_RUNNER_MODE` | no | `direct` | `direct` runs scanners inside the worker; `docker` runs them through Docker with the scanner-toolbox image |
| `SCANNER_TOOLBOX_IMAGE` | no | `security-preflight/scanner-toolbox:local` | Image used by the Docker scanner runner |
| `ALLOW_DOCKER_SOCKET` | no | `false` | Explicit opt-in for future Docker socket based scanning |
| `ALLOW_ACTIVE_DAST` | no | `false` | Enables controlled active DAST profiles |
| `DAST_ALLOWED_HOSTS` | no | `localhost,127.0.0.1,host.docker.internal` | Comma-separated active DAST allowlist |

## Health Endpoints

- `GET /health` - liveness
- `GET /ready` - readiness (200 ready, 503 not ready)

## External Dependencies

- Docker Desktop and Docker Compose.
- PostgreSQL and Redis services from the local Compose stack.
- Scanner tools packaged in local containers: Gitleaks, Semgrep, Trivy, Syft,
  Grype, OSV Scanner, Checkov, Redocly/OpenAPI tooling, and optional ZAP
  baseline planning for controlled DAST.
- Optional scanner network access for vulnerability database updates.
- Optional controlled DAST target on localhost or allowlisted staging hosts.

## Backup and Restore

- Report evidence is stored under the configured reports volume, planned as
  `~/SecurityPreflight/reports` on the host.
- PostgreSQL stores scan history, findings, settings, and audit events.
- Backup requires copying both the PostgreSQL volume/export and report storage
  volume.

## Operational Limits and Scaling

- MVP is single-user and local-only.
- Scanner workloads are CPU, memory, and I/O intensive. Profiles must define
  timeouts and should avoid running unnecessary tools.
- Default scanner project mounts are read-only.
- Scan execution planning blocks active DAST unless it is enabled by both the
  selected profile and request.
- Active DAST is disabled by default and must be explicitly enabled per safe
  target/profile. The default allowlist is `localhost`, `127.0.0.1`, and
  `host.docker.internal`.

## Troubleshooting

Start with `docs/runbook.md` for incident scenarios.

## Rollback

MVP rollback means stopping the Compose stack and returning to the previous
local git revision or previous container images.
