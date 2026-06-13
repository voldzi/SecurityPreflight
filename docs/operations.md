# Operations

## Local Development

### Prerequisites

- macOS with Docker Desktop installed and running.
- Docker Compose available through Docker Desktop.
- Node.js and pnpm for local development after the application workspace is
  scaffolded.
- Local Chroma tooling for retrieval-assisted development.

### Setup

```bash
bash scripts/validate-skeleton.sh
```

Application setup commands will be added after the pnpm workspace and Docker
Compose stack are scaffolded.

### Run

```bash
bash scripts/validate-skeleton.sh
```

The planned local runtime is Docker Compose with Web UI on
`http://localhost:8780` and API on `http://localhost:8781`. The exact
`docker compose` command will be documented after `infra/docker-compose.yml`
exists.

### Test, Lint, Typecheck

```bash
bash scripts/validate-skeleton.sh
```

Stack-specific test, lint, and typecheck commands will be added when the
workspace packages exist.

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
| `SCANNER_NETWORK_MODE` | no | `none` | Default network mode for passive scanners |
| `ALLOW_DOCKER_SOCKET` | no | `false` | Explicit opt-in for future Docker socket based scanning |
| `ALLOW_ACTIVE_DAST` | no | `false` | Enables controlled active DAST profiles |
| `DAST_ALLOWED_HOSTS` | no | `localhost,127.0.0.1,host.docker.internal` | Comma-separated active DAST allowlist |

## Health Endpoints

- `GET /health` - liveness
- `GET /ready` - readiness (200 ready, 503 not ready)

## External Dependencies

- Docker Desktop and Docker Compose.
- PostgreSQL and Redis services from the local Compose stack.
- Scanner tools packaged in local containers: Gitleaks, Semgrep, Trivy, and an
  OpenAPI validator/linter.
- Optional scanner network access for vulnerability database updates.
- Optional controlled DAST target on localhost or allowlisted staging hosts.

## Backup and Restore

- Report evidence is stored under the configured reports volume, planned as
  `~/SecurityPreflight/reports` on the host.
- PostgreSQL stores scan history, findings, settings, and audit events.
- Backup requires copying both the PostgreSQL volume/export and report storage
  volume. Exact commands will be added after Compose volumes are defined.

## Operational Limits and Scaling

- MVP is single-user and local-only.
- Scanner workloads are CPU, memory, and I/O intensive. Profiles must define
  timeouts and should avoid running unnecessary tools.
- Default scanner project mounts are read-only.
- Active DAST is disabled by default and must be explicitly enabled per safe
  target/profile.

## Troubleshooting

Start with `docs/runbook.md` for incident scenarios.

## Rollback

MVP rollback means stopping the Compose stack and returning to the previous
local git revision or previous container images. Exact commands will be added
after the stack is implemented.
