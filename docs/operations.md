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

The Web UI depends on `@voldzi/stratos-ui` from the public npm registry. Do not
add a repository `.npmrc` or a user-local `@voldzi:registry=https://npm.pkg.github.com`
override for SecurityPreflight builds; that mapping makes CI and Docker builds
resolve the package from GitHub Packages instead of npm.

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
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml down
```

The Web image installs dependencies directly from the lockfile and public npm
registry. It does not require a BuildKit `npmrc` secret for STRATOS UI.

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

Safe web perimeter dry-run example:

```bash
pnpm --filter @security-preflight/cli preflight scan \
  --project . \
  --profile web-perimeter-safe \
  --dast-target https://staging.example.com \
  --allow-active-dast \
  --allow-host staging.example.com \
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

The Web UI supports two scan target modes in the run panel:

- Directory target: register a project first, then select it from the run
  panel. The registered path is a container path under
  `PROJECTS_ROOT_CONTAINER`, for example `/workspace/projects/app`. The matching
  host directory must be mounted through `PROJECTS_ROOT_HOST`.
- Web/API target: switch the run panel to `Web/API`, enter an `http` or `https`
  URL, and select one of the web profiles such as `web-perimeter-safe`,
  `openapi-runtime-safe`, `controlled-dast-local`, or `external-vps-safe`. The
  UI sends the URL host as the explicit allowlist. Only use this for systems you
  own or are explicitly authorized to test.

Web/API profiles provide bounded safe checks:

- `web-perimeter-safe` checks DNS resolution, TLS certificate state, TLS version
  acceptance, a small fixed common-port inventory, HTTP security headers,
  discoverable admin/debug/API documentation endpoints, WAF/edge indicators, and
  Nuclei safe templates.
- `openapi-runtime-safe` validates the local OpenAPI contract and probes only
  documented `GET`/`HEAD` operations without path parameters.
- `controlled-dast-local` adds OWASP ZAP baseline when the runner can execute
  ZAP.
- `external-vps-safe` writes the hardened external scanner handoff contract and
  can use `SCANNER_RUNNER_MODE=remote` to dispatch ZAP/Nuclei web-target
  commands to an external VPS without uploading source code.

The profiles do not perform brute force, credential attacks, denial-of-service,
exploit chaining, destructive fuzzing, or third-party scanning.

The run panel includes a scan log drawer for the latest planned or queued run.
It uses the redacted `/api/v1/scans/runs` evidence APIs to show run identity,
gate status, progress, step timeline, evidence files, blockers, and finding
summaries without exposing raw scanner stdout, source code, or secrets.
When PostgreSQL persistence is enabled, the worker also records queued,
running, step-completed, completed, failed, and finding-triage events. The UI
uses `/api/v1/scans/runs/{scanRunId}/progress` for live progress and can update
basic finding triage state through the protected triage API. Raw scanner output
remains in `/reports` evidence files, not in PostgreSQL.

When the stack runs in Docker Compose, set `PROJECTS_ROOT_HOST` to a host
directory containing the projects to scan. The API and worker mount it
read-only at `PROJECTS_ROOT_CONTAINER`. The API uses that root to validate
registered project paths and detect metadata; the worker maps queued host paths
under that root into the container path before reading project files.

Completed worker jobs write `central-result-envelope.json`,
`defectdojo.sarif.json`, `report.json`, and `report.md`. A central storage
service can implement or call `POST /api/v1/results/ingest` using the OpenAPI
schema. Set `SECURITY_PREFLIGHT_RESULT_SINK_ENABLED=true` and
`SECURITY_PREFLIGHT_RESULT_SINK_URL` to have the worker post the redacted
central envelope after each scan. Do not send raw scanner outputs or source
code through this endpoint.

DefectDojo export uses the documented SARIF import path with
`scan_type=SARIF`. Set `SECURITY_PREFLIGHT_DEFECTDOJO_EXPORT_ENABLED=true`,
`SECURITY_PREFLIGHT_DEFECTDOJO_URL`,
`SECURITY_PREFLIGHT_DEFECTDOJO_TOKEN_REF`, and
`SECURITY_PREFLIGHT_DEFECTDOJO_PRODUCT` to upload the generated SARIF file to
`/api/v2/import-scan/`. Set `SECURITY_PREFLIGHT_DEFECTDOJO_REIMPORT=true` for
`/api/v2/reimport-scan/`.

Greenbone/OpenVAS evidence is imported from an approved XML or JSON report via
`SECURITY_PREFLIGHT_GREENBONE_REPORT_PATH`. SecurityPreflight does not store
Greenbone credentials in reports. OpenSCAP evidence can be imported from
`SECURITY_PREFLIGHT_OPENSCAP_RESULTS_PATH`; alternatively, set
`SECURITY_PREFLIGHT_OPENSCAP_EVAL_ENABLED=true`,
`SECURITY_PREFLIGHT_OPENSCAP_CONTENT_PATH`, and
`SECURITY_PREFLIGHT_OPENSCAP_PROFILE` to run `oscap xccdf eval` in the worker.
If these integrations are not configured, the scan records `scope=platform`
readiness gaps. They describe incomplete SecurityPreflight evidence coverage,
not vulnerabilities in the checked project.

The API can export completed scan evidence as STRATOS-style PDF or PPTX
payloads through `POST /api/v1/reports/export`. Exports are generated from
redacted report files under `REPORTS_PATH`.

Document-grounded AI uses AKB through `POST /api/v1/akb/ai/ask`. Configure AKB
only with runtime environment variables. Browser clients must not call AKB
directly and SecurityPreflight does not store AKB prompts, responses, chunks,
embeddings, or document text.

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

For an internal production-like host, build from the Git repository and apply
the production Compose override so only the Web UI and API ports are published:

```bash
docker compose --env-file .env -p securitypreflight \
  -f infra/docker-compose.yml \
  --profile build-support \
  build scanner-runtime

docker compose --env-file .env -p securitypreflight \
  -f infra/docker-compose.yml \
  -f infra/docker-compose.production.yml \
  up -d --build
```

SecurityPreflight uses an explicit Docker Compose default network outside
common LAN ranges:

- default subnet: `10.246.250.0/24`
- default gateway: `10.246.250.1`
- default network name: `security-preflight_default`

Do not configure SecurityPreflight Docker IPAM with local LAN ranges. The
forbidden ranges include `192.168.1.x`, `192.168.10.x`, `192.168.100.x`, and
`192.168.200.x`; using them can hijack routes to real hosts such as Ollama on
`192.168.200.2:11434`. If a previous deployment already created a conflicting
network, stop the stack and remove the old Docker network before starting the
updated compose file:

```bash
docker compose --env-file .env -p securitypreflight \
  -f infra/docker-compose.yml \
  -f infra/docker-compose.production.yml \
  down
for network in security-preflight_default securitypreflight_default; do
  docker network inspect "$network" >/dev/null 2>&1 && docker network rm "$network"
done
docker compose --env-file .env -p securitypreflight \
  -f infra/docker-compose.yml \
  --profile build-support \
  build scanner-runtime
docker compose --env-file .env -p securitypreflight \
  -f infra/docker-compose.yml \
  -f infra/docker-compose.production.yml \
  up -d --build
```

After startup, verify that no Docker network uses one of the forbidden LAN
subnets:

```bash
docker network inspect $(docker network ls -q) \
  --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{.Gateway}}{{end}}' \
  | grep -E '192\.168\.(1|10|100|200)\.' || echo OK
```

Set `APP_ENV=production`, `NEXT_PUBLIC_API_URL` to the browser-reachable API
URL, `SECURITY_PREFLIGHT_CORS_ORIGINS` to the Web UI origin, and
`PROJECTS_ROOT_HOST` to the host directory that may be scanned. The production
override removes PostgreSQL and Redis host port publishing; they remain
reachable only inside the Compose network.

Production defaults to `SECURITY_PREFLIGHT_AUTH_MODE=oidc` when the variable is
unset. The API fails closed until `SECURITY_PREFLIGHT_OIDC_ISSUER`,
`SECURITY_PREFLIGHT_OIDC_CLIENT_ID`, and `SECURITY_PREFLIGHT_OIDC_AUDIENCE` are
configured. `SECURITY_PREFLIGHT_OIDC_JWKS_URL` may be supplied explicitly; when
it is absent, the API derives the standard Keycloak URL
`<issuer>/protocol/openid-connect/certs`. `shared-token` mode exists only for
controlled transition deployments and requires
`SECURITY_PREFLIGHT_API_TOKEN`. Do not place GitHub Packages tokens, scanner
tokens, production secrets, private keys, bearer tokens, or certificate material
in the repository or generated reports.

### STRATOS Keycloak

SecurityPreflight follows the STRATOS Keycloak pattern:

- realm: `stratos`
- public issuer: `https://login.zeleznalady.cz/realms/stratos`
- Web client: `security-preflight-web`
- public Web URL: `https://stratos.zeleznalady.cz/sp`
- centrally managed realm roles: `stratos_user`, `stratos_admin`
- application permissions: STRATOS Access Governance capabilities and scopes;
  the SecurityPreflight script does not create realm roles
- valid Web redirect URIs: `https://stratos.zeleznalady.cz/sp/` and
  `https://stratos.zeleznalady.cz/sp/*`

Provision or update the Keycloak client from the production host after the code
is present. The wrapper prompts only for the Keycloak admin password and uses
the STRATOS/SecurityPreflight production defaults:

```bash
cd /srv/SecurityPreflight
./infra/keycloak/provision-production-keycloak-client.sh
```

Override `KEYCLOAK_CONTAINER`, `KEYCLOAK_INTERNAL_URL`, `KEYCLOAK_PUBLIC_URL`,
`KEYCLOAK_REALM`, `SECURITY_PREFLIGHT_REDIRECT_URIS`, or
`SECURITY_PREFLIGHT_WEB_ORIGINS` when the STRATOS deployment differs. For
non-interactive automation, call
`infra/keycloak/ensure-security-preflight-client.sh` directly with the required
environment variables. The scripts create a public authorization-code/PKCE
client and write only public OIDC values to `SECURITY_PREFLIGHT_ENV_FILE`; they
do not create or persist a web client secret.

### STRATOS Nginx Publication

The internet-facing URL is `https://stratos.zeleznalady.cz/sp`. Add the
repository include file to the publishing nginx host:

```bash
cp /srv/SecurityPreflight/infra/nginx/stratos-security-preflight.conf \
  /etc/nginx/stratos-locations.d/security-preflight.conf
nginx -t
systemctl reload nginx
```

The include keeps the Next.js Web UI prefix intact for `/sp/`, while API calls
under `/sp/api/` are mapped to the Fastify API `/api/` paths.
The Web UI is built with trailing-slash routing so `/sp/` is a terminal route
and does not redirect back to `/sp`.
The include also applies the SecurityPreflight production security header
baseline on `/sp`, `/sp/`, health/readiness, and `/sp/api/` responses. Keep it
in sync with `apps/web/next.config.mjs` and `apps/api/src/security-headers.ts`
when changing CSP, HSTS, frame, referrer, or permissions policies.

## Configuration

Configuration comes from environment variables. `.env.example` mirrors this
table and must stay in sync.

| Name | Required | Default | Purpose |
| --- | --- | --- | --- |
| `APP_ENV` | yes | `development` | Runtime environment |
| `APP_PORT` | yes | `8781` | API HTTP port |
| `WEB_PORT` | yes | `8780` | Web UI HTTP port |
| `NEXT_PUBLIC_API_URL` | yes | `http://localhost:8781` | Browser-visible API base URL baked into the Web build and supplied at runtime |
| `NEXT_PUBLIC_SECURITY_PREFLIGHT_BASE_PATH` | no | unset | Next.js base path; production uses `/sp` |
| `NEXT_PUBLIC_SECURITY_PREFLIGHT_PUBLIC_BASE_URL` | no | unset | Browser-visible Web UI base URL used for OIDC redirect URI |
| `NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_ISSUER` | no | STRATOS issuer in `.env.example` | Public OIDC issuer used by the browser PKCE login |
| `NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_CLIENT_ID` | no | `security-preflight-web` in `.env.example` | Public OIDC client id for the Web UI |
| `NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_SCOPES` | no | `openid profile email` | Public OIDC scopes requested by the Web UI |
| `NEXT_PUBLIC_STRATOS_HOME_URL` | no | `https://stratos.zeleznalady.cz/` | Target URL for Budget & Contract in the STRATOS topbar switcher |
| `NEXT_PUBLIC_PROJECTFLOW_URL` | no | `https://stratos.zeleznalady.cz/project` | Target URL for ProjectFlow in the STRATOS topbar switcher |
| `NEXT_PUBLIC_AKB_URL` | no | `https://stratos.zeleznalady.cz/akb` | Target URL for AKB in the STRATOS topbar switcher |
| `NEXT_PUBLIC_ARCHFLOW_URL` | no | unset | Optional target URL for ArchFlow in the STRATOS topbar switcher |
| `NEXT_PUBLIC_PROCESSFORGE_URL` | no | unset | Optional target URL for ProcessForge in the STRATOS topbar switcher |
| `LOG_LEVEL` | no | `info` | Log verbosity |
| `DATABASE_URL` | yes | local compose postgres | PostgreSQL connection string. Production on `docker.home.cz` uses the HAProxy PostgreSQL endpoint `haproxy.home.cz:5000`; keep credentials only in runtime `.env`, never in Git |
| `SECURITY_PREFLIGHT_DB_ENABLED` | no | `true` | Enables PostgreSQL persistence for scan runs, steps, finding metadata, triage, and audit events |
| `SECURITY_PREFLIGHT_DB_REQUIRED` | no | `false` | When `true`, API/worker persistence failures are treated as hard operational failures |
| `SECURITY_PREFLIGHT_DB_APPLICATION_NAME` | no | `security-preflight` | PostgreSQL application name for connection attribution |
| `SECURITY_PREFLIGHT_DB_POOL_MAX` | no | `8` | Maximum PostgreSQL pool size per API/worker process |
| `SECURITY_PREFLIGHT_DB_CONNECT_TIMEOUT_MS` | no | `5000` | PostgreSQL connection timeout in milliseconds |
| `SECURITY_PREFLIGHT_DB_IDLE_TIMEOUT_MS` | no | `30000` | PostgreSQL idle connection timeout in milliseconds |
| `REDIS_URL` | yes | unset | Redis connection string |
| `REPORTS_PATH` | yes | `/reports` | Container path for generated reports and evidence |
| `SECURITY_PREFLIGHT_SCAN_RUNS_MERGE_EVIDENCE` | no | `false` | When PostgreSQL persistence is healthy, also scan report directories and merge evidence-only runs into `/api/v1/scans/runs`; leave disabled in production for faster list responses |
| `SECURITY_PREFLIGHT_EVIDENCE_SCAN_LIMIT` | no | `100` | Maximum report directories parsed by the filesystem evidence fallback when PostgreSQL is unavailable or evidence merge is enabled |
| `PROJECTS_ROOT_HOST` | no | unset | Host directory containing projects that the Docker API and worker may read through a read-only mount |
| `PROJECTS_ROOT_CONTAINER` | no | `/workspace/projects` | Container mount path for `PROJECTS_ROOT_HOST`; registered project paths must stay inside this root |
| `PROJECTS_OPT_ROOT_HOST` | no | same as `PROJECTS_ROOT_HOST` | Optional second host directory mounted read-only for additional applications such as `/opt` |
| `PROJECTS_OPT_ROOT_CONTAINER` | no | `/workspace/opt-projects` | Container mount path for `PROJECTS_OPT_ROOT_HOST` |
| `PROJECTS_ROOTS_CONTAINER` | no | `PROJECTS_ROOT_CONTAINER` | Comma-separated container roots allowed for project registration and auto-discovery, for example `/workspace/projects,/workspace/opt-projects` |
| `PROJECTS_AUTODISCOVERY_ENABLED` | no | `false` | When `true`, `/api/v1/projects` synchronizes mounted application directories containing known project markers into the project registry |
| `PROJECTS_AUTODISCOVERY_DEPTH` | no | `1` | Maximum directory depth scanned under each configured project root for auto-discovery; production APSYD deployments use `2` for `/opt/apsyd/<app>` |
| `SECURITY_PREFLIGHT_AUTH_MODE` | no | dev: `disabled`, production: `oidc` | API auth mode: `disabled`, `shared-token`, or `oidc` |
| `SECURITY_PREFLIGHT_API_TOKEN` | no | unset | Shared-token mode bearer token; never commit |
| `SECURITY_PREFLIGHT_CORS_ORIGINS` | yes for browser production | localhost origins | Comma-separated allowed browser origins for API CORS |
| `SECURITY_PREFLIGHT_OIDC_ISSUER` | required for OIDC | STRATOS issuer in `.env.example` | OIDC issuer expected in bearer JWTs |
| `SECURITY_PREFLIGHT_OIDC_JWKS_URL` | no | derived from issuer | JWKS URL for RS256 bearer token validation; can be explicit for nonstandard IdPs |
| `SECURITY_PREFLIGHT_OIDC_CLIENT_ID` | required for OIDC | `security-preflight-web` in `.env.example` | OIDC client id / authorized party |
| `SECURITY_PREFLIGHT_OIDC_AUDIENCE` | required for OIDC | client id | Expected token audience |
| `SECURITY_PREFLIGHT_REQUIRED_ROLES` | no | legacy role list | Migration diagnostics exposed by auth status; does not authorize API data |
| `SECURITY_PREFLIGHT_OPERATOR_ROLES` | no | legacy role list | Migration diagnostics exposed by auth status; does not authorize mutations or exports |
| `SECURITY_PREFLIGHT_POLICY_DECISION_URL` | production | unset | STRATOS Information Policy V2 decision endpoint; protected OIDC operations fail closed when unavailable |
| `SECURITY_PREFLIGHT_POLICY_REGISTRY_URL` | production | derived from decision URL | STRATOS `POST /api/v1/policy/bindings` endpoint used before a project or classification is persisted |
| `STRATOS_POLICY_SERVICE_TOKEN` | production | unset | Secret service credential supplied at runtime for delegated policy decisions; never commit it |
| `SECURITY_PREFLIGHT_POLICY_TIMEOUT_MS` | no | `3000` | Timeout for a synchronous capability/scope/policy decision |

| `SCANNER_NETWORK_MODE` | no | `none` | Default network mode for passive scanners |
| `SCANNER_RUNNER_ENABLED` | no | `true` | Enables worker execution of planned external scanner commands |
| `SCANNER_RUNNER_MODE` | no | `direct` | `direct` runs scanners inside the worker; `docker` runs them through Docker with the scanner-toolbox image; `remote` dispatches supported web scanners to the external scanner API |
| `SCANNER_TOOLBOX_IMAGE` | no | `security-preflight/scanner-toolbox:local` | Image used by the Docker scanner runner |
| `SECURITY_PREFLIGHT_DOCKER_NETWORK_NAME` | no | `security-preflight_default` | Explicit Docker Compose network name |
| `SECURITY_PREFLIGHT_DOCKER_SUBNET` | no | `10.246.250.0/24` | Explicit Docker IPAM subnet; must not use LAN ranges such as `192.168.x.x` |
| `SECURITY_PREFLIGHT_DOCKER_GATEWAY` | no | `10.246.250.1` | Explicit Docker IPAM gateway for the configured subnet |
| `ALLOW_DOCKER_SOCKET` | no | `false` | Explicit opt-in for future Docker socket based scanning |
| `ALLOW_ACTIVE_DAST` | no | `false` | Enables controlled active DAST profiles |
| `DAST_ALLOWED_HOSTS` | no | `localhost,127.0.0.1,host.docker.internal` | Comma-separated active DAST allowlist |
| `SECURITY_PREFLIGHT_EXTERNAL_SCANNER_URL` | no | unset | Hardened external scanner VPS API endpoint for signed result exchange |
| `SECURITY_PREFLIGHT_EXTERNAL_SCANNER_HEALTH_URL` | no | unset | Optional external scanner health endpoint checked by `external-runner:vps` |
| `SECURITY_PREFLIGHT_EXTERNAL_SCANNER_TOKEN_REF` | no | unset | Optional `env:NAME`, `file:/path`, or env-name reference used as bearer token for remote scanner dispatch |
| `SECURITY_PREFLIGHT_EXTERNAL_SCANNER_PUBLIC_KEY` | no | unset | Public key used to verify external scanner result signatures |
| `SECURITY_PREFLIGHT_EXTERNAL_SCANNER_REQUIRE_SIGNATURE` | no | `true` | Requires remote scanner responses to include a detached signature over the returned payload |
| `SECURITY_PREFLIGHT_DEFECTDOJO_URL` | no | unset | DefectDojo base URL for SARIF import |
| `SECURITY_PREFLIGHT_DEFECTDOJO_TOKEN_REF` | no | unset | Secret-store reference for the DefectDojo API token; never commit the token |
| `SECURITY_PREFLIGHT_DEFECTDOJO_PRODUCT` | no | unset | DefectDojo product mapping for imported findings |
| `SECURITY_PREFLIGHT_DEFECTDOJO_EXPORT_ENABLED` | no | `false` | Enables worker upload of `defectdojo.sarif.json` to DefectDojo |
| `SECURITY_PREFLIGHT_DEFECTDOJO_EXPORT_REQUIRED` | no | `false` | Fails the worker job if DefectDojo upload fails |
| `SECURITY_PREFLIGHT_DEFECTDOJO_REIMPORT` | no | `false` | Uses `/api/v2/reimport-scan/` instead of `/api/v2/import-scan/` |
| `SECURITY_PREFLIGHT_DEFECTDOJO_PRODUCT_TYPE` | no | `STRATOS` | Product type name for DefectDojo auto-created context |
| `SECURITY_PREFLIGHT_DEFECTDOJO_ENGAGEMENT` | no | generated | Engagement name for DefectDojo import |
| `SECURITY_PREFLIGHT_DEFECTDOJO_AUTO_CREATE_CONTEXT` | no | `true` | Allows DefectDojo to create product type, product, and engagement context |
| `SECURITY_PREFLIGHT_GREENBONE_URL` | no | unset | Greenbone/OpenVAS manager endpoint for enterprise assurance evidence |
| `SECURITY_PREFLIGHT_GREENBONE_CREDENTIAL_REF` | no | unset | Secret-store reference for Greenbone credentials; never commit credentials |
| `SECURITY_PREFLIGHT_GREENBONE_REPORT_PATH` | no | unset | Approved Greenbone/OpenVAS XML or JSON report to import into normalized findings |
| `SECURITY_PREFLIGHT_OPENSCAP_CONTENT_PATH` | no | unset | Mounted path to approved SCAP content for optional local OpenSCAP evaluation |
| `SECURITY_PREFLIGHT_OPENSCAP_RESULTS_PATH` | no | unset | Approved OpenSCAP XCCDF result XML to import into normalized findings |
| `SECURITY_PREFLIGHT_OPENSCAP_PROFILE` | no | unset | OpenSCAP profile id used when local evaluation is enabled |
| `SECURITY_PREFLIGHT_OPENSCAP_EVAL_ENABLED` | no | `false` | Enables worker execution of `oscap xccdf eval`; otherwise import a result XML |
| `SECURITY_PREFLIGHT_RESULT_SINK_ENABLED` | no | `false` | Enables worker delivery of redacted `central-result-envelope.json` |
| `SECURITY_PREFLIGHT_RESULT_SINK_URL` | no | unset | Central result ingest URL, usually `/api/v1/results/ingest` on the central service |
| `SECURITY_PREFLIGHT_RESULT_SINK_TOKEN_REF` | no | unset | Optional `env:NAME`, `file:/path`, or env-name bearer token reference for central delivery |
| `SECURITY_PREFLIGHT_RESULT_SINK_REQUIRED` | no | `false` | Fails the worker job if central result delivery fails |
| `SECURITY_PREFLIGHT_AKB_DOCKER_NETWORK` | no | `akl_app_zone` | Existing Docker network that exposes AKB RAG services to the API in production |
| `SECURITY_PREFLIGHT_AKB_RAG_BASE_URL` | no | `http://rag-retrieval-service:8080/api/v1` in production override, unset locally | AKB RAG API base URL, normally ending in `/api/v1` |
| `SECURITY_PREFLIGHT_AKB_PUBLIC_BASE_URL` | no | `https://stratos.zeleznalady.cz/akb` | Human-facing AKB URL shown in UI status |
| `SECURITY_PREFLIGHT_AKB_SERVICE_TOKEN` | no | unset | Compatibility bearer token for AKB when OIDC is unavailable; never commit |
| `SECURITY_PREFLIGHT_AKB_OIDC_TOKEN_URL` | no | unset | OIDC token endpoint for AKB client credentials |
| `SECURITY_PREFLIGHT_AKB_OIDC_CLIENT_ID` | no | unset | OIDC client id for AKB service access |
| `SECURITY_PREFLIGHT_AKB_OIDC_CLIENT_SECRET` | no | unset | OIDC client secret for AKB service access; never commit |
| `SECURITY_PREFLIGHT_AKB_OIDC_AUDIENCE` | no | `akl-api` | AKB API audience for OIDC client credentials |
| `SECURITY_PREFLIGHT_AKB_OIDC_SCOPE` | no | `openid profile email` | OIDC scopes requested for AKB service access |
| `SECURITY_PREFLIGHT_AKB_SYNC_REQUIRED` | no | `false` | Reserved fail-fast flag for future AKB document registration workflows |
| `SECURITY_PREFLIGHT_TENANT_ID` | no | `default` | Tenant id sent to AKB scoped RAG requests |

The API and worker receive the same Policy Registry endpoints and rotated
runtime credential. This keeps report creation, queued scans and external
operations on the same fail-closed policy decision path.

## Health Endpoints

- `GET /health` - liveness
- `GET /ready` - readiness (200 ready, 503 not ready)

## External Dependencies

- Docker Desktop and Docker Compose.
- PostgreSQL and Redis services from the local Compose stack.
- Scanner tools packaged in local containers and the API doctor runtime:
  Docker CLI/Compose plugin, Gitleaks, Semgrep, Trivy, Syft, Grype, OSV
  Scanner, Checkov, Redocly/OpenAPI tooling, Nuclei, OpenSCAP, Greenbone
  `gvm-cli`, and optional ZAP baseline/API scan planning for controlled DAST.
- Optional scanner network access for vulnerability database updates.
- Optional controlled DAST target on localhost or allowlisted staging hosts.
- Optional hardened external scanner VPS for internet vantage-point checks. It
  receives signed-job contracts or supported web scanner commands only; raw
  source code and secrets stay out of the external scanner.
- Optional DefectDojo instance for centralized finding triage through SARIF
  import. Production tokens must live in a secret store and be referenced by
  name only.
- Optional AKB RAG service for STRATOS document-grounded AI. The production
  Compose override attaches the API to the existing `akl_app_zone` Docker
  network and uses `http://rag-retrieval-service:8080/api/v1` by default.
  Production should use caller bearer propagation, OIDC client credentials, or
  a controlled backend token, never browser-side direct AKB calls.

## Backup and Restore

- Report evidence is stored under the configured reports volume, planned as
  `~/SecurityPreflight/reports` on the host.
- The project registry is stored as `projects.json` inside `REPORTS_PATH`.
  It contains metadata and bounded stack-detection results only; source code
  is not copied into the registry.
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
