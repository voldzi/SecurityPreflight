# Security

## Authentication

Local development may run with `SECURITY_PREFLIGHT_AUTH_MODE=disabled`.
Production does not default to anonymous access: when `APP_ENV=production` and
`SECURITY_PREFLIGHT_AUTH_MODE` is unset, the API uses `oidc` and fails closed
until OIDC issuer, client id, and audience are configured. For Keycloak, the
JWKS URL is derived from the issuer when `SECURITY_PREFLIGHT_OIDC_JWKS_URL` is
not set.

Protected API endpoints accept bearer tokens. OIDC mode validates RS256 JWTs
against JWKS, issuer, audience, expiry, not-before, subject, and authorized
party. The Web UI supports STRATOS-style OIDC PKCE login through public
`NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_*` values and sends bearer tokens only to
SecurityPreflight, not directly to AKB. `shared-token` mode is available only as
a transition control for restricted deployments and requires
`SECURITY_PREFLIGHT_API_TOKEN`.

The STRATOS production identity source is Keycloak realm `stratos` at
`https://login.zeleznalady.cz/realms/stratos`. The application client is the
public PKCE client `security-preflight-web`, provisioned by
`infra/keycloak/ensure-security-preflight-client.sh`, with production redirect
URI `https://stratos.zeleznalady.cz/sp/*`.

## Authorization

The API enforces coarse RBAC from token roles. Read endpoints require one of
`SECURITY_PREFLIGHT_REQUIRED_ROLES`. Mutating endpoints, scan queueing, report
exports, central ingest, and AKB questions require one of
`SECURITY_PREFLIGHT_OPERATOR_ROLES`. Defaults include
`security-preflight.viewer`, `security-preflight.operator`,
`security-preflight.admin`, `stratos_security_admin`, `stratos_superadmin`, and
`superadmin` as appropriate.

Project-level ownership, exception approver roles, and per-project
authorization are still planned. Until they exist, healthcare deployments must
scope access at the STRATOS/Keycloak role level and network boundary:
`security-preflight.viewer` for read-only review, `security-preflight.operator`
for scan execution and report export, and `security-preflight.admin` or
`stratos_security_admin` for administration.

## Secret Management

- Secrets are never committed to the repository.
- `.env.example` lists every configuration variable with safe placeholders.
- Project `.preflight/config.json` files must not contain tokens, passwords,
  cookies, private keys, production `.env` values, scanner tokens, or GitHub
  tokens.
- MVP stores secrets only as runtime values in memory or Docker-managed local
  secret mechanisms where practical.
- Future host-side secret integration should use macOS Keychain through the CLI.
- Reports, raw outputs, and logs must redact credential-shaped values before
  display or persistence where practical.

## TLS

Local development traffic may use HTTP on localhost. Any shared or production
deployment must terminate TLS before browser access and configure explicit API
CORS origins through `SECURITY_PREFLIGHT_CORS_ORIGINS`.

## Input Validation

All API inputs are validated with Zod schemas shared from `packages/core` or
`packages/config`. Invalid input returns the unified `ErrorResponse` shape with
`code`, `message`, and `requestId`.

## Injection Protection

Database access uses a typed ORM/query layer with parameterized queries. Shell
execution for scanner adapters must avoid string interpolation; commands are
constructed as argument arrays and paths are resolved, normalized, and checked
before use.

## XSS / CSRF

The Web UI must treat scanner output, file paths, evidence, and report excerpts
as untrusted data. Render findings as escaped text by default. Do not render raw
HTML from scanner output.

The production API uses bearer tokens rather than cookies, so CSRF risk is
bounded by CORS and token storage. If cookie-based sessions are added later,
CSRF protections must be added first.

## Audit Logs

Audit events are recorded for project registration, scan start, scan
completion, scan cancellation, report export, settings changes, risk exception
creation, exception approval, and finding status changes.

MVP stores audit events in PostgreSQL and includes relevant event references in
scan evidence. Retention is local and controlled by the report/database cleanup
policy.

## Safe Error Messages

Errors returned to clients never leak stack traces, secrets, or internal
infrastructure details. Internal detail belongs in logs keyed by `requestId`.

## Dependency Scanning

Trivy is the default MVP dependency and filesystem scanner. Findings are
normalized into the shared `Finding` model and evaluated by the selected scan
profile's release gate.

The healthcare reference profile additionally requires SBOM generation,
SBOM-based vulnerability analysis, OSV dependency checks, license-policy
evidence, IaC scanning, OpenAPI validation, privacy/audit/encryption/retention
documentation evidence, and central result envelope export readiness.

## Scanner Isolation

Scanner workloads run with read-only project mounts by default. Scanner
containers should drop unnecessary capabilities, avoid privileged mode, avoid
the Docker socket, and disable network access unless a check explicitly needs
it.

The default execution model runs scanner commands inside the constrained worker
container with a read-only project mount. A Docker runner can use the
scanner-toolbox image for per-step isolation when explicitly configured. The
default Compose worker does not receive `/var/run/docker.sock`. Any Docker
socket mode is an explicit higher-risk configuration and must be documented in
`docs/operations.md`.

Scan execution planning happens before scanner execution. Plans record the
intended command argument array, read-only project mount, evidence paths,
network mode, and guardrails. A plan with blocked guardrails must not be queued
or executed by the worker.

The worker executes internal documentation, OpenAPI, configuration, and
forbidden-file checks, plus configured external scanner commands. External
scanner commands are not treated as successful unless a runner executes them
and writes evidence. Disabled runner policy, unavailable scanner binaries, or
scanner execution failures create blocking tooling evidence rather than a false
pass.

## Controlled DAST and Penetration Testing

SecurityPreflight may run safe, controlled DAST and penetration-test readiness
checks against applications owned by the user. Active DAST is disabled by
default and allowed only for localhost, `127.0.0.1`,
`host.docker.internal`, or explicitly allowlisted staging hosts.

The `controlled-dast-local` profile is the first controlled DAST profile. It
plans an OWASP ZAP baseline only when active scanning is explicitly enabled in
the request and the target URL is local or allowlisted. URLs with embedded
credentials, non-HTTP protocols, non-allowlisted hosts, and production-like
hostnames are blocked by the plan guardrails by default.

The tool must not implement or enable brute-force attacks, denial-of-service
tests, exploit chaining, authentication bypass attempts, data exfiltration, or
scanning of third-party/public targets. Formal penetration testing remains a
separate human-led activity; SecurityPreflight prepares evidence and finds
obvious issues before that review.

## Privacy

Default behavior is offline-first: no cloud upload, no external telemetry, no
automatic report sharing, and no source-code upload outside the developer
MacBook. External export requires explicit user action and must not include
plaintext secrets.

Central result exchange uses the redacted `security-preflight.result.v1`
envelope. Central storage must receive findings, summaries, gate results, and
evidence metadata only; source code and raw scanner outputs remain local unless
an explicit future export policy allows them.

PDF and PPTX report exports are explicit user actions and are generated from
redacted `report.md`, `report.json`, step summaries, finding summaries, and the
evidence manifest. They must not include raw scanner stdout/stderr, full source
files, secrets, production `.env` values, private keys, or bearer tokens.

AKB is the STRATOS boundary for document-grounded AI. SecurityPreflight calls
AKB only from the backend and sends scan-run metadata, tags, data
classification, and a correlation id. SecurityPreflight must not store AKB
prompts, RAG answers, chunks, embeddings, extracted document text, or citation
source context. If AKB is not configured or cannot provide a cited answer, the
API fails closed or returns AKB's explicit no-answer state.
