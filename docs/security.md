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
URIs `https://stratos.zeleznalady.cz/sp/` and
`https://stratos.zeleznalady.cz/sp/*`.

When production OIDC is configured, the Web UI starts the STRATOS PKCE login
automatically if no bearer token is present. This avoids presenting a disabled
dashboard where scan profiles and scan actions cannot load. If the API rejects
a stored token with `401`, the Web UI clears it and starts a fresh STRATOS
login. A `403` remains visible as an authorization/RBAC problem and is not
retried automatically. In that state the Web UI renders only the STRATOS
topbar and a no-access visual; it clears loaded workspace state and does not
show projects, scan history, findings, telemetry, AKB answers, or scanner
evidence to the user without the required role.

## Authorization

The API verifies identity with OIDC and authorizes every protected route through
the STRATOS access projection and capability/scope policy decision endpoints.
For every protected OIDC request the API loads a fresh caller-bound
`GET /api/v1/auth/me` projection; ALLOW projections are not cached. Missing,
expired or suspended application access and scopes omitted because they are
inactive fail closed before local data is returned. SecurityPreflight then uses
`security-preflight:access`, `submit_scan`, `read_scan`, `external_operation`,
`export`, `read_audit`, and `manage_access`. A missing policy service, unknown
capability, scope mismatch, unknown binding, or malformed decision fails closed.
`SECURITY_PREFLIGHT_REQUIRED_ROLES` and `SECURITY_PREFLIGHT_OPERATOR_ROLES`
are identity diagnostics only and default to the approved `stratos_user` and
`stratos_admin` baseline. They are not authorization primitives.

Project authorization is evaluated against STRATOS organization/project scopes.
Project and scan-run collections are filtered to active effective project scopes;
direct access is re-decided against the concrete project. A Keycloak
`stratos_admin` role, client role, or caller-supplied identity header never
bypasses this PEP. Shared-token mode has no governance bypass by default; the
explicit `SECURITY_PREFLIGHT_LOCAL_GOVERNANCE_BYPASS=true` compatibility switch
works only outside production.

Information Policy V2 maps the five local data classifications to a canonical
binding with `legalClassification=NONE`. Scan reports, SARIF and central result
envelopes inherit the binding. External AI, central delivery and DefectDojo
export require capability, project scope, an ALLOW decision and PAP for cyber
information/evidence. Policy outage and unknown obligations deny the operation.
Project creation first registers an owning active STRATOS `project` scope under
`scope_org_stratos` through a service-token on-behalf-of call. STRATOS reloads
the actor identity, membership and `security-preflight:manage_access` capability
on the parent organization scope. The API then registers an authoritative
binding before local persistence. Scans, reports, SARIF, telemetry and exports
use the returned id and hash. The worker rechecks `external_operation` as
`service:security-preflight` immediately before any restricted-network plan;
queued approval is not treated as a lasting authorization. SecurityPreflight does not provide a true-public
publication surface; audit evidence always remains authenticated and governed.

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

## Browser Security Headers

The Web UI, API, and production nginx include send a production security header
baseline:

- `Strict-Transport-Security`
- `Content-Security-Policy` with `frame-ancestors 'none'`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- restrictive `Permissions-Policy`
- `Cross-Origin-Opener-Policy: same-origin`

The Web UI CSP permits STRATOS Keycloak and the public STRATOS origin for OIDC
and API calls. The API CSP is stricter because API responses do not need browser
script, image, or style execution.

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

Audit events are recorded for queued scans, worker start, step completion,
scan completion/failure, and finding triage changes. PostgreSQL stores bounded
event metadata, actor identifiers from the authenticated request when
available, finding status changes, and references to evidence files. Raw
scanner stdout, source code, credentials, AKB prompts, AKB answers, document
chunks, and embeddings are not copied into PostgreSQL. Retention is local and
controlled by the report/database cleanup policy.

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

Scanner workloads run with read-only project mounts by default. The API also
receives the same read-only project root for project registration validation and
bounded stack detection; it persists metadata only and must not copy source code
into the registry. Scanner containers should drop unnecessary capabilities,
avoid privileged mode, avoid the Docker socket, and disable network access
unless a check explicitly needs it.

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

The `web-perimeter-safe` profile adds bounded network and HTTP checks for
explicitly allowlisted targets: DNS records, TLS certificate state, TLS protocol
acceptance, common management ports, HTTP security headers, discoverable
admin/debug/API endpoints, WAF or edge-protection indicators, and Nuclei safe
templates. The built-in endpoint probes use a fixed short path list, short
timeouts, and GET/HEAD-style requests only. The `openapi-runtime-safe` profile
adds bounded GET/HEAD probes for documented OpenAPI operations without path
parameters. The `external-vps-safe` profile verifies readiness for a hardened
external scanner and `SCANNER_RUNNER_MODE=remote` can dispatch supported
web-target scanner commands, such as ZAP and Nuclei, without sending source
code to the VPS.

Greenbone/OpenVAS and OpenSCAP are handled as enterprise assurance evidence
imports. Greenbone findings are normalized from approved XML or JSON reports;
OpenSCAP findings are normalized from XCCDF result XML or from an explicit
local `oscap xccdf eval` run. DefectDojo export uses SARIF import and requires
an explicit worker opt-in. Production credentials must remain in a secret store
outside Git and reports.

Missing Greenbone/OpenVAS, OpenSCAP, DefectDojo, external scanner, or runner
configuration is classified as `scope=platform`. It is reported as a
SecurityPreflight readiness gap and scan-completeness limitation, not as a
vulnerability in the checked application. Normalized Greenbone/OpenSCAP results
from approved evidence remain `scope=application`.

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
