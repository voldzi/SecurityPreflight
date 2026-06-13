# Security

## Authentication

MVP is single-user and local-only. The Web UI and CLI talk to the API on the
developer workstation. No remote user authentication is required while the API
is bound to localhost only.

If remote access, team use, or central synchronization is introduced later,
authentication must be designed before those modes are enabled.

## Authorization

MVP authorization is process-bound: the local user who starts the stack can use
the local UI and CLI. There are no multi-user roles in MVP.

Future team features must introduce explicit roles for project owners,
reviewers, exception approvers, and administrators before sharing scan data.

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

Local MVP traffic is HTTP on localhost. TLS is not required for loopback-only
development use.

If the API is exposed beyond localhost, TLS and authentication are mandatory
before use.

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

CSRF protection is not required for loopback-only MVP if the API is not exposed
to browsers outside the local UI origin. If cookie-based sessions or remote
access are added later, CSRF protections must be added first.

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

## Scanner Isolation

Scanner workloads run with read-only project mounts by default. Scanner
containers should drop unnecessary capabilities, avoid privileged mode, avoid
the Docker socket, and disable network access unless a check explicitly needs
it.

The MVP execution model uses a constrained scanner-toolbox container or service
instead of giving the worker broad Docker socket access. Any future Docker
socket mode is an explicit higher-risk configuration and must be documented in
`docs/operations.md`.

Scan execution planning happens before scanner execution. Plans record the
intended command argument array, read-only project mount, evidence paths,
network mode, and guardrails. A plan with blocked guardrails must not be queued
or executed by the worker.

The worker can execute internal documentation, OpenAPI, configuration, and
forbidden-file checks. External scanner commands are not treated as successful
unless an isolated runner actually executes them and writes evidence. Until the
scanner-toolbox runner is implemented, skipped external steps create blocking
tooling evidence rather than a false pass.

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
