# ADR 0004: Production Authentication Boundary

## Status

Accepted

## Context

SecurityPreflight is intended for highly sensitive application checks, including
healthcare systems. A remotely reachable production deployment cannot remain
anonymous. STRATOS applications use Keycloak/OIDC as the normal identity
boundary and pass bearer tokens to backend services, not directly to internal
knowledge services.

## Decision

SecurityPreflight supports three API authentication modes:

- `disabled` for localhost-only development;
- `shared-token` for restricted transition deployments;
- `oidc` for production STRATOS deployments.

If `SECURITY_PREFLIGHT_AUTH_MODE` is unset, development defaults to `disabled`
and `APP_ENV=production` defaults to `oidc`. OIDC mode validates RS256 JWTs
against issuer, JWKS, client id, audience, expiry, not-before, and subject.
Roles from `realm_access` and `resource_access` drive coarse RBAC:
read endpoints require configured viewer roles, while mutating endpoints,
report export, scan queueing, central ingest, and AKB questions require
operator roles.

The Web UI supports STRATOS-style PKCE login through public
`NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_*` values and can also accept a bearer
token for `shared-token` transition mode. Tokens are sent only to the
SecurityPreflight API; AKB calls remain backend-only.

## Consequences

Production deployments fail closed until OIDC is configured, unless operators
explicitly choose `shared-token`. This avoids accidental anonymous exposure of
scan history, healthcare evidence, report exports, and AKB AI operations.

Future work should add persistent users/projects, per-project authorization,
durable audit events, token refresh handling, and TLS termination automation.
