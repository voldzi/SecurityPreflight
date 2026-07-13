# ADR-0006: STRATOS access governance and Information Policy V2

## Status

Accepted and aligned with the active STRATOS access projection, scope registry
and Information Policy V2 contracts.

## Decision

SecurityPreflight uses OIDC only for identity, reloads the caller's active
`/auth/me` application projection on every protected request, and delegates
authorization to the STRATOS policy decision endpoint using explicit
application capabilities and registered organization/project scopes. Policy decisions fail closed and carry
`decisionId`, reason codes and obligations into structured audit logs.

Local project classifications map to Information Policy V2. Only
`legalClassification=NONE` is accepted. External AI, telemetry and security
evidence exports additionally require PAP. Generated reports and scan artefacts
inherit the canonical binding and central exchange uses Integration Envelope
V1 with correlation, idempotency and policy hash.

Before a project is stored, the API registers the owning project scope as an
active direct child of `scope_org_stratos` through a restricted on-behalf-of
service call. STRATOS rechecks the actor's active identity, membership and
`security-preflight:manage_access` on the parent scope. The API then registers
the proposed binding in the STRATOS Policy Registry. Whenever classification
changes, it registers a new binding without changing the scope. Only the complete
authoritative response, including binding id and hash, may enter a scan plan or
derived artefact.

## Consequences

Legacy display roles no longer authorize routes. Production requires projection,
scope registry, policy registry and decision endpoints plus a runtime service
credential. ALLOW projection caching is forbidden so suspended/expired grants
and inactive scopes affect the next request. Policy outage intentionally denies
governed operations. SecurityPreflight has no anonymous true-public publication
surface.
