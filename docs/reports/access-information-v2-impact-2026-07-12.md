# SecurityPreflight Access and Information V2 impact

> [!CAUTION]
> **HISTORICAL / SUPERSEDED G2–G9 EVIDENCE — NO RESET AUTHORITY.**
> The coordinated STRATOS G4–G9 rollout and reset epoch were completed on
> 2026-07-13. This report remains only as point-in-time implementation and gate
> evidence. Its reset and activation references do not authorize another reset,
> rehearsal, or destructive rollback. Current rollout is forward-only and must
> use non-destructive migration or an approved forward fix.

## Scope

SecurityPreflight now consumes STRATOS Access Governance V1, Information Policy
V2 and Integration Envelope V1. The implementation is prepared for G2/G3
integration; production deployment, owner reset and epoch activation were not
performed.

## Behavioural impact

- OIDC authenticates identity; server authorization uses concrete capabilities
  and organization/project scopes through the central policy decision endpoint.
- Protected operations fail closed on unknown capability, scope mismatch,
  policy outage, unsupported policy version, legal classification, label or
  obligation.
- Local classifications map only to canonical V2 bindings with
  `legalClassification=NONE`.
- Project creation first activates the owned scope and then registers the
  binding; classification updates ensure the scope before registering a new
  immutable binding. New-project and deletion failures use explicit scope
  compensation/reconciliation.
- External AI, telemetry and vulnerability evidence exports require an ALLOW
  decision and PAP when the payload contains cyber information, IOC or evidence.
- JSON, SARIF and central scan artefacts inherit the binding. The central result
  contains a `stratos-integration-envelope-1` envelope, correlation,
  idempotency and policy hash.
- The owner reset is dry-run by default, requires exact epoch and G7 confirmation
  and validates Docker volume ownership before deletion.

## Compatibility and operations

`@voldzi/stratos-ui` is moving to `0.3.33` for the shared Information Policy
panel. Keycloak provisioning validates only
the centrally managed `stratos_user`/`stratos_admin` baseline and creates no
application roles.
Before G4, configure the API-only governance credential and the separate
worker-only runtime decision credential. Missing or cross-injected credentials
fail readiness/startup; governed OIDC and external worker operations fail
closed.

## Verification evidence

Acceptance tests cover ALLOW/DENY fixtures, unknown classification and
obligation, scope/capability denial, PAP external-operation matrix, export
leakage, decision correlation, inherited report binding and integration
envelope. Reset tests verify dry-run and refusal without both confirmations;
destructive reset rehearsal and isolated restore remain G5/G6 activities.
