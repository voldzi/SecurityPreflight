# SecurityPreflight Access and Information V2 impact

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
- External AI, telemetry and vulnerability evidence exports require an ALLOW
  decision and PAP when the payload contains cyber information, IOC or evidence.
- JSON, SARIF and central scan artefacts inherit the binding. The central result
  contains a `stratos-integration-envelope-1` envelope, correlation,
  idempotency and policy hash.
- The owner reset is dry-run by default, requires exact epoch and G7 confirmation
  and validates Docker volume ownership before deletion.

## Compatibility and operations

`@voldzi/stratos-ui` is pinned to `0.3.32`. Legacy role lists remain visible in
auth status only for migration diagnostics and no longer grant API operations.
Before G4, configure the policy decision endpoint and runtime-only service token
for both API and worker. A missing configuration intentionally denies governed
OIDC and external worker operations.

## Verification evidence

Acceptance tests cover ALLOW/DENY fixtures, unknown classification and
obligation, scope/capability denial, PAP external-operation matrix, export
leakage, decision correlation, inherited report binding and integration
envelope. Reset tests verify dry-run and refusal without both confirmations;
destructive reset rehearsal and isolated restore remain G5/G6 activities.
