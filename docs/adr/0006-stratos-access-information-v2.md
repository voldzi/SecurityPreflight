# ADR-0006: STRATOS access governance and Information Policy V2

## Status

Accepted for G2/G3 integration. Production activation and epoch reset remain
blocked until G4-G6 complete.

## Decision

SecurityPreflight uses OIDC only for identity and delegates authorization to
the STRATOS policy decision endpoint using explicit application capabilities
and organization/project scopes. Policy decisions fail closed and carry
`decisionId`, reason codes and obligations into structured audit logs.

Local project classifications map to Information Policy V2. Only
`legalClassification=NONE` is accepted. External AI, telemetry and security
evidence exports additionally require PAP. Generated reports and scan artefacts
inherit the canonical binding and central exchange uses Integration Envelope
V1 with correlation, idempotency and policy hash.

## Consequences

Legacy display roles no longer authorize routes. Production requires the
policy endpoint and a runtime service credential. Policy outage intentionally
denies governed operations. Owner data reset is a separate guarded G7 action;
the repository provides a dry-run-first script but deployment and reset are not
part of this decision's implementation step.
