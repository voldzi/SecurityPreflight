# ADR 0005: STRATOS Keycloak Client

## Status

Accepted

## Context

SecurityPreflight is part of the STRATOS application group and will be used for
security checks of sensitive, including healthcare, applications. Production
access must use the same identity boundary as the rest of STRATOS rather than a
standalone local token.

## Decision

SecurityPreflight uses Keycloak realm `stratos`, public Web client
`security-preflight-web`, and public path
`https://stratos.zeleznalady.cz/sp` for browser sign-in with authorization code
and PKCE. The API validates bearer access tokens against the STRATOS issuer
`https://login.zeleznalady.cz/realms/stratos`; JWKS is explicit when configured
and otherwise derived from the standard Keycloak certs endpoint.

The repository owns an idempotent provisioning script at
`infra/keycloak/ensure-security-preflight-client.sh`. It creates or updates the
public client, adds a client audience mapper, and verifies the centrally owned
realm-role baseline `stratos_user` and `stratos_admin`. It never creates or
deletes realm roles. Application authorization belongs to STRATOS Access
Governance capabilities and scopes.

The script may update the deployment `.env` with public OIDC values. It does
not create or store a web client secret.

For manual production operation, `infra/keycloak/provision-production-keycloak-client.sh`
wraps the provisioning defaults and prompts only for the Keycloak admin
password.

## Consequences

SecurityPreflight shares STRATOS login and identity lifecycle. Production deployments can be configured reproducibly from
the repository without putting credentials in Git. User-to-project authorization
and durable audit events are enforced through Access Governance.
