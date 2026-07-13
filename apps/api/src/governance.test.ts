import { afterEach, describe, expect, it, vi } from "vitest";
import {
  authorizeGovernedRequest,
  decidePolicy,
  loadSecurityPreflightAccessProjection,
  parseSecurityPreflightAccessProjection,
  policyBindingForClassification,
  securityPreflightProjectionScopeMatches,
  type SecurityPreflightAccessProjection
} from "./governance.js";

const originalEnvironment = { ...process.env };

afterEach(() => {
  vi.unstubAllGlobals();
  process.env = { ...originalEnvironment };
});

const base = {
  operation: "read",
  identityActive: true,
  membershipActive: true,
  applicationAccess: true,
  capability: true,
  scopeMatches: true,
  policyBinding: policyBindingForClassification("internal")
};

describe("Information Policy V2", () => {
  it("matches the binding and decision ALLOW/DENY fixtures", () => {
    expect(decidePolicy(base)).toMatchObject({ decision: "ALLOW", reasonCodes: ["POLICY_ALLOW"], obligations: ["AUDIT_ACCESS"] });
    expect(decidePolicy({ ...base, capability: false })).toMatchObject({ decision: "DENY", reasonCodes: ["CAPABILITY_MISSING"] });
    expect(decidePolicy({ ...base, scopeMatches: false })).toMatchObject({ decision: "DENY", reasonCodes: ["SCOPE_MISMATCH"] });
    expect(decidePolicy({ ...base, policyBinding: null })).toMatchObject({ decision: "DENY", reasonCodes: ["POLICY_UNAVAILABLE"] });
  });

  it("rejects unknown classifications, legal classifications and obligations", () => {
    expect(() => policyBindingForClassification("top-secret")).toThrow(/Unknown SecurityPreflight data classification/);
    expect(decidePolicy({ ...base, policyBinding: { ...base.policyBinding, legalClassification: "D" as "NONE" } })).toMatchObject({ decision: "DENY", reasonCodes: ["LEGAL_CLASSIFICATION_UNSUPPORTED"] });
    expect(decidePolicy({ ...base, policyBinding: { ...base.policyBinding, obligations: ["AUDIT_ACCESS", "UNKNOWN"] } })).toMatchObject({ decision: "DENY", reasonCodes: ["OBLIGATION_UNKNOWN"] });
    expect(decidePolicy({ ...base, policyBinding: { ...base.policyBinding, tlp: "TLP:BLUE" } })).toMatchObject({ decision: "DENY", reasonCodes: ["TLP_UNKNOWN"] });
    expect(decidePolicy({ ...base, policyBinding: { ...base.policyBinding, tlp: "TLP:RED", audience: { organizationId: "org_stratos", scopeType: "project", scopeIds: ["project_test"] } } })).toMatchObject({ decision: "DENY", reasonCodes: ["TLP_RECIPIENT_SET_REQUIRED"] });
  });

  it.each([
    ["external_operation", true, "PAP_REQUIRED"],
    ["external_ai", true, "PAP_REQUIRED"],
    ["export", true, "PAP_REQUIRED"],
    ["external_operation", false, "POLICY_ALLOW"],
    ["external_ai", false, "POLICY_ALLOW"],
    ["export", false, "POLICY_ALLOW"]
  ])("applies PAP only to cyber information for %s", (operation, cyberInformation, reasonCode) => {
    const policyBinding = { ...base.policyBinding, pap: null };
    expect(decidePolicy({ ...base, operation, cyberInformation, policyBinding }).reasonCodes).toEqual([reasonCode]);
  });

  it("prevents export leakage and returns auditable correlation", () => {
    const decision = decidePolicy({ ...base, operation: "export", policyBinding: { ...base.policyBinding, obligations: ["AUDIT_ACCESS", "NO_EXPORT"] } });
    expect(decision).toMatchObject({ decision: "DENY", reasonCodes: ["EXPORT_FORBIDDEN"] });
    expect(decision.decisionId).toMatch(/^dec_/);
  });

  it("delegates capability and project scope with audit correlation", async () => {
    process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL = "https://policy.test/api/v1/policy/decisions";
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => new Response(JSON.stringify({ decision: "ALLOW", reasonCodes: ["POLICY_ALLOW"], obligations: ["AUDIT_ACCESS"], policyVersion: "information-policy-2.0.0", decisionId: "dec_test" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const request = { id: "req_test", headers: { authorization: "Bearer caller-token" } } as Parameters<typeof authorizeGovernedRequest>[0]["request"];
    const accessProjection: SecurityPreflightAccessProjection = {
      capabilities: ["security-preflight:access", "security-preflight:read_scan"],
      scopes: [{ type: "organization", id: "org_stratos" }],
      effectiveScopes: [{ type: "organization", id: "org_stratos" }, { type: "project", id: "project_test" }]
    };
    const decision = await authorizeGovernedRequest({ request, context: { mode: "oidc", subject: "user:test", provider: "keycloak", name: "Test", email: null, roles: ["stratos_user"], isAdmin: false }, accessProjection, capabilityId: "security-preflight:read_scan", operation: "read", scope: { type: "project", id: "project_test" }, policyBinding: base.policyBinding });
    expect(decision.decisionId).toBe("dec_test");
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    const sent = JSON.parse(String(init.body));
    expect(new Headers(init.headers).get("authorization")).toBe("Bearer caller-token");
    expect(sent).toMatchObject({ capabilityId: "security-preflight:read_scan", scope: { type: "project", id: "project_test" } });
    expect(sent).not.toHaveProperty("actorSubjectId");
  });

  it("fails closed for unknown capabilities and policy outage", async () => {
    const request = { id: "req_test", headers: {} } as Parameters<typeof authorizeGovernedRequest>[0]["request"];
    const context = { mode: "oidc" as const, subject: "user:test", provider: "keycloak", name: "Test", email: null, roles: ["stratos_admin"], isAdmin: true };
    const accessProjection: SecurityPreflightAccessProjection = { capabilities: ["security-preflight:access", "security-preflight:read_scan"], scopes: [{ type: "organization", id: "org_stratos" }], effectiveScopes: [{ type: "organization", id: "org_stratos" }] };
    await expect(authorizeGovernedRequest({ request, context, capabilityId: "security-preflight:unknown", operation: "read", policyBinding: base.policyBinding })).resolves.toMatchObject({ decision: "DENY", reasonCodes: ["CAPABILITY_MISSING"] });
    await expect(authorizeGovernedRequest({ request, context, accessProjection, capabilityId: "security-preflight:read_scan", operation: "read", policyBinding: base.policyBinding })).resolves.toMatchObject({ decision: "DENY", reasonCodes: ["POLICY_UNAVAILABLE"] });
  });

  it("rejects expired, suspended and not-yet-valid access projections", () => {
    const baseAccess = {
      application: "SECURITY_PREFLIGHT",
      capabilities: ["security-preflight:access", "security-preflight:read_scan"],
      scopes: [{ type: "project", id: "project_test" }],
      effectiveScopes: [{ type: "project", id: "project_test" }]
    };
    expect(parseSecurityPreflightAccessProjection({ applicationAccess: [{ ...baseAccess, validUntil: "2020-01-01T00:00:00.000Z" }] })).toBeNull();
    expect(parseSecurityPreflightAccessProjection({ applicationAccess: [{ ...baseAccess, suspendedAt: "2026-07-13T00:00:00.000Z" }] })).toBeNull();
    expect(parseSecurityPreflightAccessProjection({ applicationAccess: [{ ...baseAccess, validFrom: "2999-01-01T00:00:00.000Z" }] })).toBeNull();
  });

  it("requires the application capability and an active effective scope", () => {
    expect(parseSecurityPreflightAccessProjection({ applicationAccess: [{ application: "SECURITY_PREFLIGHT", capabilities: ["security-preflight:read_scan"], scopes: [{ type: "project", id: "project_test" }] }] })).toBeNull();
    expect(parseSecurityPreflightAccessProjection({ applicationAccess: [{ application: "SECURITY_PREFLIGHT", capabilities: ["security-preflight:access"], scopes: [{ type: "project", id: "project_test" }], effectiveScopes: [] }] })).toBeNull();
    const projection = parseSecurityPreflightAccessProjection({ applicationAccess: [{ application: "SECURITY_PREFLIGHT", capabilities: ["security-preflight:access", "security-preflight:read_scan"], scopes: [{ type: "organization", id: "org_stratos" }], effectiveScopes: [{ type: "organization", id: "org_stratos" }, { type: "project", id: "project_active" }] }] });
    expect(projection).not.toBeNull();
    expect(securityPreflightProjectionScopeMatches(projection as SecurityPreflightAccessProjection, { type: "project", id: "project_active" }, "user:test")).toBe(true);
    expect(securityPreflightProjectionScopeMatches(projection as SecurityPreflightAccessProjection, { type: "project", id: "project_deactivated" }, "user:test")).toBe(false);
  });

  it("loads /auth/me with the caller bearer and fails closed for a suspended grant", async () => {
    process.env.SECURITY_PREFLIGHT_ACCESS_PROJECTION_URL = "https://stratos.test/api/v1/auth/me";
    const request = { id: "req_projection", headers: { authorization: "Bearer caller-token" } } as Parameters<typeof loadSecurityPreflightAccessProjection>[0]["request"];
    const context = { mode: "oidc" as const, subject: "user:test", provider: "keycloak", name: "Test", email: null, roles: ["stratos_user"], isAdmin: false };
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => new Response(JSON.stringify({ applicationAccess: [] }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(loadSecurityPreflightAccessProjection({ request, context })).resolves.toMatchObject({ ok: false, statusCode: 403, reasonCodes: ["APPLICATION_ACCESS_MISSING"] });
    expect((fetchMock.mock.calls[0]?.[1] as RequestInit).headers).toMatchObject({ authorization: "Bearer caller-token" });
  });

  it("does not let a stratos_admin display role bypass a missing capability or scope", async () => {
    process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL = "https://policy.test/api/v1/policy/decisions";
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ decision: "ALLOW", reasonCodes: ["POLICY_ALLOW"], obligations: ["AUDIT_ACCESS"], policyVersion: "information-policy-2.0.0", decisionId: "dec_should_not_be_called" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const request = { id: "req_admin" } as Parameters<typeof authorizeGovernedRequest>[0]["request"];
    const context = { mode: "oidc" as const, subject: "user:admin", provider: "keycloak", name: "Admin", email: null, roles: ["stratos_admin"], isAdmin: true };
    const projection: SecurityPreflightAccessProjection = { capabilities: ["security-preflight:access", "security-preflight:read_scan"], scopes: [{ type: "project", id: "project_a" }], effectiveScopes: [{ type: "project", id: "project_a" }] };
    await expect(authorizeGovernedRequest({ request, context, accessProjection: projection, capabilityId: "security-preflight:export", operation: "export", scope: { type: "project", id: "project_a" }, policyBinding: base.policyBinding })).resolves.toMatchObject({ decision: "DENY", reasonCodes: ["CAPABILITY_MISSING"] });
    await expect(authorizeGovernedRequest({ request, context, accessProjection: projection, capabilityId: "security-preflight:read_scan", operation: "access", scope: { type: "project", id: "project_b" }, policyBinding: base.policyBinding })).resolves.toMatchObject({ decision: "DENY", reasonCodes: ["SCOPE_MISMATCH"] });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("requires an explicit non-production opt-in for the legacy shared-token governance bypass", async () => {
    process.env.SECURITY_PREFLIGHT_AUTH_MODE = "shared-token";
    delete process.env.SECURITY_PREFLIGHT_LOCAL_GOVERNANCE_BYPASS;
    const request = { id: "req_shared" } as Parameters<typeof authorizeGovernedRequest>[0]["request"];
    const context = { mode: "shared-token" as const, subject: "shared-token", provider: "security-preflight", name: "Shared", email: null, roles: ["stratos_admin"], isAdmin: true };
    await expect(authorizeGovernedRequest({ request, context, capabilityId: "security-preflight:read_scan", operation: "access", policyBinding: base.policyBinding })).resolves.toMatchObject({ decision: "DENY", reasonCodes: ["POLICY_UNAVAILABLE"] });
    process.env.SECURITY_PREFLIGHT_LOCAL_GOVERNANCE_BYPASS = "true";
    await expect(authorizeGovernedRequest({ request, context, capabilityId: "security-preflight:read_scan", operation: "access", policyBinding: base.policyBinding })).resolves.toMatchObject({ decision: "ALLOW" });
  });
});
