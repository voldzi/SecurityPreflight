import { afterEach, describe, expect, it, vi } from "vitest";
import { authorizeGovernedRequest, decidePolicy, policyBindingForClassification } from "./governance.js";

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
    process.env.STRATOS_POLICY_SERVICE_TOKEN = "runtime-secret";
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => new Response(JSON.stringify({ decision: "ALLOW", reasonCodes: ["POLICY_ALLOW"], obligations: ["AUDIT_ACCESS"], policyVersion: "information-policy-2.0.0", decisionId: "dec_test" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const request = { id: "req_test" } as Parameters<typeof authorizeGovernedRequest>[0]["request"];
    const decision = await authorizeGovernedRequest({ request, context: { mode: "oidc", subject: "user:test", provider: "keycloak", name: "Test", email: null, roles: ["stratos_user"], isAdmin: false }, capabilityId: "security-preflight:read_scan", operation: "read", scope: { type: "project", id: "project_test" }, policyBinding: base.policyBinding });
    expect(decision.decisionId).toBe("dec_test");
    const sent = JSON.parse(String((fetchMock.mock.calls[0]?.[1] as RequestInit).body));
    expect(sent).toMatchObject({ actorSubjectId: "user:test", capabilityId: "security-preflight:read_scan", scope: { type: "project", id: "project_test" } });
  });

  it("fails closed for unknown capabilities and policy outage", async () => {
    const request = { id: "req_test" } as Parameters<typeof authorizeGovernedRequest>[0]["request"];
    const context = { mode: "oidc" as const, subject: "user:test", provider: "keycloak", name: "Test", email: null, roles: ["stratos_admin"], isAdmin: true };
    await expect(authorizeGovernedRequest({ request, context, capabilityId: "security-preflight:unknown", operation: "read", policyBinding: base.policyBinding })).resolves.toMatchObject({ decision: "DENY", reasonCodes: ["CAPABILITY_MISSING"] });
    await expect(authorizeGovernedRequest({ request, context, capabilityId: "security-preflight:read_scan", operation: "read", policyBinding: base.policyBinding })).resolves.toMatchObject({ decision: "DENY", reasonCodes: ["POLICY_UNAVAILABLE"] });
  });
});
