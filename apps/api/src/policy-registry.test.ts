import { afterEach, describe, expect, it, vi } from "vitest";
import { informationPolicyBindingHash, type InformationPolicyBinding } from "@security-preflight/core";
import { PolicyRegistryError, registerProjectPolicyBinding } from "./policy-registry.js";

const originalEnvironment = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnvironment };
  vi.unstubAllGlobals();
});

describe("STRATOS Policy Registry", () => {
  it("registers and returns the authoritative project binding", async () => {
    process.env.SECURITY_PREFLIGHT_AUTH_MODE = "oidc";
    process.env.SECURITY_PREFLIGHT_POLICY_REGISTRY_URL = "https://stratos.test/api/v1/policy/bindings";
    process.env.SECURITY_PREFLIGHT_GOVERNANCE_SERVICE_TOKEN = "governance-only";
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: RequestInit) => {
      const input = JSON.parse(String(init?.body));
      expect(input.applicationId).toBe("security-preflight");
      expect(new Headers(init?.headers).get("authorization")).toBe("Bearer governance-only");
      return new Response(JSON.stringify(registryResponse(input)), { status: 200 });
    }));
    const binding = await registerProjectPolicyBinding("project_health", "health-data");
    expect(binding).toMatchObject({ policyBindingId: "pb_security_preflight_project_health_health-data", organizationId: "org_stratos", policyVersion: "information-policy-2.0.0", pap: "PAP:AMBER" });
    expect(binding.policyHash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("fails closed when registry is unavailable in OIDC mode", async () => {
    process.env.SECURITY_PREFLIGHT_AUTH_MODE = "oidc";
    delete process.env.SECURITY_PREFLIGHT_POLICY_REGISTRY_URL;
    delete process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL;
    delete process.env.SECURITY_PREFLIGHT_GOVERNANCE_SERVICE_TOKEN;
    await expect(registerProjectPolicyBinding("project_health", "health-data")).rejects.toMatchObject({ code: "POLICY_REGISTRY_UNAVAILABLE" } satisfies Partial<PolicyRegistryError>);
  });

  it("does not accept the worker or retired shared credential for Registry writes", async () => {
    process.env.SECURITY_PREFLIGHT_AUTH_MODE = "oidc";
    process.env.SECURITY_PREFLIGHT_POLICY_REGISTRY_URL = "https://stratos.test/api/v1/policy/bindings";
    delete process.env.SECURITY_PREFLIGHT_GOVERNANCE_SERVICE_TOKEN;
    process.env.SECURITY_PREFLIGHT_WORKER_SERVICE_TOKEN = "worker-only";
    process.env.SECURITY_PREFLIGHT_POLICY_SERVICE_TOKEN = "retired-shared-token";
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(registerProjectPolicyBinding("project_health", "health-data")).rejects.toMatchObject({ code: "POLICY_REGISTRY_UNAVAILABLE" } satisfies Partial<PolicyRegistryError>);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["unknown handling class", { handlingClass: "SECRET" }],
    ["unknown content category", { contentCategories: ["SECURITY", "UNKNOWN"] }],
    ["duplicate obligation", { obligations: ["AUDIT_ACCESS", "AUDIT_ACCESS"] }],
    ["cross-field audience mismatch", { audience: { organizationId: "org_stratos", scopeType: "organization", scopeIds: ["project_health"] } }]
  ])("rejects a schema-invalid Registry response: %s", async (_label, override) => {
    process.env.SECURITY_PREFLIGHT_AUTH_MODE = "oidc";
    process.env.SECURITY_PREFLIGHT_POLICY_REGISTRY_URL = "https://stratos.test/api/v1/policy/bindings";
    process.env.SECURITY_PREFLIGHT_GOVERNANCE_SERVICE_TOKEN = "governance-only";
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: RequestInit) => {
      const input = JSON.parse(String(init?.body));
      return new Response(JSON.stringify({ ...registryResponse(input), ...override }), { status: 200 });
    }));
    await expect(registerProjectPolicyBinding("project_health", "health-data")).rejects.toMatchObject({ code: "POLICY_REGISTRY_RESPONSE_INVALID" } satisfies Partial<PolicyRegistryError>);
  });

  it("rejects a valid-shaped response whose immutable policy content or hash differs", async () => {
    process.env.SECURITY_PREFLIGHT_AUTH_MODE = "oidc";
    process.env.SECURITY_PREFLIGHT_POLICY_REGISTRY_URL = "https://stratos.test/api/v1/policy/bindings";
    process.env.SECURITY_PREFLIGHT_GOVERNANCE_SERVICE_TOKEN = "governance-only";
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: RequestInit) => {
      const input = JSON.parse(String(init?.body));
      const changed = { ...input, pap: "PAP:GREEN" };
      return new Response(JSON.stringify(registryResponse(changed)), { status: 200 });
    }));
    await expect(registerProjectPolicyBinding("project_health", "health-data")).rejects.toMatchObject({ code: "POLICY_REGISTRY_RESPONSE_INVALID" } satisfies Partial<PolicyRegistryError>);
  });
});

function registryResponse(input: Record<string, unknown>) {
  return {
    schemaVersion: "stratos-information-policy-2",
    ...input,
    organizationId: "org_stratos",
    policyHash: informationPolicyBindingHash(input as unknown as InformationPolicyBinding),
    originator: "service-security-preflight-governance-id"
  };
}
