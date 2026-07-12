import { afterEach, describe, expect, it, vi } from "vitest";
import { informationPolicyBindingHash } from "@security-preflight/core";
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
    process.env.STRATOS_POLICY_SERVICE_TOKEN = "runtime-only";
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: RequestInit) => {
      const input = JSON.parse(String(init?.body));
      return new Response(JSON.stringify({ ...input, organizationId: "org_stratos", policyHash: informationPolicyBindingHash(input) }), { status: 200 });
    }));
    const binding = await registerProjectPolicyBinding("project_health", "health-data");
    expect(binding).toMatchObject({ policyBindingId: "pb_security_preflight_project_health_health-data", organizationId: "org_stratos", policyVersion: "information-policy-2.0.0", pap: "PAP:AMBER" });
    expect(binding.policyHash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("fails closed when registry is unavailable in OIDC mode", async () => {
    process.env.SECURITY_PREFLIGHT_AUTH_MODE = "oidc";
    delete process.env.SECURITY_PREFLIGHT_POLICY_REGISTRY_URL;
    delete process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL;
    delete process.env.STRATOS_POLICY_SERVICE_TOKEN;
    await expect(registerProjectPolicyBinding("project_health", "health-data")).rejects.toMatchObject({ code: "POLICY_REGISTRY_UNAVAILABLE" } satisfies Partial<PolicyRegistryError>);
  });
});
