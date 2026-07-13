import { afterEach, describe, expect, it, vi } from "vitest";
import { registerProjectGovernanceScope, ScopeRegistryError } from "./scope-registry.js";

const originalEnvironment = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnvironment };
  vi.unstubAllGlobals();
});

describe("STRATOS Scope Registry", () => {
  it("registers the owning active project scope on behalf of an authorized actor", async () => {
    process.env.SECURITY_PREFLIGHT_AUTH_MODE = "oidc";
    process.env.SECURITY_PREFLIGHT_SCOPE_REGISTRY_URL = "https://stratos.test/api/v1/access/scopes";
    process.env.STRATOS_POLICY_SERVICE_TOKEN = "runtime-only";
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      const input = JSON.parse(String(init?.body));
      expect(url).toBe("https://stratos.test/api/v1/access/scopes/project/project_health");
      expect(input).toMatchObject({
        actorSubjectId: "oidc:security-admin",
        parentId: "scope_org_stratos",
        applicationId: "security-preflight",
        sourceRef: "security-preflight:project:project_health",
        isActive: true
      });
      return new Response(JSON.stringify({
        id: "scope_security_preflight_project_health",
        organizationId: "org_stratos",
        type: "project",
        key: "project_health",
        parentId: "scope_org_stratos",
        application: "SECURITY_PREFLIGHT",
        sourceSystem: "APPLICATION",
        sourceRef: "security-preflight:project:project_health",
        isActive: true
      }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    await expect(registerProjectGovernanceScope({ projectId: "project_health", displayName: "Health", actorSubjectId: "oidc:security-admin" })).resolves.toMatchObject({
      type: "project",
      key: "project_health",
      isActive: true
    });
    expect((fetchMock.mock.calls[0]?.[1] as RequestInit).headers).toMatchObject({ authorization: "Bearer runtime-only" });
  });

  it("fails closed when delegated scope registration is unavailable", async () => {
    process.env.SECURITY_PREFLIGHT_AUTH_MODE = "oidc";
    delete process.env.SECURITY_PREFLIGHT_SCOPE_REGISTRY_URL;
    delete process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL;
    delete process.env.STRATOS_POLICY_SERVICE_TOKEN;
    await expect(registerProjectGovernanceScope({ projectId: "project_health", displayName: "Health" })).rejects.toMatchObject({ code: "SCOPE_REGISTRY_UNAVAILABLE" } satisfies Partial<ScopeRegistryError>);
  });

  it("rejects a response that does not preserve ownership and parent", async () => {
    process.env.SECURITY_PREFLIGHT_AUTH_MODE = "oidc";
    process.env.SECURITY_PREFLIGHT_SCOPE_REGISTRY_URL = "https://stratos.test/api/v1/access/scopes";
    process.env.STRATOS_POLICY_SERVICE_TOKEN = "runtime-only";
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      id: "scope_wrong",
      organizationId: "org_stratos",
      type: "project",
      key: "project_health",
      parentId: "scope_other",
      application: "SECURITY_PREFLIGHT",
      sourceSystem: "APPLICATION",
      sourceRef: "security-preflight:project:project_health",
      isActive: true
    }), { status: 200 })));
    await expect(registerProjectGovernanceScope({ projectId: "project_health", displayName: "Health" })).rejects.toMatchObject({ code: "SCOPE_REGISTRY_RESPONSE_INVALID" } satisfies Partial<ScopeRegistryError>);
  });
});
