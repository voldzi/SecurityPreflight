import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { informationPolicyBindingForClassification, informationPolicyBindingHash, type InformationPolicyBinding } from "@security-preflight/core";
import { createProject, deleteProject, listProjects, ProjectRegistryError, projectRegistryPath } from "./projects.js";

const originalEnvironment = { ...process.env };
const cleanupPaths: string[] = [];

afterEach(async () => {
  process.env = { ...originalEnvironment };
  vi.unstubAllGlobals();
  await Promise.all(cleanupPaths.splice(0).map((entry) => rm(entry, { recursive: true, force: true })));
});

describe("project access-governance lifecycle", () => {
  it("registers the owning scope before the authoritative binding and local project, then reconciles idempotently", async () => {
    const fixture = await projectFixture("governed");
    configureGovernance(fixture.root, fixture.reportsPath);
    const calls: Array<{ url: string; active?: boolean }> = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ url, active: url.includes("/access/scopes/") ? body.isActive : undefined });
      return url.includes("/access/scopes/")
        ? scopeResponse("project_governed", body.isActive)
        : bindingResponse(body);
    }));

    const project = await createProject({
      id: "project_governed",
      name: "Governed app",
      path: fixture.projectPath,
      dataClassification: "sensitive"
    });
    await expect(listProjects()).resolves.toHaveLength(1);

    expect(calls).toEqual([
      { url: "https://stratos.test/api/v1/access/scopes/project/project_governed", active: true },
      { url: "https://stratos.test/api/v1/policy/bindings", active: undefined },
      { url: "https://stratos.test/api/v1/access/scopes/project/project_governed", active: true }
    ]);
    expect(project.policyBinding).toMatchObject({ policyBindingId: "pb_security_preflight_project_governed_sensitive" });
  });

  it("deactivates a newly activated scope when binding registration fails", async () => {
    const fixture = await projectFixture("binding-failure");
    configureGovernance(fixture.root, fixture.reportsPath);
    const states: boolean[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (url.includes("/access/scopes/")) {
        states.push(body.isActive);
        return scopeResponse("project_binding_failure", body.isActive);
      }
      return new Response("registry unavailable", { status: 503 });
    }));

    await expect(createProject({
      id: "project_binding_failure",
      name: "Binding failure",
      path: fixture.projectPath
    })).rejects.toMatchObject({ code: "POLICY_REGISTRY_REJECTED" } satisfies Partial<ProjectRegistryError>);
    expect(states).toEqual([true, false]);
    await expect(access(projectRegistryPath())).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("ensures the active scope before upgrading a legacy local binding", async () => {
    const fixture = await projectFixture("legacy-binding");
    configureGovernance(fixture.root, fixture.reportsPath);
    await mkdir(fixture.reportsPath, { recursive: true });
    const legacyBase = {
      ...informationPolicyBindingForClassification("internal"),
      policyBindingId: "pb_legacy_security_preflight_project",
      organizationId: "org_stratos"
    };
    await writeFile(projectRegistryPath(), `${JSON.stringify({
      schemaVersion: "security-preflight.projects.v1",
      projects: [{
        id: "project_legacy_binding",
        name: "Legacy binding",
        path: fixture.projectPath,
        repositoryUrl: null,
        publicUrl: null,
        defaultBranch: null,
        technologyStack: ["Node.js"],
        dataClassification: "internal",
        policyBinding: { ...legacyBase, policyHash: informationPolicyBindingHash(legacyBase) },
        owner: null,
        createdAt: "2026-07-13T00:00:00.000Z",
        updatedAt: "2026-07-13T00:00:00.000Z"
      }]
    }, null, 2)}\n`, "utf8");
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      calls.push(url);
      const body = JSON.parse(String(init?.body));
      return url.includes("/access/scopes/")
        ? scopeResponse("project_legacy_binding", body.isActive)
        : bindingResponse(body);
    }));

    await expect(listProjects()).resolves.toHaveLength(1);
    expect(calls).toEqual([
      "https://stratos.test/api/v1/access/scopes/project/project_legacy_binding",
      "https://stratos.test/api/v1/policy/bindings"
    ]);
    const stored = await readFile(projectRegistryPath(), "utf8");
    expect(JSON.parse(stored).projects[0].policyBinding).toMatchObject({
      schemaVersion: "stratos-information-policy-2",
      applicationId: "security-preflight",
      policyBindingId: "pb_security_preflight_project_legacy_binding_internal"
    });
  });

  it("deactivates a new scope if local persistence fails after a valid binding", async () => {
    const fixture = await projectFixture("write-failure");
    configureGovernance(fixture.root, fixture.reportsPath);
    const blockedReportsPath = path.join(fixture.root, "not-a-directory");
    await writeFile(blockedReportsPath, "blocked", "utf8");
    const states: boolean[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (url.includes("/access/scopes/")) {
        states.push(body.isActive);
        return scopeResponse("project_write_failure", body.isActive);
      }
      process.env.REPORTS_PATH = blockedReportsPath;
      return bindingResponse(body);
    }));

    await expect(createProject({
      id: "project_write_failure",
      name: "Write failure",
      path: fixture.projectPath
    })).rejects.toThrow();
    expect(states).toEqual([true, false]);
  });

  it("reactivates a scope when local deletion cannot be persisted", async () => {
    const fixture = await projectFixture("delete-failure");
    configureGovernance(fixture.root, fixture.reportsPath);
    const blockedReportsPath = path.join(fixture.root, "not-a-directory");
    await writeFile(blockedReportsPath, "blocked", "utf8");
    const states: boolean[] = [];
    let failDeleteWrite = false;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (url.includes("/access/scopes/")) {
        states.push(body.isActive);
        if (body.isActive === false && failDeleteWrite) process.env.REPORTS_PATH = blockedReportsPath;
        return scopeResponse("project_delete_failure", body.isActive);
      }
      return bindingResponse(body);
    }));
    await createProject({ id: "project_delete_failure", name: "Delete failure", path: fixture.projectPath });
    failDeleteWrite = true;

    await expect(deleteProject("project_delete_failure")).rejects.toThrow();
    expect(states).toEqual([true, false, true]);
  });

  it("commits local deletion only after the owned central scope is inactive", async () => {
    const fixture = await projectFixture("delete-success");
    configureGovernance(fixture.root, fixture.reportsPath);
    const states: boolean[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (url.includes("/access/scopes/")) {
        states.push(body.isActive);
        return scopeResponse("project_delete_success", body.isActive);
      }
      return bindingResponse(body);
    }));
    await createProject({ id: "project_delete_success", name: "Delete success", path: fixture.projectPath });

    await expect(deleteProject("project_delete_success")).resolves.toBe(true);
    expect(states).toEqual([true, false]);
    const stored = JSON.parse(await readFile(projectRegistryPath(), "utf8"));
    expect(stored.projects).toEqual([]);
  });

  it("deactivates auto-discovered scopes if the local registry batch cannot be committed", async () => {
    const fixture = await projectFixture("autodiscovery");
    configureGovernance(fixture.root, fixture.reportsPath);
    process.env.PROJECTS_AUTODISCOVERY_ENABLED = "true";
    process.env.PROJECTS_AUTODISCOVERY_DEPTH = "1";
    const blockedReportsPath = path.join(fixture.root, "not-a-directory");
    await writeFile(blockedReportsPath, "blocked", "utf8");
    const states: boolean[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (url.includes("/access/scopes/")) {
        states.push(body.isActive);
        return scopeResponse(body.sourceRef.split(":").at(-1), body.isActive);
      }
      process.env.REPORTS_PATH = blockedReportsPath;
      return bindingResponse(body);
    }));

    await expect(listProjects()).rejects.toThrow();
    expect(states).toEqual([true, false]);
  });

  it("surfaces an explicit reconciliation error if compensation also fails", async () => {
    const fixture = await projectFixture("compensation-failure");
    configureGovernance(fixture.root, fixture.reportsPath);
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (url.includes("/access/scopes/")) {
        return body.isActive
          ? scopeResponse("project_compensation_failure", true)
          : new Response("deactivation unavailable", { status: 503 });
      }
      return new Response("binding unavailable", { status: 503 });
    }));

    await expect(createProject({
      id: "project_compensation_failure",
      name: "Compensation failure",
      path: fixture.projectPath
    })).rejects.toMatchObject({ code: "PROJECT_GOVERNANCE_RECONCILIATION_REQUIRED" } satisfies Partial<ProjectRegistryError>);
  });
});

async function projectFixture(name: string) {
  const root = await mkdtemp(path.join(tmpdir(), `security-preflight-${name}-`));
  cleanupPaths.push(root);
  const projectPath = path.join(root, "app");
  const reportsPath = path.join(root, "reports");
  await mkdir(projectPath, { recursive: true });
  await writeFile(path.join(projectPath, "package.json"), JSON.stringify({ name }), "utf8");
  return { root, projectPath, reportsPath };
}

function configureGovernance(root: string, reportsPath: string) {
  process.env.SECURITY_PREFLIGHT_AUTH_MODE = "oidc";
  process.env.PROJECTS_ROOT_CONTAINER = root;
  process.env.REPORTS_PATH = reportsPath;
  process.env.SECURITY_PREFLIGHT_SCOPE_REGISTRY_URL = "https://stratos.test/api/v1/access/scopes";
  process.env.SECURITY_PREFLIGHT_POLICY_REGISTRY_URL = "https://stratos.test/api/v1/policy/bindings";
  process.env.SECURITY_PREFLIGHT_GOVERNANCE_SERVICE_TOKEN = "governance-only";
}

function scopeResponse(projectId: string, isActive: boolean) {
  return new Response(JSON.stringify({
    id: `scope_${projectId}`,
    organizationId: "org_stratos",
    type: "project",
    key: projectId,
    parentId: "scope_org_stratos",
    application: "SECURITY_PREFLIGHT",
    sourceSystem: "APPLICATION",
    sourceRef: `security-preflight:project:${projectId}`,
    isActive
  }), { status: 200 });
}

function bindingResponse(input: Record<string, unknown>) {
  return new Response(JSON.stringify({
    schemaVersion: "stratos-information-policy-2",
    ...input,
    organizationId: "org_stratos",
    policyHash: informationPolicyBindingHash(input as unknown as InformationPolicyBinding),
    originator: "service-security-preflight-governance-id"
  }), { status: 200 });
}
