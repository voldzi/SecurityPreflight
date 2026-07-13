import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { informationPolicyBindingHash } from "@security-preflight/core";
import { createProject } from "./projects.js";

const originalEnvironment = { ...process.env };
const cleanupPaths: string[] = [];

afterEach(async () => {
  process.env = { ...originalEnvironment };
  vi.unstubAllGlobals();
  await Promise.all(cleanupPaths.splice(0).map((entry) => rm(entry, { recursive: true, force: true })));
});

describe("project access-governance registration", () => {
  it("registers the owning scope before the authoritative binding and local project", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "security-preflight-governed-project-"));
    cleanupPaths.push(root);
    const projectPath = path.join(root, "app");
    const reportsPath = path.join(root, "reports");
    await mkdir(projectPath, { recursive: true });
    await writeFile(path.join(projectPath, "package.json"), "{\"name\":\"governed-app\"}\n", "utf8");

    process.env.SECURITY_PREFLIGHT_AUTH_MODE = "oidc";
    process.env.PROJECTS_ROOT_CONTAINER = root;
    process.env.REPORTS_PATH = reportsPath;
    process.env.SECURITY_PREFLIGHT_SCOPE_REGISTRY_URL = "https://stratos.test/api/v1/access/scopes";
    process.env.SECURITY_PREFLIGHT_POLICY_REGISTRY_URL = "https://stratos.test/api/v1/policy/bindings";
    process.env.STRATOS_POLICY_SERVICE_TOKEN = "runtime-only";
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      calls.push(url);
      const body = JSON.parse(String(init?.body));
      if (url.includes("/access/scopes/")) {
        expect(body.actorSubjectId).toBe("oidc:security-admin");
        return new Response(JSON.stringify({
          id: "scope_project_governed",
          organizationId: "org_stratos",
          type: "project",
          key: "project_governed",
          parentId: "scope_org_stratos",
          application: "SECURITY_PREFLIGHT",
          sourceSystem: "APPLICATION",
          sourceRef: "security-preflight:project:project_governed",
          isActive: true
        }), { status: 200 });
      }
      return new Response(JSON.stringify({ ...body, organizationId: "org_stratos", policyHash: informationPolicyBindingHash(body) }), { status: 200 });
    }));

    const project = await createProject({
      id: "project_governed",
      name: "Governed app",
      path: projectPath,
      dataClassification: "sensitive",
      governanceActorSubjectId: "oidc:security-admin"
    });

    expect(calls).toEqual([
      "https://stratos.test/api/v1/access/scopes/project/project_governed",
      "https://stratos.test/api/v1/policy/bindings"
    ]);
    expect(project.policyBinding).toMatchObject({ policyBindingId: "pb_security_preflight_project_governed_sensitive" });
  });
});
