import { readFile } from "node:fs/promises";
import path from "node:path";
import { registerProjectGovernanceScope } from "../apps/api/src/scope-registry.js";

type ProjectEntry = { id: string; name: string };

const apply = process.argv.includes("--apply");
const registryPath = path.join(path.resolve(process.env.REPORTS_PATH ?? "/reports"), "projects.json");
const payload = JSON.parse(await readFile(registryPath, "utf8")) as { projects?: unknown };
const projects = Array.isArray(payload.projects)
  ? payload.projects.flatMap<ProjectEntry>((value) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) return [];
      const project = value as Record<string, unknown>;
      return typeof project.id === "string" && project.id.trim() && typeof project.name === "string" && project.name.trim()
        ? [{ id: project.id.trim(), name: project.name.trim() }]
        : [];
    })
  : [];

if (!apply) {
  console.log(JSON.stringify({ mode: "dry-run", registryPath, projectCount: projects.length, projectIds: projects.map((project) => project.id) }, null, 2));
  console.log("Re-run with --apply only during the governed rollout to register these existing scopes.");
  process.exit(0);
}

for (const project of projects) {
  await registerProjectGovernanceScope({
    projectId: project.id,
    displayName: project.name
  });
}

console.log(JSON.stringify({ mode: "apply", registeredProjectScopes: projects.length }, null, 2));
