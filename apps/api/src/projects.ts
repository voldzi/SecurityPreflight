import { createHash } from "node:crypto";
import type { Dirent } from "node:fs";
import { mkdir, readFile, readdir, rename, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { detectTechnologyStack, type DataClassification, type Project } from "@security-preflight/core";
import { PolicyRegistryError, registerProjectPolicyBinding, registeredPolicyBindingSchema } from "./policy-registry.js";
import { deactivateProjectGovernanceScope, registerProjectGovernanceScope, ScopeRegistryError } from "./scope-registry.js";

const registrySchemaVersion = "security-preflight.projects.v1";
const maxStackFiles = 1500;
const maxStackDepth = 4;
const defaultAutoDiscoveryDepth = 1;
const ignoredStackDirs = new Set([
  ".cache",
  ".git",
  ".next",
  ".turbo",
  ".venv",
  "build",
  "coverage",
  "dist",
  "logs",
  "node_modules",
  "releases",
  "target"
]);
const projectMarkerFiles = new Set([
  ".git",
  "Dockerfile",
  "compose.yml",
  "docker-compose.yml",
  "go.mod",
  "package.json",
  "pom.xml",
  "pyproject.toml",
  "requirements.txt"
]);

// Read legacy v1 entries only so the reconciliation pass can replace them with
// a fully validated Registry response before they reach a scan plan.
const legacyPolicyBindingSchema = z.object({
  policyBindingId: z.string().min(1),
  organizationId: z.literal("org_stratos"),
  policyHash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  policyVersion: z.literal("information-policy-2.0.0"),
  handlingClass: z.enum(["PUBLIC", "INTERNAL", "RESTRICTED"]),
  legalClassification: z.literal("NONE"),
  tlp: z.enum(["TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"]).nullable(),
  pap: z.enum(["PAP:RED", "PAP:AMBER", "PAP:GREEN", "PAP:CLEAR"]).nullable(),
  obligations: z.array(z.string()),
  contentCategories: z.array(z.string()),
  audience: z.record(z.unknown())
}).passthrough();

const projectSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  path: z.string().min(1),
  repositoryUrl: z.string().nullable(),
  publicUrl: z.string().url().nullable().default(null),
  defaultBranch: z.string().nullable(),
  technologyStack: z.array(z.string()),
  dataClassification: z.enum(["public", "internal", "confidential", "sensitive", "health-data"]),
  policyBinding: z.union([registeredPolicyBindingSchema, legacyPolicyBindingSchema]).optional(),
  owner: z.string().nullable(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime()
});

const registryFileSchema = z.object({
  schemaVersion: z.literal(registrySchemaVersion),
  projects: z.array(projectSchema)
});

export interface ProjectCreateInput {
  id?: string;
  name: string;
  path: string;
  repositoryUrl?: string | null;
  publicUrl?: string | null;
  defaultBranch?: string | null;
  dataClassification?: DataClassification;
  owner?: string | null;
}

export interface ProjectUpdateInput {
  name?: string;
  path?: string;
  repositoryUrl?: string | null;
  publicUrl?: string | null;
  defaultBranch?: string | null;
  dataClassification?: DataClassification;
  owner?: string | null;
}

export class ProjectRegistryError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
    readonly details?: unknown[]
  ) {
    super(message);
  }
}

export async function listProjects(): Promise<Project[]> {
  const registry = await readRegistry();
  const migrated = await ensureProjectBindings(registry.projects);
  const projects = await syncAutoDiscoveredProjects(migrated);

  return projects.sort((left, right) => left.name.localeCompare(right.name, "en"));
}

export async function getProject(projectId: string): Promise<Project | null> {
  const registry = await readRegistry();
  const index = registry.projects.findIndex((project) => project.id === projectId);
  if (index < 0) return null;
  const project = registry.projects[index] as Project;
  await registerScope(project.id, project.name);
  if (isValidatedRegisteredPolicyBinding(project.policyBinding)) return project;
  const migrated = { ...project, policyBinding: await registerBinding(project.id, project.dataClassification), updatedAt: new Date().toISOString() };
  registry.projects[index] = migrated;
  await writeRegistry(registry.projects);
  return migrated;
}

export async function createProject(input: ProjectCreateInput): Promise<Project> {
  const registry = await readRegistry();
  const normalizedPath = await validateRegisteredProjectPath(input.path);
  const id = normalizeProjectId(input.id ?? createProjectId(normalizedPath));

  if (registry.projects.some((project) => project.id === id)) {
    throw new ProjectRegistryError(409, "PROJECT_ID_EXISTS", "A registered project with this ID already exists.");
  }

  if (registry.projects.some((project) => project.path === normalizedPath)) {
    throw new ProjectRegistryError(409, "PROJECT_PATH_EXISTS", "A registered project with this path already exists.");
  }

  const now = new Date().toISOString();
  const detected = await inspectProject(normalizedPath);
  const dataClassification = input.dataClassification ?? "internal";
  const displayName = input.name.trim();
  const policyBinding = await registerNewProjectGovernance(id, displayName, dataClassification);
  const project: Project = {
    id,
    name: displayName,
    path: normalizedPath,
    repositoryUrl: sanitizeRepositoryUrl(input.repositoryUrl ?? detected.repositoryUrl),
    publicUrl: sanitizePublicUrl(input.publicUrl),
    defaultBranch: normalizeNullableString(input.defaultBranch ?? detected.defaultBranch),
    technologyStack: detected.technologyStack,
    dataClassification,
    policyBinding,
    owner: normalizeNullableString(input.owner),
    createdAt: now,
    updatedAt: now
  };

  registry.projects.push(project);
  try {
    await writeRegistry(registry.projects);
  } catch (error) {
    await rollbackNewProjectScopes([{ projectId: id, displayName }], error);
  }

  return project;
}

export async function updateProject(projectId: string, input: ProjectUpdateInput): Promise<Project> {
  const registry = await readRegistry();
  const projectIndex = registry.projects.findIndex((project) => project.id === projectId);

  if (projectIndex < 0) {
    throw new ProjectRegistryError(404, "PROJECT_NOT_FOUND", "Registered project was not found.");
  }

  const current = registry.projects[projectIndex] as Project;
  const nextPath = input.path ? await validateRegisteredProjectPath(input.path) : current.path;

  if (nextPath !== current.path && registry.projects.some((project) => project.id !== projectId && project.path === nextPath)) {
    throw new ProjectRegistryError(409, "PROJECT_PATH_EXISTS", "A registered project with this path already exists.");
  }

  const detected = nextPath !== current.path ? await inspectProject(nextPath) : null;
  const displayName = input.name?.trim() ?? current.name;
  const dataClassification = input.dataClassification ?? current.dataClassification;
  await registerScope(current.id, displayName);
  const policyBinding = dataClassification !== current.dataClassification || !isValidatedRegisteredPolicyBinding(current.policyBinding)
    ? await registerBinding(current.id, dataClassification)
    : current.policyBinding;
  const next: Project = {
    ...current,
    name: displayName,
    path: nextPath,
    repositoryUrl: sanitizeRepositoryUrl(input.repositoryUrl !== undefined ? input.repositoryUrl : (detected?.repositoryUrl ?? current.repositoryUrl)),
    publicUrl: sanitizePublicUrl(input.publicUrl !== undefined ? input.publicUrl : current.publicUrl),
    defaultBranch: normalizeNullableString(input.defaultBranch !== undefined ? input.defaultBranch : (detected?.defaultBranch ?? current.defaultBranch)),
    technologyStack: detected?.technologyStack ?? current.technologyStack,
    dataClassification,
    policyBinding,
    owner: input.owner !== undefined ? normalizeNullableString(input.owner) : current.owner,
    updatedAt: new Date().toISOString()
  };

  registry.projects[projectIndex] = next;
  await writeRegistry(registry.projects);

  return next;
}

export async function deleteProject(projectId: string): Promise<boolean> {
  const registry = await readRegistry();
  const current = registry.projects.find((project) => project.id === projectId);
  if (!current) return false;
  const nextProjects = registry.projects.filter((project) => project.id !== projectId);

  await deactivateScope(current.id, current.name);
  try {
    await writeRegistry(nextProjects);
  } catch (error) {
    try {
      await registerScope(current.id, current.name);
    } catch (compensationError) {
      throw reconciliationRequiredError("Local project deletion failed and the project scope could not be reactivated.", error, [{
        projectId: current.id,
        compensation: errorDescriptor(compensationError)
      }]);
    }
    throw error;
  }

  return true;
}

export function projectRegistryPath(): string {
  return path.join(path.resolve(process.env.REPORTS_PATH ?? "/reports"), "projects.json");
}

async function readRegistry(): Promise<{ projects: Project[] }> {
  try {
    const payload = await readFile(projectRegistryPath(), "utf8");
    const parsed = registryFileSchema.safeParse(JSON.parse(payload));

    if (!parsed.success) {
      throw new ProjectRegistryError(500, "PROJECT_REGISTRY_INVALID", "Project registry file is invalid.", [parsed.error.flatten()]);
    }

    return { projects: parsed.data.projects };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { projects: [] };
    }

    if (error instanceof ProjectRegistryError) {
      throw error;
    }

    if (error instanceof SyntaxError) {
      throw new ProjectRegistryError(500, "PROJECT_REGISTRY_INVALID", "Project registry file is not valid JSON.");
    }

    throw error;
  }
}

async function writeRegistry(projects: Project[]): Promise<void> {
  const filePath = projectRegistryPath();
  await mkdir(path.dirname(filePath), { recursive: true });

  const payload = `${JSON.stringify({ schemaVersion: registrySchemaVersion, projects }, null, 2)}\n`;
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tempPath, payload, { encoding: "utf8", mode: 0o600 });
  await rename(tempPath, filePath);
}

async function validateRegisteredProjectPath(value: string): Promise<string> {
  if (value.includes("\0")) {
    throw new ProjectRegistryError(400, "INVALID_PROJECT_PATH", "Project path must not contain null bytes.");
  }

  if (!path.isAbsolute(value)) {
    throw new ProjectRegistryError(400, "INVALID_PROJECT_PATH", "Project path must be absolute.");
  }

  const normalizedPath = path.resolve(value);
  const roots = projectRootContainers();

  if (roots.length > 0) {
    const insideRoot = roots.some((root) => isInsideRoot(normalizedPath, root.path));

    if (!insideRoot) {
      throw new ProjectRegistryError(
        400,
        "PROJECT_PATH_OUTSIDE_ROOT",
        `Project path must be inside one of the configured roots: ${roots.map((root) => root.path).join(", ")}.`
      );
    }
  }

  let projectStat: Awaited<ReturnType<typeof stat>>;

  try {
    projectStat = await stat(normalizedPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new ProjectRegistryError(400, "PROJECT_PATH_NOT_FOUND", "Project path does not exist or is not mounted in the API container.");
    }

    throw error;
  }

  if (!projectStat.isDirectory()) {
    throw new ProjectRegistryError(400, "PROJECT_PATH_NOT_DIRECTORY", "Project path must point to a directory.");
  }

  return normalizedPath;
}

async function syncAutoDiscoveredProjects(projects: Project[]): Promise<Project[]> {
  if (process.env.PROJECTS_AUTODISCOVERY_ENABLED !== "true") {
    return projects;
  }

  const discovered = await discoverMountedProjects();
  if (discovered.length === 0) {
    return projects;
  }

  const now = new Date().toISOString();
  const nextProjects = [...projects];
  const newProjectScopes: Array<{ projectId: string; displayName: string }> = [];
  let changed = false;
  try {
    for (const candidate of discovered) {
      const existingIndex = nextProjects.findIndex((project) => project.id === candidate.id || project.path === candidate.path);
      const detected = await inspectProject(candidate.path);
      const previous = existingIndex >= 0 ? nextProjects[existingIndex] : null;
      const projectId = previous?.id ?? candidate.id;
      const displayName = previous?.name ?? candidate.name;
      const dataClassification = previous?.dataClassification ?? candidate.dataClassification;
      let policyBinding = previous?.policyBinding;
      if (!previous) {
        policyBinding = await registerNewProjectGovernance(projectId, displayName, dataClassification);
        newProjectScopes.push({ projectId, displayName });
      }
      const project: Project = {
        id: projectId,
        name: displayName,
        path: candidate.path,
        repositoryUrl: previous?.repositoryUrl ?? detected.repositoryUrl,
        publicUrl: previous?.publicUrl ?? null,
        defaultBranch: previous?.defaultBranch ?? detected.defaultBranch,
        technologyStack: detected.technologyStack,
        dataClassification,
        policyBinding,
        owner: previous?.owner ?? candidate.owner,
        createdAt: previous?.createdAt ?? now,
        updatedAt: previous?.updatedAt ?? now
      };

      if (existingIndex >= 0) {
        if (JSON.stringify(nextProjects[existingIndex]) !== JSON.stringify(project)) {
          nextProjects[existingIndex] = { ...project, updatedAt: now };
          changed = true;
        }
      } else {
        nextProjects.push(project);
        changed = true;
      }
    }
    if (changed) await writeRegistry(nextProjects);
  } catch (error) {
    if (newProjectScopes.length > 0) await rollbackNewProjectScopes(newProjectScopes, error);
    throw error;
  }

  return nextProjects;
}

async function registerBinding(projectId: string, classification: DataClassification) {
  try {
    return await registerProjectPolicyBinding(projectId, classification);
  } catch (error) {
    if (error instanceof PolicyRegistryError) throw new ProjectRegistryError(error.statusCode, error.code, error.message);
    throw error;
  }
}

async function registerScope(projectId: string, displayName: string) {
  try {
    return await registerProjectGovernanceScope({ projectId, displayName });
  } catch (error) {
    if (error instanceof ScopeRegistryError) throw new ProjectRegistryError(error.statusCode, error.code, error.message);
    throw error;
  }
}

async function deactivateScope(projectId: string, displayName: string) {
  try {
    return await deactivateProjectGovernanceScope({ projectId, displayName });
  } catch (error) {
    if (error instanceof ScopeRegistryError) throw new ProjectRegistryError(error.statusCode, error.code, error.message);
    throw error;
  }
}

async function registerNewProjectGovernance(projectId: string, displayName: string, classification: DataClassification) {
  await registerScope(projectId, displayName);
  try {
    return await registerBinding(projectId, classification);
  } catch (error) {
    await rollbackNewProjectScopes([{ projectId, displayName }], error);
  }
}

async function ensureProjectBindings(projects: Project[]): Promise<Project[]> {
  let changed = false;
  const migrated: Project[] = [];
  for (const project of projects) {
    await registerScope(project.id, project.name);
    if (isValidatedRegisteredPolicyBinding(project.policyBinding)) {
      migrated.push(project);
      continue;
    }
    migrated.push({ ...project, policyBinding: await registerBinding(project.id, project.dataClassification), updatedAt: new Date().toISOString() });
    changed = true;
  }
  if (changed) await writeRegistry(migrated);
  return migrated;
}

function isValidatedRegisteredPolicyBinding(value: unknown): boolean {
  return registeredPolicyBindingSchema.safeParse(value).success;
}

async function rollbackNewProjectScopes(scopes: Array<{ projectId: string; displayName: string }>, primaryError: unknown): Promise<never> {
  const failures: unknown[] = [];
  for (const scope of [...scopes].reverse()) {
    try {
      await deactivateScope(scope.projectId, scope.displayName);
    } catch (compensationError) {
      failures.push({ projectId: scope.projectId, compensation: errorDescriptor(compensationError) });
    }
  }
  if (failures.length > 0) {
    throw reconciliationRequiredError("Project governance failed and one or more newly activated scopes could not be deactivated.", primaryError, failures);
  }
  throw primaryError;
}

function reconciliationRequiredError(message: string, primaryError: unknown, failures: unknown[]): ProjectRegistryError {
  return new ProjectRegistryError(503, "PROJECT_GOVERNANCE_RECONCILIATION_REQUIRED", message, [
    { primary: errorDescriptor(primaryError) },
    ...failures
  ]);
}

function errorDescriptor(error: unknown): { name: string; code?: string } {
  if (error instanceof ProjectRegistryError) return { name: error.name, code: error.code };
  if (error instanceof Error) return { name: error.name };
  return { name: "UnknownError" };
}

async function discoverMountedProjects(): Promise<Array<{ id: string; name: string; path: string; dataClassification: DataClassification; owner: string }>> {
  const roots = projectRootContainers();
  const depth = autoDiscoveryDepth();
  const discovered: Array<{ id: string; name: string; path: string; dataClassification: DataClassification; owner: string }> = [];
  const seenPaths = new Set<string>();

  for (const root of roots) {
    await discoverProjectsInRoot(root, depth, discovered, seenPaths);
  }

  return discovered.sort((left, right) => left.id.localeCompare(right.id, "en"));
}

async function discoverProjectsInRoot(
  root: { label: string; path: string },
  maxDepth: number,
  discovered: Array<{ id: string; name: string; path: string; dataClassification: DataClassification; owner: string }>,
  seenPaths: Set<string>
): Promise<void> {
  async function walk(current: string, depth: number): Promise<void> {
    if (depth > maxDepth) return;

    let entries: Dirent[];
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }

    if (depth > 0 && isProjectDirectory(entries)) {
      const normalizedPath = path.resolve(current);
      if (!seenPaths.has(normalizedPath)) {
        seenPaths.add(normalizedPath);
        const relative = path.relative(root.path, normalizedPath).split(path.sep).join("/");
        const id = normalizeProjectId(`${root.label}_${slugifyPath(relative)}`);
        discovered.push({
          id,
          name: projectNameFromPath(relative),
          path: normalizedPath,
          dataClassification: inferDataClassification(normalizedPath),
          owner: inferOwner(normalizedPath)
        });
      }
      return;
    }

    for (const entry of entries) {
      if (entry.name.includes("\0")) continue;
      if (!entry.isDirectory()) continue;
      if (ignoredStackDirs.has(entry.name)) continue;
      await walk(path.join(current, entry.name), depth + 1);
    }
  }

  await walk(root.path, 0);
}

function projectRootContainers(): Array<{ label: string; path: string }> {
  const configured = splitCsv(process.env.PROJECTS_ROOTS_CONTAINER);
  const legacy = splitCsv(process.env.PROJECTS_ROOT_CONTAINER);
  const roots = configured.length > 0 ? configured : legacy;
  const seen = new Set<string>();

  return roots
    .map((rootPath) => path.resolve(rootPath))
    .filter((rootPath) => {
      if (seen.has(rootPath)) return false;
      seen.add(rootPath);
      return true;
    })
    .map((rootPath) => ({
      label: rootLabel(rootPath),
      path: rootPath
    }));
}

function isInsideRoot(normalizedPath: string, normalizedRoot: string): boolean {
  const relative = path.relative(normalizedRoot, normalizedPath);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function isProjectDirectory(entries: Dirent[]): boolean {
  return entries.some((entry) => projectMarkerFiles.has(entry.name));
}

function autoDiscoveryDepth(): number {
  const parsed = Number.parseInt(process.env.PROJECTS_AUTODISCOVERY_DEPTH ?? String(defaultAutoDiscoveryDepth), 10);

  if (!Number.isFinite(parsed)) {
    return defaultAutoDiscoveryDepth;
  }

  return Math.min(Math.max(parsed, 1), 4);
}

function splitCsv(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function rootLabel(rootPath: string): string {
  const base = path.basename(rootPath);

  if (base === "projects") return "srv";
  if (base === "opt-projects") return "opt";

  return slugify(base || "projects");
}

function projectNameFromPath(relativePath: string): string {
  const parts = relativePath.split("/").filter(Boolean);
  return parts.join(" / ");
}

function inferDataClassification(projectPath: string): DataClassification {
  const normalized = projectPath.toLowerCase();
  return normalized.includes("apsyd") ? "health-data" : "sensitive";
}

function inferOwner(projectPath: string): string {
  const normalized = projectPath.toLowerCase();
  return normalized.includes("apsyd") ? "APSYD" : "STRATOS";
}

function sanitizePublicUrl(value: string | null | undefined): string | null {
  const normalized = normalizeNullableString(value);
  if (!normalized) return null;

  try {
    const parsed = new URL(normalized);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new ProjectRegistryError(400, "INVALID_PROJECT_PUBLIC_URL", "Project public URL must use http or https.");
    }
    parsed.username = "";
    parsed.password = "";
    parsed.hash = "";
    return parsed.toString();
  } catch (error) {
    if (error instanceof ProjectRegistryError) {
      throw error;
    }
    throw new ProjectRegistryError(400, "INVALID_PROJECT_PUBLIC_URL", "Project public URL must be a valid http or https URL.");
  }
}

function slugify(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.:-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function slugifyPath(value: string): string {
  return (
    value
      .split("/")
      .map((part) => slugify(part))
      .filter(Boolean)
      .join("_") || "project"
  );
}

async function inspectProject(projectPath: string): Promise<{
  technologyStack: string[];
  repositoryUrl: string | null;
  defaultBranch: string | null;
}> {
  const [files, repositoryUrl, defaultBranch] = await Promise.all([
    collectProjectFiles(projectPath),
    readGitRemoteUrl(projectPath),
    readGitDefaultBranch(projectPath)
  ]);

  return {
    technologyStack: detectTechnologyStack(files),
    repositoryUrl,
    defaultBranch
  };
}

async function collectProjectFiles(root: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(current: string, depth: number): Promise<void> {
    if (depth > maxStackDepth || files.length >= maxStackFiles) return;

    let entries: Dirent[];
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (files.length >= maxStackFiles) return;
      if (entry.name.includes("\0")) continue;
      if (entry.isDirectory() && ignoredStackDirs.has(entry.name)) continue;

      const fullPath = path.join(current, entry.name);
      const relativePath = path.relative(root, fullPath).split(path.sep).join("/");

      if (entry.isFile()) {
        files.push(relativePath);
        continue;
      }

      if (entry.isDirectory()) {
        await walk(fullPath, depth + 1);
      }
    }
  }

  await walk(root, 0);

  return files;
}

async function readGitRemoteUrl(projectPath: string): Promise<string | null> {
  try {
    const config = await readFile(path.join(projectPath, ".git", "config"), "utf8");
    const match = config.match(/^\s*url\s*=\s*(.+)$/m);
    return sanitizeRepositoryUrl(match?.[1] ?? null);
  } catch {
    return null;
  }
}

async function readGitDefaultBranch(projectPath: string): Promise<string | null> {
  try {
    const head = await readFile(path.join(projectPath, ".git", "HEAD"), "utf8");
    const match = head.trim().match(/^ref:\s+refs\/heads\/(.+)$/);
    return normalizeNullableString(match?.[1] ?? null);
  } catch {
    return null;
  }
}

function createProjectId(projectPath: string): string {
  return `project_${createHash("sha256").update(projectPath).digest("hex").slice(0, 16)}`;
}

function normalizeProjectId(value: string): string {
  const normalized = value.trim();

  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{1,119}$/.test(normalized)) {
    throw new ProjectRegistryError(
      400,
      "INVALID_PROJECT_ID",
      "Project ID must be 2-120 characters and contain only letters, numbers, dots, underscores, colons, or hyphens."
    );
  }

  return normalized;
}

function normalizeNullableString(value: string | null | undefined): string | null {
  const normalized = value?.trim();
  return normalized ? normalized : null;
}

function sanitizeRepositoryUrl(value: string | null | undefined): string | null {
  const normalized = normalizeNullableString(value);
  if (!normalized) return null;

  return normalized.replace(/^(https?:\/\/)[^/@]+@/i, "$1");
}
