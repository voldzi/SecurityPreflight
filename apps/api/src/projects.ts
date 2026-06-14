import { createHash } from "node:crypto";
import type { Dirent } from "node:fs";
import { mkdir, readFile, readdir, rename, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { detectTechnologyStack, type DataClassification, type Project } from "@security-preflight/core";

const registrySchemaVersion = "security-preflight.projects.v1";
const maxStackFiles = 1500;
const maxStackDepth = 4;
const ignoredStackDirs = new Set([
  ".cache",
  ".git",
  ".next",
  ".turbo",
  ".venv",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "target"
]);

const projectSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  path: z.string().min(1),
  repositoryUrl: z.string().nullable(),
  defaultBranch: z.string().nullable(),
  technologyStack: z.array(z.string()),
  dataClassification: z.enum(["public", "internal", "confidential", "sensitive", "health-data"]),
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
  defaultBranch?: string | null;
  dataClassification?: DataClassification;
  owner?: string | null;
}

export interface ProjectUpdateInput {
  name?: string;
  path?: string;
  repositoryUrl?: string | null;
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

  return registry.projects.sort((left, right) => left.name.localeCompare(right.name, "en"));
}

export async function getProject(projectId: string): Promise<Project | null> {
  const registry = await readRegistry();

  return registry.projects.find((project) => project.id === projectId) ?? null;
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
  const project: Project = {
    id,
    name: input.name.trim(),
    path: normalizedPath,
    repositoryUrl: sanitizeRepositoryUrl(input.repositoryUrl ?? detected.repositoryUrl),
    defaultBranch: normalizeNullableString(input.defaultBranch ?? detected.defaultBranch),
    technologyStack: detected.technologyStack,
    dataClassification: input.dataClassification ?? "internal",
    owner: normalizeNullableString(input.owner),
    createdAt: now,
    updatedAt: now
  };

  registry.projects.push(project);
  await writeRegistry(registry.projects);

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
  const next: Project = {
    ...current,
    name: input.name?.trim() ?? current.name,
    path: nextPath,
    repositoryUrl: sanitizeRepositoryUrl(input.repositoryUrl !== undefined ? input.repositoryUrl : (detected?.repositoryUrl ?? current.repositoryUrl)),
    defaultBranch: normalizeNullableString(input.defaultBranch !== undefined ? input.defaultBranch : (detected?.defaultBranch ?? current.defaultBranch)),
    technologyStack: detected?.technologyStack ?? current.technologyStack,
    dataClassification: input.dataClassification ?? current.dataClassification,
    owner: input.owner !== undefined ? normalizeNullableString(input.owner) : current.owner,
    updatedAt: new Date().toISOString()
  };

  registry.projects[projectIndex] = next;
  await writeRegistry(registry.projects);

  return next;
}

export async function deleteProject(projectId: string): Promise<boolean> {
  const registry = await readRegistry();
  const nextProjects = registry.projects.filter((project) => project.id !== projectId);

  if (nextProjects.length === registry.projects.length) {
    return false;
  }

  await writeRegistry(nextProjects);

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
  const root = process.env.PROJECTS_ROOT_CONTAINER?.trim();

  if (root) {
    const normalizedRoot = path.resolve(root);
    const relative = path.relative(normalizedRoot, normalizedPath);
    const insideRoot = relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));

    if (!insideRoot) {
      throw new ProjectRegistryError(400, "PROJECT_PATH_OUTSIDE_ROOT", `Project path must be inside ${normalizedRoot}.`);
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
