import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import type { DataClassification, FindingType, ScanProfile } from "@security-preflight/core";

const execFileAsync = promisify(execFile);

export type ToolStatus = "available" | "missing" | "error";

export interface ToolCheckResult {
  name: string;
  command: string;
  status: ToolStatus;
  version: string | null;
  message: string | null;
}

export interface ToolchainDoctorResult {
  checkedAt: string;
  tools: ToolCheckResult[];
  summary: {
    available: number;
    missing: number;
    error: number;
  };
}

export const defaultToolChecks: Array<{ name: string; command: string; args: string[] }> = [
  { name: "Docker", command: "docker", args: ["--version"] },
  { name: "Docker Compose", command: "docker", args: ["compose", "version"] },
  { name: "Gitleaks", command: "gitleaks", args: ["version"] },
  { name: "Semgrep", command: "semgrep", args: ["--version"] },
  { name: "Trivy", command: "trivy", args: ["--version"] },
  { name: "Redocly", command: "npx", args: ["--yes", "@redocly/cli@latest", "--version"] }
];

export async function runToolchainDoctor(
  checks: Array<{ name: string; command: string; args: string[] }> = defaultToolChecks
): Promise<ToolchainDoctorResult> {
  const tools = await Promise.all(
    checks.map(async (check) => {
      try {
        const { stdout, stderr } = await execFileAsync(check.command, check.args, { timeout: 15_000 });
        const version = (stdout || stderr).trim().split("\n")[0] ?? null;

        return {
          name: check.name,
          command: [check.command, ...check.args].join(" "),
          status: "available" as const,
          version,
          message: null
        };
      } catch (error) {
        const nodeError = error as NodeJS.ErrnoException;
        const isMissing = nodeError.code === "ENOENT";

        return {
          name: check.name,
          command: [check.command, ...check.args].join(" "),
          status: isMissing ? ("missing" as const) : ("error" as const),
          version: null,
          message: nodeError.message
        };
      }
    })
  );

  return {
    checkedAt: new Date().toISOString(),
    tools,
    summary: {
      available: tools.filter((tool) => tool.status === "available").length,
      missing: tools.filter((tool) => tool.status === "missing").length,
      error: tools.filter((tool) => tool.status === "error").length
    }
  };
}

export type ScanExecutionMode = "container" | "internal";
export type ScanNetworkMode = "disabled" | "restricted";
export type ScanStepStatus = "planned" | "blocked";

export interface ScanProjectInput {
  id: string;
  name: string;
  path: string;
  dataClassification?: DataClassification;
}

export interface DastPolicyInput {
  targetUrl?: string | null;
  allowedHosts?: string[];
  excludedPaths?: string[];
  allowActiveScan?: boolean;
  allowProductionTargets?: boolean;
  timeoutSeconds?: number;
}

export interface DastGuardrailResult {
  allowed: boolean;
  host: string | null;
  normalizedTargetUrl: string | null;
  reasons: string[];
}

export interface ScanExecutionStep {
  id: string;
  checkId: string;
  tool: string;
  type: FindingType;
  status: ScanStepStatus;
  executionMode: ScanExecutionMode;
  command: string[] | null;
  timeoutSeconds: number;
  networkMode: ScanNetworkMode;
  evidencePaths: string[];
  projectMount: {
    sourcePath: string;
    targetPath: string;
    readOnly: boolean;
  };
  guardrails: {
    dropCapabilities: boolean;
    privileged: boolean;
    dockerSocket: boolean;
    activeDast: boolean;
  };
  blockedReasons: string[];
}

export interface ScanExecutionPlan {
  id: string;
  scanRunId: string;
  createdAt: string;
  project: ScanProjectInput;
  profile: {
    id: string;
    name: string;
    timeoutSeconds: number;
    allowActiveDast: boolean;
    allowProductionTargets: boolean;
  };
  blocked: boolean;
  blockedReasons: string[];
  evidenceRoot: string;
  policy: {
    defaultNetworkMode: ScanNetworkMode;
    allowedDastHosts: string[];
    activeDastTarget: string | null;
  };
  steps: ScanExecutionStep[];
}

export interface BuildScanExecutionPlanInput {
  scanRunId?: string;
  project: ScanProjectInput;
  profile: ScanProfile;
  dast?: DastPolicyInput;
  reportsRoot?: string;
}

interface CheckDefinition {
  tool: string;
  type: FindingType;
  executionMode: ScanExecutionMode;
  activeDast?: boolean;
  needsNetwork?: boolean;
  evidenceExtensions?: string[];
  buildCommand?: (context: CommandContext) => string[] | null;
}

interface CommandContext {
  checkId: string;
  evidenceBase: string;
  targetUrl: string | null;
  timeoutSeconds: number;
}

export const defaultDastAllowedHosts = ["localhost", "127.0.0.1", "host.docker.internal"];

const projectMountTarget = "/workspace/project";
const evidenceMountTarget = "/workspace/evidence";

const checkDefinitions: Record<string, CheckDefinition> = {
  "gitleaks:quick": {
    tool: "gitleaks",
    type: "secret",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => [
      "gitleaks",
      "detect",
      "--source",
      projectMountTarget,
      "--no-git",
      "--redact",
      "--report-format",
      "json",
      "--report-path",
      `${evidenceBase}.json`
    ]
  },
  gitleaks: {
    tool: "gitleaks",
    type: "secret",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => [
      "gitleaks",
      "detect",
      "--source",
      projectMountTarget,
      "--redact",
      "--report-format",
      "json",
      "--report-path",
      `${evidenceBase}.json`
    ]
  },
  "gitleaks:history": {
    tool: "gitleaks",
    type: "secret",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => [
      "gitleaks",
      "detect",
      "--source",
      projectMountTarget,
      "--redact",
      "--report-format",
      "json",
      "--report-path",
      `${evidenceBase}.json`
    ]
  },
  "semgrep:light": {
    tool: "semgrep",
    type: "sast",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => [
      "semgrep",
      "scan",
      "--config",
      "auto",
      "--json",
      "--output",
      `${evidenceBase}.json`,
      projectMountTarget
    ]
  },
  semgrep: {
    tool: "semgrep",
    type: "sast",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => [
      "semgrep",
      "scan",
      "--config",
      "auto",
      "--json",
      "--output",
      `${evidenceBase}.json`,
      projectMountTarget
    ]
  },
  "trivy:fs-quick": {
    tool: "trivy",
    type: "sca",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => ["trivy", "fs", "--format", "json", "--output", `${evidenceBase}.json`, projectMountTarget]
  },
  "trivy:fs": {
    tool: "trivy",
    type: "sca",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => ["trivy", "fs", "--format", "json", "--output", `${evidenceBase}.json`, projectMountTarget]
  },
  "trivy:image": {
    tool: "trivy",
    type: "container",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => [
      "trivy",
      "config",
      "--format",
      "json",
      "--output",
      `${evidenceBase}.json`,
      projectMountTarget
    ]
  },
  container: {
    tool: "trivy",
    type: "container",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => [
      "trivy",
      "config",
      "--format",
      "json",
      "--output",
      `${evidenceBase}.json`,
      projectMountTarget
    ]
  },
  dockerfile: {
    tool: "trivy",
    type: "container",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => [
      "trivy",
      "config",
      "--format",
      "json",
      "--output",
      `${evidenceBase}.json`,
      projectMountTarget
    ]
  },
  "container:misconfiguration": {
    tool: "trivy",
    type: "container",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => [
      "trivy",
      "config",
      "--format",
      "json",
      "--output",
      `${evidenceBase}.json`,
      projectMountTarget
    ]
  },
  "container:secrets": {
    tool: "trivy",
    type: "secret",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => [
      "trivy",
      "fs",
      "--scanners",
      "secret",
      "--format",
      "json",
      "--output",
      `${evidenceBase}.json`,
      projectMountTarget
    ]
  },
  "openapi:lint": {
    tool: "redocly",
    type: "openapi",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => [
      "npx",
      "--yes",
      "@redocly/cli@latest",
      "lint",
      `${projectMountTarget}/openapi/openapi.json`,
      "--format",
      "json",
      "--output",
      `${evidenceBase}.json`
    ]
  },
  "zap:baseline": {
    tool: "zap",
    type: "dast",
    executionMode: "container",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json", "html"],
    buildCommand: ({ evidenceBase, targetUrl, timeoutSeconds }) =>
      targetUrl
        ? [
            "zap-baseline.py",
            "-t",
            targetUrl,
            "-J",
            `${evidenceBase}.json`,
            "-r",
            `${evidenceBase}.html`,
            "-m",
            String(Math.ceil(timeoutSeconds / 60))
          ]
        : null
  }
};

const internalCheckTypes: Record<string, FindingType> = {
  documentation: "documentation",
  readme: "documentation",
  operations: "documentation",
  security: "documentation",
  observability: "documentation",
  runbook: "documentation",
  adr: "documentation",
  openapi: "openapi",
  "api:error-response": "openapi",
  "api:health": "configuration",
  "api:ready": "configuration",
  "env-example": "configuration",
  "forbidden-files": "configuration",
  sbom: "sca",
  "threat-model": "documentation",
  "data-classification": "configuration",
  "audit-logging": "configuration",
  auth: "configuration",
  encryption: "configuration",
  retention: "configuration",
  secrets: "secret"
};

export function evaluateDastGuardrails(input: DastPolicyInput & { profile: Pick<ScanProfile, "allowActiveDast" | "allowProductionTargets"> }): DastGuardrailResult {
  const reasons: string[] = [];
  const allowedHosts = normalizeAllowedHosts(input.allowedHosts);
  const activeScanAllowed = input.profile.allowActiveDast && input.allowActiveScan === true;

  if (!activeScanAllowed) {
    reasons.push("Active DAST must be explicitly enabled by both the scan profile and request.");
  }

  if (!input.targetUrl) {
    reasons.push("Active DAST requires an explicit targetUrl.");
    return { allowed: false, host: null, normalizedTargetUrl: null, reasons };
  }

  let url: URL;

  try {
    url = new URL(input.targetUrl);
  } catch {
    reasons.push("Active DAST targetUrl must be a valid URL.");
    return { allowed: false, host: null, normalizedTargetUrl: null, reasons };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    reasons.push("Active DAST targetUrl must use http or https.");
  }

  if (url.username || url.password) {
    reasons.push("Active DAST targetUrl must not include credentials.");
  }

  const host = url.hostname.toLowerCase();

  if (!isHostAllowed(host, allowedHosts)) {
    reasons.push(`Active DAST host '${host}' is not in the allowed host list.`);
  }

  const productionAllowed = input.profile.allowProductionTargets || input.allowProductionTargets === true;
  if (!productionAllowed && /(^|[.-])(prod|production)([.-]|$)/i.test(host)) {
    reasons.push("Active DAST production-like hostnames are blocked unless production targets are explicitly allowed.");
  }

  return {
    allowed: reasons.length === 0,
    host,
    normalizedTargetUrl: url.toString(),
    reasons
  };
}

export function buildScanExecutionPlan(input: BuildScanExecutionPlanInput): ScanExecutionPlan {
  const scanRunId = input.scanRunId ?? `scan_${Date.now().toString(36)}`;
  const reportsRoot = input.reportsRoot ?? "/reports";
  const evidenceRoot = path.posix.join(reportsRoot, scanRunId);
  const projectPath = normalizeProjectPath(input.project.path);
  const allowedDastHosts = normalizeAllowedHosts(input.dast?.allowedHosts);
  const dastGuardrails = evaluateDastGuardrails({
    ...input.dast,
    allowedHosts: allowedDastHosts,
    profile: input.profile
  });

  const steps = input.profile.checks.map((checkId, index) =>
    buildExecutionStep({
      checkId,
      sequence: index + 1,
      profile: input.profile,
      projectPath,
      evidenceRoot,
      dastGuardrails,
      dastTimeoutSeconds: input.dast?.timeoutSeconds
    })
  );
  const blockedReasons = [...new Set(steps.flatMap((step) => step.blockedReasons))];

  return {
    id: `plan_${scanRunId}`,
    scanRunId,
    createdAt: new Date().toISOString(),
    project: {
      ...input.project,
      path: projectPath,
      dataClassification: input.project.dataClassification ?? "internal"
    },
    profile: {
      id: input.profile.id,
      name: input.profile.name,
      timeoutSeconds: input.profile.timeoutSeconds,
      allowActiveDast: input.profile.allowActiveDast,
      allowProductionTargets: input.profile.allowProductionTargets
    },
    blocked: blockedReasons.length > 0,
    blockedReasons,
    evidenceRoot,
    policy: {
      defaultNetworkMode: "disabled",
      allowedDastHosts,
      activeDastTarget: dastGuardrails.normalizedTargetUrl
    },
    steps
  };
}

function buildExecutionStep(input: {
  checkId: string;
  sequence: number;
  profile: ScanProfile;
  projectPath: string;
  evidenceRoot: string;
  dastGuardrails: DastGuardrailResult;
  dastTimeoutSeconds?: number;
}): ScanExecutionStep {
  const definition = checkDefinitions[input.checkId] ?? createInternalDefinition(input.checkId);
  const evidenceBase = path.posix.join(evidenceMountTarget, sanitizeFilePart(input.checkId));
  const evidencePaths = (definition.evidenceExtensions ?? ["json"]).map((extension) =>
    path.posix.join(input.evidenceRoot, `${sanitizeFilePart(input.checkId)}.${extension}`)
  );
  const blockedReasons: string[] = [];

  if (definition.activeDast && !input.dastGuardrails.allowed) {
    blockedReasons.push(...input.dastGuardrails.reasons);
  }

  if (definition.tool === "unknown") {
    blockedReasons.push(`No scanner adapter is registered for check '${input.checkId}'.`);
  }

  const timeoutSeconds = definition.activeDast
    ? Math.min(input.dastTimeoutSeconds ?? input.profile.timeoutSeconds, input.profile.timeoutSeconds)
    : input.profile.timeoutSeconds;
  const command =
    blockedReasons.length > 0
      ? null
      : definition.buildCommand?.({
          checkId: input.checkId,
          evidenceBase,
          targetUrl: input.dastGuardrails.normalizedTargetUrl,
          timeoutSeconds
        }) ?? null;

  return {
    id: `step_${input.sequence.toString().padStart(2, "0")}_${sanitizeId(input.checkId)}`,
    checkId: input.checkId,
    tool: definition.tool,
    type: definition.type,
    status: blockedReasons.length > 0 ? "blocked" : "planned",
    executionMode: definition.executionMode,
    command,
    timeoutSeconds,
    networkMode: definition.needsNetwork ? "restricted" : "disabled",
    evidencePaths,
    projectMount: {
      sourcePath: input.projectPath,
      targetPath: projectMountTarget,
      readOnly: true
    },
    guardrails: {
      dropCapabilities: true,
      privileged: false,
      dockerSocket: false,
      activeDast: definition.activeDast === true
    },
    blockedReasons
  };
}

function createInternalDefinition(checkId: string): CheckDefinition {
  const type = internalCheckTypes[checkId];

  if (!type) {
    return {
      tool: "unknown",
      type: "tooling",
      executionMode: "internal",
      evidenceExtensions: ["json"]
    };
  }

  return {
    tool: "security-preflight",
    type,
    executionMode: "internal",
    evidenceExtensions: ["json"]
  };
}

function normalizeProjectPath(value: string): string {
  if (!value.trim() || value.includes("\0")) {
    throw new Error("Project path must be a non-empty path without null bytes.");
  }

  if (!path.isAbsolute(value)) {
    throw new Error("Project path must be absolute.");
  }

  return path.resolve(value);
}

function normalizeAllowedHosts(value: string[] | undefined): string[] {
  const normalized = (value && value.length > 0 ? value : defaultDastAllowedHosts)
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);

  return [...new Set(normalized)];
}

function isHostAllowed(host: string, allowedHosts: string[]): boolean {
  return allowedHosts.some((allowedHost) => {
    if (allowedHost.startsWith("*.")) {
      const suffix = allowedHost.slice(1);
      return host.endsWith(suffix) && host.length > suffix.length;
    }

    return host === allowedHost;
  });
}

function sanitizeFilePart(value: string): string {
  return sanitizeId(value).replaceAll("_", "-");
}

function sanitizeId(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "check";
}
