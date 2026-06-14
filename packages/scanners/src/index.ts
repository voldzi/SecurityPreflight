import { execFile } from "node:child_process";
import { createPublicKey, createVerify, verify as verifyDetachedSignature } from "node:crypto";
import dns from "node:dns/promises";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import tls from "node:tls";
import { promisify } from "node:util";
import {
  createFindingFingerprint,
  evaluateGate,
  requiredScannerTools,
  redactSecrets,
  type DataClassification,
  type Finding,
  type FindingType,
  type GateEvaluation,
  type ScanProfile,
  type ToolRequirement,
  type Severity
} from "@security-preflight/core";

const execFileAsync = promisify(execFile);

export type ToolStatus = "available" | "missing" | "error";

export interface ToolCheckResult {
  id: string;
  name: string;
  category: ToolRequirement["category"];
  requiredForHealthcare: boolean;
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
    healthcareAvailable: number;
    healthcareMissing: number;
    healthcareError: number;
    optionalAvailable: number;
    optionalMissing: number;
    optionalError: number;
  };
}

export type ToolCheckDefinition = Pick<ToolRequirement, "id" | "name" | "category" | "requiredForHealthcare" | "command" | "args">;

export const defaultToolChecks: ToolCheckDefinition[] = [
  ...requiredScannerTools.map((tool) => ({
    id: tool.id,
    name: tool.name,
    category: tool.category,
    requiredForHealthcare: tool.requiredForHealthcare,
    command: tool.command,
    args: tool.args
  }))
];

export async function runToolchainDoctor(checks: ToolCheckDefinition[] = defaultToolChecks): Promise<ToolchainDoctorResult> {
  const tools = await Promise.all(
    checks.map(async (check) => {
      try {
        const { stdout, stderr } = await execFileAsync(check.command, check.args, { timeout: 15_000 });
        const version = (stdout || stderr).trim().split("\n")[0] ?? null;

        return {
          id: check.id,
          name: check.name,
          category: check.category,
          requiredForHealthcare: check.requiredForHealthcare,
          command: [check.command, ...check.args].join(" "),
          status: "available" as const,
          version,
          message: null
        };
      } catch (error) {
        const nodeError = error as NodeJS.ErrnoException;
        const isMissing = nodeError.code === "ENOENT";

        return {
          id: check.id,
          name: check.name,
          category: check.category,
          requiredForHealthcare: check.requiredForHealthcare,
          command: [check.command, ...check.args].join(" "),
          status: isMissing ? ("missing" as const) : ("error" as const),
          version: null,
          message: nodeError.message
        };
      }
    })
  );
  const healthcareTools = tools.filter((tool) => tool.requiredForHealthcare);
  const optionalTools = tools.filter((tool) => !tool.requiredForHealthcare);
  const countStatus = (items: ToolCheckResult[], status: ToolStatus) => items.filter((tool) => tool.status === status).length;

  return {
    checkedAt: new Date().toISOString(),
    tools,
    summary: {
      available: countStatus(tools, "available"),
      missing: countStatus(tools, "missing"),
      error: countStatus(tools, "error"),
      healthcareAvailable: countStatus(healthcareTools, "available"),
      healthcareMissing: countStatus(healthcareTools, "missing"),
      healthcareError: countStatus(healthcareTools, "error"),
      optionalAvailable: countStatus(optionalTools, "available"),
      optionalMissing: countStatus(optionalTools, "missing"),
      optionalError: countStatus(optionalTools, "error")
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
    failThreshold: Exclude<Severity, "info">;
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
  "dns:records": {
    tool: "security-preflight-web-probe",
    type: "configuration",
    executionMode: "internal",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json"]
  },
  "tls:certificate": {
    tool: "security-preflight-web-probe",
    type: "configuration",
    executionMode: "internal",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json"]
  },
  "tls:configuration": {
    tool: "security-preflight-web-probe",
    type: "configuration",
    executionMode: "internal",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json"]
  },
  "ports:common": {
    tool: "security-preflight-web-probe",
    type: "configuration",
    executionMode: "internal",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json"]
  },
  "http:security-headers": {
    tool: "security-preflight-web-probe",
    type: "configuration",
    executionMode: "internal",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json"]
  },
  "endpoint:admin": {
    tool: "security-preflight-web-probe",
    type: "dast",
    executionMode: "internal",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json"]
  },
  "endpoint:debug": {
    tool: "security-preflight-web-probe",
    type: "dast",
    executionMode: "internal",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json"]
  },
  "api:discovery": {
    tool: "security-preflight-web-probe",
    type: "dast",
    executionMode: "internal",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json"]
  },
  "waf:behavior": {
    tool: "security-preflight-web-probe",
    type: "configuration",
    executionMode: "internal",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json"]
  },
  "openapi:runtime-safe": {
    tool: "security-preflight-api-probe",
    type: "openapi",
    executionMode: "internal",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json"]
  },
  "external-runner:vps": {
    tool: "security-preflight-external-runner",
    type: "configuration",
    executionMode: "internal",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json", "job.json", "response.json"]
  },
  "defectdojo:export": {
    tool: "security-preflight-defectdojo",
    type: "configuration",
    executionMode: "internal",
    needsNetwork: true,
    evidenceExtensions: ["json"]
  },
  "greenbone:openvas": {
    tool: "greenbone",
    type: "dast",
    executionMode: "internal",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json", "xml"]
  },
  "openscap:system": {
    tool: "openscap",
    type: "configuration",
    executionMode: "internal",
    evidenceExtensions: ["json", "xml", "html"]
  },
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
  "syft:sbom": {
    tool: "syft",
    type: "sca",
    executionMode: "container",
    evidenceExtensions: ["cyclonedx.json"],
    buildCommand: ({ evidenceBase }) => [
      "syft",
      projectMountTarget,
      "-o",
      "cyclonedx-json",
      "--file",
      `${evidenceBase}.cyclonedx.json`
    ]
  },
  "grype:sbom": {
    tool: "grype",
    type: "sca",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => ["grype", projectMountTarget, "-o", "json", "--file", `${evidenceBase}.json`]
  },
  "osv:dependencies": {
    tool: "osv-scanner",
    type: "sca",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => ["osv-scanner", "--format", "json", "--output", `${evidenceBase}.json`, projectMountTarget]
  },
  "iac:checkov": {
    tool: "checkov",
    type: "iac",
    executionMode: "container",
    evidenceExtensions: ["json"],
    buildCommand: ({ evidenceBase }) => ["checkov", "-d", projectMountTarget, "-o", "json", "--output-file-path", `${evidenceBase}.json`]
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
  },
  "zap:api-scan": {
    tool: "zap",
    type: "dast",
    executionMode: "container",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["json", "html"],
    buildCommand: ({ evidenceBase, timeoutSeconds }) => [
      "zap-api-scan.py",
      "-t",
      `${projectMountTarget}/openapi/openapi.json`,
      "-f",
      "openapi",
      "-J",
      `${evidenceBase}.json`,
      "-r",
      `${evidenceBase}.html`,
      "-m",
      String(Math.ceil(timeoutSeconds / 60))
    ]
  },
  "nuclei:safe": {
    tool: "nuclei",
    type: "dast",
    executionMode: "container",
    activeDast: true,
    needsNetwork: true,
    evidenceExtensions: ["jsonl"],
    buildCommand: ({ evidenceBase, targetUrl }) =>
      targetUrl
        ? [
            "nuclei",
            "-u",
            targetUrl,
            "-templates",
            "/opt/nuclei-templates",
            "-jsonl",
            "-o",
            `${evidenceBase}.jsonl`,
            "-severity",
            "low,medium,high,critical",
            "-tags",
            "exposure,misconfig,tech,headers,tls,dns",
            "-rl",
            "3",
            "-bs",
            "1",
            "-retries",
            "0",
            "-timeout",
            "8",
            "-duc",
            "-no-color"
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
  "privacy-impact": "documentation",
  "audit-logging": "configuration",
  auth: "configuration",
  authorization: "configuration",
  encryption: "configuration",
  retention: "configuration",
  "logging-redaction": "configuration",
  "telemetry-export": "configuration",
  "license-policy": "configuration",
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
      failThreshold: input.profile.failThreshold,
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

export type ScanExecutionStatus = "completed" | "failed";
export type ScanStepExecutionStatus = "passed" | "failed" | "skipped" | "blocked" | "error";

export interface ScanStepExecutionResult {
  stepId: string;
  checkId: string;
  status: ScanStepExecutionStatus;
  startedAt: string;
  finishedAt: string;
  evidencePath: string;
  findings: Finding[];
  message: string;
}

export interface ScanExecutionResult {
  scanRunId: string;
  status: ScanExecutionStatus;
  startedAt: string;
  finishedAt: string;
  evidenceRoot: string;
  stepResults: ScanStepExecutionResult[];
  findings: Finding[];
  gate: GateEvaluation;
}

export type ExternalRunnerMode = "direct" | "docker" | "remote";

export interface ExecuteScanPlanOptions {
  runExternalCommands?: boolean;
  treatSkippedExternalChecksAsFindings?: boolean;
  externalRunner?: ExternalRunnerMode;
  scannerImage?: string;
  dockerCommand?: string;
}

interface CommandRunResult {
  runner: ExternalRunnerMode;
  command: string[];
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
  errorMessage: string | null;
}

const mandatoryDocumentationFiles = [
  "README.md",
  "AGENTS.md",
  "CLAUDE.md",
  ".env.example",
  "docs/README.md",
  "docs/architecture.md",
  "docs/api.md",
  "docs/security.md",
  "docs/operations.md",
  "docs/observability.md",
  "docs/runbook.md"
];

const singleDocumentChecks: Record<string, string[]> = {
  readme: ["README.md"],
  operations: ["docs/operations.md"],
  security: ["docs/security.md"],
  observability: ["docs/observability.md"],
  runbook: ["docs/runbook.md"],
  adr: ["docs/adr"]
};

const ignoredWalkSegments = new Set([
  ".git",
  ".next",
  ".chroma-state",
  ".turbo",
  "coverage",
  "dist",
  "build",
  "node_modules"
]);

const forbiddenFileNames = new Set([".env", ".env.local", ".env.production", "id_rsa", "id_dsa"]);
const forbiddenFileExtensions = new Set([".key", ".p12", ".pfx", ".pem"]);
const adminEndpointPaths = [
  "/admin",
  "/administrator",
  "/login",
  "/manage",
  "/manager",
  "/console",
  "/wp-admin",
  "/strapi/admin",
  "/keycloak",
  "/grafana"
];
const debugEndpointPaths = [
  "/debug",
  "/_debug",
  "/__debug",
  "/metrics",
  "/actuator",
  "/actuator/env",
  "/actuator/heapdump",
  "/server-status",
  "/phpinfo.php",
  "/trace"
];
const apiDiscoveryPaths = [
  "/openapi.json",
  "/swagger.json",
  "/v3/api-docs",
  "/api-docs",
  "/swagger",
  "/swagger-ui",
  "/docs",
  "/redoc",
  "/graphql",
  "/graphiql"
];
const commonPortChecks = [
  { port: 22, service: "SSH", severity: "medium" as const },
  { port: 80, service: "HTTP", severity: "info" as const },
  { port: 443, service: "HTTPS", severity: "info" as const },
  { port: 2375, service: "Docker API", severity: "critical" as const },
  { port: 3000, service: "development web server", severity: "medium" as const },
  { port: 3306, service: "MySQL/MariaDB", severity: "high" as const },
  { port: 5432, service: "PostgreSQL", severity: "high" as const },
  { port: 5672, service: "AMQP", severity: "high" as const },
  { port: 6379, service: "Redis", severity: "critical" as const },
  { port: 8080, service: "alternate HTTP/admin", severity: "medium" as const },
  { port: 8081, service: "alternate HTTP/admin", severity: "medium" as const },
  { port: 8443, service: "alternate HTTPS/admin", severity: "medium" as const },
  { port: 9200, service: "Elasticsearch", severity: "high" as const },
  { port: 9300, service: "Elasticsearch transport", severity: "high" as const },
  { port: 15672, service: "RabbitMQ management", severity: "high" as const },
  { port: 27017, service: "MongoDB", severity: "high" as const }
];

export async function executeScanPlan(
  plan: ScanExecutionPlan,
  options: ExecuteScanPlanOptions = {}
): Promise<ScanExecutionResult> {
  const startedAt = new Date().toISOString();
  await mkdir(plan.evidenceRoot, { recursive: true });

  if (plan.blocked) {
    const stepResults = await Promise.all(plan.steps.map((step) => writeBlockedStepEvidence(plan, step)));
    const findings = stepResults.flatMap((result) => result.findings);
    const gate = evaluateGate(findings, plan.profile, plan.project.dataClassification ?? "internal");

    return {
      scanRunId: plan.scanRunId,
      status: "failed",
      startedAt,
      finishedAt: new Date().toISOString(),
      evidenceRoot: plan.evidenceRoot,
      stepResults,
      findings,
      gate
    };
  }

  const stepResults: ScanStepExecutionResult[] = [];

  for (const step of plan.steps) {
    stepResults.push(await executeStep(plan, step, options));
  }

  const findings = stepResults.flatMap((result) => result.findings);
  const gate = evaluateGate(findings, plan.profile, plan.project.dataClassification ?? "internal");
  const hasErrors = stepResults.some((result) => result.status === "error" || result.status === "blocked");

  return {
    scanRunId: plan.scanRunId,
    status: hasErrors ? "failed" : "completed",
    startedAt,
    finishedAt: new Date().toISOString(),
    evidenceRoot: plan.evidenceRoot,
    stepResults,
    findings,
    gate
  };
}

async function executeStep(
  plan: ScanExecutionPlan,
  step: ScanExecutionStep,
  options: ExecuteScanPlanOptions
): Promise<ScanStepExecutionResult> {
  const startedAt = new Date().toISOString();
  const evidencePath = stepResultEvidencePath(step);

  try {
    if (step.executionMode === "internal") {
      const findings = await runInternalCheck(plan, step);
      const result: ScanStepExecutionResult = {
        stepId: step.id,
        checkId: step.checkId,
        status: findings.length > 0 ? "failed" : "passed",
        startedAt,
        finishedAt: new Date().toISOString(),
        evidencePath,
        findings,
        message: findings.length > 0 ? "Internal check produced findings." : "Internal check passed."
      };
      await writeStepEvidence(plan, step, result);
      return result;
    }

    if (!step.command || step.status === "blocked") {
      const result: ScanStepExecutionResult = {
        stepId: step.id,
        checkId: step.checkId,
        status: "blocked",
        startedAt,
        finishedAt: new Date().toISOString(),
        evidencePath,
        findings: [
          createExecutionFinding(plan, step, {
            severity: "high",
            title: `Scanner step '${step.checkId}' was blocked by guardrails`,
            description: step.blockedReasons.join(" ") || "The scanner step has no executable command.",
            recommendation: "Adjust the scan request or profile so guardrails allow this step."
          })
        ],
        message: step.blockedReasons.join(" ") || "External scanner command is not available."
      };
      await writeStepEvidence(plan, step, result);
      return result;
    }

    if (!options.runExternalCommands) {
      const findings =
        options.treatSkippedExternalChecksAsFindings ?? true
          ? [
              createExecutionFinding(plan, step, {
                severity: "high",
                title: `Scanner step '${step.checkId}' was not executed`,
                description:
                  "The execution adapter for external scanner commands is disabled. Production evidence requires this step to run in an isolated scanner runner.",
                recommendation: "Enable an isolated scanner runner for this tool before relying on the scan result."
              })
            ]
          : [];
      const result: ScanStepExecutionResult = {
        stepId: step.id,
        checkId: step.checkId,
        status: "skipped",
        startedAt,
        finishedAt: new Date().toISOString(),
        evidencePath,
        findings,
        message: "External scanner command was skipped by execution policy."
      };
      await writeStepEvidence(plan, step, result);
      return result;
    }

    const commandResult = await runExternalScannerCommand(plan, step, options);
    await writeExternalCommandEvidence(plan, step, commandResult);
    const findings = await parseExternalFindings(plan, step, commandResult);
    const executionFinding =
      commandResult.timedOut || (commandResult.exitCode !== 0 && findings.length === 0)
        ? createExecutionFinding(plan, step, {
            severity: "high",
            title: `Scanner step '${step.checkId}' failed`,
            description:
              commandResult.errorMessage ||
              firstNonEmptyLine(commandResult.stderr) ||
              firstNonEmptyLine(commandResult.stdout) ||
              `Scanner exited with code ${commandResult.exitCode ?? "unknown"}.`,
            recommendation: "Inspect command evidence and rerun after fixing the scanner or project configuration.",
            evidence: [commandResult.stderr, commandResult.stdout].filter(Boolean).join("\n")
          })
        : null;
    const allFindings = executionFinding ? [...findings, executionFinding] : findings;
    const result: ScanStepExecutionResult = {
      stepId: step.id,
      checkId: step.checkId,
      status: commandResult.timedOut || commandResult.exitCode !== 0 ? "failed" : allFindings.length > 0 ? "failed" : "passed",
      startedAt,
      finishedAt: new Date().toISOString(),
      evidencePath,
      findings: allFindings,
      message:
        commandResult.exitCode === 0
          ? allFindings.length > 0
            ? "External scanner completed and produced findings."
            : "External scanner completed without findings."
          : "External scanner completed with a non-zero exit status."
    };
    await writeStepEvidence(plan, step, result);
    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const result: ScanStepExecutionResult = {
      stepId: step.id,
      checkId: step.checkId,
      status: "error",
      startedAt,
      finishedAt: new Date().toISOString(),
      evidencePath,
      findings: [
        createExecutionFinding(plan, step, {
          severity: "high",
          title: `Scanner step '${step.checkId}' failed`,
          description: message,
          recommendation: "Inspect step evidence and rerun after fixing the scanner or project configuration."
        })
      ],
      message
    };
    await writeStepEvidence(plan, step, result);
    return result;
  }
}

async function writeBlockedStepEvidence(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<ScanStepExecutionResult> {
  const now = new Date().toISOString();
  const blocked = step.blockedReasons.length > 0;
  const result: ScanStepExecutionResult = {
    stepId: step.id,
    checkId: step.checkId,
    status: blocked ? "blocked" : "skipped",
    startedAt: now,
    finishedAt: now,
    evidencePath: stepResultEvidencePath(step),
    findings: blocked
      ? [
          createExecutionFinding(plan, step, {
            severity: "high",
            title: `Scanner step '${step.checkId}' was blocked by guardrails`,
            description: step.blockedReasons.join(" "),
            recommendation: "Adjust the scan request or profile so guardrails allow this step."
          })
        ]
      : [],
    message: blocked ? step.blockedReasons.join(" ") : "Plan execution halted because another step was blocked by guardrails."
  };
  await writeStepEvidence(plan, step, result);
  return result;
}

async function runExternalScannerCommand(
  plan: ScanExecutionPlan,
  step: ScanExecutionStep,
  options: ExecuteScanPlanOptions
): Promise<CommandRunResult> {
  const runner = options.externalRunner ?? resolveExternalRunnerMode();

  if (runner === "remote") {
    return runRemoteScannerCommand(plan, step);
  }

  if (runner === "docker") {
    return runDockerScannerCommand(plan, step, options);
  }

  return runDirectScannerCommand(plan, step);
}

function resolveExternalRunnerMode(): ExternalRunnerMode {
  if (process.env.SCANNER_RUNNER_MODE === "docker") {
    return "docker";
  }

  if (process.env.SCANNER_RUNNER_MODE === "remote") {
    return "remote";
  }

  return "direct";
}

async function runRemoteScannerCommand(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<CommandRunResult> {
  if (!step.command?.[0]) {
    return emptyCommandFailure("remote", [], "Scanner command is missing.");
  }

  if (!["zap", "nuclei"].includes(step.tool)) {
    return emptyCommandFailure(
      "remote",
      step.command,
      `Remote scanner mode only supports web-target scanner tools; '${step.tool}' requires local project access.`
    );
  }

  const endpoint = process.env.SECURITY_PREFLIGHT_EXTERNAL_SCANNER_URL?.trim();
  const token = await resolveSecretReference(process.env.SECURITY_PREFLIGHT_EXTERNAL_SCANNER_TOKEN_REF);

  if (!endpoint) {
    return emptyCommandFailure("remote", step.command, "SECURITY_PREFLIGHT_EXTERNAL_SCANNER_URL is not configured.");
  }

  const requestedAt = new Date().toISOString();
  const payload = {
    schemaVersion: "security-preflight.external-command.v1",
    jobId: `${plan.scanRunId}:${step.id}`,
    requestedAt,
    scanRunId: plan.scanRunId,
    project: {
      id: plan.project.id,
      name: plan.project.name,
      dataClassification: plan.project.dataClassification ?? "internal"
    },
    step: {
      id: step.id,
      checkId: step.checkId,
      tool: step.tool,
      timeoutSeconds: step.timeoutSeconds,
      command: step.command,
      evidenceExtensions: step.evidencePaths.map((evidencePath) => path.extname(evidencePath).replace(/^\./, ""))
    },
    target: {
      url: plan.policy.activeDastTarget,
      allowedHosts: plan.policy.allowedDastHosts
    },
    policy: {
      activeDast: step.guardrails.activeDast,
      networkMode: step.networkMode,
      noSourceUpload: true
    }
  };

  await writeFile(supplementalEvidencePath(step, "job"), `${redactSecrets(JSON.stringify(payload, null, 2))}\n`, "utf8");

  const startedAt = Date.now();
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "user-agent": "SecurityPreflight/0.1 external-runner",
        ...(token.ok ? { authorization: `Bearer ${token.value}` } : {})
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(step.timeoutSeconds * 1000)
    });
    const responseText = await response.text();
    await writeFile(supplementalEvidencePath(step, "response"), `${redactSecrets(responseText)}\n`, "utf8");

    if (!response.ok) {
      return {
        runner: "remote",
        command: step.command,
        exitCode: response.status,
        signal: null,
        timedOut: false,
        stdout: "",
        stderr: responseText,
        errorMessage: `External scanner returned HTTP ${response.status}.`
      };
    }

    const responseJson = parseJson(responseText);
    const payloadRecord = extractSignedPayload(responseJson);
    const signatureRequired = process.env.SECURITY_PREFLIGHT_EXTERNAL_SCANNER_REQUIRE_SIGNATURE !== "false";
    const publicKey = process.env.SECURITY_PREFLIGHT_EXTERNAL_SCANNER_PUBLIC_KEY?.trim();

    if (signatureRequired) {
      const signatureCheck = verifyRemotePayloadSignature(responseJson, publicKey);
      if (!signatureCheck.ok) {
        return {
          runner: "remote",
          command: step.command,
          exitCode: null,
          signal: null,
          timedOut: false,
          stdout: responseText,
          stderr: "",
          errorMessage: signatureCheck.error
        };
      }
    }

    await writeRemoteEvidenceFiles(step, payloadRecord);
    const resultRecord = asRecord(payloadRecord.result ?? payloadRecord.commandResult ?? payloadRecord);
    const durationMs = Date.now() - startedAt;

    return {
      runner: "remote",
      command: stringArrayValue(resultRecord.command) ?? step.command,
      exitCode: numberValue(resultRecord.exitCode) ?? (numberValue(resultRecord.statusCode) ?? 0),
      signal: stringValue(resultRecord.signal),
      timedOut: Boolean(resultRecord.timedOut),
      stdout: stringValue(resultRecord.stdout) ?? `External scanner completed in ${durationMs} ms.`,
      stderr: stringValue(resultRecord.stderr) ?? "",
      errorMessage: stringValue(resultRecord.errorMessage)
    };
  } catch (error) {
    return {
      runner: "remote",
      command: step.command,
      exitCode: null,
      signal: null,
      timedOut: error instanceof Error && error.name === "TimeoutError",
      stdout: "",
      stderr: "",
      errorMessage: error instanceof Error ? error.message : String(error)
    };
  }
}

async function runDirectScannerCommand(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<CommandRunResult> {
  if (!step.command?.[0]) {
    return emptyCommandFailure("direct", [], "Scanner command is missing.");
  }

  const command = materializeDirectCommand(plan, step);
  return runCommand("direct", command, {
    cwd: step.projectMount.sourcePath,
    timeoutSeconds: step.timeoutSeconds
  });
}

async function runDockerScannerCommand(
  plan: ScanExecutionPlan,
  step: ScanExecutionStep,
  options: ExecuteScanPlanOptions
): Promise<CommandRunResult> {
  if (!step.command?.[0]) {
    return emptyCommandFailure("docker", [], "Scanner command is missing.");
  }

  const dockerCommand = options.dockerCommand ?? process.env.DOCKER_COMMAND ?? "docker";
  const scannerImage =
    step.tool === "zap"
      ? process.env.ZAP_DOCKER_IMAGE ?? "ghcr.io/zaproxy/zaproxy:stable"
      : options.scannerImage ?? process.env.SCANNER_TOOLBOX_IMAGE ?? "security-preflight/scanner-toolbox:local";
  const networkMode =
    step.networkMode === "restricted"
      ? process.env.SCANNER_RESTRICTED_NETWORK_MODE ?? "bridge"
      : process.env.SCANNER_DISABLED_NETWORK_MODE ?? "none";
  const command = [
    dockerCommand,
    "run",
    "--rm",
    "--network",
    networkMode,
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--read-only",
    "--tmpfs",
    "/tmp:rw,nosuid,nodev,size=512m",
    "--tmpfs",
    "/home/scanner/.cache:rw,nosuid,nodev,size=512m",
    "--volume",
    `${step.projectMount.sourcePath}:${projectMountTarget}:ro`,
    "--volume",
    `${plan.evidenceRoot}:${evidenceMountTarget}:rw`,
    "--workdir",
    "/workspace",
    scannerImage,
    ...step.command
  ];

  return runCommand("docker", command, {
    cwd: plan.project.path,
    timeoutSeconds: step.timeoutSeconds + 30
  });
}

function materializeDirectCommand(plan: ScanExecutionPlan, step: ScanExecutionStep): string[] {
  return (step.command ?? []).map((argument) =>
    argument.replaceAll(projectMountTarget, step.projectMount.sourcePath).replaceAll(evidenceMountTarget, plan.evidenceRoot)
  );
}

async function runCommand(
  runner: ExternalRunnerMode,
  command: string[],
  options: { cwd: string; timeoutSeconds: number }
): Promise<CommandRunResult> {
  const [executable, ...args] = command;

  if (!executable) {
    return emptyCommandFailure(runner, command, "Scanner command is missing.");
  }

  try {
    const { stdout, stderr } = await execFileAsync(executable, args, {
      cwd: options.cwd,
      encoding: "utf8",
      env: {
        ...process.env,
        CI: "true",
        NO_COLOR: "1",
        SEMGREP_SEND_METRICS: "off",
        TRIVY_NO_PROGRESS: "true",
        CHECKOV_NO_GUIDE: "true"
      },
      maxBuffer: 16 * 1024 * 1024,
      timeout: options.timeoutSeconds * 1000
    });

    return {
      runner,
      command,
      exitCode: 0,
      signal: null,
      timedOut: false,
      stdout: String(stdout ?? ""),
      stderr: String(stderr ?? ""),
      errorMessage: null
    };
  } catch (error) {
    const nodeError = error as NodeJS.ErrnoException & {
      stdout?: string | Buffer;
      stderr?: string | Buffer;
      code?: string | number;
      signal?: string;
      killed?: boolean;
    };
    const code = typeof nodeError.code === "number" ? nodeError.code : null;
    const timedOut = nodeError.killed === true || nodeError.signal === "SIGTERM";

    return {
      runner,
      command,
      exitCode: code,
      signal: nodeError.signal ?? null,
      timedOut,
      stdout: bufferToString(nodeError.stdout),
      stderr: bufferToString(nodeError.stderr),
      errorMessage: nodeError.message
    };
  }
}

function emptyCommandFailure(runner: ExternalRunnerMode, command: string[], message: string): CommandRunResult {
  return {
    runner,
    command,
    exitCode: null,
    signal: null,
    timedOut: false,
    stdout: "",
    stderr: "",
    errorMessage: message
  };
}

async function writeExternalCommandEvidence(
  plan: ScanExecutionPlan,
  step: ScanExecutionStep,
  result: CommandRunResult
): Promise<void> {
  const payload = {
    scanRunId: plan.scanRunId,
    stepId: step.id,
    checkId: step.checkId,
    tool: step.tool,
    runner: result.runner,
    command: result.command,
    exitCode: result.exitCode,
    signal: result.signal,
    timedOut: result.timedOut,
    generatedEvidencePaths: await existingEvidencePaths(step.evidencePaths),
    stdout: truncateEvidence(result.stdout),
    stderr: truncateEvidence(result.stderr),
    errorMessage: result.errorMessage
  };

  await writeFile(commandEvidencePath(step), `${redactSecrets(JSON.stringify(payload, null, 2))}\n`, "utf8");
}

async function parseExternalFindings(
  plan: ScanExecutionPlan,
  step: ScanExecutionStep,
  commandResult: CommandRunResult
): Promise<Finding[]> {
  const documents = await readJsonEvidenceDocuments(step, commandResult);

  if (documents.length === 0) {
    return [];
  }

  switch (step.tool) {
    case "gitleaks":
      return documents.flatMap((document) => parseGitleaksFindings(plan, step, document));
    case "semgrep":
      return documents.flatMap((document) => parseSemgrepFindings(plan, step, document));
    case "trivy":
      return documents.flatMap((document) => parseTrivyFindings(plan, step, document));
    case "grype":
      return documents.flatMap((document) => parseGrypeFindings(plan, step, document));
    case "osv-scanner":
      return documents.flatMap((document) => parseOsvFindings(plan, step, document));
    case "checkov":
      return documents.flatMap((document) => parseCheckovFindings(plan, step, document));
    case "redocly":
      return documents.flatMap((document) => parseRedoclyFindings(plan, step, document));
    case "zap":
      return documents.flatMap((document) => parseZapFindings(plan, step, document));
    case "nuclei":
      return documents.flatMap((document) => parseNucleiFindings(plan, step, document));
    default:
      return [];
  }
}

async function readJsonEvidenceDocuments(step: ScanExecutionStep, commandResult: CommandRunResult): Promise<unknown[]> {
  const documents: unknown[] = [];

  for (const evidencePath of step.evidencePaths) {
    if (evidencePath.endsWith(".jsonl")) {
      try {
        const lines = (await readFile(evidencePath, "utf8"))
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean);

        for (const line of lines) {
          documents.push(JSON.parse(line));
        }
      } catch {
        // JSONL parse failures are represented by command metadata.
      }
      continue;
    }

    if (!evidencePath.endsWith(".json")) {
      continue;
    }

    try {
      documents.push(JSON.parse(await readFile(evidencePath, "utf8")));
    } catch {
      // Some tools only write evidence on findings. Command metadata remains available.
    }
  }

  if (documents.length === 0) {
    const inline = commandResult.stdout.trim();

    if (inline.startsWith("{") || inline.startsWith("[")) {
      try {
        documents.push(JSON.parse(inline));
      } catch {
        // Non-JSON stdout is retained in command evidence.
      }
    }
  }

  return documents;
}

function parseGitleaksFindings(plan: ScanExecutionPlan, step: ScanExecutionStep, document: unknown): Finding[] {
  const leaks = Array.isArray(document) ? document : [];

  return leaks.map((leak) => {
    const item = asRecord(leak);
    const ruleId = stringValue(item.RuleID) ?? stringValue(item.ruleId) ?? step.checkId;
    const filePath = normalizeExternalFilePath(plan, stringValue(item.File) ?? stringValue(item.file));

    return createExecutionFinding(plan, step, {
      severity: "critical",
      title: `Secret detected by ${ruleId}`,
      description: stringValue(item.Description) ?? "Gitleaks detected a secret-like value.",
      filePath,
      line: numberValue(item.StartLine) ?? numberValue(item.startLine),
      ruleId,
      recommendation: "Remove the secret, rotate the credential, and keep the replacement outside Git.",
      evidence: JSON.stringify(redactObject(item))
    });
  });
}

function parseSemgrepFindings(plan: ScanExecutionPlan, step: ScanExecutionStep, document: unknown): Finding[] {
  const root = asRecord(document);
  const results = arrayValue(root.results);

  return results.map((result) => {
    const item = asRecord(result);
    const extra = asRecord(item.extra);
    const metadata = asRecord(extra.metadata);
    const ruleId = stringValue(item.check_id) ?? step.checkId;
    const message = stringValue(extra.message) ?? stringValue(item.message) ?? "Semgrep finding";

    return createExecutionFinding(plan, step, {
      severity: normalizeSeverity(stringValue(extra.severity), "medium"),
      title: message,
      description: message,
      filePath: normalizeExternalFilePath(plan, stringValue(item.path)),
      line: numberValue(asRecord(item.start).line),
      ruleId,
      cwe: stringListValue(metadata.cwe),
      owasp: stringListValue(metadata.owasp),
      recommendation: stringValue(metadata.fix) ?? "Review the Semgrep finding and remediate the affected code.",
      evidence: JSON.stringify(redactObject({ check_id: ruleId, path: item.path, start: item.start, extra }))
    });
  });
}

function parseTrivyFindings(plan: ScanExecutionPlan, step: ScanExecutionStep, document: unknown): Finding[] {
  const root = asRecord(document);
  const results = arrayValue(root.Results);
  const findings: Finding[] = [];

  for (const result of results) {
    const item = asRecord(result);
    const target = normalizeExternalFilePath(plan, stringValue(item.Target));

    for (const vulnerability of arrayValue(item.Vulnerabilities)) {
      const vuln = asRecord(vulnerability);
      const id = stringValue(vuln.VulnerabilityID) ?? step.checkId;
      const packageName = stringValue(vuln.PkgName) ?? "package";
      findings.push(
        createExecutionFinding(plan, step, {
          severity: normalizeSeverity(stringValue(vuln.Severity), "medium"),
          title: `${id} in ${packageName}`,
          description: stringValue(vuln.Title) ?? stringValue(vuln.Description) ?? `Trivy reported ${id}.`,
          filePath: target,
          ruleId: id,
          cve: id.startsWith("CVE-") ? id : null,
          recommendation: stringValue(vuln.FixedVersion)
            ? `Upgrade ${packageName} to ${vuln.FixedVersion} or later.`
            : "Review the vulnerable dependency and apply the vendor remediation.",
          evidence: JSON.stringify(redactObject(vuln))
        })
      );
    }

    for (const misconfiguration of arrayValue(item.Misconfigurations)) {
      const misconfig = asRecord(misconfiguration);
      const id = stringValue(misconfig.ID) ?? step.checkId;
      findings.push(
        createExecutionFinding(plan, step, {
          severity: normalizeSeverity(stringValue(misconfig.Severity), "medium"),
          title: stringValue(misconfig.Title) ?? `Container misconfiguration ${id}`,
          description: stringValue(misconfig.Message) ?? stringValue(misconfig.Description) ?? `Trivy reported ${id}.`,
          filePath: normalizeExternalFilePath(plan, stringValue(misconfig.FilePath)) ?? target,
          line: numberValue(misconfig.StartLine),
          ruleId: id,
          recommendation: stringValue(misconfig.Resolution) ?? "Review the misconfiguration and harden the affected file.",
          evidence: JSON.stringify(redactObject(misconfig))
        })
      );
    }

    for (const secret of arrayValue(item.Secrets)) {
      const secretRecord = asRecord(secret);
      const id = stringValue(secretRecord.RuleID) ?? step.checkId;
      findings.push(
        createExecutionFinding(plan, step, {
          severity: "critical",
          title: stringValue(secretRecord.Title) ?? `Secret detected by ${id}`,
          description: stringValue(secretRecord.Match) ?? "Trivy detected a secret-like value.",
          filePath: normalizeExternalFilePath(plan, stringValue(secretRecord.FilePath)) ?? target,
          line: numberValue(secretRecord.StartLine),
          ruleId: id,
          recommendation: "Remove the secret, rotate the credential, and keep the replacement outside Git.",
          evidence: JSON.stringify(redactObject(secretRecord))
        })
      );
    }
  }

  return findings;
}

function parseGrypeFindings(plan: ScanExecutionPlan, step: ScanExecutionStep, document: unknown): Finding[] {
  const root = asRecord(document);

  return arrayValue(root.matches).map((match) => {
    const item = asRecord(match);
    const vulnerability = asRecord(item.vulnerability);
    const artifact = asRecord(item.artifact);
    const id = stringValue(vulnerability.id) ?? step.checkId;
    const packageName = stringValue(artifact.name) ?? "package";
    const location = asRecord(arrayValue(artifact.locations)[0]);

    return createExecutionFinding(plan, step, {
      severity: normalizeSeverity(stringValue(vulnerability.severity), "medium"),
      title: `${id} in ${packageName}`,
      description: stringValue(vulnerability.description) ?? `Grype reported ${id}.`,
      filePath: normalizeExternalFilePath(plan, stringValue(location.path)),
      ruleId: id,
      cve: id.startsWith("CVE-") ? id : null,
      recommendation: stringValue(vulnerability.fix?.versions?.[0])
        ? `Upgrade ${packageName} to ${String(vulnerability.fix.versions[0])} or later.`
        : "Review the vulnerable dependency and apply the vendor remediation.",
      evidence: JSON.stringify(redactObject({ vulnerability, artifact }))
    });
  });
}

function parseOsvFindings(plan: ScanExecutionPlan, step: ScanExecutionStep, document: unknown): Finding[] {
  const root = asRecord(document);
  const findings: Finding[] = [];

  for (const result of arrayValue(root.results)) {
    const resultRecord = asRecord(result);
    const source = asRecord(resultRecord.source);

    for (const packageResult of arrayValue(resultRecord.packages)) {
      const packageRecord = asRecord(packageResult);
      const packageInfo = asRecord(packageRecord.package);
      const packageName = stringValue(packageInfo.name) ?? "package";

      for (const vulnerability of arrayValue(packageRecord.vulnerabilities)) {
        const vuln = asRecord(vulnerability);
        const id = stringValue(vuln.id) ?? step.checkId;
        findings.push(
          createExecutionFinding(plan, step, {
            severity: normalizeOsvSeverity(vuln),
            title: `${id} in ${packageName}`,
            description: stringValue(vuln.summary) ?? stringValue(vuln.details) ?? `OSV Scanner reported ${id}.`,
            filePath: normalizeExternalFilePath(plan, stringValue(source.path)),
            ruleId: id,
            cve: id.startsWith("CVE-") ? id : null,
            recommendation: "Upgrade or replace the affected dependency according to OSV advisory guidance.",
            evidence: JSON.stringify(redactObject({ package: packageInfo, vulnerability: vuln }))
          })
        );
      }
    }
  }

  return findings;
}

function parseCheckovFindings(plan: ScanExecutionPlan, step: ScanExecutionStep, document: unknown): Finding[] {
  const failedChecks = collectCheckovFailedChecks(document);

  return failedChecks.map((check) => {
    const item = asRecord(check);
    const fileRange = arrayValue(item.file_line_range);
    const ruleId = stringValue(item.check_id) ?? step.checkId;

    return createExecutionFinding(plan, step, {
      severity: normalizeSeverity(stringValue(item.severity), "medium"),
      title: stringValue(item.check_name) ?? `Checkov policy ${ruleId} failed`,
      description: stringValue(item.check_name) ?? `Checkov reported ${ruleId}.`,
      filePath: normalizeExternalFilePath(plan, stringValue(item.file_path) ?? stringValue(item.file_abs_path)),
      line: numberValue(fileRange[0]),
      ruleId,
      recommendation: stringValue(item.guideline) ?? "Review the infrastructure policy failure and harden the configuration.",
      evidence: JSON.stringify(redactObject(item))
    });
  });
}

function collectCheckovFailedChecks(document: unknown): unknown[] {
  if (Array.isArray(document)) {
    return document.flatMap((entry) => collectCheckovFailedChecks(entry));
  }

  const root = asRecord(document);
  const results = asRecord(root.results);
  const failed = arrayValue(results.failed_checks);

  if (failed.length > 0) {
    return failed;
  }

  return arrayValue(root.failed_checks);
}

function parseRedoclyFindings(plan: ScanExecutionPlan, step: ScanExecutionStep, document: unknown): Finding[] {
  const problems = Array.isArray(document) ? document : arrayValue(asRecord(document).problems);

  return problems.map((problem) => {
    const item = asRecord(problem);
    const location = asRecord(arrayValue(item.location)[0]);
    const source = asRecord(location.source);
    const ruleId = stringValue(item.ruleId) ?? step.checkId;

    return createExecutionFinding(plan, step, {
      severity: normalizeSeverity(stringValue(item.severity), "medium"),
      title: stringValue(item.message) ?? `OpenAPI lint issue ${ruleId}`,
      description: stringValue(item.message) ?? `Redocly reported ${ruleId}.`,
      filePath: normalizeExternalFilePath(plan, stringValue(source.absoluteRef) ?? stringValue(source.ref)),
      line: numberValue(location.line),
      ruleId,
      recommendation: "Update the OpenAPI JSON contract to satisfy the lint rule.",
      evidence: JSON.stringify(redactObject(item))
    });
  });
}

function parseZapFindings(plan: ScanExecutionPlan, step: ScanExecutionStep, document: unknown): Finding[] {
  const root = asRecord(document);
  const findings: Finding[] = [];

  for (const site of arrayValue(root.site)) {
    for (const alert of arrayValue(asRecord(site).alerts)) {
      const item = asRecord(alert);
      const ruleId = stringValue(item.pluginid) ?? step.checkId;
      findings.push(
        createExecutionFinding(plan, step, {
          severity: normalizeZapSeverity(stringValue(item.riskcode) ?? stringValue(item.riskdesc)),
          title: stringValue(item.alert) ?? `ZAP alert ${ruleId}`,
          description: stringValue(item.desc) ?? stringValue(item.riskdesc) ?? `ZAP reported ${ruleId}.`,
          endpoint: stringValue(asRecord(arrayValue(item.instances)[0]).uri),
          ruleId,
          cwe: stringValue(item.cweid),
          recommendation: stringValue(item.solution) ?? "Review and remediate the DAST finding.",
          evidence: JSON.stringify(redactObject(item))
        })
      );
    }
  }

  return findings;
}

function parseNucleiFindings(plan: ScanExecutionPlan, step: ScanExecutionStep, document: unknown): Finding[] {
  const item = asRecord(document);
  const info = asRecord(item.info);
  const ruleId = stringValue(item["template-id"]) ?? stringValue(item.templateID) ?? stringValue(item.template) ?? step.checkId;
  const title = stringValue(info.name) ?? `Nuclei finding ${ruleId}`;
  const matchedAt = stringValue(item["matched-at"]) ?? stringValue(item.matched) ?? stringValue(item.host);
  const tags = stringListValue(info.tags);
  const classification = asRecord(info.classification);

  return [
    createExecutionFinding(plan, step, {
      severity: normalizeSeverity(stringValue(info.severity), "medium"),
      title,
      description: stringValue(info.description) ?? title,
      endpoint: matchedAt,
      ruleId,
      cwe: stringListValue(classification["cwe-id"]),
      cve: stringListValue(classification["cve-id"]),
      recommendation:
        stringValue(info.remediation) ??
        (tags ? `Review the Nuclei safe-template finding and associated tags: ${tags}.` : "Review and remediate the Nuclei safe-template finding."),
      evidence: JSON.stringify(redactObject(item))
    })
  ];
}

function parseGreenboneReportFindings(plan: ScanExecutionPlan, step: ScanExecutionStep, report: string): Finding[] {
  const json = parseJson(report);

  if (json) {
    const parsed = parseGreenboneJsonFindings(plan, step, json);
    if (parsed.length > 0) {
      return parsed;
    }
  }

  return xmlBlocks(report, "result")
    .map((block) => {
      const nvt = xmlTag(block, "nvt") ?? "";
      const name = xmlTag(nvt, "name") ?? xmlTag(block, "name") ?? "Greenbone/OpenVAS finding";
      const oid = xmlAttribute(nvt, "oid") ?? xmlTag(nvt, "oid") ?? xmlTag(block, "id");
      const host = xmlTag(block, "host");
      const port = xmlTag(block, "port");
      const threat = xmlTag(block, "threat");
      const score = numberValue(xmlTag(block, "severity"));
      const severity = greenboneSeverity(threat, score);

      if (severity === "info") {
        return null;
      }

      return createExecutionFinding(plan, step, {
        severity,
        title: name,
        description: xmlTag(block, "description") ?? xmlTag(block, "summary") ?? `${name} was reported by Greenbone/OpenVAS.`,
        endpoint: [host, port].filter(Boolean).join(":") || plan.policy.activeDastTarget,
        ruleId: oid ?? step.checkId,
        cve: stringListValue(xmlBlocks(nvt, "cve").map((item) => decodeXml(item.replace(/<[^>]+>/g, "")))),
        recommendation: xmlTag(block, "solution") ?? "Review the Greenbone/OpenVAS result and apply the vendor remediation.",
        evidence: JSON.stringify(redactObject({ name, oid, host, port, threat, score }))
      });
    })
    .filter((finding): finding is Finding => finding !== null)
    .slice(0, 250);
}

function parseGreenboneJsonFindings(plan: ScanExecutionPlan, step: ScanExecutionStep, document: unknown): Finding[] {
  const root = asRecord(document);
  const results = arrayValue(root.results ?? root.Results ?? root.findings ?? root.vulnerabilities);

  return results
    .map((result) => {
      const item = asRecord(result);
      const name = stringValue(item.name ?? item.title ?? item.nvtName) ?? "Greenbone/OpenVAS finding";
      const severity = greenboneSeverity(stringValue(item.threat), numberValue(item.severity ?? item.cvss));

      if (severity === "info") {
        return null;
      }

      return createExecutionFinding(plan, step, {
        severity,
        title: name,
        description: stringValue(item.description ?? item.summary) ?? `${name} was reported by Greenbone/OpenVAS.`,
        endpoint: stringValue(item.endpoint) ?? ([stringValue(item.host), stringValue(item.port)].filter(Boolean).join(":") || plan.policy.activeDastTarget),
        ruleId: stringValue(item.oid ?? item.id ?? item.nvtOid) ?? step.checkId,
        cve: stringListValue(item.cves ?? item.cve),
        recommendation: stringValue(item.solution ?? item.remediation) ?? "Review the Greenbone/OpenVAS result and apply the vendor remediation.",
        evidence: JSON.stringify(redactObject(item))
      });
    })
    .filter((finding): finding is Finding => finding !== null)
    .slice(0, 250);
}

function parseOpenScapResultFindings(plan: ScanExecutionPlan, step: ScanExecutionStep, report: string): Finding[] {
  return xmlBlocks(report, "rule-result")
    .map((block) => {
      const result = xmlTag(block, "result")?.toLowerCase();

      if (!result || ["pass", "fixed", "notapplicable", "notselected", "informational"].includes(result)) {
        return null;
      }

      const ruleId = xmlAttribute(block, "idref") ?? xmlTag(block, "idref") ?? step.checkId;
      const severity = result === "fail" ? normalizeSeverity(xmlAttribute(block, "severity") ?? xmlTag(block, "severity"), "medium") : "high";
      const title = xmlTag(block, "title") ?? `OpenSCAP rule ${ruleId} ${result}`;

      return createExecutionFinding(plan, step, {
        severity,
        title,
        description: xmlTag(block, "description") ?? `OpenSCAP reported rule ${ruleId} with result '${result}'.`,
        ruleId,
        recommendation: xmlTag(block, "fixtext") ?? "Review the OpenSCAP rule result and remediate the failed baseline control.",
        evidence: JSON.stringify(redactObject({ ruleId, result, severity }))
      });
    })
    .filter((finding): finding is Finding => finding !== null)
    .slice(0, 250);
}

async function runInternalCheck(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  switch (step.checkId) {
    case "documentation":
      return checkPathsExist(plan, step, mandatoryDocumentationFiles, "Mandatory documentation is missing.");
    case "openapi":
      return checkOpenApiDocument(plan, step);
    case "api:error-response":
      return checkOpenApiErrorResponse(plan, step);
    case "api:health":
      return checkOpenApiPath(plan, step, "/health");
    case "api:ready":
      return checkOpenApiPath(plan, step, "/ready");
    case "telemetry-export":
      return checkOpenApiPath(plan, step, "/api/v1/results/ingest");
    case "dns:records":
      return checkDnsRecords(plan, step);
    case "tls:certificate":
      return checkTlsCertificate(plan, step);
    case "tls:configuration":
      return checkTlsConfiguration(plan, step);
    case "ports:common":
      return checkCommonPorts(plan, step);
    case "http:security-headers":
      return checkHttpSecurityHeaders(plan, step);
    case "endpoint:admin":
      return checkEndpointExposure(plan, step, adminEndpointPaths, "administration");
    case "endpoint:debug":
      return checkEndpointExposure(plan, step, debugEndpointPaths, "debug");
    case "api:discovery":
      return checkEndpointExposure(plan, step, apiDiscoveryPaths, "public API discovery");
    case "waf:behavior":
      return checkWafBehavior(plan, step);
    case "openapi:runtime-safe":
      return checkOpenApiRuntimeSafe(plan, step);
    case "external-runner:vps":
      return checkExternalRunnerReadiness(plan, step);
    case "defectdojo:export":
      return checkDefectDojoReadiness(plan, step);
    case "greenbone:openvas":
      return checkGreenboneReadiness(plan, step);
    case "openscap:system":
      return checkOpenScapReadiness(plan, step);
    case "privacy-impact":
      return checkDocumentationKeywords(plan, step, ["privacy", "data protection", "personal data", "health-data"]);
    case "threat-model":
      return checkDocumentationKeywords(plan, step, ["threat", "abuse", "risk", "attack"]);
    case "data-classification":
      return checkProjectDataClassification(plan, step);
    case "audit-logging":
      return checkDocumentationKeywords(plan, step, ["audit", "requestId", "retention"]);
    case "auth":
      return checkDocumentationKeywords(plan, step, ["authentication", "auth"]);
    case "authorization":
      return checkDocumentationKeywords(plan, step, ["authorization", "role", "permission"]);
    case "encryption":
      return checkDocumentationKeywords(plan, step, ["encryption", "tls", "secret"]);
    case "retention":
      return checkDocumentationKeywords(plan, step, ["retention", "cleanup", "expiry"]);
    case "logging-redaction":
      return checkDocumentationKeywords(plan, step, ["redact", "redaction", "log"]);
    case "license-policy":
      return checkDocumentationKeywords(plan, step, ["license", "sbom", "supply-chain"]);
    case "env-example":
      return checkEnvExample(plan, step);
    case "forbidden-files":
      return checkForbiddenFiles(plan, step);
    default:
      {
        const requiredPaths = singleDocumentChecks[step.checkId];

        if (requiredPaths) {
          return checkPathsExist(plan, step, requiredPaths, `Required ${step.checkId} documentation is missing.`);
        }
      }

      return [
        createExecutionFinding(plan, step, {
          severity: "medium",
          title: `Internal check '${step.checkId}' is not implemented`,
          description: "The scan profile references an internal check that does not have an executor yet.",
          recommendation: "Add an executor for this check or remove it from production profiles."
        })
      ];
  }
}

async function checkPathsExist(
  plan: ScanExecutionPlan,
  step: ScanExecutionStep,
  relativePaths: string[],
  description: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const relativePath of relativePaths) {
    const absolutePath = path.join(plan.project.path, relativePath);

    try {
      await stat(absolutePath);
    } catch {
      findings.push(
        createExecutionFinding(plan, step, {
          severity: "medium",
          title: `Missing required path: ${relativePath}`,
          description,
          filePath: relativePath,
          recommendation: `Create ${relativePath} or update the scan profile if this project intentionally does not use it.`
        })
      );
    }
  }

  return findings;
}

async function checkOpenApiDocument(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const openApi = await readOpenApi(plan);

  if (!openApi.ok) {
    return [
      createExecutionFinding(plan, step, {
        severity: "high",
        title: "OpenAPI JSON contract is missing or invalid",
        description: openApi.message,
        filePath: "openapi/openapi.json",
        recommendation: "Add a valid JSON-first OpenAPI contract at openapi/openapi.json."
      })
    ];
  }

  return [];
}

async function checkOpenApiErrorResponse(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const openApi = await readOpenApi(plan);

  if (!openApi.ok) {
    return checkOpenApiDocument(plan, step);
  }

  const errorProperties = openApi.document?.components?.schemas?.ErrorResponse?.properties?.error?.properties;
  const missing = ["code", "message", "requestId"].filter((property) => !errorProperties?.[property]);

  if (missing.length === 0) {
    return [];
  }

  return [
    createExecutionFinding(plan, step, {
      severity: "high",
      title: "OpenAPI ErrorResponse is missing required fields",
      description: `Missing fields: ${missing.join(", ")}.`,
      filePath: "openapi/openapi.json",
      recommendation: "Define ErrorResponse.error.code, ErrorResponse.error.message, and ErrorResponse.error.requestId."
    })
  ];
}

async function checkOpenApiPath(plan: ScanExecutionPlan, step: ScanExecutionStep, apiPath: string): Promise<Finding[]> {
  const openApi = await readOpenApi(plan);

  if (!openApi.ok) {
    return checkOpenApiDocument(plan, step);
  }

  if (openApi.document?.paths?.[apiPath]) {
    return [];
  }

  return [
    createExecutionFinding(plan, step, {
      severity: "high",
      title: `OpenAPI contract is missing ${apiPath}`,
      description: `The API contract must document ${apiPath}.`,
      filePath: "openapi/openapi.json",
      recommendation: `Add ${apiPath} to openapi/openapi.json.`
    })
  ];
}

async function checkDnsRecords(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const target = activeTarget(plan);

  if (!target) {
    return missingActiveTargetFinding(plan, step);
  }

  if (isLocalHost(target.hostname)) {
    return [];
  }

  const [a, aaaa, cname, mx, ns, txt] = await Promise.all([
    resolveDns(() => dns.resolve4(target.hostname)),
    resolveDns(() => dns.resolve6(target.hostname)),
    resolveDns(() => dns.resolveCname(target.hostname)),
    resolveDns(() => dns.resolveMx(target.hostname)),
    resolveDns(() => dns.resolveNs(target.hostname)),
    resolveDns(() => dns.resolveTxt(target.hostname))
  ]);
  const hasAddress = a.records.length > 0 || aaaa.records.length > 0 || cname.records.length > 0;

  if (!hasAddress) {
    return [
      createExecutionFinding(plan, step, {
        severity: "high",
        title: "Target hostname does not resolve to an address",
        description: `DNS lookup for ${target.hostname} did not return A, AAAA, or CNAME records.`,
        endpoint: target.origin,
        recommendation: "Fix DNS records before relying on perimeter or API scan results.",
        evidence: JSON.stringify(redactObject({ host: target.hostname, a, aaaa, cname, mx, ns, txt }))
      })
    ];
  }

  const findings: Finding[] = [];

  if (mx.records.length === 0 && txt.records.flat().some((record) => /^v=spf1/i.test(record)) === false) {
    findings.push(
      createExecutionFinding(plan, step, {
        severity: "info",
        title: "No mail security DNS evidence observed",
        description: `No MX records or SPF TXT record were observed for ${target.hostname}.`,
        endpoint: target.origin,
        recommendation: "If this domain sends mail, publish SPF, DKIM, and DMARC evidence; otherwise document that mail is intentionally disabled.",
        evidence: JSON.stringify(redactObject({ host: target.hostname, mx, txt }))
      })
    );
  }

  return findings;
}

async function checkTlsCertificate(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const target = activeTarget(plan);

  if (!target) {
    return missingActiveTargetFinding(plan, step);
  }

  if (target.protocol !== "https:") {
    return [
      createExecutionFinding(plan, step, {
        severity: "high",
        title: "Target does not use HTTPS",
        description: `The configured target ${target.toString()} uses ${target.protocol.replace(":", "")}.`,
        endpoint: target.toString(),
        recommendation: "Use HTTPS for healthcare and other sensitive applications before running web/API assurance scans."
      })
    ];
  }

  const result = await inspectTlsCertificate(target.hostname, Number(target.port || 443));

  if (!result.ok) {
    return [
      createExecutionFinding(plan, step, {
        severity: "high",
        title: "TLS certificate could not be inspected",
        description: result.error,
        endpoint: target.origin,
        recommendation: "Confirm the HTTPS endpoint is reachable and presents a valid certificate chain.",
        evidence: JSON.stringify(redactObject(result))
      })
    ];
  }

  const findings: Finding[] = [];
  const validTo = Date.parse(result.certificate.validTo ?? "");
  const daysRemaining = Number.isFinite(validTo) ? Math.floor((validTo - Date.now()) / 86_400_000) : null;

  if (!result.authorized) {
    findings.push(
      createExecutionFinding(plan, step, {
        severity: "high",
        title: "TLS certificate is not trusted by the runtime",
        description: result.authorizationError ?? "The TLS peer certificate chain was not authorized.",
        endpoint: target.origin,
        recommendation: "Install a trusted certificate chain with a hostname that matches the target.",
        evidence: JSON.stringify(redactObject(result))
      })
    );
  }

  if (daysRemaining !== null && daysRemaining < 0) {
    findings.push(
      createExecutionFinding(plan, step, {
        severity: "critical",
        title: "TLS certificate is expired",
        description: `The certificate expired ${Math.abs(daysRemaining)} days ago.`,
        endpoint: target.origin,
        recommendation: "Renew and deploy the certificate immediately.",
        evidence: JSON.stringify(redactObject(result))
      })
    );
  } else if (daysRemaining !== null && daysRemaining < 30) {
    findings.push(
      createExecutionFinding(plan, step, {
        severity: daysRemaining < 14 ? "high" : "medium",
        title: "TLS certificate expires soon",
        description: `The certificate expires in ${daysRemaining} days.`,
        endpoint: target.origin,
        recommendation: "Renew the certificate before the healthcare assurance gate.",
        evidence: JSON.stringify(redactObject(result))
      })
    );
  }

  if (!result.certificate.subjectaltname?.includes(target.hostname) && !isLocalHost(target.hostname)) {
    findings.push(
      createExecutionFinding(plan, step, {
        severity: "medium",
        title: "TLS certificate SAN does not visibly include the target host",
        description: `The certificate SAN list did not include ${target.hostname}.`,
        endpoint: target.origin,
        recommendation: "Verify the certificate includes the public service hostname.",
        evidence: JSON.stringify(redactObject(result))
      })
    );
  }

  return findings;
}

async function checkTlsConfiguration(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const target = activeTarget(plan);

  if (!target) {
    return missingActiveTargetFinding(plan, step);
  }

  if (target.protocol !== "https:") {
    return [
      createExecutionFinding(plan, step, {
        severity: "high",
        title: "TLS configuration cannot be evaluated on a non-HTTPS target",
        description: `The configured target ${target.toString()} does not use HTTPS.`,
        endpoint: target.toString(),
        recommendation: "Expose the application through HTTPS and rerun the TLS configuration check."
      })
    ];
  }

  const port = Number(target.port || 443);
  const [tls10, tls11, tls12, tls13] = await Promise.all([
    probeTlsVersion(target.hostname, port, "TLSv1"),
    probeTlsVersion(target.hostname, port, "TLSv1.1"),
    probeTlsVersion(target.hostname, port, "TLSv1.2"),
    probeTlsVersion(target.hostname, port, "TLSv1.3")
  ]);
  const findings: Finding[] = [];

  for (const legacy of [tls10, tls11]) {
    if (legacy.accepted) {
      findings.push(
        createExecutionFinding(plan, step, {
          severity: "high",
          title: `${legacy.version} is accepted by the target`,
          description: `The endpoint accepted a ${legacy.version} handshake.`,
          endpoint: target.origin,
          recommendation: "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or newer.",
          evidence: JSON.stringify(redactObject({ tls10, tls11, tls12, tls13 }))
        })
      );
    }
  }

  if (!tls12.accepted && !tls13.accepted) {
    findings.push(
      createExecutionFinding(plan, step, {
        severity: "critical",
        title: "TLS 1.2 or newer was not confirmed",
        description: "The probe could not establish TLS 1.2 or TLS 1.3.",
        endpoint: target.origin,
        recommendation: "Configure the service to support TLS 1.2 or TLS 1.3 with modern ciphers.",
        evidence: JSON.stringify(redactObject({ tls10, tls11, tls12, tls13 }))
      })
    );
  }

  return findings;
}

async function checkCommonPorts(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const target = activeTarget(plan);

  if (!target) {
    return missingActiveTargetFinding(plan, step);
  }

  const targetPort = Number(target.port || (target.protocol === "https:" ? 443 : 80));
  const probes = await Promise.all(commonPortChecks.map((portCheck) => probeTcpPort(target.hostname, portCheck.port)));

  return probes.flatMap((probe, index) => {
    const portCheck = commonPortChecks[index];

    if (!portCheck || !probe.open || portCheck.port === targetPort || portCheck.severity === "info") {
      return [];
    }

    return [
      createExecutionFinding(plan, step, {
        severity: portCheck.severity,
        title: `${portCheck.service} port is reachable`,
        description: `TCP port ${portCheck.port} on ${target.hostname} accepted a connection.`,
        endpoint: `${target.hostname}:${portCheck.port}`,
        recommendation: "Confirm the service is intentionally public, protected by network policy, and documented in the exposed-services inventory.",
        evidence: JSON.stringify(redactObject({ host: target.hostname, ...probe, service: portCheck.service }))
      })
    ];
  });
}

async function checkHttpSecurityHeaders(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const target = activeTarget(plan);

  if (!target) {
    return missingActiveTargetFinding(plan, step);
  }

  const response = await fetchTarget(target.toString(), { method: "GET", timeoutMs: 8_000 });

  if (!response.ok) {
    return [
      createExecutionFinding(plan, step, {
        severity: "medium",
        title: "HTTP security headers could not be inspected",
        description: response.error ?? `The target returned HTTP ${response.status ?? "unknown"}.`,
        endpoint: target.toString(),
        recommendation: "Confirm the target is reachable and rerun the header check.",
        evidence: JSON.stringify(redactObject(response))
      })
    ];
  }

  const headers = response.headers;
  const findings: Finding[] = [];
  const hasCspFrameAncestors = /frame-ancestors/i.test(headers["content-security-policy"] ?? "");

  if (target.protocol !== "https:") {
    findings.push(
      createExecutionFinding(plan, step, {
        severity: "high",
        title: "Application is reachable over plain HTTP",
        description: "The target URL uses HTTP instead of HTTPS.",
        endpoint: target.toString(),
        recommendation: "Serve healthcare and sensitive applications over HTTPS only."
      })
    );
  }

  if (target.protocol === "https:" && !headers["strict-transport-security"]) {
    findings.push(headerFinding(plan, step, target, "Strict-Transport-Security", "high", "Enable HSTS with an appropriate max-age."));
  }

  if (!headers["x-content-type-options"]?.toLowerCase().includes("nosniff")) {
    findings.push(headerFinding(plan, step, target, "X-Content-Type-Options", "medium", "Set X-Content-Type-Options: nosniff."));
  }

  if (!headers["x-frame-options"] && !hasCspFrameAncestors) {
    findings.push(headerFinding(plan, step, target, "X-Frame-Options or CSP frame-ancestors", "medium", "Prevent clickjacking with X-Frame-Options or CSP frame-ancestors."));
  }

  if (!headers["content-security-policy"]) {
    findings.push(headerFinding(plan, step, target, "Content-Security-Policy", "medium", "Define a Content-Security-Policy suited to the application."));
  }

  if (!headers["referrer-policy"]) {
    findings.push(headerFinding(plan, step, target, "Referrer-Policy", "low", "Set a Referrer-Policy that avoids leaking sensitive paths."));
  }

  if (!headers["permissions-policy"]) {
    findings.push(headerFinding(plan, step, target, "Permissions-Policy", "low", "Set a restrictive Permissions-Policy for browser capabilities."));
  }

  const evidence = JSON.stringify(redactObject({ url: target.toString(), status: response.status, headers }));

  return findings.map((finding) => ({
    ...finding,
    evidence
  }));
}

async function checkEndpointExposure(
  plan: ScanExecutionPlan,
  step: ScanExecutionStep,
  pathsToCheck: string[],
  label: string
): Promise<Finding[]> {
  const target = activeTarget(plan);

  if (!target) {
    return missingActiveTargetFinding(plan, step);
  }

  const findings: Finding[] = [];

  for (const probePath of pathsToCheck) {
    const url = buildTargetUrl(target, probePath);
    const response = await probeHttpEndpoint(url);

    if (!response.status) {
      continue;
    }

    const isAccessible = response.status >= 200 && response.status < 300;
    const isProtected = response.status === 401 || response.status === 403;
    const isRedirect = response.status >= 300 && response.status < 400;

    if (!isAccessible && !isProtected && !isRedirect) {
      continue;
    }

    findings.push(
      createExecutionFinding(plan, step, {
        severity: isAccessible ? (label === "debug" ? "high" : label === "public API discovery" ? "low" : "medium") : "info",
        title: `${label} endpoint is discoverable`,
        description: `${url} returned HTTP ${response.status}.`,
        endpoint: url,
        recommendation: isAccessible
          ? "Remove the endpoint from the public surface or require strong authentication, authorization, and audit logging."
          : "Confirm the endpoint is intentionally exposed and remains protected by authentication and authorization.",
        evidence: JSON.stringify(redactObject(response))
      })
    );
  }

  return findings;
}

async function checkWafBehavior(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const target = activeTarget(plan);

  if (!target) {
    return missingActiveTargetFinding(plan, step);
  }

  const baseline = await fetchTarget(target.toString(), { method: "GET", timeoutMs: 8_000 });
  const probeUrl = buildTargetUrl(target, "/securitypreflight-safe-probe");
  const probe = await fetchTarget(`${probeUrl}?securitypreflight_probe=%3Cscript%3E`, { method: "GET", timeoutMs: 8_000 });
  const waf = detectWafSignals([baseline, probe]);

  if (waf.length > 0 || [403, 406, 429].includes(probe.status ?? 0)) {
    return [];
  }

  return [
    createExecutionFinding(plan, step, {
      severity: "low",
      title: "No WAF or edge-protection behavior was observed",
      description: "The safe WAF probe did not observe common WAF/CDN headers or blocking behavior.",
      endpoint: target.origin,
      recommendation: "For internet-exposed healthcare applications, document compensating controls or place the service behind an approved WAF/edge policy.",
      evidence: JSON.stringify(redactObject({ baseline, probe, wafSignals: waf }))
    })
  ];
}

async function checkOpenApiRuntimeSafe(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const target = activeTarget(plan);

  if (!target) {
    return missingActiveTargetFinding(plan, step);
  }

  const openApi = await readOpenApi(plan);

  if (!openApi.ok) {
    return checkOpenApiDocument(plan, step);
  }

  const paths = asRecord(openApi.document.paths);
  const candidates = Object.entries(paths)
    .flatMap(([apiPath, methods]) =>
      Object.keys(asRecord(methods))
        .filter((method) => ["get", "head"].includes(method.toLowerCase()))
        .map((method) => ({ method: method.toUpperCase(), apiPath }))
    )
    .filter((candidate) => !candidate.apiPath.includes("{"))
    .slice(0, 25);
  const findings: Finding[] = [];

  for (const candidate of candidates) {
    const url = buildTargetUrl(target, candidate.apiPath);
    const response = await probeHttpEndpoint(url, candidate.method === "HEAD" ? "HEAD" : "GET");

    if ((response.status ?? 0) >= 500) {
      findings.push(
        createExecutionFinding(plan, step, {
          severity: "high",
          title: "Documented OpenAPI operation returned a server error",
          description: `${candidate.method} ${candidate.apiPath} returned HTTP ${response.status}.`,
          endpoint: url,
          recommendation: "Fix the operation or update the contract before relying on the API readiness gate.",
          evidence: JSON.stringify(redactObject({ candidate, response }))
        })
      );
    }
  }

  return findings;
}

async function checkExternalRunnerReadiness(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const target = activeTarget(plan);
  const endpoint = process.env.SECURITY_PREFLIGHT_EXTERNAL_SCANNER_URL?.trim();
  const publicKey = process.env.SECURITY_PREFLIGHT_EXTERNAL_SCANNER_PUBLIC_KEY?.trim();
  const healthUrl = process.env.SECURITY_PREFLIGHT_EXTERNAL_SCANNER_HEALTH_URL?.trim();

  if (!target) {
    return missingActiveTargetFinding(plan, step);
  }

  const handoff = {
    schemaVersion: "security-preflight.external-handoff.v1",
    generatedAt: new Date().toISOString(),
    scanRunId: plan.scanRunId,
    targetUrl: target.toString(),
    allowedHosts: plan.policy.allowedDastHosts,
    expectedChecks: ["dns:records", "tls:certificate", "tls:configuration", "http:security-headers", "nuclei:safe", "zap:baseline"],
    signatureRequired: process.env.SECURITY_PREFLIGHT_EXTERNAL_SCANNER_REQUIRE_SIGNATURE !== "false",
    noSourceUpload: true
  };
  await writeFile(supplementalEvidencePath(step, "job"), `${redactSecrets(JSON.stringify(handoff, null, 2))}\n`, "utf8");

  if (!endpoint || !publicKey) {
    return [
      createExecutionFinding(plan, step, {
        severity: "high",
        title: "External scanner VPS is not configured",
        description:
          "SECURITY_PREFLIGHT_EXTERNAL_SCANNER_URL and SECURITY_PREFLIGHT_EXTERNAL_SCANNER_PUBLIC_KEY are required for signed external scanner result exchange.",
        endpoint: target.toString(),
        recommendation: "Provision the hardened scanner VPS, configure signed result return, and keep credentials outside Git.",
        evidence: JSON.stringify(redactObject({ configuredEndpoint: Boolean(endpoint), configuredPublicKey: Boolean(publicKey) }))
      })
    ];
  }

  if (!healthUrl) {
    return [];
  }

  const health = await fetchTarget(healthUrl, { method: "GET", timeoutMs: 8_000 });
  await writeFile(supplementalEvidencePath(step, "response"), `${redactSecrets(JSON.stringify(health, null, 2))}\n`, "utf8");

  if (health.ok && health.status && health.status >= 200 && health.status < 300) {
    return [];
  }

  return [
    createExecutionFinding(plan, step, {
      severity: "high",
      title: "External scanner VPS health check failed",
      description: health.error ?? `External scanner health endpoint returned HTTP ${health.status ?? "unknown"}.`,
      endpoint: healthUrl,
      recommendation: "Verify the hardened scanner VPS health endpoint, network route, and authentication boundary before using remote scans.",
      evidence: JSON.stringify(redactObject(health))
    })
  ];
}

async function checkDefectDojoReadiness(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const baseUrl = process.env.SECURITY_PREFLIGHT_DEFECTDOJO_URL?.trim();
  const tokenRef = process.env.SECURITY_PREFLIGHT_DEFECTDOJO_TOKEN_REF?.trim();
  const product = process.env.SECURITY_PREFLIGHT_DEFECTDOJO_PRODUCT?.trim();
  const token = await resolveSecretReference(tokenRef);

  if (baseUrl && token.ok && product) {
    return [];
  }

  return [
    createExecutionFinding(plan, step, {
      severity: "medium",
      title: "DefectDojo export is not configured",
      description: "DefectDojo URL, resolvable token reference, and product mapping are required before findings can be centrally triaged.",
      recommendation:
        "Configure SECURITY_PREFLIGHT_DEFECTDOJO_URL, SECURITY_PREFLIGHT_DEFECTDOJO_TOKEN_REF, and SECURITY_PREFLIGHT_DEFECTDOJO_PRODUCT in the deployment secret store.",
      evidence: JSON.stringify(
        redactObject({
          configuredBaseUrl: Boolean(baseUrl),
          configuredTokenRef: Boolean(tokenRef),
          tokenResolved: token.ok,
          tokenSource: token.source,
          configuredProduct: Boolean(product)
        })
      )
    })
  ];
}

async function checkGreenboneReadiness(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const target = activeTarget(plan);
  const endpoint = process.env.SECURITY_PREFLIGHT_GREENBONE_URL?.trim();
  const credentialRef = process.env.SECURITY_PREFLIGHT_GREENBONE_CREDENTIAL_REF?.trim();
  const reportPath = process.env.SECURITY_PREFLIGHT_GREENBONE_REPORT_PATH?.trim();
  const credential = await resolveSecretReference(credentialRef);

  if (!target) {
    return missingActiveTargetFinding(plan, step);
  }

  if (reportPath) {
    try {
      const report = await readFile(reportPath, "utf8");
      await writeFile(supplementalEvidencePath(step, "xml"), report, "utf8");
      return parseGreenboneReportFindings(plan, step, report);
    } catch (error) {
      return [
        createExecutionFinding(plan, step, {
          severity: "high",
          title: "Greenbone/OpenVAS report evidence is not readable",
          description: error instanceof Error ? error.message : String(error),
          endpoint: target.toString(),
          recommendation: "Attach a readable Greenbone XML report through SECURITY_PREFLIGHT_GREENBONE_REPORT_PATH.",
          evidence: JSON.stringify(redactObject({ reportPath }))
        })
      ];
    }
  }

  if (endpoint && credential.ok) {
    return [
      createExecutionFinding(plan, step, {
        severity: "medium",
        title: "Greenbone/OpenVAS scan result is not attached",
        description: "Greenbone connectivity is configured, but no XML report was attached for normalized finding import.",
        endpoint: target.toString(),
        recommendation:
          "Run the approved Greenbone/OpenVAS task from the scanner network and set SECURITY_PREFLIGHT_GREENBONE_REPORT_PATH to the exported XML report before relying on enterprise assurance evidence.",
        evidence: JSON.stringify(redactObject({ configuredEndpoint: Boolean(endpoint), credentialResolved: credential.ok, credentialSource: credential.source }))
      })
    ];
  }

  return [
    createExecutionFinding(plan, step, {
      severity: "high",
      title: "Greenbone/OpenVAS integration is not configured",
      description: "Greenbone/OpenVAS requires a configured manager endpoint, resolvable credential reference, and imported report evidence.",
      endpoint: target.toString(),
      recommendation:
        "Configure SECURITY_PREFLIGHT_GREENBONE_URL, SECURITY_PREFLIGHT_GREENBONE_CREDENTIAL_REF, and SECURITY_PREFLIGHT_GREENBONE_REPORT_PATH, then run the enterprise assurance profile from an approved scanner network.",
      evidence: JSON.stringify(
        redactObject({
          configuredEndpoint: Boolean(endpoint),
          configuredCredentialRef: Boolean(credentialRef),
          credentialResolved: credential.ok,
          credentialSource: credential.source,
          configuredReportPath: Boolean(reportPath)
        })
      )
    })
  ];
}

async function checkOpenScapReadiness(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const contentPath = process.env.SECURITY_PREFLIGHT_OPENSCAP_CONTENT_PATH?.trim();
  const resultPath = process.env.SECURITY_PREFLIGHT_OPENSCAP_RESULTS_PATH?.trim();
  const profile = process.env.SECURITY_PREFLIGHT_OPENSCAP_PROFILE?.trim();
  const evalEnabled = process.env.SECURITY_PREFLIGHT_OPENSCAP_EVAL_ENABLED === "true";

  if (resultPath) {
    try {
      const report = await readFile(resultPath, "utf8");
      await writeFile(supplementalEvidencePath(step, "xml"), report, "utf8");
      return parseOpenScapResultFindings(plan, step, report);
    } catch (error) {
      return [
        createExecutionFinding(plan, step, {
          severity: "high",
          title: "OpenSCAP result evidence is not readable",
          description: error instanceof Error ? error.message : String(error),
          recommendation: "Attach a readable OpenSCAP XCCDF result XML through SECURITY_PREFLIGHT_OPENSCAP_RESULTS_PATH.",
          evidence: JSON.stringify(redactObject({ resultPath }))
        })
      ];
    }
  }

  if (contentPath) {
    try {
      await stat(contentPath);
    } catch {
      return [
        createExecutionFinding(plan, step, {
          severity: "high",
          title: "OpenSCAP content path is not readable",
          description: `Configured OpenSCAP content path '${contentPath}' could not be read.`,
          recommendation: "Mount approved SCAP content into the scanner runtime and verify filesystem permissions.",
          evidence: JSON.stringify(redactObject({ contentPath }))
        })
      ];
    }

    if (!evalEnabled || !profile) {
      return [
        createExecutionFinding(plan, step, {
          severity: "medium",
          title: "OpenSCAP evaluation evidence is not configured",
          description: "OpenSCAP content is mounted, but no result XML is attached and local oscap evaluation is not fully enabled.",
          recommendation:
            "Set SECURITY_PREFLIGHT_OPENSCAP_RESULTS_PATH to an approved result XML, or set SECURITY_PREFLIGHT_OPENSCAP_EVAL_ENABLED=true and SECURITY_PREFLIGHT_OPENSCAP_PROFILE to run oscap xccdf eval.",
          evidence: JSON.stringify(redactObject({ contentPath, evalEnabled, configuredProfile: Boolean(profile) }))
        })
      ];
    }

    const xmlPath = supplementalEvidencePath(step, "xml");
    const htmlPath = supplementalEvidencePath(step, "html");
    const command = ["xccdf", "eval", "--profile", profile, "--results", xmlPath, "--report", htmlPath, contentPath];

    try {
      await execFileAsync("oscap", command, {
        cwd: plan.project.path,
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
        timeout: step.timeoutSeconds * 1000
      });
    } catch (error) {
      const nodeError = error as NodeJS.ErrnoException & { stdout?: string | Buffer; stderr?: string | Buffer; code?: string | number };
      try {
        const report = await readFile(xmlPath, "utf8");
        const findings = parseOpenScapResultFindings(plan, step, report);
        const executionFinding =
          findings.length === 0 && String(nodeError.code) !== "2"
            ? [
                createExecutionFinding(plan, step, {
                  severity: "high",
                  title: "OpenSCAP evaluation failed",
                  description: nodeError.message,
                  recommendation: "Inspect OpenSCAP command evidence and fix content/profile compatibility.",
                  evidence: [bufferToString(nodeError.stderr), bufferToString(nodeError.stdout)].filter(Boolean).join("\n")
                })
              ]
            : [];
        return [...findings, ...executionFinding];
      } catch {
        return [
          createExecutionFinding(plan, step, {
            severity: "high",
            title: "OpenSCAP evaluation failed before writing result XML",
            description: nodeError.message,
            recommendation: "Inspect OpenSCAP installation, content path, profile id, and runtime permissions.",
            evidence: JSON.stringify(redactObject({ command, stderr: bufferToString(nodeError.stderr), stdout: bufferToString(nodeError.stdout) }))
          })
        ];
      }
    }

    const report = await readFile(xmlPath, "utf8");
    return parseOpenScapResultFindings(plan, step, report);
  }

  return [
    createExecutionFinding(plan, step, {
      severity: "medium",
      title: "OpenSCAP content is not configured",
      description: "OpenSCAP needs approved SCAP content before compliance evidence can be generated.",
      recommendation:
        "Configure SECURITY_PREFLIGHT_OPENSCAP_CONTENT_PATH plus SECURITY_PREFLIGHT_OPENSCAP_RESULTS_PATH, or enable local oscap evaluation with SECURITY_PREFLIGHT_OPENSCAP_EVAL_ENABLED=true."
    })
  ];
}

async function checkProjectDataClassification(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const classification = plan.project.dataClassification ?? "internal";

  if (classification === "health-data" || classification === "sensitive") {
    return [];
  }

  return [
    createExecutionFinding(plan, step, {
      severity: "medium",
      title: "Healthcare reference scan requires sensitive data classification",
      description: `Current data classification is '${classification}'.`,
      recommendation: "Set project dataClassification to health-data or sensitive for healthcare reference scans."
    })
  ];
}

async function checkDocumentationKeywords(
  plan: ScanExecutionPlan,
  step: ScanExecutionStep,
  keywords: string[]
): Promise<Finding[]> {
  const documents = ["docs/security.md", "docs/architecture.md", "docs/operations.md", "docs/observability.md", "docs/runbook.md"];
  const combined: string[] = [];

  for (const relativePath of documents) {
    try {
      combined.push(await readFile(path.join(plan.project.path, relativePath), "utf8"));
    } catch {
      // Missing canonical docs are reported by the documentation check.
    }
  }

  const haystack = combined.join("\n").toLowerCase();
  const matched = keywords.some((keyword) => haystack.includes(keyword.toLowerCase()));

  if (matched) {
    return [];
  }

  return [
    createExecutionFinding(plan, step, {
      severity: "medium",
      title: `Missing evidence for ${step.checkId}`,
      description: `Canonical documentation does not mention any of: ${keywords.join(", ")}.`,
      recommendation: `Document ${step.checkId} controls in the active documentation set.`
    })
  ];
}

async function checkEnvExample(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const envExamplePath = path.join(plan.project.path, ".env.example");

  try {
    const content = await readFile(envExamplePath, "utf8");
    const suspicious = content
      .split(/\r?\n/)
      .filter((line) => /^[A-Z0-9_]+=.+/.test(line))
      .filter((line) => !/=$/.test(line))
      .filter((line) => !/(example|placeholder|changeme|development|localhost|false|true|info|none|\/reports)/i.test(line));

    if (suspicious.length === 0) {
      return [];
    }

    return [
      createExecutionFinding(plan, step, {
        severity: "high",
        title: ".env.example may contain concrete secret-like values",
        description: `Suspicious assignments: ${suspicious.map((line) => line.split("=")[0]).join(", ")}.`,
        filePath: ".env.example",
        recommendation: "Replace concrete values with safe placeholders and keep real secrets outside Git."
      })
    ];
  } catch {
    return [
      createExecutionFinding(plan, step, {
        severity: "medium",
        title: "Missing .env.example",
        description: "The project should document required configuration using safe placeholder values.",
        filePath: ".env.example",
        recommendation: "Add .env.example and keep it aligned with operations documentation."
      })
    ];
  }
}

async function checkForbiddenFiles(plan: ScanExecutionPlan, step: ScanExecutionStep): Promise<Finding[]> {
  const forbidden = await findForbiddenFiles(plan.project.path);

  return forbidden.map((relativePath) =>
    createExecutionFinding(plan, step, {
      severity: "critical",
      title: `Forbidden sensitive file present: ${relativePath}`,
      description: "The project contains a file name that commonly holds secrets or private keys.",
      filePath: relativePath,
      recommendation: "Remove the file from the repository and rotate any exposed credentials if it was committed."
    })
  );
}

async function findForbiddenFiles(root: string): Promise<string[]> {
  const findings: string[] = [];

  async function walk(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });

    for (const entry of entries) {
      if (ignoredWalkSegments.has(entry.name)) {
        continue;
      }

      const absolutePath = path.join(directory, entry.name);
      const relativePath = path.relative(root, absolutePath);

      if (entry.isDirectory()) {
        await walk(absolutePath);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      if (forbiddenFileNames.has(entry.name) || forbiddenFileExtensions.has(path.extname(entry.name))) {
        findings.push(relativePath);
      }
    }
  }

  await walk(root);
  return findings.sort();
}

async function readOpenApi(plan: ScanExecutionPlan): Promise<{ ok: true; document: Record<string, any> } | { ok: false; message: string }> {
  const openApiPath = path.join(plan.project.path, "openapi/openapi.json");

  try {
    const raw = await readFile(openApiPath, "utf8");
    return { ok: true, document: JSON.parse(raw) as Record<string, any> };
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : String(error) };
  }
}

function activeTarget(plan: ScanExecutionPlan): URL | null {
  if (!plan.policy.activeDastTarget) {
    return null;
  }

  try {
    return new URL(plan.policy.activeDastTarget);
  } catch {
    return null;
  }
}

function missingActiveTargetFinding(plan: ScanExecutionPlan, step: ScanExecutionStep): Finding[] {
  return [
    createExecutionFinding(plan, step, {
      severity: "high",
      title: "Web target is missing",
      description: "This check requires an explicit, allowlisted HTTP or HTTPS target URL.",
      recommendation: "Provide dast.targetUrl with the target host in dast.allowedHosts and rerun the profile."
    })
  ];
}

function isLocalHost(hostname: string): boolean {
  return ["localhost", "127.0.0.1", "::1", "host.docker.internal"].includes(hostname.toLowerCase());
}

async function resolveDns<T>(resolver: () => Promise<T[]>): Promise<{ ok: boolean; records: T[]; error: string | null }> {
  try {
    return { ok: true, records: await resolver(), error: null };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;

    if (code === "ENODATA" || code === "ENOTFOUND" || code === "ENODOMAIN") {
      return { ok: true, records: [], error: null };
    }

    return { ok: false, records: [], error: error instanceof Error ? error.message : String(error) };
  }
}

async function inspectTlsCertificate(
  host: string,
  port: number
): Promise<
  | {
      ok: true;
      authorized: boolean;
      authorizationError: string | null;
      protocol: string | null;
      cipher: string | null;
      certificate: {
        subject: unknown;
        issuer: unknown;
        subjectaltname: string | null;
        validFrom: string | null;
        validTo: string | null;
        fingerprint256: string | null;
      };
    }
  | { ok: false; error: string }
> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host,
      port,
      servername: isLocalHost(host) ? undefined : host,
      rejectUnauthorized: false,
      timeout: 8_000
    });

    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();
      resolve({
        ok: true,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name ?? null,
        certificate: {
          subject: certificate.subject ?? null,
          issuer: certificate.issuer ?? null,
          subjectaltname: certificate.subjectaltname ?? null,
          validFrom: certificate.valid_from ?? null,
          validTo: certificate.valid_to ?? null,
          fingerprint256: certificate.fingerprint256 ?? null
        }
      });
      socket.end();
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve({ ok: false, error: "TLS certificate probe timed out." });
    });
    socket.once("error", (error) => {
      resolve({ ok: false, error: error.message });
    });
  });
}

async function probeTlsVersion(
  host: string,
  port: number,
  version: tls.SecureVersion
): Promise<{ version: tls.SecureVersion; accepted: boolean; protocol: string | null; error: string | null }> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host,
      port,
      servername: isLocalHost(host) ? undefined : host,
      minVersion: version,
      maxVersion: version,
      rejectUnauthorized: false,
      timeout: 5_000
    });

    socket.once("secureConnect", () => {
      resolve({ version, accepted: true, protocol: socket.getProtocol(), error: null });
      socket.end();
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve({ version, accepted: false, protocol: null, error: "TLS version probe timed out." });
    });
    socket.once("error", (error) => {
      resolve({ version, accepted: false, protocol: null, error: error.message });
    });
  });
}

async function probeTcpPort(host: string, port: number): Promise<{ port: number; open: boolean; error: string | null }> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port, timeout: 1_500 });
    let settled = false;
    const finish = (open: boolean, error: string | null) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, open, error });
    };

    socket.once("connect", () => finish(true, null));
    socket.once("timeout", () => finish(false, "Port probe timed out."));
    socket.once("error", (error) => finish(false, error.message));
  });
}

interface HttpProbeResult {
  url: string;
  method: string;
  ok: boolean;
  status: number | null;
  headers: Record<string, string>;
  error: string | null;
}

async function fetchTarget(url: string, options: { method: string; timeoutMs: number }): Promise<HttpProbeResult> {
  try {
    const response = await fetch(url, {
      method: options.method,
      redirect: "manual",
      headers: {
        accept: "*/*",
        "user-agent": "SecurityPreflight/0.1 safe-probe"
      },
      signal: AbortSignal.timeout(options.timeoutMs)
    });
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    return {
      url,
      method: options.method,
      ok: true,
      status: response.status,
      headers,
      error: null
    };
  } catch (error) {
    return {
      url,
      method: options.method,
      ok: false,
      status: null,
      headers: {},
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

async function probeHttpEndpoint(url: string, method = "HEAD"): Promise<HttpProbeResult> {
  const head = await fetchTarget(url, { method, timeoutMs: 6_000 });

  if (method === "HEAD" && (head.status === 405 || head.status === 501 || !head.ok)) {
    return fetchTarget(url, { method: "GET", timeoutMs: 6_000 });
  }

  return head;
}

function buildTargetUrl(target: URL, candidatePath: string): string {
  const basePath = target.pathname.replace(/\/$/, "");
  const normalizedCandidate = candidatePath.startsWith("/") ? candidatePath : `/${candidatePath}`;
  const next = new URL(target.toString());
  next.pathname = basePath && basePath !== "/" ? `${basePath}${normalizedCandidate}` : normalizedCandidate;
  next.search = "";
  next.hash = "";
  return next.toString();
}

function headerFinding(
  plan: ScanExecutionPlan,
  step: ScanExecutionStep,
  target: URL,
  header: string,
  severity: Severity,
  recommendation: string
): Finding {
  return createExecutionFinding(plan, step, {
    severity,
    title: `Missing or weak HTTP security header: ${header}`,
    description: `The response did not include an acceptable ${header} header.`,
    endpoint: target.toString(),
    recommendation
  });
}

function detectWafSignals(probes: HttpProbeResult[]): string[] {
  const haystack = probes
    .flatMap((probe) => Object.entries(probe.headers).map(([key, value]) => `${key}: ${value}`))
    .join("\n")
    .toLowerCase();
  const signals = [
    "cloudflare",
    "cf-ray",
    "akamai",
    "imperva",
    "incapsula",
    "sucuri",
    "fastly",
    "x-azure-ref",
    "x-amz-cf",
    "x-sucuri",
    "x-waf",
    "mod_security",
    "barracuda"
  ];

  return signals.filter((signal) => haystack.includes(signal));
}

export interface SecretReferenceResolution {
  ok: boolean;
  value: string;
  source: "env" | "file" | "unresolved";
  error: string | null;
}

export async function resolveSecretReference(reference: string | null | undefined): Promise<SecretReferenceResolution> {
  const raw = reference?.trim();

  if (!raw) {
    return { ok: false, value: "", source: "unresolved", error: "Secret reference is not configured." };
  }

  if (raw.startsWith("env:")) {
    const envName = raw.slice("env:".length).trim();
    const value = process.env[envName]?.trim();
    return value
      ? { ok: true, value, source: "env", error: null }
      : { ok: false, value: "", source: "env", error: `Environment variable '${envName}' is not set.` };
  }

  if (raw.startsWith("file:")) {
    const filePath = raw.slice("file:".length).trim();
    try {
      return { ok: true, value: (await readFile(filePath, "utf8")).trim(), source: "file", error: null };
    } catch (error) {
      return { ok: false, value: "", source: "file", error: error instanceof Error ? error.message : String(error) };
    }
  }

  if (path.isAbsolute(raw)) {
    try {
      return { ok: true, value: (await readFile(raw, "utf8")).trim(), source: "file", error: null };
    } catch (error) {
      return { ok: false, value: "", source: "file", error: error instanceof Error ? error.message : String(error) };
    }
  }

  const value = process.env[raw]?.trim();
  return value
    ? { ok: true, value, source: "env", error: null }
    : { ok: false, value: "", source: "unresolved", error: `Secret reference '${raw}' did not resolve to env: or file: content.` };
}

function parseJson(value: string): unknown | null {
  const trimmed = value.trim();

  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
    return null;
  }

  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

function extractSignedPayload(document: unknown): Record<string, any> {
  const root = asRecord(document);
  const payload = root.payload ?? root.data ?? document;

  if (typeof payload === "string") {
    return asRecord(parseJson(payload));
  }

  return asRecord(payload);
}

function verifyRemotePayloadSignature(document: unknown, publicKey: string | undefined): { ok: boolean; error: string | null } {
  const root = asRecord(document);
  const payload = root.payload ?? root.data;
  const signature = normalizeSignature(stringValue(root.signature) ?? stringValue(root.detachedSignature));

  if (!publicKey) {
    return { ok: false, error: "External scanner signature verification requires SECURITY_PREFLIGHT_EXTERNAL_SCANNER_PUBLIC_KEY." };
  }

  if (payload === undefined || !signature) {
    return { ok: false, error: "External scanner response did not include a signed payload and detached signature." };
  }

  const signingInput = typeof payload === "string" ? payload : JSON.stringify(payload);
  const publicKeyValue = publicKey.replaceAll("\\n", "\n");
  const signatureBytes = Buffer.from(signature, "base64");

  try {
    const key = createPublicKey(publicKeyValue);
    const verified = verifyDetachedSignature(null, Buffer.from(signingInput), key, signatureBytes);
    if (verified) {
      return { ok: true, error: null };
    }
  } catch {
    // RSA/ECDSA keys need a digest-based verifier; fall through to SHA-256.
  }

  try {
    const verifier = createVerify("sha256");
    verifier.update(signingInput);
    verifier.end();
    return verifier.verify(publicKeyValue, signatureBytes)
      ? { ok: true, error: null }
      : { ok: false, error: "External scanner response signature could not be verified." };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

function normalizeSignature(value: string | null): string | null {
  if (!value) {
    return null;
  }

  if (value.startsWith("sha256=")) {
    return value.slice("sha256=".length);
  }

  return value;
}

async function writeRemoteEvidenceFiles(step: ScanExecutionStep, payload: Record<string, any>): Promise<void> {
  const evidence = payload.evidence ?? payload.generatedEvidence ?? payload.files;

  if (Array.isArray(evidence)) {
    for (const item of evidence) {
      const record = asRecord(item);
      const extension = stringValue(record.extension ?? record.kind ?? record.name)?.replace(/^\./, "");
      const content = decodeEvidenceValue(record.content, stringValue(record.encoding));
      const outputPath = extension ? step.evidencePaths.find((candidate) => candidate.endsWith(`.${extension}`)) : null;

      if (outputPath && content !== null) {
        await writeFile(outputPath, content, "utf8");
      }
    }
    return;
  }

  const record = asRecord(evidence);
  for (const [key, value] of Object.entries(record)) {
    const extension = key.replace(/^\./, "");
    const outputPath = step.evidencePaths.find((candidate) => candidate.endsWith(`.${extension}`));
    const content = decodeEvidenceValue(value, stringValue(asRecord(value).encoding));

    if (outputPath && content !== null) {
      await writeFile(outputPath, content, "utf8");
    }
  }
}

function decodeEvidenceValue(value: unknown, encoding: string | null): string | null {
  if (typeof value === "string") {
    return encoding === "base64" ? Buffer.from(value, "base64").toString("utf8") : value;
  }

  const record = asRecord(value);
  const content = stringValue(record.content ?? record.data);

  if (!content) {
    return null;
  }

  return stringValue(record.encoding) === "base64" || encoding === "base64" ? Buffer.from(content, "base64").toString("utf8") : content;
}

function xmlBlocks(source: string, tagName: string): string[] {
  const expression = new RegExp(`<${tagName}\\b[^>]*>[\\s\\S]*?<\\/${tagName}>`, "gi");
  return source.match(expression) ?? [];
}

function xmlTag(source: string, tagName: string): string | null {
  const match = new RegExp(`<${tagName}\\b[^>]*>([\\s\\S]*?)<\\/${tagName}>`, "i").exec(source);
  return match?.[1] ? decodeXml(match[1].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim()) : null;
}

function xmlAttribute(source: string, attributeName: string): string | null {
  const match = new RegExp(`\\b${attributeName}=(["'])(.*?)\\1`, "i").exec(source);
  return match?.[2] ? decodeXml(match[2]) : null;
}

function decodeXml(value: string): string {
  return value
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&")
    .replaceAll("&quot;", "\"")
    .replaceAll("&apos;", "'");
}

function greenboneSeverity(threat: string | null, score: number | null): Severity {
  if (score !== null) {
    if (score >= 9) return "critical";
    if (score >= 7) return "high";
    if (score >= 4) return "medium";
    if (score > 0) return "low";
  }

  return normalizeSeverity(threat, "info");
}

async function writeStepEvidence(
  plan: ScanExecutionPlan,
  step: ScanExecutionStep,
  result: ScanStepExecutionResult
): Promise<void> {
  const payload = {
    scanRunId: plan.scanRunId,
    step,
    result: {
      ...result,
      findings: result.findings.map((finding) => ({
        ...finding,
        evidence: redactSecrets(finding.evidence)
      }))
    }
  };

  await writeFile(result.evidencePath, `${redactSecrets(JSON.stringify(payload, null, 2))}\n`, "utf8");
}

export async function writeExecutionResultEvidence(result: ScanExecutionResult): Promise<string> {
  const outputPath = path.join(result.evidenceRoot, "execution-result.json");
  await mkdir(result.evidenceRoot, { recursive: true });
  await writeFile(outputPath, `${redactSecrets(JSON.stringify(result, null, 2))}\n`, "utf8");
  return outputPath;
}

function primaryEvidencePath(step: ScanExecutionStep): string {
  return step.evidencePaths[0] ?? path.join(process.cwd(), `${step.id}.json`);
}

function supplementalEvidencePath(step: ScanExecutionStep, suffix: string): string {
  const expectedSuffix = `.${suffix}`;
  const evidencePath = step.evidencePaths.find((candidate) => candidate.endsWith(expectedSuffix) || candidate.endsWith(`${expectedSuffix}.json`));

  if (evidencePath) {
    return evidencePath;
  }

  return path.join(path.dirname(primaryEvidencePath(step)), `${sanitizeFilePart(step.checkId)}.${suffix}`);
}

function stepResultEvidencePath(step: ScanExecutionStep): string {
  if (step.executionMode === "internal") {
    return primaryEvidencePath(step);
  }

  return path.join(path.dirname(primaryEvidencePath(step)), `${sanitizeFilePart(step.checkId)}.execution.json`);
}

function commandEvidencePath(step: ScanExecutionStep): string {
  return path.join(path.dirname(primaryEvidencePath(step)), `${sanitizeFilePart(step.checkId)}.command.json`);
}

async function existingEvidencePaths(evidencePaths: string[]): Promise<string[]> {
  const existing: string[] = [];

  for (const evidencePath of evidencePaths) {
    try {
      await stat(evidencePath);
      existing.push(evidencePath);
    } catch {
      // Missing raw scanner evidence is represented by command status and findings.
    }
  }

  return existing;
}

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, any>) : {};
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringValue(value: unknown): string | null {
  if (typeof value === "string" && value.trim()) {
    return value;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  return null;
}

function stringListValue(value: unknown): string | null {
  if (Array.isArray(value)) {
    const values = value.map((item) => stringValue(item)).filter((item): item is string => item !== null);
    return values.length > 0 ? values.join(", ") : null;
  }

  return stringValue(value);
}

function stringArrayValue(value: unknown): string[] | null {
  if (!Array.isArray(value)) {
    return null;
  }

  const values = value.map((item) => stringValue(item)).filter((item): item is string => item !== null);
  return values.length > 0 ? values : null;
}

function numberValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string") {
    const parsed = Number.parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function bufferToString(value: string | Buffer | undefined): string {
  if (!value) {
    return "";
  }

  return Buffer.isBuffer(value) ? value.toString("utf8") : value;
}

function firstNonEmptyLine(value: string): string | null {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find(Boolean) ?? null;
}

function truncateEvidence(value: string, maxLength = 12_000): string {
  const redacted = redactSecrets(value);

  if (redacted.length <= maxLength) {
    return redacted;
  }

  return `${redacted.slice(0, maxLength)}\n...[truncated]`;
}

function redactObject(value: unknown): unknown {
  return JSON.parse(redactSecrets(JSON.stringify(value)));
}

function normalizeSeverity(value: string | null, fallback: Severity): Severity {
  const normalized = value?.toLowerCase().trim();

  switch (normalized) {
    case "critical":
    case "crit":
      return "critical";
    case "high":
    case "error":
    case "fail":
    case "failed":
      return "high";
    case "medium":
    case "moderate":
    case "warning":
    case "warn":
      return "medium";
    case "low":
      return "low";
    case "info":
    case "informational":
    case "passed":
      return "info";
    default:
      return fallback;
  }
}

function normalizeOsvSeverity(vulnerability: Record<string, any>): Severity {
  const severity = stringValue(vulnerability.database_specific?.severity);

  if (severity) {
    return normalizeSeverity(severity, "medium");
  }

  const cvssSeverity = arrayValue(vulnerability.severity)
    .map((entry) => stringValue(asRecord(entry).score))
    .find(Boolean);

  if (!cvssSeverity) {
    return "medium";
  }

  const cvssScore = Number.parseFloat(cvssSeverity.split("/").pop() ?? cvssSeverity);

  if (!Number.isFinite(cvssScore)) {
    return "medium";
  }

  if (cvssScore >= 9) return "critical";
  if (cvssScore >= 7) return "high";
  if (cvssScore >= 4) return "medium";
  return "low";
}

function normalizeZapSeverity(value: string | null): Severity {
  if (!value) {
    return "medium";
  }

  if (value === "3") return "high";
  if (value === "2") return "medium";
  if (value === "1") return "low";
  if (value === "0") return "info";
  return normalizeSeverity(value.split(/\s|\(/)[0] ?? value, "medium");
}

function normalizeExternalFilePath(plan: ScanExecutionPlan, value: string | null): string | null {
  if (!value) {
    return null;
  }

  const withoutMount = value.startsWith(projectMountTarget)
    ? path.relative(projectMountTarget, value)
    : value.startsWith(stepProjectPrefix(plan))
      ? path.relative(plan.project.path, value)
      : value;

  const normalized = withoutMount.replaceAll("\\", "/").replace(/^\/+/, "");
  return normalized || null;
}

function stepProjectPrefix(plan: ScanExecutionPlan): string {
  return path.resolve(plan.project.path);
}

function createExecutionFinding(
  plan: ScanExecutionPlan,
  step: ScanExecutionStep,
  input: {
    severity: Severity;
    title: string;
    description: string;
    recommendation: string;
    ruleId?: string | null;
    filePath?: string | null;
    line?: number | null;
    endpoint?: string | null;
    cwe?: string | null;
    cve?: string | null;
    owasp?: string | null;
    evidence?: string | null;
  }
): Finding {
  const filePath = input.filePath ?? null;
  const fingerprint = createFindingFingerprint({
    tool: step.tool,
    type: step.type,
    ruleId: input.ruleId ?? step.checkId,
    filePath,
    line: input.line ?? null,
    endpoint: input.endpoint ?? null,
    title: input.title
  });

  return {
    id: `finding_${fingerprint.slice(0, 16)}`,
    scanRunId: plan.scanRunId,
    tool: step.tool,
    type: step.type,
    severity: input.severity,
    title: input.title,
    description: input.description,
    evidence: redactSecrets(input.evidence ?? `${step.checkId}: ${input.description}`),
    filePath,
    line: input.line ?? null,
    endpoint: input.endpoint ?? null,
    cwe: input.cwe ?? null,
    cve: input.cve ?? null,
    owasp: input.owasp ?? null,
    recommendation: input.recommendation,
    status: "open",
    fingerprint
  };
}
