import { execFile } from "node:child_process";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
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
  type Severity
} from "@security-preflight/core";

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
  ...requiredScannerTools.map((tool) => ({
    name: tool.name,
    command: tool.command,
    args: tool.args
  }))
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

export interface ExecuteScanPlanOptions {
  runExternalCommands?: boolean;
  treatSkippedExternalChecksAsFindings?: boolean;
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
  const evidencePath = primaryEvidencePath(step);

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

    const result: ScanStepExecutionResult = {
      stepId: step.id,
      checkId: step.checkId,
      status: "skipped",
      startedAt,
      finishedAt: new Date().toISOString(),
      evidencePath,
      findings: [
        createExecutionFinding(plan, step, {
          severity: "high",
          title: `Scanner step '${step.checkId}' needs an isolated runner`,
          description: "Direct host execution is intentionally not implemented for scanner commands.",
          recommendation: "Run external scanners through the constrained scanner-toolbox adapter."
        })
      ],
      message: "External scanner runner is not implemented yet."
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
    evidencePath: primaryEvidencePath(step),
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

  await writeFile(primaryEvidencePath(step), `${redactSecrets(JSON.stringify(payload, null, 2))}\n`, "utf8");
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

function createExecutionFinding(
  plan: ScanExecutionPlan,
  step: ScanExecutionStep,
  input: {
    severity: Severity;
    title: string;
    description: string;
    recommendation: string;
    filePath?: string | null;
  }
): Finding {
  const filePath = input.filePath ?? null;
  const fingerprint = createFindingFingerprint({
    tool: step.tool,
    type: step.type,
    ruleId: step.checkId,
    filePath,
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
    evidence: redactSecrets(`${step.checkId}: ${input.description}`),
    filePath,
    line: null,
    endpoint: null,
    cwe: null,
    cve: null,
    owasp: null,
    recommendation: input.recommendation,
    status: "open",
    fingerprint
  };
}
