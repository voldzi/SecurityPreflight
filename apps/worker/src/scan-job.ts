import path from "node:path";
import { mkdir, writeFile } from "node:fs/promises";
import {
  executeScanPlan,
  writeExecutionResultEvidence,
  type ScanExecutionPlan,
  type ScanExecutionResult
} from "@security-preflight/scanners";
import { generateCentralResultEnvelope, generateJsonReport, generateMarkdownReport } from "@security-preflight/report";
import type { Project, ScanProfile, ScanRun } from "@security-preflight/core";

export interface ExecuteScanJobInput {
  plan: ScanExecutionPlan;
  requestId?: string;
}

export interface ExecuteScanJobResult {
  scanRunId: string;
  status: "completed" | "failed";
  evidenceRoot: string;
  gateResult: string;
  findingCount: number;
  reportPaths: {
    executionResult: string;
    json: string;
    markdown: string;
    centralEnvelope: string;
  };
}

export async function executeScanJob(input: ExecuteScanJobInput): Promise<ExecuteScanJobResult> {
  const plan = mapProjectPathForWorker(input.plan);
  const execution = await executeScanPlan(plan, {
    runExternalCommands: process.env.SCANNER_RUNNER_ENABLED !== "false",
    externalRunner: process.env.SCANNER_RUNNER_MODE === "docker" ? "docker" : "direct",
    scannerImage: process.env.SCANNER_TOOLBOX_IMAGE
  });
  const executionResult = await writeExecutionResultEvidence(execution);
  const reportPaths = await writeReports(plan, execution);

  return {
    scanRunId: plan.scanRunId,
    status: execution.status,
    evidenceRoot: plan.evidenceRoot,
    gateResult: execution.gate.result,
    findingCount: execution.findings.length,
    reportPaths: {
      executionResult,
      ...reportPaths
    }
  };
}

function mapProjectPathForWorker(plan: ScanExecutionPlan): ScanExecutionPlan {
  const hostRoot = process.env.PROJECTS_ROOT_HOST;
  const containerRoot = process.env.PROJECTS_ROOT_CONTAINER;

  if (!hostRoot || !containerRoot) {
    return plan;
  }

  const normalizedHostRoot = path.resolve(hostRoot);
  const normalizedProjectPath = path.resolve(plan.project.path);
  const relative = path.relative(normalizedHostRoot, normalizedProjectPath);

  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    return plan;
  }

  const mappedPath = path.join(containerRoot, relative);

  return {
    ...plan,
    project: {
      ...plan.project,
      path: mappedPath
    },
    steps: plan.steps.map((step) => ({
      ...step,
      projectMount: {
        ...step.projectMount,
        sourcePath: mappedPath
      }
    }))
  };
}

async function writeReports(
  plan: ScanExecutionPlan,
  execution: ScanExecutionResult
): Promise<{ json: string; markdown: string; centralEnvelope: string }> {
  await mkdir(plan.evidenceRoot, { recursive: true });

  const now = new Date().toISOString();
  const project: Project = {
    id: plan.project.id,
    name: plan.project.name,
    path: plan.project.path,
    repositoryUrl: null,
    defaultBranch: null,
    technologyStack: [],
    dataClassification: plan.project.dataClassification ?? "internal",
    owner: null,
    createdAt: plan.createdAt,
    updatedAt: now
  };
  const profile: ScanProfile = {
    id: plan.profile.id,
    name: plan.profile.name,
    description: "Runtime scan profile reconstructed from the queued execution plan.",
    checks: plan.steps.map((step) => step.checkId),
    failThreshold: plan.profile.failThreshold,
    allowActiveDast: plan.profile.allowActiveDast,
    allowProductionTargets: plan.profile.allowProductionTargets,
    timeoutSeconds: plan.profile.timeoutSeconds
  };
  const scanRun: ScanRun = {
    id: plan.scanRunId,
    projectId: plan.project.id,
    profileId: plan.profile.id,
    status: execution.status,
    startedAt: execution.startedAt,
    finishedAt: execution.finishedAt,
    commitHash: null,
    branch: null,
    toolVersions: {},
    summary: execution.gate.summary,
    gateResult: execution.gate.result
  };
  const input = {
    project,
    scanRun,
    profile,
    gate: execution.gate,
    findings: execution.findings
  };
  const json = path.join(plan.evidenceRoot, "report.json");
  const markdown = path.join(plan.evidenceRoot, "report.md");
  const centralEnvelope = path.join(plan.evidenceRoot, "central-result-envelope.json");

  await writeFile(json, `${generateJsonReport(input)}\n`, "utf8");
  await writeFile(markdown, generateMarkdownReport(input), "utf8");
  await writeFile(centralEnvelope, `${JSON.stringify(generateCentralResultEnvelope(input), null, 2)}\n`, "utf8");

  return { json, markdown, centralEnvelope };
}
