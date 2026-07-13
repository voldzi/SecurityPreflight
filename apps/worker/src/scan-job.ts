import path from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import {
  executeScanPlan,
  resolveSecretReference,
  writeExecutionResultEvidence,
  type ScanExecutionPlan,
  type ScanExecutionResult
} from "@security-preflight/scanners";
import { recordCompletedScan, recordFailedScan, recordRunningScan, recordScanStepResult } from "@security-preflight/persistence";
import { generateCentralResultEnvelope, generateJsonReport, generateMarkdownReport, generateSarifReport } from "@security-preflight/report";
import { informationPolicyBindingHash, type InformationPolicyBinding, type Project, type ScanProfile, type ScanRun } from "@security-preflight/core";

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
    sarif: string;
    centralTelemetryDelivery: string;
    defectDojoDelivery: string;
  };
}

export async function executeScanJob(input: ExecuteScanJobInput): Promise<ExecuteScanJobResult> {
  const plan = mapProjectPathForWorker(input.plan);

  try {
    if (planRequiresExternalOperation(plan)) {
      const decision = await authorizeWorkerExternalOperation({ operation: "external_operation", scopeId: plan.project.id, policyBinding: plan.project.policyBinding });
      if (!decision.allowed) {
        throw new Error(`Worker external operation denied by STRATOS policy (${decision.reasonCodes.join(",")}).`);
      }
    }
    await recordRunningScan(plan, input.requestId);

    const execution = await executeScanPlan(plan, {
      runExternalCommands: process.env.SCANNER_RUNNER_ENABLED !== "false",
      externalRunner: resolveWorkerRunnerMode(),
      scannerImage: process.env.SCANNER_TOOLBOX_IMAGE,
      onStepResult: async (result) => {
        await recordScanStepResult(plan, result);
      }
    });
    const executionResult = await writeExecutionResultEvidence(execution);
    const reportPaths = await writeReports(plan, execution);
    const integrationPaths = await writeIntegrationDeliveries(plan, reportPaths);
    const persistedReportPaths = {
      executionResult,
      ...reportPaths,
      ...integrationPaths
    };

    await recordCompletedScan(plan, execution, persistedReportPaths);

    return {
      scanRunId: plan.scanRunId,
      status: execution.status,
      evidenceRoot: plan.evidenceRoot,
      gateResult: execution.gate.result,
      findingCount: execution.findings.length,
      reportPaths: persistedReportPaths
    };
  } catch (error) {
    await recordFailedScan(plan, error, input.requestId);
    throw error;
  }
}

export function planRequiresExternalOperation(plan: ScanExecutionPlan) {
  return Boolean(plan.policy.activeDastTarget) || plan.steps.some((step) => step.networkMode === "restricted");
}

function resolveWorkerRunnerMode(): "direct" | "docker" | "remote" {
  if (process.env.SCANNER_RUNNER_MODE === "docker") return "docker";
  if (process.env.SCANNER_RUNNER_MODE === "remote") return "remote";

  return "direct";
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
): Promise<{ json: string; markdown: string; centralEnvelope: string; sarif: string }> {
  await mkdir(plan.evidenceRoot, { recursive: true });

  const now = new Date().toISOString();
  const project: Project = {
    id: plan.project.id,
    name: plan.project.name,
    path: plan.project.path,
    repositoryUrl: null,
    publicUrl: plan.policy.activeDastTarget,
    defaultBranch: null,
    technologyStack: [],
    dataClassification: plan.project.dataClassification ?? "internal",
    policyBinding: plan.project.policyBinding,
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
  const sarif = path.join(plan.evidenceRoot, "defectdojo.sarif.json");

  await writeFile(json, `${generateJsonReport(input)}\n`, "utf8");
  await writeFile(markdown, generateMarkdownReport(input), "utf8");
  await writeFile(centralEnvelope, `${JSON.stringify(generateCentralResultEnvelope(input), null, 2)}\n`, "utf8");
  await writeFile(sarif, `${generateSarifReport(input)}\n`, "utf8");

  return { json, markdown, centralEnvelope, sarif };
}

async function writeIntegrationDeliveries(
  plan: ScanExecutionPlan,
  reportPaths: { centralEnvelope: string; sarif: string }
): Promise<{ centralTelemetryDelivery: string; defectDojoDelivery: string }> {
  const centralTelemetryDelivery = path.join(plan.evidenceRoot, "central-telemetry-delivery.json");
  const defectDojoDelivery = path.join(plan.evidenceRoot, "defectdojo-delivery.json");

  const centralTelemetry = await deliverCentralTelemetry(reportPaths.centralEnvelope);
  await writeFile(centralTelemetryDelivery, `${JSON.stringify(centralTelemetry, null, 2)}\n`, "utf8");

  const defectDojo = await deliverDefectDojoSarif(plan, reportPaths.sarif);
  await writeFile(defectDojoDelivery, `${JSON.stringify(defectDojo, null, 2)}\n`, "utf8");

  if (centralTelemetry.status === "failed" && process.env.SECURITY_PREFLIGHT_RESULT_SINK_REQUIRED === "true") {
    throw new Error(String(centralTelemetry.message ?? "Central telemetry delivery failed."));
  }

  if (defectDojo.status === "failed" && process.env.SECURITY_PREFLIGHT_DEFECTDOJO_EXPORT_REQUIRED === "true") {
    throw new Error(String(defectDojo.message ?? "DefectDojo export failed."));
  }

  return { centralTelemetryDelivery, defectDojoDelivery };
}

async function deliverCentralTelemetry(centralEnvelopePath: string): Promise<Record<string, unknown>> {
  const enabled = process.env.SECURITY_PREFLIGHT_RESULT_SINK_ENABLED === "true";
  const endpoint = process.env.SECURITY_PREFLIGHT_RESULT_SINK_URL?.trim();

  if (!enabled) {
    return {
      status: "skipped",
      reason: "SECURITY_PREFLIGHT_RESULT_SINK_ENABLED is not true.",
      generatedAt: new Date().toISOString()
    };
  }

  if (!endpoint) {
    return {
      status: "failed",
      message: "SECURITY_PREFLIGHT_RESULT_SINK_URL is required when central telemetry delivery is enabled.",
      generatedAt: new Date().toISOString()
    };
  }

  const token = await resolveSecretReference(process.env.SECURITY_PREFLIGHT_RESULT_SINK_TOKEN_REF);
  const envelope = await readFile(centralEnvelopePath, "utf8");
  const parsedEnvelope = JSON.parse(envelope) as { project?: { id?: string; dataClassification?: string }; policyBinding?: Record<string, unknown> };
  const policyDecision = await authorizeWorkerExternalOperation({ operation: "external_operation", scopeId: parsedEnvelope.project?.id ?? "unknown", policyBinding: parsedEnvelope.policyBinding });
  if (!policyDecision.allowed) return { status: "failed", message: "Central telemetry delivery denied by policy.", decisionId: policyDecision.decisionId, reasonCodes: policyDecision.reasonCodes, generatedAt: new Date().toISOString() };

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "user-agent": "SecurityPreflight/0.1 telemetry-export",
        ...(token.ok ? { authorization: `Bearer ${token.value}` } : {})
      },
      body: envelope,
      signal: AbortSignal.timeout(30_000)
    });
    const body = await response.text();

    return {
      status: response.ok ? "sent" : "failed",
      endpoint,
      statusCode: response.status,
      generatedAt: new Date().toISOString(),
      response: redactDeliveryBody(body)
    };
  } catch (error) {
    return {
      status: "failed",
      endpoint,
      generatedAt: new Date().toISOString(),
      message: error instanceof Error ? error.message : String(error)
    };
  }
}

async function deliverDefectDojoSarif(plan: ScanExecutionPlan, sarifPath: string): Promise<Record<string, unknown>> {
  const enabled = process.env.SECURITY_PREFLIGHT_DEFECTDOJO_EXPORT_ENABLED === "true";
  const baseUrl = process.env.SECURITY_PREFLIGHT_DEFECTDOJO_URL?.trim();
  const productName = process.env.SECURITY_PREFLIGHT_DEFECTDOJO_PRODUCT?.trim();

  if (!enabled) {
    return {
      status: "skipped",
      reason: "SECURITY_PREFLIGHT_DEFECTDOJO_EXPORT_ENABLED is not true.",
      sarifPath,
      generatedAt: new Date().toISOString()
    };
  }

  const token = await resolveSecretReference(process.env.SECURITY_PREFLIGHT_DEFECTDOJO_TOKEN_REF);
  const policyDecision = await authorizeWorkerExternalOperation({ operation: "export", scopeId: plan.project.id, policyBinding: plan.project.policyBinding });
  if (!policyDecision.allowed) return { status: "failed", message: "DefectDojo export denied by policy.", decisionId: policyDecision.decisionId, reasonCodes: policyDecision.reasonCodes, generatedAt: new Date().toISOString() };

  if (!baseUrl || !productName || !token.ok) {
    return {
      status: "failed",
      message: "DefectDojo URL, product, and resolvable token reference are required for SARIF export.",
      configuredBaseUrl: Boolean(baseUrl),
      configuredProduct: Boolean(productName),
      tokenResolved: token.ok,
      tokenSource: token.source,
      generatedAt: new Date().toISOString()
    };
  }

  const sarif = await readFile(sarifPath, "utf8");
  const endpoint = `${baseUrl.replace(/\/+$/, "")}/api/v2/${process.env.SECURITY_PREFLIGHT_DEFECTDOJO_REIMPORT === "true" ? "reimport-scan" : "import-scan"}/`;
  const form = new FormData();
  const date = new Date().toISOString().slice(0, 10);

  form.set("scan_type", "SARIF");
  form.set("file", new Blob([sarif], { type: "application/sarif+json" }), `${plan.scanRunId}.sarif.json`);
  form.set("minimum_severity", process.env.SECURITY_PREFLIGHT_DEFECTDOJO_MINIMUM_SEVERITY ?? "Info");
  form.set("active", "true");
  form.set("verified", process.env.SECURITY_PREFLIGHT_DEFECTDOJO_VERIFIED ?? "false");
  form.set("test_title", process.env.SECURITY_PREFLIGHT_DEFECTDOJO_TEST_TITLE ?? `SecurityPreflight ${plan.profile.id} ${plan.scanRunId}`);
  form.set("product_type_name", process.env.SECURITY_PREFLIGHT_DEFECTDOJO_PRODUCT_TYPE ?? "STRATOS");
  form.set("product_name", productName);
  form.set("engagement_name", process.env.SECURITY_PREFLIGHT_DEFECTDOJO_ENGAGEMENT ?? `SecurityPreflight ${date}`);
  form.set("auto_create_context", process.env.SECURITY_PREFLIGHT_DEFECTDOJO_AUTO_CREATE_CONTEXT ?? "true");

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Token ${token.value}`,
        "user-agent": "SecurityPreflight/0.1 defectdojo-sarif"
      },
      body: form,
      signal: AbortSignal.timeout(60_000)
    });
    const body = await response.text();

    return {
      status: response.ok ? "sent" : "failed",
      endpoint,
      scanType: "SARIF",
      productName,
      statusCode: response.status,
      sarifPath,
      generatedAt: new Date().toISOString(),
      response: redactDeliveryBody(body)
    };
  } catch (error) {
    return {
      status: "failed",
      endpoint,
      productName,
      sarifPath,
      generatedAt: new Date().toISOString(),
      message: error instanceof Error ? error.message : String(error)
    };
  }
}

export async function authorizeWorkerExternalOperation(input: { operation: string; scopeId: string; policyBinding?: object }): Promise<{ allowed: boolean; decisionId: string | null; reasonCodes: string[] }> {
  const endpoint = process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL?.trim();
  const token = process.env.SECURITY_PREFLIGHT_WORKER_SERVICE_TOKEN?.trim();
  const capabilityId = input.operation === "export"
    ? "security-preflight:export"
    : input.operation === "external_operation"
      ? "security-preflight:external_operation"
      : null;
  if (!endpoint || !token || !capabilityId || !registeredPolicyBinding(input.policyBinding, input.scopeId)) return { allowed: false, decisionId: null, reasonCodes: ["POLICY_UNAVAILABLE"] };
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { accept: "application/json", authorization: `Bearer ${token}`, "content-type": "application/json", "x-correlation-id": `worker:${input.scopeId}` },
      body: JSON.stringify({ applicationId: "security-preflight", capabilityId, operation: input.operation, scope: { type: "project", id: input.scopeId }, policyBinding: input.policyBinding }),
      signal: AbortSignal.timeout(Number(process.env.SECURITY_PREFLIGHT_POLICY_TIMEOUT_MS ?? 3000))
    });
    if (!response.ok) return { allowed: false, decisionId: null, reasonCodes: ["POLICY_UNAVAILABLE"] };
    const decision = await response.json() as { decision?: string; decisionId?: string; reasonCodes?: string[]; obligations?: string[]; policyVersion?: string };
    const validDecision = (decision.decision === "ALLOW" || decision.decision === "DENY")
      && typeof decision.decisionId === "string"
      && Boolean(decision.decisionId)
      && decision.policyVersion === "information-policy-2.0.0"
      && Array.isArray(decision.reasonCodes)
      && decision.reasonCodes.length > 0
      && decision.reasonCodes.every((reason) => typeof reason === "string" && Boolean(reason))
      && Array.isArray(decision.obligations)
      && decision.obligations.every((obligation) => typeof obligation === "string" && workerPolicyObligations.has(obligation));
    if (!validDecision) return { allowed: false, decisionId: null, reasonCodes: ["POLICY_RESPONSE_INVALID"] };
    if (decision.decision !== "ALLOW" || !decision.obligations?.includes("AUDIT_ACCESS")) {
      return { allowed: false, decisionId: decision.decisionId ?? null, reasonCodes: decision.reasonCodes ?? ["POLICY_RESPONSE_INVALID"] };
    }
    return { allowed: true, decisionId: decision.decisionId as string, reasonCodes: decision.reasonCodes as string[] };
  } catch {
    return { allowed: false, decisionId: null, reasonCodes: ["POLICY_UNAVAILABLE"] };
  }
}

const workerPolicyObligations = new Set([
  "AUDIT_ACCESS",
  "NO_EXTERNAL_AI",
  "LOCAL_PROCESSING_ONLY",
  "NO_PUBLIC_EXPORT",
  "NO_EXPORT",
  "WATERMARK",
  "ENCRYPT_AT_REST",
  "RECIPIENT_CONFIRMATION",
  "ORIGINATOR_APPROVAL",
  "PAP_ENFORCEMENT"
]);

function registeredPolicyBinding(value: object | undefined, scopeId: string): value is Record<string, unknown> {
  if (!value || Array.isArray(value)) return false;
  const binding = value as Record<string, unknown>;
  const obligations = strictUniqueKnownStrings(binding.obligations, workerPolicyObligations);
  const categories = strictUniqueKnownStrings(binding.contentCategories, workerPolicyContentCategories);
  const audience = recordValue(binding.audience);
  const scopeIds = strictUniqueCanonicalStrings(audience.scopeIds);
  const recipients = audience.recipientSubjectIds === undefined ? [] : strictUniqueCanonicalStrings(audience.recipientSubjectIds);
  const hashMatches = typeof binding.policyHash === "string"
    && binding.policyHash === informationPolicyBindingHash(binding as unknown as InformationPolicyBinding);
  return binding.schemaVersion === "stratos-information-policy-2"
    && typeof binding.policyBindingId === "string"
    && /^(?:pol|pb)_[A-Za-z0-9_-]{8,}$/.test(binding.policyBindingId)
    && binding.organizationId === "org_stratos"
    && binding.applicationId === "security-preflight"
    && binding.policyVersion === "information-policy-2.0.0"
    && ["PUBLIC", "INTERNAL", "RESTRICTED"].includes(String(binding.handlingClass))
    && binding.legalClassification === "NONE"
    && (binding.tlp === null || ["TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"].includes(String(binding.tlp)))
    && (binding.pap === null || ["PAP:RED", "PAP:AMBER", "PAP:GREEN", "PAP:CLEAR"].includes(String(binding.pap)))
    && obligations !== null
    && categories !== null
    && audience.organizationId === "org_stratos"
    && audience.scopeType === "project"
    && scopeIds !== null
    && scopeIds.length === 1
    && scopeIds[0] === scopeId
    && recipients !== null
    && recipients.length === 0
    && hashMatches;
}

const workerPolicyContentCategories = new Set([
  "PERSONAL_DATA",
  "FINANCIAL",
  "CONTRACTUAL",
  "PROJECT_MANAGEMENT",
  "SECURITY",
  "CYBER_THREAT",
  "SOURCE_CODE",
  "AUTHENTICATION",
  "AUDIT",
  "PUBLIC_INFORMATION"
]);

function strictUniqueKnownStrings(value: unknown, allowed: Set<string>): string[] | null {
  const items = strictUniqueCanonicalStrings(value);
  return items && items.every((item) => allowed.has(item)) ? items : null;
}

function strictUniqueCanonicalStrings(value: unknown): string[] | null {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string" && item.length > 0 && item === item.trim())) return null;
  const items = value as string[];
  return new Set(items).size === items.length ? items : null;
}

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function redactDeliveryBody(value: string, maxLength = 4_000): string {
  const redacted = value
    .replace(/(Authorization:\s*Bearer\s+)[^\s"']+/gi, "$1********")
    .replace(/(Authorization:\s*Token\s+)[^\s"']+/gi, "$1********")
    .replace(/(token\s*[:=]\s*)[^\s"']+/gi, "$1********");

  return redacted.length <= maxLength ? redacted : `${redacted.slice(0, maxLength)}\n...[truncated]`;
}
