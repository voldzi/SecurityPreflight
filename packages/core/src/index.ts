import { createHash } from "node:crypto";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type GateResult = "pass" | "warning" | "fail" | "error";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type FindingStatus = "open" | "accepted" | "false-positive" | "fixed" | "suppressed";
export type DataClassification =
  | "public"
  | "internal"
  | "confidential"
  | "sensitive"
  | "health-data";
export type FindingType =
  | "sast"
  | "sca"
  | "secret"
  | "container"
  | "iac"
  | "dast"
  | "openapi"
  | "documentation"
  | "configuration"
  | "tooling";

export interface Project {
  id: string;
  name: string;
  path: string;
  repositoryUrl: string | null;
  defaultBranch: string | null;
  technologyStack: string[];
  dataClassification: DataClassification;
  owner: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ScanProfile {
  id: string;
  name: string;
  description: string;
  checks: string[];
  failThreshold: Exclude<Severity, "info">;
  allowActiveDast: boolean;
  allowProductionTargets: boolean;
  timeoutSeconds: number;
}

export interface ScanRun {
  id: string;
  projectId: string;
  profileId: string;
  status: ScanStatus;
  startedAt: string;
  finishedAt: string | null;
  commitHash: string | null;
  branch: string | null;
  toolVersions: Record<string, string>;
  summary: SeveritySummary;
  gateResult: GateResult;
}

export interface Finding {
  id: string;
  scanRunId: string;
  tool: string;
  type: FindingType;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
  filePath: string | null;
  line: number | null;
  endpoint: string | null;
  cwe: string | null;
  cve: string | null;
  owasp: string | null;
  recommendation: string;
  status: FindingStatus;
  fingerprint: string;
}

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface GateEvaluation {
  result: GateResult;
  blockingReasons: string[];
  summary: SeveritySummary;
}

export const severityOrder: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

export const defaultScanProfiles: ScanProfile[] = [
  {
    id: "fast-local",
    name: "fast-local",
    description: "Quick local feedback for secrets, documentation, OpenAPI, lightweight SAST, and filesystem SCA.",
    checks: ["gitleaks:quick", "documentation", "openapi", "semgrep:light", "trivy:fs-quick"],
    failThreshold: "critical",
    allowActiveDast: false,
    allowProductionTargets: false,
    timeoutSeconds: 600
  },
  {
    id: "pre-commit",
    name: "pre-commit",
    description: "Pre-commit gate for secrets, lightweight code checks, dependency scan, OpenAPI, and forbidden files.",
    checks: ["gitleaks", "semgrep:light", "trivy:fs", "openapi", "env-example", "forbidden-files"],
    failThreshold: "critical",
    allowActiveDast: false,
    allowProductionTargets: false,
    timeoutSeconds: 900
  },
  {
    id: "pre-release",
    name: "pre-release",
    description: "Release readiness profile with full scanners, documentation compliance, gate evaluation, and reports.",
    checks: ["gitleaks:history", "semgrep", "trivy:fs", "openapi", "documentation", "container", "sbom"],
    failThreshold: "high",
    allowActiveDast: false,
    allowProductionTargets: false,
    timeoutSeconds: 1800
  },
  {
    id: "api-security",
    name: "api-security",
    description: "OpenAPI JSON-first checks, ErrorResponse compliance, health/readiness endpoints, and safe DAST readiness.",
    checks: ["openapi", "openapi:lint", "api:error-response", "api:health", "api:ready"],
    failThreshold: "high",
    allowActiveDast: false,
    allowProductionTargets: false,
    timeoutSeconds: 900
  },
  {
    id: "container-security",
    name: "container-security",
    description: "Dockerfile, image, and container misconfiguration readiness checks.",
    checks: ["dockerfile", "container:misconfiguration", "trivy:image", "container:secrets"],
    failThreshold: "high",
    allowActiveDast: false,
    allowProductionTargets: false,
    timeoutSeconds: 1200
  },
  {
    id: "documentation-compliance",
    name: "documentation-compliance",
    description: "Mandatory repository documentation and minimum content checks.",
    checks: ["documentation", "readme", "operations", "security", "observability", "runbook", "adr"],
    failThreshold: "medium",
    allowActiveDast: false,
    allowProductionTargets: false,
    timeoutSeconds: 300
  },
  {
    id: "sensitive-data-ready",
    name: "sensitive-data-ready",
    description: "Strict readiness checks for health, hospital, and highly sensitive data systems.",
    checks: ["threat-model", "data-classification", "audit-logging", "auth", "encryption", "retention", "secrets"],
    failThreshold: "medium",
    allowActiveDast: false,
    allowProductionTargets: false,
    timeoutSeconds: 1800
  }
];

export function emptySeveritySummary(): SeveritySummary {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function summarizeFindings(findings: Finding[]): SeveritySummary {
  return findings.reduce<SeveritySummary>((summary, finding) => {
    summary[finding.severity] += 1;
    return summary;
  }, emptySeveritySummary());
}

export function evaluateGate(
  findings: Finding[],
  profile: Pick<ScanProfile, "name" | "failThreshold">,
  dataClassification: DataClassification = "internal"
): GateEvaluation {
  const summary = summarizeFindings(findings);
  const openFindings = findings.filter((finding) => finding.status === "open");
  const blockingReasons: string[] = [];

  for (const finding of openFindings) {
    if (finding.type === "secret") {
      blockingReasons.push(`${finding.severity.toUpperCase()} secret finding: ${finding.title}`);
      continue;
    }

    if (finding.severity === "critical") {
      blockingReasons.push(`CRITICAL finding: ${finding.title}`);
      continue;
    }

    if (profile.name === "pre-release" && finding.severity === "high") {
      blockingReasons.push(`HIGH pre-release finding: ${finding.title}`);
      continue;
    }

    const isSensitive = dataClassification === "sensitive" || dataClassification === "health-data";
    const sensitiveMediumBlocker =
      isSensitive &&
      finding.severity === "medium" &&
      ["auth", "authorization", "audit", "encryption", "secret"].some((keyword) =>
        `${finding.title} ${finding.description} ${finding.recommendation}`.toLowerCase().includes(keyword)
      );

    if (sensitiveMediumBlocker) {
      blockingReasons.push(`MEDIUM sensitive-data finding: ${finding.title}`);
    }
  }

  if (blockingReasons.length > 0) {
    return { result: "fail", blockingReasons, summary };
  }

  const warningThreshold = severityOrder[profile.failThreshold] > severityOrder.medium ? "medium" : "low";
  const hasWarnings = openFindings.some((finding) => severityOrder[finding.severity] >= severityOrder[warningThreshold]);

  return {
    result: hasWarnings ? "warning" : "pass",
    blockingReasons,
    summary
  };
}

export function detectTechnologyStack(files: string[]): string[] {
  const names = new Set(files.map((file) => file.split("/").pop() ?? file));
  const stack = new Set<string>();

  if (names.has("package.json")) stack.add("Node.js");
  if (files.some((file) => file.endsWith("next.config.js") || file.endsWith("next.config.mjs"))) stack.add("Next.js");
  if (names.has("pnpm-lock.yaml")) stack.add("pnpm");
  if (names.has("Dockerfile")) stack.add("Docker");
  if (names.has("docker-compose.yml") || names.has("compose.yml")) stack.add("Docker Compose");
  if (names.has("pyproject.toml") || names.has("requirements.txt")) stack.add("Python");
  if (names.has("go.mod")) stack.add("Go");
  if (names.has("Cargo.toml")) stack.add("Rust");
  if (names.has("Package.swift")) stack.add("Swift");
  if (files.some((file) => file.endsWith(".xcodeproj"))) stack.add("Xcode");
  if (files.some((file) => file.endsWith(".xcworkspace"))) stack.add("Xcode Workspace");
  if (names.has("pom.xml")) stack.add("Maven");
  if (names.has("build.gradle") || names.has("build.gradle.kts")) stack.add("Gradle");

  return [...stack].sort();
}

export function createFindingFingerprint(input: {
  tool: string;
  type: FindingType;
  ruleId?: string | null;
  filePath?: string | null;
  line?: number | null;
  method?: string | null;
  endpoint?: string | null;
  title: string;
}): string {
  const normalizedTitle = input.title.trim().toLowerCase().replace(/\s+/g, " ");
  const material = [
    input.tool,
    input.type,
    input.ruleId ?? "",
    input.filePath ?? "",
    input.line ?? "",
    input.method ?? "",
    input.endpoint ?? "",
    normalizedTitle
  ].join("|");

  return createHash("sha256").update(material).digest("hex");
}

const redactionPatterns: Array<[RegExp, string]> = [
  [/(Authorization:\s*Bearer\s+)[^\s"']+/gi, "$1********"],
  [/(api[_-]?key\s*[:=]\s*)[^\s"']+/gi, "$1********"],
  [/(password\s*[:=]\s*)[^\s"']+/gi, "$1********"],
  [/(cookie\s*[:=]\s*)[^\n\r]+/gi, "$1********"],
  [/(token\s*[:=]\s*)[^\s"']+/gi, "$1********"]
];

export function redactSecrets(value: string): string {
  return redactionPatterns.reduce((redacted, [pattern, replacement]) => redacted.replace(pattern, replacement), value);
}
