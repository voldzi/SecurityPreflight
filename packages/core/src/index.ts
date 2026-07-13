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
export type FindingScope = "application" | "platform";
export const INFORMATION_POLICY_VERSION = "information-policy-2.0.0" as const;
export const INTEGRATION_ENVELOPE_VERSION = "stratos-integration-envelope-1" as const;
export const STRATOS_ORGANIZATION_ID = "org_stratos" as const;
export interface InformationPolicyBinding {
  policyBindingId?: string;
  organizationId?: string;
  policyHash?: string;
  policyVersion: string;
  handlingClass: string;
  legalClassification: "NONE";
  tlp: string | null;
  pap: string | null;
  obligations: string[];
  contentCategories: string[];
  audience: Record<string, unknown>;
}

export function informationPolicyBindingForClassification(classification: string): InformationPolicyBinding {
  const values: Record<string, Pick<InformationPolicyBinding, "handlingClass" | "tlp" | "pap" | "obligations">> = {
    public: { handlingClass: "PUBLIC", tlp: "TLP:CLEAR", pap: "PAP:CLEAR", obligations: ["AUDIT_ACCESS"] },
    internal: { handlingClass: "INTERNAL", tlp: "TLP:GREEN", pap: "PAP:GREEN", obligations: ["AUDIT_ACCESS"] },
    confidential: { handlingClass: "RESTRICTED", tlp: "TLP:AMBER", pap: "PAP:AMBER", obligations: ["AUDIT_ACCESS", "NO_PUBLIC_EXPORT", "ENCRYPT_AT_REST"] },
    sensitive: { handlingClass: "RESTRICTED", tlp: "TLP:AMBER+STRICT", pap: "PAP:AMBER", obligations: ["AUDIT_ACCESS", "NO_PUBLIC_EXPORT", "ENCRYPT_AT_REST"] },
    "health-data": { handlingClass: "RESTRICTED", tlp: "TLP:AMBER+STRICT", pap: "PAP:AMBER", obligations: ["AUDIT_ACCESS", "NO_PUBLIC_EXPORT", "ENCRYPT_AT_REST"] }
  };
  const mapped = values[classification];
  if (!mapped) throw new Error(`Unknown SecurityPreflight data classification: ${classification}`);
  return { ...mapped, policyVersion: INFORMATION_POLICY_VERSION, legalClassification: "NONE", contentCategories: ["SECURITY", "CYBER_THREAT"], audience: { organizationId: STRATOS_ORGANIZATION_ID, scopeType: "project" } };
}

export function informationPolicyBindingHash(binding: InformationPolicyBinding): string {
  const canonical = stablePolicyJson({ audience: binding.audience, contentCategories: binding.contentCategories, handlingClass: binding.handlingClass, legalClassification: binding.legalClassification, obligations: binding.obligations, pap: binding.pap, policyBindingId: binding.policyBindingId ?? null, policyVersion: binding.policyVersion, tlp: binding.tlp });
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

function stablePolicyJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stablePolicyJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stablePolicyJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}
export type ToolCategory =
  | "runtime"
  | "secret-scanning"
  | "sast"
  | "sca"
  | "sbom"
  | "license"
  | "container"
  | "iac"
  | "openapi"
  | "dast"
  | "attestation"
  | "telemetry";

export interface ToolRequirement {
  id: string;
  name: string;
  category: ToolCategory;
  requiredForHealthcare: boolean;
  command: string;
  args: string[];
  checks: string[];
  purpose: string;
}

export interface Project {
  id: string;
  name: string;
  path: string;
  repositoryUrl: string | null;
  publicUrl: string | null;
  defaultBranch: string | null;
  technologyStack: string[];
  dataClassification: DataClassification;
  policyBinding?: InformationPolicyBinding;
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
  scope?: FindingScope;
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

export const requiredScannerTools: ToolRequirement[] = [
  {
    id: "docker",
    name: "Docker",
    category: "runtime",
    requiredForHealthcare: true,
    command: "docker",
    args: ["--version"],
    checks: ["container", "trivy:image", "scanner-toolbox"],
    purpose: "Local container runtime for isolated scanner execution."
  },
  {
    id: "docker-compose",
    name: "Docker Compose",
    category: "runtime",
    requiredForHealthcare: true,
    command: "docker",
    args: ["compose", "version"],
    checks: ["local-stack", "scanner-toolbox"],
    purpose: "Local orchestration for API, worker, Redis, PostgreSQL, and scanner services."
  },
  {
    id: "gitleaks",
    name: "Gitleaks",
    category: "secret-scanning",
    requiredForHealthcare: true,
    command: "gitleaks",
    args: ["version"],
    checks: ["gitleaks:quick", "gitleaks", "gitleaks:history", "secrets"],
    purpose: "Secret detection in working tree and Git history."
  },
  {
    id: "semgrep",
    name: "Semgrep",
    category: "sast",
    requiredForHealthcare: true,
    command: "semgrep",
    args: ["--version"],
    checks: ["semgrep:light", "semgrep", "auth", "authorization", "audit-logging"],
    purpose: "Static application security checks and framework-specific rules."
  },
  {
    id: "trivy",
    name: "Trivy",
    category: "sca",
    requiredForHealthcare: true,
    command: "trivy",
    args: ["--version"],
    checks: ["trivy:fs-quick", "trivy:fs", "trivy:image", "container:secrets", "container:misconfiguration"],
    purpose: "Filesystem, dependency, container, and misconfiguration scanning."
  },
  {
    id: "redocly",
    name: "Redocly",
    category: "openapi",
    requiredForHealthcare: true,
    command: "redocly",
    args: ["--version"],
    checks: ["openapi", "openapi:lint", "api:error-response", "api:health", "api:ready"],
    purpose: "OpenAPI JSON-first contract validation."
  },
  {
    id: "syft",
    name: "Syft",
    category: "sbom",
    requiredForHealthcare: true,
    command: "syft",
    args: ["version"],
    checks: ["syft:sbom", "sbom"],
    purpose: "CycloneDX SBOM generation for central evidence and supply-chain review."
  },
  {
    id: "grype",
    name: "Grype",
    category: "sca",
    requiredForHealthcare: true,
    command: "grype",
    args: ["version"],
    checks: ["grype:sbom", "license-policy"],
    purpose: "Vulnerability analysis from SBOM evidence."
  },
  {
    id: "osv-scanner",
    name: "OSV Scanner",
    category: "sca",
    requiredForHealthcare: true,
    command: "osv-scanner",
    args: ["--version"],
    checks: ["osv:dependencies"],
    purpose: "Open-source vulnerability checks against lockfiles and manifests."
  },
  {
    id: "checkov",
    name: "Checkov",
    category: "iac",
    requiredForHealthcare: true,
    command: "checkov",
    args: ["--version"],
    checks: ["iac:checkov"],
    purpose: "Infrastructure-as-code and deployment policy scanning."
  },
  {
    id: "zap",
    name: "OWASP ZAP",
    category: "dast",
    requiredForHealthcare: true,
    command: "zap-baseline.py",
    args: ["--version"],
    checks: ["zap:baseline", "zap:api-scan"],
    purpose: "Controlled baseline DAST for explicitly allowlisted owned targets."
  },
  {
    id: "nuclei",
    name: "Nuclei",
    category: "dast",
    requiredForHealthcare: true,
    command: "nuclei",
    args: ["-version"],
    checks: ["nuclei:safe"],
    purpose: "Safe-template exposure and misconfiguration checks for explicitly allowlisted owned web targets."
  },
  {
    id: "gvm-cli",
    name: "Greenbone/OpenVAS CLI",
    category: "dast",
    requiredForHealthcare: true,
    command: "gvm-cli",
    args: ["--version"],
    checks: ["greenbone:openvas"],
    purpose: "Greenbone/OpenVAS report import and authenticated network vulnerability evidence support."
  },
  {
    id: "openscap",
    name: "OpenSCAP",
    category: "attestation",
    requiredForHealthcare: true,
    command: "oscap",
    args: ["--version"],
    checks: ["openscap:system"],
    purpose: "OpenSCAP XCCDF result import and optional local compliance evaluation for approved SCAP content."
  }
];

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
    description: "OpenAPI JSON-first checks, ErrorResponse compliance, health/readiness endpoints, and safe runtime API probes.",
    checks: ["openapi", "openapi:lint", "api:error-response", "api:health", "api:ready", "openapi:runtime-safe"],
    failThreshold: "high",
    allowActiveDast: true,
    allowProductionTargets: false,
    timeoutSeconds: 900
  },
  {
    id: "web-perimeter-safe",
    name: "web-perimeter-safe",
    description:
      "Safe DNS, TLS, common-port, HTTP header, exposed endpoint, WAF fingerprint, and Nuclei safe-template checks for an explicitly allowlisted web target.",
    checks: [
      "dns:records",
      "tls:certificate",
      "tls:configuration",
      "ports:common",
      "http:security-headers",
      "endpoint:admin",
      "endpoint:debug",
      "api:discovery",
      "waf:behavior",
      "nuclei:safe"
    ],
    failThreshold: "high",
    allowActiveDast: true,
    allowProductionTargets: false,
    timeoutSeconds: 1200
  },
  {
    id: "controlled-dast-local",
    name: "controlled-dast-local",
    description:
      "Controlled OWASP ZAP baseline profile for localhost or explicitly allowlisted staging targets owned by the user.",
    checks: ["api:health", "api:ready", "http:security-headers", "api:discovery", "zap:baseline"],
    failThreshold: "high",
    allowActiveDast: true,
    allowProductionTargets: false,
    timeoutSeconds: 1200
  },
  {
    id: "openapi-runtime-safe",
    name: "openapi-runtime-safe",
    description:
      "OpenAPI contract validation plus bounded safe GET/HEAD runtime probes against an explicitly allowlisted API target.",
    checks: ["openapi", "openapi:lint", "api:error-response", "api:health", "api:ready", "openapi:runtime-safe", "zap:api-scan"],
    failThreshold: "high",
    allowActiveDast: true,
    allowProductionTargets: false,
    timeoutSeconds: 1200
  },
  {
    id: "external-vps-safe",
    name: "external-vps-safe",
    description:
      "External scanner readiness profile for a hardened VPS runner using safe web probes, OWASP ZAP baseline, Nuclei safe templates, and signed result return.",
    checks: [
      "external-runner:vps",
      "dns:records",
      "tls:certificate",
      "tls:configuration",
      "http:security-headers",
      "api:discovery",
      "waf:behavior",
      "nuclei:safe",
      "zap:baseline"
    ],
    failThreshold: "high",
    allowActiveDast: true,
    allowProductionTargets: false,
    timeoutSeconds: 1800
  },
  {
    id: "enterprise-assurance",
    name: "enterprise-assurance",
    description:
      "Enterprise assurance profile for healthcare evidence pipelines that combine local checks with Greenbone/OpenVAS import, OpenSCAP import/evaluation, and DefectDojo SARIF export.",
    checks: [
      "greenbone:openvas",
      "openscap:system",
      "defectdojo:export",
      "telemetry-export",
      "syft:sbom",
      "grype:sbom",
      "iac:checkov",
      "openapi"
    ],
    failThreshold: "medium",
    allowActiveDast: true,
    allowProductionTargets: false,
    timeoutSeconds: 2400
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
    id: "stratos-policy-conformance",
    name: "stratos-policy-conformance",
    description: "STRATOS Access Governance V1, Information Policy V2 and integration envelope conformance checks.",
    checks: ["policy:openapi-binding", "policy:audit-correlation", "policy:log-redaction", "policy:export-inheritance", "policy:fail-closed", "policy:provider-compatibility"],
    failThreshold: "high",
    allowActiveDast: false,
    allowProductionTargets: false,
    timeoutSeconds: 300
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
  },
  {
    id: "healthcare-reference",
    name: "healthcare-reference",
    description:
      "Reference profile for healthcare and other highly sensitive systems requiring evidence, privacy, SBOM, API, IaC, and central-result export readiness.",
    checks: [
      "gitleaks:history",
      "semgrep",
      "trivy:fs",
      "osv:dependencies",
      "syft:sbom",
      "grype:sbom",
      "openapi",
      "openapi:lint",
      "api:error-response",
      "api:health",
      "api:ready",
      "documentation",
      "threat-model",
      "data-classification",
      "privacy-impact",
      "audit-logging",
      "auth",
      "authorization",
      "encryption",
      "retention",
      "logging-redaction",
      "telemetry-export",
      "iac:checkov",
      "container",
      "license-policy",
      "forbidden-files"
    ],
    failThreshold: "medium",
    allowActiveDast: false,
    allowProductionTargets: false,
    timeoutSeconds: 2400
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

export function findingScope(finding: Pick<Finding, "scope">): FindingScope {
  return finding.scope ?? "application";
}

export function applicationFindings(findings: Finding[]): Finding[] {
  return findings.filter((finding) => findingScope(finding) === "application");
}

export function platformFindings(findings: Finding[]): Finding[] {
  return findings.filter((finding) => findingScope(finding) === "platform");
}

export function evaluateGate(
  findings: Finding[],
  profile: Pick<ScanProfile, "name" | "failThreshold">,
  dataClassification: DataClassification = "internal"
): GateEvaluation {
  const scopedApplicationFindings = applicationFindings(findings);
  const summary = summarizeFindings(scopedApplicationFindings);
  const openFindings = scopedApplicationFindings.filter((finding) => finding.status === "open");
  const openPlatformGaps = platformFindings(findings).filter((finding) => finding.status === "open");
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

    if (profile.name === "healthcare-reference" && severityOrder[finding.severity] >= severityOrder.medium) {
      blockingReasons.push(`${finding.severity.toUpperCase()} healthcare-reference finding: ${finding.title}`);
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
  const hasPlatformReadinessGaps = openPlatformGaps.some((finding) => severityOrder[finding.severity] >= severityOrder.medium);

  return {
    result: hasWarnings || hasPlatformReadinessGaps ? "warning" : "pass",
    blockingReasons: hasPlatformReadinessGaps
      ? [
          ...blockingReasons,
          ...openPlatformGaps
            .filter((finding) => severityOrder[finding.severity] >= severityOrder.medium)
            .map((finding) => `PLATFORM readiness gap: ${finding.title}`)
        ]
      : blockingReasons,
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
  [/(Authorization:\s*Bearer\s+)[^\s"'\\]+/gi, "$1********"],
  [/(api[_-]?key\s*[:=]\s*)[^\s"'\\]+/gi, "$1********"],
  [/(password\s*[:=]\s*)[^\s"'\\]+/gi, "$1********"],
  [/(cookie\s*[:=]\s*)[^\n\r\\]+/gi, "$1********"],
  [/(token\s*[:=]\s*)[^\s"'\\]+/gi, "$1********"]
];

export function redactSecrets(value: string): string {
  return redactionPatterns.reduce((redacted, [pattern, replacement]) => redacted.replace(pattern, replacement), value);
}
