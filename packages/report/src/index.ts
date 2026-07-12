import { createHash } from "node:crypto";
import {
  applicationFindings,
  findingScope,
  informationPolicyBindingForClassification,
  informationPolicyBindingHash,
  INTEGRATION_ENVELOPE_VERSION,
  STRATOS_ORGANIZATION_ID,
  platformFindings,
  redactSecrets,
  summarizeFindings,
  type Finding,
  type GateEvaluation,
  type Project,
  type ScanProfile,
  type ScanRun,
  type InformationPolicyBinding
} from "@security-preflight/core";

export interface ReportInput {
  project: Project;
  scanRun: ScanRun;
  profile: ScanProfile;
  gate: GateEvaluation;
  findings: Finding[];
}

export interface StratosIntegrationEnvelope<T> {
  schemaVersion: typeof INTEGRATION_ENVELOPE_VERSION;
  organizationId: typeof STRATOS_ORGANIZATION_ID;
  sourceSystem: "SECURITY_PREFLIGHT";
  externalRef: string;
  actor: { type: "service"; subjectId: "service:security-preflight" };
  correlationId: string;
  idempotencyKey: string;
  policyBindingId: string;
  policyVersion: string;
  policyHash: string;
  classification: Pick<InformationPolicyBinding, "handlingClass" | "legalClassification" | "tlp" | "pap">;
  payload: T;
}

export interface CentralResultEnvelope {
  schemaVersion: "security-preflight.result.v1";
  envelopeId: string;
  generatedAt: string;
  producer: {
    name: "SecurityPreflight";
    version: string;
  };
  project: Pick<Project, "id" | "name" | "repositoryUrl" | "defaultBranch" | "technologyStack" | "dataClassification" | "owner">;
  scanRun: ScanRun;
  profile: Pick<ScanProfile, "id" | "name" | "checks" | "failThreshold" | "allowActiveDast" | "allowProductionTargets">;
  gate: GateEvaluation;
  findings: Finding[];
  evidence: {
    findingCount: number;
    applicationFindingCount: number;
    platformReadinessGapCount: number;
    redacted: true;
    source: "local-report";
  };
  policyBinding: InformationPolicyBinding;
  integrationEnvelope: StratosIntegrationEnvelope<{ envelopeId: string; scanRunId: string; projectId: string }>;
}

export function generateJsonReport(input: ReportInput): string {
  return JSON.stringify({ ...input, policyBinding: reportPolicyBinding(input) }, redactingJsonReplacer, 2);
}

export function generateSarifReport(input: ReportInput): string {
  const sarifFindings = applicationFindings(input.findings);
  const ruleMap = new Map<string, { id: string; name: string; shortDescription: { text: string }; help: { text: string }; properties: Record<string, unknown> }>();

  for (const finding of sarifFindings) {
    const ruleId = finding.cve ?? finding.cwe ?? finding.fingerprint.slice(0, 16);
    const id = `${finding.tool}:${ruleId}`;

    if (!ruleMap.has(id)) {
      ruleMap.set(id, {
        id,
        name: finding.title,
        shortDescription: { text: finding.title },
        help: { text: redactSecrets(finding.recommendation) },
        properties: {
          securitySeverity: sarifSecuritySeverity(finding.severity),
          tags: [finding.type, finding.severity, finding.tool, findingScope(finding)].filter(Boolean)
        }
      });
    }
  }

  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "SecurityPreflight",
            informationUri: input.project.repositoryUrl ?? "https://github.com/voldzi/SecurityPreflight",
            version: process.env.npm_package_version ?? "0.1.0",
            rules: [...ruleMap.values()]
          }
        },
        automationDetails: {
          id: input.scanRun.id,
          description: {
            text: `${input.project.name} / ${input.profile.name}`
          }
        },
        properties: {
          policyBinding: reportPolicyBinding(input)
        },
        results: sarifFindings.map((finding) => {
          const ruleId = `${finding.tool}:${finding.cve ?? finding.cwe ?? finding.fingerprint.slice(0, 16)}`;
          const location = finding.filePath
            ? {
                physicalLocation: {
                  artifactLocation: {
                    uri: finding.filePath.replaceAll("\\", "/")
                  },
                  region: finding.line ? { startLine: finding.line } : undefined
                }
              }
            : finding.endpoint
              ? {
                  logicalLocations: [
                    {
                      name: finding.endpoint,
                      kind: "endpoint"
                    }
                  ]
              }
              : undefined;

          return {
            ruleId,
            level: sarifLevel(finding.severity),
            message: {
              text: redactSecrets(finding.description)
            },
            locations: location ? [location] : [],
            partialFingerprints: {
              securityPreflightFingerprint: finding.fingerprint
            },
            properties: {
              severity: finding.severity,
              tool: finding.tool,
              type: finding.type,
              scope: findingScope(finding),
              status: finding.status,
              endpoint: finding.endpoint,
              cwe: finding.cwe,
              cve: finding.cve,
              owasp: finding.owasp,
              recommendation: redactSecrets(finding.recommendation),
              evidence: truncateReportEvidence(redactSecrets(finding.evidence))
            }
          };
        })
      }
    ]
  };

  return JSON.stringify(sarif, null, 2);
}

export function generateCentralResultEnvelope(input: ReportInput, generatedAt = new Date().toISOString()): CentralResultEnvelope {
  const redactedFindings = input.findings.map((finding) => ({
    ...finding,
    evidence: redactSecrets(finding.evidence),
    description: redactSecrets(finding.description),
    recommendation: redactSecrets(finding.recommendation)
  }));
  const material = JSON.stringify({
    projectId: input.project.id,
    scanRunId: input.scanRun.id,
    profileId: input.profile.id,
    gate: input.gate.result,
    findings: redactedFindings.map((finding) => finding.fingerprint)
  });
  const envelopeId = `spr_${createHash("sha256").update(material).digest("hex").slice(0, 24)}`;
  const policyBinding = reportPolicyBinding(input);
  const policyHash = informationPolicyBindingHash(policyBinding);

  return {
    schemaVersion: "security-preflight.result.v1",
    envelopeId,
    generatedAt,
    producer: {
      name: "SecurityPreflight",
      version: process.env.npm_package_version ?? "0.1.0"
    },
    project: {
      id: input.project.id,
      name: input.project.name,
      repositoryUrl: input.project.repositoryUrl,
      defaultBranch: input.project.defaultBranch,
      technologyStack: input.project.technologyStack,
      dataClassification: input.project.dataClassification,
      owner: input.project.owner
    },
    scanRun: input.scanRun,
    profile: {
      id: input.profile.id,
      name: input.profile.name,
      checks: input.profile.checks,
      failThreshold: input.profile.failThreshold,
      allowActiveDast: input.profile.allowActiveDast,
      allowProductionTargets: input.profile.allowProductionTargets
    },
    gate: input.gate,
    findings: redactedFindings,
    evidence: {
      findingCount: redactedFindings.length,
      applicationFindingCount: applicationFindings(redactedFindings).length,
      platformReadinessGapCount: platformFindings(redactedFindings).length,
      redacted: true,
      source: "local-report"
    },
    policyBinding,
    integrationEnvelope: {
      schemaVersion: INTEGRATION_ENVELOPE_VERSION,
      organizationId: STRATOS_ORGANIZATION_ID,
      sourceSystem: "SECURITY_PREFLIGHT",
      externalRef: `scan:${input.scanRun.id}`,
      actor: { type: "service", subjectId: "service:security-preflight" },
      correlationId: input.scanRun.id,
      idempotencyKey: `security-preflight:${input.scanRun.id}:${envelopeId}`,
      policyBindingId: policyBinding.policyBindingId as string,
      policyVersion: policyBinding.policyVersion,
      policyHash,
      classification: { handlingClass: policyBinding.handlingClass, legalClassification: policyBinding.legalClassification, tlp: policyBinding.tlp, pap: policyBinding.pap },
      payload: { envelopeId, scanRunId: input.scanRun.id, projectId: input.project.id }
    }
  };
}

function reportPolicyBinding(input: ReportInput): InformationPolicyBinding {
  return { ...informationPolicyBindingForClassification(input.project.dataClassification), policyBindingId: `pb_security_preflight_${input.project.id}` };
}


export function generateMarkdownReport(input: ReportInput): string {
  const appFindings = applicationFindings(input.findings);
  const platformGaps = platformFindings(input.findings);
  const appSummary = summarizeFindings(appFindings);
  const platformSummary = summarizeFindings(platformGaps);
  const topFindings = appFindings
    .slice(0, 10)
    .map((finding, index) =>
      [
        `### ${index + 1}. ${finding.title}`,
        "",
        `Severity: ${finding.severity.toUpperCase()}`,
        `Scope: application`,
        `Tool: ${finding.tool}`,
        finding.filePath ? `File: \`${finding.filePath}${finding.line ? `:${finding.line}` : ""}\`` : null,
        finding.endpoint ? `Endpoint: \`${finding.endpoint}\`` : null,
        `Recommendation: ${finding.recommendation}`
      ]
        .filter(Boolean)
        .join("\n")
    )
    .join("\n\n");
  const platformReadiness = platformGaps
    .slice(0, 10)
    .map((finding, index) =>
      [
        `### ${index + 1}. ${finding.title}`,
        "",
        `Severity: ${finding.severity.toUpperCase()}`,
        `Scope: platform`,
        `Tool: ${finding.tool}`,
        finding.endpoint ? `Endpoint: \`${finding.endpoint}\`` : null,
        `Recommendation: ${finding.recommendation}`
      ]
        .filter(Boolean)
        .join("\n")
    )
    .join("\n\n");

  const markdown = `# Security Preflight Report

## Project

| Field | Value |
|---|---|
| Project | ${input.project.name} |
| Path | \`${input.project.path}\` |
| Branch | \`${input.scanRun.branch ?? "unknown"}\` |
| Commit | \`${input.scanRun.commitHash ?? "unknown"}\` |
| Data classification | \`${input.project.dataClassification}\` |

## Scan

| Field | Value |
|---|---|
| Profile | \`${input.profile.name}\` |
| Started | \`${input.scanRun.startedAt}\` |
| Finished | \`${input.scanRun.finishedAt ?? "running"}\` |
| Result | \`${input.gate.result.toUpperCase()}\` |

## Summary

Application findings are issues attributed to the checked project or target. Platform readiness gaps are SecurityPreflight scanner/runtime configuration gaps and do not mean that the checked application contains that vulnerability.

### Application Findings

| Severity | Count |
|---|---:|
| Critical | ${appSummary.critical} |
| High | ${appSummary.high} |
| Medium | ${appSummary.medium} |
| Low | ${appSummary.low} |
| Info | ${appSummary.info} |

### Platform Readiness Gaps

| Severity | Count |
|---|---:|
| Critical | ${platformSummary.critical} |
| High | ${platformSummary.high} |
| Medium | ${platformSummary.medium} |
| Low | ${platformSummary.low} |
| Info | ${platformSummary.info} |

## Release Gate

**Result:** ${input.gate.result.toUpperCase()}

### Blocking reasons

${input.gate.blockingReasons.length > 0 ? input.gate.blockingReasons.map((reason) => `- ${reason}`).join("\n") : "- None"}

## Platform Readiness Gaps

${platformReadiness || "No platform readiness gaps."}

## Top Application Findings

${topFindings || "No application findings."}
`;

  return redactSecrets(markdown);
}

function sarifLevel(severity: Finding["severity"]): "error" | "warning" | "note" | "none" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
    case "low":
      return "warning";
    case "info":
      return "note";
  }
}

function sarifSecuritySeverity(severity: Finding["severity"]): string {
  switch (severity) {
    case "critical":
      return "9.5";
    case "high":
      return "8.0";
    case "medium":
      return "5.0";
    case "low":
      return "2.5";
    case "info":
      return "0.0";
  }
}

function truncateReportEvidence(value: string, maxLength = 2_000): string {
  return value.length <= maxLength ? value : `${value.slice(0, maxLength)}\n...[truncated]`;
}

function redactingJsonReplacer(_key: string, value: unknown): unknown {
  return typeof value === "string" ? redactSecrets(value) : value;
}
