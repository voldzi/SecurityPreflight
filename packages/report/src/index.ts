import { redactSecrets, type Finding, type GateEvaluation, type Project, type ScanProfile, type ScanRun } from "@security-preflight/core";

export interface ReportInput {
  project: Project;
  scanRun: ScanRun;
  profile: ScanProfile;
  gate: GateEvaluation;
  findings: Finding[];
}

export function generateJsonReport(input: ReportInput): string {
  return redactSecrets(JSON.stringify(input, null, 2));
}

export function generateMarkdownReport(input: ReportInput): string {
  const topFindings = input.findings
    .slice(0, 10)
    .map((finding, index) =>
      [
        `### ${index + 1}. ${finding.title}`,
        "",
        `Severity: ${finding.severity.toUpperCase()}`,
        `Tool: ${finding.tool}`,
        finding.filePath ? `File: \`${finding.filePath}${finding.line ? `:${finding.line}` : ""}\`` : null,
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

| Severity | Count |
|---|---:|
| Critical | ${input.gate.summary.critical} |
| High | ${input.gate.summary.high} |
| Medium | ${input.gate.summary.medium} |
| Low | ${input.gate.summary.low} |
| Info | ${input.gate.summary.info} |

## Release Gate

**Result:** ${input.gate.result.toUpperCase()}

### Blocking reasons

${input.gate.blockingReasons.length > 0 ? input.gate.blockingReasons.map((reason) => `- ${reason}`).join("\n") : "- None"}

## Top Findings

${topFindings || "No findings."}
`;

  return redactSecrets(markdown);
}
