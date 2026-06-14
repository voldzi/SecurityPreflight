import { describe, expect, it } from "vitest";
import { emptySeveritySummary, type Finding, type Project, type ScanProfile, type ScanRun } from "@security-preflight/core";
import { generateCentralResultEnvelope, generateSarifReport } from "./index.js";

describe("central result envelope", () => {
  it("generates a redacted stable result envelope", () => {
    const project: Project = {
      id: "project_1",
      name: "Healthcare API",
      path: "/tmp/healthcare-api",
      repositoryUrl: null,
      defaultBranch: "main",
      technologyStack: ["Node.js"],
      dataClassification: "health-data",
      owner: "security",
      createdAt: "2026-06-13T09:00:00.000Z",
      updatedAt: "2026-06-13T09:00:00.000Z"
    };
    const scanRun: ScanRun = {
      id: "scan_1",
      projectId: project.id,
      profileId: "healthcare-reference",
      status: "completed",
      startedAt: "2026-06-13T10:00:00.000Z",
      finishedAt: "2026-06-13T10:01:00.000Z",
      commitHash: null,
      branch: "main",
      toolVersions: {},
      summary: emptySeveritySummary(),
      gateResult: "pass"
    };
    const profile: ScanProfile = {
      id: "healthcare-reference",
      name: "healthcare-reference",
      description: "Healthcare reference profile",
      checks: ["documentation"],
      failThreshold: "medium",
      allowActiveDast: false,
      allowProductionTargets: false,
      timeoutSeconds: 2400
    };
    const finding: Finding = {
      id: "finding_1",
      scanRunId: scanRun.id,
      tool: "test",
      type: "configuration",
      severity: "info",
      title: "redaction check",
      description: "token=secret-value",
      evidence: "Authorization: Bearer secret-value",
      filePath: null,
      line: null,
      endpoint: null,
      cwe: null,
      cve: null,
      owasp: null,
      recommendation: "password=secret-value",
      status: "open",
      fingerprint: "abc"
    };
    const envelope = generateCentralResultEnvelope(
      {
        project,
        scanRun,
        profile,
        gate: {
          result: "pass",
          blockingReasons: [],
          summary: emptySeveritySummary()
        },
        findings: [finding]
      },
      "2026-06-13T10:02:00.000Z"
    );

    expect(envelope.schemaVersion).toBe("security-preflight.result.v1");
    expect(envelope.project.dataClassification).toBe("health-data");
    expect(envelope.evidence.redacted).toBe(true);
    expect(envelope.findings[0]?.evidence).not.toContain("secret-value");
  });

  it("generates redacted SARIF for DefectDojo import", () => {
    const project: Project = {
      id: "project_1",
      name: "Healthcare API",
      path: "/tmp/healthcare-api",
      repositoryUrl: "https://example.invalid/healthcare-api.git",
      defaultBranch: "main",
      technologyStack: ["Node.js"],
      dataClassification: "health-data",
      owner: "security",
      createdAt: "2026-06-13T09:00:00.000Z",
      updatedAt: "2026-06-13T09:00:00.000Z"
    };
    const scanRun: ScanRun = {
      id: "scan_1",
      projectId: project.id,
      profileId: "healthcare-reference",
      status: "completed",
      startedAt: "2026-06-13T10:00:00.000Z",
      finishedAt: "2026-06-13T10:01:00.000Z",
      commitHash: null,
      branch: "main",
      toolVersions: {},
      summary: emptySeveritySummary(),
      gateResult: "warning"
    };
    const profile: ScanProfile = {
      id: "healthcare-reference",
      name: "healthcare-reference",
      description: "Healthcare reference profile",
      checks: ["semgrep"],
      failThreshold: "medium",
      allowActiveDast: false,
      allowProductionTargets: false,
      timeoutSeconds: 2400
    };
    const finding: Finding = {
      id: "finding_1",
      scanRunId: scanRun.id,
      tool: "semgrep",
      type: "sast",
      severity: "high",
      title: "Unsafe authorization branch",
      description: "token=secret-value",
      evidence: "Authorization: Bearer secret-value",
      filePath: "src/auth.ts",
      line: 42,
      endpoint: null,
      cwe: "CWE-862",
      cve: null,
      owasp: "A01:2021",
      recommendation: "Fix authorization logic.",
      status: "open",
      fingerprint: "abc123456789"
    };
    const sarif = JSON.parse(
      generateSarifReport({
        project,
        scanRun,
        profile,
        gate: {
          result: "warning",
          blockingReasons: [],
          summary: emptySeveritySummary()
        },
        findings: [finding]
      })
    );

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.name).toBe("SecurityPreflight");
    expect(sarif.runs[0].results[0].level).toBe("error");
    expect(JSON.stringify(sarif)).not.toContain("secret-value");
  });
});
