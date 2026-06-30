import { describe, expect, it } from "vitest";
import { emptySeveritySummary, type Finding, type Project, type ScanProfile, type ScanRun } from "@security-preflight/core";
import { generateCentralResultEnvelope, generateJsonReport, generateMarkdownReport, generateSarifReport } from "./index.js";

describe("central result envelope", () => {
  it("generates a redacted stable result envelope", () => {
    const project: Project = {
      id: "project_1",
      name: "Healthcare API",
      path: "/tmp/healthcare-api",
      repositoryUrl: null,
      publicUrl: null,
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
      publicUrl: "https://healthcare-api.example.invalid",
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

  it("generates parseable redacted JSON when findings contain control characters", () => {
    const project: Project = {
      id: "project_1",
      name: "Healthcare API",
      path: "/tmp/healthcare-api",
      repositoryUrl: null,
      publicUrl: null,
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
      status: "failed",
      startedAt: "2026-06-13T10:00:00.000Z",
      finishedAt: "2026-06-13T10:01:00.000Z",
      commitHash: null,
      branch: "main",
      toolVersions: {},
      summary: emptySeveritySummary(),
      gateResult: "fail"
    };
    const profile: ScanProfile = {
      id: "healthcare-reference",
      name: "healthcare-reference",
      description: "Healthcare reference profile",
      checks: ["trivy:fs"],
      failThreshold: "medium",
      allowActiveDast: false,
      allowProductionTargets: false,
      timeoutSeconds: 2400
    };
    const finding: Finding = {
      id: "finding_1",
      scanRunId: scanRun.id,
      tool: "trivy",
      type: "sca",
      severity: "low",
      title: "Cookie encoder finding",
      description: "cookie: session=secret-value\r\nSet-Cookie: admin=1",
      evidence: "Authorization: Bearer secret-value\r\ncookie: session=secret-value",
      filePath: null,
      line: null,
      endpoint: null,
      cwe: "CWE-93",
      cve: "CVE-2026-43969",
      owasp: null,
      recommendation: "Upgrade dependency.",
      status: "open",
      fingerprint: "abc123456789"
    };
    const reportText = generateJsonReport({
      project,
      scanRun,
      profile,
      gate: {
        result: "fail",
        blockingReasons: ["LOW healthcare-reference finding: Cookie encoder finding"],
        summary: { ...emptySeveritySummary(), low: 1 }
      },
      findings: [finding]
    });
    const report = JSON.parse(reportText);

    expect(report.findings[0].description).toContain("cookie: ********");
    expect(reportText).not.toContain("secret-value");
  });

  it("separates platform readiness gaps from application findings", () => {
    const project: Project = {
      id: "project_1",
      name: "Healthcare API",
      path: "/tmp/healthcare-api",
      repositoryUrl: "https://example.invalid/healthcare-api.git",
      publicUrl: "https://healthcare-api.example.invalid",
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
      checks: ["greenbone:openvas"],
      failThreshold: "medium",
      allowActiveDast: false,
      allowProductionTargets: false,
      timeoutSeconds: 2400
    };
    const platformGap: Finding = {
      id: "finding_platform",
      scanRunId: scanRun.id,
      tool: "greenbone",
      type: "tooling",
      scope: "platform",
      severity: "high",
      title: "Greenbone/OpenVAS integration is not configured",
      description: "Greenbone/OpenVAS requires a configured manager endpoint.",
      evidence: "{}",
      filePath: null,
      line: null,
      endpoint: null,
      cwe: null,
      cve: null,
      owasp: null,
      recommendation: "Configure Greenbone/OpenVAS before relying on enterprise assurance evidence.",
      status: "open",
      fingerprint: "platform123"
    };
    const input = {
      project,
      scanRun,
      profile,
      gate: {
        result: "warning" as const,
        blockingReasons: ["PLATFORM readiness gap: Greenbone/OpenVAS integration is not configured"],
        summary: emptySeveritySummary()
      },
      findings: [platformGap]
    };
    const markdown = generateMarkdownReport(input);
    const sarif = JSON.parse(generateSarifReport(input));

    expect(markdown).toContain("## Platform Readiness Gaps");
    expect(markdown).toContain("Scope: platform");
    expect(markdown).toContain("No application findings.");
    expect(sarif.runs[0].results).toHaveLength(0);
  });
});
