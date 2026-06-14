import { describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { defaultScanProfiles } from "@security-preflight/core";
import { buildScanExecutionPlan, evaluateDastGuardrails, executeScanPlan, writeExecutionResultEvidence } from "./index.js";

const profile = (id: string) => {
  const match = defaultScanProfiles.find((candidate) => candidate.id === id);

  if (!match) {
    throw new Error(`Missing test profile ${id}`);
  }

  return match;
};

describe("scan execution planner", () => {
  it("plans a fast local profile with read-only mounts and disabled network", () => {
    const plan = buildScanExecutionPlan({
      scanRunId: "scan_test",
      project: {
        id: "project_1",
        name: "Example",
        path: process.cwd(),
        dataClassification: "internal"
      },
      profile: profile("fast-local"),
      reportsRoot: "/reports"
    });

    expect(plan.blocked).toBe(false);
    expect(plan.steps.length).toBeGreaterThan(0);
    expect(plan.steps.every((step) => step.projectMount.readOnly)).toBe(true);
    expect(plan.steps.every((step) => step.guardrails.privileged === false)).toBe(true);
    expect(plan.steps.every((step) => step.guardrails.dockerSocket === false)).toBe(true);
    expect(plan.steps.every((step) => step.networkMode === "disabled")).toBe(true);
  });

  it("blocks controlled DAST until active scanning and a target are explicit", () => {
    const plan = buildScanExecutionPlan({
      scanRunId: "scan_dast_missing_target",
      project: {
        id: "project_1",
        name: "Example",
        path: process.cwd()
      },
      profile: profile("controlled-dast-local")
    });

    const zapStep = plan.steps.find((step) => step.checkId === "zap:baseline");

    expect(plan.blocked).toBe(true);
    expect(zapStep?.status).toBe("blocked");
    expect(plan.blockedReasons).toContain("Active DAST requires an explicit targetUrl.");
  });

  it("allows an explicit localhost ZAP baseline target", () => {
    const plan = buildScanExecutionPlan({
      scanRunId: "scan_dast_localhost",
      project: {
        id: "project_1",
        name: "Example",
        path: process.cwd()
      },
      profile: profile("controlled-dast-local"),
      dast: {
        allowActiveScan: true,
        targetUrl: "http://localhost:3000"
      }
    });

    const zapStep = plan.steps.find((step) => step.checkId === "zap:baseline");

    expect(plan.blocked).toBe(false);
    expect(zapStep?.networkMode).toBe("restricted");
    expect(zapStep?.command).toContain("http://localhost:3000/");
  });

  it("requires explicit target guardrails for safe web perimeter checks", () => {
    const missingTargetPlan = buildScanExecutionPlan({
      scanRunId: "scan_perimeter_missing_target",
      project: {
        id: "project_1",
        name: "Example",
        path: process.cwd()
      },
      profile: profile("web-perimeter-safe")
    });

    expect(missingTargetPlan.blocked).toBe(true);
    expect(missingTargetPlan.blockedReasons).toContain("Active DAST requires an explicit targetUrl.");

    const allowedPlan = buildScanExecutionPlan({
      scanRunId: "scan_perimeter_allowed",
      project: {
        id: "project_1",
        name: "Example",
        path: process.cwd()
      },
      profile: profile("web-perimeter-safe"),
      dast: {
        allowActiveScan: true,
        targetUrl: "https://staging.example.test",
        allowedHosts: ["staging.example.test"]
      }
    });

    expect(allowedPlan.blocked).toBe(false);
    expect(allowedPlan.steps.map((step) => step.checkId)).toEqual(
      expect.arrayContaining([
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
      ])
    );
    expect(allowedPlan.steps.every((step) => step.networkMode === "restricted")).toBe(true);
  });

  it("rejects active DAST targets outside the allowlist", () => {
    const guardrails = evaluateDastGuardrails({
      profile: profile("controlled-dast-local"),
      allowActiveScan: true,
      targetUrl: "https://example.com"
    });

    expect(guardrails.allowed).toBe(false);
    expect(guardrails.reasons).toContain("Active DAST host 'example.com' is not in the allowed host list.");
  });

  it("executes internal documentation checks and writes evidence", async () => {
    const reportsRoot = await mkdtemp(path.join(tmpdir(), "security-preflight-reports-"));

    try {
      const plan = buildScanExecutionPlan({
        scanRunId: "scan_docs",
        project: {
          id: "project_1",
          name: "SecurityPreflight",
          path: path.resolve("../..")
        },
        profile: profile("documentation-compliance"),
        reportsRoot
      });
      const result = await executeScanPlan(plan);
      const resultPath = await writeExecutionResultEvidence(result);
      const resultJson = JSON.parse(await readFile(resultPath, "utf8")) as { gate: { result: string } };

      expect(result.status).toBe("completed");
      expect(result.findings).toHaveLength(0);
      expect(result.gate.result).toBe("pass");
      expect(resultJson.gate.result).toBe("pass");
    } finally {
      await rm(reportsRoot, { recursive: true, force: true });
    }
  });

  it("executes external commands directly and normalizes scanner evidence", async () => {
    const reportsRoot = await mkdtemp(path.join(tmpdir(), "security-preflight-reports-"));
    const projectRoot = await mkdtemp(path.join(tmpdir(), "security-preflight-project-"));

    try {
      const plan = buildScanExecutionPlan({
        scanRunId: "scan_external_semgrep",
        project: {
          id: "project_1",
          name: "External",
          path: projectRoot
        },
        profile: {
          id: "external-test",
          name: "external-test",
          description: "External runner test profile.",
          checks: ["semgrep"],
          failThreshold: "medium",
          allowActiveDast: false,
          allowProductionTargets: false,
          timeoutSeconds: 60
        },
        reportsRoot
      });
      const rawEvidencePath = plan.steps[0]?.evidencePaths[0];

      if (!rawEvidencePath) {
        throw new Error("Missing test evidence path");
      }

      const command = [
        process.execPath,
        "-e",
        "require('node:fs').writeFileSync(process.argv[1], JSON.stringify({results:[{check_id:'test.rule',path:'src/app.ts',start:{line:7},extra:{severity:'ERROR',message:'Unsafe test pattern'}}]}))",
        rawEvidencePath
      ];
      const externalPlan = {
        ...plan,
        steps: plan.steps.map((step) => ({ ...step, command }))
      };
      const result = await executeScanPlan(externalPlan, { runExternalCommands: true, externalRunner: "direct" });
      const rawEvidence = JSON.parse(await readFile(rawEvidencePath, "utf8")) as { results: unknown[] };
      const executionEvidencePath = result.stepResults[0]?.evidencePath;

      expect(result.status).toBe("completed");
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.tool).toBe("semgrep");
      expect(result.findings[0]?.severity).toBe("high");
      expect(result.findings[0]?.filePath).toBe("src/app.ts");
      expect(rawEvidence.results).toHaveLength(1);
      expect(executionEvidencePath).toContain("semgrep.execution.json");
      await expect(readFile(executionEvidencePath ?? "", "utf8")).resolves.toContain("Unsafe test pattern");
    } finally {
      await rm(reportsRoot, { recursive: true, force: true });
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it("normalizes Nuclei JSONL evidence from safe-template scans", async () => {
    const reportsRoot = await mkdtemp(path.join(tmpdir(), "security-preflight-reports-"));
    const projectRoot = await mkdtemp(path.join(tmpdir(), "security-preflight-project-"));

    try {
      const plan = buildScanExecutionPlan({
        scanRunId: "scan_external_nuclei",
        project: {
          id: "project_1",
          name: "External",
          path: projectRoot
        },
        profile: {
          id: "nuclei-test",
          name: "nuclei-test",
          description: "Nuclei runner test profile.",
          checks: ["nuclei:safe"],
          failThreshold: "medium",
          allowActiveDast: true,
          allowProductionTargets: false,
          timeoutSeconds: 60
        },
        dast: {
          allowActiveScan: true,
          targetUrl: "http://localhost:3000",
          allowedHosts: ["localhost"]
        },
        reportsRoot
      });
      const rawEvidencePath = plan.steps[0]?.evidencePaths[0];

      if (!rawEvidencePath) {
        throw new Error("Missing test evidence path");
      }

      const command = [
        process.execPath,
        "-e",
        "require('node:fs').writeFileSync(process.argv[1], JSON.stringify({'template-id':'exposed-panel','matched-at':'http://localhost:3000/admin',info:{name:'Exposed admin panel',severity:'high',description:'Admin panel was reachable',tags:['exposure']}})+'\\n')",
        rawEvidencePath
      ];
      const externalPlan = {
        ...plan,
        steps: plan.steps.map((step) => ({ ...step, command }))
      };
      const result = await executeScanPlan(externalPlan, { runExternalCommands: true, externalRunner: "direct" });

      expect(result.status).toBe("completed");
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.tool).toBe("nuclei");
      expect(result.findings[0]?.severity).toBe("high");
      expect(result.findings[0]?.endpoint).toBe("http://localhost:3000/admin");
    } finally {
      await rm(reportsRoot, { recursive: true, force: true });
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it("does not execute unblocked steps when guardrails block the plan", async () => {
    const reportsRoot = await mkdtemp(path.join(tmpdir(), "security-preflight-reports-"));

    try {
      const plan = buildScanExecutionPlan({
        scanRunId: "scan_blocked",
        project: {
          id: "project_1",
          name: "SecurityPreflight",
          path: path.resolve("../..")
        },
        profile: profile("controlled-dast-local"),
        dast: {
          allowActiveScan: true,
          targetUrl: "https://example.com"
        },
        reportsRoot
      });
      const result = await executeScanPlan(plan);

      expect(result.status).toBe("failed");
      expect(result.stepResults.find((step) => step.checkId === "zap:baseline")?.status).toBe("blocked");
      expect(result.stepResults.find((step) => step.checkId === "http:security-headers")?.status).toBe("blocked");
      expect(result.stepResults.find((step) => step.checkId === "api:discovery")?.status).toBe("blocked");
      expect(result.stepResults.find((step) => step.checkId === "api:health")?.status).toBe("skipped");
      expect(result.findings).toHaveLength(3);
    } finally {
      await rm(reportsRoot, { recursive: true, force: true });
    }
  });
});
