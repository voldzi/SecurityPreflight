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
      expect(result.stepResults.find((step) => step.checkId === "api:health")?.status).toBe("skipped");
      expect(result.findings).toHaveLength(1);
    } finally {
      await rm(reportsRoot, { recursive: true, force: true });
    }
  });
});
