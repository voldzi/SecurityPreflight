import { access, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultScanProfiles } from "@security-preflight/core";
import { buildScanExecutionPlan } from "@security-preflight/scanners";
import { executeScanJob } from "./scan-job.js";

const documentationProfile = defaultScanProfiles.find((profile) => profile.id === "documentation-compliance");

if (!documentationProfile) {
  throw new Error("Missing documentation-compliance profile");
}

describe("scan job execution", () => {
  it("executes an internal documentation scan and writes reports", async () => {
    const reportsRoot = await mkdtemp(path.join(tmpdir(), "security-preflight-worker-"));

    try {
      const plan = buildScanExecutionPlan({
        scanRunId: "scan_worker_docs",
        reportsRoot,
        profile: documentationProfile,
        project: {
          id: "project_security_preflight",
          name: "SecurityPreflight",
          path: path.resolve("../..")
        }
      });

      const result = await executeScanJob({ plan, requestId: "req_test" });

      expect(result.status).toBe("completed");
      expect(result.gateResult).toBe("pass");
      expect(result.findingCount).toBe(0);
      await expect(access(result.reportPaths.executionResult)).resolves.toBeUndefined();
      await expect(access(result.reportPaths.json)).resolves.toBeUndefined();
      await expect(access(result.reportPaths.markdown)).resolves.toBeUndefined();
    } finally {
      await rm(reportsRoot, { recursive: true, force: true });
    }
  });
});
