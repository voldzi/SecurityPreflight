import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { createServer } from "./server.js";

describe("api server", () => {
  it("serves health", async () => {
    const server = createServer({ logger: false });
    const response = await server.inject({ method: "GET", url: "/health" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      status: "ok",
      service: "security-preflight-api"
    });
  });

  it("serves scan profiles", async () => {
    const server = createServer({ logger: false });
    const response = await server.inject({ method: "GET", url: "/api/v1/scan-profiles" });

    expect(response.statusCode).toBe(200);
    expect(response.json().data.length).toBeGreaterThan(0);
    expect(response.json().data.some((profile: { id: string }) => profile.id === "healthcare-reference")).toBe(true);
  });

  it("serves healthcare toolchain requirements", async () => {
    const server = createServer({ logger: false });
    const response = await server.inject({ method: "GET", url: "/api/v1/toolchain/requirements" });

    expect(response.statusCode).toBe(200);
    expect(response.json().meta.healthcareRequired).toBeGreaterThan(0);
    expect(response.json().data.some((tool: { id: string }) => tool.id === "syft")).toBe(true);
    expect(response.json().data.some((tool: { id: string }) => tool.id === "checkov")).toBe(true);
  });

  it("plans a local scan", async () => {
    const server = createServer({ logger: false });
    const response = await server.inject({
      method: "POST",
      url: "/api/v1/scans/plan",
      payload: {
        scanRunId: "scan_test",
        profileId: "fast-local",
        project: {
          id: "project_test",
          name: "Test Project",
          path: process.cwd()
        }
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      scanRunId: "scan_test",
      blocked: false,
      profile: {
        id: "fast-local"
      }
    });
  });

  it("returns a blocked plan for unsafe DAST requests", async () => {
    const server = createServer({ logger: false });
    const response = await server.inject({
      method: "POST",
      url: "/api/v1/scans/plan",
      payload: {
        profileId: "controlled-dast-local",
        project: {
          id: "project_test",
          name: "Test Project",
          path: process.cwd()
        },
        dast: {
          allowActiveScan: true,
          targetUrl: "https://example.com"
        }
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      blocked: true
    });
    expect(response.json().blockedReasons).toContain("Active DAST host 'example.com' is not in the allowed host list.");
  });

  it("queues an unblocked scan plan", async () => {
    const queued: Array<{ name: string; data: unknown }> = [];
    const server = createServer({
      logger: false,
      scanQueue: {
        async add(name, data) {
          queued.push({ name, data });
          return { id: "job_test" };
        }
      }
    });
    const response = await server.inject({
      method: "POST",
      url: "/api/v1/scans/queue",
      payload: {
        scanRunId: "scan_queue_test",
        profileId: "documentation-compliance",
        project: {
          id: "project_test",
          name: "Test Project",
          path: process.cwd()
        }
      }
    });

    expect(response.statusCode).toBe(202);
    expect(response.json()).toMatchObject({
      data: {
        jobId: "job_test",
        scanRunId: "scan_queue_test",
        status: "queued"
      }
    });
    expect(queued).toHaveLength(1);
    expect(queued[0]?.name).toBe("scan.execute");
  });

  it("serves scan run history, detail, and report content from report evidence", async () => {
    const previousReportsPath = process.env.REPORTS_PATH;
    const reportsPath = await mkdtemp(path.join(tmpdir(), "security-preflight-api-test-"));
    const scanRunId = "scan_history_test";
    const evidenceRoot = path.join(reportsPath, scanRunId);

    await mkdir(evidenceRoot, { recursive: true });
    await writeFile(
      path.join(evidenceRoot, "execution-result.json"),
      `${JSON.stringify(
        {
          scanRunId,
          status: "completed",
          startedAt: "2026-01-01T00:00:00.000Z",
          finishedAt: "2026-01-01T00:00:05.000Z",
          evidenceRoot,
          stepResults: [
            {
              stepId: "step_01_documentation",
              checkId: "documentation",
              status: "passed",
              startedAt: "2026-01-01T00:00:00.000Z",
              finishedAt: "2026-01-01T00:00:01.000Z",
              evidencePath: path.join(evidenceRoot, "documentation.json"),
              findings: [],
              message: "Documentation checks passed."
            }
          ],
          findings: [],
          gate: {
            result: "pass",
            blockingReasons: [],
            summary: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              info: 0
            }
          }
        },
        null,
        2
      )}\n`,
      "utf8"
    );
    await writeFile(
      path.join(evidenceRoot, "report.json"),
      `${JSON.stringify(
        {
          project: {
            id: "project_test",
            name: "Test Project",
            dataClassification: "health-data"
          },
          scanRun: {
            id: scanRunId,
            projectId: "project_test",
            profileId: "documentation-compliance",
            status: "completed",
            startedAt: "2026-01-01T00:00:00.000Z",
            finishedAt: "2026-01-01T00:00:05.000Z",
            gateResult: "pass",
            summary: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              info: 0
            }
          },
          profile: {
            id: "documentation-compliance",
            name: "documentation-compliance"
          },
          gate: {
            result: "pass",
            blockingReasons: [],
            summary: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              info: 0
            }
          },
          findings: []
        },
        null,
        2
      )}\n`,
      "utf8"
    );
    await writeFile(path.join(evidenceRoot, "report.md"), "# Security Preflight Report\n\nNo findings.\n", "utf8");
    await writeFile(path.join(evidenceRoot, "central-result-envelope.json"), "{}\n", "utf8");
    process.env.REPORTS_PATH = reportsPath;

    try {
      const server = createServer({ logger: false });
      const listResponse = await server.inject({ method: "GET", url: "/api/v1/scans/runs" });
      const detailResponse = await server.inject({ method: "GET", url: `/api/v1/scans/runs/${scanRunId}` });
      const reportResponse = await server.inject({ method: "GET", url: `/api/v1/scans/runs/${scanRunId}/report?format=markdown` });

      expect(listResponse.statusCode).toBe(200);
      expect(listResponse.json()).toMatchObject({
        meta: {
          total: 1
        },
        data: [
          {
            id: scanRunId,
            status: "completed",
            gateResult: "pass",
            findingCount: 0,
            durationMs: 5000,
            project: {
              name: "Test Project",
              dataClassification: "health-data"
            },
            evidence: {
              hasExecutionResult: true,
              hasJsonReport: true,
              hasMarkdownReport: true,
              hasCentralEnvelope: true
            }
          }
        ]
      });
      expect(detailResponse.statusCode).toBe(200);
      expect(detailResponse.json().data.steps).toHaveLength(1);
      expect(detailResponse.json().data.gate.result).toBe("pass");
      expect(reportResponse.statusCode).toBe(200);
      expect(reportResponse.json().data.content).toContain("Security Preflight Report");
    } finally {
      if (previousReportsPath === undefined) {
        delete process.env.REPORTS_PATH;
      } else {
        process.env.REPORTS_PATH = previousReportsPath;
      }

      await rm(reportsPath, { recursive: true, force: true });
    }
  });

  it("does not queue a blocked scan plan", async () => {
    const server = createServer({
      logger: false,
      scanQueue: {
        async add() {
          throw new Error("queue should not be called");
        }
      }
    });
    const response = await server.inject({
      method: "POST",
      url: "/api/v1/scans/queue",
      payload: {
        profileId: "controlled-dast-local",
        project: {
          id: "project_test",
          name: "Test Project",
          path: process.cwd()
        },
        dast: {
          allowActiveScan: true,
          targetUrl: "https://example.com"
        }
      }
    });

    expect(response.statusCode).toBe(409);
    expect(response.json().error.code).toBe("SCAN_PLAN_BLOCKED");
  });

  it("accepts a redacted central result envelope", async () => {
    const server = createServer({ logger: false });
    const response = await server.inject({
      method: "POST",
      url: "/api/v1/results/ingest",
      payload: {
        schemaVersion: "security-preflight.result.v1",
        generatedAt: new Date().toISOString(),
        producer: {
          name: "SecurityPreflight",
          version: "0.1.0"
        },
        project: {
          id: "project_test",
          name: "Test Project",
          dataClassification: "health-data"
        },
        scanRun: {
          id: "scan_test",
          status: "completed",
          gateResult: "pass"
        },
        profile: {
          id: "healthcare-reference",
          name: "healthcare-reference",
          checks: ["documentation"]
        },
        gate: {
          result: "pass",
          blockingReasons: []
        },
        findings: [],
        evidence: {
          findingCount: 0,
          redacted: true
        }
      }
    });

    expect(response.statusCode).toBe(202);
    expect(response.json()).toMatchObject({
      data: {
        status: "accepted",
        scanRunId: "scan_test"
      }
    });
  });
});
