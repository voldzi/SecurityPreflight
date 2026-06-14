import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createServer } from "./server.js";

describe("api server", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

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

  it("exports scan run reports as STRATOS-style PDF and PPTX payloads", async () => {
    await withReportFixture("scan_export_test", async () => {
      const server = createServer({ logger: false });

      for (const format of ["PDF", "PPTX"] as const) {
        const response = await server.inject({
          method: "POST",
          url: "/api/v1/reports/export",
          payload: {
            scanRunId: "scan_export_test",
            format
          }
        });
        const data = response.json().data;
        const content = Buffer.from(data.content, "base64");

        expect(response.statusCode).toBe(200);
        expect(data.reportType).toBe("SECURITY_PREFLIGHT_SCAN");
        expect(data.format).toBe(format);
        expect(data.contentHash).toHaveLength(64);
        expect(content.length).toBeGreaterThan(500);
        expect(content.subarray(0, format === "PDF" ? 4 : 2).toString()).toBe(format === "PDF" ? "%PDF" : "PK");
      }
    });
  });

  it("reports AKB integration status without exposing secrets", async () => {
    const previousRagBaseUrl = process.env.SECURITY_PREFLIGHT_AKB_RAG_BASE_URL;
    const previousServiceToken = process.env.SECURITY_PREFLIGHT_AKB_SERVICE_TOKEN;

    delete process.env.SECURITY_PREFLIGHT_AKB_RAG_BASE_URL;
    process.env.SECURITY_PREFLIGHT_AKB_SERVICE_TOKEN = "secret-token";

    try {
      const server = createServer({ logger: false });
      const response = await server.inject({ method: "GET", url: "/api/v1/akb/status" });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({
        data: {
          configured: false,
          ragConfigured: false,
          authMode: "service-token",
          boundaries: {
            storesPrompts: false,
            storesResponses: false,
            storesChunks: false,
            requiresCitations: true
          }
        }
      });
      expect(JSON.stringify(response.json())).not.toContain("secret-token");
    } finally {
      restoreEnv("SECURITY_PREFLIGHT_AKB_RAG_BASE_URL", previousRagBaseUrl);
      restoreEnv("SECURITY_PREFLIGHT_AKB_SERVICE_TOKEN", previousServiceToken);
    }
  });

  it("bridges scan run questions through AKB RAG without storing the answer", async () => {
    const previousRagBaseUrl = process.env.SECURITY_PREFLIGHT_AKB_RAG_BASE_URL;
    const previousServiceToken = process.env.SECURITY_PREFLIGHT_AKB_SERVICE_TOKEN;
    let outboundPayload: Record<string, unknown> | null = null;

    process.env.SECURITY_PREFLIGHT_AKB_RAG_BASE_URL = "https://akb.example.test/api/v1";
    process.env.SECURITY_PREFLIGHT_AKB_SERVICE_TOKEN = "test-service-token";
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const headers = init?.headers as Record<string, string>;
      outboundPayload = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
      expect(String(input)).toBe("https://akb.example.test/api/v1/rag/query");
      expect(headers.authorization).toBe("Bearer test-service-token");
      expect(headers.accept).toBe("application/json");
      expect(headers["X-AKL-Subject"]).toBe("security-preflight-user");
      expect(headers["X-AKL-Roles"]).toBe("security-preflight.viewer");

      return new Response(
        JSON.stringify({
          answer: "Citovana odpoved z AKB.",
          confidence: 0.82,
          no_answer: false,
          citations: [
            {
              chunk_id: "chunk-1",
              document_id: "doc-1",
              document_version_id: "version-1",
              title: "Security report",
              page: 1,
              section_path: "Gate",
              open_url: "/api/v1/citations/chunk-1/open"
            }
          ],
          warnings: []
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    });

    try {
      await withReportFixture("scan_akb_test", async () => {
        const server = createServer({ logger: false });
        const response = await server.inject({
          method: "POST",
          url: "/api/v1/akb/ai/ask",
          payload: {
            scanRunId: "scan_akb_test",
            question: "Shrn vysledek skenu pro audit."
          }
        });

        expect(response.statusCode).toBe(200);
        expect(response.json().data).toMatchObject({
          provider: "AKB",
          scanRunId: "scan_akb_test",
          answer: "Citovana odpoved z AKB.",
          confidence: 0.82,
          noAnswer: false,
          citations: [
            {
              chunkId: "chunk-1",
              documentId: "doc-1"
            }
          ]
        });
        expect(outboundPayload).toMatchObject({
          query: "Shrn vysledek skenu pro audit.",
          question: "Shrn vysledek skenu pro audit.",
          require_citations: true,
          subject_id: "security-preflight-user",
          filters: {
            only_valid: true,
            classification_max: "health-data",
            tags: expect.arrayContaining(["stratos", "security-preflight", "security-preflight-scan:scan_akb_test"])
          },
          scope: {
            entity_type: "SecurityScanRun",
            entity_id: "scan_akb_test"
          }
        });
      });
    } finally {
      restoreEnv("SECURITY_PREFLIGHT_AKB_RAG_BASE_URL", previousRagBaseUrl);
      restoreEnv("SECURITY_PREFLIGHT_AKB_SERVICE_TOKEN", previousServiceToken);
    }
  });

  it("suppresses AKB answers that omit required citations", async () => {
    const previousRagBaseUrl = process.env.SECURITY_PREFLIGHT_AKB_RAG_BASE_URL;
    const previousServiceToken = process.env.SECURITY_PREFLIGHT_AKB_SERVICE_TOKEN;

    process.env.SECURITY_PREFLIGHT_AKB_RAG_BASE_URL = "https://akb.example.test/api/v1";
    process.env.SECURITY_PREFLIGHT_AKB_SERVICE_TOKEN = "test-service-token";
    vi.stubGlobal(
      "fetch",
      async () =>
        new Response(
          JSON.stringify({
            answer: "Nedolozena odpoved bez citaci.",
            confidence: 0.5,
            no_answer: false,
            citations: []
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        )
    );

    try {
      await withReportFixture("scan_akb_uncited_test", async () => {
        const server = createServer({ logger: false });
        const response = await server.inject({
          method: "POST",
          url: "/api/v1/akb/ai/ask",
          payload: {
            scanRunId: "scan_akb_uncited_test",
            question: "Shrn vysledek skenu."
          }
        });

        expect(response.statusCode).toBe(200);
        expect(response.json().data).toMatchObject({
          answer: "",
          noAnswer: true,
          warnings: ["AKB response omitted citations; answer suppressed."],
          missingInformation: ["AKB did not return required citations."]
        });
      });
    } finally {
      restoreEnv("SECURITY_PREFLIGHT_AKB_RAG_BASE_URL", previousRagBaseUrl);
      restoreEnv("SECURITY_PREFLIGHT_AKB_SERVICE_TOKEN", previousServiceToken);
    }
  });

  it("fails closed when AKB AI is requested without AKB configuration", async () => {
    const previousRagBaseUrl = process.env.SECURITY_PREFLIGHT_AKB_RAG_BASE_URL;
    const previousAliasRagBaseUrl = process.env.AKL_RAG_BASE_URL;

    delete process.env.SECURITY_PREFLIGHT_AKB_RAG_BASE_URL;
    delete process.env.AKL_RAG_BASE_URL;

    try {
      await withReportFixture("scan_akb_missing_test", async () => {
        const server = createServer({ logger: false });
        const response = await server.inject({
          method: "POST",
          url: "/api/v1/akb/ai/ask",
          payload: {
            scanRunId: "scan_akb_missing_test",
            question: "Shrn vysledek skenu."
          }
        });

        expect(response.statusCode).toBe(503);
        expect(response.json().error.code).toBe("AKB_NOT_CONFIGURED");
      });
    } finally {
      restoreEnv("SECURITY_PREFLIGHT_AKB_RAG_BASE_URL", previousRagBaseUrl);
      restoreEnv("AKL_RAG_BASE_URL", previousAliasRagBaseUrl);
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

async function withReportFixture(scanRunId: string, callback: () => Promise<void>): Promise<void> {
  const previousReportsPath = process.env.REPORTS_PATH;
  const reportsPath = await mkdtemp(path.join(tmpdir(), "security-preflight-api-test-"));
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
    await callback();
  } finally {
    restoreEnv("REPORTS_PATH", previousReportsPath);
    await rm(reportsPath, { recursive: true, force: true });
  }
}

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}
