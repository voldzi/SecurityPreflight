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
});
