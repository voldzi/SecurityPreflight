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
});
