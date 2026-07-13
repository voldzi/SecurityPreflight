import { afterEach, describe, expect, it, vi } from "vitest";
import {
  askAkb,
  SECURITY_PREFLIGHT_ORGANIZATION_ID,
  securityPreflightOrganizationId,
  SecurityPreflightOrganizationConfigurationError,
  type AkbAskInput
} from "./akb.js";
import { createServer } from "./server.js";

const originalEnvironment = { ...process.env };

const askInput: AkbAskInput = {
  question: "Summarize the scan with citations.",
  correlationId: "request-organization-test",
  run: {
    id: "scan-organization-test",
    status: "completed",
    gateResult: "pass",
    findingCount: 0,
    project: {
      id: "project-organization-test",
      name: "Organization test",
      dataClassification: "internal"
    },
    profile: {
      id: "fast-local",
      name: "Fast local"
    },
    severitySummary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    evidence: { files: [], hasCentralEnvelope: true }
  }
};

describe("AKB organization invariant", () => {
  afterEach(() => {
    process.env = { ...originalEnvironment };
    vi.unstubAllGlobals();
  });

  it("resolves only the canonical STRATOS organization", () => {
    expect(securityPreflightOrganizationId({})).toBe(SECURITY_PREFLIGHT_ORGANIZATION_ID);
    expect(securityPreflightOrganizationId({ SECURITY_PREFLIGHT_TENANT_ID: "org_stratos" })).toBe("org_stratos");
    expect(() => securityPreflightOrganizationId({ SECURITY_PREFLIGHT_TENANT_ID: "default" })).toThrow(
      SecurityPreflightOrganizationConfigurationError
    );
  });

  it("aborts API startup when production configuration uses the retired default tenant", () => {
    process.env.APP_ENV = "production";
    process.env.SECURITY_PREFLIGHT_TENANT_ID = "default";

    expect(() => createServer({ logger: false })).toThrow(/must equal org_stratos/i);
  });

  it("always sends org_stratos to AKB and ignores the retired STRATOS_TENANT_ID fallback", async () => {
    delete process.env.SECURITY_PREFLIGHT_TENANT_ID;
    process.env.STRATOS_TENANT_ID = "default";
    process.env.SECURITY_PREFLIGHT_AKB_RAG_BASE_URL = "https://akb.example.test/api/v1";
    const outboundPayloads: Array<Record<string, unknown>> = [];
    vi.stubGlobal("fetch", async (_input: string | URL | Request, init?: RequestInit) => {
      outboundPayloads.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(JSON.stringify({
        answer: "Cited answer.",
        citations: [{ chunk_id: "chunk-1", document_id: "document-1", title: "Evidence" }]
      }), { status: 200, headers: { "content-type": "application/json" } });
    });

    await askAkb(askInput);

    expect(outboundPayloads).toHaveLength(1);
    expect(outboundPayloads[0]?.subject).toMatchObject({ tenant_id: "org_stratos" });
    expect(JSON.stringify(outboundPayloads[0])).not.toContain('"tenant_id":"default"');
  });

  it("rejects a caller attempt to select another AKB organization before fetch", async () => {
    process.env.SECURITY_PREFLIGHT_TENANT_ID = "org_stratos";
    process.env.SECURITY_PREFLIGHT_AKB_RAG_BASE_URL = "https://akb.example.test/api/v1";
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(askAkb({ ...askInput, subject: { tenantId: "default" } })).rejects.toMatchObject({
      code: "AKB_ORGANIZATION_INVALID",
      statusCode: 400
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
