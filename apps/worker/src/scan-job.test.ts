import { access, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { defaultScanProfiles, informationPolicyBindingForClassification, informationPolicyBindingHash } from "@security-preflight/core";
import { buildScanExecutionPlan } from "@security-preflight/scanners";
import { authorizeWorkerExternalOperation, executeScanJob, planRequiresExternalOperation } from "./scan-job.js";

const originalEnvironment = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnvironment };
  vi.unstubAllGlobals();
});

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
      await expect(access(result.reportPaths.centralEnvelope)).resolves.toBeUndefined();
    } finally {
      await rm(reportsRoot, { recursive: true, force: true });
    }
  });

  it("requires and forwards the authoritative registered binding for a worker external operation", async () => {
    process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL = "https://stratos.test/api/v1/policy/decisions";
    process.env.STRATOS_POLICY_SERVICE_TOKEN = "runtime-only";
    const bindingBase = {
      ...informationPolicyBindingForClassification("sensitive"),
      policyBindingId: "pb_security_preflight_project_sensitive",
      organizationId: "org_stratos"
    };
    const policyBinding = { ...bindingBase, policyHash: informationPolicyBindingHash(bindingBase) };
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      expect(body).toMatchObject({
        actorSubjectId: "service:security-preflight",
        capabilityId: "security-preflight:external_operation",
        operation: "external_operation",
        scope: { type: "project", id: "project_sensitive" },
        policyBinding
      });
      return new Response(JSON.stringify({ decision: "ALLOW", decisionId: "dec_external", reasonCodes: ["POLICY_ALLOW"], obligations: ["AUDIT_ACCESS"], policyVersion: "information-policy-2.0.0" }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    await expect(authorizeWorkerExternalOperation({ operation: "external_operation", scopeId: "project_sensitive", policyBinding })).resolves.toEqual({ allowed: true, decisionId: "dec_external", reasonCodes: ["POLICY_ALLOW"] });
  });

  it("fails closed for an unregistered binding and a NO_EXPORT decision", async () => {
    process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL = "https://stratos.test/api/v1/policy/decisions";
    process.env.STRATOS_POLICY_SERVICE_TOKEN = "runtime-only";
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { capabilityId: string };
      return body.capabilityId === "security-preflight:external_operation"
        ? new Response(JSON.stringify({ decision: "ALLOW", decisionId: "dec_external", reasonCodes: ["POLICY_ALLOW"], obligations: ["AUDIT_ACCESS"], policyVersion: "information-policy-2.0.0" }), { status: 200 })
        : new Response(JSON.stringify({ decision: "DENY", decisionId: "dec_export", reasonCodes: ["EXPORT_FORBIDDEN"], obligations: [], policyVersion: "information-policy-2.0.0" }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    await expect(authorizeWorkerExternalOperation({ operation: "export", scopeId: "project_sensitive", policyBinding: informationPolicyBindingForClassification("sensitive") })).resolves.toEqual({ allowed: false, decisionId: null, reasonCodes: ["POLICY_UNAVAILABLE"] });
    expect(fetchMock).not.toHaveBeenCalled();

    const bindingBase = { ...informationPolicyBindingForClassification("sensitive"), policyBindingId: "pb_security_preflight_project_sensitive", organizationId: "org_stratos" };
    const policyBinding = { ...bindingBase, policyHash: informationPolicyBindingHash(bindingBase) };
    await expect(authorizeWorkerExternalOperation({ operation: "export", scopeId: "project_sensitive", policyBinding })).resolves.toEqual({ allowed: false, decisionId: "dec_export", reasonCodes: ["EXPORT_FORBIDDEN"] });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("fails closed when the policy service returns an unknown worker obligation", async () => {
    process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL = "https://stratos.test/api/v1/policy/decisions";
    process.env.STRATOS_POLICY_SERVICE_TOKEN = "runtime-only";
    const bindingBase = { ...informationPolicyBindingForClassification("sensitive"), policyBindingId: "pb_security_preflight_project_sensitive", organizationId: "org_stratos" };
    const policyBinding = { ...bindingBase, policyHash: informationPolicyBindingHash(bindingBase) };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      decision: "ALLOW",
      decisionId: "dec_unknown_obligation",
      reasonCodes: ["POLICY_ALLOW"],
      obligations: ["AUDIT_ACCESS", "UNSUPPORTED_OBLIGATION"],
      policyVersion: "information-policy-2.0.0"
    }), { status: 200 })));

    await expect(authorizeWorkerExternalOperation({ operation: "external_operation", scopeId: "project_sensitive", policyBinding })).resolves.toEqual({
      allowed: false,
      decisionId: null,
      reasonCodes: ["POLICY_RESPONSE_INVALID"]
    });
  });

  it("requires a fresh worker policy decision for every restricted-network scan plan", () => {
    const plan = buildScanExecutionPlan({
      scanRunId: "scan_worker_policy",
      reportsRoot: "/reports",
      profile: documentationProfile,
      project: { id: "project_policy", name: "Policy", path: "/workspace/project" }
    });
    expect(planRequiresExternalOperation(plan)).toBe(false);
    expect(planRequiresExternalOperation({
      ...plan,
      steps: [{ ...plan.steps[0]!, networkMode: "restricted" }, ...plan.steps.slice(1)]
    })).toBe(true);
  });
});
