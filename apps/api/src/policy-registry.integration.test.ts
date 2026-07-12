import { describe, expect, it } from "vitest";
import { registerProjectPolicyBinding } from "./policy-registry.js";

const registryUrl = process.env.SECURITY_PREFLIGHT_POLICY_REGISTRY_URL?.trim();
const decisionUrl = process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL?.trim();
const token = process.env.STRATOS_POLICY_SERVICE_TOKEN?.trim();
const enabled = process.env.SECURITY_PREFLIGHT_G4_INTEGRATION_TEST === "true" && Boolean(registryUrl && decisionUrl && token);

describe.skipIf(!enabled)("live STRATOS Registry and decision compatibility", () => {
  it("allows an authoritative binding and denies unknown id and stale hash", async () => {
    const projectId = `g4_${Date.now().toString(36)}`;
    const binding = await registerProjectPolicyBinding(projectId, "sensitive");
    const base = { actorSubjectId: "service:security-preflight", applicationId: "security-preflight", capabilityId: "security-preflight:read_scan", operation: "read", scope: { type: "project", id: projectId } };
    const allowed = await decide({ ...base, policyBinding: binding });
    expect(allowed).toMatchObject({ decision: "ALLOW", reasonCodes: ["POLICY_ALLOW"] });
    expect(allowed.decisionId).toMatch(/^dec_/);
    const unknown = await decide({ ...base, policyBinding: { ...binding, policyBindingId: `pb_unknown_${Date.now()}` } });
    expect(unknown).toMatchObject({ decision: "DENY", reasonCodes: ["POLICY_UNAVAILABLE"] });
    const stale = await decide({ ...base, policyBinding: { ...binding, policyHash: `sha256:${"0".repeat(64)}` } });
    expect(stale).toMatchObject({ decision: "DENY", reasonCodes: ["POLICY_UNAVAILABLE"] });
  });

  it("rejects an unknown obligation before a binding can be used", async () => {
    const response = await fetch(registryUrl as string, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ policyVersion: "information-policy-2.0.0", handlingClass: "RESTRICTED", legalClassification: "NONE", tlp: "TLP:AMBER", pap: "PAP:AMBER", contentCategories: ["SECURITY"], audience: { organizationId: "org_stratos", scopeType: "project", scopeIds: ["g4_unknown_obligation"] }, obligations: ["UNKNOWN_OBLIGATION"] })
    });
    expect(response.ok).toBe(false);
  });
});

async function decide(payload: unknown): Promise<{ decision: string; reasonCodes: string[]; decisionId: string }> {
  const response = await fetch(decisionUrl as string, { method: "POST", headers: headers(), body: JSON.stringify(payload) });
  expect(response.ok).toBe(true);
  return response.json() as Promise<{ decision: string; reasonCodes: string[]; decisionId: string }>;
}

function headers(): Record<string, string> {
  return { accept: "application/json", authorization: `Bearer ${token}`, "content-type": "application/json" };
}
