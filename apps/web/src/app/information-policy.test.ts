import { describe, expect, it } from "vitest";
import { projectPolicyDetails } from "./information-policy";

describe("SecurityPreflight information-policy projection", () => {
  it("maps the authoritative project binding into the shared read-only panel contract", () => {
    expect(projectPolicyDetails({
      policyBindingId: "pb_security_preflight_project_sensitive",
      policyHash: `sha256:${"a".repeat(64)}`,
      policyVersion: "information-policy-2.0.0",
      handlingClass: "RESTRICTED",
      legalClassification: "NONE",
      tlp: "TLP:AMBER+STRICT",
      pap: "PAP:AMBER",
      obligations: ["AUDIT_ACCESS", "NO_PUBLIC_EXPORT"],
      contentCategories: ["SECURITY", "CYBER_THREAT"],
      audience: { organizationId: "org_stratos", scopeType: "project", scopeIds: ["project-sensitive"] }
    })).toMatchObject({
      inherited: false,
      audience: { organizationId: "org_stratos", scopeType: "project", scopeIds: ["project-sensitive"] },
      publication: { status: "NOT_PUBLISHED" }
    });
  });

  it("does not invent a policy when the Registry binding is missing", () => {
    expect(projectPolicyDetails(undefined)).toBeNull();
  });
});
