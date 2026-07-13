import { describe, expect, it } from "vitest";
import { assertWorkerGovernanceConfiguration, workerGovernanceConfiguration } from "./governance-config.js";

describe("worker governance configuration", () => {
  it("requires the worker-only decision credential in production", () => {
    expect(workerGovernanceConfiguration({ APP_ENV: "production" })).toMatchObject({
      valid: false,
      checks: { policyDecisionConfigured: false, workerCredentialConfigured: false }
    });
    expect(workerGovernanceConfiguration({
      APP_ENV: "production",
      SECURITY_PREFLIGHT_POLICY_DECISION_URL: "https://stratos.test/api/v1/policy/decisions",
      SECURITY_PREFLIGHT_WORKER_SERVICE_TOKEN: "worker-only"
    }).valid).toBe(true);
  });

  it("rejects governance and retired shared credentials even when the worker token exists", () => {
    const base = {
      APP_ENV: "production",
      SECURITY_PREFLIGHT_POLICY_DECISION_URL: "https://stratos.test/api/v1/policy/decisions",
      SECURITY_PREFLIGHT_WORKER_SERVICE_TOKEN: "worker-only"
    };
    expect(() => assertWorkerGovernanceConfiguration({ ...base, SECURITY_PREFLIGHT_GOVERNANCE_SERVICE_TOKEN: "governance-only" })).toThrow(/governanceCredentialAbsent/);
    expect(() => assertWorkerGovernanceConfiguration({ ...base, SECURITY_PREFLIGHT_POLICY_SERVICE_TOKEN: "retired" })).toThrow(/retiredSharedCredentialAbsent/);
  });
});
