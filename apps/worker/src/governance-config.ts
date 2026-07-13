export function workerGovernanceConfiguration(environment: NodeJS.ProcessEnv): {
  valid: boolean;
  checks: Record<string, boolean>;
} {
  const production = environment.APP_ENV === "production";
  const checks = {
    policyDecisionConfigured: !production || Boolean(environment.SECURITY_PREFLIGHT_POLICY_DECISION_URL?.trim()),
    workerCredentialConfigured: !production || Boolean(environment.SECURITY_PREFLIGHT_WORKER_SERVICE_TOKEN?.trim()),
    governanceCredentialAbsent: !environment.SECURITY_PREFLIGHT_GOVERNANCE_SERVICE_TOKEN?.trim(),
    retiredSharedCredentialAbsent: !environment.SECURITY_PREFLIGHT_POLICY_SERVICE_TOKEN?.trim()
  };
  return { valid: Object.values(checks).every(Boolean), checks };
}

export function assertWorkerGovernanceConfiguration(environment: NodeJS.ProcessEnv): void {
  const configuration = workerGovernanceConfiguration(environment);
  if (!configuration.valid) {
    const failedChecks = Object.entries(configuration.checks).filter(([, value]) => !value).map(([name]) => name);
    throw new Error(`Invalid worker governance configuration: ${failedChecks.join(", ")}`);
  }
}
