import { informationPolicyBindingForClassification, type DataClassification, type InformationPolicyBinding } from "@security-preflight/core";

export type RegisteredPolicyBinding = InformationPolicyBinding & {
  policyBindingId: string;
  organizationId: "org_stratos";
  policyHash: string;
};

export class PolicyRegistryError extends Error {
  constructor(readonly code: string, message: string, readonly statusCode = 503) {
    super(message);
  }
}

export async function registerProjectPolicyBinding(projectId: string, classification: DataClassification): Promise<RegisteredPolicyBinding> {
  const input = {
    ...informationPolicyBindingForClassification(classification),
    policyBindingId: `pb_security_preflight_${safeId(projectId)}_${classification}`,
    audience: { organizationId: "org_stratos", scopeType: "project", scopeIds: [projectId] }
  };
  const endpoint = policyRegistryEndpoint();
  const token = process.env.STRATOS_POLICY_SERVICE_TOKEN?.trim();
  if (!endpoint || !token) {
    if (process.env.SECURITY_PREFLIGHT_AUTH_MODE === "disabled" || (process.env.APP_ENV !== "production" && !process.env.SECURITY_PREFLIGHT_AUTH_MODE)) {
      const { informationPolicyBindingHash } = await import("@security-preflight/core");
      return { ...input, organizationId: "org_stratos", policyHash: informationPolicyBindingHash(input) };
    }
    throw new PolicyRegistryError("POLICY_REGISTRY_UNAVAILABLE", "STRATOS Policy Registry is not configured.");
  }
  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: { accept: "application/json", authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(Number(process.env.SECURITY_PREFLIGHT_POLICY_TIMEOUT_MS ?? 3000))
    });
  } catch {
    throw new PolicyRegistryError("POLICY_REGISTRY_UNAVAILABLE", "STRATOS Policy Registry is unavailable.");
  }
  if (!response.ok) throw new PolicyRegistryError("POLICY_REGISTRY_REJECTED", `STRATOS Policy Registry rejected the binding (${response.status}).`, response.status === 409 ? 409 : 503);
  const binding = await response.json() as Record<string, unknown>;
  if (binding.policyBindingId !== input.policyBindingId || binding.organizationId !== "org_stratos" || binding.policyVersion !== input.policyVersion || typeof binding.policyHash !== "string" || !/^sha256:[a-f0-9]{64}$/.test(binding.policyHash)) {
    throw new PolicyRegistryError("POLICY_REGISTRY_RESPONSE_INVALID", "STRATOS Policy Registry returned an invalid binding.");
  }
  return binding as unknown as RegisteredPolicyBinding;
}

function policyRegistryEndpoint(): string | null {
  const explicit = process.env.SECURITY_PREFLIGHT_POLICY_REGISTRY_URL?.trim();
  if (explicit) return explicit;
  const decision = process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL?.trim();
  return decision?.replace(/\/decisions\/?$/, "/bindings") ?? null;
}

function safeId(value: string): string {
  return value.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 100);
}
