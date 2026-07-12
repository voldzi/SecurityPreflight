import { randomUUID } from "node:crypto";
import type { FastifyRequest } from "fastify";
import { INFORMATION_POLICY_VERSION, INTEGRATION_ENVELOPE_VERSION, STRATOS_ORGANIZATION_ID, informationPolicyBindingForClassification, type InformationPolicyBinding } from "@security-preflight/core";
import type { SecurityPreflightAuthContext } from "./auth.js";

export { INFORMATION_POLICY_VERSION, INTEGRATION_ENVELOPE_VERSION, STRATOS_ORGANIZATION_ID };

export const SECURITY_PREFLIGHT_CAPABILITIES = [
  "security-preflight:access",
  "security-preflight:submit_scan",
  "security-preflight:read_scan",
  "security-preflight:external_operation",
  "security-preflight:export",
  "security-preflight:read_audit",
  "security-preflight:manage_access"
] as const;

const handlingClasses = new Set(["PUBLIC", "INTERNAL", "RESTRICTED"]);
const tlpValues = new Set(["TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"]);
const papValues = new Set(["PAP:RED", "PAP:AMBER", "PAP:GREEN", "PAP:CLEAR"]);
const obligations = new Set(["AUDIT_ACCESS", "NO_EXTERNAL_AI", "LOCAL_PROCESSING_ONLY", "NO_PUBLIC_EXPORT", "NO_EXPORT", "WATERMARK", "ENCRYPT_AT_REST", "RECIPIENT_CONFIRMATION", "ORIGINATOR_APPROVAL", "PAP_ENFORCEMENT"]);

export type PolicyBinding = InformationPolicyBinding;

export type PolicyDecision = {
  decision: "ALLOW" | "DENY";
  reasonCodes: string[];
  obligations: string[];
  policyVersion: string;
  decisionId: string;
};

export function policyBindingForClassification(classification: string): PolicyBinding {
  return informationPolicyBindingForClassification(classification);
}

export function decidePolicy(input: {
  operation: string;
  identityActive: boolean;
  membershipActive: boolean;
  applicationAccess: boolean;
  capability: boolean;
  scopeMatches: boolean;
  policyBinding: PolicyBinding | null;
  cyberInformation?: boolean;
}): PolicyDecision {
  const deny = (reason: string): PolicyDecision => ({ decision: "DENY", reasonCodes: [reason], obligations: [], policyVersion: input.policyBinding?.policyVersion ?? INFORMATION_POLICY_VERSION, decisionId: `dec_${randomUUID()}` });
  if (!input.identityActive) return deny("IDENTITY_DISABLED");
  if (!input.membershipActive) return deny("ORGANIZATION_MEMBERSHIP_INACTIVE");
  if (!input.applicationAccess) return deny("APPLICATION_ACCESS_MISSING");
  if (!input.capability) return deny("CAPABILITY_MISSING");
  if (!input.scopeMatches) return deny("SCOPE_MISMATCH");
  const value = input.policyBinding;
  if (!value) return deny("POLICY_UNAVAILABLE");
  if (value.policyVersion !== INFORMATION_POLICY_VERSION) return deny("POLICY_VERSION_UNSUPPORTED");
  if (value.legalClassification !== "NONE") return deny("LEGAL_CLASSIFICATION_UNSUPPORTED");
  if (!handlingClasses.has(value.handlingClass)) return deny("HANDLING_CLASS_UNKNOWN");
  if (value.tlp != null && !tlpValues.has(value.tlp)) return deny("TLP_UNKNOWN");
  if (value.pap != null && !papValues.has(value.pap)) return deny("PAP_UNKNOWN");
  if (value.obligations.some((item) => !obligations.has(item))) return deny("OBLIGATION_UNKNOWN");
  if (["export", "public_export"].includes(input.operation) && value.obligations.includes("NO_EXPORT")) return deny("EXPORT_FORBIDDEN");
  if (input.operation === "public_export" && value.obligations.includes("NO_PUBLIC_EXPORT")) return deny("PUBLIC_EXPORT_FORBIDDEN");
  if (input.operation === "external_ai" && (value.obligations.includes("NO_EXTERNAL_AI") || value.obligations.includes("LOCAL_PROCESSING_ONLY"))) return deny("EXTERNAL_AI_FORBIDDEN");
  if (input.cyberInformation && ["external_ai", "external_operation", "export"].includes(input.operation) && value.pap == null) return deny("PAP_REQUIRED");
  return { decision: "ALLOW", reasonCodes: ["POLICY_ALLOW"], obligations: [...value.obligations], policyVersion: value.policyVersion, decisionId: `dec_${randomUUID()}` };
}

export async function authorizeGovernedRequest(input: {
  request: FastifyRequest;
  context: SecurityPreflightAuthContext | null;
  capabilityId: string;
  operation: string;
  scope?: { type: string; id: string };
  policyBinding?: PolicyBinding;
  cyberInformation?: boolean;
}): Promise<PolicyDecision> {
  if (!SECURITY_PREFLIGHT_CAPABILITIES.includes(input.capabilityId as typeof SECURITY_PREFLIGHT_CAPABILITIES[number])) {
    return decidePolicy({ operation: input.operation, identityActive: true, membershipActive: true, applicationAccess: true, capability: false, scopeMatches: true, policyBinding: input.policyBinding ?? null });
  }
  if (!input.context || input.context.mode === "shared-token") {
    return decidePolicy({ operation: input.operation, identityActive: true, membershipActive: true, applicationAccess: true, capability: true, scopeMatches: true, policyBinding: input.policyBinding ?? policyBindingForClassification("internal"), cyberInformation: input.cyberInformation });
  }
  const endpoint = process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL?.trim();
  const token = process.env.STRATOS_POLICY_SERVICE_TOKEN?.trim();
  if (!endpoint || !token) return denyUnavailable(input.policyBinding);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { accept: "application/json", authorization: `Bearer ${token}`, "content-type": "application/json", "x-correlation-id": input.request.id },
      body: JSON.stringify({ actorSubjectId: input.context.subject, applicationId: "security-preflight", capabilityId: input.capabilityId, operation: input.operation, scope: input.scope ?? { type: "organization", id: STRATOS_ORGANIZATION_ID }, policyBinding: input.policyBinding ?? policyBindingForClassification("internal") }),
      signal: AbortSignal.timeout(Number(process.env.SECURITY_PREFLIGHT_POLICY_TIMEOUT_MS ?? 3000))
    });
    if (!response.ok) return denyUnavailable(input.policyBinding);
    const decision = await response.json() as PolicyDecision;
    if (!decision.decision || !decision.decisionId || !Array.isArray(decision.reasonCodes)) return denyUnavailable(input.policyBinding);
    if (decision.decision === "ALLOW" && input.cyberInformation && ["external_ai", "external_operation", "export"].includes(input.operation) && input.policyBinding?.pap == null) {
      return decidePolicy({ operation: input.operation, identityActive: true, membershipActive: true, applicationAccess: true, capability: true, scopeMatches: true, policyBinding: input.policyBinding ?? null, cyberInformation: true });
    }
    return decision;
  } catch {
    return denyUnavailable(input.policyBinding);
  }
}

function denyUnavailable(value?: PolicyBinding): PolicyDecision {
  return { decision: "DENY", reasonCodes: ["POLICY_UNAVAILABLE"], obligations: [], policyVersion: value?.policyVersion ?? INFORMATION_POLICY_VERSION, decisionId: `dec_${randomUUID()}` };
}
