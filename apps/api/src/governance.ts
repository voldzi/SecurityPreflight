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

export type SecurityPreflightCapability = typeof SECURITY_PREFLIGHT_CAPABILITIES[number];

export type SecurityPreflightAccessScope = {
  type: string;
  id?: string;
  ownerSubjectId?: string;
};

export type SecurityPreflightAccessProjection = {
  profileId?: string;
  capabilities: SecurityPreflightCapability[];
  scopes: SecurityPreflightAccessScope[];
  effectiveScopes?: SecurityPreflightAccessScope[];
  validUntil?: string;
};

export type SecurityPreflightAccessProjectionResult =
  | { ok: true; projection: SecurityPreflightAccessProjection }
  | { ok: false; statusCode: 403 | 503; code: "APPLICATION_ACCESS_MISSING" | "ACCESS_GOVERNANCE_UNAVAILABLE"; reasonCodes: string[] };

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
  if (value.tlp === "TLP:RED") {
    const recipients = Array.isArray(value.audience.recipientSubjectIds) ? value.audience.recipientSubjectIds.filter((item) => typeof item === "string" && Boolean(item.trim())) : [];
    if (value.audience.scopeType !== "recipient_set" || recipients.length === 0) return deny("TLP_RECIPIENT_SET_REQUIRED");
  }
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
  scope?: SecurityPreflightAccessScope;
  accessProjection?: SecurityPreflightAccessProjection;
  policyBinding?: PolicyBinding;
  cyberInformation?: boolean;
}): Promise<PolicyDecision> {
  if (!SECURITY_PREFLIGHT_CAPABILITIES.includes(input.capabilityId as typeof SECURITY_PREFLIGHT_CAPABILITIES[number])) {
    return decidePolicy({ operation: input.operation, identityActive: true, membershipActive: true, applicationAccess: true, capability: false, scopeMatches: true, policyBinding: input.policyBinding ?? null });
  }
  if (input.context?.mode === "oidc") {
    if (!input.accessProjection) {
      return decidePolicy({ operation: input.operation, identityActive: true, membershipActive: true, applicationAccess: false, capability: false, scopeMatches: false, policyBinding: input.policyBinding ?? null });
    }
    const capability = input.accessProjection.capabilities.includes(input.capabilityId as SecurityPreflightCapability);
    const requestedScope = input.scope ?? { type: "organization", id: STRATOS_ORGANIZATION_ID };
    const scopeMatches = securityPreflightProjectionScopeMatches(input.accessProjection, requestedScope, input.context.subject);
    if (!capability || !scopeMatches) {
      return decidePolicy({ operation: input.operation, identityActive: true, membershipActive: true, applicationAccess: true, capability, scopeMatches, policyBinding: input.policyBinding ?? null });
    }
  }
  if (!input.context || input.context.mode !== "oidc") {
    if (!localGovernanceBypassAllowed(input.context?.mode)) return denyUnavailable(input.policyBinding);
    return decidePolicy({ operation: input.operation, identityActive: true, membershipActive: true, applicationAccess: true, capability: true, scopeMatches: true, policyBinding: input.policyBinding ?? policyBindingForClassification("internal"), cyberInformation: input.cyberInformation });
  }
  const endpoint = process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL?.trim();
  const authorization = bearerAuthorization(input.request);
  if (!endpoint || !authorization) return denyUnavailable(input.policyBinding);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { accept: "application/json", authorization, "content-type": "application/json", "x-correlation-id": input.request.id },
      body: JSON.stringify({ applicationId: "security-preflight", capabilityId: input.capabilityId, operation: input.operation, scope: input.scope ?? { type: "organization", id: STRATOS_ORGANIZATION_ID }, policyBinding: input.policyBinding ?? policyBindingForClassification("internal") }),
      signal: AbortSignal.timeout(Number(process.env.SECURITY_PREFLIGHT_POLICY_TIMEOUT_MS ?? 3000))
    });
    if (!response.ok) return denyUnavailable(input.policyBinding);
    const decision = parsePolicyDecision(await response.json());
    if (!decision) return denyUnavailable(input.policyBinding);
    if (decision.decision === "ALLOW" && input.cyberInformation && ["external_ai", "external_operation", "export"].includes(input.operation) && input.policyBinding?.pap == null) {
      return decidePolicy({ operation: input.operation, identityActive: true, membershipActive: true, applicationAccess: true, capability: true, scopeMatches: true, policyBinding: input.policyBinding ?? null, cyberInformation: true });
    }
    return decision;
  } catch {
    return denyUnavailable(input.policyBinding);
  }
}

export async function loadSecurityPreflightAccessProjection(input: {
  request: FastifyRequest;
  context: SecurityPreflightAuthContext;
}): Promise<SecurityPreflightAccessProjectionResult> {
  if (input.context.mode !== "oidc") {
    return { ok: false, statusCode: 403, code: "APPLICATION_ACCESS_MISSING", reasonCodes: ["APPLICATION_ACCESS_MISSING"] };
  }
  const endpoint = accessProjectionEndpoint();
  const authorization = bearerAuthorization(input.request);
  if (!endpoint || !authorization) {
    return { ok: false, statusCode: 503, code: "ACCESS_GOVERNANCE_UNAVAILABLE", reasonCodes: ["POLICY_UNAVAILABLE"] };
  }
  try {
    const response = await fetch(endpoint, {
      headers: {
        accept: "application/json",
        authorization,
        "x-correlation-id": input.request.id
      },
      signal: AbortSignal.timeout(Number(process.env.SECURITY_PREFLIGHT_POLICY_TIMEOUT_MS ?? 3000))
    });
    if (response.status === 401 || response.status === 403) {
      return { ok: false, statusCode: 403, code: "APPLICATION_ACCESS_MISSING", reasonCodes: ["APPLICATION_ACCESS_MISSING"] };
    }
    if (!response.ok) {
      return { ok: false, statusCode: 503, code: "ACCESS_GOVERNANCE_UNAVAILABLE", reasonCodes: ["POLICY_UNAVAILABLE"] };
    }
    const projection = parseSecurityPreflightAccessProjection(await response.json());
    if (!projection) {
      return { ok: false, statusCode: 403, code: "APPLICATION_ACCESS_MISSING", reasonCodes: ["APPLICATION_ACCESS_MISSING"] };
    }
    return { ok: true, projection };
  } catch {
    return { ok: false, statusCode: 503, code: "ACCESS_GOVERNANCE_UNAVAILABLE", reasonCodes: ["POLICY_UNAVAILABLE"] };
  }
}

export function parseSecurityPreflightAccessProjection(value: unknown): SecurityPreflightAccessProjection | null {
  const payload = recordValue(value);
  const accesses = Array.isArray(payload.applicationAccess) ? payload.applicationAccess : [];
  const candidate = accesses.find((item) => {
    const access = recordValue(item);
    return normalizeApplicationId(access.application) === "security-preflight";
  });
  const access = recordValue(candidate);
  if (Object.keys(access).length === 0 || access.isActive === false || normalizeOptionalString(access.suspendedAt)) return null;
  const validFrom = normalizeOptionalString(access.validFrom);
  if (validFrom && (!Number.isFinite(Date.parse(validFrom)) || Date.parse(validFrom) > Date.now())) return null;
  const validUntil = normalizeOptionalString(access.validUntil);
  if (validUntil && (!Number.isFinite(Date.parse(validUntil)) || Date.parse(validUntil) <= Date.now())) return null;
  const capabilities = Array.isArray(access.capabilities)
    ? [...new Set(access.capabilities.filter((item): item is SecurityPreflightCapability => typeof item === "string" && SECURITY_PREFLIGHT_CAPABILITIES.includes(item as SecurityPreflightCapability)))]
    : [];
  const scopes = parseAccessScopes(access.scopes);
  const effectiveScopes = Array.isArray(access.effectiveScopes) ? parseAccessScopes(access.effectiveScopes) : undefined;
  if (!capabilities.includes("security-preflight:access") || scopes.length === 0 || (effectiveScopes && effectiveScopes.length === 0)) return null;
  return {
    profileId: normalizeOptionalString(access.profileId),
    capabilities,
    scopes,
    ...(effectiveScopes ? { effectiveScopes } : {}),
    ...(validUntil ? { validUntil } : {})
  };
}

export function securityPreflightProjectionScopeMatches(
  projection: SecurityPreflightAccessProjection,
  requested: SecurityPreflightAccessScope,
  subjectId: string
) {
  const grants = projection.effectiveScopes ?? projection.scopes;
  return grants.some((grant) => {
    if (grant.type === "own") {
      return requested.type === "own" && requested.ownerSubjectId === subjectId;
    }
    const grantedId = grant.id ?? (grant.type === "organization" ? STRATOS_ORGANIZATION_ID : undefined);
    const requestedId = requested.id ?? (requested.type === "organization" ? STRATOS_ORGANIZATION_ID : undefined);
    return grant.type === requested.type && Boolean(grantedId && requestedId && grantedId === requestedId);
  });
}

export function securityPreflightProjectionDefaultScope(projection: SecurityPreflightAccessProjection) {
  const grants = projection.effectiveScopes ?? projection.scopes;
  const concrete = grants.filter((scope) => scope.type !== "own" && (scope.id || scope.type === "organization"));
  const selected = concrete.find((scope) => scope.type === "organization") ?? concrete[0];
  if (!selected) return null;
  return {
    type: selected.type,
    id: selected.id ?? STRATOS_ORGANIZATION_ID
  } satisfies SecurityPreflightAccessScope;
}

function denyUnavailable(value?: PolicyBinding): PolicyDecision {
  return { decision: "DENY", reasonCodes: ["POLICY_UNAVAILABLE"], obligations: [], policyVersion: value?.policyVersion ?? INFORMATION_POLICY_VERSION, decisionId: `dec_${randomUUID()}` };
}

function parsePolicyDecision(value: unknown): PolicyDecision | null {
  const decision = recordValue(value);
  if (decision.decision !== "ALLOW" && decision.decision !== "DENY") return null;
  if (!normalizeOptionalString(decision.decisionId) || decision.policyVersion !== INFORMATION_POLICY_VERSION) return null;
  if (!Array.isArray(decision.reasonCodes) || !decision.reasonCodes.every((item) => typeof item === "string" && Boolean(item.trim()))) return null;
  if (!Array.isArray(decision.obligations) || !decision.obligations.every((item) => typeof item === "string" && obligations.has(item))) return null;
  if (decision.decision === "ALLOW" && !decision.obligations.includes("AUDIT_ACCESS")) return null;
  return {
    decision: decision.decision,
    decisionId: decision.decisionId as string,
    reasonCodes: decision.reasonCodes as string[],
    obligations: decision.obligations as string[],
    policyVersion: INFORMATION_POLICY_VERSION
  };
}

function parseAccessScopes(value: unknown): SecurityPreflightAccessScope[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const scope = recordValue(item);
    const type = normalizeOptionalString(scope.type);
    const id = normalizeOptionalString(scope.id);
    const ownerSubjectId = normalizeOptionalString(scope.ownerSubjectId ?? scope.owner_subject_id);
    return type ? [{ type, ...(id ? { id } : {}), ...(ownerSubjectId ? { ownerSubjectId } : {}) }] : [];
  });
}

function accessProjectionEndpoint() {
  const explicit = process.env.SECURITY_PREFLIGHT_ACCESS_PROJECTION_URL?.trim();
  if (explicit) return explicit;
  const decision = process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL?.trim();
  return decision?.replace(/\/api\/v1\/policy\/decisions\/?$/, "/api/v1/auth/me") ?? "";
}

function bearerAuthorization(request: FastifyRequest) {
  const value = request.headers.authorization;
  return typeof value === "string" && value.startsWith("Bearer ") && value.slice("Bearer ".length).trim() ? value : "";
}

function localGovernanceBypassAllowed(mode: SecurityPreflightAuthContext["mode"] | undefined) {
  if (process.env.APP_ENV === "production") return false;
  const configuredMode = process.env.SECURITY_PREFLIGHT_AUTH_MODE?.trim().toLowerCase();
  if ((!configuredMode || configuredMode === "disabled") && !mode) return true;
  return mode === "shared-token" && process.env.SECURITY_PREFLIGHT_LOCAL_GOVERNANCE_BYPASS === "true";
}

function normalizeApplicationId(value: unknown) {
  return normalizeOptionalString(value)?.toLowerCase().replaceAll("_", "-") ?? "";
}

function normalizeOptionalString(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
