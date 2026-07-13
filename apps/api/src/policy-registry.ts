import { z } from "zod";
import {
  informationPolicyBindingForClassification,
  informationPolicyBindingHash,
  type DataClassification,
  type InformationPolicyBinding
} from "@security-preflight/core";

const policyBindingIdPattern = /^(?:pol|pb)_[A-Za-z0-9_-]{8,}$/;
const policyObligations = [
  "AUDIT_ACCESS",
  "NO_EXTERNAL_AI",
  "LOCAL_PROCESSING_ONLY",
  "NO_PUBLIC_EXPORT",
  "NO_EXPORT",
  "WATERMARK",
  "ENCRYPT_AT_REST",
  "RECIPIENT_CONFIRMATION",
  "ORIGINATOR_APPROVAL",
  "PAP_ENFORCEMENT"
] as const;
const policyContentCategories = [
  "PERSONAL_DATA",
  "FINANCIAL",
  "CONTRACTUAL",
  "PROJECT_MANAGEMENT",
  "SECURITY",
  "CYBER_THREAT",
  "SOURCE_CODE",
  "AUTHENTICATION",
  "AUDIT",
  "PUBLIC_INFORMATION"
] as const;

const canonicalString = z.string().min(1).max(200).refine((value) => value === value.trim(), "must be canonical");
const uniqueCanonicalArray = <T extends z.ZodTypeAny>(item: T) => z.array(item).max(100).refine(
  (values) => new Set(values as unknown[]).size === values.length,
  "must contain unique values"
);
const audienceSchema = z.object({
  organizationId: z.literal("org_stratos"),
  scopeType: z.enum(["organization", "organization_unit", "project", "document", "recipient_set", "public"]),
  scopeIds: uniqueCanonicalArray(canonicalString).optional(),
  recipientSubjectIds: uniqueCanonicalArray(canonicalString).optional()
}).strict();

export const registeredPolicyBindingSchema = z.object({
  schemaVersion: z.literal("stratos-information-policy-2"),
  policyBindingId: z.string().regex(policyBindingIdPattern),
  organizationId: z.literal("org_stratos"),
  applicationId: z.literal("security-preflight"),
  policyHash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  policyVersion: z.literal("information-policy-2.0.0"),
  handlingClass: z.enum(["PUBLIC", "INTERNAL", "RESTRICTED"]),
  legalClassification: z.literal("NONE"),
  tlp: z.enum(["TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"]).nullable(),
  pap: z.enum(["PAP:RED", "PAP:AMBER", "PAP:GREEN", "PAP:CLEAR"]).nullable(),
  obligations: uniqueCanonicalArray(z.enum(policyObligations)),
  contentCategories: uniqueCanonicalArray(z.enum(policyContentCategories)),
  audience: audienceSchema,
  originator: canonicalString.nullable()
}).strict().superRefine((binding, context) => {
  const scopeIds = binding.audience.scopeIds ?? [];
  const recipients = binding.audience.recipientSubjectIds ?? [];
  const scopeType = binding.audience.scopeType;
  if ((scopeType === "organization" || scopeType === "public") && (scopeIds.length > 0 || recipients.length > 0)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["audience"], message: `${scopeType} audience must be unscoped` });
  }
  if (["organization_unit", "project", "document"].includes(scopeType) && scopeIds.length === 0) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["audience", "scopeIds"], message: "scope IDs are required" });
  }
  if (scopeType === "recipient_set" && scopeIds.length === 0 && recipients.length === 0) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["audience"], message: "recipient-set audience requires a recipient or scope" });
  }
  if (scopeType !== "recipient_set" && recipients.length > 0) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["audience", "recipientSubjectIds"], message: "recipients require recipient_set audience" });
  }
  if (binding.tlp === "TLP:RED" && (scopeType !== "recipient_set" || recipients.length === 0)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["tlp"], message: "TLP:RED requires explicit recipients" });
  }
  if (scopeType === "public") {
    if (binding.handlingClass !== "PUBLIC") context.addIssue({ code: z.ZodIssueCode.custom, path: ["handlingClass"], message: "public audience requires PUBLIC handling" });
    if (binding.tlp !== null && binding.tlp !== "TLP:CLEAR") context.addIssue({ code: z.ZodIssueCode.custom, path: ["tlp"], message: "public audience requires TLP:CLEAR or null" });
    if (binding.pap !== null && binding.pap !== "PAP:CLEAR") context.addIssue({ code: z.ZodIssueCode.custom, path: ["pap"], message: "public audience requires PAP:CLEAR or null" });
    if (!binding.contentCategories.includes("PUBLIC_INFORMATION")) context.addIssue({ code: z.ZodIssueCode.custom, path: ["contentCategories"], message: "public audience requires PUBLIC_INFORMATION" });
    if (binding.contentCategories.some((category) => category === "PERSONAL_DATA" || category === "AUTHENTICATION")) context.addIssue({ code: z.ZodIssueCode.custom, path: ["contentCategories"], message: "public audience contains a sensitive category" });
    if (!binding.obligations.includes("AUDIT_ACCESS")) context.addIssue({ code: z.ZodIssueCode.custom, path: ["obligations"], message: "public audience requires AUDIT_ACCESS" });
    if (binding.obligations.includes("NO_EXPORT") || binding.obligations.includes("NO_PUBLIC_EXPORT")) context.addIssue({ code: z.ZodIssueCode.custom, path: ["obligations"], message: "public audience forbids public distribution" });
  }
});

export type RegisteredPolicyBinding = InformationPolicyBinding & {
  schemaVersion: "stratos-information-policy-2";
  policyBindingId: string;
  organizationId: "org_stratos";
  applicationId: "security-preflight";
  policyHash: string;
  originator: string | null;
};

export class PolicyRegistryError extends Error {
  constructor(readonly code: string, message: string, readonly statusCode = 503) {
    super(message);
  }
}

export async function registerProjectPolicyBinding(projectId: string, classification: DataClassification): Promise<RegisteredPolicyBinding> {
  const input = registrationInput(projectId, classification);
  const endpoint = policyRegistryEndpoint();
  const token = process.env.SECURITY_PREFLIGHT_GOVERNANCE_SERVICE_TOKEN?.trim();
  if (!endpoint || !token) {
    if (process.env.SECURITY_PREFLIGHT_AUTH_MODE === "disabled" || (process.env.APP_ENV !== "production" && !process.env.SECURITY_PREFLIGHT_AUTH_MODE)) {
      return {
        schemaVersion: "stratos-information-policy-2",
        ...input,
        organizationId: "org_stratos",
        policyHash: informationPolicyBindingHash(input),
        originator: null
      };
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
  if (!response.ok) {
    const statusCode = [400, 401, 403, 409].includes(response.status) ? response.status : 503;
    throw new PolicyRegistryError("POLICY_REGISTRY_REJECTED", `STRATOS Policy Registry rejected the binding (${response.status}).`, statusCode);
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new PolicyRegistryError("POLICY_REGISTRY_RESPONSE_INVALID", "STRATOS Policy Registry returned an invalid binding.");
  }
  const parsed = registeredPolicyBindingSchema.safeParse(payload);
  if (!parsed.success || !bindingMatchesRegistration(parsed.data, input)) {
    throw new PolicyRegistryError("POLICY_REGISTRY_RESPONSE_INVALID", "STRATOS Policy Registry returned an invalid or mismatched binding.");
  }
  return parsed.data as RegisteredPolicyBinding;
}

function bindingMatchesRegistration(binding: z.infer<typeof registeredPolicyBindingSchema>, input: ReturnType<typeof registrationInput>): boolean {
  return binding.policyBindingId === input.policyBindingId
    && binding.policyHash === informationPolicyBindingHash(input)
    && binding.policyVersion === input.policyVersion
    && binding.handlingClass === input.handlingClass
    && binding.legalClassification === input.legalClassification
    && binding.tlp === input.tlp
    && binding.pap === input.pap
    && sameArray(binding.obligations, input.obligations)
    && sameArray(binding.contentCategories, input.contentCategories)
    && binding.audience.organizationId === input.audience.organizationId
    && binding.audience.scopeType === input.audience.scopeType
    && sameArray(binding.audience.scopeIds ?? [], input.audience.scopeIds);
}

function registrationInput(projectId: string, classification: DataClassification) {
  return {
    applicationId: "security-preflight" as const,
    ...informationPolicyBindingForClassification(classification),
    policyBindingId: `pb_security_preflight_${safeId(projectId)}_${classification}`,
    audience: { organizationId: "org_stratos" as const, scopeType: "project" as const, scopeIds: [projectId] }
  };
}

function sameArray(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
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
