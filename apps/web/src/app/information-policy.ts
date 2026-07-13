import type { InformationPolicyDetails } from "@voldzi/stratos-ui";

export interface ProjectPolicyBinding {
  policyBindingId: string;
  policyHash: string;
  policyVersion: string;
  handlingClass: InformationPolicyDetails["handlingClass"];
  legalClassification: "NONE";
  tlp: InformationPolicyDetails["tlp"];
  pap: InformationPolicyDetails["pap"];
  obligations: string[];
  contentCategories: string[];
  audience: InformationPolicyDetails["audience"];
}

export function projectPolicyDetails(binding: ProjectPolicyBinding | undefined): InformationPolicyDetails | null {
  if (!binding) return null;
  return {
    policyBindingId: binding.policyBindingId,
    policyHash: binding.policyHash,
    policyVersion: binding.policyVersion,
    handlingClass: binding.handlingClass,
    legalClassification: binding.legalClassification,
    tlp: binding.tlp,
    pap: binding.pap,
    obligations: [...binding.obligations],
    contentCategories: [...binding.contentCategories],
    audience: {
      organizationId: binding.audience.organizationId,
      scopeType: binding.audience.scopeType,
      scopeIds: binding.audience.scopeIds ? [...binding.audience.scopeIds] : undefined,
      recipientSubjectIds: binding.audience.recipientSubjectIds ? [...binding.audience.recipientSubjectIds] : undefined
    },
    inherited: false,
    sourceLabel: "SecurityPreflight project",
    publication: { status: "NOT_PUBLISHED" }
  };
}
