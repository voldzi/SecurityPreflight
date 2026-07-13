import { redactSecrets, type SeveritySummary } from "@security-preflight/core";

export interface AkbIntegrationStatus {
  configured: boolean;
  ragConfigured: boolean;
  publicBaseUrl: string | null;
  authMode: "caller-bearer" | "oidc-client-credentials" | "service-token" | "none";
  syncRequired: boolean;
  boundaries: {
    storesPrompts: false;
    storesResponses: false;
    storesChunks: false;
    requiresCitations: true;
  };
}

export const SECURITY_PREFLIGHT_ORGANIZATION_ID = "org_stratos";

export class SecurityPreflightOrganizationConfigurationError extends Error {
  constructor(value: string) {
    super(`SECURITY_PREFLIGHT_TENANT_ID must equal ${SECURITY_PREFLIGHT_ORGANIZATION_ID}; received ${value}.`);
    this.name = "SecurityPreflightOrganizationConfigurationError";
  }
}

export function securityPreflightOrganizationId(environment: NodeJS.ProcessEnv = process.env): typeof SECURITY_PREFLIGHT_ORGANIZATION_ID {
  const configured = environment.SECURITY_PREFLIGHT_TENANT_ID?.trim();
  if (configured && configured !== SECURITY_PREFLIGHT_ORGANIZATION_ID) {
    throw new SecurityPreflightOrganizationConfigurationError(configured);
  }
  return SECURITY_PREFLIGHT_ORGANIZATION_ID;
}

export interface AkbAskInput {
  question: string;
  answerMode?: string;
  responseLanguage?: string;
  maxChunks?: number;
  correlationId: string;
  authorization?: string;
  run: {
    id: string;
    status: string;
    gateResult: string;
    findingCount: number;
    project: {
      id: string;
      name: string;
      dataClassification: string;
    };
    profile: {
      id: string;
      name: string;
    };
    severitySummary: SeveritySummary;
    evidence: {
      files: string[];
      hasCentralEnvelope: boolean;
    };
  };
  subject?: {
    tenantId?: string;
    userId?: string;
    roles?: string[];
    classificationClearance?: string[];
  };
}

export interface AkbCitation {
  chunkId: string | null;
  documentId: string | null;
  documentVersionId: string | null;
  title: string | null;
  page: number | null;
  sectionPath: string | null;
  openUrl: string | null;
}

export interface AkbAskResult {
  provider: "AKB";
  scanRunId: string;
  answer: string;
  confidence: number | null;
  noAnswer: boolean;
  citations: AkbCitation[];
  warnings: string[];
  missingInformation: string[];
  usedSourceIds: string[];
  correlationId: string;
}

export class AkbIntegrationError extends Error {
  constructor(
    public readonly code: "AKB_NOT_CONFIGURED" | "AKB_ORGANIZATION_INVALID" | "AKB_TOKEN_FAILED" | "AKB_REQUEST_FAILED",
    message: string,
    public readonly statusCode: number,
    public readonly details: unknown[] = []
  ) {
    super(message);
  }
}

export function getAkbIntegrationStatus(authorization?: string): AkbIntegrationStatus {
  const config = getAkbConfig();
  const hasOidc = Boolean(config.oidcTokenUrl && config.oidcClientId && config.oidcClientSecret);
  const hasServiceToken = Boolean(config.serviceToken);

  return {
    configured: Boolean(config.ragBaseUrl),
    ragConfigured: Boolean(config.ragBaseUrl),
    publicBaseUrl: config.publicBaseUrl,
    authMode: authorization ? "caller-bearer" : hasOidc ? "oidc-client-credentials" : hasServiceToken ? "service-token" : "none",
    syncRequired: config.syncRequired,
    boundaries: {
      storesPrompts: false,
      storesResponses: false,
      storesChunks: false,
      requiresCitations: true
    }
  };
}

export async function askAkb(input: AkbAskInput): Promise<AkbAskResult> {
  const config = getAkbConfig();

  if (!config.ragBaseUrl) {
    throw new AkbIntegrationError("AKB_NOT_CONFIGURED", "AKB RAG base URL is not configured.", 503);
  }

  const endpoint = `${trimSlashes(config.ragBaseUrl)}/rag/query`;
  const authorization = await resolveAuthorizationHeader(config, input.authorization);
  const tags = [
    "stratos",
    "security-preflight",
    `security-preflight-scan:${input.run.id}`,
    `security-preflight-project:${input.run.project.id}`,
    `security-preflight-profile:${input.run.profile.id}`
  ];
  const requestedOrganizationId = input.subject?.tenantId?.trim();
  if (input.subject?.tenantId !== undefined && requestedOrganizationId !== config.organizationId) {
    throw new AkbIntegrationError(
      "AKB_ORGANIZATION_INVALID",
      `AKB requests are limited to organization ${config.organizationId}.`,
      400
    );
  }
  const subject = {
    tenant_id: config.organizationId,
    user_id: input.subject?.userId ?? "security-preflight-user",
    roles: input.subject?.roles ?? ["stratos_user"],
    classification_clearance:
      input.subject?.classificationClearance ?? clearanceForClassification(input.run.project.dataClassification)
  };
  const requestPayload = {
    query: input.question,
    question: input.question,
    answer_mode: input.answerMode ?? "security_preflight_brief",
    response_language: input.responseLanguage ?? "cs",
    subject_id: subject.user_id,
    filters: {
      only_valid: true,
      classification_max: classificationMaxForAkb(input.run.project.dataClassification),
      tags
    },
    scope: {
      entity_type: "SecurityScanRun",
      entity_id: input.run.id,
      tags,
      metadata: {
        security_preflight_scan_run_id: input.run.id,
        security_preflight_project_id: input.run.project.id,
        security_preflight_profile_id: input.run.profile.id,
        security_preflight_gate_result: input.run.gateResult,
        security_preflight_finding_count: input.run.findingCount,
        security_preflight_evidence_files: input.run.evidence.files,
        security_preflight_has_central_envelope: input.run.evidence.hasCentralEnvelope,
        data_classification: input.run.project.dataClassification
      }
    },
    subject,
    require_citations: true,
    correlation_id: input.correlationId,
    max_chunks: input.maxChunks ?? 8
  };

  let response: Response;

  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "X-AKL-Subject": subject.user_id,
        "X-AKL-Roles": subject.roles.join(","),
        "X-Request-ID": input.correlationId,
        "X-Correlation-ID": input.correlationId,
        ...(authorization ? { authorization } : {})
      },
      body: JSON.stringify(requestPayload)
    });
  } catch (error) {
    throw new AkbIntegrationError("AKB_REQUEST_FAILED", "AKB RAG request failed.", 502, [error instanceof Error ? error.message : "network error"]);
  }

  const responseText = await response.text();

  if (!response.ok) {
    throw new AkbIntegrationError("AKB_REQUEST_FAILED", `AKB RAG request failed with status ${response.status}.`, 502, [
      response.status,
      redactSecrets(responseText.slice(0, 400))
    ]);
  }

  const payload = parseJsonRecord(responseText);

  return normalizeAkbResponse(payload, input.run.id, input.correlationId);
}

async function resolveAuthorizationHeader(config: ReturnType<typeof getAkbConfig>, callerAuthorization?: string): Promise<string | null> {
  if (callerAuthorization?.toLowerCase().startsWith("bearer ")) {
    return callerAuthorization;
  }

  if (config.oidcTokenUrl && config.oidcClientId && config.oidcClientSecret) {
    return `Bearer ${await fetchOidcToken(config)}`;
  }

  if (config.serviceToken) {
    return `Bearer ${config.serviceToken}`;
  }

  return null;
}

async function fetchOidcToken(config: ReturnType<typeof getAkbConfig>): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: config.oidcClientId ?? "",
    client_secret: config.oidcClientSecret ?? "",
    scope: config.oidcScope
  });

  if (config.oidcAudience) {
    body.set("audience", config.oidcAudience);
  }

  let response: Response;

  try {
    response = await fetch(config.oidcTokenUrl ?? "", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      body
    });
  } catch {
    throw new AkbIntegrationError("AKB_TOKEN_FAILED", "AKB OIDC token request failed.", 502);
  }

  const payload = parseJsonRecord(await response.text());
  const token = stringValue(payload.access_token);

  if (!response.ok || !token) {
    throw new AkbIntegrationError("AKB_TOKEN_FAILED", "AKB OIDC token response was not usable.", 502, [response.status]);
  }

  return token;
}

function normalizeAkbResponse(payload: Record<string, unknown>, scanRunId: string, correlationId: string): AkbAskResult {
  const answer = stringValue(payload.answer) ?? stringValue(payload.response) ?? "";
  const citations = arrayValue(payload.citations).map((item) => {
    const citation = recordValue(item);

    return {
      chunkId: nullableString(citation.chunk_id ?? citation.chunkId),
      documentId: nullableString(citation.document_id ?? citation.documentId),
      documentVersionId: nullableString(citation.document_version_id ?? citation.documentVersionId),
      title: nullableString(citation.title),
      page: numberValue(citation.page),
      sectionPath: nullableString(citation.section_path ?? citation.sectionPath),
      openUrl: nullableString(citation.open_url ?? citation.openUrl)
    };
  });
  const noAnswerFlag = booleanValue(payload.no_answer ?? payload.noAnswer);
  const answerIsCited = answer.length > 0 && citations.length > 0;
  const noAnswer = !answerIsCited || noAnswerFlag === true;
  const warnings = stringArrayValue(payload.warnings);
  const missingInformation = stringArrayValue(payload.missing_information ?? payload.missingInformation);

  if (answer && !citations.length) {
    warnings.push("AKB response omitted citations; answer suppressed.");
    missingInformation.push("AKB did not return required citations.");
  }

  return {
    provider: "AKB",
    scanRunId,
    answer: answerIsCited ? redactSecrets(answer) : "",
    confidence: numberValue(payload.confidence),
    noAnswer,
    citations,
    warnings,
    missingInformation,
    usedSourceIds: stringArrayValue(payload.used_source_ids ?? payload.usedSourceIds),
    correlationId
  };
}

function getAkbConfig() {
  return {
    organizationId: securityPreflightOrganizationId(),
    ragBaseUrl: firstNonEmpty(process.env.SECURITY_PREFLIGHT_AKB_RAG_BASE_URL, process.env.AKL_RAG_BASE_URL),
    publicBaseUrl: firstNonEmpty(process.env.SECURITY_PREFLIGHT_AKB_PUBLIC_BASE_URL, process.env.NEXT_PUBLIC_AKB_URL),
    serviceToken: firstNonEmpty(process.env.SECURITY_PREFLIGHT_AKB_SERVICE_TOKEN, process.env.AKL_SERVICE_TOKEN),
    oidcTokenUrl: firstNonEmpty(process.env.SECURITY_PREFLIGHT_AKB_OIDC_TOKEN_URL, process.env.STRATOS_AKB_OIDC_TOKEN_URL),
    oidcClientId: firstNonEmpty(process.env.SECURITY_PREFLIGHT_AKB_OIDC_CLIENT_ID, process.env.STRATOS_AKB_OIDC_CLIENT_ID),
    oidcClientSecret: firstNonEmpty(process.env.SECURITY_PREFLIGHT_AKB_OIDC_CLIENT_SECRET, process.env.STRATOS_AKB_OIDC_CLIENT_SECRET),
    oidcAudience:
      firstNonEmpty(process.env.SECURITY_PREFLIGHT_AKB_OIDC_AUDIENCE, process.env.STRATOS_AKB_OIDC_AUDIENCE) ?? "akl-api",
    oidcScope:
      firstNonEmpty(process.env.SECURITY_PREFLIGHT_AKB_OIDC_SCOPE, process.env.STRATOS_AKB_OIDC_SCOPE) ?? "openid profile email",
    syncRequired: (process.env.SECURITY_PREFLIGHT_AKB_SYNC_REQUIRED ?? "false").toLowerCase() === "true"
  };
}

function clearanceForClassification(value: string): string[] {
  if (value === "health-data") return ["INTERNAL", "RESTRICTED", "SENSITIVE", "HEALTH_DATA"];
  if (value === "sensitive") return ["INTERNAL", "RESTRICTED", "SENSITIVE"];
  if (value === "confidential") return ["INTERNAL", "RESTRICTED"];
  return ["PUBLIC", "INTERNAL"];
}

function classificationMaxForAkb(value: string): string {
  if (value === "health-data") return "health-data";
  if (value === "sensitive") return "sensitive";
  if (value === "confidential") return "confidential";
  if (value === "internal") return "internal";
  return "public";
}

function firstNonEmpty(...values: Array<string | undefined>): string | null {
  return values.find((value): value is string => typeof value === "string" && value.trim().length > 0)?.trim() ?? null;
}

function trimSlashes(value: string): string {
  return value.replace(/\/+$/, "");
}

function parseJsonRecord(value: string): Record<string, unknown> {
  try {
    return recordValue(JSON.parse(value));
  } catch {
    return {};
  }
}

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function stringArrayValue(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function booleanValue(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}
