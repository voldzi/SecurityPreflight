export type RegisteredProjectScope = {
  id: string;
  organizationId: "org_stratos";
  type: "project";
  key: string;
  parentId: "scope_org_stratos";
  application: "SECURITY_PREFLIGHT";
  sourceSystem: "APPLICATION";
  sourceRef: string;
  isActive: true;
};

export class ScopeRegistryError extends Error {
  constructor(readonly code: string, message: string, readonly statusCode = 503) {
    super(message);
  }
}

export async function registerProjectGovernanceScope(input: {
  projectId: string;
  displayName: string;
  actorSubjectId?: string;
}): Promise<RegisteredProjectScope | null> {
  const baseUrl = scopeRegistryBaseUrl();
  const token = process.env.STRATOS_POLICY_SERVICE_TOKEN?.trim();
  if (!baseUrl || !token) {
    if (localGovernanceMode()) return null;
    throw new ScopeRegistryError("SCOPE_REGISTRY_UNAVAILABLE", "STRATOS Scope Registry is not configured.");
  }
  const actorSubjectId = input.actorSubjectId?.trim() || "service:security-preflight";
  const sourceRef = `security-preflight:project:${input.projectId}`;
  let response: Response;
  try {
    response = await fetch(`${baseUrl.replace(/\/$/, "")}/project/${encodeURIComponent(input.projectId)}`, {
      method: "PUT",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        actorSubjectId,
        displayName: input.displayName,
        description: "SecurityPreflight audit project scope.",
        parentId: "scope_org_stratos",
        applicationId: "security-preflight",
        sourceRef,
        isActive: true,
        reason: "Register or refresh the owning SecurityPreflight project scope."
      }),
      signal: AbortSignal.timeout(Number(process.env.SECURITY_PREFLIGHT_POLICY_TIMEOUT_MS ?? 3000))
    });
  } catch {
    throw new ScopeRegistryError("SCOPE_REGISTRY_UNAVAILABLE", "STRATOS Scope Registry is unavailable.");
  }
  if (!response.ok) {
    throw new ScopeRegistryError(
      "SCOPE_REGISTRY_REJECTED",
      `STRATOS Scope Registry rejected the project scope (${response.status}).`,
      response.status === 400 || response.status === 401 || response.status === 403 || response.status === 409 ? response.status : 503
    );
  }
  const scope = await response.json() as Partial<RegisteredProjectScope>;
  if (
    scope.organizationId !== "org_stratos"
    || scope.type !== "project"
    || scope.key !== input.projectId
    || scope.parentId !== "scope_org_stratos"
    || scope.application !== "SECURITY_PREFLIGHT"
    || scope.sourceSystem !== "APPLICATION"
    || scope.sourceRef !== sourceRef
    || scope.isActive !== true
    || typeof scope.id !== "string"
    || !scope.id
  ) {
    throw new ScopeRegistryError("SCOPE_REGISTRY_RESPONSE_INVALID", "STRATOS Scope Registry returned an invalid project scope.");
  }
  return scope as RegisteredProjectScope;
}

function scopeRegistryBaseUrl() {
  const explicit = process.env.SECURITY_PREFLIGHT_SCOPE_REGISTRY_URL?.trim();
  if (explicit) return explicit;
  const decision = process.env.SECURITY_PREFLIGHT_POLICY_DECISION_URL?.trim();
  return decision?.replace(/\/api\/v1\/policy\/decisions\/?$/, "/api/v1/access/scopes") ?? "";
}

function localGovernanceMode() {
  return process.env.APP_ENV !== "production"
    && (!process.env.SECURITY_PREFLIGHT_AUTH_MODE || process.env.SECURITY_PREFLIGHT_AUTH_MODE === "disabled");
}
