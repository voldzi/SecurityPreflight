import { createHash, createPublicKey, timingSafeEqual, verify } from "node:crypto";
import type { FastifyRequest } from "fastify";

export type SecurityPreflightAuthMode = "disabled" | "shared-token" | "oidc";

type Jwk = {
  kid?: string;
  kty?: string;
  alg?: string;
  use?: string;
  n?: string;
  e?: string;
};

type JwtHeader = {
  alg?: string;
  kid?: string;
};

type JwtPayload = {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  azp?: string;
  client_id?: string;
  email?: string;
  preferred_username?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  realm_access?: {
    roles?: string[];
  };
  resource_access?: Record<
    string,
    {
      roles?: string[];
    }
  >;
};

type OidcConfig = {
  issuer: string;
  jwksUrl: string;
  clientId: string;
  audience: string;
};

export type SecurityPreflightAuthContext = {
  mode: SecurityPreflightAuthMode;
  subject: string;
  provider: string;
  name: string;
  email: string | null;
  roles: string[];
  isAdmin: boolean;
};

type SecurityPreflightAuthErrorCode = "UNAUTHORIZED" | "FORBIDDEN" | "OIDC_CONFIG_MISSING" | "SHARED_TOKEN_CONFIG_MISSING";

export type SecurityPreflightAuthResult =
  | { ok: true; context: SecurityPreflightAuthContext | null }
  | {
      ok: false;
      statusCode: 401 | 403 | 503;
      code: SecurityPreflightAuthErrorCode;
      message: string;
    };

export type SecurityPreflightAuthStatus = {
  mode: SecurityPreflightAuthMode;
  required: boolean;
  configured: boolean;
  issuer: string | null;
  audience: string | null;
  clientId: string | null;
  requiredRoles: string[];
  operatorRoles: string[];
  publicOidc: {
    configured: boolean;
    issuer: string | null;
    clientId: string | null;
    scopes: string;
  };
};

let jwksCache: { url: string; expiresAt: number; keys: Jwk[] } | null = null;

export function getAuthStatus(): SecurityPreflightAuthStatus {
  const config = getAuthConfig();
  const oidc = getOidcConfig();
  const publicIssuer = firstNonEmpty(process.env.NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_ISSUER, process.env.SECURITY_PREFLIGHT_OIDC_ISSUER);
  const publicClientId = firstNonEmpty(
    process.env.NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_CLIENT_ID,
    process.env.SECURITY_PREFLIGHT_OIDC_CLIENT_ID
  );

  return {
    mode: config.mode,
    required: config.mode !== "disabled",
    configured: config.mode === "disabled" || (config.mode === "shared-token" ? Boolean(config.sharedToken) : Boolean(oidc)),
    issuer: oidc?.issuer ?? null,
    audience: oidc?.audience ?? null,
    clientId: oidc?.clientId ?? null,
    requiredRoles: config.requiredRoles,
    operatorRoles: config.operatorRoles,
    publicOidc: {
      configured: Boolean(publicIssuer && publicClientId),
      issuer: publicIssuer,
      clientId: publicClientId,
      scopes: firstNonEmpty(process.env.NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_SCOPES, process.env.SECURITY_PREFLIGHT_OIDC_SCOPES) ?? "openid profile email"
    }
  };
}

export function isPublicRoute(request: FastifyRequest): boolean {
  const path = request.url.split("?")[0] ?? request.url;

  return (
    request.method === "OPTIONS" ||
    path === "/health" ||
    path === "/ready" ||
    path === "/api/v1/auth/status" ||
    path.startsWith("/api/v1/openapi")
  );
}

export async function authenticateSecurityPreflightRequest(request: FastifyRequest): Promise<SecurityPreflightAuthResult> {
  const config = getAuthConfig();

  if (config.mode === "disabled") {
    return { ok: true, context: null };
  }

  const authorization = request.headers.authorization;
  const token = typeof authorization === "string" && authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";

  if (!token) {
    return fail(401, "UNAUTHORIZED", "Bearer token is required.");
  }

  if (config.mode === "shared-token") {
    if (!config.sharedToken) {
      return fail(503, "SHARED_TOKEN_CONFIG_MISSING", "Shared-token authentication is enabled, but SECURITY_PREFLIGHT_API_TOKEN is missing.");
    }

    if (!safeTokenEqual(token, config.sharedToken)) {
      return fail(401, "UNAUTHORIZED", "Bearer token is invalid.");
    }

    return {
      ok: true,
      context: {
        mode: "shared-token",
        subject: "shared-token",
        provider: "security-preflight",
        name: "Shared token operator",
        email: null,
        roles: [...new Set([...config.requiredRoles, ...config.operatorRoles, "security-preflight.admin"])].sort(),
        isAdmin: true
      }
    };
  }

  const oidc = getOidcConfig();
  if (!oidc) {
    return fail(503, "OIDC_CONFIG_MISSING", "OIDC authentication is enabled, but issuer, JWKS URL, client id, or audience is missing.");
  }

  try {
    const claims = await verifyJwt(token, oidc);
    const context = claimsToAuthContext(claims, oidc.issuer);
    const routeAuthorization = authorizeRoute(request, context, config);

    if (!routeAuthorization.ok) {
      return routeAuthorization;
    }

    return { ok: true, context };
  } catch (error) {
    return fail(401, "UNAUTHORIZED", error instanceof Error ? error.message : "Bearer token could not be verified.");
  }
}

function authorizeRoute(
  request: FastifyRequest,
  context: SecurityPreflightAuthContext,
  config: ReturnType<typeof getAuthConfig>
): SecurityPreflightAuthResult {
  const neededRoles = isMutationRoute(request) ? config.operatorRoles : config.requiredRoles;

  if (!neededRoles.length || hasAnyRole(context.roles, neededRoles) || context.isAdmin) {
    return { ok: true, context };
  }

  return fail(403, "FORBIDDEN", "Authenticated identity does not have the required SecurityPreflight role.");
}

function isMutationRoute(request: FastifyRequest): boolean {
  if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) return true;
  return false;
}

async function verifyJwt(token: string, config: OidcConfig): Promise<JwtPayload> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid bearer token.");
  }

  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const header = parseJwtPart<JwtHeader>(headerPart);
  const payload = parseJwtPart<JwtPayload>(payloadPart);

  if (header.alg !== "RS256") {
    throw new Error("Unsupported token algorithm.");
  }

  if (payload.iss !== config.issuer) {
    throw new Error("Invalid token issuer.");
  }

  if (!payload.sub) {
    throw new Error("Token subject is missing.");
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp <= now) {
    throw new Error("Token is expired.");
  }

  if (typeof payload.nbf === "number" && payload.nbf > now + 30) {
    throw new Error("Token is not valid yet.");
  }

  const audiences = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
  const authorizedParty = payload.azp ?? payload.client_id;
  if (!audiences.includes(config.audience) && authorizedParty !== config.clientId) {
    throw new Error("Token audience does not match SecurityPreflight.");
  }

  const key = await getSigningKey(config.jwksUrl, header.kid);
  const publicKey = createPublicKey({ key, format: "jwk" });
  const signedContent = `${headerPart}.${payloadPart}`;
  const valid = verify("RSA-SHA256", Buffer.from(signedContent), publicKey, base64UrlToBuffer(signaturePart));

  if (!valid) {
    throw new Error("Token signature is invalid.");
  }

  return payload;
}

async function getSigningKey(jwksUrl: string, kid: string | undefined) {
  const keys = await getJwks(jwksUrl);
  const key = keys.find((candidate) => candidate.kty === "RSA" && (!kid || candidate.kid === kid));

  if (!key?.n || !key.e) {
    throw new Error("OIDC signing key could not be found.");
  }

  return key;
}

async function getJwks(jwksUrl: string) {
  const now = Date.now();
  if (jwksCache && jwksCache.url === jwksUrl && jwksCache.expiresAt > now) {
    return jwksCache.keys;
  }

  const response = await fetch(jwksUrl, { headers: { accept: "application/json" } });
  if (!response.ok) {
    throw new Error(`OIDC JWKS could not be loaded (${response.status}).`);
  }

  const payload = (await response.json()) as { keys?: Jwk[] };
  const keys = Array.isArray(payload.keys) ? payload.keys : [];
  jwksCache = { url: jwksUrl, keys, expiresAt: now + 5 * 60 * 1000 };
  return keys;
}

function claimsToAuthContext(claims: JwtPayload, issuer: string): SecurityPreflightAuthContext {
  const email = normalizeOptionalString(claims.email);
  const fallbackName = email?.split("@")[0] ?? claims.preferred_username ?? claims.sub ?? "User";
  const fullName = [claims.given_name, claims.family_name].filter(Boolean).join(" ").trim();
  const name = (normalizeOptionalString(claims.name) ?? fullName) || fallbackName;
  const roles = extractRoles(claims);

  return {
    mode: "oidc",
    subject: claims.sub as string,
    provider: issuer,
    name,
    email: email ?? null,
    roles,
    isAdmin: hasAnyRole(roles, ["superadmin", "stratos_superadmin", "security-preflight.admin", "stratos_security_admin"])
  };
}

function extractRoles(claims: JwtPayload): string[] {
  const roles = new Set<string>();
  claims.realm_access?.roles?.forEach((role) => roles.add(role));

  for (const access of Object.values(claims.resource_access ?? {})) {
    access.roles?.forEach((role) => roles.add(role));
  }

  return [...roles].sort();
}

function getAuthConfig() {
  const explicitMode = firstNonEmpty(process.env.SECURITY_PREFLIGHT_AUTH_MODE)?.toLowerCase() as SecurityPreflightAuthMode | undefined;
  const mode = explicitMode ?? (process.env.APP_ENV === "production" ? "oidc" : "disabled");

  return {
    mode: ["disabled", "shared-token", "oidc"].includes(mode) ? mode : "disabled",
    sharedToken: firstNonEmpty(process.env.SECURITY_PREFLIGHT_API_TOKEN),
    requiredRoles: csv(process.env.SECURITY_PREFLIGHT_REQUIRED_ROLES, [
      "security-preflight.viewer",
      "security-preflight.operator",
      "security-preflight.admin",
      "stratos_security_admin",
      "stratos_superadmin",
      "superadmin"
    ]),
    operatorRoles: csv(process.env.SECURITY_PREFLIGHT_OPERATOR_ROLES, [
      "security-preflight.operator",
      "security-preflight.admin",
      "stratos_security_admin",
      "stratos_superadmin",
      "superadmin"
    ])
  };
}

function getOidcConfig(): OidcConfig | null {
  const issuer = firstNonEmpty(process.env.SECURITY_PREFLIGHT_OIDC_ISSUER, process.env.STRATOS_OIDC_ISSUER)?.replace(/\/$/, "");
  const jwksUrl = firstNonEmpty(process.env.SECURITY_PREFLIGHT_OIDC_JWKS_URL, process.env.STRATOS_OIDC_JWKS_URL);
  const clientId = firstNonEmpty(process.env.SECURITY_PREFLIGHT_OIDC_CLIENT_ID, process.env.STRATOS_SECURITY_PREFLIGHT_OIDC_CLIENT_ID);
  const audience = firstNonEmpty(process.env.SECURITY_PREFLIGHT_OIDC_AUDIENCE) ?? clientId;

  if (!issuer || !jwksUrl || !clientId || !audience) {
    return null;
  }

  return { issuer, jwksUrl, clientId, audience };
}

function hasAnyRole(actual: string[], allowed: string[]): boolean {
  const roleSet = new Set(actual);
  return allowed.some((role) => roleSet.has(role));
}

function safeTokenEqual(actual: string, expected: string): boolean {
  const actualHash = createHash("sha256").update(actual).digest();
  const expectedHash = createHash("sha256").update(expected).digest();
  return timingSafeEqual(actualHash, expectedHash);
}

function parseJwtPart<T>(part: string): T {
  return JSON.parse(base64UrlToBuffer(part).toString("utf8")) as T;
}

function base64UrlToBuffer(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function csv(value: string | undefined, fallback: string[]): string[] {
  const parsed = value
    ?.split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  return parsed?.length ? parsed : fallback;
}

function firstNonEmpty(...values: Array<string | undefined>): string | null {
  return values.find((value): value is string => typeof value === "string" && value.trim().length > 0)?.trim() ?? null;
}

function normalizeOptionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function fail(
  statusCode: 401 | 403 | 503,
  code: SecurityPreflightAuthErrorCode,
  message: string
): SecurityPreflightAuthResult {
  return {
    ok: false,
    statusCode,
    code,
    message
  };
}
