const CODE_VERIFIER_KEY = "security-preflight.oidc.codeVerifier";
const STATE_KEY = "security-preflight.oidc.state";

export interface OidcClientConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scopes: string;
}

export function oidcConfig(): OidcClientConfig | null {
  const issuer = process.env.NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_ISSUER?.replace(/\/$/, "");
  const clientId = process.env.NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_CLIENT_ID;
  const publicBaseUrl = process.env.NEXT_PUBLIC_SECURITY_PREFLIGHT_PUBLIC_BASE_URL?.replace(/\/$/, "");
  const basePath = process.env.NEXT_PUBLIC_SECURITY_PREFLIGHT_BASE_PATH?.replace(/\/$/, "");

  if (!issuer || !clientId || typeof window === "undefined") return null;

  const fallbackBaseUrl = `${window.location.origin}${basePath || ""}`;

  return {
    issuer,
    clientId,
    redirectUri: `${publicBaseUrl || fallbackBaseUrl}/`,
    scopes: process.env.NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_SCOPES || "openid profile email"
  };
}

export async function startOidcLogin(config: OidcClientConfig): Promise<void> {
  const verifier = randomBase64Url(64);
  const challenge = await sha256Base64Url(verifier);
  const state = randomBase64Url(24);
  window.sessionStorage.setItem(CODE_VERIFIER_KEY, verifier);
  window.sessionStorage.setItem(STATE_KEY, state);

  const url = new URL(`${config.issuer}/protocol/openid-connect/auth`);
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", config.scopes);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  window.location.assign(url.toString());
}

export async function completeOidcLogin(config: OidcClientConfig, search: URLSearchParams): Promise<string | null> {
  const code = search.get("code");
  const state = search.get("state");

  if (!code) return null;

  const expectedState = window.sessionStorage.getItem(STATE_KEY);
  const verifier = window.sessionStorage.getItem(CODE_VERIFIER_KEY);
  window.sessionStorage.removeItem(STATE_KEY);
  window.sessionStorage.removeItem(CODE_VERIFIER_KEY);

  if (!state || !expectedState || state !== expectedState || !verifier) {
    throw new Error("OIDC callback state mismatch.");
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    code,
    code_verifier: verifier
  });
  const response = await fetch(`${config.issuer}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body
  });

  if (!response.ok) {
    throw new Error(`OIDC token exchange failed (${response.status}).`);
  }

  const tokens = (await response.json()) as { access_token?: string };
  if (!tokens.access_token) {
    throw new Error("OIDC token response did not include an access token.");
  }

  window.history.replaceState({}, document.title, window.location.pathname);
  return tokens.access_token;
}

export function oidcLogoutUrl(config: OidcClientConfig): string {
  const url = new URL(`${config.issuer}/protocol/openid-connect/logout`);
  url.searchParams.set("post_logout_redirect_uri", config.redirectUri);
  url.searchParams.set("client_id", config.clientId);
  return url.toString();
}

function randomBase64Url(bytes: number): string {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return base64Url(data);
}

async function sha256Base64Url(value: string): Promise<string> {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64Url(new Uint8Array(digest));
}

function base64Url(data: Uint8Array): string {
  let binary = "";
  data.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
