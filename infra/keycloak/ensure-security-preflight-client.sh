#!/usr/bin/env bash
set -euo pipefail

KEYCLOAK_CONTAINER="${KEYCLOAK_CONTAINER:-keycloak}"
KEYCLOAK_INTERNAL_URL="${KEYCLOAK_INTERNAL_URL:-http://127.0.0.1:8081}"
KEYCLOAK_PUBLIC_URL="${KEYCLOAK_PUBLIC_URL:-https://login.zeleznalady.cz}"
KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-}"
REALM="${KEYCLOAK_REALM:-stratos}"
SECURITY_PREFLIGHT_WEB_CLIENT_ID="${SECURITY_PREFLIGHT_OIDC_CLIENT_ID:-security-preflight-web}"
SECURITY_PREFLIGHT_PUBLIC_BASE_URL="${SECURITY_PREFLIGHT_PUBLIC_BASE_URL:-${NEXT_PUBLIC_SECURITY_PREFLIGHT_PUBLIC_BASE_URL:-https://stratos.zeleznalady.cz/sp}}"
SECURITY_PREFLIGHT_OIDC_SCOPES="${SECURITY_PREFLIGHT_OIDC_SCOPES:-openid profile email}"
ENV_FILE="${SECURITY_PREFLIGHT_ENV_FILE:-}"

KEYCLOAK_PUBLIC_URL="${KEYCLOAK_PUBLIC_URL%/}"
SECURITY_PREFLIGHT_PUBLIC_BASE_URL="${SECURITY_PREFLIGHT_PUBLIC_BASE_URL%/}"
SECURITY_PREFLIGHT_PUBLIC_ORIGIN="${SECURITY_PREFLIGHT_PUBLIC_ORIGIN:-$(printf "%s" "$SECURITY_PREFLIGHT_PUBLIC_BASE_URL" | sed -E 's#^(https?://[^/]+).*#\1#')}"
SECURITY_PREFLIGHT_BASE_PATH="${SECURITY_PREFLIGHT_BASE_PATH:-$(printf "%s" "$SECURITY_PREFLIGHT_PUBLIC_BASE_URL" | sed -E 's#^https?://[^/]+##')}"
NEXT_PUBLIC_API_URL_VALUE="${NEXT_PUBLIC_API_URL:-$SECURITY_PREFLIGHT_PUBLIC_BASE_URL}"
SECURITY_PREFLIGHT_REDIRECT_URIS="${SECURITY_PREFLIGHT_REDIRECT_URIS:-[\"$SECURITY_PREFLIGHT_PUBLIC_BASE_URL/\",\"$SECURITY_PREFLIGHT_PUBLIC_BASE_URL/*\",\"http://docker.home.cz:8780/*\",\"http://localhost:8780/*\",\"http://127.0.0.1:8780/*\",\"https://securitypreflight.zeleznalady.cz/*\",\"https://security-preflight.zeleznalady.cz/*\"]}"
SECURITY_PREFLIGHT_WEB_ORIGINS="${SECURITY_PREFLIGHT_WEB_ORIGINS:-[\"$SECURITY_PREFLIGHT_PUBLIC_ORIGIN\",\"http://docker.home.cz:8780\",\"http://localhost:8780\",\"http://127.0.0.1:8780\",\"https://securitypreflight.zeleznalady.cz\",\"https://security-preflight.zeleznalady.cz\",\"+\"]}"
SECURITY_PREFLIGHT_CORS_ORIGINS_VALUE="${SECURITY_PREFLIGHT_CORS_ORIGINS:-$SECURITY_PREFLIGHT_PUBLIC_ORIGIN,http://docker.home.cz:8780,http://localhost:8780,http://127.0.0.1:8780}"
OIDC_ISSUER="${SECURITY_PREFLIGHT_OIDC_ISSUER:-$KEYCLOAK_PUBLIC_URL/realms/$REALM}"
OIDC_ISSUER="${OIDC_ISSUER%/}"
OIDC_JWKS_URL="${SECURITY_PREFLIGHT_OIDC_JWKS_URL:-$OIDC_ISSUER/protocol/openid-connect/certs}"

fail() {
  printf "ERROR: %s\n" "$1" >&2
  exit 1
}

docker inspect "$KEYCLOAK_CONTAINER" >/dev/null 2>&1 || fail "Keycloak container not found: $KEYCLOAK_CONTAINER"

if [ "${KEYCLOAK_USE_CONTAINER_BOOTSTRAP_PASSWORD:-false}" = "true" ]; then
  if [ -z "$KEYCLOAK_ADMIN_USER" ]; then
    KEYCLOAK_ADMIN_USER="$(
      docker inspect "$KEYCLOAK_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' \
        | sed -n 's/^KC_BOOTSTRAP_ADMIN_USERNAME=//p; s/^KEYCLOAK_ADMIN=//p' \
        | head -n 1
    )"
  fi

  if [ -z "${KEYCLOAK_ADMIN_PASSWORD:-}" ]; then
    KEYCLOAK_ADMIN_PASSWORD="$(
      docker inspect "$KEYCLOAK_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' \
        | sed -n 's/^KC_BOOTSTRAP_ADMIN_PASSWORD=//p; s/^KEYCLOAK_ADMIN_PASSWORD=//p' \
        | head -n 1
    )"
  fi
fi

KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"

if [ -z "${KEYCLOAK_ADMIN_PASSWORD:-}" ]; then
  read -rsp "Keycloak admin password: " KEYCLOAK_ADMIN_PASSWORD
  printf "\n"
fi

[[ -n "$KEYCLOAK_ADMIN_PASSWORD" ]] || fail "Password cannot be empty."

printf "Keycloak container:       %s\n" "$KEYCLOAK_CONTAINER"
printf "Keycloak URL:             %s\n" "$KEYCLOAK_INTERNAL_URL"
printf "Realm:                    %s\n" "$REALM"
printf "SecurityPreflight client: %s\n" "$SECURITY_PREFLIGHT_WEB_CLIENT_ID"
printf "Public base URL:          %s\n" "$SECURITY_PREFLIGHT_PUBLIC_BASE_URL"
printf "OIDC issuer:              %s\n" "$OIDC_ISSUER"
printf "Redirect URIs:            %s\n" "$SECURITY_PREFLIGHT_REDIRECT_URIS"
printf "Web origins:              %s\n" "$SECURITY_PREFLIGHT_WEB_ORIGINS"
[ -n "$ENV_FILE" ] && printf "Env update:               %s\n" "$ENV_FILE"
printf "\n"

docker exec -i \
  -e KEYCLOAK_INTERNAL_URL="$KEYCLOAK_INTERNAL_URL" \
  -e KEYCLOAK_ADMIN_USER="$KEYCLOAK_ADMIN_USER" \
  -e KEYCLOAK_ADMIN_PASSWORD="$KEYCLOAK_ADMIN_PASSWORD" \
  -e REALM="$REALM" \
  -e SECURITY_PREFLIGHT_WEB_CLIENT_ID="$SECURITY_PREFLIGHT_WEB_CLIENT_ID" \
  -e SECURITY_PREFLIGHT_PUBLIC_BASE_URL="$SECURITY_PREFLIGHT_PUBLIC_BASE_URL" \
  -e SECURITY_PREFLIGHT_REDIRECT_URIS="$SECURITY_PREFLIGHT_REDIRECT_URIS" \
  -e SECURITY_PREFLIGHT_WEB_ORIGINS="$SECURITY_PREFLIGHT_WEB_ORIGINS" \
  "$KEYCLOAK_CONTAINER" sh -s <<"IN_CONTAINER"
set -euo pipefail

KCADM=/opt/keycloak/bin/kcadm.sh

"$KCADM" config credentials \
  --server "$KEYCLOAK_INTERNAL_URL" \
  --realm master \
  --user "$KEYCLOAK_ADMIN_USER" \
  --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null

if ! "$KCADM" get "realms/$REALM" >/dev/null 2>&1; then
  echo "ERROR: Realm $REALM does not exist." >&2
  exit 1
fi

csv_id_for_client() {
  client_id="$1"
  while IFS= read -r line; do
    line="${line%$'\r'}"
    case "$line" in
      \"*,\"$client_id\")
        id="${line%%,*}"
        id="${id#\"}"
        id="${id%\"}"
        printf "%s\n" "$id"
        return 0
        ;;
    esac
  done <<EOF
$("$KCADM" get clients -r "$REALM" -q "clientId=$client_id" --fields id,clientId --format csv)
EOF
}

require_realm_role() {
  role="$1"
  if ! "$KCADM" get "roles/$role" -r "$REALM" >/dev/null 2>&1; then
    echo "ERROR: Required centrally managed realm role '$role' is missing." >&2
    exit 1
  fi
}

ensure_audience_mapper() {
  client_uuid="$1"
  mapper_name="$2"
  if "$KCADM" get "clients/$client_uuid/protocol-mappers/models" -r "$REALM" | grep -q "\"name\" *: *\"$mapper_name\""; then
    return 0
  fi
  "$KCADM" create "clients/$client_uuid/protocol-mappers/models" -r "$REALM" \
    -s "name=$mapper_name" \
    -s "protocol=openid-connect" \
    -s "protocolMapper=oidc-audience-mapper" \
    -s "config.\"included.client.audience\"=$SECURITY_PREFLIGHT_WEB_CLIENT_ID" \
    -s 'config."access.token.claim"=true' >/dev/null
}

require_realm_role "stratos_user"
require_realm_role "stratos_admin"

web_uuid="$(csv_id_for_client "$SECURITY_PREFLIGHT_WEB_CLIENT_ID")"
if [ -z "$web_uuid" ]; then
  "$KCADM" create clients -r "$REALM" \
    -s "clientId=$SECURITY_PREFLIGHT_WEB_CLIENT_ID" \
    -s "name=SecurityPreflight" \
    -s "enabled=true" \
    -s "publicClient=true" \
    -s "standardFlowEnabled=true" \
    -s "directAccessGrantsEnabled=false" \
    -s "implicitFlowEnabled=false" \
    -s "frontchannelLogout=true" \
    -s "fullScopeAllowed=true" \
    -s "rootUrl=$SECURITY_PREFLIGHT_PUBLIC_BASE_URL" \
    -s "baseUrl=$SECURITY_PREFLIGHT_PUBLIC_BASE_URL" \
    -s "redirectUris=$SECURITY_PREFLIGHT_REDIRECT_URIS" \
    -s "webOrigins=$SECURITY_PREFLIGHT_WEB_ORIGINS" >/dev/null
  web_uuid="$(csv_id_for_client "$SECURITY_PREFLIGHT_WEB_CLIENT_ID")"
else
  "$KCADM" update "clients/$web_uuid" -r "$REALM" \
    -s "enabled=true" \
    -s "publicClient=true" \
    -s "standardFlowEnabled=true" \
    -s "directAccessGrantsEnabled=false" \
    -s "implicitFlowEnabled=false" \
    -s "frontchannelLogout=true" \
    -s "fullScopeAllowed=true" \
    -s "rootUrl=$SECURITY_PREFLIGHT_PUBLIC_BASE_URL" \
    -s "baseUrl=$SECURITY_PREFLIGHT_PUBLIC_BASE_URL" \
    -s "redirectUris=$SECURITY_PREFLIGHT_REDIRECT_URIS" \
    -s "webOrigins=$SECURITY_PREFLIGHT_WEB_ORIGINS" >/dev/null
fi

ensure_audience_mapper "$web_uuid" "security-preflight-web audience"

"$KCADM" get clients -r "$REALM" -q "clientId=$SECURITY_PREFLIGHT_WEB_CLIENT_ID" --fields clientId,enabled,publicClient,standardFlowEnabled,redirectUris,webOrigins
IN_CONTAINER

if [ -n "$ENV_FILE" ]; then
  ENV_FILE="$ENV_FILE" \
  SECURITY_PREFLIGHT_AUTH_MODE="oidc" \
  SECURITY_PREFLIGHT_OIDC_ISSUER="$OIDC_ISSUER" \
  SECURITY_PREFLIGHT_OIDC_JWKS_URL="$OIDC_JWKS_URL" \
  SECURITY_PREFLIGHT_OIDC_CLIENT_ID="$SECURITY_PREFLIGHT_WEB_CLIENT_ID" \
  SECURITY_PREFLIGHT_OIDC_AUDIENCE="$SECURITY_PREFLIGHT_WEB_CLIENT_ID" \
  SECURITY_PREFLIGHT_CORS_ORIGINS="$SECURITY_PREFLIGHT_CORS_ORIGINS_VALUE" \
  NEXT_PUBLIC_SECURITY_PREFLIGHT_PUBLIC_BASE_URL="$SECURITY_PREFLIGHT_PUBLIC_BASE_URL" \
  NEXT_PUBLIC_SECURITY_PREFLIGHT_BASE_PATH="$SECURITY_PREFLIGHT_BASE_PATH" \
  NEXT_PUBLIC_API_URL="$NEXT_PUBLIC_API_URL_VALUE" \
  NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_ISSUER="$OIDC_ISSUER" \
  NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_CLIENT_ID="$SECURITY_PREFLIGHT_WEB_CLIENT_ID" \
  NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_SCOPES="$SECURITY_PREFLIGHT_OIDC_SCOPES" \
  NEXT_PUBLIC_STRATOS_HOME_URL="${NEXT_PUBLIC_STRATOS_HOME_URL:-https://stratos.zeleznalady.cz/}" \
  NEXT_PUBLIC_PROJECTFLOW_URL="${NEXT_PUBLIC_PROJECTFLOW_URL:-https://stratos.zeleznalady.cz/project}" \
  NEXT_PUBLIC_AKB_URL="${NEXT_PUBLIC_AKB_URL:-https://stratos.zeleznalady.cz/akb}" \
    python3 - <<'PY'
from pathlib import Path
import os

path = Path(os.environ["ENV_FILE"])
path.parent.mkdir(parents=True, exist_ok=True)
values = {
    "SECURITY_PREFLIGHT_AUTH_MODE": os.environ["SECURITY_PREFLIGHT_AUTH_MODE"],
    "SECURITY_PREFLIGHT_OIDC_ISSUER": os.environ["SECURITY_PREFLIGHT_OIDC_ISSUER"],
    "SECURITY_PREFLIGHT_OIDC_JWKS_URL": os.environ["SECURITY_PREFLIGHT_OIDC_JWKS_URL"],
    "SECURITY_PREFLIGHT_OIDC_CLIENT_ID": os.environ["SECURITY_PREFLIGHT_OIDC_CLIENT_ID"],
    "SECURITY_PREFLIGHT_OIDC_AUDIENCE": os.environ["SECURITY_PREFLIGHT_OIDC_AUDIENCE"],
    "SECURITY_PREFLIGHT_CORS_ORIGINS": os.environ["SECURITY_PREFLIGHT_CORS_ORIGINS"],
    "NEXT_PUBLIC_SECURITY_PREFLIGHT_PUBLIC_BASE_URL": os.environ["NEXT_PUBLIC_SECURITY_PREFLIGHT_PUBLIC_BASE_URL"],
    "NEXT_PUBLIC_SECURITY_PREFLIGHT_BASE_PATH": os.environ["NEXT_PUBLIC_SECURITY_PREFLIGHT_BASE_PATH"],
    "NEXT_PUBLIC_API_URL": os.environ["NEXT_PUBLIC_API_URL"],
    "NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_ISSUER": os.environ["NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_ISSUER"],
    "NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_CLIENT_ID": os.environ["NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_CLIENT_ID"],
    "NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_SCOPES": os.environ["NEXT_PUBLIC_SECURITY_PREFLIGHT_OIDC_SCOPES"],
    "NEXT_PUBLIC_STRATOS_HOME_URL": os.environ["NEXT_PUBLIC_STRATOS_HOME_URL"],
    "NEXT_PUBLIC_PROJECTFLOW_URL": os.environ["NEXT_PUBLIC_PROJECTFLOW_URL"],
    "NEXT_PUBLIC_AKB_URL": os.environ["NEXT_PUBLIC_AKB_URL"],
}
lines = path.read_text().splitlines() if path.exists() else []
seen = set()
next_lines = []
for line in lines:
    if "=" in line and not line.lstrip().startswith("#"):
        key = line.split("=", 1)[0]
        if key in values:
            next_lines.append(f"{key}={values[key]}")
            seen.add(key)
            continue
    next_lines.append(line)
for key, value in values.items():
    if key not in seen:
        next_lines.append(f"{key}={value}")
path.write_text("\n".join(next_lines) + "\n")
PY
  printf "Updated %s with public SecurityPreflight OIDC values.\n" "$ENV_FILE"
fi

unset KEYCLOAK_ADMIN_PASSWORD
printf "\nSecurityPreflight Keycloak client is ready and the STRATOS role baseline is present in realm %s.\n" "$REALM"
