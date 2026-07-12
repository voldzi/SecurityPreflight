#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KEYCLOAK_CONTAINER="${KEYCLOAK_CONTAINER:-keycloak}"
KEYCLOAK_INTERNAL_URL="${KEYCLOAK_INTERNAL_URL:-http://127.0.0.1:8081}"
KEYCLOAK_PUBLIC_URL="${KEYCLOAK_PUBLIC_URL:-https://login.zeleznalady.cz}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-stratos}"
KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
SECURITY_PREFLIGHT_ENV_FILE="${SECURITY_PREFLIGHT_ENV_FILE:-/srv/SecurityPreflight/.env}"
SECURITY_PREFLIGHT_PUBLIC_BASE_URL="${SECURITY_PREFLIGHT_PUBLIC_BASE_URL:-https://stratos.zeleznalady.cz/sp}"
SECURITY_PREFLIGHT_CORS_ORIGINS="${SECURITY_PREFLIGHT_CORS_ORIGINS:-https://stratos.zeleznalady.cz,http://docker.home.cz:8780,http://localhost:8780,http://127.0.0.1:8780}"
SECURITY_PREFLIGHT_OIDC_CLIENT_ID="${SECURITY_PREFLIGHT_OIDC_CLIENT_ID:-security-preflight-web}"

cleanup() {
  unset KEYCLOAK_ADMIN_PASSWORD
}
trap cleanup EXIT

read -rsp "Keycloak admin password: " KEYCLOAK_ADMIN_PASSWORD
printf "\n"

if [ -z "$KEYCLOAK_ADMIN_PASSWORD" ]; then
  printf "ERROR: Keycloak admin password cannot be empty.\n" >&2
  exit 1
fi

export KEYCLOAK_CONTAINER
export KEYCLOAK_INTERNAL_URL
export KEYCLOAK_PUBLIC_URL
export KEYCLOAK_REALM
export KEYCLOAK_ADMIN_USER
export KEYCLOAK_ADMIN_PASSWORD
export SECURITY_PREFLIGHT_ENV_FILE
export SECURITY_PREFLIGHT_PUBLIC_BASE_URL
export SECURITY_PREFLIGHT_CORS_ORIGINS
export SECURITY_PREFLIGHT_OIDC_CLIENT_ID

"$SCRIPT_DIR/ensure-security-preflight-client.sh"
