#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/immutable-release-common.sh
source "${SCRIPT_DIR}/lib/immutable-release-common.sh"

usage() {
  printf 'Usage: %s --sha <full-git-sha> --image-manifest <path> --compose-override <path>\n' "$0" >&2
  exit 2
}

TARGET_SHA=""
IMAGE_MANIFEST=""
COMPOSE_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sha)
      [[ $# -ge 2 ]] || usage
      TARGET_SHA="$2"
      shift 2
      ;;
    --image-manifest)
      [[ $# -ge 2 ]] || usage
      IMAGE_MANIFEST="$2"
      shift 2
      ;;
    --compose-override)
      [[ $# -ge 2 ]] || usage
      COMPOSE_OVERRIDE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage
      ;;
  esac
done
[[ -n "$TARGET_SHA" && -n "$IMAGE_MANIFEST" && -n "$COMPOSE_OVERRIDE" ]] || usage
sp_validate_full_sha "$TARGET_SHA"

RELEASE_ROOT="${SECURITY_PREFLIGHT_RELEASE_ROOT:-/srv/SecurityPreflight}"
ENV_FILE="${SECURITY_PREFLIGHT_PROD_ENV_FILE:-${RELEASE_ROOT}/.env}"
RELEASE_DIR="${RELEASE_ROOT}/releases/${TARGET_SHA}"
PROJECT_NAME="securitypreflight"
RETRY_ATTEMPTS="${SECURITY_PREFLIGHT_RELEASE_VERIFY_ATTEMPTS:-12}"
RETRY_DELAY="${SECURITY_PREFLIGHT_RELEASE_VERIFY_DELAY_SECONDS:-5}"
[[ "$RETRY_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] || sp_fail "Invalid verification attempt count"
[[ "$RETRY_DELAY" =~ ^[0-9]+$ ]] || sp_fail "Invalid verification retry delay"

for command_name in curl docker psql python3; do
  sp_require_command "$command_name"
done
sp_require_private_env_file "$ENV_FILE"
sp_validate_production_env "$ENV_FILE"
sp_require_file "$IMAGE_MANIFEST"
sp_require_file "$COMPOSE_OVERRIDE"
sp_require_file "${RELEASE_DIR}/.securitypreflight-release-sha"

BASE_COMPOSE="${RELEASE_DIR}/infra/docker-compose.yml"
PRODUCTION_COMPOSE="${RELEASE_DIR}/infra/docker-compose.production.yml"
COMPOSE=(
  docker compose
  --project-name "$PROJECT_NAME"
  --env-file "$ENV_FILE"
  -f "$BASE_COMPOSE"
  -f "$PRODUCTION_COMPOSE"
  -f "$COMPOSE_OVERRIDE"
)

expected_image_id() {
  local service="$1"
  local value
  value="$(awk -F= -v expected="$service" '$1 == expected { print substr($0, index($0, "=") + 1); count++ } END { if (count != 1) exit 1 }' "$IMAGE_MANIFEST")" \
    || sp_fail "Image manifest must contain exactly one entry for $service"
  [[ "$value" =~ ^sha256:[0-9a-f]{64}$ ]] || sp_fail "Invalid image id for $service"
  printf '%s\n' "$value"
}

for service in web api worker scanner-toolbox; do
  container_id="$("${COMPOSE[@]}" ps --status running -q "$service")"
  [[ -n "$container_id" && "$(printf '%s\n' "$container_id" | wc -l | tr -d '[:space:]')" == "1" ]] \
    || sp_fail "Release service is not running exactly once: $service"
  actual_image_id="$(docker inspect --format '{{.Image}}' "$container_id")"
  [[ "$actual_image_id" == "$(expected_image_id "$service")" ]] \
    || sp_fail "Running $service container does not use the image built from target SHA"
  [[ "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$container_id")" == "$PROJECT_NAME" ]] \
    || sp_fail "Running $service container is not owned by Compose project $PROJECT_NAME"
done

redis_container=""
for service in postgres redis; do
  container_id="$("${COMPOSE[@]}" ps --status running -q "$service")"
  [[ -n "$container_id" && "$(printf '%s\n' "$container_id" | wc -l | tr -d '[:space:]')" == "1" ]] \
    || sp_fail "Data service is not running exactly once: $service"
  if [[ "$service" == "redis" ]]; then
    redis_container="$container_id"
  fi
done

[[ "$(docker exec "$redis_container" redis-cli --raw ping)" == "PONG" ]] \
  || sp_fail "Redis did not answer PONG after target startup"
database_url="$(sp_env_value "$ENV_FILE" DATABASE_URL)"
database_probe="$(
  PGAPPNAME=security-preflight-release-verify PGDATABASE="$database_url" psql \
    --no-psqlrc --tuples-only --no-align --command='SELECT 1'
)"
[[ "$(printf '%s' "$database_probe" | tr -d '[:space:]')" == "1" ]] \
  || sp_fail "PostgreSQL did not pass the post-start read-only probe"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/securitypreflight-release-verify.XXXXXX")"
chmod 0700 "$tmp_dir"
trap 'rm -rf "$tmp_dir"' EXIT

curl_to_file() {
  local url="$1"
  local output_file="$2"
  curl --fail --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --retry "$RETRY_ATTEMPTS" \
    --retry-delay "$RETRY_DELAY" \
    --retry-all-errors \
    --output "$output_file" \
    "$url"
}

validate_ready_json() {
  local response_file="$1"
  python3 - "$response_file" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if path.stat().st_size > 65536:
    raise SystemExit("Readiness response exceeds 64 KiB")
body = json.loads(path.read_text(encoding="utf-8"))
if body.get("status") != "ok" or body.get("service") != "security-preflight-api":
    raise SystemExit("SecurityPreflight API readiness response is invalid")
PY
}

validate_web_html() {
  local response_file="$1"
  python3 - "$response_file" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
size = path.stat().st_size
if size <= 0 or size > 2 * 1024 * 1024:
    raise SystemExit("Web smoke response size is invalid")
body = path.read_text(encoding="utf-8", errors="strict").lower()
if "securitypreflight" not in body or "<html" not in body:
    raise SystemExit("Web smoke response does not identify SecurityPreflight HTML")
PY
}

app_port="$(sp_env_value "$ENV_FILE" APP_PORT 8781)"
web_port="$(sp_env_value "$ENV_FILE" WEB_PORT 8780)"
[[ "$app_port" =~ ^[1-9][0-9]{0,4}$ && "$app_port" -le 65535 ]] || sp_fail "Invalid APP_PORT"
[[ "$web_port" =~ ^[1-9][0-9]{0,4}$ && "$web_port" -le 65535 ]] || sp_fail "Invalid WEB_PORT"
base_path="$(sp_env_value "$ENV_FILE" NEXT_PUBLIC_SECURITY_PREFLIGHT_BASE_PATH)"
[[ -z "$base_path" || "$base_path" =~ ^(/[A-Za-z0-9._~-]+)+$ ]] \
  || sp_fail "Invalid NEXT_PUBLIC_SECURITY_PREFLIGHT_BASE_PATH"

curl_to_file "http://127.0.0.1:${app_port}/ready" "${tmp_dir}/local-ready.json"
validate_ready_json "${tmp_dir}/local-ready.json"
curl_to_file "http://127.0.0.1:${web_port}${base_path}/" "${tmp_dir}/local-web.html"
validate_web_html "${tmp_dir}/local-web.html"

public_base_url="${SECURITY_PREFLIGHT_RELEASE_PUBLIC_BASE_URL:-$(sp_env_value "$ENV_FILE" NEXT_PUBLIC_SECURITY_PREFLIGHT_PUBLIC_BASE_URL)}"
[[ "$public_base_url" == https://* ]] || sp_fail "Public verification URL must use HTTPS"
public_base_url="${public_base_url%/}"
curl_to_file "${public_base_url}/api/ready" "${tmp_dir}/public-ready.json"
validate_ready_json "${tmp_dir}/public-ready.json"
curl_to_file "${public_base_url}/" "${tmp_dir}/public-web.html"
validate_web_html "${tmp_dir}/public-web.html"

printf 'Release verification passed for %s.\n' "$TARGET_SHA"
