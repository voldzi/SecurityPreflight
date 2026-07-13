#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/immutable-release-common.sh
source "${SCRIPT_DIR}/lib/immutable-release-common.sh"

usage() {
  printf 'Usage: %s --sha <full-git-sha>\n' "$0" >&2
  exit 2
}

TARGET_SHA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sha)
      [[ $# -ge 2 ]] || usage
      TARGET_SHA="$2"
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
[[ -n "$TARGET_SHA" ]] || usage
sp_validate_full_sha "$TARGET_SHA"

RELEASE_ROOT="${SECURITY_PREFLIGHT_RELEASE_ROOT:-/srv/SecurityPreflight}"
ENV_FILE="${SECURITY_PREFLIGHT_PROD_ENV_FILE:-${RELEASE_ROOT}/.env}"
RELEASE_DIR="${RELEASE_ROOT}/releases/${TARGET_SHA}"
BACKUPS_DIR="${RELEASE_ROOT}/backups"
PROJECT_NAME="securitypreflight"
TIMESTAMP="${SECURITY_PREFLIGHT_RELEASE_TIMESTAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
[[ "$TIMESTAMP" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || sp_fail "Invalid backup timestamp"

for command_name in docker pg_dump pg_restore python3 sha256sum; do
  sp_require_command "$command_name"
done
sp_require_private_env_file "$ENV_FILE"
sp_validate_production_env "$ENV_FILE"
sp_require_file "${RELEASE_DIR}/.securitypreflight-release-sha"
[[ "$(tr -d '[:space:]' <"${RELEASE_DIR}/.securitypreflight-release-sha")" == "$TARGET_SHA" ]] \
  || sp_fail "Release directory does not match its SHA marker"

BASE_COMPOSE="${RELEASE_DIR}/infra/docker-compose.yml"
PRODUCTION_COMPOSE="${RELEASE_DIR}/infra/docker-compose.production.yml"
sp_require_file "$BASE_COMPOSE"
sp_require_file "$PRODUCTION_COMPOSE"
COMPOSE=(
  docker compose
  --project-name "$PROJECT_NAME"
  --env-file "$ENV_FILE"
  -f "$BASE_COMPOSE"
  -f "$PRODUCTION_COMPOSE"
)

running_services="$("${COMPOSE[@]}" ps --status running --services)"
for writer in api worker; do
  if grep -Fxq "$writer" <<<"$running_services"; then
    sp_fail "Writer service must be stopped before backup: $writer"
  fi
done

redis_container="$("${COMPOSE[@]}" ps -q redis)"
[[ -n "$redis_container" && "$(printf '%s\n' "$redis_container" | wc -l | tr -d '[:space:]')" == "1" ]] \
  || sp_fail "Exactly one Redis container is required for backup"
[[ "$(docker inspect --format '{{.State.Running}}' "$redis_container")" == "true" ]] \
  || sp_fail "Redis must remain running while its RDB backup is created"

report_volumes="$(
  docker volume ls \
    --filter "label=com.docker.compose.project=${PROJECT_NAME}" \
    --filter 'label=com.docker.compose.volume=security_preflight_reports' \
    --format '{{.Name}}'
)"
report_volume_count="$(printf '%s\n' "$report_volumes" | awk 'NF { count++ } END { print count+0 }')"
[[ "$report_volume_count" == "1" ]] \
  || sp_fail "Exactly one Compose-owned report volume is required for backup"
report_volume="$(printf '%s\n' "$report_volumes" | awk 'NF { print; exit }')"
for writer in api worker; do
  writer_container="$("${COMPOSE[@]}" ps --all -q "$writer")"
  [[ -n "$writer_container" && "$(printf '%s\n' "$writer_container" | wc -l | tr -d '[:space:]')" == "1" ]] \
    || sp_fail "Exactly one stopped writer container is required for backup: $writer"
  [[ "$(docker inspect --format '{{.State.Running}}' "$writer_container")" == "false" ]] \
    || sp_fail "Writer container is still running during backup: $writer"
  mounted_report_volume="$(
    docker inspect \
      --format '{{range .Mounts}}{{if eq .Destination "/reports"}}{{.Name}}{{end}}{{end}}' \
      "$writer_container"
  )"
  [[ "$mounted_report_volume" == "$report_volume" ]] \
    || sp_fail "Writer $writer does not mount the Compose-owned report volume"
done

database_url="$(sp_env_value "$ENV_FILE" DATABASE_URL)"
[[ -n "$database_url" ]] || sp_fail "DATABASE_URL is missing from the persistent .env"

umask 077
sp_prepare_private_directory "$BACKUPS_DIR"
final_dir="${BACKUPS_DIR}/release-${TIMESTAMP}-${TARGET_SHA}"
[[ ! -e "$final_dir" ]] || sp_fail "Backup directory already exists: $final_dir"
stage_dir="$(mktemp -d "${BACKUPS_DIR}/.release-${TIMESTAMP}-${TARGET_SHA}.tmp.XXXXXX")"
chmod 0700 "$stage_dir"
redis_remote_file="/tmp/security-preflight-release-${TARGET_SHA}-$$.rdb"
cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [[ -n "$redis_remote_file" ]]; then
    docker exec "$redis_container" rm -f "$redis_remote_file" >/dev/null 2>&1
  fi
  if [[ -n "${stage_dir:-}" && -d "$stage_dir" ]]; then
    rm -rf "$stage_dir"
  fi
  exit "$status"
}
trap cleanup EXIT

postgres_dump="${stage_dir}/postgres.dump"
postgres_list="${stage_dir}/postgres.pg_restore.list"
printf 'Creating PostgreSQL custom-format backup after writer shutdown...\n' >&2
PGAPPNAME=security-preflight-release-backup PGDATABASE="$database_url" pg_dump \
  --format=custom \
  --no-owner \
  --no-privileges \
  --file="$postgres_dump"
[[ -s "$postgres_dump" ]] || sp_fail "PostgreSQL custom dump is empty"
pg_restore --list "$postgres_dump" >"$postgres_list"
[[ -s "$postgres_list" ]] || sp_fail "pg_restore --list produced an empty inventory"
restore_entries="$(awk 'NF && $1 !~ /^;/ { count++ } END { print count+0 }' "$postgres_list")"
[[ "$restore_entries" =~ ^[1-9][0-9]*$ ]] \
  || sp_fail "PostgreSQL dump contains no restorable entries"

printf 'Creating Redis RDB transfer with no application writers running...\n' >&2
docker exec "$redis_container" redis-cli --rdb "$redis_remote_file" >/dev/null
docker exec "$redis_container" redis-check-rdb "$redis_remote_file" \
  >"${stage_dir}/redis-check-rdb.txt"
docker cp "${redis_container}:${redis_remote_file}" "${stage_dir}/redis.rdb" >/dev/null
docker exec "$redis_container" rm -f "$redis_remote_file"
redis_remote_file=""
[[ -s "${stage_dir}/redis.rdb" ]] || sp_fail "Redis RDB backup is empty"

archive_image="$(docker inspect --format '{{.Config.Image}}' "$redis_container")"
[[ -n "$archive_image" ]] || sp_fail "Could not identify the existing Redis image for report backup"
printf 'Creating read-only report-volume archive...\n' >&2
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --volume "${report_volume}:/source:ro" \
  --volume "${stage_dir}:/backup" \
  --entrypoint tar \
  "$archive_image" \
  -C /source -czf /backup/reports.tar.gz .
[[ -s "${stage_dir}/reports.tar.gz" ]] || sp_fail "Report-volume archive is empty"
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --volume "${stage_dir}:/backup:ro" \
  --entrypoint tar \
  "$archive_image" \
  -tzf /backup/reports.tar.gz \
  >"${stage_dir}/reports.tar.list"
[[ -s "${stage_dir}/reports.tar.list" ]] || sp_fail "Report archive inventory is empty"

(
  cd "$stage_dir"
  sha256sum postgres.dump redis.rdb reports.tar.gz >SHA256SUMS
  sha256sum --check SHA256SUMS >/dev/null
)

database_identity="$(DATABASE_URL="$database_url" python3 - <<'PY'
import os
from urllib.parse import unquote, urlsplit

parsed = urlsplit(os.environ["DATABASE_URL"])
print(f"database_host={parsed.hostname or 'unknown'}")
print(f"database_port={parsed.port or 5432}")
print(f"database_name={unquote(parsed.path.lstrip('/')) or 'unknown'}")
PY
)"
current_sha="$(sp_current_release_sha "$RELEASE_ROOT")"
runtime_sha="$(sp_runtime_release_sha "$RELEASE_ROOT")"
{
  printf 'schema=securitypreflight-immutable-release-backup-1\n'
  printf 'created_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'compose_project=%s\n' "$PROJECT_NAME"
  printf 'target_release_sha=%s\n' "$TARGET_SHA"
  printf 'current_release_sha=%s\n' "${current_sha:-none}"
  printf 'runtime_release_sha=%s\n' "${runtime_sha:-none}"
  printf '%s\n' "$database_identity"
  printf 'postgres_format=custom\n'
  printf 'postgres_restore_entries=%s\n' "$restore_entries"
  printf 'postgres_dump_bytes=%s\n' "$(wc -c <"$postgres_dump" | tr -d '[:space:]')"
  printf 'redis_format=rdb\n'
  printf 'redis_dump_bytes=%s\n' "$(wc -c <"${stage_dir}/redis.rdb" | tr -d '[:space:]')"
  printf 'reports_format=tar.gz\n'
  printf 'reports_archive_bytes=%s\n' "$(wc -c <"${stage_dir}/reports.tar.gz" | tr -d '[:space:]')"
  printf 'reports_volume=%s\n' "$report_volume"
  printf 'pg_dump_version=%s\n' "$(pg_dump --version | head -n 1)"
  printf 'pg_restore_version=%s\n' "$(pg_restore --version | head -n 1)"
} >"${stage_dir}/manifest.txt"

chmod 0600 "${stage_dir}"/*
mv "$stage_dir" "$final_dir"
stage_dir=""
chmod 0700 "$final_dir"
trap - EXIT

printf '%s\n' "$final_dir"
