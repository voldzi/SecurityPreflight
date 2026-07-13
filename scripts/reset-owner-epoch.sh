#!/usr/bin/env bash
set -euo pipefail

epoch="${SECURITY_PREFLIGHT_DATA_EPOCH:-stratos-epoch-2026-01}"
project="${SECURITY_PREFLIGHT_COMPOSE_PROJECT:-security-preflight}"
phase="${SECURITY_PREFLIGHT_RESET_PHASE:-}"
execute=false

for argument in "$@"; do
  case "$argument" in
    --execute) execute=true ;;
    --) ;;
    *)
      printf 'Unknown reset argument: %s\n' "$argument" >&2
      exit 64
      ;;
  esac
done

volumes=(
  "${project}_security_preflight_postgres"
  "${project}_security_preflight_cache"
  "${project}_security_preflight_reports"
)

if [[ "$execute" != true ]]; then
  printf 'SecurityPreflight owner reset dry-run for epoch %s\n' "$epoch"
  printf 'Compose project: %s\nVolumes to remove:\n' "$project"
  printf '  %s\n' "${volumes[@]}"
  printf 'No data was changed. Execute only as an isolated G5 rehearsal or inside an approved G7 window.\n'
  exit 0
fi

case "$phase" in
  rehearsal)
    expected="RESET_SECURITY_PREFLIGHT_REHEARSAL_${epoch}"
    if [[ "${APP_ENV:-development}" == "production" ]]; then
      printf 'Refusing rehearsal against APP_ENV=production.\n' >&2
      exit 64
    fi
    if [[ "${SECURITY_PREFLIGHT_RESET_APPROVED_WINDOW:-}" != "G5" ]]; then
      printf 'Refusing rehearsal outside the G5 window.\n' >&2
      exit 64
    fi
    if [[ "${SECURITY_PREFLIGHT_REHEARSAL_ISOLATED:-}" != "true" || "$project" == "security-preflight" ]]; then
      printf 'Refusing rehearsal without an explicitly isolated non-default compose project.\n' >&2
      exit 64
    fi
    manifest="${SECURITY_PREFLIGHT_RESET_BACKUP_MANIFEST:-}"
    if [[ -z "$manifest" || ! -f "$manifest" ]]; then
      printf 'Refusing rehearsal without SECURITY_PREFLIGHT_RESET_BACKUP_MANIFEST.\n' >&2
      exit 64
    fi
    node -e '
      const manifest = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
      const valid = manifest.schemaVersion === "security-preflight-backup-verification-1"
        && typeof manifest.backupId === "string" && manifest.backupId.length > 0
        && manifest.postgresBackupVerified === true
        && manifest.redisBackupVerified === true
        && manifest.reportsBackupVerified === true;
      if (!valid) process.exit(1);
    ' "$manifest" || { printf 'Refusing rehearsal because the backup manifest is invalid.\n' >&2; exit 64; }
    ;;
  production)
    expected="RESET_SECURITY_PREFLIGHT_${epoch}"
    if [[ "${APP_ENV:-}" != "production" ]]; then
      printf 'Refusing production reset unless APP_ENV=production.\n' >&2
      exit 64
    fi
    if [[ "${SECURITY_PREFLIGHT_RESET_APPROVED_WINDOW:-}" != "G7" ]]; then
      printf 'Refusing production reset outside an approved G7 window.\n' >&2
      exit 64
    fi
    if [[ "${SECURITY_PREFLIGHT_RESET_MAINTENANCE_CONFIRMED:-}" != "true" || "${SECURITY_PREFLIGHT_RESET_APPLICATION_STOPPED:-}" != "true" ]]; then
      printf 'Refusing production reset without maintenance and stopped-application confirmation.\n' >&2
      exit 64
    fi
    IFS=',' read -r -a rehearsals <<< "${SECURITY_PREFLIGHT_RESET_REHEARSAL_EVIDENCE:-}"
    if [[ "${#rehearsals[@]}" -lt 2 || -z "${rehearsals[0]:-}" || -z "${rehearsals[1]:-}" || "${rehearsals[0]}" == "${rehearsals[1]}" ]]; then
      printf 'Refusing production reset without two distinct rehearsal evidence identifiers.\n' >&2
      exit 64
    fi
    if [[ -z "${SECURITY_PREFLIGHT_RESET_RESTORE_EVIDENCE:-}" || -z "${SECURITY_PREFLIGHT_RESET_PRODUCTION_CHANGE_ID:-}" ]]; then
      printf 'Refusing production reset without G6 restore evidence and a production change id.\n' >&2
      exit 64
    fi
    ;;
  *)
    printf 'Refusing reset. SECURITY_PREFLIGHT_RESET_PHASE must be rehearsal or production.\n' >&2
    exit 64
    ;;
esac

if [[ "${SECURITY_PREFLIGHT_RESET_CONFIRM:-}" != "$expected" ]]; then
  printf 'Refusing reset. Expected SECURITY_PREFLIGHT_RESET_CONFIRM=%s.\n' "$expected" >&2
  exit 64
fi

for volume in "${volumes[@]}"; do
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    actual_project="$(docker volume inspect "$volume" --format '{{ index .Labels "com.docker.compose.project" }}')"
    if [[ "$actual_project" != "$project" ]]; then
      printf 'Refusing to remove volume %s owned by compose project %s.\n' "$volume" "$actual_project" >&2
      exit 65
    fi
  fi
done

docker compose -p "$project" -f infra/docker-compose.yml -f infra/docker-compose.production.yml down --remove-orphans
for volume in "${volumes[@]}"; do docker volume rm "$volume" 2>/dev/null || true; done
printf '{"dataEpoch":"%s","phase":"%s","composeProject":"%s","postgresRemoved":true,"redisQueueRemoved":true,"reportStorageRemoved":true,"credentialsIncluded":false}\n' "$epoch" "$phase" "$project"
