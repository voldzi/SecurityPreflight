#!/usr/bin/env bash
set -euo pipefail

epoch="${SECURITY_PREFLIGHT_DATA_EPOCH:-stratos-epoch-2026-01}"
expected="RESET_SECURITY_PREFLIGHT_${epoch}"
project="${SECURITY_PREFLIGHT_COMPOSE_PROJECT:-security-preflight}"
execute=false

if [[ "${1:-}" == "--execute" ]]; then execute=true; fi

volumes=(
  "${project}_security_preflight_postgres"
  "${project}_security_preflight_cache"
  "${project}_security_preflight_reports"
)

if [[ "$execute" != true ]]; then
  printf 'SecurityPreflight owner reset dry-run for epoch %s\n' "$epoch"
  printf 'Compose project: %s\nVolumes to remove:\n' "$project"
  printf '  %s\n' "${volumes[@]}"
  printf 'No data was changed. Execute only in an approved G7 window with --execute and SECURITY_PREFLIGHT_RESET_CONFIRM=%s.\n' "$expected"
  exit 0
fi

if [[ "${SECURITY_PREFLIGHT_RESET_CONFIRM:-}" != "$expected" ]]; then
  printf 'Refusing reset. Expected SECURITY_PREFLIGHT_RESET_CONFIRM=%s.\n' "$expected" >&2
  exit 64
fi

if [[ "${SECURITY_PREFLIGHT_RESET_APPROVED_WINDOW:-}" != "G7" ]]; then
  printf 'Refusing reset outside an approved G7 window.\n' >&2
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
printf '{"dataEpoch":"%s","composeProject":"%s","postgresRemoved":true,"redisQueueRemoved":true,"reportStorageRemoved":true,"credentialsIncluded":false}\n' "$epoch" "$project"
