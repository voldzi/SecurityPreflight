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
GIT_DIR="${SECURITY_PREFLIGHT_RELEASE_GIT_DIR:-${RELEASE_ROOT}/git/SecurityPreflight.git}"
PROJECT_NAME="securitypreflight"
DEPLOYMENTS_DIR="${RELEASE_ROOT}/deployments"
BACKUPS_DIR="${RELEASE_ROOT}/backups"
DEPLOYMENT_ID="$(date -u +%Y%m%dT%H%M%SZ)-${TARGET_SHA}-$$"
DEPLOYMENT_DIR="${DEPLOYMENTS_DIR}/${DEPLOYMENT_ID}"
DEPLOYMENT_RECORD="${DEPLOYMENT_DIR}/record.txt"
IMAGE_MANIFEST="${DEPLOYMENT_DIR}/images.txt"
IMAGE_OVERRIDE="${DEPLOYMENT_DIR}/compose.images.yml"
BACKUP_DIR="none"
WRITERS_STOPPED="false"
START_ATTEMPTED="false"
OLD_WRITERS_RESTARTED="false"
declare -a OLD_WRITER_IDS=()

for command_name in curl docker git pg_dump pg_restore psql python3 sha256sum tar; do
  sp_require_command "$command_name"
done
sp_require_private_env_file "$ENV_FILE"
sp_validate_production_env "$ENV_FILE"

umask 077
mkdir -p "$RELEASE_ROOT" "${RELEASE_ROOT}/git" "${RELEASE_ROOT}/releases" "$DEPLOYMENTS_DIR"
sp_prepare_private_directory "$BACKUPS_DIR"
sp_prepare_private_directory "$DEPLOYMENTS_DIR"
sp_acquire_deploy_lock "$RELEASE_ROOT"
mkdir "$DEPLOYMENT_DIR"
chmod 0700 "$DEPLOYMENT_DIR"

write_deployment_record() {
  local deployment_status="$1"
  local temporary="${DEPLOYMENT_RECORD}.$$.tmp"
  {
    printf 'schema=securitypreflight-immutable-deployment-1\n'
    printf 'deployment_id=%s\n' "$DEPLOYMENT_ID"
    printf 'status=%s\n' "$deployment_status"
    printf 'compose_project=%s\n' "$PROJECT_NAME"
    printf 'target_sha=%s\n' "$TARGET_SHA"
    printf 'backup_dir=%s\n' "$BACKUP_DIR"
    printf 'writers_stopped=%s\n' "$WRITERS_STOPPED"
    printf 'start_attempted=%s\n' "$START_ATTEMPTED"
    printf 'old_writers_restarted=%s\n' "$OLD_WRITERS_RESTARTED"
    printf 'recorded_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$DEPLOYMENT_RECORD"
}

on_exit() {
  local status=$?
  trap - EXIT
  set +e
  if [[ $status -ne 0 ]]; then
    if [[ "$START_ATTEMPTED" == "true" ]]; then
      sp_write_runtime_release_sha "$RELEASE_ROOT" "$TARGET_SHA"
      printf 'Target startup was attempted. Do not restore old code or downgrade data; deploy a reviewed forward-fix SHA.\n' >&2
    elif [[ "$WRITERS_STOPPED" == "true" && ${#OLD_WRITER_IDS[@]} -gt 0 ]]; then
      if docker start "${OLD_WRITER_IDS[@]}" >/dev/null; then
        OLD_WRITERS_RESTARTED="true"
        printf 'Pre-upgrade failure: the unchanged previous writer containers were restarted.\n' >&2
      else
        printf 'WARNING: previous writer containers could not be restarted automatically.\n' >&2
      fi
    fi
    write_deployment_record failed
    printf 'Deployment failed; current was not advanced.\n' >&2
  fi
  sp_release_deploy_lock
  exit "$status"
}
trap on_exit EXIT

write_deployment_record preparing
release_dir="$(
  SECURITY_PREFLIGHT_RELEASE_ROOT="$RELEASE_ROOT" \
  SECURITY_PREFLIGHT_PROD_ENV_FILE="$ENV_FILE" \
  SECURITY_PREFLIGHT_RELEASE_GIT_DIR="$GIT_DIR" \
    "${SCRIPT_DIR}/prepare-docker-home-release.sh" --sha "$TARGET_SHA"
)"
[[ "$release_dir" == "${RELEASE_ROOT}/releases/${TARGET_SHA}" ]] \
  || sp_fail "Release preparation returned an unexpected directory"
for release_script in backup-docker-home-release.sh verify-docker-home-release.sh; do
  sp_require_file "${release_dir}/scripts/${release_script}"
done

current_sha="$(sp_current_release_sha "$RELEASE_ROOT")"
runtime_sha="$(sp_runtime_release_sha "$RELEASE_ROOT")"
if [[ -n "$runtime_sha" && -n "$current_sha" && "$runtime_sha" != "$current_sha" ]]; then
  git --git-dir="$GIT_DIR" merge-base --is-ancestor "$current_sha" "$runtime_sha" \
    || sp_fail "Recorded runtime SHA does not descend from current; manual review is required"
fi
baseline_sha="${runtime_sha:-$current_sha}"
if [[ -n "$baseline_sha" && "$baseline_sha" != "$TARGET_SHA" ]]; then
  git --git-dir="$GIT_DIR" merge-base --is-ancestor "$baseline_sha" "$TARGET_SHA" \
    || sp_fail "Production release must move forward from the recorded runtime SHA"
fi
if [[ "$current_sha" == "$TARGET_SHA" && "$runtime_sha" == "$TARGET_SHA" ]]; then
  sp_fail "Target SHA is already current and running"
fi

cd "$release_dir"
BASE_COMPOSE="${release_dir}/infra/docker-compose.yml"
PRODUCTION_COMPOSE="${release_dir}/infra/docker-compose.production.yml"
sp_require_file "$BASE_COMPOSE"
sp_require_file "$PRODUCTION_COMPOSE"
BUILD_COMPOSE=(
  docker compose
  --project-name "$PROJECT_NAME"
  --env-file "$ENV_FILE"
  -f "$BASE_COMPOSE"
  -f "$PRODUCTION_COMPOSE"
)

printf 'Rendering target Compose configuration with explicit project %s...\n' "$PROJECT_NAME"
"${BUILD_COMPOSE[@]}" config --quiet

write_deployment_record building
printf 'Building the exact target release before maintenance begins...\n'
DOCKER_BUILDKIT=1 "${BUILD_COMPOSE[@]}" --profile build-support build scanner-runtime
DOCKER_BUILDKIT=1 "${BUILD_COMPOSE[@]}" build web api worker scanner-toolbox

source_image_for_service() {
  case "$1" in
    web|api|worker)
      printf '%s-%s\n' "$PROJECT_NAME" "$1"
      ;;
    scanner-toolbox)
      printf 'security-preflight/scanner-toolbox:local\n'
      ;;
    scanner-runtime)
      printf 'security-preflight/scanner-runtime:local\n'
      ;;
    *)
      sp_fail "Unsupported release image service: $1"
      ;;
  esac
}

tag_exact_release_image() {
  local service="$1"
  local source_image
  local source_id
  local exact_tag
  local existing_id
  source_image="$(source_image_for_service "$service")"
  source_id="$(docker image inspect --format '{{.Id}}' "$source_image")"
  [[ "$source_id" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || sp_fail "Built image id is invalid for $service"
  exact_tag="security-preflight/release-${service}:${TARGET_SHA}"
  existing_id="$(docker image inspect --format '{{.Id}}' "$exact_tag" 2>/dev/null || true)"
  if [[ -n "$existing_id" && "$existing_id" != "$source_id" ]]; then
    sp_fail "Exact release image tag collision for $service at $TARGET_SHA"
  fi
  docker image tag "$source_id" "$exact_tag"
  printf '%s=%s\n' "$service" "$source_id" >>"$IMAGE_MANIFEST"
}

: >"$IMAGE_MANIFEST"
for service in scanner-runtime web api worker scanner-toolbox; do
  tag_exact_release_image "$service"
done
chmod 0600 "$IMAGE_MANIFEST"

{
  printf 'services:\n'
  for service in web api worker scanner-toolbox; do
    printf '  %s:\n' "$service"
    printf '    image: security-preflight/release-%s:%s\n' "$service" "$TARGET_SHA"
  done
} >"$IMAGE_OVERRIDE"
chmod 0600 "$IMAGE_OVERRIDE"

RUNTIME_COMPOSE=(
  "${BUILD_COMPOSE[@]}"
  -f "$IMAGE_OVERRIDE"
)
"${RUNTIME_COMPOSE[@]}" config --quiet

for writer in api worker; do
  writer_id="$("${BUILD_COMPOSE[@]}" ps --status running -q "$writer")"
  [[ -n "$writer_id" && "$(printf '%s\n' "$writer_id" | wc -l | tr -d '[:space:]')" == "1" ]] \
    || sp_fail "Existing production writer is not running exactly once: $writer"
  OLD_WRITER_IDS+=("$writer_id")
done
for data_service in postgres redis; do
  data_id="$("${BUILD_COMPOSE[@]}" ps --status running -q "$data_service")"
  [[ -n "$data_id" && "$(printf '%s\n' "$data_id" | wc -l | tr -d '[:space:]')" == "1" ]] \
    || sp_fail "Existing production data service is not running exactly once: $data_service"
done

write_deployment_record maintenance
printf 'Build complete. Entering maintenance and stopping API/worker writers...\n'
WRITERS_STOPPED="true"
docker stop --time 60 "${OLD_WRITER_IDS[0]}" >/dev/null
docker stop --time 120 "${OLD_WRITER_IDS[1]}" >/dev/null
for writer_id in "${OLD_WRITER_IDS[@]}"; do
  [[ "$(docker inspect --format '{{.State.Running}}' "$writer_id")" == "false" ]] \
    || sp_fail "Writer container did not stop cleanly: $writer_id"
done
write_deployment_record backing_up

BACKUP_DIR="$(
  SECURITY_PREFLIGHT_RELEASE_ROOT="$RELEASE_ROOT" \
  SECURITY_PREFLIGHT_PROD_ENV_FILE="$ENV_FILE" \
    "${release_dir}/scripts/backup-docker-home-release.sh" --sha "$TARGET_SHA"
)"
[[ "$BACKUP_DIR" == "${BACKUPS_DIR}/"* && -d "$BACKUP_DIR" ]] \
  || sp_fail "Verified backups were not written below $BACKUPS_DIR"
write_deployment_record backed_up

START_ATTEMPTED="true"
write_deployment_record starting
printf 'Starting target release forward-only with prebuilt exact-SHA images...\n'
"${RUNTIME_COMPOSE[@]}" up -d --no-build
sp_write_runtime_release_sha "$RELEASE_ROOT" "$TARGET_SHA"

write_deployment_record verifying
SECURITY_PREFLIGHT_RELEASE_ROOT="$RELEASE_ROOT" \
SECURITY_PREFLIGHT_PROD_ENV_FILE="$ENV_FILE" \
  "${release_dir}/scripts/verify-docker-home-release.sh" \
    --sha "$TARGET_SHA" \
    --image-manifest "$IMAGE_MANIFEST" \
    --compose-override "$IMAGE_OVERRIDE"

sp_atomic_current_symlink "$RELEASE_ROOT" "$release_dir"
WRITERS_STOPPED="false"
write_deployment_record succeeded
printf 'Immutable SecurityPreflight release is current: %s\n' "$release_dir"

trap - EXIT
sp_release_deploy_lock
