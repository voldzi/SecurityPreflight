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
RELEASES_DIR="${RELEASE_ROOT}/releases"
GIT_DIR="${SECURITY_PREFLIGHT_RELEASE_GIT_DIR:-${RELEASE_ROOT}/git/SecurityPreflight.git}"

for command_name in git python3 sha256sum tar; do
  sp_require_command "$command_name"
done
sp_require_private_env_file "$ENV_FILE"

GIT_URL="${SECURITY_PREFLIGHT_RELEASE_GIT_URL:-$(sp_env_value "$ENV_FILE" SECURITY_PREFLIGHT_RELEASE_GIT_URL https://github.com/voldzi/SecurityPreflight.git)}"
TRUSTED_REF="${SECURITY_PREFLIGHT_RELEASE_TRUSTED_REF:-$(sp_env_value "$ENV_FILE" SECURITY_PREFLIGHT_RELEASE_TRUSTED_REF refs/remotes/origin/main)}"
[[ -n "$GIT_URL" ]] || sp_fail "SECURITY_PREFLIGHT_RELEASE_GIT_URL is empty"
[[ "$TRUSTED_REF" == refs/remotes/origin/* ]] \
  || sp_fail "Trusted release ref must be an origin remote-tracking ref"

umask 077
mkdir -p "$RELEASE_ROOT" "$RELEASES_DIR" "$(dirname "$GIT_DIR")"

clone_tmp=""
stage_parent=""
release_lock="${RELEASES_DIR}/.${TARGET_SHA}.prepare.lock"
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$clone_tmp" && -d "$clone_tmp" ]]; then
    rm -rf "$clone_tmp"
  fi
  if [[ -n "$stage_parent" && -d "$stage_parent" ]]; then
    chmod -R u+w "$stage_parent" 2>/dev/null || true
    rm -rf "$stage_parent"
  fi
  if [[ -d "$release_lock" ]]; then
    rmdir "$release_lock"
  fi
  exit "$status"
}
trap cleanup EXIT

if [[ ! -d "$GIT_DIR" ]]; then
  clone_tmp="${GIT_DIR}.tmp.$$"
  [[ ! -e "$clone_tmp" ]] || sp_fail "Temporary Git mirror path already exists: $clone_tmp"
  git clone --bare --no-local "$GIT_URL" "$clone_tmp"
  mv "$clone_tmp" "$GIT_DIR"
  clone_tmp=""
fi

[[ "$(git --git-dir="$GIT_DIR" rev-parse --is-bare-repository)" == "true" ]] \
  || sp_fail "Release Git directory is not bare: $GIT_DIR"
[[ "$(git --git-dir="$GIT_DIR" remote get-url origin)" == "$GIT_URL" ]] \
  || sp_fail "Release Git origin does not match the configured URL"

git --git-dir="$GIT_DIR" fetch --prune origin \
  '+refs/heads/*:refs/remotes/origin/*' \
  '+refs/tags/*:refs/tags/*'

resolved_sha="$(git --git-dir="$GIT_DIR" rev-parse --verify "${TARGET_SHA}^{commit}")"
[[ "$resolved_sha" == "$TARGET_SHA" ]] || sp_fail "Requested SHA did not resolve exactly"
git --git-dir="$GIT_DIR" show-ref --verify --quiet "$TRUSTED_REF" \
  || sp_fail "Trusted release ref is missing after fetch: $TRUSTED_REF"
git --git-dir="$GIT_DIR" merge-base --is-ancestor "$TARGET_SHA" "$TRUSTED_REF" \
  || sp_fail "Requested SHA is not reachable from $TRUSTED_REF"

if git --git-dir="$GIT_DIR" ls-tree -r "$TARGET_SHA" \
  | awk '$1 == "160000" { found=1 } END { exit !found }'; then
  sp_fail "Release commits containing Git submodules are not supported"
fi

if ! mkdir "$release_lock" 2>/dev/null; then
  sp_fail "Another preparation may be active for ${TARGET_SHA}"
fi
chmod 0700 "$release_lock"

stage_parent="$(mktemp -d "${RELEASES_DIR}/.${TARGET_SHA}.tmp.XXXXXX")"
archive_file="${stage_parent}/release.tar"
archive_checksum_file="${stage_parent}/release.tar.sha256"
release_stage="${stage_parent}/tree"
mkdir "$release_stage"

git --git-dir="$GIT_DIR" archive --format=tar --output="$archive_file" "$TARGET_SHA"
[[ -s "$archive_file" ]] || sp_fail "git archive produced an empty release archive"
(
  cd "$stage_parent"
  sha256sum release.tar >release.tar.sha256
  sha256sum --check release.tar.sha256 >/dev/null
)
archive_sha="$(awk '{print $1}' "$archive_checksum_file")"
[[ "$archive_sha" =~ ^[0-9a-f]{64}$ ]] || sp_fail "Release archive SHA-256 is invalid"

release_dir="${RELEASES_DIR}/${TARGET_SHA}"
if [[ -e "$release_dir" ]]; then
  [[ -d "$release_dir" && ! -L "$release_dir" ]] \
    || sp_fail "Existing release path is not a regular directory: $release_dir"
  sp_require_file "${release_dir}/.securitypreflight-release-sha"
  sp_require_file "${release_dir}/.securitypreflight-release-manifest"
  [[ "$(tr -d '[:space:]' <"${release_dir}/.securitypreflight-release-sha")" == "$TARGET_SHA" ]] \
    || sp_fail "Existing release marker does not match directory SHA"
  stored_archive_sha="$(sp_release_manifest_value "${release_dir}/.securitypreflight-release-manifest" archive_sha256)"
  [[ "$stored_archive_sha" == "$archive_sha" ]] \
    || sp_fail "Existing release collides with a different archive SHA-256"
  sp_require_immutable_tree "$release_dir"
  sp_verify_release_tree "$GIT_DIR" "$TARGET_SHA" "$release_dir"
  rm -rf "$stage_parent"
  stage_parent=""
  rmdir "$release_lock"
  trap - EXIT
  printf '%s\n' "$release_dir"
  exit 0
fi

tar -xf "$archive_file" -C "$release_stage"
python3 - "$release_stage" <<'PY'
import os
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
for candidate in root.rglob("*"):
    if not candidate.is_symlink():
        continue
    target = (candidate.parent / os.readlink(candidate)).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise SystemExit(f"Release contains an escaping symlink: {candidate}") from exc
PY

printf '%s\n' "$TARGET_SHA" >"${release_stage}/.securitypreflight-release-sha"
{
  printf 'git_sha=%s\n' "$TARGET_SHA"
  printf 'trusted_ref=%s\n' "$TRUSTED_REF"
  printf 'archive_sha256=%s\n' "$archive_sha"
  printf 'prepared_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"${release_stage}/.securitypreflight-release-manifest"

sp_verify_release_tree "$GIT_DIR" "$TARGET_SHA" "$release_stage"
chmod -R a-w "$release_stage"
# Keep only the staging root owner-writable until its atomic rename. Some
# platforms reject renaming a non-writable source directory even when both
# parents are writable; all archived contents are already read-only here.
chmod u+w "$release_stage"
[[ ! -e "$release_dir" ]] || sp_fail "Release path appeared during preparation: $release_dir"
mv "$release_stage" "$release_dir"
chmod a-w "$release_dir"
rm -rf "$stage_parent"
stage_parent=""
rmdir "$release_lock"
trap - EXIT

printf '%s\n' "$release_dir"
