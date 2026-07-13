#!/usr/bin/env bash
# shellcheck shell=bash

sp_fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

sp_require_command() {
  command -v "$1" >/dev/null 2>&1 || sp_fail "Required command not found: $1"
}

sp_require_file() {
  [[ -f "$1" ]] || sp_fail "Required file not found: $1"
}

sp_validate_full_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] \
    || sp_fail "Git SHA must be the full 40-character lowercase commit id"
}

sp_env_value() {
  local env_file="$1"
  local key="$2"
  local default_value="${3-}"

  python3 - "$env_file" "$key" "$default_value" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
key = sys.argv[2]
default = sys.argv[3]
value = None
for raw_line in path.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    candidate, raw_value = line.split("=", 1)
    if candidate.strip() == key:
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]

print(default if value is None else value)
PY
}

sp_require_private_env_file() {
  local env_file="$1"
  python3 - "$env_file" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
try:
    info = os.lstat(path)
except FileNotFoundError as exc:
    raise SystemExit(f"Production env file does not exist: {path}") from exc
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
    raise SystemExit(f"Production env file must be a regular non-symlink file: {path}")
mode = stat.S_IMODE(info.st_mode)
if mode != 0o600:
    raise SystemExit(f"Production env file must have mode 0600: {path} mode={mode:04o}")
PY
}

sp_prepare_private_directory() {
  local directory="$1"
  python3 - "$directory" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
try:
    info = os.lstat(path)
except FileNotFoundError:
    os.mkdir(path, 0o700)
    info = os.lstat(path)
if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
    raise SystemExit(f"Private path must be a non-symlink directory: {path}")
os.chmod(path, 0o700)
mode = stat.S_IMODE(os.lstat(path).st_mode)
if mode != 0o700:
    raise SystemExit(f"Private directory must have mode 0700: {path} mode={mode:04o}")
PY
}

sp_validate_production_env() {
  local env_file="$1"
  python3 - "$env_file" <<'PY'
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

values: dict[str, str] = {}
for raw_line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    values[key.strip()] = value

def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)

require(values.get("APP_ENV") == "production", "Persistent .env must set APP_ENV=production")
require(
    values.get("SECURITY_PREFLIGHT_AUTH_MODE", "") in {"", "oidc"},
    "Production immutable deployment permits only OIDC authentication",
)
require(
    values.get("SECURITY_PREFLIGHT_DB_REQUIRED", "").lower() == "true",
    "Persistent .env must set SECURITY_PREFLIGHT_DB_REQUIRED=true",
)

database_url = values.get("DATABASE_URL", "")
parsed_database = urlsplit(database_url)
require(parsed_database.scheme in {"postgres", "postgresql"}, "DATABASE_URL must use PostgreSQL")
require(parsed_database.hostname == "haproxy.home.cz", "DATABASE_URL must use haproxy.home.cz")
require((parsed_database.port or 5432) == 5000, "DATABASE_URL must use HAProxy port 5000")
require(bool(parsed_database.username), "DATABASE_URL must include a runtime database user")
require(bool(parsed_database.password), "DATABASE_URL must include a runtime database password")
require(bool(unquote(parsed_database.path.lstrip("/"))), "DATABASE_URL must include a database name")

public_url = values.get("NEXT_PUBLIC_SECURITY_PREFLIGHT_PUBLIC_BASE_URL", "")
require(public_url.startswith("https://"), "Public SecurityPreflight URL must use HTTPS")
projects_root = values.get("PROJECTS_ROOT_HOST", "")
require(projects_root.startswith("/"), "PROJECTS_ROOT_HOST must be an absolute production path")

placeholder_pattern = re.compile(
    r"(?:replace[-_ ]?with|change[-_ ]?me|<[^>]*(?:password|secret|token|user)[^>]*>|"
    r"example[-_ ]?(?:password|secret|token)|long[-_ ]?random)",
    re.IGNORECASE,
)
for key, value in values.items():
    if placeholder_pattern.search(value):
        raise SystemExit(f"Persistent .env contains a placeholder value for {key}")
PY
}

sp_release_manifest_value() {
  local manifest="$1"
  local key="$2"
  awk -F= -v expected="$key" '$1 == expected { print substr($0, index($0, "=") + 1); found=1 } END { if (!found) exit 1 }' "$manifest"
}

sp_verify_release_tree() {
  local git_dir="$1"
  local sha="$2"
  local release_dir="$3"

  sp_validate_full_sha "$sha"
  python3 - "$git_dir" "$sha" "$release_dir" <<'PY'
import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path

git_dir, sha, raw_release_dir = sys.argv[1:]
release_dir = Path(raw_release_dir)
metadata_names = {
    ".securitypreflight-release-manifest",
    ".securitypreflight-release-sha",
}

raw_tree = subprocess.check_output(
    ["git", f"--git-dir={git_dir}", "ls-tree", "-r", "-z", sha]
)
expected: dict[str, tuple[str, str]] = {}
for record in raw_tree.split(b"\0"):
    if not record:
        continue
    metadata, raw_path = record.split(b"\t", 1)
    mode, object_type, object_id = metadata.decode("ascii").split()
    if object_type != "blob":
        raise SystemExit(f"unsupported Git object in release tree: {object_type}")
    expected[os.fsdecode(raw_path)] = (mode, object_id)

actual: set[str] = set()
for root, directory_names, file_names in os.walk(release_dir, followlinks=False):
    root_path = Path(root)
    for name in list(directory_names):
        candidate = root_path / name
        if candidate.is_symlink():
            actual.add(candidate.relative_to(release_dir).as_posix())
            directory_names.remove(name)
    for name in file_names:
        if root_path == release_dir and name in metadata_names:
            continue
        actual.add((root_path / name).relative_to(release_dir).as_posix())

if actual != set(expected):
    missing = sorted(set(expected) - actual)
    extra = sorted(actual - set(expected))
    raise SystemExit(
        f"release tree path mismatch; missing={missing[:5]} extra={extra[:5]}"
    )

for relative_path, (mode, object_id) in expected.items():
    candidate = release_dir / relative_path
    file_stat = candidate.lstat()
    if mode == "120000":
        if not stat.S_ISLNK(file_stat.st_mode):
            raise SystemExit(f"expected symlink in release tree: {relative_path}")
        content = os.fsencode(os.readlink(candidate))
    elif mode in {"100644", "100755"}:
        if not stat.S_ISREG(file_stat.st_mode):
            raise SystemExit(f"expected regular file in release tree: {relative_path}")
        content = candidate.read_bytes()
        executable = bool(file_stat.st_mode & stat.S_IXUSR)
        if executable != (mode == "100755"):
            raise SystemExit(f"executable mode mismatch in release tree: {relative_path}")
    else:
        raise SystemExit(f"unsupported Git mode in release tree: {mode}")
    digest = hashlib.sha1(
        f"blob {len(content)}\0".encode("ascii") + content,
        usedforsecurity=False,
    ).hexdigest()
    if digest != object_id:
        raise SystemExit(f"content mismatch in release tree: {relative_path}")
PY
}

sp_require_immutable_tree() {
  local release_dir="$1"
  python3 - "$release_dir" <<'PY'
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
for candidate in [root, *root.rglob("*")]:
    info = candidate.lstat()
    if not stat.S_ISLNK(info.st_mode) and stat.S_IMODE(info.st_mode) & 0o222:
        raise SystemExit(f"Release path is writable: {candidate}")
PY
}

sp_current_release_sha() {
  local release_root="$1"
  local current_link="${release_root}/current"

  if [[ ! -e "$current_link" && ! -L "$current_link" ]]; then
    return 0
  fi
  [[ -L "$current_link" ]] || sp_fail "${current_link} must be a symlink"

  local target
  target="$(python3 - "$current_link" <<'PY'
import os
import sys
print(os.path.realpath(sys.argv[1]))
PY
)"
  case "$target" in
    "${release_root}/releases/"*) ;;
    *) sp_fail "current symlink points outside ${release_root}/releases" ;;
  esac

  local sha
  sha="$(basename "$target")"
  sp_validate_full_sha "$sha"
  sp_require_file "${target}/.securitypreflight-release-sha"
  [[ "$(tr -d '[:space:]' <"${target}/.securitypreflight-release-sha")" == "$sha" ]] \
    || sp_fail "current release directory does not match its SHA marker"
  printf '%s\n' "$sha"
}

sp_runtime_release_sha() {
  local release_root="$1"
  local marker="${release_root}/runtime-sha"
  [[ -e "$marker" ]] || return 0
  [[ -f "$marker" && ! -L "$marker" ]] || sp_fail "runtime-sha must be a regular file"
  local sha
  sha="$(tr -d '[:space:]' <"$marker")"
  sp_validate_full_sha "$sha"
  printf '%s\n' "$sha"
}

sp_write_runtime_release_sha() {
  local release_root="$1"
  local sha="$2"
  local temporary="${release_root}/.runtime-sha.$$.tmp"
  sp_validate_full_sha "$sha"
  printf '%s\n' "$sha" >"$temporary"
  chmod 0600 "$temporary"
  python3 - "$temporary" "${release_root}/runtime-sha" <<'PY'
import os
import sys
os.replace(sys.argv[1], sys.argv[2])
PY
}

sp_atomic_current_symlink() {
  local release_root="$1"
  local release_dir="$2"
  local temporary_link="${release_root}/.current.$$.tmp"
  local current_link="${release_root}/current"

  case "$release_dir" in
    "${release_root}/releases/"*) ;;
    *) sp_fail "Refusing to activate a release outside ${release_root}/releases" ;;
  esac
  local release_sha
  release_sha="$(basename "$release_dir")"
  sp_validate_full_sha "$release_sha"
  sp_require_file "${release_dir}/.securitypreflight-release-sha"
  [[ "$(tr -d '[:space:]' <"${release_dir}/.securitypreflight-release-sha")" == "$release_sha" ]] \
    || sp_fail "Release directory and Git SHA marker do not match"

  rm -f "$temporary_link"
  ln -s "$release_dir" "$temporary_link"
  python3 - "$temporary_link" "$current_link" <<'PY'
import os
import sys
os.replace(sys.argv[1], sys.argv[2])
PY
}

sp_acquire_deploy_lock() {
  local release_root="$1"
  local lock_dir="${release_root}/.immutable-deploy.lock"
  if ! mkdir "$lock_dir" 2>/dev/null; then
    sp_fail "Another immutable deployment may be active: $lock_dir"
  fi
  chmod 0700 "$lock_dir"
  printf 'pid=%s\nhost=%s\nstarted_utc=%s\n' \
    "$$" "$(hostname)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"${lock_dir}/owner"
  chmod 0600 "${lock_dir}/owner"
  SECURITY_PREFLIGHT_DEPLOY_LOCK_DIR="$lock_dir"
}

sp_release_deploy_lock() {
  if [[ -n "${SECURITY_PREFLIGHT_DEPLOY_LOCK_DIR:-}" && -d "${SECURITY_PREFLIGHT_DEPLOY_LOCK_DIR}" ]]; then
    rm -f "${SECURITY_PREFLIGHT_DEPLOY_LOCK_DIR}/owner"
    rmdir "${SECURITY_PREFLIGHT_DEPLOY_LOCK_DIR}"
  fi
}
