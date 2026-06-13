#!/usr/bin/env bash
# Validates the application skeleton required by the central standards
# (chromadb tooling repo, docs/standards/). File-level checks only;
# runtime requirements are covered by tests.
set -euo pipefail

root="${1:-.}"
failures=0

ok() { echo "ok:   $*"; }
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}

require_file() {
  if [[ -f "$root/$1" ]]; then
    ok "$1 exists"
  else
    fail "$1 is missing"
  fi
}

require_dir() {
  if [[ -d "$root/$1" ]]; then
    ok "$1/ exists"
  else
    fail "$1/ is missing"
  fi
}

required_files=(
  README.md
  AGENTS.md
  CLAUDE.md
  .env.example
  docs/README.md
  docs/architecture.md
  docs/api.md
  docs/security.md
  docs/operations.md
  docs/observability.md
  docs/runbook.md
)

for f in "${required_files[@]}"; do
  require_file "$f"
done
require_dir docs/adr

# CLAUDE.md must equal AGENTS.md apart from its trailing Compact Instructions
# section (blank lines ignored). Intentional platform-specific differences
# require adapting this check via an ADR.
strip_compact() {
  sed '/^## Compact Instructions$/,$d' "$1" | grep -v '^[[:space:]]*$' || true
}
if [[ -f "$root/AGENTS.md" && -f "$root/CLAUDE.md" ]]; then
  if diff <(strip_compact "$root/CLAUDE.md") <(grep -v '^[[:space:]]*$' "$root/AGENTS.md" || true) >/dev/null 2>&1; then
    ok "AGENTS.md and CLAUDE.md are aligned"
  else
    fail "AGENTS.md and CLAUDE.md differ beyond the Compact Instructions section"
  fi
fi

no_api_marker="does not provide a REST API"

if [[ ! -f "$root/openapi/openapi.json" ]]; then
  if [[ -f "$root/docs/api.md" ]] && grep -q "$no_api_marker" "$root/docs/api.md"; then
    ok "no openapi/openapi.json and docs/api.md declares no REST API"
  else
    fail "openapi/openapi.json is missing and docs/api.md does not declare that the app provides no REST API"
  fi
else
  require_file openapi/README.md

  if [[ -f "$root/openapi/openapi.json" ]]; then
    if python3 -m json.tool "$root/openapi/openapi.json" >/dev/null 2>&1; then
      ok "openapi/openapi.json is valid JSON"
    else
      fail "openapi/openapi.json is not valid JSON"
    fi
  fi

  if [[ -f "$root/docs/api.md" ]]; then
    if grep -q "openapi/openapi.json" "$root/docs/api.md"; then
      ok "docs/api.md references openapi/openapi.json"
    else
      fail "docs/api.md does not reference openapi/openapi.json"
    fi
  fi

  if [[ -f "$root/openapi/openapi.yaml" ]]; then
    if head -n 2 "$root/openapi/openapi.yaml" | grep -q "generated from openapi/openapi.json"; then
      ok "openapi/openapi.yaml is marked as generated"
    else
      fail "openapi/openapi.yaml exists but is not marked as generated from openapi/openapi.json"
    fi
  fi
fi

echo
if [[ "$failures" -gt 0 ]]; then
  echo "Skeleton validation failed: $failures problem(s)."
  exit 1
fi
echo "Skeleton validation passed."
