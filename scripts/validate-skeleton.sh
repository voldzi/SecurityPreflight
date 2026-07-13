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

if [[ -x "$root/scripts/validate-docker-ipam.sh" ]]; then
  "$root/scripts/validate-docker-ipam.sh" "$root" || failures=$((failures + 1))
else
  fail "scripts/validate-docker-ipam.sh is missing or not executable"
fi

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

if grep -Eq 'security-preflight\.(viewer|operator|admin)|stratos_security_admin|stratos_superadmin' "$root/infra/keycloak/ensure-security-preflight-client.sh"; then
  fail "Keycloak provisioning contains deprecated SecurityPreflight/STRATOS realm roles"
else
  ok "Keycloak provisioning does not create deprecated realm roles"
fi

if [[ -f "$root/infra/docker-compose.yml" ]]; then
  api_environment="$(awk '/^  api:/{capture=1} /^  worker:/{capture=0} capture' "$root/infra/docker-compose.yml")"
  worker_environment="$(awk '/^  worker:/{capture=1} /^  postgres:/{capture=0} capture' "$root/infra/docker-compose.yml")"
  if grep -q 'SECURITY_PREFLIGHT_GOVERNANCE_SERVICE_TOKEN' <<<"$api_environment" \
    && ! grep -q 'SECURITY_PREFLIGHT_WORKER_SERVICE_TOKEN' <<<"$api_environment"; then
    ok "API receives only the governance service credential"
  else
    fail "API service credential boundary is missing or exposes the worker credential"
  fi
  if grep -q 'SECURITY_PREFLIGHT_WORKER_SERVICE_TOKEN' <<<"$worker_environment" \
    && ! grep -q 'SECURITY_PREFLIGHT_GOVERNANCE_SERVICE_TOKEN' <<<"$worker_environment" \
    && ! grep -q 'SECURITY_PREFLIGHT_POLICY_REGISTRY_URL' <<<"$worker_environment" \
    && ! grep -q 'SECURITY_PREFLIGHT_SCOPE_REGISTRY_URL' <<<"$worker_environment"; then
    ok "worker receives only the runtime decision credential and endpoint"
  else
    fail "worker service credential boundary exposes Registry configuration"
  fi
fi

retired_credential_references="$(grep -Rl --exclude='*.test.ts' --exclude='*.integration.test.ts' --exclude='validate-skeleton.sh' 'SECURITY_PREFLIGHT_POLICY_SERVICE_TOKEN' \
  "$root/.env.example" "$root/apps" "$root/infra" "$root/packages" "$root/scripts" 2>/dev/null || true)"
unexpected_retired_references="$(grep -Ev '/apps/api/src/server\.ts$|/apps/worker/src/governance-config\.ts$' <<<"$retired_credential_references" || true)"
if [[ -n "$unexpected_retired_references" ]]; then
  fail "runtime sources still accept or expose the retired shared policy service credential"
else
  ok "retired shared credential appears only in fail-closed rejection guards"
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
