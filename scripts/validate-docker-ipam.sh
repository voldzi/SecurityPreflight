#!/usr/bin/env bash
# Verifies that SecurityPreflight Docker IPAM defaults never use local LAN
# ranges that are routed on docker.home.cz/dmz.home.cz.
set -euo pipefail

root="${1:-.}"
failures=0

ok() { echo "ok:   $*"; }
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}

checked_files=(
  ".env.example"
  "docker-compose.yml"
  "infra/docker-compose.yml"
  "infra/docker-compose.production.yml"
)

for file in "${checked_files[@]}"; do
  [[ -f "$root/$file" ]] || continue
  if grep -En '192\.168\.(1|10|100|200)\.' "$root/$file" >/dev/null; then
    fail "$file references forbidden LAN Docker IPAM range 192.168.1/10/100/200"
  else
    ok "$file avoids forbidden LAN Docker IPAM ranges"
  fi
done

if [[ -f "$root/infra/docker-compose.yml" ]]; then
  if grep -q 'SECURITY_PREFLIGHT_DOCKER_SUBNET:-10.246.250.0/24' "$root/infra/docker-compose.yml"; then
    ok "infra/docker-compose.yml keeps safe default subnet 10.246.250.0/24"
  else
    fail "infra/docker-compose.yml must keep SECURITY_PREFLIGHT_DOCKER_SUBNET default at 10.246.250.0/24"
  fi

  if grep -q 'SECURITY_PREFLIGHT_DOCKER_GATEWAY:-10.246.250.1' "$root/infra/docker-compose.yml"; then
    ok "infra/docker-compose.yml keeps safe default gateway 10.246.250.1"
  else
    fail "infra/docker-compose.yml must keep SECURITY_PREFLIGHT_DOCKER_GATEWAY default at 10.246.250.1"
  fi
fi

echo
if [[ "$failures" -gt 0 ]]; then
  echo "Docker IPAM validation failed: $failures problem(s)."
  exit 1
fi
echo "Docker IPAM validation passed."
