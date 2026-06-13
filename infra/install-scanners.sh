#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  git \
  jq \
  python3 \
  python3-pip \
  pipx \
  tar \
  unzip
rm -rf /var/lib/apt/lists/*

arch="$(dpkg --print-architecture)"
case "${arch}" in
  amd64)
    gitleaks_arch="x64"
    osv_arch="amd64"
    ;;
  arm64)
    gitleaks_arch="arm64"
    osv_arch="arm64"
    ;;
  *) echo "Unsupported scanner architecture: ${arch}" >&2; exit 1 ;;
esac

gitleaks_version="$(curl -sSfL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r '.tag_name | sub("^v"; "")')"
curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${gitleaks_version}/gitleaks_${gitleaks_version}_linux_${gitleaks_arch}.tar.gz" \
  -o /tmp/gitleaks.tar.gz
tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks
rm /tmp/gitleaks.tar.gz

curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

curl -sSfL "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_${osv_arch}" \
  -o /usr/local/bin/osv-scanner
chmod +x /usr/local/bin/osv-scanner

PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install semgrep
PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install checkov
