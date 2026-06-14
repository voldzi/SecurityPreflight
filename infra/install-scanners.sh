#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  git \
  jq \
  openscap-scanner \
  python3 \
  python3-pip \
  pipx \
  tar \
  unzip

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y --no-install-recommends \
  docker-ce-cli \
  docker-compose-plugin
rm -rf /var/lib/apt/lists/*

arch="$(dpkg --print-architecture)"
case "${arch}" in
  amd64)
    gitleaks_arch="x64"
    nuclei_arch="amd64"
    osv_arch="amd64"
    ;;
  arm64)
    gitleaks_arch="arm64"
    nuclei_arch="arm64"
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

nuclei_version="$(curl -sSfL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.tag_name | sub("^v"; "")')"
curl -sSfL "https://github.com/projectdiscovery/nuclei/releases/download/v${nuclei_version}/nuclei_${nuclei_version}_linux_${nuclei_arch}.zip" \
  -o /tmp/nuclei.zip
unzip -q /tmp/nuclei.zip -d /tmp/nuclei
install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei
rm -rf /tmp/nuclei /tmp/nuclei.zip
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates

PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install semgrep
PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install checkov
PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install gvm-tools
