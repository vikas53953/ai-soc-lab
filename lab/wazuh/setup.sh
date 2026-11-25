#!/usr/bin/env bash
# Starts a single-node Wazuh (manager + indexer + dashboard) in Docker, adds our custom
# rule, and turns on event archives so the agent can search raw Sysmon events.
#
# Needs: Docker with the compose plugin, git, ~8 GB free RAM for Wazuh.
# Linux hosts also need: sudo sysctl -w vm.max_map_count=262144
#
# Usage:  ./lab/wazuh/setup.sh            (uses WAZUH_VERSION below)
#         WAZUH_VERSION=v4.12.0 ./lab/wazuh/setup.sh
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-v4.12.0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$HERE/.wazuh-docker"

if [ ! -d "$WORK" ]; then
  echo "==> Downloading official wazuh-docker $WAZUH_VERSION"
  git clone --depth 1 --branch "$WAZUH_VERSION" https://github.com/wazuh/wazuh-docker.git "$WORK"
fi
cd "$WORK/single-node"

if [ ! -d config/wazuh_indexer_ssl_certs ] || [ -z "$(ls -A config/wazuh_indexer_ssl_certs 2>/dev/null)" ]; then
  echo "==> Generating TLS certificates"
  docker compose -f generate-indexer-certs.yml run --rm generator
fi

echo "==> Starting Wazuh"
docker compose up -d

echo "==> Waiting for the manager container"
for _ in $(seq 1 60); do
  if docker compose exec -T wazuh.manager test -f /var/ossec/etc/ossec.conf 2>/dev/null; then break; fi
  sleep 5
done

echo "==> Installing custom rule 100200 (encoded PowerShell)"
docker compose cp "$HERE/local_rules.xml" wazuh.manager:/var/ossec/etc/rules/local_rules.xml
docker compose exec -T wazuh.manager chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml

echo "==> Turning on archives (raw events -> wazuh-archives-* index)"
docker compose exec -T wazuh.manager sed -i 's#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#' /var/ossec/etc/ossec.conf
docker compose exec -T wazuh.manager sh -c \
  "sed -i '/archives:/,/enabled:/ s/enabled: false/enabled: true/' /etc/filebeat/filebeat.yml"

echo "==> Restarting manager to load the rule and archive settings"
docker compose restart wazuh.manager

CA="$WORK/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem"
cat <<EOF

Wazuh is starting (give it 2 to 3 minutes).
  Dashboard: https://localhost  (default login admin / SecretPassword; change it)
  Indexer:   https://localhost:9200

Put these in your .env:
  SIEM_BACKEND=wazuh
  WAZUH_INDEXER_URL=https://localhost:9200
  WAZUH_INDEXER_USER=admin
  WAZUH_INDEXER_PASSWORD=<your indexer password>
  WAZUH_CA_CERT=$CA

Check archives are flowing after the Windows agent connects:
  curl --cacert "$CA" -u admin:<password> "https://localhost:9200/_cat/indices/wazuh-archives-*?v"
EOF
