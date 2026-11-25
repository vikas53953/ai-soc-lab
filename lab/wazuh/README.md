# Wazuh in Docker

`./setup.sh` does four things:

1. Downloads the official `wazuh-docker` single-node setup (version pinned by `WAZUH_VERSION`).
2. Generates TLS certificates and starts the manager, indexer and dashboard.
3. Copies `local_rules.xml` into the manager (rule **100200**: PowerShell with an encoded command).
4. Turns on **archives**, so every raw event (not just alerts) lands in `wazuh-archives-*`.

Why archives: by default Wazuh only stores alerts. The agent's `search_events` tool needs the
surrounding Sysmon events too (parent process, children), and those mostly don't raise alerts.
Archives use more disk, which is fine for a lab.

Not yet tested against a live Wazuh. If a step fails, the official guide is
https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
