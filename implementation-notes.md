# Implementation notes

Deviations from the plan, one line each, newest first.

- 2026-11-25: The brief said `docker-compose.yml`. Wazuh's single-node stack needs generated TLS certificates
  and three containers, so `lab/wazuh/setup.sh` wraps the official `wazuh-docker` compose files instead of copying them.
- 2026-11-25: Added an offline "fixture" mode (sample data in `fixtures/`) so the agent can be built and tested
  before the lab exists. The same code talks to the live Wazuh indexer when `SIEM_BACKEND=wazuh`.
- 2026-11-25: The MCP Python SDK is version 2.x, where `FastMCP` was renamed `MCPServer`. Code uses the 2.x names.
- 2026-11-25: Model is `claude-opus-5-5` at `medium` effort (set in `.env`). The plan mentioned a smaller model for
  bulk triage; that switch belongs to a later cost pass once the eval gives us numbers to compare.
