# Project map

One line per file: what it does, in plain words.

## Agent code (`src/ai_soc/`)

| File | What it does |
|---|---|
| `config.py` | Reads every setting from environment variables (`.env`). |
| `siem/backends.py` | Gets alerts and events, either from the sample files or from the live Wazuh indexer, and trims them to a small, consistent shape. |
| `mcp_servers/siem_server.py` | The MCP server. Gives the AI exactly two read-only tools, `get_alert` and `search_events`, and enforces limits (24-hour window, 200 results). |
| `agent/verdict.py` | The shape the final answer must have, and the `submit_verdict` tool the AI uses to hand it in. |
| `agent/triage.py` | The agent loop: asks Claude, runs the tools it asks for, checks the verdict's evidence is real, repeats until done. |
| `evals/scoring.py` | Compares one verdict with the answer key and says which checks passed. |
| `evals/run_evals.py` | Runs every answer-key case through the agent, prints PASS/FAIL, saves details to `results/`. |

## Data and answer keys

| Path | What it is |
|---|---|
| `fixtures/T1059_001/` | Sample Wazuh alert and Sysmon events for the encoded PowerShell attack, so everything runs offline. |
| `evals/cases/T1059_001.yaml` | Answer key: expected verdict, ATT&CK technique and the key event the agent must cite. |
| `results/` | Output of each eval run (not committed). |

## Lab (`lab/`)

| File | What it does |
|---|---|
| `wazuh/setup.sh` | Starts Wazuh in Docker, installs our rule, turns on raw-event archives. |
| `wazuh/local_rules.xml` | Rule 100200: alert when PowerShell starts with an encoded command (ATT&CK T1059.001). |
| `windows/setup-endpoint.ps1` | Installs Sysmon and the Wazuh agent on a Windows lab VM. |
| `windows/run-atomic-T1059_001.ps1` | Runs the labeled Atomic Red Team attack. |

## Tests (`tests/`)

| File | What it checks |
|---|---|
| `test_backend.py` | Sample data loads; searches respect host, time window, text filter and limit. |
| `test_mcp_server.py` | The MCP server lists its two tools, answers calls, rejects a 24-hour-plus window, and runs as a subprocess without seeing the API key. |
| `test_triage_loop.py` | The full agent loop with a scripted fake Claude: made-up evidence is rejected, real evidence is accepted, refusals and endless loops stop cleanly, and the scorer fails a wrong verdict. |

## Other

| File | What it is |
|---|---|
| `.env.example` | Template for your settings. Copy to `.env`. |
| `implementation-notes.md` | Every place the build differs from the plan, and why. |
