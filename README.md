# ai-soc-lab

An AI SOC triage agent you can measure. A labeled attack runs in a home lab, Wazuh raises an alert,
and a Claude agent investigates it through an MCP tool server and returns a verdict with
MITRE ATT&CK mapping and cited evidence. An answer key scores every verdict.

```
Atomic Red Team ──> Windows + Sysmon ──> Wazuh ──> siem-mcp ──> triage agent (Claude) ──> verdict JSON ──> scorer
   (attack)            (telemetry)        (SIEM)    (2 tools)        (investigates)          (+ evidence)     (answer key)
```

This is week 1 of a 16-week build: one attack, one alert, one scored verdict.

## Quick start (offline, no lab needed)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # add your ANTHROPIC_API_KEY
set -a && source .env && set +a

pytest -q                        # 12 tests, no API calls
triage 1764065109.4471           # triage the sample alert with Claude
run-evals                        # score it against evals/cases/T1059_001.yaml
```

`triage` and `run-evals` call the Claude API and cost money on each run.

## With the real lab

1. **Wazuh:** `./lab/wazuh/setup.sh` on a Linux or Docker host (see `lab/wazuh/README.md`).
2. **Endpoint:** on a Windows lab VM, `lab\windows\setup-endpoint.ps1 -WazuhManager <manager IP> -AgentName WS01`.
3. **Attack:** on that VM, `lab\windows\run-atomic-T1059_001.ps1`.
4. **Triage:** set `SIEM_BACKEND=wazuh` and the `WAZUH_*` values in `.env`, then `triage <alert id from the dashboard>`.

## What the agent returns

```json
{
  "verdict": "malicious",
  "confidence": 0.8,
  "attack_techniques": ["T1059.001"],
  "summary": "PowerShell ran a base64-encoded command ...",
  "evidence": [{"event_id": "ev-0004", "why": "encoded PowerShell command line"}],
  "next_steps": ["Decode the command", "..."]
}
```

Every `event_id` in `evidence` must be one the tools actually returned. If the agent cites
anything else, the verdict is rejected and it has to try again.

## Safety

- The SIEM tools are read-only. The agent cannot change anything in this version.
- Tool output is treated as untrusted data in the system prompt (log fields can carry attacker text).
- Your Anthropic API key is not passed to the MCP server process.
- Attack scripts are for your own lab VMs only.

See [PROJECT-MAP.md](PROJECT-MAP.md) for what every file does.
