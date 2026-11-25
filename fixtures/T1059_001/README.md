# Sample data: T1059.001 encoded PowerShell on WS01

Synthetic documents shaped like Wazuh indexer output, so the pipeline can run without a lab.
They model what Atomic Red Team T1059.001 "PowerShell Command Execution" produces:

| id | what it is |
|---|---|
| `1764065109.4471` | the alert (custom rule 100200) |
| `ev-0003` | parent: PowerShell running `Invoke-AtomicTest` as `LAB\analyst` |
| `ev-0004` | the encoded PowerShell process (the attack) |
| `ev-0005`, `ev-0006` | child conhost and process exit |
| `ev-0001`, `ev-0002`, `ev-0007` | normal background noise on WS01 |
| `ev-0101` | an event on a different host (WS02), which must never show up in WS01 searches |

The encoded command decodes to a harmless `Write-Host 'Hello, from PowerShell!'`.
Replace these files with a real export from your lab once Wazuh is running.
