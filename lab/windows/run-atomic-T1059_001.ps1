<#
  Runs the labeled attack for the first eval case: Atomic Red Team T1059.001,
  "PowerShell Command Execution" (PowerShell with a base64-encoded command).
  The command only prints a harmless "Hello" message.

  LAB VM ONLY. Windows Defender may block Atomic Red Team files; add an exclusion for
  C:\AtomicRedTeam on the lab VM if the install fails.

  Run in an elevated PowerShell:   .\run-atomic-T1059_001.ps1
#>
$ErrorActionPreference = "Stop"

if (-not (Get-Module -ListAvailable -Name invoke-atomicredteam)) {
  Write-Host "==> Installing Invoke-AtomicRedTeam and the atomics"
  IEX (IWR "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing)
  Install-AtomicRedTeam -getAtomics -Force
}
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

Write-Host "==> Tests available for T1059.001 (confirm the name below exists):"
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

$started = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Invoke-AtomicTest T1059.001 -TestNames "PowerShell Command Execution"
Write-Host ""
Write-Host "Attack ran at $started (UTC) on $env:COMPUTERNAME."
Write-Host "Next: find the alert for rule 100200 in the Wazuh dashboard, copy its id, then run:"
Write-Host "  triage <alert id>"
