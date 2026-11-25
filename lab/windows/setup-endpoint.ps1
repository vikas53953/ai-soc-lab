<#
  Prepares a LAB Windows VM as a monitored endpoint:
    1. Installs Sysmon with the sysmon-modular config
    2. Installs the Wazuh agent and points it at your manager
    3. Tells the agent to ship the Sysmon event log

  Run in an elevated PowerShell on a lab VM only:
    .\setup-endpoint.ps1 -WazuhManager 10.10.30.10 -AgentName WS01
#>
param(
  [Parameter(Mandatory = $true)][string]$WazuhManager,
  [string]$AgentName = $env:COMPUTERNAME,
  [string]$WazuhAgentVersion = "4.12.0-1"
)
$ErrorActionPreference = "Stop"
$work = "C:\LabSetup"
New-Item -ItemType Directory -Force -Path $work | Out-Null

Write-Host "==> Installing Sysmon"
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$work\Sysmon.zip" -UseBasicParsing
Expand-Archive "$work\Sysmon.zip" -DestinationPath "$work\Sysmon" -Force
Invoke-WebRequest "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "$work\sysmonconfig.xml" -UseBasicParsing
& "$work\Sysmon\Sysmon64.exe" -accepteula -i "$work\sysmonconfig.xml"

Write-Host "==> Installing Wazuh agent $WazuhAgentVersion"
$msi = "$work\wazuh-agent.msi"
Invoke-WebRequest "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhAgentVersion.msi" -OutFile $msi -UseBasicParsing
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" /q WAZUH_MANAGER=$WazuhManager WAZUH_AGENT_NAME=$AgentName"

Write-Host "==> Shipping the Sysmon log to Wazuh"
$conf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$block = @"

<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
"@
if (-not (Select-String -Path $conf -Pattern "Microsoft-Windows-Sysmon/Operational" -Quiet)) {
  Add-Content -Path $conf -Value $block
}
Restart-Service WazuhSvc
Write-Host "Done. In the Wazuh dashboard, agent '$AgentName' should show as Active within a minute."
