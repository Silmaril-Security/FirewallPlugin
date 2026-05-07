# docker/run.ps1 - boots the openclaw + plugin container for exporter e2e
# tests. Pulls secrets from the host's ~/.openclaw/openclaw.json. Optional
# -StateMount lets the orchestrator share / preserve exporter state across
# restarts and inspect on-disk pending/inflight/logs from the host side.
#
# Usage:
#   .\docker\run.ps1 -ContainerName c1 -Detach
#   .\docker\run.ps1 -ContainerName c1 -StateMount C:\tmp\exporter-test-A -Detach

param(
    [string] $ContainerName = "silmaril-exporter-test",
    [int]    $HostPort = 18790,
    [string] $AnthropicKeyOverride = "",
    [string] $StateMount = "",
    [switch] $Detach,
    [switch] $RemoveExisting
)

$ErrorActionPreference = "Stop"

$hostCfg = "$env:USERPROFILE\.openclaw\openclaw.json"
if (-not (Test-Path $hostCfg)) {
    throw "Host openclaw.json not found at $hostCfg - cannot extract secrets."
}
$cfg = Get-Content $hostCfg -Raw | ConvertFrom-Json

$fp = $cfg.plugins.entries.'firewall-plugin'.config
if (-not $fp) { throw "firewall-plugin config not found in host openclaw.json" }

$gatewayToken = $cfg.gateway.auth.token
if (-not $gatewayToken) { throw "gateway.auth.token missing in host openclaw.json" }

$envVars = $cfg.env.vars
$anthropicKey = if ($AnthropicKeyOverride) { $AnthropicKeyOverride } else { $envVars.ANTHROPIC_API_KEY }
$openaiKey    = $envVars.OPENAI_API_KEY
if (-not $anthropicKey) { throw "ANTHROPIC_API_KEY missing - pass -AnthropicKeyOverride or set in host openclaw.json env.vars" }

$silmarilKey   = if ($fp.silmarilApiKey) { $fp.silmarilApiKey } else { $fp.apiKey }
$silmarilUrl   = $fp.apiUrl
$pluginKey     = $fp.apiKey
$fpReportUrl   = if ($fp.falsePositiveReportUrl) { $fp.falsePositiveReportUrl } else { "" }

if (-not $silmarilKey) { throw "silmarilApiKey/apiKey missing in host firewall-plugin config" }
if (-not $silmarilUrl) { throw "apiUrl missing in host firewall-plugin config" }

$existing = docker ps -aq --filter "name=^/$ContainerName$" 2>$null
if ($existing) {
    Write-Host "Removing existing container $ContainerName..."
    docker rm -f $ContainerName 2>&1 | Out-Null
    $LASTEXITCODE = 0
}

$dockerArgs = @(
    "run",
    "--name", $ContainerName,
    "-p", "${HostPort}:18789",
    "--add-host=host.docker.internal:host-gateway",
    "-e", "OPENCLAW_GATEWAY_TOKEN=$gatewayToken",
    "-e", "ANTHROPIC_API_KEY=$anthropicKey",
    "-e", "SILMARIL_API_KEY=$silmarilKey",
    "-e", "SILMARIL_PLUGIN_API_KEY=$pluginKey",
    "-e", "SILMARIL_CLASSIFY_URL=$silmarilUrl",
    "-e", "SILMARIL_FP_REPORT_URL=$fpReportUrl"
)
if ($openaiKey) { $dockerArgs += @("-e", "OPENAI_API_KEY=$openaiKey") }
if ($StateMount) {
    if (-not (Test-Path $StateMount)) { New-Item -Path $StateMount -ItemType Directory -Force | Out-Null }
    $dockerArgs += @(
        "-v", "${StateMount}:/exporter-state",
        "-e", "OPENCLAW_STATE_DIR=/exporter-state"
    )
}
if ($Detach) { $dockerArgs += "-d" }
$dockerArgs += "silmaril-firewall-openclaw:dev"

Write-Host "Starting container $ContainerName (hostPort=$HostPort, stateMount='$StateMount')..."
& docker @dockerArgs
