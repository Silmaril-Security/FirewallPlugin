# docker/run.ps1 — boots the container with secrets pulled from the host's
# ~/.openclaw/openclaw.json. Used for one-shot smoke + e2e cases.
#
# Usage:
#   .\docker\run.ps1                                          # default: no userEmail (F1 fallback path)
#   .\docker\run.ps1 -UserEmail gary@silmaril.dev             # admin path
#   .\docker\run.ps1 -UserEmail not-gary@example.com -Detach  # background container
#   .\docker\run.ps1 -UserEmailEnvOnly -UserEmailEnv gary@... # env var, empty config
#   .\docker\run.ps1 -StateMount C:\tmp\state                 # mount state dir for exporter inspection

param(
    [string] $UserEmail = "",
    [string] $UserEmailEnv = "",
    [switch] $UserEmailEnvOnly,
    [string] $ContainerName = "silmaril-firewall-test",
    [int]    $HostPort = 18790,
    [string] $AnthropicKeyOverride = "",
    [string] $FixtureUrl = "",
    [string] $StateMount = "",
    [switch] $Detach,
    [switch] $RemoveExisting,
    [string[]] $AddHost = @()
)

$ErrorActionPreference = "Stop"

# Pull secrets from the host openclaw.json (read-only).
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

# When -UserEmailEnvOnly is set, the userEmail field in config is forced empty
# (so resolveUserEmail() falls back to the USER_EMAIL env var).
if ($UserEmailEnvOnly) { $UserEmail = "" }

# Stop any existing container with the same name.
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
    "--add-host=fixtures.test:host-gateway",
    "-e", "OPENCLAW_GATEWAY_TOKEN=$gatewayToken",
    "-e", "ANTHROPIC_API_KEY=$anthropicKey",
    "-e", "SILMARIL_API_KEY=$silmarilKey",
    "-e", "SILMARIL_PLUGIN_API_KEY=$pluginKey",
    "-e", "SILMARIL_CLASSIFY_URL=$silmarilUrl",
    "-e", "SILMARIL_FP_REPORT_URL=$fpReportUrl",
    "-e", "OPENCLAW_USER_EMAIL=$UserEmail"
)
if ($UserEmailEnv) { $dockerArgs += @("-e", "USER_EMAIL=$UserEmailEnv") }
if ($openaiKey)    { $dockerArgs += @("-e", "OPENAI_API_KEY=$openaiKey") }
if ($FixtureUrl)   { $dockerArgs += @("-e", "SILMARIL_FIXTURE_URL=$FixtureUrl") }
if ($StateMount) {
    if (-not (Test-Path $StateMount)) { New-Item -Path $StateMount -ItemType Directory -Force | Out-Null }
    $dockerArgs += @(
        "-v", "${StateMount}:/exporter-state",
        "-e", "OPENCLAW_STATE_DIR=/exporter-state"
    )
}
foreach ($mapping in $AddHost) { $dockerArgs += @("--add-host", $mapping) }
if ($Detach) { $dockerArgs += "-d" }
$dockerArgs += "silmaril-firewall-openclaw:dev"

Write-Host "Starting container $ContainerName (userEmail='$UserEmail', userEmailEnv='$UserEmailEnv', hostPort=$HostPort, fixtureUrl='$FixtureUrl')..."
& docker @dockerArgs
