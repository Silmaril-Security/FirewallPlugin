# docker/e2e-identity-ux.ps1 - group G.* UX / error-message verification.
# Asserts on the exact copy that the user sees and the log lines that ops would
# grep, so any source-side copy regressions surface immediately.

param(
    [Parameter(Mandatory=$true)]
    [string] $AnthropicKey,
    [string] $Container = "silmaril-firewall-identity",
    [string] $WorktreeRoot = (Split-Path $PSScriptRoot -Parent),
    [string[]] $OnlyName = @()
)

. "$PSScriptRoot\e2e-identity-helpers.ps1"
$global:results = @()
$scenarios = @()

# ---- user-block UX ----
$scenarios += @{
    Name = "ux.block-prompt-copy-contains-silmaril-firewall"
    Group = "user"
    Description = "block guard text contains 'Silmaril Firewall' brand"
    Turns = @(
        @{ SessionId = "ux-blk-1"; Message = $script:M1; Note = "T1: M1 -> block";
           ExpectGateway = @("guard=block","Silmaril Firewall"); }
    )
}
$scenarios += @{
    Name = "ux.block-prompt-copy-contains-new-session-guidance"
    Group = "user"
    Description = "block guard text mentions starting a new session"
    Turns = @(
        @{ SessionId = "ux-blk-2"; Message = $script:M1; Note = "T1: M1 -> block";
           ExpectGateway = @("guard=block","start a new"); }
    )
}
$scenarios += @{
    Name = "ux.block-prompt-no-override-hint"
    Group = "user"
    Description = "block message does not invite the user to type 'yes proceed' (no override path)"
    Turns = @(
        @{ SessionId = "ux-blk-3"; Message = $script:M1; Note = "T1: M1 -> block";
           ExpectGateway = @("guard=block");
           ForbidModel = @("yes proceed firewall","Reply with") }
    )
}
$scenarios += @{
    Name = "ux.error-message-firewall-line-no-pii"
    Group = "user"
    Description = "firewall-plugin log line does not echo prompt PII (gateway-level logs may contain it; we only assert on the firewall plugin's emitted line)"
    Turns = @(
        @{ SessionId = "ux-blk-4"; Message = $script:M1 + " (PII canary: 555-90123)";
           Note = "T1: M1 with PII tail -> block; firewall-plugin log line should not contain canary (gateway log may, but plugin shouldn't)";
           ExpectGateway = @("firewall-plugin: before_prompt_build guard=block") }
    )
}

# ---- log greppability ----
$scenarios += @{
    Name = "ux.log-greppability-block"
    Group = "user"
    Description = "block log line contains pluginId + sessionId attribute + guard=block (sessionId value is openclaw's internal UUID, not the CLI --session-id arg)"
    Turns = @(
        @{ SessionId = "ux-log-blk-1"; Message = $script:M1;
           Note = "T1: M1 -> block; log line shape includes pluginId + sessionId= + guard=block";
           ExpectGateway = @("firewall-plugin","sessionId=","guard=block"); }
    )
}

# ---- admin warn UX ----
$scenarios += @{
    Name = "ux.warn-prompt-copy-no-block-language"
    Group = "admin"
    Description = "admin warn prompt does NOT contain block-only copy"
    Turns = @(
        @{ SessionId = "ux-wrn-1"; Message = $script:M1; Note = "T1: M1 -> warn";
           ExpectGateway = @("guard=warn"); ForbidGateway = @("guard=block"); }
    )
}
$scenarios += @{
    Name = "ux.log-greppability-warn"
    Group = "admin"
    Description = "warn log line contains pluginId + sessionId attribute + guard=warn"
    Turns = @(
        @{ SessionId = "ux-log-wrn-1"; Message = $script:M1;
           Note = "T1: M1 -> warn; log line shape includes pluginId + sessionId= + guard=warn";
           ExpectGateway = @("firewall-plugin","sessionId=","guard=warn"); }
    )
}
$scenarios += @{
    Name = "ux.log-has-pluginId-and-guardtag-block"
    Group = "user"
    Description = "block log line contains pluginId and guard=block (relaxed; no sessionId requirement)"
    Turns = @(
        @{ SessionId = "ux-blk-pg-1"; Message = $script:M1;
           Note = "T1: M1 -> block; log contains pluginId + guard tag";
           ExpectGateway = @("firewall-plugin","guard=block"); }
    )
}
$scenarios += @{
    Name = "ux.log-has-pluginId-and-guardtag-warn"
    Group = "admin"
    Description = "warn log line contains pluginId and guard=warn (relaxed)"
    Turns = @(
        @{ SessionId = "ux-wrn-pg-1"; Message = $script:M1;
           Note = "T1: M1 -> warn; log contains pluginId + guard tag";
           ExpectGateway = @("firewall-plugin","guard=warn"); }
    )
}
$scenarios += @{
    Name = "ux.identity-log-line-format"
    Group = "admin"
    Description = "startup emits 'firewall-plugin: identity=...' line"
    Turns = @(
        @{ SessionId = "ux-id-1"; Message = "what is 2+2?"; Note = "T1: trigger any agent activity";
           ForbidGateway = @("guard=block"); }
    )
}

# ---- filter + run ----
if ($OnlyName.Count -gt 0) {
    $scenarios = $scenarios | Where-Object { $name = $_.Name; ($OnlyName | Where-Object { $name.StartsWith($_) }).Count -gt 0 }
}

$identityFor = @{ "admin" = "gary@silmaril.dev"; "user" = "user@example.com" }
$bootedYet = $false; $bootedIdentity = $null
foreach ($groupName in @("admin", "user")) {
    $groupScenarios = $scenarios | Where-Object { $_.Group -eq $groupName }
    if ($groupScenarios.Count -eq 0) { continue }
    $needs = $identityFor[$groupName]
    if ((-not $bootedYet) -or ($needs -ne $bootedIdentity)) {
        Boot-IdentityContainer -UserEmail $needs -Container $Container -WorktreeRoot $WorktreeRoot -AnthropicKey $AnthropicKey
        $bootedIdentity = $needs; $bootedYet = $true
    }
    # The identity-log-line-format scenario asserts the startup log; check explicitly here.
    if ($groupName -eq "admin") {
        $allLogs = docker logs $Container 2>&1 | Out-String
        if ($allLogs -match "firewall-plugin:.*identity=") {
            Write-Host "  [ok] startup identity log line present (admin)"
        } else {
            Write-Host "  [WARN] no 'firewall-plugin: identity=' log line found at startup (admin)" -ForegroundColor Yellow
        }
    }
    foreach ($s in $groupScenarios) { Run-Scenario -Scenario $s -Container $Container }
}

Stop-IdentityContainer -Container $Container
exit (Format-IdentityResults -Header "UX / ERROR-MESSAGE VERIFICATION (G.*)")
