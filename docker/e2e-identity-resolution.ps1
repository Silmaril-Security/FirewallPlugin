# docker/e2e-identity-resolution.ps1 - group A.* identity-resolution edge cases
# and group B.role-flip-via-restart, B.identity-change-via-restart.
#
# Each scenario boots a fresh container with a different identity shape and
# probes role resolution with a single M1 message. PASS = role matches expected.

param(
    [Parameter(Mandatory=$true)]
    [string] $AnthropicKey,
    [string] $Container = "silmaril-firewall-identity",
    [string] $WorktreeRoot = (Split-Path $PSScriptRoot -Parent),
    [string[]] $OnlyName = @()
)

. "$PSScriptRoot\e2e-identity-helpers.ps1"

$global:results = @()

# ---- A.* identity-resolution cases ----
# Each case: boot with specific identity shape, send M1, assert role.
$cases = @(
    @{ Name = "id.missing-email-no-config-no-env"; Boot = @{ UserEmail = "" }; ExpectRole = "user"; Description = "no config userEmail, no USER_EMAIL env -> user/block" }
    @{ Name = "id.empty-string-config-falls-to-env"; Boot = @{ UserEmail = ""; UserEmailEnv = "gary@silmaril.dev" }; ExpectRole = "admin"; Description = "userEmail='' + USER_EMAIL=admin -> env wins -> admin/warn" }
    @{ Name = "id.whitespace-only-config-falls-to-env"; Boot = @{ UserEmail = "   "; UserEmailEnv = "gary@silmaril.dev" }; ExpectRole = "admin"; Description = "userEmail='   ' trimmed -> env wins -> admin" }
    @{ Name = "id.config-overrides-env"; Boot = @{ UserEmail = "user@example.com"; UserEmailEnv = "gary@silmaril.dev" }; ExpectRole = "user"; Description = "config user wins over env admin" }
    @{ Name = "id.env-only-admin"; Boot = @{ UserEmailEnvOnly = $true; UserEmailEnv = "gary@silmaril.dev" }; ExpectRole = "admin"; Description = "env-only admin -> admin/warn" }
    @{ Name = "id.case-insensitive-admin-upper"; Boot = @{ UserEmail = "GARY@SILMARIL.DEV" }; ExpectRole = "admin"; Description = "uppercase admin email matches via lowercase lookup" }
    @{ Name = "id.case-insensitive-admin-mixed"; Boot = @{ UserEmail = "Gary@Silmaril.Dev" }; ExpectRole = "admin"; Description = "mixed case admin email matches" }
    @{ Name = "id.leading-trailing-whitespace-trimmed"; Boot = @{ UserEmail = "  gary@silmaril.dev  " }; ExpectRole = "admin"; Description = "whitespace trimmed -> admin" }
    @{ Name = "id.unicode-homoglyph-rejected"; Boot = @{ UserEmail = "g$([char]0x0430)ry@silmaril.dev" }; ExpectRole = "user"; Description = "Cyrillic homoglyph not admin" }
    @{ Name = "id.emoji-localpart-rejected"; Boot = @{ UserEmail = "gary$([System.Char]::ConvertFromUtf32(0x1F3A9))@silmaril.dev" }; ExpectRole = "user"; Description = "emoji in localpart not admin" }
    @{ Name = "id.malformed-no-at-rejected"; Boot = @{ UserEmail = "garysilmaril.dev" }; ExpectRole = "user"; Description = "no @ -> not admin, no crash" }
    @{ Name = "id.very-long-email-10kb"; Boot = @{ UserEmail = ("a" * 10000) + "@silmaril.dev" }; ExpectRole = "user"; Description = "10kb email -> user, no DoS" }
    @{ Name = "id.totally-different-domain"; Boot = @{ UserEmail = "gary@evil.com" }; ExpectRole = "user"; Description = "admin localpart but different domain -> user" }
    @{ Name = "id.subdomain-spoof"; Boot = @{ UserEmail = "gary@silmaril.dev.evil.com" }; ExpectRole = "user"; Description = "subdomain spoof -> user" }
)

$scenarios = @()
foreach ($c in $cases) {
    $scenarios += @{
        Name = $c.Name
        Group = $c.ExpectRole
        Description = $c.Description
        Boot = $c.Boot
        Turns = Build-RoleProbeTurns -SessionId ($c.Name -replace "[^a-z0-9]+", "-") -ExpectRole $c.ExpectRole -Note "role probe"
    }
}

# ---- B.* role-flip & identity-change tests ----
$scenarios += @{
    Name = "id.identity-change-via-restart"
    Group = "multi"
    Description = "admin -> M1 warns; restart with user identity -> M1 blocks"
    BootPhases = @(
        @{ Boot = @{ UserEmail = "gary@silmaril.dev" }; Turns = (Build-RoleProbeTurns -SessionId "ic-admin" -ExpectRole "admin" -Note "phase1: admin warns") }
        @{ Boot = @{ UserEmail = "user@example.com" }; Turns = (Build-RoleProbeTurns -SessionId "ic-user" -ExpectRole "user" -Note "phase2: user blocks (after restart)") }
    )
}

$scenarios += @{
    Name = "pol.role-flip-via-restart"
    Group = "multi"
    Description = "boot admin role; restart with different user role; verify decision flips"
    BootPhases = @(
        @{ Boot = @{ UserEmail = "gary@silmaril.dev" }; Turns = (Build-RoleProbeTurns -SessionId "rf-admin" -ExpectRole "admin" -Note "phase1: admin warns") }
        @{ Boot = @{ UserEmail = "different-user@example.com" }; Turns = (Build-RoleProbeTurns -SessionId "rf-user" -ExpectRole "user" -Note "phase2: different user blocks") }
    )
}

# ---- filter ----
if ($OnlyName.Count -gt 0) {
    $scenarios = $scenarios | Where-Object { $name = $_.Name; ($OnlyName | Where-Object { $name.StartsWith($_) }).Count -gt 0 }
}

# ---- run ----
foreach ($s in $scenarios) {
    if ($s.BootPhases) {
        $name = $s.Name
        Write-Host "`n>>> $name :: $($s.Description)"
        $allOk = $true
        $totalTurns = 0
        foreach ($phase in $s.BootPhases) {
            $bootArgs = @{ Container = $Container; WorktreeRoot = $WorktreeRoot; AnthropicKey = $AnthropicKey } + $phase.Boot
            Boot-IdentityContainer @bootArgs
            foreach ($t in $phase.Turns) {
                $turnArgs = @{ Container = $Container } + $t
                $r = Invoke-Turn @turnArgs
                $totalTurns++
                $tag = if ($r.Reasons.Count -eq 0) { "ok" } else { "FAIL" }
                Write-Host "  [$tag] turn '$($t.SessionId)' :: $($t.Note)"
                if ($r.Reasons.Count -gt 0) {
                    $allOk = $false
                    foreach ($x in $r.Reasons) { Write-Host "      - $x" }
                    Write-Host "      gateway:$($r.GatewayFirewall)"
                }
            }
        }
        $global:results += [PSCustomObject]@{
            Scenario = $name
            Group = $s.Group
            Turns = $totalTurns
            Status = if ($allOk) { "PASS" } else { "FAIL" }
            ExpectedToFail = $false
        }
    } else {
        $bootArgs = @{ Container = $Container; WorktreeRoot = $WorktreeRoot; AnthropicKey = $AnthropicKey } + $s.Boot
        Boot-IdentityContainer @bootArgs
        Run-Scenario -Scenario $s -Container $Container
    }
}

Stop-IdentityContainer -Container $Container

$exitCode = Format-IdentityResults -Header "IDENTITY RESOLUTION (A.* + B.*)"
exit $exitCode
