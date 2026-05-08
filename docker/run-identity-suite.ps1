# docker/run-identity-suite.ps1 - top-level driver for the identity-mechanism
# E2E suite. Rebuilds the docker image (picking up the latest plugin), then
# runs each e2e-identity-*.ps1 group sequentially.

param(
    [Parameter(Mandatory=$true)]
    [string] $AnthropicKey,
    [string] $WorktreeRoot = (Split-Path $PSScriptRoot -Parent),
    [string[]] $Skip = @(),                     # e.g. -Skip stability,fuzz
    [switch] $SkipBuild,                        # skip image rebuild
    [int]    $StabilityTurns = 50,
    [int]    $FuzzMaxParametric = 24
)

$ErrorActionPreference = "Continue"
$startedAt = Get-Date

if (-not $SkipBuild) {
    Write-Host "############ STEP 1: build image with latest plugin ############" -ForegroundColor Cyan
    & "$PSScriptRoot\build.ps1"
    if ($LASTEXITCODE -ne 0) { Write-Host "build failed (exit $LASTEXITCODE)" -ForegroundColor Red; exit 1 }
}

$groups = @(
    @{ Name = "resolution"; Script = "e2e-identity-resolution.ps1"; Args = @{} }
    @{ Name = "decisions";  Script = "e2e-identity-decisions.ps1";  Args = @{} }
    @{ Name = "approval-fuzz"; Script = "e2e-identity-approval-fuzz.ps1"; Args = @{ MaxParametric = $FuzzMaxParametric } }
    @{ Name = "sessions";   Script = "e2e-identity-sessions.ps1";   Args = @{} }
    @{ Name = "ux";         Script = "e2e-identity-ux.ps1";         Args = @{} }
    @{ Name = "input";      Script = "e2e-identity-input.ps1";      Args = @{} }
    @{ Name = "identity-old"; Script = "e2e-identity.ps1";          Args = @{} }   # original 25 scenarios from 82b95c8
    @{ Name = "stability";  Script = "e2e-identity-stability.ps1";  Args = @{ Turns = $StabilityTurns } }
)

$summary = @()
foreach ($g in $groups) {
    if ($Skip -contains $g.Name) {
        Write-Host "`n############ SKIP $($g.Name) ############" -ForegroundColor Yellow
        continue
    }
    Write-Host "`n############ STEP: $($g.Name) ############" -ForegroundColor Cyan
    $argMap = @{ AnthropicKey = $AnthropicKey } + $g.Args
    $started = Get-Date
    & "$PSScriptRoot\$($g.Script)" @argMap
    $exitCode = $LASTEXITCODE
    $duration = (Get-Date) - $started
    $summary += [PSCustomObject]@{
        Group = $g.Name
        ExitCode = $exitCode
        DurationSec = [math]::Round($duration.TotalSeconds, 1)
    }
}

$total = (Get-Date) - $startedAt
Write-Host "`n############ FULL IDENTITY SUITE SUMMARY ############`n" -ForegroundColor Cyan
$summary | Format-Table -AutoSize
Write-Host "`ntotal duration: $([math]::Round($total.TotalMinutes, 1)) min"

$failures = ($summary | Where-Object { $_.ExitCode -ne 0 }).Count
if ($failures -gt 0) {
    Write-Host "$failures of $($summary.Count) groups had failures" -ForegroundColor Red
    exit 1
}
Write-Host "all $($summary.Count) groups PASSED" -ForegroundColor Green
exit 0
