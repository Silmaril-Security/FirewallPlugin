# scripts/policy-live-smoke.ps1
# One-shot live verification: start gateway loaded with worktree plugin,
# run a benign agent command, capture identity + policy log lines, shut down.
# Must run inside `silclaw with --wait -- ...`.

$ErrorActionPreference = "Stop"
$logDir = "C:\Users\aumup\Desktop\workspace\silmaril-plugin\.claude\worktrees\role-dev\.live-smoke"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$gwOut = Join-Path $logDir "gateway.stdout.log"
$gwErr = Join-Path $logDir "gateway.stderr.log"
$agentOut = Join-Path $logDir "agent.stdout.log"

Write-Host "=== Starting gateway (background) ==="
$nodeExe = "C:\Program Files\nodejs\node.exe"
$openclawMjs = "C:\Users\aumup\AppData\Roaming\npm\node_modules\openclaw\openclaw.mjs"
$gw = Start-Process -FilePath $nodeExe -ArgumentList $openclawMjs,"gateway" -PassThru -NoNewWindow -RedirectStandardOutput $gwOut -RedirectStandardError $gwErr
Write-Host "Gateway pid: $($gw.Id)"

try {
    Write-Host "=== Waiting for gateway to listen on port 18789 (up to 60s) ==="
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        $conn = Get-NetTCPConnection -LocalPort 18789 -ErrorAction SilentlyContinue
        if ($conn) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) {
        Write-Host "GATEWAY DID NOT START. stderr tail:"
        Get-Content $gwErr -Tail 50 -ErrorAction SilentlyContinue
        Write-Host "stdout tail:"
        Get-Content $gwOut -Tail 50 -ErrorAction SilentlyContinue
        throw "gateway timeout"
    }
    Write-Host "Gateway is listening."

    Write-Host "`n=== Running benign agent command ==="
    & openclaw agent --session-id role-policy-live-A0 --message "What is 2+2? Reply with just the number." 2>&1 | Tee-Object -FilePath $agentOut
    Write-Host "Agent exit code: $LASTEXITCODE"

    Write-Host "`n=== Gateway stdout (last 80 lines) ==="
    Get-Content $gwOut -Tail 80 -ErrorAction SilentlyContinue

    Write-Host "`n=== Gateway stderr (last 40 lines) ==="
    Get-Content $gwErr -Tail 40 -ErrorAction SilentlyContinue

    Write-Host "`n=== Identity / policy log lines from gateway stdout ==="
    Get-Content $gwOut -ErrorAction SilentlyContinue | Where-Object { $_ -match "firewall-plugin: (identity|policy)" }

} finally {
    Write-Host "`n=== Stopping gateway ==="
    if ($gw -and -not $gw.HasExited) {
        Stop-Process -Id $gw.Id -Force -ErrorAction SilentlyContinue
        Write-Host "Gateway stopped."
    } else {
        Write-Host "Gateway already exited."
    }
}

Write-Host "`n=== DONE ==="
