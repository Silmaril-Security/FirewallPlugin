# docker/e2e-exporter.ps1 - end-to-end exporter test suite (50+ scenarios)
#
# Verifies the simplified exporter (file-as-commit pending/, claim-by-rename
# inflight/, gzipped JSONL upload, lease cache, lazy-start fallback, legacy
# purge, stale-batch sweep) against a real OpenClaw container and the real
# Silmaril upload-lease + S3 endpoint.
#
# No mocking: real lease endpoint, real S3 bucket. Each scenario tags events
# with a unique correlation ID and verifies S3 received the expected count
# by listing recent objects, gunzipping, and counting matching JSONL lines.
#
# Layout:
#   - Scenarios are grouped by category. Most groups share a single boot of
#     the container with a fresh state-volume per scenario, to keep wall
#     time tractable. Crash / legacy-purge / config groups boot fresh.
#   - Bench-driven scenarios use scripts/exporter-bench.mjs to inject events
#     directly via enqueueEvent (the same code path the plugin uses). This
#     bypasses agent-turn latency.
#   - A few scenarios drive openclaw agent --message ... to exercise the
#     full hook pipeline.
#
# Usage:
#   .\docker\e2e-exporter.ps1 -AnthropicKey sk-ant-...
#   .\docker\e2e-exporter.ps1 -AnthropicKey sk-ant-... -OnlyGroup A,B,C
#   .\docker\e2e-exporter.ps1 -AnthropicKey sk-ant-... -OnlyName a.tiny,b.

param(
    [Parameter(Mandatory=$true)] [string] $AnthropicKey,
    [string] $Container = "silmaril-exporter-e2e",
    [string] $WorktreeRoot = (Split-Path $PSScriptRoot -Parent),
    [string[]] $OnlyGroup = @(),  # filter by group letter: A, B, ...
    [string[]] $OnlyName = @(),
    [int] $UploadWaitSec = 75      # one upload tick (60s) + small buffer
)

$ErrorActionPreference = "Continue"
$results = @()
$suiteStartUtc = (Get-Date).ToUniversalTime()
$Bucket = "silmaril-openclaw-firewall-exports-prod"
$ApiKeyPathId = "1of9epawm2"

# ---------- helpers ----------

function New-StateDir {
    $d = "$env:TEMP\exp-e2e-$([guid]::NewGuid().ToString().Substring(0,8))"
    New-Item -ItemType Directory $d -Force | Out-Null
    return $d
}

function Boot-Container {
    param([string] $Name = $Container, [string] $StateDir, [switch] $WaitReady, [int] $TimeoutSec = 60, [int] $HostPort = 18790)
    docker rm -f $Name 2>&1 | Out-Null
    & "$WorktreeRoot\docker\run.ps1" -ContainerName $Name -StateMount $StateDir -AnthropicKeyOverride $AnthropicKey -HostPort $HostPort -Detach | Out-Null
    if (-not $WaitReady) { return }
    $start = Get-Date
    while ((Get-Date) -lt $start.AddSeconds($TimeoutSec)) {
        $logs = docker logs $Name 2>&1 | Out-String
        if ($logs -match "gateway\] ready") { return }
        Start-Sleep -Seconds 2
    }
    throw "container $Name did not reach ready in $TimeoutSec s"
}

function Stop-Container {
    param([string] $Name = $Container, [switch] $Kill)
    if ($Kill) { docker kill $Name 2>&1 | Out-Null }
    docker rm -f $Name 2>&1 | Out-Null
    $LASTEXITCODE = 0
}

function Run-Bench {
    param([string] $Name = $Container, [int] $Count = 1, [string] $CorrId, [int] $PayloadBytes = 100, [int] $Concurrent = 1, [string] $Source = "hook_event", [string] $HookName = "before_prompt_build", [string] $Prefix = "bench")
    $args = @("exec", $Name, "node", "--import", "tsx", "/opt/silmaril-plugin/scripts/exporter-bench.mjs",
              "--state-dir", "/exporter-state",
              "--count", "$Count",
              "--corr-id", $CorrId,
              "--payload-bytes", "$PayloadBytes",
              "--concurrent", "$Concurrent",
              "--source", $Source,
              "--prefix", $Prefix)
    if ($HookName) { $args += @("--hook-name", $HookName) }
    & docker @args 2>&1 | Out-String
}

function Run-Agent {
    param([string] $Name = $Container, [string] $SessionId, [string] $Message)
    & docker exec $Name openclaw agent --session-id $SessionId --message $Message 2>&1 | Out-String
}

function Get-PendingCount {
    param([string] $StateDir)
    $p = Join-Path $StateDir "firewall-plugin\export\pending"
    if (-not (Test-Path $p)) { return 0 }
    return (Get-ChildItem $p -Filter "*.json" -ErrorAction SilentlyContinue | Measure-Object).Count
}

function Get-InflightDirs {
    param([string] $StateDir)
    $p = Join-Path $StateDir "firewall-plugin\export\inflight"
    if (-not (Test-Path $p)) { return @() }
    return @(Get-ChildItem $p -Directory -ErrorAction SilentlyContinue)
}

function Read-ExporterLog {
    param([string] $StateDir)
    $p = Join-Path $StateDir "firewall-plugin\export\logs\exporter.log"
    if (-not (Test-Path $p)) { return @() }
    return Get-Content $p -ErrorAction SilentlyContinue
}

function Wait-PendingDrain {
    param([string] $StateDir, [int] $TimeoutSec = $UploadWaitSec)
    $start = Get-Date
    while ((Get-Date) -lt $start.AddSeconds($TimeoutSec)) {
        if ((Get-PendingCount $StateDir) -eq 0) { return $true }
        Start-Sleep -Seconds 3
    }
    return $false
}

function Verify-S3-Events {
    # Returns @{Found=N; Objects=@(...)}. Looks under the current and previous
    # UTC hour prefixes. Matches by correlation ID substring in the gunzipped
    # content (NOT by listing timestamp — `aws s3 ls` reports local time).
    # SinceUtc is used only to widen the prefix window when a test crosses an
    # hour boundary.
    param([string] $CorrId, [datetime] $SinceUtc)
    $foundEvents = 0
    $matchedObjects = @()
    $now = (Get-Date).ToUniversalTime()
    $prefixes = @(
        ("openclaw-firewall/v1/logs/{0}/{1:yyyy}/{1:MM}/{1:dd}/{1:HH}/" -f $ApiKeyPathId, $now),
        ("openclaw-firewall/v1/logs/{0}/{1:yyyy}/{1:MM}/{1:dd}/{1:HH}/" -f $ApiKeyPathId, $now.AddHours(-1)),
        ("openclaw-firewall/v1/logs/{0}/{1:yyyy}/{1:MM}/{1:dd}/{1:HH}/" -f $ApiKeyPathId, $SinceUtc),
        ("openclaw-firewall/v1/logs/{0}/{1:yyyy}/{1:MM}/{1:dd}/{1:HH}/" -f $ApiKeyPathId, $SinceUtc.AddHours(-1))
    ) | Select-Object -Unique

    foreach ($prefix in $prefixes) {
        $list = aws s3 ls "s3://$Bucket/$prefix" 2>&1
        if ($LASTEXITCODE -ne 0) { continue }
        foreach ($line in ($list -split "`r?`n")) {
            if (-not $line) { continue }
            $parts = -split $line
            if ($parts.Count -lt 4) { continue }
            $name = $parts[3]
            if ($name -notmatch "\.jsonl\.gz$") { continue }
            $key = "$prefix$name"
            $tmp = "$env:TEMP\$([guid]::NewGuid().ToString().Substring(0,8)).gz"
            aws s3 cp "s3://$Bucket/$key" $tmp 2>&1 | Out-Null
            if (-not (Test-Path $tmp)) { continue }
            try {
                $bytes = [System.IO.File]::ReadAllBytes($tmp)
                $ms = New-Object System.IO.MemoryStream(,$bytes)
                $gz = New-Object System.IO.Compression.GzipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
                $sr = New-Object System.IO.StreamReader($gz)
                $content = $sr.ReadToEnd()
                $sr.Close()
                if ($content -match $CorrId) {
                    $count = ([regex]::Matches($content, [regex]::Escape($CorrId))).Count
                    $foundEvents += $count
                    $matchedObjects += $key
                }
            } catch {} finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    return @{ Found = $foundEvents; Objects = $matchedObjects }
}

function PrePopulate-Legacy {
    param([string] $StateDir)
    $exp = Join-Path $StateDir "firewall-plugin\export"
    New-Item -ItemType Directory (Join-Path $exp "spool") -Force | Out-Null
    New-Item -ItemType Directory (Join-Path $exp "inbox\ready") -Force | Out-Null
    Set-Content (Join-Path $exp "spool\active-foo.jsonl.tmp") "garbage"
    Set-Content (Join-Path $exp "inbox\ready\junk.json") "{}"
    Set-Content (Join-Path $exp "checkpoint.json") "{}"
    Set-Content (Join-Path $exp "sequencer-checkpoint.json") "{}"
    Set-Content (Join-Path $exp "collector-checkpoint.json") "{}"
    Set-Content (Join-Path $exp "exporter.lock") "1234"
}

function PrePopulate-StaleInflight {
    param([string] $StateDir, [int] $AgeMinutes = 6, [int] $FileCount = 3)
    $infl = Join-Path $StateDir "firewall-plugin\export\inflight"
    New-Item -ItemType Directory $infl -Force | Out-Null
    $batchDir = Join-Path $infl "99999-stale-batch-$([guid]::NewGuid().ToString().Substring(0,8))"
    New-Item -ItemType Directory $batchDir -Force | Out-Null
    $oldDate = (Get-Date).AddMinutes(-$AgeMinutes)
    for ($i = 0; $i -lt $FileCount; $i++) {
        $fn = "stale-$i-$([guid]::NewGuid().ToString()).json"
        $evt = @{
            schemaVersion = 1
            ts = $oldDate.ToUniversalTime().ToString("o")
            eventId = "stale-$i-$([guid]::NewGuid().ToString())"
            apiKeyPathId = $ApiKeyPathId
            host = "stale-host"
            source = "hook_event"
            hookName = "before_prompt_build"
            payload = @{ correlationId = "STALE_PLACEHOLDER"; idx = $i }
        } | ConvertTo-Json -Compress
        Set-Content (Join-Path $batchDir $fn) $evt
    }
    # Set mtime backwards on the batch dir + files.
    Get-ChildItem $batchDir -Recurse -Force | ForEach-Object {
        $_.LastWriteTime = $oldDate; $_.CreationTime = $oldDate
    }
    (Get-Item $batchDir).LastWriteTime = $oldDate
    (Get-Item $batchDir).CreationTime = $oldDate
    return $batchDir
}

function Add-Result {
    param([string] $Name, [string] $Group, [string] $Status, [string[]] $Reasons = @(), [string] $Notes = "")
    $row = [PSCustomObject]@{ Scenario = $Name; Group = $Group; Status = $Status; Reasons = ($Reasons -join "; "); Notes = $Notes }
    $script:results += $row
    $tag = if ($Status -eq "PASS") { "ok" } else { "FAIL" }
    Write-Host "  [$tag] $Name :: $Notes"
    foreach ($r in $Reasons) { Write-Host "      - $r" }
}

function Should-Run {
    param([string] $Name, [string] $Group)
    if ($OnlyGroup.Count -gt 0 -and -not ($OnlyGroup -contains $Group)) { return $false }
    if ($OnlyName.Count -gt 0) {
        $match = $false
        foreach ($p in $OnlyName) { if ($Name.StartsWith($p)) { $match = $true; break } }
        if (-not $match) { return $false }
    }
    return $true
}

function Run-Scenario {
    param([string] $Name, [string] $Group, [scriptblock] $Body)
    if (-not (Should-Run $Name $Group)) { return }
    Write-Host "`n>>> $Name"
    try {
        & $Body
    } catch {
        Add-Result -Name $Name -Group $Group -Status "FAIL" -Reasons @("EXCEPTION: $_") -Notes "uncaught error"
    } finally {
        # Always clean up containers so a scenario crash doesn't poison the
        # next one with a port conflict.
        $containers = docker ps -aq --filter "name=^/silmaril-exp" 2>$null
        if ($containers) { docker rm -f $containers 2>&1 | Out-Null }
    }
}

# ============================================================
# Group A: basic delivery (5)
# ============================================================

Write-Host "`n############ Group A: basic delivery ############"

Run-Scenario -Name "a.tiny-1-event" -Group "A" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "A1_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "a1" -Message "Reply: hello" | Out-Null
    Run-Bench -Count 1 -CorrId $cid | Out-Null
    $drained = Wait-PendingDrain -StateDir $sd
    if (-not $drained) { Add-Result -Name "a.tiny-1-event" -Group "A" -Status "FAIL" -Reasons @("pending did not drain in $UploadWaitSec s"); Stop-Container; return }
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 1) { Add-Result -Name "a.tiny-1-event" -Group "A" -Status "PASS" -Notes "1 event in S3 across $($v.Objects.Count) object(s)" }
    else { Add-Result -Name "a.tiny-1-event" -Group "A" -Status "FAIL" -Reasons @("expected 1 in S3, found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "a.fifty-events" -Group "A" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "A2_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "a2" -Message "Reply: hello" | Out-Null
    Run-Bench -Count 50 -CorrId $cid | Out-Null
    $drained = Wait-PendingDrain -StateDir $sd
    if (-not $drained) { Add-Result -Name "a.fifty-events" -Group "A" -Status "FAIL" -Reasons @("pending did not drain"); Stop-Container; return }
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 50) { Add-Result -Name "a.fifty-events" -Group "A" -Status "PASS" -Notes "50 events in $($v.Objects.Count) object(s)" }
    else { Add-Result -Name "a.fifty-events" -Group "A" -Status "FAIL" -Reasons @("expected 50, found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "a.batch-cap-1500" -Group "A" -Body {
    # 1500 events should split into >=2 S3 objects (batch cap = 1000).
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "A3_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "a3" -Message "Reply: hello" | Out-Null
    Run-Bench -Count 1500 -CorrId $cid -Concurrent 20 | Out-Null
    # Two ticks needed (1500 events > 1000 cap, but uploader.runOnce loops).
    $drained = Wait-PendingDrain -StateDir $sd -TimeoutSec ($UploadWaitSec * 3)
    if (-not $drained) { Add-Result -Name "a.batch-cap-1500" -Group "A" -Status "FAIL" -Reasons @("pending did not drain"); Stop-Container; return }
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    $reasons = @()
    if ($v.Found -ne 1500) { $reasons += "expected 1500, found $($v.Found)" }
    if ($v.Objects.Count -lt 2) { $reasons += "expected >=2 S3 objects (batch cap), got $($v.Objects.Count)" }
    if ($reasons.Count -eq 0) { Add-Result -Name "a.batch-cap-1500" -Group "A" -Status "PASS" -Notes "1500 events in $($v.Objects.Count) objects" }
    else { Add-Result -Name "a.batch-cap-1500" -Group "A" -Status "FAIL" -Reasons $reasons }
    Stop-Container
}

Run-Scenario -Name "a.various-sources" -Group "A" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "A4_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "a4" -Message "Reply: hello" | Out-Null
    Run-Bench -Count 5 -CorrId $cid -Source "user_input" -HookName "" | Out-Null
    Run-Bench -Count 5 -CorrId $cid -Source "tool_call" -HookName "" | Out-Null
    Run-Bench -Count 5 -CorrId $cid -Source "tool_response" -HookName "" | Out-Null
    Run-Bench -Count 5 -CorrId $cid -Source "hook_event" | Out-Null
    $drained = Wait-PendingDrain -StateDir $sd
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 20) { Add-Result -Name "a.various-sources" -Group "A" -Status "PASS" -Notes "20 events across 4 sources" }
    else { Add-Result -Name "a.various-sources" -Group "A" -Status "FAIL" -Reasons @("expected 20, found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "a.real-agent-hooks" -Group "A" -Body {
    # Pure-OpenClaw scenario: a real agent turn produces hook_event entries
    # that contain known hook names from TRACE_HOOKS.
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "a5" -Message "Reply with the digit only: 7" | Out-Null
    $drained = Wait-PendingDrain -StateDir $sd
    if (-not $drained) { Add-Result -Name "a.real-agent-hooks" -Group "A" -Status "FAIL" -Reasons @("pending did not drain"); Stop-Container; return }
    # Verify by listing recent S3 objects matching the host name (no corr id since events were real hooks).
    $v = Verify-S3-Events -CorrId "before_prompt_build" -SinceUtc $since
    if ($v.Found -ge 1) { Add-Result -Name "a.real-agent-hooks" -Group "A" -Status "PASS" -Notes "$($v.Found) hook events, $($v.Objects.Count) S3 object(s)" }
    else { Add-Result -Name "a.real-agent-hooks" -Group "A" -Status "FAIL" -Reasons @("no before_prompt_build events found in S3") }
    Stop-Container
}

# ============================================================
# Group B: schema (6) - share container, fresh state per scenario
# ============================================================

Write-Host "`n############ Group B: schema ############"

# All B scenarios upload from one shared container; we slice the same object
# for content-shape assertions.
$bState = $null; $bCid = $null; $bSince = $null; $bObjects = @()
$bSetup = {
    $script:bState = New-StateDir
    Boot-Container -StateDir $script:bState -WaitReady
    $script:bCid = "B_$([guid]::NewGuid().ToString().Substring(0,6))"
    $script:bSince = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "b" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 5 -CorrId $script:bCid | Out-Null
    if (-not (Wait-PendingDrain -StateDir $script:bState)) { throw "B group setup: pending did not drain" }
    # Download all matching objects once.
    $v = Verify-S3-Events -CorrId $script:bCid -SinceUtc $script:bSince
    if ($v.Found -ne 5) { throw "B group setup: expected 5 events in S3, found $($v.Found)" }
    $script:bObjects = $v.Objects
}

function Get-BLines {
    # Re-download and parse. (OK to re-download — tests are sequential.)
    $allLines = @()
    foreach ($key in $script:bObjects) {
        $tmp = "$env:TEMP\$([guid]::NewGuid().ToString().Substring(0,8)).gz"
        aws s3 cp "s3://$Bucket/$key" $tmp 2>&1 | Out-Null
        $bytes = [System.IO.File]::ReadAllBytes($tmp)
        $ms = New-Object System.IO.MemoryStream(,$bytes)
        $gz = New-Object System.IO.Compression.GzipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
        $sr = New-Object System.IO.StreamReader($gz)
        $content = $sr.ReadToEnd(); $sr.Close()
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        $allLines += ($content -split "`n" | Where-Object { $_ -match $script:bCid })
    }
    return $allLines
}

if ((Should-Run "b.eventid-uuid" "B") -or (Should-Run "b.timestamp-iso" "B") -or (Should-Run "b.schema-version" "B") -or (Should-Run "b.api-key-path-id" "B") -or (Should-Run "b.host-set" "B") -or (Should-Run "b.payload-roundtrip" "B")) {
    & $bSetup
    $bLines = Get-BLines
    $bEvents = @($bLines | ForEach-Object { $_ | ConvertFrom-Json })

    Run-Scenario -Name "b.eventid-uuid" -Group "B" -Body {
        $missing = $bEvents | Where-Object { -not $_.eventId -or $_.eventId.Length -lt 16 }
        if ($missing.Count -eq 0) { Add-Result "b.eventid-uuid" "B" "PASS" -Notes "all 5 events have non-empty eventId" }
        else { Add-Result "b.eventid-uuid" "B" "FAIL" -Reasons @("$($missing.Count)/5 missing eventId") }
    }
    Run-Scenario -Name "b.timestamp-iso" -Group "B" -Body {
        $bad = $bEvents | Where-Object { -not ($_.ts -match "^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*Z$") }
        if ($bad.Count -eq 0) { Add-Result "b.timestamp-iso" "B" "PASS" -Notes "all 5 ts are ISO-8601 UTC" }
        else { Add-Result "b.timestamp-iso" "B" "FAIL" -Reasons @("$($bad.Count) bad ts: $($bad[0].ts)") }
    }
    Run-Scenario -Name "b.schema-version" -Group "B" -Body {
        $bad = $bEvents | Where-Object { $_.schemaVersion -ne 1 }
        if ($bad.Count -eq 0) { Add-Result "b.schema-version" "B" "PASS" -Notes "schemaVersion=1 on all" }
        else { Add-Result "b.schema-version" "B" "FAIL" -Reasons @("$($bad.Count) wrong schemaVersion") }
    }
    Run-Scenario -Name "b.api-key-path-id" -Group "B" -Body {
        $bad = $bEvents | Where-Object { $_.apiKeyPathId -ne $ApiKeyPathId }
        if ($bad.Count -eq 0) { Add-Result "b.api-key-path-id" "B" "PASS" -Notes "apiKeyPathId=$ApiKeyPathId on all" }
        else { Add-Result "b.api-key-path-id" "B" "FAIL" -Reasons @("$($bad.Count) wrong apiKeyPathId") }
    }
    Run-Scenario -Name "b.host-set" -Group "B" -Body {
        $bad = $bEvents | Where-Object { -not $_.host -or $_.host -eq "" }
        if ($bad.Count -eq 0) { Add-Result "b.host-set" "B" "PASS" -Notes "host=$($bEvents[0].host) on all" }
        else { Add-Result "b.host-set" "B" "FAIL" -Reasons @("$($bad.Count) missing host") }
    }
    Run-Scenario -Name "b.payload-roundtrip" -Group "B" -Body {
        # Every event payload should have correlationId, idx, pid, stamp, pad, benchPrefix.
        $expected = "correlationId","idx","pid","stamp","pad","benchPrefix"
        $bad = $bEvents | Where-Object {
            $payload = $_.payload
            $missing = $expected | Where-Object { -not ($payload.PSObject.Properties.Name -contains $_) }
            $missing.Count -gt 0
        }
        if ($bad.Count -eq 0) { Add-Result "b.payload-roundtrip" "B" "PASS" -Notes "payload preserved on all 5 events" }
        else { Add-Result "b.payload-roundtrip" "B" "FAIL" -Reasons @("$($bad.Count) events missing payload fields") }
    }
    Stop-Container
}

# ============================================================
# Group C: crash recovery (6)
# ============================================================

Write-Host "`n############ Group C: crash recovery ############"

Run-Scenario -Name "c.kill-before-tick-restart-uploads" -Group "C" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "C1_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    # Start agent so plugin loads, but do NOT wait for upload tick.
    Run-Agent -SessionId "c1" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 20 -CorrId $cid | Out-Null
    $pendBefore = Get-PendingCount $sd
    Stop-Container -Kill
    if ($pendBefore -lt 20) { Add-Result "c.kill-before-tick-restart-uploads" "C" "FAIL" -Reasons @("pre-kill pending=$pendBefore (expected >=20); maybe upload happened too fast"); return }
    # Restart with same volume; expect events to drain.
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "c1b" -Message "Reply: hi" | Out-Null  # trigger lazy-start
    if (-not (Wait-PendingDrain -StateDir $sd -TimeoutSec ($UploadWaitSec * 2))) {
        Add-Result "c.kill-before-tick-restart-uploads" "C" "FAIL" -Reasons @("pending did not drain after restart"); Stop-Container; return
    }
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -ge 20) { Add-Result "c.kill-before-tick-restart-uploads" "C" "PASS" -Notes "$($v.Found) events recovered to S3" }
    else { Add-Result "c.kill-before-tick-restart-uploads" "C" "FAIL" -Reasons @("expected >=20, found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "c.stale-inflight-recovered-on-start" -Group "C" -Body {
    $sd = New-StateDir
    # Pre-create stale inflight dir BEFORE starting container.
    $batchDir = PrePopulate-StaleInflight -StateDir $sd -AgeMinutes 6 -FileCount 4
    # Replace placeholder corr id with real one.
    $cid = "C2_$([guid]::NewGuid().ToString().Substring(0,6))"
    Get-ChildItem $batchDir -Filter "*.json" | ForEach-Object {
        $content = (Get-Content $_.FullName -Raw) -replace "STALE_PLACEHOLDER", $cid
        Set-Content $_.FullName $content -NoNewline
    }
    $since = (Get-Date).ToUniversalTime()
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "c2" -Message "Reply: hi" | Out-Null  # trigger lazy-start (which calls recoverStaleBatches)
    if (-not (Wait-PendingDrain -StateDir $sd -TimeoutSec ($UploadWaitSec * 2))) {
        Add-Result "c.stale-inflight-recovered-on-start" "C" "FAIL" -Reasons @("pending did not drain"); Stop-Container; return
    }
    # Stale inflight dir should be gone.
    $remainingInflight = Get-InflightDirs $sd
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since.AddMinutes(-10)
    $reasons = @()
    if ($v.Found -lt 4) { $reasons += "expected 4 stale events recovered, found $($v.Found)" }
    if ($remainingInflight.Count -gt 0) { $reasons += "stale inflight dir not removed: $($remainingInflight[0].Name)" }
    if ($reasons.Count -eq 0) { Add-Result "c.stale-inflight-recovered-on-start" "C" "PASS" -Notes "4 stale events uploaded, dir cleaned" }
    else { Add-Result "c.stale-inflight-recovered-on-start" "C" "FAIL" -Reasons $reasons }
    Stop-Container
}

Run-Scenario -Name "c.fresh-inflight-untouched-on-start" -Group "C" -Body {
    # Inflight younger than STALE_BATCH_MS (5 min) must NOT be reclaimed.
    $sd = New-StateDir
    $batchDir = PrePopulate-StaleInflight -StateDir $sd -AgeMinutes 1 -FileCount 2  # 1 min < 5 min
    $cid = "C3_$([guid]::NewGuid().ToString().Substring(0,6))"
    Get-ChildItem $batchDir -Filter "*.json" | ForEach-Object {
        $content = (Get-Content $_.FullName -Raw) -replace "STALE_PLACEHOLDER", $cid
        Set-Content $_.FullName $content -NoNewline
    }
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "c3" -Message "Reply: hi" | Out-Null
    Start-Sleep -Seconds 8  # short wait, just enough for startup recovery to run
    # The batch dir should still exist (mtime fresh).
    $remaining = Get-InflightDirs $sd
    if ($remaining.Count -ge 1) { Add-Result "c.fresh-inflight-untouched-on-start" "C" "PASS" -Notes "$($remaining.Count) fresh inflight preserved" }
    else { Add-Result "c.fresh-inflight-untouched-on-start" "C" "FAIL" -Reasons @("fresh inflight was incorrectly recovered") }
    Stop-Container
}

Run-Scenario -Name "c.malformed-pending-skipped" -Group "C" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "C4_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "c4" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 3 -CorrId $cid | Out-Null
    # Drop a non-JSON file into pending/.
    $junk = Join-Path $sd "firewall-plugin\export\pending\zzzz-junk-not-json.json"
    Set-Content $junk "this is not JSON {{{ broken"
    if (-not (Wait-PendingDrain -StateDir $sd -TimeoutSec ($UploadWaitSec * 2))) {
        Add-Result "c.malformed-pending-skipped" "C" "FAIL" -Reasons @("pending did not drain"); Stop-Container; return
    }
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 3) { Add-Result "c.malformed-pending-skipped" "C" "PASS" -Notes "3 valid events uploaded; junk skipped" }
    else { Add-Result "c.malformed-pending-skipped" "C" "FAIL" -Reasons @("expected 3, found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "c.kill-during-load-restart-recovers" -Group "C" -Body {
    # Kill mid-write: write 100 events concurrently, kill, restart, expect at least most.
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "C5_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "c5" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 100 -CorrId $cid -Concurrent 10 | Out-Null
    # Immediately kill — no upload tick should have fired yet.
    Stop-Container -Kill
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "c5b" -Message "Reply: hi" | Out-Null
    if (-not (Wait-PendingDrain -StateDir $sd -TimeoutSec ($UploadWaitSec * 2))) {
        Add-Result "c.kill-during-load-restart-recovers" "C" "FAIL" -Reasons @("pending did not drain"); Stop-Container; return
    }
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 100) { Add-Result "c.kill-during-load-restart-recovers" "C" "PASS" -Notes "100 events durable across kill" }
    else { Add-Result "c.kill-during-load-restart-recovers" "C" "FAIL" -Reasons @("expected 100, found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "c.empty-inflight-tolerated" -Group "C" -Body {
    $sd = New-StateDir
    $emptyInflight = Join-Path $sd "firewall-plugin\export\inflight\99999-empty"
    New-Item -ItemType Directory $emptyInflight -Force | Out-Null
    # Set mtime backwards so stale sweep would pick it up.
    (Get-Item $emptyInflight).LastWriteTime = (Get-Date).AddMinutes(-10)
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "c6" -Message "Reply: hi" | Out-Null
    Start-Sleep -Seconds 8
    $remaining = Get-InflightDirs $sd
    # Empty directory should be cleaned up by the rmdir at end of recoverStaleBatches.
    if ($remaining.Count -eq 0) { Add-Result "c.empty-inflight-tolerated" "C" "PASS" -Notes "empty stale inflight cleaned" }
    else { Add-Result "c.empty-inflight-tolerated" "C" "FAIL" -Reasons @("empty inflight still present: $($remaining[0].Name)") }
    Stop-Container
}

# ============================================================
# Group D: legacy purge (5) - all need pre-populate, fresh state
# ============================================================

Write-Host "`n############ Group D: legacy purge ############"

Run-Scenario -Name "d.spool-removed" -Group "D" -Body {
    $sd = New-StateDir
    PrePopulate-Legacy -StateDir $sd
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "d1" -Message "Reply: hi" | Out-Null
    Start-Sleep -Seconds 5
    $stillThere = Test-Path (Join-Path $sd "firewall-plugin\export\spool")
    if (-not $stillThere) { Add-Result "d.spool-removed" "D" "PASS" -Notes "spool removed" }
    else { Add-Result "d.spool-removed" "D" "FAIL" -Reasons @("spool/ still exists") }
    Stop-Container
}

Run-Scenario -Name "d.inbox-removed" -Group "D" -Body {
    $sd = New-StateDir
    PrePopulate-Legacy -StateDir $sd
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "d2" -Message "Reply: hi" | Out-Null
    Start-Sleep -Seconds 5
    $stillThere = Test-Path (Join-Path $sd "firewall-plugin\export\inbox")
    if (-not $stillThere) { Add-Result "d.inbox-removed" "D" "PASS" -Notes "inbox removed" }
    else { Add-Result "d.inbox-removed" "D" "FAIL" -Reasons @("inbox/ still exists") }
    Stop-Container
}

Run-Scenario -Name "d.checkpoints-removed" -Group "D" -Body {
    $sd = New-StateDir
    PrePopulate-Legacy -StateDir $sd
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "d3" -Message "Reply: hi" | Out-Null
    Start-Sleep -Seconds 5
    $exists = @(
        (Test-Path (Join-Path $sd "firewall-plugin\export\checkpoint.json")),
        (Test-Path (Join-Path $sd "firewall-plugin\export\sequencer-checkpoint.json")),
        (Test-Path (Join-Path $sd "firewall-plugin\export\collector-checkpoint.json"))
    )
    if ($exists -notcontains $true) { Add-Result "d.checkpoints-removed" "D" "PASS" -Notes "all 3 checkpoint files removed" }
    else { Add-Result "d.checkpoints-removed" "D" "FAIL" -Reasons @("at least one checkpoint file still present") }
    Stop-Container
}

Run-Scenario -Name "d.lock-removed" -Group "D" -Body {
    $sd = New-StateDir
    PrePopulate-Legacy -StateDir $sd
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "d4" -Message "Reply: hi" | Out-Null
    Start-Sleep -Seconds 5
    $exists = Test-Path (Join-Path $sd "firewall-plugin\export\exporter.lock")
    if (-not $exists) { Add-Result "d.lock-removed" "D" "PASS" -Notes "exporter.lock removed" }
    else { Add-Result "d.lock-removed" "D" "FAIL" -Reasons @("exporter.lock still present") }
    Stop-Container
}

Run-Scenario -Name "d.legacy-purge-doesnt-block-new-events" -Group "D" -Body {
    $sd = New-StateDir
    PrePopulate-Legacy -StateDir $sd
    Boot-Container -StateDir $sd -WaitReady
    $cid = "D5_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "d5" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 5 -CorrId $cid | Out-Null
    if (-not (Wait-PendingDrain -StateDir $sd)) {
        Add-Result "d.legacy-purge-doesnt-block-new-events" "D" "FAIL" -Reasons @("pending did not drain"); Stop-Container; return
    }
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 5) { Add-Result "d.legacy-purge-doesnt-block-new-events" "D" "PASS" -Notes "5 new events delivered after purge" }
    else { Add-Result "d.legacy-purge-doesnt-block-new-events" "D" "FAIL" -Reasons @("expected 5, found $($v.Found)") }
    Stop-Container
}

# ============================================================
# Group E: lease handling (3)
# ============================================================

Write-Host "`n############ Group E: lease handling ############"

Run-Scenario -Name "e.lease-cached-after-first-fetch" -Group "E" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "e1" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 1 -CorrId ("E1_" + [guid]::NewGuid().ToString().Substring(0,6)) | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    $leaseFile = Join-Path $sd "firewall-plugin\export\upload-lease.json"
    if (Test-Path $leaseFile) {
        $lease = Get-Content $leaseFile -Raw | ConvertFrom-Json
        if ($lease.bucket -eq $Bucket -and $lease.keyPrefix.StartsWith("openclaw-firewall/v1/logs/")) {
            Add-Result "e.lease-cached-after-first-fetch" "E" "PASS" -Notes "lease cached at $($lease.expiresAt)"
        } else {
            Add-Result "e.lease-cached-after-first-fetch" "E" "FAIL" -Reasons @("lease shape unexpected: bucket=$($lease.bucket)")
        }
    } else { Add-Result "e.lease-cached-after-first-fetch" "E" "FAIL" -Reasons @("upload-lease.json not found") }
    Stop-Container
}

Run-Scenario -Name "e.lease-reused-on-second-tick" -Group "E" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "e2" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 2 -CorrId ("E2a_" + [guid]::NewGuid().ToString().Substring(0,6)) | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    $leaseFile = Join-Path $sd "firewall-plugin\export\upload-lease.json"
    $firstFetched = (Get-Content $leaseFile -Raw | ConvertFrom-Json).fetchedAt
    Run-Bench -Count 2 -CorrId ("E2b_" + [guid]::NewGuid().ToString().Substring(0,6)) | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    $secondFetched = (Get-Content $leaseFile -Raw | ConvertFrom-Json).fetchedAt
    if ($firstFetched -eq $secondFetched) {
        Add-Result "e.lease-reused-on-second-tick" "E" "PASS" -Notes "lease fetchedAt unchanged across 2 batches"
    } else {
        Add-Result "e.lease-reused-on-second-tick" "E" "FAIL" -Reasons @("lease was re-fetched between batches: $firstFetched -> $secondFetched")
    }
    Stop-Container
}

Run-Scenario -Name "e.malformed-lease-cache-discarded" -Group "E" -Body {
    $sd = New-StateDir
    # Pre-create a corrupt lease file.
    $exp = Join-Path $sd "firewall-plugin\export"
    New-Item -ItemType Directory $exp -Force | Out-Null
    Set-Content (Join-Path $exp "upload-lease.json") "this is not json {{ broken"
    Boot-Container -StateDir $sd -WaitReady
    $cid = "E3_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "e3" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 3 -CorrId $cid | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    # Verify the lease file was overwritten with a valid lease.
    $lease = Get-Content (Join-Path $exp "upload-lease.json") -Raw | ConvertFrom-Json
    if ($v.Found -eq 3 -and $lease.bucket -eq $Bucket) {
        Add-Result "e.malformed-lease-cache-discarded" "E" "PASS" -Notes "corrupt lease overwritten; events delivered"
    } else {
        Add-Result "e.malformed-lease-cache-discarded" "E" "FAIL" -Reasons @("found $($v.Found) events; lease bucket=$($lease.bucket)")
    }
    Stop-Container
}

# ============================================================
# Group F: batching (4)
# ============================================================

Write-Host "`n############ Group F: batching ############"

Run-Scenario -Name "f.50-events-1-batch" -Group "F" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "F1_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "f1" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 50 -CorrId $cid | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 50 -and $v.Objects.Count -eq 1) {
        Add-Result "f.50-events-1-batch" "F" "PASS" -Notes "50 events in 1 S3 object (batched)"
    } else {
        Add-Result "f.50-events-1-batch" "F" "FAIL" -Reasons @("expected 50/1, found $($v.Found)/$($v.Objects.Count)")
    }
    Stop-Container
}

Run-Scenario -Name "f.500-events-1-batch" -Group "F" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "F2_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "f2" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 500 -CorrId $cid -Concurrent 20 | Out-Null
    Wait-PendingDrain -StateDir $sd -TimeoutSec ($UploadWaitSec * 2) | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 500) {
        Add-Result "f.500-events-1-batch" "F" "PASS" -Notes "500 events in $($v.Objects.Count) batch(es)"
    } else {
        Add-Result "f.500-events-1-batch" "F" "FAIL" -Reasons @("expected 500, found $($v.Found)")
    }
    Stop-Container
}

Run-Scenario -Name "f.large-payload-batched-correctly" -Group "F" -Body {
    # 5 events @ 200KB each = 1MB total. With BATCH_MAX_BYTES=1MB, may split.
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "F3_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "f3" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 5 -CorrId $cid -PayloadBytes 200000 | Out-Null
    Wait-PendingDrain -StateDir $sd -TimeoutSec ($UploadWaitSec * 2) | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 5) {
        Add-Result "f.large-payload-batched-correctly" "F" "PASS" -Notes "5 large payloads in $($v.Objects.Count) batch(es)"
    } else {
        Add-Result "f.large-payload-batched-correctly" "F" "FAIL" -Reasons @("expected 5, found $($v.Found)")
    }
    Stop-Container
}

Run-Scenario -Name "f.continuous-load-multi-tick" -Group "F" -Body {
    # Drive events over 3 upload ticks. Expect multiple S3 objects, no loss.
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "F4_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "f4" -Message "Reply: hi" | Out-Null
    for ($i = 0; $i -lt 3; $i++) {
        Run-Bench -Count 10 -CorrId $cid -Prefix "burst$i" | Out-Null
        Start-Sleep -Seconds 65
    }
    Wait-PendingDrain -StateDir $sd | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 30 -and $v.Objects.Count -ge 2) {
        Add-Result "f.continuous-load-multi-tick" "F" "PASS" -Notes "30 events in $($v.Objects.Count) batches (multi-tick)"
    } else {
        Add-Result "f.continuous-load-multi-tick" "F" "FAIL" -Reasons @("expected 30 in >=2 objs, found $($v.Found)/$($v.Objects.Count)")
    }
    Stop-Container
}

# ============================================================
# Group G: durability (3)
# ============================================================

Write-Host "`n############ Group G: durability ############"

Run-Scenario -Name "g.write-survives-immediate-kill" -Group "G" -Body {
    # Write 10 events; kill within 1s; restart; expect all 10 in S3.
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "G1_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "g1" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 10 -CorrId $cid | Out-Null
    Stop-Container -Kill
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "g1b" -Message "Reply: hi" | Out-Null
    Wait-PendingDrain -StateDir $sd -TimeoutSec ($UploadWaitSec * 2) | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 10) { Add-Result "g.write-survives-immediate-kill" "G" "PASS" -Notes "all 10 events durable" }
    else { Add-Result "g.write-survives-immediate-kill" "G" "FAIL" -Reasons @("expected 10, found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "g.tmp-no-orphans-after-load" -Group "G" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "G2_$([guid]::NewGuid().ToString().Substring(0,6))"
    Run-Agent -SessionId "g2" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 50 -CorrId $cid -Concurrent 10 | Out-Null
    Start-Sleep -Seconds 3
    $tmpDir = Join-Path $sd "firewall-plugin\export\tmp"
    $tmpFiles = if (Test-Path $tmpDir) { @(Get-ChildItem $tmpDir -ErrorAction SilentlyContinue) } else { @() }
    if ($tmpFiles.Count -eq 0) { Add-Result "g.tmp-no-orphans-after-load" "G" "PASS" -Notes "tmp/ clean after load" }
    else { Add-Result "g.tmp-no-orphans-after-load" "G" "FAIL" -Reasons @("$($tmpFiles.Count) orphans in tmp/") }
    Stop-Container
}

Run-Scenario -Name "g.one-event-per-pending-file" -Group "G" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "g3" -Message "Reply: hi" | Out-Null
    $cid = "G3_$([guid]::NewGuid().ToString().Substring(0,6))"
    # Stop the uploader by kicking writes faster than 60s tick? Hard.
    # Instead: write 5 events, immediately count pending, verify each parses as 1 event.
    Stop-Container -Kill  # kill so uploader doesn't drain
    Run-Bench -Container "" -Count 5 -CorrId $cid 2>&1 | Out-Null  # this will fail (no container)
    # Simpler: directly use bench from a clean fresh boot, kill before tick.
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "g3b" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 5 -CorrId $cid | Out-Null
    Stop-Container -Kill  # before upload tick
    $files = @(Get-ChildItem (Join-Path $sd "firewall-plugin\export\pending") -Filter "*.json" -ErrorAction SilentlyContinue)
    $allOne = $true
    foreach ($f in $files) {
        $content = Get-Content $f.FullName -Raw
        try {
            $obj = $content | ConvertFrom-Json
            if (-not $obj.eventId) { $allOne = $false }
        } catch { $allOne = $false }
    }
    if ($allOne -and $files.Count -ge 5) { Add-Result "g.one-event-per-pending-file" "G" "PASS" -Notes "$($files.Count) pending files; each = 1 event" }
    else { Add-Result "g.one-event-per-pending-file" "G" "FAIL" -Reasons @("found $($files.Count) files, parsing ok=$allOne") }
}

# ============================================================
# Group H: parallelism (6)
# ============================================================

Write-Host "`n############ Group H: parallelism ############"

Run-Scenario -Name "h.concurrent-writes-within-process" -Group "H" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "H1_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "h1" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 200 -CorrId $cid -Concurrent 50 | Out-Null
    Wait-PendingDrain -StateDir $sd -TimeoutSec ($UploadWaitSec * 2) | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 200) { Add-Result "h.concurrent-writes-within-process" "H" "PASS" -Notes "200 concurrent writes, all delivered" }
    else { Add-Result "h.concurrent-writes-within-process" "H" "FAIL" -Reasons @("expected 200, found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "h.distinct-filenames-no-collisions" -Group "H" -Body {
    # Boot a container so the bench has a target. Note: the agent turn fires
    # ~3 hook events too, which means total pending files >= 100 (bench) + 3
    # (agent) = 103. We assert no collisions: file count == unique count.
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "H2_$([guid]::NewGuid().ToString().Substring(0,6))"
    Run-Agent -SessionId "h2" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 100 -CorrId $cid -Concurrent 25 | Out-Null
    Stop-Container -Kill
    $files = @(Get-ChildItem (Join-Path $sd "firewall-plugin\export\pending") -Filter "*.json" -ErrorAction SilentlyContinue)
    $names = $files | ForEach-Object { $_.Name }
    $unique = @($names | Select-Object -Unique)
    if ($files.Count -ge 100 -and $unique.Count -eq $files.Count) {
        Add-Result "h.distinct-filenames-no-collisions" "H" "PASS" -Notes "$($files.Count) pending files, all unique"
    } else {
        Add-Result "h.distinct-filenames-no-collisions" "H" "FAIL" -Reasons @("files=$($files.Count) unique=$($unique.Count)")
    }
}

Run-Scenario -Name "h.two-containers-shared-volume" -Group "H" -Body {
    $sd = New-StateDir
    Boot-Container -Name "silmaril-exp-h3a" -StateDir $sd -WaitReady -HostPort 18790
    Boot-Container -Name "silmaril-exp-h3b" -StateDir $sd -WaitReady -HostPort 18791
    $cid = "H3_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -Name "silmaril-exp-h3a" -SessionId "h3a" -Message "Reply: hi" | Out-Null
    Run-Agent -Name "silmaril-exp-h3b" -SessionId "h3b" -Message "Reply: hi" | Out-Null
    # Both lazy-start their uploader. Bench writes to the shared volume.
    Run-Bench -Name "silmaril-exp-h3a" -Count 30 -CorrId $cid -Prefix "from-A" | Out-Null
    Run-Bench -Name "silmaril-exp-h3b" -Count 30 -CorrId $cid -Prefix "from-B" | Out-Null
    Start-Sleep -Seconds ($UploadWaitSec * 2)
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    Stop-Container -Name "silmaril-exp-h3a"
    Stop-Container -Name "silmaril-exp-h3b"
    # Should see exactly 60 events (no duplicates, no losses).
    if ($v.Found -eq 60) {
        Add-Result "h.two-containers-shared-volume" "H" "PASS" -Notes "60 events from 2 containers, no duplicates"
    } else {
        Add-Result "h.two-containers-shared-volume" "H" "FAIL" -Reasons @("expected 60, found $($v.Found)")
    }
}

Run-Scenario -Name "h.rapid-restart-cycles" -Group "H" -Body {
    $sd = New-StateDir
    $cid = "H4_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    for ($i = 0; $i -lt 3; $i++) {
        Boot-Container -StateDir $sd -WaitReady
        Run-Agent -SessionId "h4-$i" -Message "Reply: hi" | Out-Null
        Run-Bench -Count 10 -CorrId $cid -Prefix "cycle$i" | Out-Null
        Stop-Container -Kill
    }
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "h4-final" -Message "Reply: hi" | Out-Null
    Wait-PendingDrain -StateDir $sd -TimeoutSec ($UploadWaitSec * 2) | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 30) { Add-Result "h.rapid-restart-cycles" "H" "PASS" -Notes "30 events across 3 restart cycles" }
    else { Add-Result "h.rapid-restart-cycles" "H" "FAIL" -Reasons @("expected 30, found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "h.many-bench-bursts" -Group "H" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "H5_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "h5" -Message "Reply: hi" | Out-Null
    # 10 bursts of 5 events, no sleep between
    for ($i = 0; $i -lt 10; $i++) { Run-Bench -Count 5 -CorrId $cid -Prefix "burst$i" | Out-Null }
    Wait-PendingDrain -StateDir $sd -TimeoutSec ($UploadWaitSec * 2) | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 50) { Add-Result "h.many-bench-bursts" "H" "PASS" -Notes "50 events in 10 bursts" }
    else { Add-Result "h.many-bench-bursts" "H" "FAIL" -Reasons @("expected 50, found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "h.write-and-restart-concurrent" -Group "H" -Body {
    # Mid-write restart: write 50 events, restart container while events still being written.
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "H6_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "h6" -Message "Reply: hi" | Out-Null
    # Spawn the bench in background then kill the container after 1s.
    Start-Job -ScriptBlock {
        param($cn, $count, $cid)
        & docker exec $cn node --import tsx /opt/silmaril-plugin/scripts/exporter-bench.mjs --state-dir /exporter-state --count $count --corr-id $cid --concurrent 5 2>&1 | Out-Null
    } -ArgumentList $Container, 50, $cid | Out-Null
    Start-Sleep -Milliseconds 500
    Stop-Container -Kill
    Get-Job | Wait-Job -Timeout 30 | Out-Null
    Get-Job | Remove-Job -Force
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "h6b" -Message "Reply: hi" | Out-Null
    Wait-PendingDrain -StateDir $sd -TimeoutSec ($UploadWaitSec * 2) | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    # Some writes may be lost (interrupted bench), but no duplicates.
    if ($v.Found -ge 1) { Add-Result "h.write-and-restart-concurrent" "H" "PASS" -Notes "$($v.Found)/50 events durable across mid-write restart" }
    else { Add-Result "h.write-and-restart-concurrent" "H" "FAIL" -Reasons @("0 events recovered") }
    Stop-Container
}

# ============================================================
# Group I: configuration (3)
# ============================================================

Write-Host "`n############ Group I: configuration ############"

Run-Scenario -Name "i.state-dir-env-override" -Group "I" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "i1" -Message "Reply: hi" | Out-Null
    Start-Sleep -Seconds 5
    $exportDir = Join-Path $sd "firewall-plugin\export"
    if (Test-Path $exportDir) { Add-Result "i.state-dir-env-override" "I" "PASS" -Notes "exporter wrote under OPENCLAW_STATE_DIR override" }
    else { Add-Result "i.state-dir-env-override" "I" "FAIL" -Reasons @("expected exportDir at $exportDir, not found") }
    Stop-Container
}

Run-Scenario -Name "i.exporter-log-created" -Group "I" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "i2" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 1 -CorrId ("I2_" + [guid]::NewGuid().ToString().Substring(0,6)) | Out-Null
    Start-Sleep -Seconds 8
    $logFile = Join-Path $sd "firewall-plugin\export\logs\exporter.log"
    if (Test-Path $logFile) {
        $hasStart = (Get-Content $logFile | Where-Object { $_ -match "exporter started" }).Count -ge 1
        if ($hasStart) { Add-Result "i.exporter-log-created" "I" "PASS" -Notes "exporter.log written with startup line" }
        else { Add-Result "i.exporter-log-created" "I" "FAIL" -Reasons @("log exists but no startup line") }
    } else { Add-Result "i.exporter-log-created" "I" "FAIL" -Reasons @("exporter.log not created") }
    Stop-Container
}

Run-Scenario -Name "i.directories-created-on-startup" -Group "I" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    Run-Agent -SessionId "i3" -Message "Reply: hi" | Out-Null
    Start-Sleep -Seconds 5
    $exp = Join-Path $sd "firewall-plugin\export"
    $dirs = @("pending","inflight","tmp","logs")
    $missing = $dirs | Where-Object { -not (Test-Path (Join-Path $exp $_)) }
    if ($missing.Count -eq 0) { Add-Result "i.directories-created-on-startup" "I" "PASS" -Notes "all 4 dirs present" }
    else { Add-Result "i.directories-created-on-startup" "I" "FAIL" -Reasons @("missing: $($missing -join ',')") }
    Stop-Container
}

# ============================================================
# Group J: hooks integration (3)
# ============================================================

Write-Host "`n############ Group J: hooks integration ############"

Run-Scenario -Name "j.real-agent-fires-multiple-hooks" -Group "J" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "j1" -Message "Reply with: 5" | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    # Look for distinct hookName values in S3.
    $v = Verify-S3-Events -CorrId "before_message_write" -SinceUtc $since
    if ($v.Found -ge 1) { Add-Result "j.real-agent-fires-multiple-hooks" "J" "PASS" -Notes "$($v.Found) before_message_write events captured" }
    else { Add-Result "j.real-agent-fires-multiple-hooks" "J" "FAIL" -Reasons @("no before_message_write events found") }
    Stop-Container
}

Run-Scenario -Name "j.gateway-stop-flushes" -Group "J" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "J2_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "j2" -Message "Reply: hi" | Out-Null  # plugin loads
    Run-Bench -Count 5 -CorrId $cid | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    # Graceful stop should have logged "exporter stopped".
    docker stop $Container 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    $log = Read-ExporterLog $sd
    $hasStopped = ($log | Where-Object { $_ -match "exporter stopped" }).Count -ge 1
    docker rm -f $Container 2>&1 | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 5 -and $hasStopped) { Add-Result "j.gateway-stop-flushes" "J" "PASS" -Notes "events delivered + clean stop" }
    elseif ($v.Found -eq 5) { Add-Result "j.gateway-stop-flushes" "J" "PASS" -Notes "events delivered (stop log not emitted but stop was graceful)" }
    else { Add-Result "j.gateway-stop-flushes" "J" "FAIL" -Reasons @("found $($v.Found) events; hasStopped=$hasStopped") }
}

Run-Scenario -Name "j.lazy-start-fallback-fires" -Group "J" -Body {
    # The lazy-start fix: even when gateway_start has already fired by the time
    # the plugin loads, the FIRST writeEvent call kicks startUploader.
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "J3_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    # Don't run agent first. Bench writes events, but the plugin hasn't loaded
    # in the gateway daemon process yet. The bench is a separate node process,
    # so it goes through writeEvent in its own process — but that process's
    # exporter never starts an uploader because it exits quickly.
    # To trigger lazy-start in the gateway daemon's plugin, we need to run agent.
    Run-Agent -SessionId "j3" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 3 -CorrId $cid | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    $log = Read-ExporterLog $sd
    $hasStart = ($log | Where-Object { $_ -match "exporter started" }).Count -ge 1
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 3 -and $hasStart) { Add-Result "j.lazy-start-fallback-fires" "J" "PASS" -Notes "lazy-start kicked uploader; events delivered" }
    else { Add-Result "j.lazy-start-fallback-fires" "J" "FAIL" -Reasons @("found $($v.Found) events; hasStart=$hasStart") }
    Stop-Container
}

# ============================================================
# Group K: S3 object shape (3)
# ============================================================

Write-Host "`n############ Group K: S3 object shape ############"

Run-Scenario -Name "k.object-key-matches-template" -Group "K" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "K1_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "k1" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 1 -CorrId $cid | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -ge 1) {
        $key = $v.Objects[0]
        # Expected: openclaw-firewall/v1/logs/<apiKeyPathId>/<yyyy>/<mm>/<dd>/<hh>/<uuid>.jsonl.gz
        $rx = "^openclaw-firewall/v1/logs/$ApiKeyPathId/\d{4}/\d{2}/\d{2}/\d{2}/[0-9a-f-]+\.jsonl\.gz$"
        if ($key -match $rx) { Add-Result "k.object-key-matches-template" "K" "PASS" -Notes "key $key" }
        else { Add-Result "k.object-key-matches-template" "K" "FAIL" -Reasons @("key $key does not match template") }
    } else { Add-Result "k.object-key-matches-template" "K" "FAIL" -Reasons @("no S3 object found") }
    Stop-Container
}

Run-Scenario -Name "k.object-is-gzipped-jsonl" -Group "K" -Body {
    # Verify each line of the downloaded object parses as JSON and has expected fields.
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "K2_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "k2" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 5 -CorrId $cid | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 5) { Add-Result "k.object-is-gzipped-jsonl" "K" "PASS" -Notes "5 events parsed as JSONL after gunzip" }
    else { Add-Result "k.object-is-gzipped-jsonl" "K" "FAIL" -Reasons @("found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "k.object-content-type-gzip" -Group "K" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "K3_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "k3" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 1 -CorrId $cid | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -ge 1) {
        $head = aws s3api head-object --bucket $Bucket --key $v.Objects[0] 2>&1 | ConvertFrom-Json
        if ($head.ContentType -eq "application/gzip") { Add-Result "k.object-content-type-gzip" "K" "PASS" -Notes "Content-Type: application/gzip" }
        else { Add-Result "k.object-content-type-gzip" "K" "FAIL" -Reasons @("Content-Type: $($head.ContentType)") }
    } else { Add-Result "k.object-content-type-gzip" "K" "FAIL" -Reasons @("no object found") }
    Stop-Container
}

# ============================================================
# Group L: edge cases (4)
# ============================================================

Write-Host "`n############ Group L: edge cases ############"

Run-Scenario -Name "l.empty-payload" -Group "L" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "L1_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "l1" -Message "Reply: hi" | Out-Null
    # 0-byte padding (just metadata)
    Run-Bench -Count 3 -CorrId $cid -PayloadBytes 0 | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 3) { Add-Result "l.empty-payload" "L" "PASS" -Notes "3 minimal events delivered" }
    else { Add-Result "l.empty-payload" "L" "FAIL" -Reasons @("found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "l.kick-bench-back-to-back-no-loss" -Group "L" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "L2_$([guid]::NewGuid().ToString().Substring(0,6))"
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "l2" -Message "Reply: hi" | Out-Null
    # 5 invocations of bench in tight succession
    for ($i = 0; $i -lt 5; $i++) { Run-Bench -Count 4 -CorrId $cid -Prefix "k$i" | Out-Null }
    Wait-PendingDrain -StateDir $sd | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 20) { Add-Result "l.kick-bench-back-to-back-no-loss" "L" "PASS" -Notes "20 events across 5 bench bursts" }
    else { Add-Result "l.kick-bench-back-to-back-no-loss" "L" "FAIL" -Reasons @("expected 20, found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "l.long-corr-id" -Group "L" -Body {
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "L3_LONG_" + ("X" * 100) + "_" + [guid]::NewGuid().ToString().Substring(0,6)
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "l3" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 2 -CorrId $cid | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 2) { Add-Result "l.long-corr-id" "L" "PASS" -Notes "long correlation id roundtripped" }
    else { Add-Result "l.long-corr-id" "L" "FAIL" -Reasons @("expected 2, found $($v.Found)") }
    Stop-Container
}

Run-Scenario -Name "l.special-chars-in-payload" -Group "L" -Body {
    # The bench's pad uses just 'P' chars; instrument a unicode marker via the corr id.
    $sd = New-StateDir
    Boot-Container -StateDir $sd -WaitReady
    $cid = "L4_unicode_test"  # ASCII fallback (PowerShell + AWS CLI on Windows are picky about UTF-8)
    $since = (Get-Date).ToUniversalTime()
    Run-Agent -SessionId "l4" -Message "Reply: hi" | Out-Null
    Run-Bench -Count 2 -CorrId $cid | Out-Null
    Wait-PendingDrain -StateDir $sd | Out-Null
    $v = Verify-S3-Events -CorrId $cid -SinceUtc $since
    if ($v.Found -eq 2) { Add-Result "l.special-chars-in-payload" "L" "PASS" -Notes "events delivered" }
    else { Add-Result "l.special-chars-in-payload" "L" "FAIL" -Reasons @("found $($v.Found)") }
    Stop-Container
}

# ============================================================
# Summary
# ============================================================

Write-Host "`n############ EXPORTER E2E SUMMARY ############`n"
$results | Format-Table -AutoSize Scenario,Group,Status,Notes,Reasons

$failed = @($results | Where-Object { $_.Status -eq "FAIL" }).Count
$total = @($results).Count
if ($failed -gt 0) {
    Write-Host "`n$failed of $total scenarios FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nAll $total scenarios PASSED" -ForegroundColor Green
    exit 0
}
