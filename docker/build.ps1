# docker/build.ps1 — builds the openclaw + plugin image.
# Run from the worktree root (the build context).
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
Write-Host "Build context: $repoRoot"
Set-Location $repoRoot
docker build -t silmaril-firewall-openclaw:dev -f docker/Dockerfile .
Write-Host "`nBuilt image: silmaril-firewall-openclaw:dev"
