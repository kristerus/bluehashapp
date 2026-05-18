# BlueHash agent (csid) — Windows Service installer.
#
# Equivalent of `scripts/com.hashnet.csid.plist` in the macOS repo:
# registers csid.exe with the Windows Service Control Manager so it
# starts on boot and runs as LocalSystem.
#
# Usage (elevated PowerShell):
#
#   .\install-service.ps1            # install
#   .\install-service.ps1 -Uninstall # uninstall
#   .\install-service.ps1 -Start     # install + immediately start
#
# Honours:
#   $env:CSID_BINARY_PATH — full path to csid.exe (default: looks for
#                            target\release\csid.exe in the workspace root)

#Requires -Version 5.0
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Start
)

$ErrorActionPreference = 'Stop'

$ServiceName = 'BlueHashAgent'
$RepoRoot    = Split-Path -Parent $PSScriptRoot
$DefaultExe  = Join-Path $RepoRoot 'target\release\csid.exe'
$ExePath     = if ($env:CSID_BINARY_PATH) { $env:CSID_BINARY_PATH } else { $DefaultExe }

if ($Uninstall) {
    Write-Host "→ Uninstalling $ServiceName" -ForegroundColor Cyan
    & sc.exe stop $ServiceName 2>$null | Out-Null
    & sc.exe delete $ServiceName
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ uninstalled $ServiceName" -ForegroundColor Green
    } else {
        Write-Warning "sc delete returned $LASTEXITCODE (already gone?)"
    }
    return
}

if (-not (Test-Path $ExePath)) {
    throw "csid.exe not found at $ExePath. Build first with: cargo build --release --package csid"
}

Write-Host "→ Installing $ServiceName" -ForegroundColor Cyan
Write-Host "  exe : $ExePath" -ForegroundColor DarkGray

# Prefer the daemon's own self-install (uses ServiceManager from
# windows-service crate; sets description, auto-start, LocalSystem).
& $ExePath install
if ($LASTEXITCODE -ne 0) {
    throw "csid install returned exit code $LASTEXITCODE"
}

if ($Start) {
    Write-Host "→ Starting $ServiceName" -ForegroundColor Cyan
    & sc.exe start $ServiceName
}

Write-Host ""
Write-Host "✓ done. Useful commands:" -ForegroundColor Green
Write-Host "    sc query $ServiceName"
Write-Host "    sc stop  $ServiceName"
Write-Host "    sc start $ServiceName"
Write-Host "    Get-Content `"$env:ProgramData\Hashnet\Logs\csid.log`" -Tail 50 -Wait"
