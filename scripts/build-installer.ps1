# BlueHash Windows installer builder.
#
# Produces a single downloadable .exe (NSIS) and .msi (Wix) installer at:
#   target\release\bundle\nsis\BlueHash_<version>_x64-setup.exe
#   target\release\bundle\msi\BlueHash_<version>_x64_en-US.msi
#
# Requires:
#   - Rust 1.78+ + MSVC toolchain
#   - WebView2 runtime (preinstalled on Windows 11)
#   - `cargo install tauri-cli --version "^1.6"`
#
# Usage:
#   .\scripts\build-installer.ps1                # full build
#   .\scripts\build-installer.ps1 -SkipDaemonBuild  # csid already built

#Requires -Version 5.0
[CmdletBinding()]
param(
    [switch]$SkipDaemonBuild,
    [string]$Configuration = 'release'
)

# NOTE: We deliberately do NOT set $ErrorActionPreference='Stop'.
# Cargo writes its progress lines to stderr, and PowerShell 5.1 wraps
# each one as a NativeCommandError under Stop -- which aborts the build
# halfway through. Instead we check $LASTEXITCODE manually after each
# native call.

$Root = Split-Path -Parent $PSScriptRoot

function Step($label) {
    Write-Host ""
    Write-Host "==> $label" -ForegroundColor Cyan
}

function Die($msg) {
    Write-Host "FAILED: $msg" -ForegroundColor Red
    exit 1
}

# 1. Build csid in release.
if (-not $SkipDaemonBuild) {
    Step "Building csid ($Configuration)"
    & cargo build "--$Configuration" -p csid
    if ($LASTEXITCODE -ne 0) { Die "csid build failed (exit $LASTEXITCODE)" }
}

$csidSrc = Join-Path $Root "target\$Configuration\csid.exe"
if (-not (Test-Path $csidSrc)) {
    Die "csid.exe not found at $csidSrc. Build csid first or omit -SkipDaemonBuild."
}

# 2. Stage csid.exe at the path Tauri's externalBin expects.
Step "Staging csid.exe for Tauri externalBin"
$BinariesDir = Join-Path $Root "csi-tray\binaries"
New-Item -ItemType Directory -Force -Path $BinariesDir | Out-Null
$csidDst = Join-Path $BinariesDir "csid-x86_64-pc-windows-msvc.exe"
Copy-Item -Force $csidSrc $csidDst
Write-Host "  staged: $csidDst" -ForegroundColor DarkGray

# 3. Temporarily patch tauri.conf.json with externalBin = [csid].
Step "Patching tauri.conf.json"
$confPath = Join-Path $Root "csi-tray\tauri.conf.json"
$confBak  = "$confPath.bak"
Copy-Item -Force $confPath $confBak
$conf = Get-Content -Raw $confPath | ConvertFrom-Json
$conf.tauri.bundle.externalBin = @("binaries/csid")
# Write UTF-8 WITHOUT a BOM. WinPS 5.1's `Set-Content -Encoding utf8`
# emits a BOM, which Tauri's JSON parser rejects ("expected value at
# line 1 column 1"). Use the .NET API with a BOM-less UTF8Encoding.
$json = $conf | ConvertTo-Json -Depth 32
[System.IO.File]::WriteAllText($confPath, $json, [System.Text.UTF8Encoding]::new($false))

try {
    # 4. Tauri bundle build.
    Step "Running cargo tauri build (this takes a minute)"
    Push-Location (Join-Path $Root "csi-tray")
    try {
        & cargo tauri build
        $tauriExit = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($tauriExit -ne 0) { Die "cargo tauri build failed (exit $tauriExit)" }
} finally {
    # 5. Always restore the original config.
    Move-Item -Force $confBak $confPath
}

# 6. Report artefacts.
Write-Host ""
Write-Host "[OK] Installer built." -ForegroundColor Green
$nsisGlob = Join-Path $Root "target\release\bundle\nsis\*.exe"
$msiGlob  = Join-Path $Root "target\release\bundle\msi\*.msi"
Get-ChildItem -ErrorAction SilentlyContinue $nsisGlob, $msiGlob | ForEach-Object {
    Write-Host "  $($_.FullName)" -ForegroundColor White
}
Write-Host ""
Write-Host "Distribute the NSIS .exe -- users double-click and it installs" -ForegroundColor DarkGray
Write-Host "BlueHash to %LocalAppData%\Programs (no admin required)." -ForegroundColor DarkGray
