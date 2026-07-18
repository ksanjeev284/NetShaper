<#
.SYNOPSIS
  Build a Windows GUI installer (NetShaper-Setup-<ver>.exe) via Inno Setup.

  1) Publishes self-contained GUI + CLI into dist\NetShaper-win-x64
  2) Compiles a modern wizard Setup.exe that embeds all of those files

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1
  powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1 -SkipPublish
#>
param(
  [switch]$SkipPublish
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$ver = & (Join-Path $PSScriptRoot "Get-Version.ps1")
if (-not $ver) { $ver = "0.0.0" }
Write-Host "NetShaper GUI installer build  v$ver" -ForegroundColor Cyan

if (-not $SkipPublish) {
  Write-Host "`n== Publish app payload =="
  & (Join-Path $PSScriptRoot "publish.ps1")
  if ($LASTEXITCODE -ne 0 -and -not (Test-Path (Join-Path $Root "dist\NetShaper-win-x64\NetShaper.exe"))) {
    throw "publish failed"
  }
}

$payload = Join-Path $Root "dist\NetShaper-win-x64\NetShaper.exe"
if (-not (Test-Path $payload)) {
  throw "Missing published app: dist\NetShaper-win-x64\NetShaper.exe - run without -SkipPublish"
}

# Find Inno Setup compiler
$isccCandidates = @(
  "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
  "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
  "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
  Write-Host ""
  Write-Host "Inno Setup 6 not found. Install it, then re-run this script:" -ForegroundColor Yellow
  Write-Host "  winget install --id JRSoftware.InnoSetup -e"
  Write-Host "Or download: https://jrsoftware.org/isinfo.php"
  throw "ISCC.exe not found"
}

$iss = Join-Path $PSScriptRoot "NetShaper.iss"
if (-not (Test-Path $iss)) { throw "Missing $iss" }

Write-Host "`n== Compile GUI installer =="
Write-Host "ISCC: $iscc"
Write-Host "Script: $iss"

& $iscc "/DMyAppVersion=$ver" $iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit $LASTEXITCODE" }

$setup = Join-Path $Root "dist\NetShaper-Setup-$ver.exe"
if (-not (Test-Path $setup)) {
  # Inno may write slightly different name — search
  $found = Get-ChildItem (Join-Path $Root "dist") -Filter "NetShaper-Setup*.exe" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($found) { $setup = $found.FullName }
}

if (-not (Test-Path $setup)) { throw "Installer EXE not produced under dist\" }

$mb = [math]::Round((Get-Item $setup).Length / 1MB, 1)
Write-Host ""
Write-Host "OK  GUI installer ready" -ForegroundColor Green
Write-Host "    $setup  ($mb MB)"
Write-Host ""
Write-Host "Users: double-click the Setup.exe wizard (admin UAC)."
Write-Host "Silent:  NetShaper-Setup-$ver.exe /VERYSILENT /NORESTART"
Write-Host "Done. Version $ver"
