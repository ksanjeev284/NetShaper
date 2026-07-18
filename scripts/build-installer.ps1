<#
.SYNOPSIS
  Full release packaging: publish zip + optional Inno Setup installer if ISCC is available.
  Version is read from Directory.Build.props via Get-Version.ps1.
#>
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$ver = & (Join-Path $PSScriptRoot "Get-Version.ps1")
if (-not $ver) { $ver = "0.0.0" }

& (Join-Path $PSScriptRoot "publish.ps1")
if ($LASTEXITCODE -ne 0) { throw "publish failed" }

$iscc = @(
  "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
  "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

$iss = Join-Path $PSScriptRoot "NetShaper.iss"
if ($iscc -and (Test-Path $iss)) {
  Write-Host "Building Inno Setup installer with $iscc (v$ver)"
  & $iscc "/DMyAppVersion=$ver" $iss
  if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }
  Write-Host "Installer: dist\NetShaper-Setup-$ver.exe"
} else {
  Write-Host "Inno Setup not found - zip package is ready under dist\."
  Write-Host "Optional: install Inno Setup 6 and re-run for NetShaper-Setup-$ver.exe"
}

Write-Host "Done. Version $ver"
