#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install NetShaper from a source checkout (builds first unless -SkipPublish).

  For release-zip users, prefer Setup.cmd / Install.ps1 inside the zip instead.
#>
param(
  [string]$InstallDir = "$env:ProgramFiles\NetShaper",
  [switch]$SkipPublish,
  [switch]$AddToPath,
  [switch]$InstallService,
  [switch]$WinDivert,
  [switch]$StartApp
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$src = Join-Path $Root "dist\NetShaper-win-x64"

if (-not $SkipPublish) {
  & (Join-Path $PSScriptRoot "publish.ps1")
}

if (-not (Test-Path (Join-Path $src "NetShaper.exe"))) {
  throw "Published build not found. Run scripts\publish.ps1 first."
}

$extra = @{}
if ($AddToPath) { $extra.AddToPath = $true }
if ($WinDivert) { $extra.WinDivert = $true }
if ($StartApp) { $extra.StartApp = $true }

& (Join-Path $PSScriptRoot "Install-FromRelease.ps1") -SourceDir $src -InstallDir $InstallDir @extra

if ($InstallService) {
  & (Join-Path $PSScriptRoot "install-service.ps1")
}
