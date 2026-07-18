<#
.SYNOPSIS
  Publish NetShaper (GUI + CLI) self-contained win-x64 Release into dist\.
  Also copies easy Setup.cmd / Install.ps1 into the release folder for end users.
#>
param(
  [string]$Configuration = "Release",
  [string]$Runtime = "win-x64",
  [switch]$FrameworkDependent
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$out = Join-Path $Root "dist\NetShaper-$Runtime"
$sc = -not $FrameworkDependent

$ver = & (Join-Path $PSScriptRoot "Get-Version.ps1")
if (-not $ver) { $ver = "0.0.0" }

Write-Host "Publishing NetShaper $ver ($Configuration / $Runtime / self-contained=$sc)"
Write-Host "Output: $out"

if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $out -Force | Out-Null

$common = @(
  "-c", $Configuration,
  "-r", $Runtime,
  "--self-contained", ($sc.ToString().ToLower()),
  "-p:PublishSingleFile=false",
  "-p:IncludeNativeLibrariesForSelfExtract=true",
  "-p:DebugType=None",
  "-p:DebugSymbols=false"
)

Write-Host "`n== GUI =="
dotnet publish (Join-Path $Root "NetShaper.Gui\NetShaper.Gui.csproj") @common -o $out
if ($LASTEXITCODE -ne 0) { throw "GUI publish failed" }

Write-Host "`n== CLI =="
dotnet publish (Join-Path $Root "NetShaper.Cli\NetShaper.Cli.csproj") @common -o (Join-Path $out "cli")
if ($LASTEXITCODE -ne 0) { throw "CLI publish failed" }

# Docs + icon
Copy-Item (Join-Path $Root "LICENSE") $out -Force
Copy-Item (Join-Path $Root "README.md") $out -Force
Copy-Item (Join-Path $Root "assets\NetShaper.ico") $out -Force -ErrorAction SilentlyContinue
if (Test-Path (Join-Path $Root "assets\NetShaper-256.png")) {
  Copy-Item (Join-Path $Root "assets\NetShaper-256.png") $out -Force
}

# Easy install for zip users
Copy-Item (Join-Path $PSScriptRoot "Install-FromRelease.ps1") (Join-Path $out "Install.ps1") -Force
Copy-Item (Join-Path $PSScriptRoot "Setup.cmd") $out -Force
Copy-Item (Join-Path $PSScriptRoot "GETTING-STARTED.txt") $out -Force
Copy-Item (Join-Path $PSScriptRoot "uninstall-app.ps1") $out -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $PSScriptRoot "install-windivert.ps1") $out -Force -ErrorAction SilentlyContinue

$ver | Set-Content (Join-Path $out "VERSION.txt")

# Zip
New-Item -ItemType Directory -Path (Join-Path $Root "dist") -Force | Out-Null
$zip = Join-Path $Root "dist\NetShaper-$ver-$Runtime.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $out "*") -DestinationPath $zip -Force

Write-Host "`nOK  NetShaper $ver"
Write-Host "Folder: $out"
Write-Host "Zip:    $zip"
Write-Host "Users:  Unzip → right-click Setup.cmd → Run as administrator"
Get-ChildItem $out -File | Select-Object Name, Length | Format-Table -AutoSize
