<#
.SYNOPSIS
  Publish NetShaper (GUI + CLI) self-contained win-x64 Release builds into dist\.
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

Write-Host "Publishing NetShaper ($Configuration / $Runtime / self-contained=$sc)"
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

# Assets / docs
Copy-Item (Join-Path $Root "LICENSE") $out -Force
Copy-Item (Join-Path $Root "README.md") $out -Force
Copy-Item (Join-Path $Root "assets\NetShaper.ico") $out -Force -ErrorAction SilentlyContinue
if (Test-Path (Join-Path $Root "assets\NetShaper-256.png")) {
  Copy-Item (Join-Path $Root "assets\NetShaper-256.png") $out -Force
}

# Version stamp
$ver = "0.3.7"
$ver | Set-Content (Join-Path $out "VERSION.txt")

# Zip
$zip = Join-Path $Root "dist\NetShaper-$ver-$Runtime.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $out "*") -DestinationPath $zip -Force

Write-Host "`nOK"
Write-Host "Folder: $out"
Write-Host "Zip:    $zip"
Get-ChildItem $out -File | Select-Object -First 15 Name, Length




