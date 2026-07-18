#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Download WinDivert (LGPLv3) into %ProgramData%\NetShaper\WinDivert for Packet shaper mode.
.NOTES
  WinDivert is third-party software: https://reqrypt.org/windivert.html
  NetShaper does not ship WinDivert binaries in-repo.
#>
$ErrorActionPreference = "Stop"
$dest = Join-Path $env:ProgramData "NetShaper\WinDivert"
$ver = "2.2.2"
$url = "https://github.com/basil00/WinDivert/releases/download/v$ver/WinDivert-$ver-A.zip"
$zip = Join-Path $env:TEMP "WinDivert-$ver.zip"

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
New-Item -ItemType Directory -Path $dest -Force | Out-Null

Write-Host "Extracting to $dest"
Expand-Archive -Path $zip -DestinationPath $dest -Force

# Normalize layout: prefer x64 binaries at WinDivert\x64\
$x64 = Get-ChildItem -Path $dest -Recurse -Filter "WinDivert.dll" | Where-Object { $_.DirectoryName -match "x64|amd64" } | Select-Object -First 1
if (-not $x64) {
  $x64 = Get-ChildItem -Path $dest -Recurse -Filter "WinDivert.dll" | Select-Object -First 1
}
if (-not $x64) { throw "WinDivert.dll not found in archive" }

$out = Join-Path $dest "x64"
New-Item -ItemType Directory -Path $out -Force | Out-Null
Copy-Item (Join-Path $x64.DirectoryName "*") $out -Force

Write-Host ""
Write-Host "Installed:"
Get-ChildItem $out | Format-Table Name, Length
Write-Host "Packet mode: set shaper to Packet and run NetShaper elevated."
Write-Host "Probe:  dotnet run --project NetShaper.Cli -- shaper packet"
