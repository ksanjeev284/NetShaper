#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Uninstall NetShaper application files, shortcuts, and registry entry.
  Does not delete %ProgramData%\NetShaper policy/stats by default.
#>
param(
  [string]$InstallDir = "$env:ProgramFiles\NetShaper",
  [switch]$RemoveData
)

$ErrorActionPreference = "Stop"

# Stop service if present
try {
  $svc = Get-Service -Name "NetShaper" -ErrorAction SilentlyContinue
  if ($svc) {
    Write-Host "Removing Windows Service..."
    Stop-Service NetShaper -Force -ErrorAction SilentlyContinue
    sc.exe delete NetShaper | Out-Null
    Start-Sleep 1
  }
} catch { /* ignore */ }

# Shortcuts
$sm = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\NetShaper"
if (Test-Path $sm) { Remove-Item $sm -Recurse -Force }
$desk = Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "NetShaper.lnk"
if (Test-Path $desk) { Remove-Item $desk -Force }

# PATH cleanup
$cliDir = Join-Path $InstallDir "cli"
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -and $machinePath.Contains($cliDir)) {
  $parts = $machinePath.Split(';') | Where-Object { $_ -and ($_ -ne $cliDir) }
  [Environment]::SetEnvironmentVariable("Path", ($parts -join ';'), "Machine")
}

# Registry
$unreg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NetShaper"
if (Test-Path $unreg) { Remove-Item $unreg -Recurse -Force }

# Files
if (Test-Path $InstallDir) {
  Write-Host "Removing $InstallDir"
  Remove-Item $InstallDir -Recurse -Force
}

if ($RemoveData) {
  $data = Join-Path $env:ProgramData "NetShaper"
  if (Test-Path $data) {
    Write-Host "Removing data $data"
    Remove-Item $data -Recurse -Force
  }
}

Write-Host "NetShaper uninstalled."
