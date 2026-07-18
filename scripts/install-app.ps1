#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install NetShaper to Program Files, Start Menu + Desktop shortcuts, optional PATH for CLI.
#>
param(
  [string]$InstallDir = "$env:ProgramFiles\NetShaper",
  [switch]$SkipPublish,
  [switch]$AddToPath,
  [switch]$InstallService
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$src = Join-Path $Root "dist\NetShaper-win-x64"

if (-not $SkipPublish) {
  & (Join-Path $PSScriptRoot "publish.ps1")
  if ($LASTEXITCODE -ne 0) { throw "publish failed" }
}

if (-not (Test-Path (Join-Path $src "NetShaper.exe"))) {
  throw "Published build not found at $src\NetShaper.exe — run scripts\publish.ps1 first."
}

Write-Host "Installing to $InstallDir"
if (Test-Path $InstallDir) {
  # Keep policy/data; replace binaries
  Get-ChildItem $InstallDir -File | Remove-Item -Force -ErrorAction SilentlyContinue
  Get-ChildItem $InstallDir -Directory | Where-Object { $_.Name -in @("cli","runtimes") } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item (Join-Path $src "*") $InstallDir -Recurse -Force

$exe = Join-Path $InstallDir "NetShaper.exe"
$cli = Join-Path $InstallDir "cli\NetShaper.Cli.exe"
$ico = Join-Path $InstallDir "NetShaper.ico"
if (-not (Test-Path $ico)) { $ico = Join-Path $InstallDir "Assets\NetShaper.ico" }

# Start Menu
$sm = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\NetShaper"
New-Item -ItemType Directory -Path $sm -Force | Out-Null
$wsh = New-Object -ComObject WScript.Shell
$sc = $wsh.CreateShortcut((Join-Path $sm "NetShaper.lnk"))
$sc.TargetPath = $exe
$sc.WorkingDirectory = $InstallDir
$sc.Description = "NetShaper traffic control"
if (Test-Path $ico) { $sc.IconLocation = "$ico,0" }
$sc.Save()

if (Test-Path $cli) {
  $sc2 = $wsh.CreateShortcut((Join-Path $sm "NetShaper CLI.lnk"))
  $sc2.TargetPath = $cli
  $sc2.WorkingDirectory = $InstallDir
  $sc2.Description = "NetShaper command line"
  if (Test-Path $ico) { $sc2.IconLocation = "$ico,0" }
  $sc2.Save()
}

# Desktop
$desk = [Environment]::GetFolderPath("CommonDesktopDirectory")
$sc3 = $wsh.CreateShortcut((Join-Path $desk "NetShaper.lnk"))
$sc3.TargetPath = $exe
$sc3.WorkingDirectory = $InstallDir
if (Test-Path $ico) { $sc3.IconLocation = "$ico,0" }
$sc3.Save()

# Uninstall registry
$unreg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NetShaper"
New-Item -Path $unreg -Force | Out-Null
Set-ItemProperty $unreg -Name "DisplayName" -Value "NetShaper"
Set-ItemProperty $unreg -Name "DisplayVersion" -Value "0.3.3"
Set-ItemProperty $unreg -Name "Publisher" -Value "NetShaper contributors"
Set-ItemProperty $unreg -Name "InstallLocation" -Value $InstallDir
Set-ItemProperty $unreg -Name "DisplayIcon" -Value $exe
Set-ItemProperty $unreg -Name "UninstallString" -Value ("powershell.exe -ExecutionPolicy Bypass -File `"{0}`"" -f (Join-Path $InstallDir "uninstall-app.ps1"))
Set-ItemProperty $unreg -Name "NoModify" -Value 1 -Type DWord
Set-ItemProperty $unreg -Name "NoRepair" -Value 1 -Type DWord

# Copy uninstall script into install dir
Copy-Item (Join-Path $PSScriptRoot "uninstall-app.ps1") $InstallDir -Force

if ($AddToPath) {
  $cliDir = Join-Path $InstallDir "cli"
  $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
  if ($machinePath -notlike "*$cliDir*") {
    [Environment]::SetEnvironmentVariable("Path", $machinePath.TrimEnd(';') + ";" + $cliDir, "Machine")
    Write-Host "Added CLI to system PATH: $cliDir"
  }
}

if ($InstallService) {
  & (Join-Path $PSScriptRoot "install-service.ps1")
}

Write-Host ""
Write-Host "Installed NetShaper 0.3.3"
Write-Host "  App:      $exe"
Write-Host "  Start:    Start Menu → NetShaper"
Write-Host "  Uninstall: scripts\uninstall-app.ps1 or Apps & Features"
