#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Easy installer for a NetShaper release zip (or dist\NetShaper-win-x64 folder).

.DESCRIPTION
  Double-click Setup.cmd in the unzipped folder, or:
    powershell -ExecutionPolicy Bypass -File Install.ps1

  - Copies files to Program Files\NetShaper
  - Start Menu + Desktop shortcuts
  - Optional: CLI on PATH, WinDivert (packet mode), launch app

.PARAMETER SourceDir
  Folder that contains NetShaper.exe (default: parent of this script, or dist\NetShaper-win-x64)

.PARAMETER AddToPath
  Add cli\ to system PATH

.PARAMETER WinDivert
  Download and install WinDivert for Packet shaper mode

.PARAMETER StartApp
  Launch NetShaper after install
#>
param(
  [string]$SourceDir = "",
  [string]$InstallDir = "$env:ProgramFiles\NetShaper",
  [switch]$AddToPath,
  [switch]$WinDivert,
  [switch]$StartApp,
  [switch]$Quiet
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) {
  if (-not $Quiet) { Write-Host "" ; Write-Host "==> $msg" -ForegroundColor Cyan }
}

# Resolve source of NetShaper.exe
if (-not $SourceDir) {
  $here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
  # Script next to NetShaper.exe (release zip layout)
  if (Test-Path (Join-Path $here "NetShaper.exe")) {
    $SourceDir = $here
  }
  # Script in scripts\ next to repo root
  elseif (Test-Path (Join-Path $here "..\dist\NetShaper-win-x64\NetShaper.exe")) {
    $SourceDir = (Resolve-Path (Join-Path $here "..\dist\NetShaper-win-x64")).Path
  }
  elseif (Test-Path (Join-Path $here "dist\NetShaper-win-x64\NetShaper.exe")) {
    $SourceDir = (Resolve-Path (Join-Path $here "dist\NetShaper-win-x64")).Path
  }
  else {
    $SourceDir = $here
  }
}

$exeSrc = Join-Path $SourceDir "NetShaper.exe"
if (-not (Test-Path $exeSrc)) {
  throw "NetShaper.exe not found in: $SourceDir`nUnzip the release fully, then run Install.ps1 or Setup.cmd from that folder."
}

$verFile = Join-Path $SourceDir "VERSION.txt"
$ver = if (Test-Path $verFile) { (Get-Content $verFile -Raw).Trim() } else { "unknown" }

Write-Host ""
Write-Host "  NetShaper installer  v$ver" -ForegroundColor Green
Write-Host "  Source:  $SourceDir"
Write-Host "  Target:  $InstallDir"
Write-Host ""

Write-Step "Copying files"
if (Test-Path $InstallDir) {
  Get-ChildItem $InstallDir -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
  Get-ChildItem $InstallDir -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in @("cli", "runtimes", "Assets") } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item (Join-Path $SourceDir "*") $InstallDir -Recurse -Force

$exe = Join-Path $InstallDir "NetShaper.exe"
$cli = Join-Path $InstallDir "cli\NetShaper.Cli.exe"
$ico = Join-Path $InstallDir "NetShaper.ico"
if (-not (Test-Path $ico)) { $ico = Join-Path $InstallDir "Assets\NetShaper.ico" }

Write-Step "Shortcuts (Start Menu + Desktop)"
$sm = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\NetShaper"
New-Item -ItemType Directory -Path $sm -Force | Out-Null
$wsh = New-Object -ComObject WScript.Shell

$sc = $wsh.CreateShortcut((Join-Path $sm "NetShaper.lnk"))
$sc.TargetPath = $exe
$sc.WorkingDirectory = $InstallDir
$sc.Description = "NetShaper — free bandwidth limiter"
if (Test-Path $ico) { $sc.IconLocation = "$ico,0" }
$sc.Save()

if (Test-Path $cli) {
  $sc2 = $wsh.CreateShortcut((Join-Path $sm "NetShaper CLI.lnk"))
  $sc2.TargetPath = $cli
  $sc2.WorkingDirectory = (Split-Path $cli)
  $sc2.Description = "NetShaper command line"
  if (Test-Path $ico) { $sc2.IconLocation = "$ico,0" }
  $sc2.Save()
}

$desk = [Environment]::GetFolderPath("CommonDesktopDirectory")
$sc3 = $wsh.CreateShortcut((Join-Path $desk "NetShaper.lnk"))
$sc3.TargetPath = $exe
$sc3.WorkingDirectory = $InstallDir
$sc3.Description = "NetShaper — free bandwidth limiter"
if (Test-Path $ico) { $sc3.IconLocation = "$ico,0" }
$sc3.Save()

Write-Step "Apps & Features entry"
$unreg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NetShaper"
New-Item -Path $unreg -Force | Out-Null
Set-ItemProperty $unreg -Name "DisplayName" -Value "NetShaper"
Set-ItemProperty $unreg -Name "DisplayVersion" -Value $ver
Set-ItemProperty $unreg -Name "Publisher" -Value "NetShaper contributors"
Set-ItemProperty $unreg -Name "InstallLocation" -Value $InstallDir
Set-ItemProperty $unreg -Name "DisplayIcon" -Value $exe

# Full uninstall script: stop service, PATH, shortcuts, registry, files
$uninst = Join-Path $InstallDir "Uninstall.ps1"
$fullUninstSrc = @(
  (Join-Path $SourceDir "uninstall-app.ps1"),
  (Join-Path $PSScriptRoot "uninstall-app.ps1")
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if ($fullUninstSrc) {
  $body = Get-Content $fullUninstSrc -Raw
  # Pin install dir for this install
  $body = $body -replace '\$InstallDir = "\$env:ProgramFiles\\NetShaper"', "`$InstallDir = `"$InstallDir`""
  Set-Content $uninst -Value $body -Encoding UTF8
} else {
  @"
#Requires -RunAsAdministrator
param([string]`$InstallDir = '$InstallDir', [switch]`$RemoveData)
`$ErrorActionPreference = 'Continue'
try { Stop-Service NetShaper -Force -ErrorAction SilentlyContinue; sc.exe delete NetShaper | Out-Null } catch {}
Remove-Item (Join-Path `$env:ProgramData 'Microsoft\Windows\Start Menu\Programs\NetShaper') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'NetShaper.lnk') -Force -ErrorAction SilentlyContinue
`$cliDir = Join-Path `$InstallDir 'cli'
`$mp = [Environment]::GetEnvironmentVariable('Path','Machine')
if (`$mp -and `$mp.Contains(`$cliDir)) {
  `$parts = `$mp.Split(';') | Where-Object { `$_ -and (`$_ -ne `$cliDir) }
  [Environment]::SetEnvironmentVariable('Path', (`$parts -join ';'), 'Machine')
}
Remove-Item 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NetShaper' -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path `$InstallDir) { Remove-Item `$InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
if (`$RemoveData -and (Test-Path (Join-Path `$env:ProgramData 'NetShaper'))) {
  Remove-Item (Join-Path `$env:ProgramData 'NetShaper') -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'NetShaper uninstalled.'
"@ | Set-Content $uninst -Encoding UTF8
}
Set-ItemProperty $unreg -Name "UninstallString" -Value ("powershell.exe -ExecutionPolicy Bypass -File `"{0}`"" -f $uninst)
Set-ItemProperty $unreg -Name "NoModify" -Value 1 -Type DWord
Set-ItemProperty $unreg -Name "NoRepair" -Value 1 -Type DWord

# Copy installer helpers into install dir for re-runs
foreach ($n in @("Install.ps1", "Setup.cmd", "GETTING-STARTED.txt", "uninstall-app.ps1", "install-windivert.ps1")) {
  $p = Join-Path $SourceDir $n
  if (Test-Path $p) { Copy-Item $p $InstallDir -Force }
}

if ($AddToPath -and (Test-Path $cli)) {
  Write-Step "Add CLI to system PATH"
  $cliDir = Split-Path $cli
  $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
  if ($machinePath -notlike "*$cliDir*") {
    [Environment]::SetEnvironmentVariable("Path", $machinePath.TrimEnd(';') + ";" + $cliDir, "Machine")
    Write-Host "  Added: $cliDir"
  } else {
    Write-Host "  Already on PATH"
  }
}

if ($WinDivert) {
  Write-Step "Install WinDivert (packet mode)"
  $wdScript = Join-Path $PSScriptRoot "install-windivert.ps1"
  if (Test-Path $wdScript) {
    & $wdScript
  } else {
    # Inline minimal install if scripts folder not present (release zip)
    $dest = Join-Path $env:ProgramData "NetShaper\WinDivert"
    $wver = "2.2.2"
    $url = "https://github.com/basil00/WinDivert/releases/download/v$wver/WinDivert-$wver-A.zip"
    $zip = Join-Path $env:TEMP "WinDivert-$wver.zip"
    Write-Host "  Downloading WinDivert $wver ..."
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Expand-Archive -Path $zip -DestinationPath $dest -Force
    $dll = Get-ChildItem -Path $dest -Recurse -Filter "WinDivert.dll" | Select-Object -First 1
    if ($dll) {
      $out = Join-Path $dest "x64"
      New-Item -ItemType Directory -Path $out -Force | Out-Null
      Copy-Item (Join-Path $dll.DirectoryName "*") $out -Force
      Write-Host "  WinDivert ready: $out"
    }
  }
}

Write-Host ""
Write-Host "  Installed NetShaper $ver" -ForegroundColor Green
Write-Host "  App:       $exe"
Write-Host "  Start:     Start Menu → NetShaper  (or Desktop shortcut)"
Write-Host "  Uninstall: Apps & Features → NetShaper"
Write-Host ""
Write-Host "  Tip: Run as Administrator for full limits & firewall."
Write-Host ""

if ($StartApp) {
  Start-Process -FilePath $exe -WorkingDirectory $InstallDir
}
