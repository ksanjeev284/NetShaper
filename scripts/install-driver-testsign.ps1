#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install NetShaperCallout.sys as a kernel service (test-signed or unsigned in test mode).
#>
param(
  [string]$SysPath = ""
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")

if (-not $SysPath) {
  $candidates = @(
    (Join-Path $Root "driver\NetShaperCallout\x64\Release\NetShaperCallout.sys"),
    (Join-Path $Root "driver\NetShaperCallout\x64\Debug\NetShaperCallout.sys"),
    (Join-Path $env:ProgramData "NetShaper\driver\NetShaperCallout.sys")
  )
  $SysPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $SysPath -or -not (Test-Path $SysPath)) {
  throw "NetShaperCallout.sys not found. Build with WDK first (see driver\README.md)."
}

# Best-effort Authenticode sign (dev cert or EV via env) before install
$signScript = Join-Path $PSScriptRoot "sign-file.ps1"
if (Test-Path $signScript) {
  try {
    if (-not $env:NETSHAPER_SIGN_THUMBPRINT -and -not $env:NETSHAPER_SIGN_PFX) {
      $ensure = Join-Path $PSScriptRoot "ensure-codesign-cert.ps1"
      if (Test-Path $ensure) { & $ensure }
    }
    & $signScript -Path $SysPath -ErrorAction Stop
  } catch {
    Write-Warning "Could not sign driver (continuing): $_"
    Write-Host "  For self-signed load you still need: scripts\enable-testsigning.ps1"
  }
}

$destDir = Join-Path $env:ProgramData "NetShaper\driver"
New-Item -ItemType Directory -Path $destDir -Force | Out-Null
$dest = Join-Path $destDir "NetShaperCallout.sys"
Copy-Item $SysPath $dest -Force

$name = "NetShaperCallout"
$existing = sc.exe query $name 2>$null
if ($LASTEXITCODE -eq 0) {
  Write-Host "Stopping / deleting existing service..."
  sc.exe stop $name | Out-Null
  Start-Sleep 1
  sc.exe delete $name | Out-Null
  Start-Sleep 1
}

Write-Host "Creating kernel service $name"
sc.exe create $name type= kernel start= demand binPath= $dest DisplayName= "NetShaper Callout Driver"
if ($LASTEXITCODE -ne 0) { throw "sc create failed" }

sc.exe start $name
if ($LASTEXITCODE -ne 0) {
  Write-Warning "sc start failed — ensure testsigning is on and driver was built for this OS."
  Write-Host "Check: bcdedit | findstr testsigning"
} else {
  Write-Host "Driver started. Probe with: NetShaper.Cli driver status"
}

Get-Item $dest | Format-List FullName, Length, LastWriteTime
