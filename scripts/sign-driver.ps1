#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Sign NetShaperCallout.sys for load.

  Dev (default): self-signed code-sign cert + Windows testsigning mode.
  Production: set NETSHAPER_SIGN_THUMBPRINT or NETSHAPER_SIGN_PFX to your EV cert,
              then complete Microsoft attestation / HLK separately (cannot be automated here).
#>
param(
  [string]$SysPath = "",
  [switch]$SkipTestSigningCheck
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
  throw "NetShaperCallout.sys not found. Build with WDK first (driver\README.md)."
}

# Ensure dev cert exists unless production env already set
if (-not $env:NETSHAPER_SIGN_THUMBPRINT -and -not $env:NETSHAPER_SIGN_PFX) {
  & (Join-Path $PSScriptRoot "ensure-codesign-cert.ps1")
}

& (Join-Path $PSScriptRoot "sign-file.ps1") -Path $SysPath

$usingEv = [bool]$env:NETSHAPER_SIGN_THUMBPRINT -or (
  $env:NETSHAPER_SIGN_PFX -and $env:NETSHAPER_SIGN_PFX -notmatch 'NetShaper-CodeSign')

if (-not $usingEv -and -not $SkipTestSigningCheck) {
  $ts = bcdedit /enum '{current}' 2>$null | Select-String "testsigning\s+Yes"
  if (-not $ts) {
    Write-Warning "testsigning is OFF. Self-signed .sys will not load on normal Windows."
    Write-Host "  Enable: powershell -File scripts\enable-testsigning.ps1  (reboot)"
    Write-Host "  Or use a commercial EV cert + Microsoft attestation for production."
  } else {
    Write-Host "testsigning is ON — self-signed driver may load after install."
  }
} elseif ($usingEv) {
  Write-Host "Signed with production credential env. Next: Microsoft attestation/HLK for your Windows targets."
  Write-Host "See packaging\CERTIFICATES.md"
}

Write-Host "Signed: $SysPath"
Write-Host "Install: powershell -File scripts\install-driver-testsign.ps1 -SysPath `"$SysPath`""
