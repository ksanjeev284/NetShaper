#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Generate NetShaper local CA, server cert, and optional client cert for mTLS remote API.
  Creates a strong random PFX password on first run (saved under ProgramData\NetShaper\certs\).
#>
param(
  [string]$ClientName = "admin-client",
  [string]$ServerName = $env:COMPUTERNAME,
  [string]$Password = ""  # optional: set desired PFX password before first ensure
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")

if ($Password) {
  $env:NETSHAPER_PFX_PASSWORD = $Password
}

Write-Host "Generating mTLS PKI via NetShaper.Cli..."
Push-Location $Root
try {
  dotnet build NetShaper.Cli -c Release --nologo -v q
  if ($LASTEXITCODE -ne 0) { throw "build failed" }

  if ($Password) {
    # Seed password file via rotate-friendly ensure: write file first
    $certs = Join-Path $env:ProgramData "NetShaper\certs"
    New-Item -ItemType Directory -Path $certs -Force | Out-Null
    $pwdPath = Join-Path $certs "pki-password.txt"
    if (-not (Test-Path $pwdPath) -or -not (Test-Path (Join-Path $certs "netshaper-ca.pfx"))) {
      @"
# Seeded by generate-certs.ps1
$Password
"@ | Set-Content $pwdPath -Encoding UTF8
    }
  }

  dotnet run --project NetShaper.Cli -c Release --no-build -- certs ensure --server $ServerName
  if ($LASTEXITCODE -ne 0) { throw "certs ensure failed" }
  dotnet run --project NetShaper.Cli -c Release --no-build -- certs issue $ClientName
  if ($LASTEXITCODE -ne 0) { throw "certs issue failed" }
  dotnet run --project NetShaper.Cli -c Release --no-build -- certs status
} finally {
  Pop-Location
}

$certsDir = Join-Path $env:ProgramData "NetShaper\certs"
Write-Host ""
Write-Host "Certs directory: $certsDir"
Get-ChildItem $certsDir -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName, Length | Format-Table -AutoSize
Write-Host "Copy clients\$ClientName.pfx to remote machines (password in pki-password.txt or env NETSHAPER_PFX_PASSWORD)."
Write-Host "Rotate anytime: NetShaper.Cli certs rotate <newPassword>"
