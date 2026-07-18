#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Create or reuse a persistent self-signed code-signing certificate for NetShaper.

  Subject CN=NetShaper matches packaging\msix\AppxManifest.xml Publisher.

  Use for:
    - MSIX sideload signing
    - Test-signing NetShaperCallout.sys (with bcdedit testsigning on)
    - Signing installers / EXEs in dev

  Production kernel drivers still need a commercial EV cert + Microsoft attestation.
  Pass -EvPfx / -Thumbprint to other sign scripts when you have a real cert.
#>
param(
  [string]$Subject = "CN=NetShaper",
  [int]$Years = 5,
  [switch]$Force,
  [switch]$TrustLocalMachine
)

$ErrorActionPreference = "Stop"
$signDir = Join-Path $env:ProgramData "NetShaper\signing"
$pfx = Join-Path $signDir "NetShaper-CodeSign.pfx"
$cer = Join-Path $signDir "NetShaper-CodeSign.cer"
$pwdFile = Join-Path $signDir "codesign-password.txt"

New-Item -ItemType Directory -Path $signDir -Force | Out-Null

function New-StrongPassword([int]$Len = 32) {
  $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-".ToCharArray()
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $bytes = New-Object byte[] $Len
  $rng.GetBytes($bytes)
  -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

if ((Test-Path $pfx) -and -not $Force) {
  Write-Host "Reusing existing code-sign cert: $pfx"
  if (Test-Path $pwdFile) {
    $pass = (Get-Content $pwdFile | Where-Object { $_ -and $_ -notmatch '^\s*#' } | Select-Object -First 1).Trim()
  } else {
    throw "PFX exists but password file missing: $pwdFile — use -Force to regenerate"
  }
} else {
  if (Test-Path $pfx) { Remove-Item $pfx, $cer -Force -ErrorAction SilentlyContinue }

  $pass = New-StrongPassword 32
  @"
# NetShaper code-signing PFX password — Administrators only
# Used by sign-file.ps1 / build-msix.ps1 / sign-driver.ps1 (test path)
$pass
"@ | Set-Content -Path $pwdFile -Encoding UTF8

  $secure = ConvertTo-SecureString -String $pass -Force -AsPlainText
  # Code signing EKU 1.3.6.1.5.5.7.3.3
  $cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -KeyAlgorithm RSA `
    -KeyLength 4096 `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears($Years) `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyExportPolicy Exportable `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")

  Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $secure | Out-Null
  Export-Certificate -Cert $cert -FilePath $cer -Type CERT | Out-Null

  # Remove private key from store (we keep PFX on disk); keep public for trust optionally
  # Leave in store for /a signtool auto-select convenience
  Write-Host "Created code-sign cert:"
  Write-Host "  Subject:    $($cert.Subject)"
  Write-Host "  Thumbprint: $($cert.Thumbprint)"
  Write-Host "  PFX:        $pfx"
  Write-Host "  CER:        $cer"
}

# Trust for local sideload / Authenticode verify on this machine
$storeLocation = if ($TrustLocalMachine) { "Cert:\LocalMachine\Root" } else { "Cert:\LocalMachine\TrustedPublisher" }
try {
  $cerObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cer
  $storePath = if ($TrustLocalMachine) { "Cert:\LocalMachine\Root" } else { "Cert:\LocalMachine\TrustedPublisher" }
  $exists = Get-ChildItem $storePath -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $cerObj.Thumbprint }
  if (-not $exists) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
      $(if ($TrustLocalMachine) { "Root" } else { "TrustedPublisher" }), "LocalMachine")
    $store.Open("ReadWrite")
    $store.Add($cerObj)
    $store.Close()
    Write-Host "Installed public cert to $storePath"
  } else {
    Write-Host "Public cert already trusted in $storePath"
  }
} catch {
  Write-Warning "Could not install trust: $_"
}

# ACL: Admins + SYSTEM
foreach ($p in @($signDir, $pfx, $pwdFile)) {
  if (Test-Path $p) {
    icacls $p /inheritance:r /grant:r "*S-1-5-32-544:(F)" /grant:r "*S-1-5-18:(F)" 2>$null | Out-Null
  }
}

Write-Host ""
Write-Host "Next:"
Write-Host "  powershell -File scripts\sign-driver.ps1          # test-sign .sys if built"
Write-Host "  powershell -File scripts\build-msix.ps1 -SelfSign # uses this cert"
Write-Host "  Production EV: set NETSHAPER_SIGN_PFX / NETSHAPER_SIGN_THUMBPRINT — see packaging\CERTIFICATES.md"
