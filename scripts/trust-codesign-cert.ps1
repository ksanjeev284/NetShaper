#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Trust the NetShaper code-signing public cert on this machine (TrustedPublisher + optional Root).
  Required for MSIX sideload and smoother Authenticode prompts with the dev cert.
#>
param(
  [switch]$IncludeRoot
)

$ErrorActionPreference = "Stop"
$cer = Join-Path $env:ProgramData "NetShaper\signing\NetShaper-CodeSign.cer"
if (-not (Test-Path $cer)) {
  & (Join-Path $PSScriptRoot "ensure-codesign-cert.ps1")
}
if (-not (Test-Path $cer)) { throw "CER missing: $cer" }

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cer

function Ensure-InStore([string]$storeName, [string]$location) {
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $location)
  $store.Open("ReadWrite")
  $hit = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
  if (-not $hit) {
    $store.Add($cert)
    Write-Host "Added to Cert:\${location}\${storeName}: $($cert.Thumbprint)"
  } else {
    Write-Host "Already in Cert:\${location}\${storeName}"
  }
  $store.Close()
}

Ensure-InStore "TrustedPublisher" "LocalMachine"
if ($IncludeRoot) {
  Ensure-InStore "Root" "LocalMachine"
  Write-Warning "Installed to LocalMachine\Root — only for dedicated dev machines."
}

# Developer mode / sideload hint
Write-Host ""
Write-Host "MSIX sideload also needs:"
Write-Host "  Settings → Privacy & security → For developers → Developer Mode  OR"
Write-Host "  Settings → Apps → Advanced app settings → Install apps from any source"
Write-Host "Then: Add-AppxPackage -Path dist\NetShaper-0.2.0-x64.msix"
