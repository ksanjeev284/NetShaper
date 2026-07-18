<#
.SYNOPSIS
  Authenticode-sign a file (EXE/SYS/MSIX/DLL) with best available credential.

  Resolution order:
    1. -Thumbprint / $env:NETSHAPER_SIGN_THUMBPRINT  (EV or store cert — production)
    2. -PfxPath + password / $env:NETSHAPER_SIGN_PFX + NETSHAPER_SIGN_PFX_PASSWORD
    3. ProgramData NetShaper code-sign PFX (dev/test self-signed from ensure-codesign-cert.ps1)
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$Path,
  [string]$PfxPath = "",
  [string]$PfxPassword = "",
  [string]$Thumbprint = "",
  [string]$TimestampUrl = "http://timestamp.digicert.com",
  [switch]$SkipTimestamp
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $Path)) { throw "File not found: $Path" }

function Find-SignTool {
  @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
    "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
  ) | ForEach-Object { Get-Item $_ -ErrorAction SilentlyContinue } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
}

$signtool = Find-SignTool
if (-not $signtool) {
  throw "signtool.exe not found. Install Windows SDK (Signing Tools)."
}

if (-not $Thumbprint) { $Thumbprint = $env:NETSHAPER_SIGN_THUMBPRINT }
if (-not $PfxPath) { $PfxPath = $env:NETSHAPER_SIGN_PFX }
if (-not $PfxPassword) { $PfxPassword = $env:NETSHAPER_SIGN_PFX_PASSWORD }

$mode = $null
$args = @("sign", "/fd", "SHA256", "/td", "SHA256")

if ($Thumbprint) {
  $mode = "store-thumbprint:$Thumbprint"
  $args += @("/sha1", $Thumbprint)
} else {
  if (-not $PfxPath) {
    $def = Join-Path $env:ProgramData "NetShaper\signing\NetShaper-CodeSign.pfx"
    if (Test-Path $def) { $PfxPath = $def }
  }
  if (-not $PfxPath -or -not (Test-Path $PfxPath)) {
    Write-Host "No signing cert. Creating dev code-sign cert..."
    & (Join-Path $PSScriptRoot "ensure-codesign-cert.ps1")
    $PfxPath = Join-Path $env:ProgramData "NetShaper\signing\NetShaper-CodeSign.pfx"
  }
  if (-not $PfxPassword) {
    $pwdFile = Join-Path $env:ProgramData "NetShaper\signing\codesign-password.txt"
    if (Test-Path $pwdFile) {
      $PfxPassword = (Get-Content $pwdFile | Where-Object { $_ -and $_ -notmatch '^\s*#' } | Select-Object -First 1).Trim()
    }
  }
  if (-not $PfxPassword) { throw "PFX password required (file or NETSHAPER_SIGN_PFX_PASSWORD)" }
  $mode = "pfx:$PfxPath"
  $args += @("/f", $PfxPath, "/p", $PfxPassword)
}

if (-not $SkipTimestamp -and $TimestampUrl) {
  $args += @("/tr", $TimestampUrl)
}

$args += $Path
Write-Host "Signing ($mode) → $Path"
& $signtool.FullName @args
if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }

& $signtool.FullName verify /pa $Path 2>$null
if ($LASTEXITCODE -eq 0) {
  Write-Host "Verify OK (Authenticode)"
} else {
  Write-Warning "signtool verify reported issues (common for self-signed without full trust chain)."
}
