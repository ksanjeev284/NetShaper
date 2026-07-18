#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Build a sideloadable MSIX package for NetShaper (full-trust desktop bridge style layout).
  Requires Windows SDK makeappx + signtool.

  Signing:
    -SelfSign  → persistent CN=NetShaper cert from ensure-codesign-cert.ps1
    Or set NETSHAPER_SIGN_THUMBPRINT / NETSHAPER_SIGN_PFX for production publisher cert
      (Publisher in AppxManifest must match cert subject CN).
#>
param(
  [switch]$SkipPublish,
  [switch]$SelfSign,
  [switch]$Sign  # sign with production env or existing codesign cert (no force-create)
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$ver = "0.3.3"
$pub = Join-Path $Root "dist\NetShaper-win-x64"
$stage = Join-Path $Root "dist\msix-stage"
$outMsix = Join-Path $Root "dist\NetShaper-$ver-x64.msix"

if (-not $SkipPublish) {
  & (Join-Path $PSScriptRoot "publish.ps1")
}

if (-not (Test-Path (Join-Path $pub "NetShaper.exe"))) {
  throw "Publish output missing: $pub"
}

if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stage "Assets") -Force | Out-Null

Copy-Item (Join-Path $pub "*") $stage -Recurse -Force
Copy-Item (Join-Path $Root "packaging\msix\AppxManifest.xml") $stage -Force

$png = Join-Path $Root "assets\NetShaper-256.png"
if (-not (Test-Path $png)) { throw "assets\NetShaper-256.png missing" }

function Resize-Png([string]$src, [string]$dst, [int]$w, [int]$h) {
  $img = [System.Drawing.Image]::FromFile($src)
  $bmp = New-Object System.Drawing.Bitmap $w, $h
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
  $g.DrawImage($img, 0, 0, $w, $h)
  $bmp.Save($dst, [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose(); $img.Dispose()
}

try {
  Add-Type -AssemblyName System.Drawing
  Resize-Png $png (Join-Path $stage "Assets\StoreLogo.png") 50 50
  Resize-Png $png (Join-Path $stage "Assets\Square44x44Logo.png") 44 44
  Resize-Png $png (Join-Path $stage "Assets\Square150x150Logo.png") 150 150
  Resize-Png $png (Join-Path $stage "Assets\Wide310x150Logo.png") 310 150
  Resize-Png $png (Join-Path $stage "Assets\SplashScreen.png") 620 300
} catch {
  Write-Warning "Resize via Drawing failed — copying 256 png as all logos"
  foreach ($n in @("StoreLogo.png","Square44x44Logo.png","Square150x150Logo.png","Wide310x150Logo.png","SplashScreen.png")) {
    Copy-Item $png (Join-Path $stage "Assets\$n") -Force
  }
}

$makeappx = @(
  "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe",
  "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\makeappx.exe"
) | ForEach-Object { Get-Item $_ -ErrorAction SilentlyContinue } | Sort-Object FullName -Descending | Select-Object -First 1

if (-not $makeappx) {
  Write-Warning "makeappx.exe not found (install Windows SDK). Staged package folder: $stage"
  Write-Host "You can pack later: makeappx pack /d `"$stage`" /p `"$outMsix`""
  exit 0
}

if (Test-Path $outMsix) { Remove-Item $outMsix -Force }
& $makeappx.FullName pack /d $stage /p $outMsix /o
if ($LASTEXITCODE -ne 0) { throw "makeappx failed" }

$doSign = $SelfSign -or $Sign -or $env:NETSHAPER_SIGN_THUMBPRINT -or $env:NETSHAPER_SIGN_PFX
if ($doSign) {
  if ($SelfSign -or (-not $env:NETSHAPER_SIGN_THUMBPRINT -and -not $env:NETSHAPER_SIGN_PFX)) {
    & (Join-Path $PSScriptRoot "ensure-codesign-cert.ps1")
  }
  & (Join-Path $PSScriptRoot "sign-file.ps1") -Path $outMsix
  Write-Host "Trust cert (once per machine): powershell -File scripts\trust-codesign-cert.ps1"
}

Write-Host "MSIX: $outMsix"
Write-Host "Install: Add-AppxPackage -Path `"$outMsix`""
