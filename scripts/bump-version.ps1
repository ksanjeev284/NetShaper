#Requires -Version 5.1
<#
.SYNOPSIS
  Bump product version in Directory.Build.props (and MSIX default).

.EXAMPLE
  powershell -File scripts\bump-version.ps1 -Version 0.4.3
  powershell -File scripts\bump-version.ps1 -Patch   # 0.4.2 -> 0.4.3
  powershell -File scripts\bump-version.ps1 -Minor   # 0.4.2 -> 0.5.0
#>
param(
  [string]$Version = "",
  [switch]$Patch,
  [switch]$Minor,
  [switch]$Major
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$props = Join-Path $Root "Directory.Build.props"
$cur = & (Join-Path $PSScriptRoot "Get-Version.ps1")

if ($Version) {
  $new = $Version.Trim()
} else {
  $parts = $cur.Split('.') | ForEach-Object { [int]$_ }
  while ($parts.Count -lt 3) { $parts += 0 }
  if ($Major) { $parts[0]++; $parts[1]=0; $parts[2]=0 }
  elseif ($Minor) { $parts[1]++; $parts[2]=0 }
  else { $parts[2]++ }  # default Patch
  $new = "$($parts[0]).$($parts[1]).$($parts[2])"
}

if ($new -notmatch '^\d+\.\d+\.\d+$') {
  throw "Version must look like 1.2.3 (got: $new)"
}

Write-Host "Version: $cur -> $new"

$text = Get-Content $props -Raw
$text = [regex]::Replace($text, '<Version>[^<]+</Version>', "<Version>$new</Version>")
$text = [regex]::Replace($text, '<AssemblyVersion>[^<]+</AssemblyVersion>', "<AssemblyVersion>$new.0</AssemblyVersion>")
$text = [regex]::Replace($text, '<FileVersion>[^<]+</FileVersion>', "<FileVersion>$new.0</FileVersion>")
Set-Content $props $text -Encoding UTF8 -NoNewline
# ensure trailing newline
Add-Content $props ""

# MSIX template default (build-msix also patches at pack time)
$msix = Join-Path $Root "packaging\msix\AppxManifest.xml"
if (Test-Path $msix) {
  $m = Get-Content $msix -Raw
  $m = [regex]::Replace($m, 'Version="[\d.]+"', "Version=`"$new.0`"")
  Set-Content $msix $m -Encoding UTF8
  Write-Host "Updated packaging\msix\AppxManifest.xml -> $new.0"
}

# Inno default fallback define (inside #ifndef)
$iss = Join-Path $PSScriptRoot "NetShaper.iss"
if (Test-Path $iss) {
  $i = Get-Content $iss -Raw
  $i = [regex]::Replace($i, '(#define MyAppVersion ")[\d.]+(")', "`${1}$new`${2}")
  [IO.File]::WriteAllText($iss, $i)
  Write-Host "Updated scripts\NetShaper.iss default -> $new"
}

Write-Host ""
Write-Host "Next:"
Write-Host "  1. powershell -File scripts\preflight.ps1"
Write-Host "  2. powershell -File scripts\release.ps1"
Write-Host "Done. v$new"
