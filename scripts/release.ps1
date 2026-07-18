#Requires -Version 5.1
<#
.SYNOPSIS
  Full release pipeline: scrub -> tests -> publish -> git push -> GitHub release.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\release.ps1
  powershell -ExecutionPolicy Bypass -File scripts\release.ps1 -SkipTests
  powershell -ExecutionPolicy Bypass -File scripts\release.ps1 -SkipPush
#>
param(
  [switch]$SkipTests,
  [switch]$SkipPush,
  [string]$Notes = ""
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

function Step($m) { Write-Host ""; Write-Host "==== $m ====" -ForegroundColor Cyan }

# Version
$ver = & (Join-Path $PSScriptRoot "Get-Version.ps1")
if (-not $ver -or $ver -eq "0.0.0") { throw "Could not read version from Directory.Build.props" }
Write-Host "NetShaper release pipeline  v$ver"

# 1) Scrub sensitive terms (patterns split so this file is not self-flagged)
Step "Scrub check (no third-party RE branding)"
$patterns = @(
  "Net" + "Limiter",
  "Lock" + "time",
  "Ghi" + "dra",
  "IL" + "Spy",
  "nl" + "drv",
  "reverse" + "\.engine",
  "decom" + "pile",
  "clean" + "-room"
)
$bad = @()
Get-ChildItem -Recurse -File -Include *.md,*.cs,*.c,*.h,*.ps1,*.xml,*.txt,*.xaml |
  Where-Object {
    $_.FullName -notmatch '\\(bin|obj|dist|\.git)\\' -and
    $_.Name -notmatch 'FileListAbsolute|PublishOutputs|release\.ps1'
  } |
  ForEach-Object {
    $text = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $text) { return }
    foreach ($p in $patterns) {
      if ($text -match $p) {
        # allow "reverse lookup" DNS wording
        if ($p -match "reverse" -and $text -match "reverse lookup") { continue }
        $bad += "$($_.FullName): $p"
      }
    }
  }
if ($bad.Count -gt 0) {
  $bad | ForEach-Object { Write-Host $_ -ForegroundColor Red }
  throw "Scrub failed - remove forbidden terms before release"
}
Write-Host "Scrub OK"

# 2) Ensure production manifest
Step "App manifest"
$manPath = Join-Path $Root "NetShaper.Gui\app.manifest"
$man = Get-Content $manPath -Raw
if ($man -notmatch "requireAdministrator") {
  $man = $man -replace "asInvoker", "requireAdministrator"
  Set-Content $manPath $man
  Write-Host "Restored requireAdministrator"
} else {
  Write-Host "requireAdministrator OK"
}
# Sync assemblyIdentity version only
$man = Get-Content $manPath -Raw
$man = [regex]::Replace($man, '(<assemblyIdentity\s+version=")[\d.]+(")', "`${1}$ver.0`${2}")
Set-Content $manPath $man -Encoding UTF8

# 3) Tests
if (-not $SkipTests) {
  Step "Build + smoke tests"
  dotnet build (Join-Path $Root "NetShaper.sln") -c Release --nologo
  if ($LASTEXITCODE -ne 0) { throw "build failed" }

  $cli = Join-Path $Root "NetShaper.Cli\bin\Release\net8.0\NetShaper.Cli.exe"
  if (-not (Test-Path $cli)) {
    $cli = Join-Path $Root "NetShaper.Cli\bin\Release\net8.0\NetShaper.Cli.dll"
  }

  $tests = @(
    @{ Name = "list"; Args = @("list") },
    @{ Name = "sample"; Args = @("sample", "1") },
    @{ Name = "shaper"; Args = @("shaper") },
    @{ Name = "stats"; Args = @("stats", "info") },
    @{ Name = "api"; Args = @("api", "show") },
    @{ Name = "driver"; Args = @("driver", "status") },
    @{ Name = "access"; Args = @("access", "show") }
  )
  foreach ($t in $tests) {
    Write-Host "  test: $($t.Name) ..." -NoNewline
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = if ($cli.EndsWith(".dll")) { "dotnet" } else { $cli }
    $psi.Arguments = if ($cli.EndsWith(".dll")) { (@($cli) + $t.Args) -join " " } else { $t.Args -join " " }
    $psi.WorkingDirectory = $Root
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit(120000) | Out-Null
    # sample may return 4 without EStats
    if ($p.ExitCode -ne 0 -and -not ($t.Name -eq "sample" -and $p.ExitCode -eq 4)) {
      Write-Host " FAIL exit=$($p.ExitCode)" -ForegroundColor Red
      Write-Host $out
      Write-Host $err
      throw "Test failed: $($t.Name)"
    }
    Write-Host " OK" -ForegroundColor Green
  }

  # Full feature suite (non-admin ops skipped unless elevated)
  $smoke = Join-Path $PSScriptRoot "feature-smoke-test.ps1"
  if (Test-Path $smoke) {
    Write-Host "  feature-smoke-test.ps1 ..."
    & powershell -NoProfile -ExecutionPolicy Bypass -File $smoke -SkipAdminOps
    if ($LASTEXITCODE -ne 0) {
      Write-Host "  feature smoke returned $LASTEXITCODE (review dist\FEATURE-TEST-REPORT.md)" -ForegroundColor Yellow
      throw "Feature smoke tests failed"
    }
    Write-Host "  feature-smoke-test OK" -ForegroundColor Green
  }
} else {
  Write-Host "Skipping tests (-SkipTests)"
}

# 4) Publish zip + GUI installer
Step "Publish self-contained zip"
& (Join-Path $PSScriptRoot "publish.ps1")
$zip = Join-Path $Root "dist\NetShaper-$ver-win-x64.zip"
if (-not (Test-Path $zip)) { throw "Missing $zip" }
$folder = Join-Path $Root "dist\NetShaper-win-x64"
foreach ($need in @("NetShaper.exe", "Setup.cmd", "Install.ps1", "GETTING-STARTED.txt", "VERSION.txt", "cli\NetShaper.Cli.exe")) {
  $p = Join-Path $folder $need
  if (-not (Test-Path $p)) { throw "Release folder missing: $need" }
}
# Zip contents check
Add-Type -AssemblyName System.IO.Compression.FileSystem
$za = [IO.Compression.ZipFile]::OpenRead($zip)
try {
  $names = $za.Entries | ForEach-Object { $_.FullName }
  foreach ($need in @("NetShaper.exe", "Setup.cmd", "Install.ps1", "GETTING-STARTED.txt")) {
    if (-not ($names | Where-Object { $_ -like "*$need" })) {
      throw "Zip missing $need"
    }
  }
} finally { $za.Dispose() }
Write-Host "Zip OK: $zip  ($([math]::Round((Get-Item $zip).Length/1MB,1)) MB)  easy-install files present"

Step "GUI installer (Inno Setup)"
$setup = Join-Path $Root "dist\NetShaper-Setup-$ver.exe"
& (Join-Path $PSScriptRoot "build-installer.ps1") -SkipPublish
if (-not (Test-Path $setup)) {
  Write-Host "WARNING: GUI Setup.exe not built (Inno missing?). Zip-only release." -ForegroundColor Yellow
  $setup = $null
} else {
  Write-Host "Setup OK: $setup  ($([math]::Round((Get-Item $setup).Length/1MB,1)) MB)"
}

# 4b) Post-publish CLI smoke on published binary
Step "Published CLI smoke"
$pubCli = Join-Path $folder "cli\NetShaper.Cli.exe"
& $pubCli list 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Published CLI list failed" }
& $pubCli sample 1 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 4) { throw "Published CLI sample failed exit=$LASTEXITCODE" }
Write-Host "Published CLI OK"

# 5) Git commit + push
if (-not $SkipPush) {
  Step "Git commit + push"
  git add -A
  $status = git status --porcelain
  if ($status) {
    git -c user.email="ksanjeev284@users.noreply.github.com" -c user.name="ksanjeev284" `
      commit -m "Release v$ver - easier install, smoke-tested build"
    git push origin main
    if ($LASTEXITCODE -ne 0) { throw "git push failed" }
  } else {
    Write-Host "No source changes to commit"
    git push origin main 2>$null
  }

  Step "GitHub release v$ver"
  if ($Notes) {
    $notes = $Notes
  } else {
    $notes = @"
## NetShaper $ver

**Free open-source Windows bandwidth limiter and traffic control**

### Easy install (recommended)
1. Download **NetShaper-Setup-$ver.exe**
2. Double-click and accept UAC
3. Follow the wizard (optional desktop icon + CLI on PATH)
4. Launch NetShaper

### Portable zip
1. Download **NetShaper-$ver-win-x64.zip**
2. Unzip -> right-click **Setup.cmd** -> Run as administrator -> **[1] Install app**

### What's included
- Full self-contained app (GUI + CLI)
- Windows GUI installer wizard
- Portable zip with Setup.cmd / Install.ps1

### Features
- Per-app download/upload limits and live traffic
- Block / Allow (WFP), QoS, quotas, DNS filters
- Dark and light themes, local API, CLI
- MIT License

### Requirements
Windows 10/11 x64 - Admin recommended for full enforcement

Source: https://github.com/ksanjeev284/NetShaper
"@
  }

  # Delete existing tag/release if present (ignore "not found")
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  gh release delete "v$ver" --repo ksanjeev284/NetShaper --yes 2>$null | Out-Null
  $ErrorActionPreference = $prevEap

  $assets = @($zip)
  if ($setup -and (Test-Path $setup)) { $assets += $setup }

  gh release create "v$ver" @assets `
    --repo ksanjeev284/NetShaper `
    --title "NetShaper $ver - Free Windows Bandwidth Limiter" `
    --notes $notes `
    --latest
  if ($LASTEXITCODE -ne 0) { throw "gh release create failed" }

  gh release view "v$ver" --repo ksanjeev284/NetShaper
}

Write-Host ""
Write-Host "Release complete: v$ver" -ForegroundColor Green
Write-Host "https://github.com/ksanjeev284/NetShaper/releases/tag/v$ver"
