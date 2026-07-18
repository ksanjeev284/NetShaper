#Requires -Version 5.1
<#
.SYNOPSIS
  Pre-release checklist: tools, version, build, CLI, features, publish, installer.
  Does NOT push or create a GitHub release.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\preflight.ps1
  powershell -ExecutionPolicy Bypass -File scripts\preflight.ps1 -SkipPublish
#>
param(
  [switch]$SkipPublish,
  [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$pass = 0; $fail = 0; $warn = 0
function Ok($m) { $script:pass++; Write-Host "  [PASS] $m" -ForegroundColor Green }
function Bad($m) { $script:fail++; Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Warn($m) { $script:warn++; Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Step($m) { Write-Host ""; Write-Host "==== $m ====" -ForegroundColor Cyan }

$ver = & (Join-Path $PSScriptRoot "Get-Version.ps1")
Write-Host "NetShaper preflight  v$ver" -ForegroundColor Cyan

# ── Tools ────────────────────────────────────────────────────
Step "Tools"
try {
  $dv = (dotnet --version 2>$null)
  if ($dv) { Ok "dotnet $dv" } else { Bad "dotnet missing" }
} catch { Bad "dotnet missing: $_" }

try {
  $gv = (git --version 2>$null)
  if ($gv) { Ok $gv } else { Bad "git missing" }
} catch { Bad "git missing" }

try {
  $gh = (gh --version 2>$null | Select-Object -First 1)
  if ($gh) {
    Ok $gh
    $auth = gh auth status 2>&1 | Out-String
    if ($auth -match "Logged in") { Ok "gh authenticated" } else { Warn "gh not logged in (needed for release push)" }
  } else { Warn "gh missing (needed for GitHub release)" }
} catch { Warn "gh missing" }

$iscc = @(
  "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
  "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
  "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) { Ok "Inno Setup: $iscc" } else { Warn "Inno Setup 6 missing - GUI Setup.exe will not build (winget install JRSoftware.InnoSetup)" }

# ── Version consistency ──────────────────────────────────────
Step "Version consistency"
if ($ver -and $ver -ne "0.0.0") { Ok "Directory.Build.props Version=$ver" } else { Bad "Version unreadable" }

$msix = Get-Content (Join-Path $Root "packaging\msix\AppxManifest.xml") -Raw
if ($msix -match "Version=`"$([regex]::Escape($ver))\.0`"") { Ok "AppxManifest Version matches $ver.0" }
elseif ($msix -match 'Version="([\d.]+)"') {
  if ($Matches[1].StartsWith($ver)) { Ok "AppxManifest $($Matches[1]) aligns with $ver" }
  else { Warn "AppxManifest Version=$($Matches[1]) vs product $ver (build-msix patches at pack time)" }
}

$iss = Get-Content (Join-Path $Root "scripts\NetShaper.iss") -Raw
if ($iss -match 'MyAppVersion') { Ok "NetShaper.iss present (version injected by build-installer)" } else { Bad "NetShaper.iss missing" }

# ── Scrub ────────────────────────────────────────────────────
Step "Scrub"
$patterns = @("Net"+"Limiter","Lock"+"time","Ghi"+"dra","IL"+"Spy","nl"+"drv","reverse"+"\.engine","decom"+"pile","clean"+"-room")
$bad = @()
Get-ChildItem -Recurse -File -Include *.md,*.cs,*.c,*.h,*.ps1,*.xml,*.txt,*.xaml |
  Where-Object {
    $_.FullName -notmatch '\\(bin|obj|dist|\.git)\\' -and
    $_.Name -notmatch 'FileListAbsolute|PublishOutputs|release\.ps1|preflight\.ps1'
  } | ForEach-Object {
    $text = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $text) { return }
    foreach ($p in $patterns) {
      if ($text -match $p) {
        if ($p -match "reverse" -and $text -match "reverse lookup") { continue }
        $bad += "$($_.Name): $p"
      }
    }
  }
if ($bad.Count -eq 0) { Ok "No forbidden branding terms" } else { $bad | ForEach-Object { Bad $_ } }

# ── Manifest ─────────────────────────────────────────────────
Step "App manifest"
$man = Get-Content (Join-Path $Root "NetShaper.Gui\app.manifest") -Raw
if ($man -match "requireAdministrator") { Ok "requireAdministrator" } else { Bad "app.manifest not requireAdministrator" }

# ── Build ────────────────────────────────────────────────────
Step "Build Release"
dotnet build (Join-Path $Root "NetShaper.sln") -c Release --nologo -v q
if ($LASTEXITCODE -eq 0) { Ok "Solution build" } else { Bad "Solution build failed"; throw "build failed" }

# ── CLI smoke ────────────────────────────────────────────────
Step "CLI smoke"
$cli = Join-Path $Root "NetShaper.Cli\bin\Release\net8.0\NetShaper.Cli.exe"
if (-not (Test-Path $cli)) { Bad "CLI exe missing"; throw "no CLI" }
Ok "CLI: $cli"

$cliTests = @(
  @{ N="list"; A=@("list"); Ok=@(0) },
  @{ N="sample"; A=@("sample","1"); Ok=@(0,4) },
  @{ N="shaper"; A=@("shaper"); Ok=@(0) },
  @{ N="stats info"; A=@("stats","info"); Ok=@(0) },
  @{ N="api show"; A=@("api","show"); Ok=@(0) },
  @{ N="driver status"; A=@("driver","status"); Ok=@(0) },
  @{ N="access show"; A=@("access","show"); Ok=@(0) },
  @{ N="profile list"; A=@("profile","list"); Ok=@(0) },
  @{ N="limits"; A=@("limits"); Ok=@(0) },
  @{ N="quotas"; A=@("quotas"); Ok=@(0) },
  @{ N="help"; A=@("help"); Ok=@(0,1) }
)
foreach ($t in $cliTests) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $cli
  $psi.Arguments = ($t.A -join " ")
  $psi.WorkingDirectory = $Root
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $p = [Diagnostics.Process]::Start($psi)
  $null = $p.StandardOutput.ReadToEnd()
  $null = $p.StandardError.ReadToEnd()
  $p.WaitForExit(90000) | Out-Null
  if ($t.Ok -contains $p.ExitCode) { Ok "cli $($t.N)" }
  else { Bad "cli $($t.N) exit=$($p.ExitCode)" }
}

# ── Feature smoke ────────────────────────────────────────────
Step "Feature smoke"
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "feature-smoke-test.ps1") -SkipAdminOps
if ($LASTEXITCODE -eq 0) { Ok "feature-smoke-test (0 FAIL)" }
else { Bad "feature-smoke-test failed - see dist\FEATURE-TEST-REPORT.md" }

# ── Publish + zip + installer ────────────────────────────────
if (-not $SkipPublish) {
  Step "Publish + zip"
  & (Join-Path $PSScriptRoot "publish.ps1")
  $folder = Join-Path $Root "dist\NetShaper-win-x64"
  $zip = Join-Path $Root "dist\NetShaper-$ver-win-x64.zip"
  foreach ($n in @("NetShaper.exe","Setup.cmd","Install.ps1","GETTING-STARTED.txt","VERSION.txt","cli\NetShaper.Cli.exe")) {
    if (Test-Path (Join-Path $folder $n)) { Ok "payload $n" } else { Bad "payload missing $n" }
  }
  if (Test-Path $zip) {
    $mb = [math]::Round((Get-Item $zip).Length/1MB,1)
    Ok "zip $mb MB"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $za = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
      $names = $za.Entries.FullName
      foreach ($need in @("NetShaper.exe","Setup.cmd","Install.ps1")) {
        if ($names | Where-Object { $_ -like "*$need" }) { Ok "zip has $need" } else { Bad "zip missing $need" }
      }
    } finally { $za.Dispose() }
  } else { Bad "zip missing" }

  # Published CLI
  $pubCli = Join-Path $folder "cli\NetShaper.Cli.exe"
  & $pubCli list 2>&1 | Out-Null
  if ($LASTEXITCODE -eq 0) { Ok "published CLI list" } else { Bad "published CLI list" }
  & $pubCli sample 1 2>&1 | Out-Null
  if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 4) { Ok "published CLI sample" } else { Bad "published CLI sample exit=$LASTEXITCODE" }
  & $pubCli profile list 2>&1 | Out-Null
  if ($LASTEXITCODE -eq 0) { Ok "published CLI profile list" } else { Bad "published CLI profile" }

  if (-not $SkipInstaller) {
    Step "GUI installer"
    if (-not $iscc) {
      Warn "Skip installer compile - Inno not installed"
    } else {
      & (Join-Path $PSScriptRoot "build-installer.ps1") -SkipPublish
      $setup = Join-Path $Root "dist\NetShaper-Setup-$ver.exe"
      if (Test-Path $setup) {
        $mb = [math]::Round((Get-Item $setup).Length/1MB,1)
        Ok "Setup.exe $mb MB"
        $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($setup)
        if ($vi.FileVersion -match [regex]::Escape($ver) -or $vi.ProductVersion -match [regex]::Escape($ver)) {
          Ok "Setup version info contains $ver"
        } else {
          Warn "Setup FileVersion=$($vi.FileVersion) ProductVersion=$($vi.ProductVersion)"
        }
        # Basic PE sanity
        $bytes = [IO.File]::ReadAllBytes($setup)
        if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) { Ok "Setup.exe is valid PE (MZ)" }
        else { Bad "Setup.exe not a PE file" }
      } else { Bad "Setup.exe not produced" }
    }
  }
} else {
  Write-Host "Skipping publish (-SkipPublish)"
}

# ── Scripts present ──────────────────────────────────────────
Step "Release scripts present"
foreach ($s in @(
  "release.ps1","publish.ps1","build-installer.ps1","Get-Version.ps1",
  "feature-smoke-test.ps1","Install-FromRelease.ps1","Setup.cmd",
  "GETTING-STARTED.txt","uninstall-app.ps1","NetShaper.iss","bump-version.ps1"
)) {
  if (Test-Path (Join-Path $PSScriptRoot $s)) { Ok "scripts\$s" } else { Bad "missing scripts\$s" }
}

# ── Summary ──────────────────────────────────────────────────
Write-Host ""
Write-Host ("=" * 60)
Write-Host "PREFLIGHT v$ver  PASS=$pass  FAIL=$fail  WARN=$warn" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
if ($fail -eq 0) {
  Write-Host "Ready for release:" -ForegroundColor Green
  Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\release.ps1"
  exit 0
} else {
  Write-Host "Fix FAIL items before release." -ForegroundColor Red
  exit 1
}
