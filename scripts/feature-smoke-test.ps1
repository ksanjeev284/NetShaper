<#
.SYNOPSIS
  End-to-end feature smoke test for NetShaper (CLI + Core surfaces).
  Run from repo root:  powershell -File scripts\feature-smoke-test.ps1
  Optional: -PublishDir dist\NetShaper-win-x64\cli  to test published binary
#>
param(
  [string]$PublishDir = "",
  [switch]$SkipAdminOps
)

$ErrorActionPreference = "Continue"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$results = [System.Collections.Generic.List[object]]::new()
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)

function Add-Result($area, $feature, $status, $detail = "") {
  $script:results.Add([pscustomobject]@{
    Area = $area
    Feature = $feature
    Status = $status
    Detail = ($detail -replace '\s+', ' ').Trim().Substring(0, [Math]::Min(160, (($detail -replace '\s+', ' ').Trim().Length)))
  }) | Out-Null
  $color = switch ($status) {
    "PASS" { "Green" }
    "FAIL" { "Red" }
    "SKIP" { "Yellow" }
    "WARN" { "DarkYellow" }
    default { "Gray" }
  }
  Write-Host ("[{0}] {1,-12} {2,-40} {3}" -f $status, $area, $feature, $detail) -ForegroundColor $color
}

function Invoke-Cli {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$CliArgs,
    [int]$TimeoutSec = 90
  )
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:cliExe
    $psi.WorkingDirectory = $Root.Path
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    # Arguments as single string for .NET ProcessStartInfo
    $psi.Arguments = ($CliArgs | ForEach-Object {
      $a = "$_"
      if ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' } else { $a }
    }) -join ' '

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    # Async read to avoid deadlock
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
      try { $p.Kill() } catch {}
      return @{ Code = -1; Out = ""; Err = "timeout ${TimeoutSec}s" }
    }
    $out = $outTask.GetAwaiter().GetResult()
    $err = $errTask.GetAwaiter().GetResult()
    return @{ Code = $p.ExitCode; Out = [string]$out; Err = [string]$err }
  } catch {
    return @{ Code = -2; Out = ""; Err = "$_" }
  }
}

function Test-CliOk {
  param(
    [string]$Area,
    [string]$Feature,
    [string[]]$CliArgs,
    [scriptblock]$Check = $null,
    [int[]]$OkCodes = @(0, 4)  # 4 = sample without EStats (still OK)
  )
  $r = Invoke-Cli -CliArgs $CliArgs
  $text = (($r.Out + "`n" + $r.Err).Trim())
  if ($OkCodes -notcontains $r.Code) {
    Add-Result $Area $Feature "FAIL" "exit=$($r.Code) $text"
    return $r
  }
  if ($Check) {
    try {
      $c = & $Check $r
      if (-not $c) {
        Add-Result $Area $Feature "FAIL" "check failed: $text"
        return $r
      }
    } catch {
      Add-Result $Area $Feature "FAIL" "check threw: $_"
      return $r
    }
  }
  $snip = if ($text.Length -gt 0) { $text.Substring(0, [Math]::Min(100, $text.Length)) } else { "ok" }
  Add-Result $Area $Feature "PASS" $snip
  return $r
}

# ── resolve CLI ──────────────────────────────────────────────
if ($PublishDir -and (Test-Path (Join-Path $PublishDir "NetShaper.Cli.exe"))) {
  $cliExe = (Resolve-Path (Join-Path $PublishDir "NetShaper.Cli.exe")).Path
  Write-Host "Using published CLI: $cliExe"
} else {
  Write-Host "Building Release CLI..."
  dotnet build (Join-Path $Root "NetShaper.Cli\NetShaper.Cli.csproj") -c Release --nologo -v q
  if ($LASTEXITCODE -ne 0) { throw "build failed" }
  $cliExe = Join-Path $Root "NetShaper.Cli\bin\Release\net8.0\NetShaper.Cli.exe"
  if (-not (Test-Path $cliExe)) { throw "CLI missing: $cliExe" }
}

Write-Host "Admin=$isAdmin  CLI=$cliExe"
Write-Host ("=" * 72)

# ── Build / package presence ─────────────────────────────────
$guiCs = Test-Path (Join-Path $Root "NetShaper.Gui\MainWindow.xaml")
$coreCs = Test-Path (Join-Path $Root "NetShaper.Core\Traffic\WindowsTrafficSampler.cs")
Add-Result "Build" "Solution projects present" $(if ($guiCs -and $coreCs) { "PASS" } else { "FAIL" }) "Gui=$guiCs Core=$coreCs"

$pubExe = Join-Path $Root "dist\NetShaper-win-x64\NetShaper.exe"
if (Test-Path $pubExe) {
  $ver = [Diagnostics.FileVersionInfo]::GetVersionInfo($pubExe).FileVersion
  Add-Result "Build" "Published GUI binary" "PASS" "v$ver"
} else {
  Add-Result "Build" "Published GUI binary" "WARN" "dist\NetShaper-win-x64\NetShaper.exe missing (run publish.ps1)"
}

# ── GUI feature inventory (static) ───────────────────────────
$xaml = Get-Content (Join-Path $Root "NetShaper.Gui\MainWindow.xaml") -Raw
$tabs = @("Dashboard","Live traffic","DNS","Rules","Limits","Quotas","History","Filters","Tools","Activity","Settings")
foreach ($t in $tabs) {
  $ok = $xaml -match [regex]::Escape("Header=`"$t`"")
  Add-Result "GUI" "Tab: $t" $(if ($ok) { "PASS" } else { "FAIL" }) $(if ($ok) { "present" } else { "missing in XAML" })
}

$guiBits = @{
  "Top talkers rates/data" = "TopTalkersGrid"
  "Live process rates/data" = "ProcessGrid"
  "Connections grid" = "ConnectionGrid"
  "Rule templates" = "TemplatesList"
  "Ask firewall UI" = "ChkAskMode"
  "Lockdown UI" = "ChkLockdown"
  "Local API UI" = "ApiCopyKey_Click"
  "mTLS certs UI" = "CertsEnsure_Click"
  "Driver UI" = "DriverPush_Click"
  "ACL UI" = "AclAdd_Click"
  "History export" = "HistoryExportSystem_Click"
  "WinDivert probe" = "ProbeWinDivert_Click"
  "Profiles" = "ProfileCombo"
  "Import/Export policy" = "ExportPolicy_Click"
}
foreach ($k in $guiBits.Keys) {
  $ok = $xaml -match $guiBits[$k]
  Add-Result "GUI" $k $(if ($ok) { "PASS" } else { "FAIL" }) $guiBits[$k]
}

# ── Policy / rules ───────────────────────────────────────────
Test-CliOk -Area "Policy" -Feature "list" -CliArgs @("list") -Check { param($r) $r.Out -match "Filters|Rules|Policy" }
Test-CliOk -Area "Policy" -Feature "policy show" -CliArgs @("policy","show") -Check { param($r) $r.Out -match "version|filters|rules" }
Test-CliOk -Area "Policy" -Feature "limits list" -CliArgs @("limits")
Test-CliOk -Area "Policy" -Feature "quotas list" -CliArgs @("quotas")

# Mutating but reversible tests on a unique fragment
$frag = "ns-smoke-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
Test-CliOk -Area "Policy" -Feature "block rule create" -CliArgs @("block", $frag)
Test-CliOk -Area "Policy" -Feature "allow rule create" -CliArgs @("allow", ($frag + "-allow"))
Test-CliOk -Area "Policy" -Feature "limit rule create" -CliArgs @("limit", $frag, "1000")
Test-CliOk -Area "Policy" -Feature "disable matching" -CliArgs @("disable", $frag)
Test-CliOk -Area "Policy" -Feature "enable matching" -CliArgs @("enable", $frag)
Test-CliOk -Area "Policy" -Feature "unblock matching" -CliArgs @("unblock", $frag)

# Export / import round-trip
$tmp = Join-Path $env:TEMP "netshaper-smoke-policy.json"
$r = Invoke-Cli -CliArgs @("export", $tmp)
if ($r.Code -eq 0 -and (Test-Path $tmp)) {
  Add-Result "Policy" "export JSON" "PASS" $tmp
  $r2 = Invoke-Cli -CliArgs @("import", $tmp)
  if ($r2.Code -eq 0) { Add-Result "Policy" "import JSON" "PASS" "ok" }
  else { Add-Result "Policy" "import JSON" "FAIL" $r2.Err }
} else {
  Add-Result "Policy" "export JSON" "FAIL" "$($r.Code) $($r.Err)"
}

# Domain rules
Test-CliOk -Area "DNS" -Feature "block-domain store" -CliArgs @("block-domain", "smoke-test.invalid")
Test-CliOk -Area "DNS" -Feature "allow-domain store" -CliArgs @("allow-domain", "example.com")
Test-CliOk -Area "DNS" -Feature "dns list/refresh" -CliArgs @("dns", "refresh")

# ── Traffic sampling ─────────────────────────────────────────
$r = Invoke-Cli -CliArgs @("sample", "1.2") -TimeoutSec 30
if ($r.Out -match "System" -and ($r.Out -match "Process" -or $r.Out -match "PID")) {
  $hasRate = $r.Out -match "\d+(\.\d+)?\s*(b/s|Kb/s|Mb/s)"
  $hasData = $r.Out -match "\d+(\.\d+)?\s*(B|KB|MB)"
  $hasSvc = $r.Out -match "\["
  $sysLine = ($r.Out -split "`r?`n" | Where-Object { $_ -match "System" } | Select-Object -First 1)
  Add-Result "Traffic" "sample system totals" $(if ($hasRate) { "PASS" } else { "FAIL" }) $sysLine
  Add-Result "Traffic" "sample process rows" "PASS" "apps listed"
  Add-Result "Traffic" "sample rates present" $(if ($hasRate) { "PASS" } else { "WARN" }) "NIC-share or EStats"
  Add-Result "Traffic" "sample data present" $(if ($hasData) { "PASS" } else { "WARN" }) "session/EStats bytes"
  Add-Result "Traffic" "service name enrichment" $(if ($hasSvc) { "PASS" } else { "WARN" }) "svchost [Service]"
} else {
  Add-Result "Traffic" "sample command" "FAIL" "exit=$($r.Code) $($r.Err) $($r.Out)"
}

# ── Shaper modes ─────────────────────────────────────────────
Test-CliOk -Area "Shaper" -Feature "show mode" -CliArgs @("shaper")
Test-CliOk -Area "Shaper" -Feature "set soft" -CliArgs @("shaper", "soft")
Test-CliOk -Area "Shaper" -Feature "set aggressive" -CliArgs @("shaper", "aggressive")
Test-CliOk -Area "Shaper" -Feature "set qos" -CliArgs @("shaper", "qos")
Test-CliOk -Area "Shaper" -Feature "probe windivert" -CliArgs @("shaper", "probe")
Test-CliOk -Area "Shaper" -Feature "set off" -CliArgs @("shaper", "off")

# ── Stats ────────────────────────────────────────────────────
Test-CliOk -Area "Stats" -Feature "info" -CliArgs @("stats", "info") -Check { param($r) $r.Out -match "Path|Samples|stats" }
Test-CliOk -Area "Stats" -Feature "top" -CliArgs @("stats", "top")
$csv = Join-Path $env:TEMP "netshaper-smoke-stats.csv"
$r = Invoke-Cli -CliArgs @("stats", "export-system", $csv)
if ($r.Code -eq 0 -and (Test-Path $csv)) {
  Add-Result "Stats" "export-system CSV" "PASS" ((Get-Item $csv).Length.ToString() + " bytes")
} else {
  Add-Result "Stats" "export-system CSV" "WARN" "exit=$($r.Code) $($r.Err)"
}

# ── API / ACL / certs / driver ───────────────────────────────
Test-CliOk -Area "API" -Feature "show settings" -CliArgs @("api", "show") -Check { param($r) $r.Out -match "Local|Key|Remote" }
Test-CliOk -Area "API" -Feature "enable local" -CliArgs @("api", "enable")
Test-CliOk -Area "API" -Feature "disable local" -CliArgs @("api", "disable")

Test-CliOk -Area "ACL" -Feature "show" -CliArgs @("access", "show")
Test-CliOk -Area "Certs" -Feature "status" -CliArgs @("certs", "status")
try {
  $r = Invoke-Cli -CliArgs @("certs", "ensure", "--server", $env:COMPUTERNAME) -TimeoutSec 90
  if ($r.Code -eq 0) {
    Add-Result "Certs" "ensure PKI" "PASS" "CA/server ready"
    $r2 = Invoke-Cli -CliArgs @("certs", "issue", "smoke-client")
    if ($r2.Code -eq 0) { Add-Result "Certs" "issue client" "PASS" "smoke-client" }
    else { Add-Result "Certs" "issue client" "FAIL" $r2.Err }
  } else {
    Add-Result "Certs" "ensure PKI" "WARN" "exit=$($r.Code) $($r.Err) $($r.Out)"
  }
} catch {
  Add-Result "Certs" "ensure PKI" "WARN" "$_"
}

Test-CliOk -Area "Driver" -Feature "status" -CliArgs @("driver", "status")

# ── WFP / QoS (admin) ────────────────────────────────────────
if ($SkipAdminOps -or -not $isAdmin) {
  $r = Invoke-Cli -CliArgs @("wfp-status")
  if ($r.Code -eq 0) { Add-Result "WFP" "wfp-status" "PASS" $r.Out }
  else { Add-Result "WFP" "wfp-status" "SKIP" "needs admin (exit=$($r.Code))" }
  Add-Result "WFP" "apply-wfp" "SKIP" "needs admin"
  Add-Result "WFP" "apply-qos" "SKIP" "needs admin"
  Add-Result "WFP" "apply-all" "SKIP" "needs admin"
  Add-Result "WFP" "clear-wfp" "SKIP" "needs admin"
  Add-Result "WFP" "clear-qos" "SKIP" "needs admin"
} else {
  Test-CliOk -Area "WFP" -Feature "wfp-status" -CliArgs @("wfp-status") -OkCodes @(0)
  Test-CliOk -Area "WFP" -Feature "apply-wfp" -CliArgs @("apply-wfp", "--persist") -OkCodes @(0)
  Test-CliOk -Area "WFP" -Feature "apply-qos" -CliArgs @("apply-qos") -OkCodes @(0)
  Test-CliOk -Area "WFP" -Feature "apply-all" -CliArgs @("apply-all", "--persist") -OkCodes @(0)
  Test-CliOk -Area "WFP" -Feature "clear-qos" -CliArgs @("clear-qos") -OkCodes @(0)
  Test-CliOk -Area "WFP" -Feature "clear-wfp" -CliArgs @("clear-wfp", "--persist") -OkCodes @(0)
}

# ── Core files / driver sources ──────────────────────────────
$checks = @{
  "Callout driver source" = "driver\NetShaperCallout\driver.c"
  "IOCTL header" = "driver\include\ns_ioctl.h"
  "Driver client" = "NetShaper.Core\Driver\NetShaperDriverClient.cs"
  "Bandwidth shaper" = "NetShaper.Core\Shaping\BandwidthShaper.cs"
  "WinDivert shaper" = "NetShaper.Core\Shaping\WinDivert\WinDivertShaper.cs"
  "WFP engine" = "NetShaper.Core\Wfp\WfpFilterEngine.cs"
  "Stats store" = "NetShaper.Core\Stats\StatsStore.cs"
  "DNS cache" = "NetShaper.Core\Dns\DnsCache.cs"
  "Ask firewall" = "NetShaper.Core\Firewall\AskFirewall.cs"
  "Remote API mTLS" = "NetShaper.Core\Api\RemoteApiServer.cs"
  "Local API" = "NetShaper.Core\Api\LocalApiServer.cs"
  "Certificate manager" = "NetShaper.Core\Api\CertificateManager.cs"
  "Access control" = "NetShaper.Core\Security\AccessControl.cs"
  "Traffic engine MT" = "NetShaper.Core\Traffic\TrafficSampleEngine.cs"
  "Service map" = "NetShaper.Core\Traffic\ServiceProcessMap.cs"
  "Windows Service host" = "NetShaper.Service\Worker.cs"
  "MSIX manifest" = "packaging\msix\AppxManifest.xml"
  "Publish script" = "scripts\publish.ps1"
  "MSIX script" = "scripts\build-msix.ps1"
  "Certs script" = "scripts\generate-certs.ps1"
  "Sign script" = "scripts\sign-file.ps1"
}
foreach ($k in $checks.Keys) {
  $p = Join-Path $Root $checks[$k]
  Add-Result "Core" $k $(if (Test-Path $p) { "PASS" } else { "FAIL" }) $checks[$k]
}

# ── Summary ──────────────────────────────────────────────────
Write-Host ("=" * 72)
$pass = ($results | Where-Object Status -eq "PASS").Count
$fail = ($results | Where-Object Status -eq "FAIL").Count
$skip = ($results | Where-Object Status -eq "SKIP").Count
$warn = ($results | Where-Object Status -eq "WARN").Count
$total = $results.Count

Write-Host "TOTAL=$total  PASS=$pass  FAIL=$fail  WARN=$warn  SKIP=$skip  Admin=$isAdmin"

$reportDir = Join-Path $Root "dist"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
$reportPath = Join-Path $reportDir "FEATURE-TEST-REPORT.md"
$csvPath = Join-Path $reportDir "feature-test-results.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$md = @()
$md += "# NetShaper feature smoke report"
$md += ""
$md += "- When: $(Get-Date -Format o)"
$md += "- Admin: $isAdmin"
$md += "- CLI: ``$cliExe``"
$md += "- Score: **$pass/$total PASS**, $fail FAIL, $warn WARN, $skip SKIP"
$md += ""
$md += "| Area | Feature | Status | Detail |"
$md += "|------|---------|--------|--------|"
foreach ($row in $results) {
  $d = ($row.Detail -replace '\|', '/' -replace "`n", " ")
  $md += "| $($row.Area) | $($row.Feature) | $($row.Status) | $d |"
}
$md += ""
$md += "## Notes"
$md += "- SKIP on WFP/QoS apply when not elevated is expected."
$md += "- sample exit code 4 = EStats not active; NIC-share rates still valid."
$md += "- Re-run elevated: ``powershell -File scripts\feature-smoke-test.ps1`` from admin shell."
$md -join "`n" | Set-Content $reportPath -Encoding UTF8

Write-Host "Report: $reportPath"
Write-Host "CSV:    $csvPath"

if ($fail -gt 0) { exit 1 } else { exit 0 }
