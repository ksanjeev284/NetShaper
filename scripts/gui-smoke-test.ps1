# NetShaper GUI UI Automation smoke test
# Temporarily builds asInvoker so tests can launch without UAC; restores requireAdministrator after.
$ErrorActionPreference = "Continue"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$results = New-Object System.Collections.Generic.List[object]
function Add-GuiResult([string]$Feature, [string]$Status, [string]$Detail = "") {
  $results.Add([pscustomobject]@{ Feature = $Feature; Status = $Status; Detail = $Detail }) | Out-Null
  $col = switch ($Status) { "PASS" { "Green" } "FAIL" { "Red" } default { "Yellow" } }
  Write-Host ("[{0}] {1} - {2}" -f $Status, $Feature, $Detail) -ForegroundColor $col
}

$manifest = Join-Path $Root "NetShaper.Gui\app.manifest"
$bak = Join-Path $Root "NetShaper.Gui\app.manifest.bak-gui-test"
Copy-Item $manifest $bak -Force

try {
  $raw = [IO.File]::ReadAllText($manifest)
  if ($raw -match "requireAdministrator") {
    $raw2 = $raw.Replace("requireAdministrator", "asInvoker")
    [IO.File]::WriteAllText($manifest, $raw2)
  }

  Write-Host "Building GUI (asInvoker for automation)..."
  & dotnet build (Join-Path $Root "NetShaper.Gui\NetShaper.Gui.csproj") -c Release --nologo -v q
  if ($LASTEXITCODE -ne 0) { throw "GUI build failed" }

  Get-Process NetShaper -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep 1

  $exe = Join-Path $Root "NetShaper.Gui\bin\Release\net8.0-windows\NetShaper.exe"
  $proc = Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) -PassThru
  Write-Host "Started PID=$($proc.Id)"

  $deadline = (Get-Date).AddSeconds(25)
  while (-not $proc.HasExited -and $proc.MainWindowHandle -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 300
    $proc.Refresh()
  }
  Start-Sleep 2
  $proc.Refresh()

  if ($proc.HasExited) { throw "GUI exited early code=$($proc.ExitCode)" }
  if ($proc.MainWindowHandle -eq [IntPtr]::Zero) { throw "No MainWindowHandle" }

  Add-GuiResult "GUI running" "PASS" ("PID=" + $proc.Id)
  Add-GuiResult "Main window" "PASS" ("hwnd=" + $proc.MainWindowHandle + " title=" + $proc.MainWindowTitle)
  Add-GuiResult "Responding" $(if ($proc.Responding) { "PASS" } else { "FAIL" }) ("resp=" + $proc.Responding)

  Add-Type -AssemblyName UIAutomationClient
  Add-Type -AssemblyName UIAutomationTypes
  Add-Type -AssemblyName System.Drawing

  $root = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr]$proc.MainWindowHandle)

  function Find-UiaByName($parent, $name, $ctype = $null) {
    $c1 = New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::NameProperty, $name)
    if ($null -ne $ctype) {
      $c2 = New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $ctype)
      $and = New-Object System.Windows.Automation.AndCondition($c1, $c2)
      return $parent.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $and)
    }
    return $parent.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c1)
  }
  function Find-UiaAll($parent, $ctype) {
    $c = New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $ctype)
    return $parent.FindAll([System.Windows.Automation.TreeScope]::Descendants, $c)
  }

  $headerBtns = @("Refresh", "Apply all", "WFP", "QoS", "Clear WFP", "Clear QoS")
  foreach ($b in $headerBtns) {
    $el = Find-UiaByName $root $b ([System.Windows.Automation.ControlType]::Button)
    Add-GuiResult ("Header: " + $b) $(if ($el) { "PASS" } else { "FAIL" }) $(if ($el) { "found" } else { "missing" })
  }

  $tabItems = Find-UiaAll $root ([System.Windows.Automation.ControlType]::TabItem)
  $tabNames = @()
  foreach ($ti in $tabItems) { $tabNames += $ti.Current.Name }
  Add-GuiResult "Tab list" $(if ($tabNames.Count -ge 10) { "PASS" } else { "FAIL" }) ($tabNames -join " | ")

  $selId = [System.Windows.Automation.SelectionItemPattern]::Pattern
  $expected = @("Dashboard", "Live traffic", "DNS", "Rules", "Limits", "Quotas", "History", "Filters", "Tools", "Activity", "Settings")
  foreach ($t in $expected) {
    $el = $null
    foreach ($ti in $tabItems) {
      if ($ti.Current.Name -eq $t) { $el = $ti; break }
    }
    if ($null -eq $el) {
      Add-GuiResult ("Open tab " + $t) "FAIL" "missing"
      continue
    }
    try {
      $el.GetCurrentPattern($selId).Select()
      Start-Sleep -Milliseconds 450
      Add-GuiResult ("Open tab " + $t) "PASS" "OK"
    } catch {
      Add-GuiResult ("Open tab " + $t) "FAIL" "$_"
    }
  }

  foreach ($ti in $tabItems) {
    if ($ti.Current.Name -eq "Live traffic") {
      try { $ti.GetCurrentPattern($selId).Select() } catch {}
      break
    }
  }
  Start-Sleep 700
  $btnNames = @()
  foreach ($bb in (Find-UiaAll $root ([System.Windows.Automation.ControlType]::Button))) {
    $btnNames += $bb.Current.Name
  }
  foreach ($want in @("Block", "Allow", "Pin", "CSV", "Copy", "Kill", "Limit", "Priority", "Quota")) {
    $hit = $null
    foreach ($n in $btnNames) { if ($n -like ("*" + $want + "*")) { $hit = $n; break } }
    Add-GuiResult ("Live: " + $want) $(if ($hit) { "PASS" } else { "WARN" }) "$hit"
  }

  foreach ($ti in $tabItems) {
    if ($ti.Current.Name -eq "Settings") {
      try { $ti.GetCurrentPattern($selId).Select() } catch {}
      break
    }
  }
  Start-Sleep 700
  $btnNames = @()
  foreach ($bb in (Find-UiaAll $root ([System.Windows.Automation.ControlType]::Button))) {
    $btnNames += $bb.Current.Name
  }
  foreach ($want in @("API", "cert", "Driver", "Export", "Import", "ProgramData", "Copy")) {
    $hit = $null
    foreach ($n in $btnNames) { if ($n -like ("*" + $want + "*")) { $hit = $n; break } }
    Add-GuiResult ("Settings: " + $want) $(if ($hit) { "PASS" } else { "WARN" }) "$hit"
  }

  foreach ($ti in $tabItems) {
    if ($ti.Current.Name -eq "Dashboard") {
      try { $ti.GetCurrentPattern($selId).Select() } catch {}
      break
    }
  }
  Start-Sleep 2500
  $grids = Find-UiaAll $root ([System.Windows.Automation.ControlType]::DataGrid)
  Add-GuiResult "DataGrids" $(if ($grids.Count -ge 1) { "PASS" } else { "FAIL" }) ("count=" + $grids.Count)
  $maxRows = 0
  foreach ($g in $grids) {
    $items = $g.FindAll(
      [System.Windows.Automation.TreeScope]::Descendants,
      (New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::DataItem)))
    if ($items.Count -gt $maxRows) { $maxRows = $items.Count }
  }
  Add-GuiResult "Grid data rows" $(if ($maxRows -gt 0) { "PASS" } else { "WARN" }) ("rows=" + $maxRows)

  foreach ($c in @("LOCKDOWN", "ASK", "Topmost")) {
    $el = Find-UiaByName $root $c ([System.Windows.Automation.ControlType]::CheckBox)
    Add-GuiResult ("CheckBox " + $c) $(if ($el) { "PASS" } else { "WARN" }) $(if ($el) { "ok" } else { "missing" })
  }

  $ref = Find-UiaByName $root "Refresh" ([System.Windows.Automation.ControlType]::Button)
  if ($ref) {
    try {
      $ref.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
      Start-Sleep 1
      Add-GuiResult "Click Refresh" "PASS" "invoked"
    } catch {
      Add-GuiResult "Click Refresh" "WARN" "$_"
    }
  }

  foreach ($ti in $tabItems) {
    if ($ti.Current.Name -eq "DNS") {
      try { $ti.GetCurrentPattern($selId).Select() } catch {}
      break
    }
  }
  Start-Sleep 500
  $btnNames = @()
  foreach ($bb in (Find-UiaAll $root ([System.Windows.Automation.ControlType]::Button))) {
    $btnNames += $bb.Current.Name
  }
  foreach ($want in @("Refresh", "Resolve", "Block", "Allow")) {
    $hit = $null
    foreach ($n in $btnNames) { if ($n -like ("*" + $want + "*")) { $hit = $n; break } }
    Add-GuiResult ("DNS: " + $want) $(if ($hit) { "PASS" } else { "WARN" }) "$hit"
  }

  $proc.Refresh()
  Add-GuiResult "Stable after walk" $(if (-not $proc.HasExited -and $proc.Responding) { "PASS" } else { "FAIL" }) ("title=" + $proc.MainWindowTitle)

  try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class WinCapGui {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, int f);
  public struct RECT { public int L; public int T; public int R; public int B; }
}
"@ -ErrorAction SilentlyContinue
    $rect = New-Object WinCapGui+RECT
    [void][WinCapGui]::GetWindowRect([IntPtr]$proc.MainWindowHandle, [ref]$rect)
    $w = [Math]::Max(200, $rect.R - $rect.L)
    $h = [Math]::Max(200, $rect.B - $rect.T)
    $bmp = New-Object System.Drawing.Bitmap $w, $h
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    [void][WinCapGui]::PrintWindow([IntPtr]$proc.MainWindowHandle, $hdc, 2)
    $g.ReleaseHdc($hdc)
    New-Item -ItemType Directory -Path (Join-Path $Root "dist") -Force | Out-Null
    $shot = Join-Path $Root "dist\gui-screenshot.png"
    $bmp.Save($shot, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Add-GuiResult "Screenshot" "PASS" $shot
  } catch {
    Add-GuiResult "Screenshot" "WARN" "$_"
  }

  try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
}
catch {
  Add-GuiResult "Harness" "FAIL" "$_"
  Get-Process NetShaper -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
finally {
  if (Test-Path $bak) {
    Copy-Item $bak $manifest -Force
    Remove-Item $bak -Force -ErrorAction SilentlyContinue
  }
  $m = [IO.File]::ReadAllText($manifest)
  if ($m -match "asInvoker") {
    [IO.File]::WriteAllText($manifest, $m.Replace("asInvoker", "requireAdministrator"))
  }
  Write-Host "Manifest restored"
  Select-String -Path $manifest -Pattern "requestedExecutionLevel"
}

$pass = @($results | Where-Object Status -eq "PASS").Count
$fail = @($results | Where-Object Status -eq "FAIL").Count
$warn = @($results | Where-Object Status -eq "WARN").Count
Write-Host ("==== GUI SCORE PASS={0} FAIL={1} WARN={2} TOTAL={3} ====" -f $pass, $fail, $warn, $results.Count)

New-Item -ItemType Directory -Path (Join-Path $Root "dist") -Force | Out-Null
$results | Export-Csv (Join-Path $Root "dist\gui-test-results.csv") -NoTypeInformation -Encoding UTF8

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# NetShaper GUI UI Automation report")
$lines.Add("")
$lines.Add("- When: " + (Get-Date -Format o))
$lines.Add("- Score: **" + $pass + "/" + $results.Count + " PASS**, " + $fail + " FAIL, " + $warn + " WARN")
$lines.Add("")
$lines.Add("| Feature | Status | Detail |")
$lines.Add("|---------|--------|--------|")
foreach ($row in $results) {
  $d = ($row.Detail -replace "\|", "/")
  $lines.Add("| " + $row.Feature + " | " + $row.Status + " | " + $d + " |")
}
[IO.File]::WriteAllLines((Join-Path $Root "dist\GUI-TEST-REPORT.md"), $lines)
Write-Host "Report: dist\GUI-TEST-REPORT.md"

if ($fail -gt 0) { exit 1 } else { exit 0 }
