#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install NetShaper.Service as a Windows Service (persistent WFP enforcer).
#>
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$proj = Join-Path $Root "NetShaper.Service\NetShaper.Service.csproj"
$out = Join-Path $Root "publish\service"

Write-Host "Publishing $proj -> $out"
dotnet publish $proj -c Release -o $out --self-contained false
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

$exe = Join-Path $out "NetShaper.Service.exe"
if (-not (Test-Path $exe)) { throw "Publish failed: $exe missing" }

$name = "NetShaper"
if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
  Write-Host "Stopping / removing existing service..."
  Stop-Service $name -Force -ErrorAction SilentlyContinue
  sc.exe delete $name | Out-Null
  Start-Sleep 2
}

Write-Host "Creating service $name"
New-Service -Name $name -BinaryPathName "`"$exe`"" -DisplayName "NetShaper Policy Service" `
  -Description "Applies NetShaper WFP block/allow policy from ProgramData\NetShaper\policy.json" `
  -StartupType Automatic | Out-Null

Start-Service $name
Get-Service $name | Format-List Name, Status, StartType, DisplayName
Write-Host ""
Write-Host "OK. Policy file: $env:ProgramData\NetShaper\policy.json"
Write-Host "Example:  cd $Root; dotnet run --project NetShaper.Cli -- block notepad"
Write-Host "Service reloads policy.json on file change."
