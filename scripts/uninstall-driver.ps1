#Requires -RunAsAdministrator
$name = "NetShaperCallout"
sc.exe stop $name 2>$null | Out-Null
Start-Sleep 1
sc.exe delete $name 2>$null | Out-Null
$dest = Join-Path $env:ProgramData "NetShaper\driver\NetShaperCallout.sys"
if (Test-Path $dest) { Remove-Item $dest -Force }
Write-Host "Driver service removed."
