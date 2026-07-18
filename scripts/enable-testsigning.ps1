#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Enable Windows test signing so an unsigned / test-signed NetShaperCallout.sys can load.
  Requires reboot.
#>
bcdedit /set testsigning on
Write-Host "Test signing enabled. Reboot required."
Write-Host "After reboot, run scripts\install-driver-testsign.ps1"
