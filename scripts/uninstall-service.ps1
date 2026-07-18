#Requires -RunAsAdministrator
$name = "NetShaper"
if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
  Stop-Service $name -Force -ErrorAction SilentlyContinue
  sc.exe delete $name
  Write-Host "Service removed."
} else {
  Write-Host "Service not installed."
}
# Optional: clear persistent WFP
Write-Host "To clear WFP filters run (admin):"
Write-Host "  dotnet run --project NetShaper.Cli -- clear-wfp --persist"
