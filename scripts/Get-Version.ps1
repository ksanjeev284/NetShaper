# Shared version from Directory.Build.props
$Root = if ($PSScriptRoot) { Resolve-Path (Join-Path $PSScriptRoot "..") } else { Get-Location }
$props = Join-Path $Root "Directory.Build.props"
if (-not (Test-Path $props)) { return "0.0.0" }
$m = [regex]::Match((Get-Content $props -Raw), '<Version>\s*([^<\s]+)\s*</Version>')
if ($m.Success) { return $m.Groups[1].Value.Trim() }
return "0.0.0"
