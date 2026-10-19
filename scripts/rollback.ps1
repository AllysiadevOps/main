param(
  [Parameter(Mandatory=$true)]
  [string] $ManifestFile,
  [switch] $SkipDocker
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$deployPy = Join-Path $root "devx\deploy.py"

$pythonCmd = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { "python3" }

$arguments = @(
  $deployPy,
  "rollback",
  "--manifest-file", $ManifestFile
)

if ($SkipDocker) {
  $arguments += "--skip-docker"
}

& $pythonCmd @arguments
exit $LASTEXITCODE
