param(
  [string] $Admin = "harpocrates-admin",
  [string] $Issuer = "harpocrates-issuer",
  [string] $Network = "testnet",
  [string] $Verifier = "CCP2EQPKT5XAYTOARX3LGHNMJ37A6W2WY3H54MRIHEZVTVAZZPUSGZQJ",
  [string] $RpcUrl = "https://soroban-testnet.stellar.org",
  [switch] $SkipBuild,
  [switch] $SkipIssuer,
  [switch] $SkipE2E,
  [int] $StellarTimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$deployPy = Join-Path $root "devx\deploy.py"

$pythonCmd = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { "python3" }

$arguments = @(
  $deployPy,
  "deploy",
  "--admin", $Admin,
  "--issuer", $Issuer,
  "--network", $Network,
  "--verifier", $Verifier,
  "--rpc-url", $RpcUrl,
  "--stellar-timeout-seconds", $StellarTimeoutSeconds
)

if ($SkipBuild) {
  $arguments += "--skip-build"
}
if ($SkipIssuer) {
  $arguments += "--skip-issuer"
}
if ($SkipE2E) {
  $arguments += "--skip-e2e"
}

& $pythonCmd @arguments
exit $LASTEXITCODE
