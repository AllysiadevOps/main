param(
  [string] $BackendUrl = "http://127.0.0.1:5050",
  [string] $ContractId = "CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT",
  [string] $Source = "harpocrates-admin",
  [string] $Network = "testnet",
  [string] $CredentialSecret,
  [string] $NullifierSecret,
  [int] $StellarTimeoutSeconds = 180,
  [switch] $EnsureCredentialRoot,
  [switch] $RegisterOnChain
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$deployPy = Join-Path $root "devx\deploy.py"

$pythonCmd = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { "python3" }

$arguments = @(
  $deployPy,
  "e2e",
  "--backend-url", $BackendUrl,
  "--contract-id", $ContractId,
  "--source", $Source,
  "--network", $Network,
  "--stellar-timeout-seconds", $StellarTimeoutSeconds
)

if ($CredentialSecret) {
  $arguments += @("--credential-secret", $CredentialSecret)
}
if ($NullifierSecret) {
  $arguments += @("--nullifier-secret", $NullifierSecret)
}
if ($EnsureCredentialRoot) {
  $arguments += "--ensure-credential-root"
}
if ($RegisterOnChain) {
  $arguments += "--register-on-chain"
}

& $pythonCmd @arguments
exit $LASTEXITCODE
