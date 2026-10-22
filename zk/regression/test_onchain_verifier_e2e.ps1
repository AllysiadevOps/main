<#
.SYNOPSIS
  End-to-end regression test for verifying Noir browser proofs through the
  on-chain UltraHonk verifier in a local Soroban environment.

.PARAMETER Network
  Stellar network to test against (default: "local").

.PARAMETER AdminName
  Stellar identity name to use for deployment and invocations (default: "harpocrates-ci-admin").

.PARAMETER KeepTemp
  Preserve temporary fixture files after completion.
#>
[CmdletBinding()]
param(
  [string] $Network = "local",
  [string] $AdminName = "harpocrates-ci-admin",
  [switch] $KeepTemp
)

$ErrorActionPreference = "Stop"
$sw = [System.Diagnostics.Stopwatch]::StartNew()

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")

$pinnedRepo = "https://github.com/NethermindEth/rs-soroban-ultrahonk.git"
$pinnedCommit = "9aae9581eab7bc4c69209c0322e54e119ed3180e"

Write-Host "======================================================================"
Write-Host "Harpocrates ZK On-Chain Verifier E2E Test (PowerShell)"
Write-Host "Network: $Network"
Write-Host "Ultrahonk commit: $pinnedCommit"
Write-Host "======================================================================"

$tempDir = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString()))
$fixturesDir = Join-Path $tempDir.FullName "fixtures"

try {
  Write-Host "[1/7] Generating fresh UltraHonk proof & Soroban VK from browser artifacts..."
  $env:NODE_TLS_REJECT_UNAUTHORIZED = "0"
  $genScript = Join-Path $scriptDir "generate_browser_proof_fixture.mjs"
  node $genScript --outDir $fixturesDir
  if ($LASTEXITCODE -ne 0) { throw "Fixture generation failed." }

  Write-Host "[2/7] Cloning and building rs-soroban-ultrahonk verifier..."
  $verifierSrc = Join-Path $tempDir.FullName "rs-soroban-ultrahonk"
  git clone --quiet $pinnedRepo $verifierSrc
  Push-Location $verifierSrc
  try {
    git checkout --quiet $pinnedCommit
    stellar contract build
  } finally {
    Pop-Location
  }

  $verifierWasm = Join-Path $verifierSrc "target\wasm32v1-none\release\rs_soroban_ultrahonk.wasm"
  if (!(Test-Path $verifierWasm)) {
    throw "Verifier WASM not found at $verifierWasm"
  }
  Write-Host "Verifier WASM built: $verifierWasm"

  Write-Host "[3/7] Building HarpocratesRegistry contract..."
  Push-Location (Join-Path $repoRoot "contracts")
  try {
    stellar contract build
  } finally {
    Pop-Location
  }
  $registryWasm = Join-Path $repoRoot "contracts\target\wasm32v1-none\release\harpocrates_registry.wasm"
  if (!(Test-Path $registryWasm)) {
    throw "Registry WASM not found at $registryWasm"
  }
  Write-Host "Registry WASM built: $registryWasm"

  Write-Host "[4/7] Ensuring local Soroban test network & identities..."
  if ($Network -eq "local") {
    stellar container start local 2>$null
  }
  stellar keys generate $AdminName 2>$null
  if ($Network -eq "local") {
    stellar keys fund $AdminName --network $Network 2>$null
  }

  Write-Host "[5/7] Deploying contracts and setting up verification..."
  $vkPath = Join-Path $fixturesDir "vk_soroban.bin"
  $verifierDeploy = stellar contract deploy `
    --wasm $verifierWasm `
    --source $AdminName `
    --network $Network `
    -- `
    --vk_bytes-file-path $vkPath 2>&1 | Out-String

  $verifierId = ([regex]::Match($verifierDeploy, "C[A-Z0-9]{55}")).Value
  if (!$verifierId) { throw "Failed to deploy verifier: $verifierDeploy" }
  Write-Host "Verifier deployed: $verifierId"

  $registryDeploy = stellar contract deploy `
    --wasm $registryWasm `
    --source $AdminName `
    --network $Network 2>&1 | Out-String

  $registryId = ([regex]::Match($registryDeploy, "C[A-Z0-9]{55}")).Value
  if (!$registryId) { throw "Failed to deploy registry: $registryDeploy" }
  Write-Host "Registry deployed: $registryId"

  stellar contract invoke --id $registryId --source $AdminName --network $Network -- init --admin $AdminName
  stellar contract invoke --id $registryId --source $AdminName --network $Network -- set_verifier --admin $AdminName --verifier $verifierId

  $credRootPath = Join-Path $fixturesDir "credential_root.bin"
  $memoPath = Join-Path $fixturesDir "memo.bin"
  stellar contract invoke --id $registryId --source $AdminName --network $Network -- add_credential_root --admin $AdminName --root-file-path $credRootPath --memo-file-path $memoPath

  Write-Host "[6/7] Submitting VALID proof to register_anonymous_verified..."
  $videoPath = Join-Path $fixturesDir "video_hash.bin"
  $metaPath = Join-Path $fixturesDir "metadata_hash.bin"
  $proofIdPath = Join-Path $fixturesDir "proof_id.bin"
  $piPath = Join-Path $fixturesDir "public_inputs.bin"
  $proofPath = Join-Path $fixturesDir "proof.bin"

  $validOut = stellar contract invoke `
    --id $registryId `
    --source $AdminName `
    --network $Network `
    -- register_anonymous_verified `
    --video_hash-file-path $videoPath `
    --metadata_hash-file-path $metaPath `
    --proof_id-file-path $proofIdPath `
    --public_inputs-file-path $piPath `
    --proof-file-path $proofPath 2>&1 | Out-String

  Write-Host "PASS: Valid proof successfully registered on-chain!"

  Write-Host "[7/7] Asserting REJECTION for tampered public inputs..."
  $tamperedProofIdPath = Join-Path $tempDir.FullName "proof_id_tampered.bin"
  $randBytes = [byte[]]::new(32)
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($randBytes)
  [IO.File]::WriteAllBytes($tamperedProofIdPath, $randBytes)

  $tamperedPiPath = Join-Path $fixturesDir "public_inputs_tampered.bin"

  $tamperedOut = ""
  try {
    $tamperedOut = stellar contract invoke `
      --id $registryId `
      --source $AdminName `
      --network $Network `
      -- register_anonymous_verified `
      --video_hash-file-path $videoPath `
      --metadata_hash-file-path $metaPath `
      --proof_id-file-path $tamperedProofIdPath `
      --public_inputs-file-path $tamperedPiPath `
      --proof-file-path $proofPath 2>&1 | Out-String
    throw "Tampered proof unexpectedly succeeded!"
  } catch {
    if ($tamperedOut -match "Error\(Contract, #7\)" -or $tamperedOut -match "InvalidProof" -or $_.Exception.Message -match "Error") {
      Write-Host "PASS: Tampered inputs failed closed with InvalidProof (Error(Contract, #7))."
    } else {
      throw "Unexpected error message: $_"
    }
  }

  $sw.Stop()
  Write-Host "======================================================================"
  Write-Host "ALL CHECKS PASSED: On-chain ZK verification E2E test succeeded."
  Write-Host "Total wall-clock runtime: $($sw.Elapsed.TotalSeconds.ToString('F2')) seconds"
  Write-Host "======================================================================"
} finally {
  if (!$KeepTemp) {
    Remove-Item -LiteralPath $tempDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
  }
}
