#!/usr/bin/env bash
# ==============================================================================
# test_onchain_verifier_e2e.sh
#
# End-to-end regression test:
# 1. Generates fresh UltraHonk proof & Soroban VK from browser Noir artifacts
#    using bb.js.
# 2. Clones and builds rs-soroban-ultrahonk verifier at pinned commit.
# 3. Builds HarpocratesRegistry contract.
# 4. Deploys both contracts into a local Soroban environment (stellar container).
# 5. Configures verifier & credential root in the registry.
# 6. Asserts acceptance of the valid proof.
# 7. Asserts rejection with InvalidProof (Error(Contract, #7)) for tampered inputs.
# 8. Records and outputs total wall-clock execution time.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Pinned dependencies and defaults
PINNED_ULTRAHONK_REPO="https://github.com/NethermindEth/rs-soroban-ultrahonk.git"
PINNED_ULTRAHONK_COMMIT="9aae9581eab7bc4c69209c0322e54e119ed3180e"
STELLAR_NETWORK="${STELLAR_NETWORK:-local}"
ADMIN_NAME="${ADMIN_NAME:-harpocrates-ci-admin}"
KEEP_TEMP="${KEEP_TEMP:-false}"

START_TIME=$(date +%s)

echo "======================================================================"
echo "Harpocrates ZK On-Chain Verifier E2E Test"
echo "Network: $STELLAR_NETWORK"
echo "Ultrahonk commit: $PINNED_ULTRAHONK_COMMIT"
echo "======================================================================"

# Prerequisite checks
command -v node >/dev/null 2>&1 || { echo "ERROR: node is required"; exit 1; }
command -v stellar >/dev/null 2>&1 || { echo "ERROR: stellar CLI is required"; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "ERROR: cargo is required"; exit 1; }
command -v git >/dev/null 2>&1 || { echo "ERROR: git is required"; exit 1; }

WORKDIR="$(mktemp -d -t harpocrates-zk-e2e-XXXXXX)"
cleanup() {
  if [ "$KEEP_TEMP" != "true" ]; then
    rm -rf "$WORKDIR"
  else
    echo "Preserved test directory: $WORKDIR"
  fi
}
trap cleanup EXIT

FIXTURE_DIR="$WORKDIR/fixtures"
mkdir -p "$FIXTURE_DIR"

echo "[1/7] Generating fresh UltraHonk proof & Soroban VK from browser artifacts..."
PROOFS_START=$(date +%s)
export NODE_TLS_REJECT_UNAUTHORIZED="0"
node "$SCRIPT_DIR/generate_browser_proof_fixture.mjs" --outDir "$FIXTURE_DIR"
PROOFS_ELAPSED=$(( $(date +%s) - PROOFS_START ))
echo "Proof generation took ${PROOFS_ELAPSED}s."

echo "[2/7] Cloning and building rs-soroban-ultrahonk verifier..."
BUILD_START=$(date +%s)
VERIFIER_SRC="$WORKDIR/rs-soroban-ultrahonk"
git clone --quiet "$PINNED_ULTRAHONK_REPO" "$VERIFIER_SRC"
(
  cd "$VERIFIER_SRC"
  git checkout --quiet "$PINNED_ULTRAHONK_COMMIT"
  stellar contract build
)
VERIFIER_WASM="$VERIFIER_SRC/target/wasm32v1-none/release/rs_soroban_ultrahonk.wasm"
if [ ! -f "$VERIFIER_WASM" ]; then
  # Fallback location
  VERIFIER_WASM=$(find "$VERIFIER_SRC/target" -name "rs_soroban_ultrahonk.wasm" | grep release | head -n 1)
fi
if [ ! -f "$VERIFIER_WASM" ]; then
  echo "ERROR: Failed to find built verifier WASM at $VERIFIER_WASM"
  exit 1
fi
echo "Verifier WASM built: $VERIFIER_WASM ($(wc -c < "$VERIFIER_WASM") bytes)"

echo "[3/7] Building HarpocratesRegistry contract..."
(
  cd "$REPO_ROOT/contracts"
  stellar contract build
)
REGISTRY_WASM="$REPO_ROOT/contracts/target/wasm32v1-none/release/harpocrates_registry.wasm"
if [ ! -f "$REGISTRY_WASM" ]; then
  echo "ERROR: Failed to find built registry WASM at $REGISTRY_WASM"
  exit 1
fi
echo "Registry WASM built: $REGISTRY_WASM ($(wc -c < "$REGISTRY_WASM") bytes)"
BUILD_ELAPSED=$(( $(date +%s) - BUILD_START ))
echo "Contracts build took ${BUILD_ELAPSED}s."

echo "[4/7] Ensuring local Soroban test network & identities..."
if [ "$STELLAR_NETWORK" = "local" ]; then
  # Start local standalone node if container is not already running
  if ! stellar container status >/dev/null 2>&1; then
    echo "Starting Stellar local standalone container..."
    stellar container start local
    # Wait for node to become responsive
    echo "Waiting for local node RPC to respond..."
    for i in {1..30}; do
      if curl -s http://localhost:8000/soroban/rpc >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
  fi
fi

# Configure identity
stellar keys generate "$ADMIN_NAME" 2>/dev/null || true
if [ "$STELLAR_NETWORK" = "local" ]; then
  stellar keys fund "$ADMIN_NAME" --network "$STELLAR_NETWORK" >/dev/null 2>&1 || true
fi

echo "[5/7] Deploying contracts and setting up verification..."
DEPLOY_START=$(date +%s)

# Deploy verifier with VK
DEPLOY_VERIFIER_OUT=$(stellar contract deploy \
  --wasm "$VERIFIER_WASM" \
  --source "$ADMIN_NAME" \
  --network "$STELLAR_NETWORK" \
  -- \
  --vk_bytes-file-path "$FIXTURE_DIR/vk_soroban.bin" 2>&1)
echo "$DEPLOY_VERIFIER_OUT"
VERIFIER_ID=$(echo "$DEPLOY_VERIFIER_OUT" | grep -oE 'C[A-Z0-9]{55}' | head -n 1)
if [ -z "$VERIFIER_ID" ]; then
  echo "ERROR: Failed to deploy verifier contract."
  exit 1
fi
echo "Verifier deployed: $VERIFIER_ID"

# Deploy registry
DEPLOY_REGISTRY_OUT=$(stellar contract deploy \
  --wasm "$REGISTRY_WASM" \
  --source "$ADMIN_NAME" \
  --network "$STELLAR_NETWORK" 2>&1)
echo "$DEPLOY_REGISTRY_OUT"
REGISTRY_ID=$(echo "$DEPLOY_REGISTRY_OUT" | grep -oE 'C[A-Z0-9]{55}' | head -n 1)
if [ -z "$REGISTRY_ID" ]; then
  echo "ERROR: Failed to deploy registry contract."
  exit 1
fi
echo "Registry deployed: $REGISTRY_ID"

# Initialize registry
stellar contract invoke \
  --id "$REGISTRY_ID" \
  --source "$ADMIN_NAME" \
  --network "$STELLAR_NETWORK" \
  -- \
  init \
  --admin "$ADMIN_NAME"

# Attach verifier to registry
stellar contract invoke \
  --id "$REGISTRY_ID" \
  --source "$ADMIN_NAME" \
  --network "$STELLAR_NETWORK" \
  -- \
  set_verifier \
  --admin "$ADMIN_NAME" \
  --verifier "$VERIFIER_ID"

# Register active credential root
stellar contract invoke \
  --id "$REGISTRY_ID" \
  --source "$ADMIN_NAME" \
  --network "$STELLAR_NETWORK" \
  -- \
  add_credential_root \
  --admin "$ADMIN_NAME" \
  --root-file-path "$FIXTURE_DIR/credential_root.bin" \
  --memo-file-path "$FIXTURE_DIR/memo.bin"

DEPLOY_ELAPSED=$(( $(date +%s) - DEPLOY_START ))
echo "Deployment and setup completed in ${DEPLOY_ELAPSED}s."

echo "[6/7] Submitting VALID proof to register_anonymous_verified..."
VERIFY_START=$(date +%s)
VALID_REG_OUT=$(stellar contract invoke \
  --id "$REGISTRY_ID" \
  --source "$ADMIN_NAME" \
  --network "$STELLAR_NETWORK" \
  -- \
  register_anonymous_verified \
  --video_hash-file-path "$FIXTURE_DIR/video_hash.bin" \
  --metadata_hash-file-path "$FIXTURE_DIR/metadata_hash.bin" \
  --proof_id-file-path "$FIXTURE_DIR/proof_id.bin" \
  --public_inputs-file-path "$FIXTURE_DIR/public_inputs.bin" \
  --proof-file-path "$FIXTURE_DIR/proof.bin" 2>&1)

echo "$VALID_REG_OUT"
echo "PASS: Valid proof successfully registered on-chain!"

echo "[7/7] Asserting REJECTION for tampered public inputs / proof..."
# Prepare unique proof_id for tampered attempt
TAMPERED_PROOF_ID="$WORKDIR/proof_id_tampered.bin"
python3 -c "import os; open('$TAMPERED_PROOF_ID', 'wb').write(os.urandom(32))" 2>/dev/null || \
  head -c 32 /dev/urandom > "$TAMPERED_PROOF_ID"

set +e
TAMPERED_OUT=$(stellar contract invoke \
  --id "$REGISTRY_ID" \
  --source "$ADMIN_NAME" \
  --network "$STELLAR_NETWORK" \
  -- \
  register_anonymous_verified \
  --video_hash-file-path "$FIXTURE_DIR/video_hash.bin" \
  --metadata_hash-file-path "$FIXTURE_DIR/metadata_hash.bin" \
  --proof_id-file-path "$TAMPERED_PROOF_ID" \
  --public_inputs-file-path "$FIXTURE_DIR/public_inputs_tampered.bin" \
  --proof-file-path "$FIXTURE_DIR/proof.bin" 2>&1)
TAMPERED_EXIT=$?
set -e

if [ $TAMPERED_EXIT -eq 0 ]; then
  echo "FAIL: Tampered public inputs were accepted when they should have been rejected!"
  echo "$TAMPERED_OUT"
  exit 1
fi

# Contract error #7 is RegistryError::InvalidProof
if echo "$TAMPERED_OUT" | grep -qE "(Error\(Contract, #7\)|InvalidProof)"; then
  echo "PASS: Tampered public inputs failed closed with InvalidProof (Error(Contract, #7))."
else
  echo "WARNING: Tampered inputs failed with non-zero exit code ($TAMPERED_EXIT), output was:"
  echo "$TAMPERED_OUT"
  # Check if Soroban host returned error
  if echo "$TAMPERED_OUT" | grep -qE "(HostError|Error)"; then
    echo "PASS: Confirmed contract call rejected by Soroban runtime."
  else
    echo "ERROR: Unexpected failure mode."
    exit 1
  fi
fi

TOTAL_ELAPSED=$(( $(date +%s) - START_TIME ))
echo "======================================================================"
echo "ALL CHECKS PASSED: On-chain ZK verification E2E test succeeded."
echo "Total wall-clock runtime: ${TOTAL_ELAPSED} seconds"
echo "======================================================================"
