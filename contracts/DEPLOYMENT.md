# Harpocrates Soroban Deployment

## Current Testnet

```text
HarpocratesRegistry=CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT
SilentWitnessUltraHonkVerifier=CCP2EQPKT5XAYTOARX3LGHNMJ37A6W2WY3H54MRIHEZVTVAZZPUSGZQJ
Admin=GDVRSXIO4SK2KSMUKJTQHMDDHBBFC7NGZZ6WLVOPKAG47GYPYAZCZR7G
Issuer=GAJ3GSKWOCTI2B3ZQRTB7TWYYIX734VJLNGOMSIQSAGRMIGX6SSVMIB4
RegistryWasmHash=a0e9bd49967bae7cb3608166b323514c8ef46832905f56b3c4a5aff41e105e68
```

## Test And Build

```powershell
cargo test
stellar contract build
```

## Deploy Registry

```powershell
stellar contract deploy `
  --wasm target\wasm32v1-none\release\harpocrates_registry.wasm `
  --source harpocrates-admin `
  --network testnet
```

Initialize:

```powershell
stellar contract invoke `
  --id YOUR_REGISTRY_CONTRACT_ID `
  --source harpocrates-admin `
  --network testnet `
  -- init `
  --admin harpocrates-admin
```

## Deploy Silent Witness Verifier

Build Noir artifacts with the pinned verifier-compatible toolchain:

```powershell
.\zk\noir\scripts\build-silent-witness-wsl.ps1
.\zk\noir\scripts\prepare-soroban-verifier-artifacts.ps1
```

Deploy the UltraHonk verifier:

```powershell
stellar contract deploy `
  --wasm C:\Users\enliven\AppData\Local\Temp\rs-soroban-ultrahonk\target\wasm32v1-none\release\rs_soroban_ultrahonk.wasm `
  --source harpocrates-admin `
  --network testnet `
  -- `
  --vk_bytes-file-path C:\Users\enliven\Documents\GitHub\harpocrates-stellar\zk\noir\silent_witness\target\vk_soroban
```

Attach it to the registry:

```powershell
.\scripts\set-verifier.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Admin harpocrates-admin `
  -Verifier YOUR_VERIFIER_CONTRACT_ID
```

## Upgrade Existing Registries To Storage V2

The role-separated registry artifact starts fresh deployments at storage V2 and adds
strict separation between registry-admin and active-issuer authority. Before
using an upgraded contract for issuer operations, the current admin must run
the existing idempotent migration entry point:

```powershell
stellar contract invoke `
  --id YOUR_REGISTRY_CONTRACT_ID `
  --source harpocrates-admin `
  --network testnet `
  -- `
  -- upgrade_storage `
  --admin harpocrates-admin
```

Then query `get_schema_version`; it must return `2`. If the current admin also
has an active legacy issuer record, migration emits `IssuerRevoked` for that
address and `SchemaUpgraded` with `previous=1, current=2`. No proof, nullifier,
credential-root, verifier, metadata, or media state is rewritten. Keep the
admin and issuer keypairs distinct and verify `is_admin`/`is_issuer` before
granting Tier 3 access.

Rollback may restore the previous immutable Wasm, and all stored evidence
remains readable. However, a pre-V2 artifact does not enforce role separation;
if it is active, do not grant issuer authority until the V2 artifact is restored
and `upgrade_storage` is confirmed idempotently complete.

## Register Tiers

Tier 1 requires an active credential root before registration:

```powershell
.\scripts\add-credential-root.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Admin harpocrates-admin `
  -CredentialRoot YOUR_NOIR_PUBLIC_CREDENTIAL_ROOT `
  -MetadataHash YOUR_CREDENTIAL_POLICY_HASH
```

Tier 1, real Noir verified:

```powershell
.\scripts\register-anonymous-verified.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Source harpocrates-admin `
  -VideoHash YOUR_32_BYTE_HEX `
  -MetadataHash YOUR_32_BYTE_HEX `
  -ProofId YOUR_32_BYTE_HEX `
  -PublicInputsPath ..\zk\noir\silent_witness\target\public_inputs `
  -ProofPath ..\zk\noir\silent_witness\target\proof
```

Revoke a Silent Witness credential root:

```powershell
.\scripts\revoke-credential-root.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Admin harpocrates-admin `
  -CredentialRoot YOUR_NOIR_PUBLIC_CREDENTIAL_ROOT
```

Tier 2:

```powershell
.\scripts\register-source.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Source harpocrates-admin `
  -VideoHash YOUR_32_BYTE_HEX `
  -MetadataHash YOUR_32_BYTE_HEX `
  -ProofId YOUR_32_BYTE_HEX
```

Tier 3:

```powershell
.\scripts\add-issuer.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Admin harpocrates-admin `
  -Issuer harpocrates-issuer `
  -MetadataHash YOUR_32_BYTE_HEX

.\scripts\register-seal.ps1 `
  -ContractId YOUR_REGISTRY_CONTRACT_ID `
  -Issuer harpocrates-issuer `
  -VideoHash YOUR_32_BYTE_HEX `
  -MetadataHash YOUR_32_BYTE_HEX `
  -ProofId YOUR_32_BYTE_HEX
```

## In-Place Registry Wasm Upgrade via Timelock

The `HarpocratesRegistry` contract supports in-place code upgrades through Stellar's `env.deployer().update_current_contract_wasm`, preserving the contract ID and all persistent storage without requiring client migration.

In-place upgrades **can only be executed through the timelock mechanism** (Action Kind `6`: `UpgradeWasm`) and **cannot be bypassed via `emergency_execute_timelock`**.

### 1. Build and Upload New Wasm

Compile the contract and upload the new Wasm bytecode to obtain its 32-byte hash:

```powershell
cargo test
stellar contract build
stellar contract install `
  --wasm target\wasm32v1-none\release\harpocrates_registry.wasm `
  --source harpocrates-admin `
  --network testnet
```

Take note of the returned 64-character hex Wasm hash (`NEW_WASM_HASH`).

### 2. Propose Wasm Upgrade Proposal

Propose the upgrade through the timelock with Action `6` (`UpgradeWasm`). The payload must be the 32-byte Wasm hash:

```powershell
stellar contract invoke `
  --id YOUR_REGISTRY_CONTRACT_ID `
  --source harpocrates-admin `
  --network testnet `
  -- propose_timelocked_action `
  --proposer harpocrates-admin `
  --action 6 `
  --target harpocrates-admin `
  --payload NEW_WASM_HASH
```

The call returns the assigned `proposal_id` (e.g. `1`).

### 3. Await Minimum Timelock Delay

The proposal cannot be executed before `min_execution_at` (`created_at + min_delay`). Any premature attempt will revert with `RegistryError::ProposalNotReady` (Code 32). Emergency execution is strictly disallowed for code upgrades and will revert with `RegistryError::InvalidProposalAction` (Code 35).

### 4. Execute Upgrade Proposal

Once the delay expires, execute the proposal:

```powershell
stellar contract invoke `
  --id YOUR_REGISTRY_CONTRACT_ID `
  --source harpocrates-admin `
  --network testnet `
  -- execute_timelocked_proposal `
  --caller harpocrates-admin `
  --proposal_id 1
```

Upon execution, the contract invokes `update_current_contract_wasm`, updates `DataKey::WasmHash`, and emits the `ContractUpgraded` event with `old_wasm_hash` and `new_wasm_hash`.

### 5. Execute Storage Schema Migration (If Applicable)

If the new contract version introduces schema updates, run `upgrade_storage`:

```powershell
stellar contract invoke `
  --id YOUR_REGISTRY_CONTRACT_ID `
  --source harpocrates-admin `
  --network testnet `
  -- upgrade_storage `
  --admin harpocrates-admin
```

Confirm schema migration by querying `get_schema_version`.

### Verification Steps

1. Verify Wasm hash:
   ```powershell
   stellar contract invoke `
     --id YOUR_REGISTRY_CONTRACT_ID `
     --source harpocrates-admin `
     --network testnet `
     -- get_current_wasm_hash
   ```
   Ensure the output matches `NEW_WASM_HASH`.

2. Verify state continuity:
   - Query `get_admin` to confirm administrative authority is preserved.
   - Query `get_verifier` to verify verifier address continuity.
   - Query `is_issuer` or verify registered credential roots to confirm all storage data remains intact.

### Rollback Strategy

If defects are identified in the upgraded Wasm code, rollback does not require re-deploying or transferring storage:

1. Identify the previous known-good Wasm hash (`PREVIOUS_WASM_HASH`), obtainable from deployment history or previous `ContractUpgraded` event logs.
2. Submit a new timelock proposal with Action `6` (`UpgradeWasm`) and `payload: PREVIOUS_WASM_HASH`.
3. Wait for the timelock delay to elapse.
4. Execute the proposal via `execute_timelocked_proposal`.
5. Verify state and active Wasm hash. All existing proofs, nullifiers, and records remain intact throughout the rollback.

