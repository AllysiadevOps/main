# Timelocked Administration Workflow

This document explains the timelocked governance workflow for sensitive administrative actions in `HarpocratesRegistry` (`#86`).

## Overview

High-impact administrative actions (such as setting the primary verifier contract, revoking an issuer, updating proof TTL, or revoking/expiring credential roots) can be subject to an on-chain timelock delay. This introduces a mandatory waiting period between when an action is proposed by the admin and when it can be executed on-chain.

The workflow provides:
- **Advance Notice**: Stored proposals and emitted events notify the network and participants before critical changes take effect.
- **Cancellation**: The admin can cancel a pending proposal prior to execution if an error or malicious proposal is detected.
- **Decoupled Execution**: Anyone can trigger execution once the minimum delay has elapsed.
- **Emergency Execution**: The admin retains an expedited emergency path to execute immediately when urgent intervention is necessary.

---

## Action Kinds

Action kinds represent the administrative operations supported by the timelock mechanism (`ProposalAction` enum, validated in `lib.rs` for `propose_timelocked_action` where `action > 0 && action <= 6 && action != 5`):

| Action Kind (`u32`) | Name (`ProposalAction`) | Target Semantics | Payload Semantics | Effect on Execution (`dispatch_timelocked_action`) |
|---------------------|-------------------------|------------------|-------------------|---------------------------------------------------|
| `1` | `SetVerifier` | New verifier contract `Address` | Unused (`[0u8; 32]`) | Updates `DataKey::Verifier` to target address and clears `DataKey::VerifierState`. Emits `VerifierSet { verifier }`. |
| `2` | `RevokeIssuer` | Issuer `Address` to revoke | Unused (`[0u8; 32]`) | Sets `IssuerRecord.active = false` for target, and clears any staged rotation record at `DataKey::IssuerRotation`. Emits `IssuerRevoked { issuer }`. |
| `3` | `SetProofTtl` | Unused (arbitrary `Address`, e.g. admin or dummy address) | Big-endian `u64` TTL in seconds encoded in the first 8 bytes (`payload[..8]`), zero-padded to 32 bytes | Updates `DataKey::ProofTtl` to the decoded `u64` seconds value. |
| `4` | `RevokeCredentialRoot` | Unused (arbitrary `Address`) | 32-byte credential root hash (`BytesN<32>`) | Sets `CredentialRootRecord.status = STATUS_REVOKED` at `DataKey::CredentialRootV2`. Emits `CredentialRootRevoked { credential_root }`. |
| `5` | `ExpireCredentialRoot`* | Unused (arbitrary `Address`) | 32-byte credential root hash (`BytesN<32>`) | Sets `CredentialRootRecord.status = STATUS_EXPIRED` and `expires_at = now` at `DataKey::CredentialRootV2`. Emits `CredentialRootExpired { credential_root, expired_at }`. |
| `6` | `UpgradeWasm` | Unused (arbitrary `Address`, e.g. admin address) | 32-byte uploaded Wasm hash (`BytesN<32>`) | Calls `env.deployer().update_current_contract_wasm(new_wasm_hash)`. Updates `DataKey::WasmHash` and emits `ContractUpgraded { old_wasm_hash, new_wasm_hash }`. |

> \* **Note on Action Kinds**: Action kind 5 is unassigned for proposals. `propose_timelocked_action` allows kinds `1..=4` and `6` (`action == 0 || action > 6 || action == 5` panics with `InvalidProposalAction`). Furthermore, Action kind 6 (`UpgradeWasm`) cannot be executed via `emergency_execute_timelock`.

---

## Delays and Configuration

- **Default Minimum Delay**: `DEFAULT_TIMELOCK_MIN_DELAY_SECS = 86_400` (24 hours).
- **Maximum Minimum Delay**: `MAX_TIMELOCK_MIN_DELAY_SECS = 604_800` (7 days).
- **Configuring Delay**: Admin calls `set_timelock_min_delay_secs(admin, delay_secs)`.
  - Must satisfy: `delay_secs > 0` and `delay_secs <= MAX_TIMELOCK_MIN_DELAY_SECS`.
  - Violations panic with `RegistryError::InvalidTimelockDelay` (Code `38`).
  - Emits event: `TimelockMinDelaySet`.
- **Querying Delay**: `get_timelock_min_delay_secs()` returns the configured or default delay in seconds.

---

## Timelock Lifecycle & State Machine

```text
       +------------------------------------+
       |  propose_timelocked_action (Admin) |
       +-----------------+------------------+
                         |
                         v
                    [ PENDING ]
                    /         \
   cancel_timelocked_proposal  \  emergency_execute_timelock (Admin)
          (Admin)               \  [Bypasses delay]
            /                    v
           v               [ EXECUTED ]
     [ CANCELLED ]               ^
                                 |  execute_timelocked_proposal (Any caller)
                                 |  [Requires now >= min_execution_at]
                                 |
                            [ MATURED ] (now >= min_execution_at)
```

### 1. Proposal (`propose_timelocked_action`)
- **Caller**: Admin only (`require_admin`).
- **Validation**:
  - `action` must be in `1..=4` or `6` (`action != 0 && action <= 6 && action != 5`); otherwise panics with `RegistryError::InvalidProposalAction` (Code `35`).
  - Pending proposals count must be `< MAX_PENDING_TIMELOCK_PROPOSALS` (maximum 16 pending proposals); otherwise panics with `RegistryError::ProposalsSaturated` (Code `37`).
- **Timing**:
  - `created_at = env.ledger().timestamp()`
  - `min_execution_at = created_at.saturating_add(min_delay)`
- **Output**: Returns sequential `proposal_id` (`u32`).
- **Event**: Emits `TimelockProposalCreated`.

### 2. Cancellation (`cancel_timelocked_proposal`)
- **Caller**: Admin only (`require_admin`).
- **Validation**:
  - Proposal must exist (`ProposalNotFound`, Code `31`).
  - Proposal must not already be executed (`ProposalAlreadyExecuted`, Code `33`).
  - Proposal must not already be cancelled (`AlreadyCancelled`, Code `39`).
- **Effect**: Sets `cancelled = true`.
- **Event**: Emits `TimelockProposalCancelled`.

### 3. Normal Execution (`execute_timelocked_proposal`)
- **Caller**: Any authenticated address (`caller.require_auth()`).
- **Validation**:
  - Proposal must exist (`ProposalNotFound`, Code `31`).
  - Proposal must not already be executed (`ProposalAlreadyExecuted`, Code `33`).
  - Proposal must not be cancelled (`ProposalCancelled`, Code `34`).
  - Current timestamp must be `>= proposal.min_execution_at`; otherwise panics with `RegistryError::ProposalNotReady` (Code `32`).
- **Effect**:
  - Marks `executed = true`.
  - Dispatches action via `dispatch_timelocked_action`.
- **Event**: Emits `TimelockProposalExecuted`.

### 4. Emergency Execution (`emergency_execute_timelock`)
- **Caller**: Admin only (`require_admin`).
- **Execution Rules & Preconditions**:
  - Bypasses the timelock delay (`min_execution_at` is ignored).
  - Proposal must exist (`ProposalNotFound`, Code `31`).
  - Proposal must not already be executed (`ProposalAlreadyExecuted`, Code `33`).
  - Proposal must not be cancelled (`ProposalCancelled`, Code `34`).
  - **UpgradeWasm Restriction**: `UpgradeWasm` (`action == 6`) is **strictly disallowed** for emergency execution; calling `emergency_execute_timelock` on an `UpgradeWasm` proposal panics with `RegistryError::InvalidProposalAction` (Code `35`). In-place contract bytecode upgrades CANNOT bypass the timelock delay under any circumstances to ensure transparency and community review.
  - Can be called immediately after proposal creation when urgent remediation is required for other supported actions (e.g. revoking a compromised issuer or replacing a malfunctioning verifier).
- **Effect**:
  - Marks `executed = true`.
  - Dispatches action via `dispatch_timelocked_action`.
- **Event**: Emits `TimelockEmergencyExec`.

---

## Errors Reference

| Error Code | Variant Name | Category | Description |
|------------|--------------|----------|-------------|
| `31` | `ProposalNotFound` | State | The referenced `proposal_id` does not exist in storage. |
| `32` | `ProposalNotReady` | State | Attempted normal execution before `min_execution_at` has elapsed. Retry once time passes. |
| `33` | `ProposalAlreadyExecuted` | State | Attempted execution or cancellation of an already executed proposal. |
| `34` | `ProposalCancelled` | State | Attempted execution of a cancelled proposal. |
| `35` | `InvalidProposalAction` | Malformed | Action kind is `0`, `5`, or exceeds `6` during proposal creation, unknown at dispatch, or action is disallowed for emergency execution (e.g. `UpgradeWasm`). |
| `36` | `InvalidProposalPayload` | Malformed | Proposal payload failed formatting/size validation. |
| `37` | `ProposalsSaturated` | Resource | Active pending proposal count reached `MAX_PENDING_TIMELOCK_PROPOSALS` (`16`). |
| `38` | `InvalidTimelockDelay` | Malformed | Delay is `0` or exceeds `MAX_TIMELOCK_MIN_DELAY_SECS` (`604_800` seconds / 7 days). |
| `39` | `AlreadyCancelled` | State | Attempted cancellation of a proposal that is already cancelled. |

---

## Events Reference

All timelock events follow Soroban event conventions with structured topics:

| Event Struct | Topics | Data Fields | Description |
|--------------|--------|-------------|-------------|
| `TimelockProposalCreated` | `["timelock", "propose", proposal_id, proposer]` | `action: u32, target: Address, created_at: u64, min_execution_at: u64` | Emitted when a new timelock action is proposed. |
| `TimelockProposalCancelled` | `["timelock", "cancel", proposal_id, cancelled_by]` | `action: u32, cancelled_at: u64` | Emitted when a pending proposal is cancelled by admin. |
| `TimelockProposalExecuted` | `["timelock", "exec", proposal_id, executed_by]` | `action: u32, executed_at: u64` | Emitted when a proposal is executed after the timelock delay. |
| `TimelockEmergencyExec` | `["timelock", "emergency", proposal_id, executed_by]` | `action: u32, executed_at: u64` | Emitted when a proposal is executed immediately via emergency bypass by admin. |
| `TimelockMinDelaySet` | `["timelock", "delay", "set", set_by]` | `previous_delay: u64, new_delay: u64` | Emitted when the minimum timelock delay is reconfigured. |
| `ContractUpgraded` | `["contract", "upgrade"]` | `old_wasm_hash: BytesN<32>, new_wasm_hash: BytesN<32>` | Emitted when contract Wasm code is upgraded in-place via timelock proposal execution. |

---

## Queries and Inspection

Contract entry points for inspecting timelock state:

- `get_timelock_proposal(proposal_id: u32) -> Option<TimelockProposal>`: Fetches the stored proposal record containing action, proposer, target, payload, timestamps, and status flags (`executed`, `cancelled`).
- `get_timelock_proposal_count() -> u32`: Returns total sequential proposal count created so far.
- `get_timelock_min_delay_secs() -> u64`: Returns current minimum delay in seconds.
- `get_current_wasm_hash() -> Option<BytesN<32>>`: Returns the current active Wasm hash recorded in contract storage after an in-place upgrade.

