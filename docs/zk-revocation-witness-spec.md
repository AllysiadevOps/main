# Revocation Witness — Formal Statement Specification

## Status

Active (`revocation_witness/v1`).
Companion circuit: `zk/noir/revocation_witness/src/main.nr`.
Host depth bound: `zk/tools/revocation_depth.py`.
Contract integration: `contracts/contracts/harpocrates-registry/src/lib.rs`.

## 1. Summary

`revocation_witness` lets a prover prove non-membership in a published revocation
tree without revealing which credential identity is acting or which credentials
have been revoked.

Specifically, the prover demonstrates knowledge of:
1. A private `credential_secret` deriving the public `credential_root`.
2. A private `nullifier_secret` deriving the public `nullifier` to prevent proof
   replay.
3. Private leaves `leaf_0, ..., leaf_7` forming an 8-leaf, depth-3 Merkle tree
   whose computed Pedersen root matches the public `revocation_root`.
4. That `credential_root` differs from every leaf in the Merkle tree (`leaf_0`
   through `leaf_7`).

## 2. Public / Private Inputs

Circuit signature (`zk/noir/revocation_witness/src/main.nr`):

| Input | Visibility | Type | Notes |
| --- | --- | --- | --- |
| `credential_secret` | private | `Field` | Prover credential secret |
| `nullifier_secret` | private | `Field` | Nullifier blinding secret |
| `leaf_0` | private | `Field` | Merkle leaf 0 (sentinel or revoked root) |
| `leaf_1` | private | `Field` | Merkle leaf 1 |
| `leaf_2` | private | `Field` | Merkle leaf 2 |
| `leaf_3` | private | `Field` | Merkle leaf 3 |
| `leaf_4` | private | `Field` | Merkle leaf 4 |
| `leaf_5` | private | `Field` | Merkle leaf 5 |
| `leaf_6` | private | `Field` | Merkle leaf 6 |
| `leaf_7` | private | `Field` | Merkle leaf 7 |
| `revocation_root` | public | `Field` | Expected Merkle root of the revocation tree |
| `nullifier` | public | `Field` | One-use replay guard |
| `domain_separator` | public | `Field` | Protocol / domain binding separator |
| `credential_root` | public | `Field` | Pseudonymous identity anchor |

### On-Chain Wire Order (`revocation_witness/v1`)

The on-chain public-input frame (`hpx-vi` revocation frame) is exactly 128 bytes
(4 big-endian 32-byte BN254 field elements):

```text
[  0.. 32)  revocation_root   Merkle root of the revocation tree
[ 32.. 64)  nullifier         One-use replay prevention nullifier
[ 64.. 96)  domain_separator  Must match REVOCATION_DOMAIN_SEPARATOR
[ 96..128)  credential_root   Must be registered & active on-chain
```

## 3. Statement and Merkle Hashing

The circuit enforces the following relations using the BN254 Pedersen hash:

### 1. Identity and Nullifier Derivation
```text
derived_root = pedersen_hash([credential_secret])
assert derived_root == credential_root

derived_nullifier = pedersen_hash([credential_secret, nullifier_secret])
assert derived_nullifier == nullifier
```

### 2. Merkle Tree Root Computation
The tree is a fixed full binary Merkle tree of depth 3 with 8 leaves evaluated
left-to-right using 2-to-1 Pedersen hashing:

```text
node_01 = pedersen_hash([leaf_0, leaf_1])
node_23 = pedersen_hash([leaf_2, leaf_3])
node_45 = pedersen_hash([leaf_4, leaf_5])
node_67 = pedersen_hash([leaf_6, leaf_7])

node_0123 = pedersen_hash([node_01, node_23])
node_4567 = pedersen_hash([node_45, node_67])

computed_root = pedersen_hash([node_0123, node_4567])
assert computed_root == revocation_root
```

### 3. Non-Membership Verification
The circuit asserts that `credential_root` does not match any leaf:
```text
assert credential_root != leaf_0
assert credential_root != leaf_1
assert credential_root != leaf_2
assert credential_root != leaf_3
assert credential_root != leaf_4
assert credential_root != leaf_5
assert credential_root != leaf_6
assert credential_root != leaf_7
```

### 4. Domain Binding
`domain_separator` is a public input binding the proof cryptographically to the
protocol and network context. In UltraHonk, all public inputs are included in
the proof challenge transcript.

The canonical domain separator format is 32 bytes (BN254 field element):
- `0x00000000000000484152504f4352415445535f5245564f434154494f4e5f5631`
- 7 zero bytes of BN254 padding followed by the 25 ASCII bytes of
  `HARPOCRATES_REVOCATION_V1`.

## 4. Depth Bound and Tree Sizing

The depth bound is fixed protocol-wide (#357):

```text
MAX_REVOCATION_WITNESS_DEPTH = 3
MAX_REVOCATION_LEAVES = 8  (2^MAX_REVOCATION_WITNESS_DEPTH)
```

- **In-circuit:** The leaf arity is fixed at compile time to 8 leaves (`leaf_0`
  to `leaf_7`). There are no dynamic-length loops or unconstrained tree sizes.
- **Host tooling (`zk/tools/revocation_depth.py`):** Guards host-side tree
  construction and proof inputs:
  - `check_revocation_depth(depth)` enforces `1 <= depth <= 3`. Oversized depths
    (`depth > 3`) raise `DepthBoundError("depth_oversize")`. Undersized depths
    (`depth < 1`) raise `DepthBoundError("depth_undersize")`. Non-integer types
    raise `DepthBoundError("malformed_depth")`.
  - `check_revocation_leaf_count(leaf_count, depth)` enforces `leaf_count <= 8`
    and `leaf_count == 2**depth`.
- Raising the depth bound requires a new circuit version, updated contract
  constants, and regenerated verification keys.

## 5. Threat Model and Privacy Properties

- **Zero-knowledge leaf privacy:** The Merkle tree leaves are private inputs.
  The verifier learns only the published `revocation_root`, not which
  credentials have been revoked or placed in the tree.
- **Pseudonymous identity:** `credential_root` is public, but the underlying
  `credential_secret` is never revealed.
- **One-use replay prevention:** `nullifier` is deterministically derived from
  `credential_secret` and `nullifier_secret`. Consuming the nullifier on-chain
  prevents replaying the same non-revocation proof.
- **Soundness:** An attacker cannot prove non-membership if their
  `credential_root` is among `leaf_0..leaf_7` without breaking the collision
  resistance of the Pedersen hash or forging a proof.
- **Bounded execution:** Depth bound caps prover and verifier work, eliminating
  prover resource exhaustion or witness inflation attacks.

## 6. Failure Modes and Codes

### Circuit Assert Failure Codes

Noir assert failures in `zk/noir/revocation_witness/src/main.nr`:

| Failure Condition | Assert Message | Description |
| --- | --- | --- |
| `derived_root != credential_root` | `"malformed"` | Credential secret does not derive public root |
| `derived_nullifier != nullifier` | `"malformed"` | Nullifier secret does not derive public nullifier |
| `computed_root != revocation_root` | `"malformed"` | Private leaves do not hash to public revocation root |
| `credential_root == leaf_i` | `"revoked"` | Credential root is present in revocation tree at index `i` |

*(Note: Synthetic test fixtures in `revocation_vectors.json` map these semantic
rejections to `"credential root mismatch"`, `"nullifier mismatch"`,
`"revocation root mismatch"`, and `"credential is in revocation set"`).*

### Host Validation Error Codes (`zk/tools/revocation_depth.py`)

| Error Code | Field | Condition |
| --- | --- | --- |
| `depth_oversize` | `depth` | `depth > 3` or `leaf_count > 8` |
| `depth_undersize` | `depth` | `depth < 1` or `leaf_count < 1` |
| `malformed_depth` | `depth` | Non-integer, boolean, or invalid depth type |

### Contract Verification Error Codes (`HarpocratesRegistry`)

| Contract Error Code | Name | Value | Condition |
| --- | --- | --- | --- |
| `NotInitialized` | `Error(Contract, #2)` | 2 | No revocation root has been published via `set_revocation_root` |
| `DuplicateNullifier` | `Error(Contract, #6)` | 6 | Nullifier was previously consumed in a prior check |
| `VerifierNotSet` | `Error(Contract, #9)` | 9 | No external verifier contract address configured |
| `InvalidPublicInputs` | `Error(Contract, #10)` | 10 | Public inputs length != 128 bytes, wrong domain separator, or mismatch with stored revocation root |
| `UnknownCredentialRoot` | `Error(Contract, #11)` | 11 | Credential root is not registered as active on-chain |
| `RevokedCredentialRoot` | `Error(Contract, #12)` | 12 | Credential root was explicitly revoked on-chain |
| `InvalidProof` | `Error(Contract, #13)` | 13 | External UltraHonk verifier contract rejects the proof |

## 7. Registry Consumption

The Soroban registry contract (`contracts/contracts/harpocrates-registry/src/lib.rs`)
interacts with the revocation witness circuit through two primary entrypoints:

### `set_revocation_root(env: Env, admin: Address, revocation_root: BytesN<32>)`
1. Verifies admin authorization (`require_admin`).
2. Persists the 32-byte Merkle root in contract storage (`DataKey::RevocationRoot`).
3. Emits a `RevocationRootSet { revocation_root }` event.

### `check_non_revocation(env: Env, public_inputs: Bytes, proof: Bytes)`
Enforces end-to-end non-revocation before granting state transitions:
1. **Public Input Parsing & Length Check:** Parses the 128-byte slice into
   `revocation_root`, `nullifier`, `domain_separator`, and `credential_root`.
   Rejects payloads not exactly 128 bytes with `InvalidPublicInputs` (10).
2. **Domain Binding Check:** Asserts `domain_separator == REVOCATION_DOMAIN_SEPARATOR`
   (constant `0x00...484152504f4352415445535f5245564f434154494f4e5f5631`). Rejects with
   `InvalidPublicInputs` (10) if mismatched.
3. **Root Consistency Check:** Fetches `DataKey::RevocationRoot`. Reverts with
   `NotInitialized` (2) if unset, or `InvalidPublicInputs` (10) if the proof's
   `revocation_root` differs from the current stored root.
4. **Active Credential Check:** Verifies `credential_root` exists and is not
   marked revoked via `require_active_credential_root`. Reverts with
   `UnknownCredentialRoot` (11) or `RevokedCredentialRoot` (12).
5. **UltraHonk Proof Verification:** Invokes external verifier contract via
   `require_verified_proof` passing `CIRCUIT_VERSION_REVOCATION_WITNESS`,
   `public_inputs`, and `proof`. Reverts with `VerifierNotSet` (9) if unconfigured,
   or `InvalidProof` (13) on verification failure.
6. **Nullifier Recording:** Writes `DataKey::VerifierNullifier(verifier, nullifier)`
   to persistent storage to prevent replay. Reverts with `DuplicateNullifier` (6)
   if already recorded.
7. **Event Emission:** Publishes `NonRevocationChecked { credential_root, nullifier, revocation_root }`.
