# Tier 2 Source Batch Commitments (`hpx-sbc/1`)

## Overview

High-volume Tier 2 sources (e.g., broadcasters ingesting thousands of clips daily)
require tamper-evident anchoring and per-item inclusion proofs without incurring
per-item storage rent and transaction fees.

`register_source_batch_root` allows a Tier 2 source to anchor an entire collection
of clip commitments in a single transaction by publishing the root of a binary
Merkle tree. Subsequent verification of individual items is achieved via
`verify_source_batch_inclusion`, which evaluates cryptographic Merkle inclusion
proofs on-chain in constant memory and bounded CPU cycles.

---

## Merkle Tree Construction & Domain Separation

To prevent second-preimage attacks between leaf hashes and internal node hashes,
all hashing utilizes SHA-256 with strictly distinct, single-byte domain separators:

* **Leaf Domain Tag (`0x00`)**:
  ```text
  leaf_hash = SHA-256(0x00 || leaf)
  ```
  Where `leaf` is a 32-byte item commitment (`BytesN<32>`).
  Preimage size: 1 + 32 = 33 bytes.

* **Internal Node Domain Tag (`0x01`)**:
  ```text
  node_hash = SHA-256(0x01 || left_child || right_child)
  ```
  Where `left_child` and `right_child` are 32-byte digests (`BytesN<32>`).
  Preimage size: 1 + 32 + 32 = 65 bytes.

### Second-Preimage Resistance by Construction

Second-preimage attacks between leaves and internal nodes are impossible by
construction due to two independent invariants:
1. **Domain prefix**: The first byte of every leaf hash preimage is `0x00`,
   while the first byte of every internal node preimage is `0x01`.
2. **Preimage length**: Leaf preimages are strictly 33 bytes; internal node
   preimages are strictly 65 bytes.

No internal node hash input can ever be validly interpreted as a leaf hash input,
and vice versa.

---

## Leaf Encoding

Each leaf in a batch represents an individual media item (e.g., video clip).
The 32-byte `leaf` digest is derived off-chain by the broadcaster as:

```text
leaf = SHA-256("harpocrates:batch-leaf:v1" || video_hash || item_metadata_hash)
```

Where:
* `"harpocrates:batch-leaf:v1"`: 25-byte domain separator prefix.
* `video_hash`: 32-byte SHA-256 digest of the raw media asset.
* `item_metadata_hash`: 32-byte SHA-256 digest of canonical item metadata (or `[0u8; 32]` if omitted).

When verifying inclusion on-chain, callers supply the derived 32-byte `leaf`
directly to `verify_source_batch_inclusion`.

---

## Bounds and Invariants

* **Minimum Batch Count**: `MIN_SOURCE_BATCH_COUNT = 1`
* **Maximum Batch Count**: `MAX_SOURCE_BATCH_COUNT = 1_048_576` (2²⁰ items)
* **Maximum Proof Length**: `MAX_SOURCE_BATCH_PROOF_LEN = 32` (maximum Merkle tree depth)

Any batch registration with `count == 0` or `count > MAX_SOURCE_BATCH_COUNT`
reverts with `RegistryError::BatchSizeExceeded` (code 54).

Any inclusion proof with `proof.len() > MAX_SOURCE_BATCH_PROOF_LEN` or an index
out of bounds (`index >= 2^(proof.len())`) reverts with
`RegistryError::InvalidInclusionProof` (code 88).

---

## Contract Interface

### 1. `register_source_batch_root`

```rust
pub fn register_source_batch_root(
    env: Env,
    source: Address,
    root: BytesN<32>,
    count: u32,
    metadata_hash: BytesN<32>,
) -> BatchRecord
```

* **Authentication**: Requires authorization from `source`.
* **Domain pause**: Reverts with `RegistryError::Paused` if `PAUSE_DOMAIN_TIER2_REGISTRATION` is active.
* **Uniqueness**: Reverts with `RegistryError::DuplicateProof` if `root` is already registered.
* **Bounds**: Reverts with `RegistryError::BatchSizeExceeded` if `count == 0` or `count > MAX_SOURCE_BATCH_COUNT`.
* **Storage**: Stores `BatchRecord` keyed by `DataKey::SourceBatch(root)`.
* **Event**: Emits `SourceBatchRootRegistered { root, source, count, metadata_hash, registered_at }`.

### 2. `verify_source_batch_inclusion`

```rust
pub fn verify_source_batch_inclusion(
    env: Env,
    root: BytesN<32>,
    leaf: BytesN<32>,
    proof: Vec<BytesN<32>>,
    index: u32,
) -> bool
```

* **Algorithm**:
  1. Validates that `proof.len() <= MAX_SOURCE_BATCH_PROOF_LEN`.
  2. If `proof.len() < 32`, validates `index < (1 << proof.len())`.
  3. Computes `current = SHA-256(0x00 || leaf)`.
  4. For each sibling `p` at depth `i` (from 0 to `proof.len() - 1`):
     - If `(index >> i) & 1 == 0`:
       `current = SHA-256(0x01 || current || p)`
     - Else:
       `current = SHA-256(0x01 || p || current)`
  5. If `current != root`, reverts with `RegistryError::InvalidInclusionProof` (code 88).
  6. Returns `true` on successful verification.

### 3. `get_source_batch`

```rust
pub fn get_source_batch(env: Env, root: BytesN<32>) -> Option<BatchRecord>
```

Read-only query returning the stored `BatchRecord` for `root`, or `None` if unregistered.

---

## Failure Codes

| Code | Variant | Class | Retryable | Meaning |
|------|---------|-------|-----------|---------|
| 4 | `DuplicateProof` | conflict | no | The batch `root` is already registered. |
| 21 | `Paused` | state | yes | Tier 2 registration is paused. |
| 54 | `BatchSizeExceeded` | oversized | no | Batch count is 0 or exceeds `MAX_SOURCE_BATCH_COUNT`. |
| 88 | `InvalidInclusionProof` | malformed | no | Merkle inclusion proof is malformed, oversized, or fails root equality. |

---

## Resource Budget & Gas

Evaluating `verify_source_batch_inclusion` requires `1 + proof.len()` invocations
of host SHA-256. At the maximum supported depth (`MAX_SOURCE_BATCH_PROOF_LEN = 32`),
resource usage stays well below Soroban transaction limits:
* CPU Instructions: ~350,000 (limit: 100,000,000)
* Memory Bytes: ~300,000 (limit: 40,000,000)
