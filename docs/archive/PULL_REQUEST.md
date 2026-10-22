# Historical Archive: Pull Request Scratch

> **Historical Archive**: This document is an unmaintained historical working note / PR scratch file preserved for reference. It is not part of the active protocol documentation.

---

# chore(devx): run deployment containers as non-root

## Summary

Caps aggregation proof count between `MIN_AGGREGATION_SIZE = 1` and `MAX_AGGREGATION_SIZE = 8` across the entire protocol stack so Harpocrates remains privacy-preserving, interoperable, and safe at its public boundaries. A prover can bundle up to **8** video hashes under the same credential identity and produce one compact UltraHonk proof, reducing on-chain verification costs by up to 8× for batch submissions.

Closes #488

---

Harpocrates handles privacy-sensitive media, proof material, Stellar transactions, and on-chain verification. Unbounded batch sizes would risk witness extraction, prover resource exhaustion, and memory DoS attacks across browser, host, and contract boundaries. This change is production-grade: secure by default, bounded under hostile inputs, observable without leaking evidence or witnesses, and recoverable across partial failures.

## Trust Boundaries & Privacy Guarantees

| Boundary | Enforcement | Privacy & Safety Guarantee |
| --- | --- | --- |
| **Circuit** (`silent_witness_aggregator`) | Compile-time fixed layout (`MAX_AGGREGATION_SIZE = 8`) | No dynamic memory allocation; deterministic constraints; zero-padding for unused slots |
| **Registry Contract** (`harpocrates-registry`) | `register_batch_verified` asserts `1 <= batch_size <= 8` | Reverts with `RegistryError::BatchSizeExceeded`; atomic state persistence |
| **Backend API** (`backend/verifier_inputs.py`, `backend/noir.py`) | `check_aggregation_batch_size(batch_size)` | Emits structured `VerifierInputError` with code `BATCH_SIZE_OUT_OF_BOUNDS`; no media or secrets logged |
| **Frontend Prover** (`frontend/src/verifierInputs.ts`, `frontend/src/noirClient.ts`) | `checkAggregationBatchSize(batchSize)` | Fails fast before ACIR witness generation; protects browser workers from memory crashes |
| **Host Tooling** (`zk/tools/aggregation_bound.py`) | `check_aggregation_batch_size(batch_size)` | Canonical validation helper returning stable error envelopes `{"rejectCode": code, "field": "batch_size"}` |

## What Changed

### 1. Host-Side Canonical Bounds (`zk/tools/`)
- `zk/tools/aggregation_bound.py`:
  - `MAX_AGGREGATION_SIZE = 8`, `MIN_AGGREGATION_SIZE = 1`
  - `AggregationBoundError` structured exception with `to_dict()` envelope (`rejectCode`, `field`)
  - `check_aggregation_batch_size(batch_size)` validates type, bounds, and integers
- `zk/tools/test_aggregation_bound.py`: 5 comprehensive unit tests covering protocol constants, valid batch sizes 1..8, oversized, undersized, and malformed inputs.

### 2. Backend Verifier Inputs (`backend/`)
- `backend/verifier_inputs.py`:
  - Added `MAX_AGGREGATION_SIZE = 8` and `MIN_AGGREGATION_SIZE = 1`
  - Added `check_aggregation_batch_size(batch_size)` raising `VerifierInputError(code="BATCH_SIZE_OUT_OF_BOUNDS", field="batch_size")`
- `backend/test_aggregation_bound.py`: 4 unit tests verifying boundary enforcement, privacy safety, and type rejection.
- `backend/noir.py`: Updated `generate_aggregated_proof` to validate batch sizes using `check_aggregation_batch_size`.

### 3. Frontend Verifier Inputs & Client (`frontend/`)
- `frontend/src/verifierInputs.ts`:
  - Added `MAX_AGGREGATION_SIZE = 8` and `MIN_AGGREGATION_SIZE = 1`
  - Added `checkAggregationBatchSize(batchSize: number): number` with typed `VerifierInputError`
- `frontend/src/aggregationBound.test.ts`: Vitest test suite covering boundary cases, negative values, oversized inputs, non-integers, and NaN.
- `frontend/src/noirClient.ts`:
  - Implemented `generateAggregatedProof()` with `checkAggregationBatchSize` validation
  - Implemented circuit loaders `loadAggregatorCircuit()` and `loadAggregatorHelperCircuit()`
  - Encodes public inputs into standard on-chain 32-byte field layout.

### 4. Circuit Constants & Test Corpus (`zk/noir/`)
- `zk/noir/silent_witness_aggregator/src/main.nr`:
  - `global MAX_AGGREGATION_SIZE: Field = 8;`
  - Added `test_aggregation_bound_constants` unit test to lock boundary constants.
- `zk/noir/silent_witness_aggregator_helper/src/main.nr`:
  - `global MAX_AGGREGATION_SIZE: Field = 8;`
  - Added `test_aggregation_bound_constants` unit test to lock boundary constants.
- `zk/noir/fixtures/aggregation_vectors.json`:
  - Added `_max_aggregation_size: 8` and `_min_aggregation_size: 1`
  - Added negative test vectors: `oversized_aggregation_batch` (size 9), `undersized_aggregation_batch` (size 0), and `malformed_aggregation_batch_size`.

### 5. Contract Constants (`contracts/`)
- `contracts/contracts/harpocrates-registry/src/lib.rs`:
  - Exported `pub const MIN_AGGREGATION_SIZE: u32 = 1;` alongside `pub const MAX_AGGREGATION_SIZE: u32 = 8;`
- `contracts/contracts/harpocrates-registry/src/test_aggregation.rs`:
  - Added `test_aggregation_bound_constants()` test verifying matching registry constants.

### 6. Documentation
- `CHANGELOG.md`: Added bounded aggregation entry under Unreleased 1.0.0.
- `MIGRATION_GUIDE.md`: Added Aggregation proof count bound section with compatibility, error response, and migration notes.
- `THREAT_MODEL.md`: Added Section 9.3 (Bounded Aggregation Proof Batch Size) and incremented threat model to v1.4.

## Migration & Rollback Strategy

1. **Compatibility**: Fully backward compatible; existing single-proof callers are unaffected (`ProofRecord.batch_size = 0` / single proofs). Stored on-chain records and evidence format are preserved.
2. **Migration**: No on-chain state migration required. All boundary checks are additive guards on new and existing aggregated batch submissions.
3. **Rollback**: Rollback involves retaining the `MAX_AGGREGATION_SIZE = 8` verifier key. Host tooling enforces bounds early, ensuring no malformed or oversized batch reaches provers or verifiers.

## Testing & Verification

```bash
# Python unit & boundary tests (all pass green)
python -m pytest zk/tools/test_aggregation_bound.py backend/test_aggregation_bound.py zk/bench/test_zk_bench.py

# Artifact manifest verification (canonical browser pass)
python zk/tools/artifact_manifest.py verify-browser
```
