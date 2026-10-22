# Historical Archive: PR Description Scratch

> **Historical Archive**: This document is an unmaintained historical working note / PR scratch file preserved for reference. It is not part of the active protocol documentation.

---

# fix(frontend): cap proof-worker memory

## Summary

Caps browser proof-worker memory at the existing Harpocrates ZK boundaries:
`zk/bench/bench.lock.json` remains the source for witness/proof/public-input
ceilings, and `zk/browser.artifacts.manifest.json` remains the source for
published browser ACIR byte ceilings. Oversized work now fails with a stable
`MEMORY_LIMIT_EXCEEDED` worker code and `proof_worker_memory_exceeded` message.

Closes #<!-- issue number -->

- the registry admin controls policy, verifier configuration, credential roots, proof lifecycle, and the issuer allowlist; and
- an active issuer attests to Tier 3 evidence under institutional authority.

- Added `frontend/src/proofWorkerMemory.ts` to enforce artifact, witness, proof,
  public-input, and aggregate runtime byte budgets without logging private
  material.
- Wired the guard through `frontend/src/noirClient.ts` for Silent Witness and
  aggregation proof paths before expensive prover boundaries.
- Added the worker error mapping in `proofWorker.ts` /
  `proofWorker.types.ts`.
- Updated `zk/bench/browser_runner.mjs` so the browser-equivalent benchmark
  runner applies the same memory budget and reports RSS in the existing schema.
- Added focused frontend and benchmark tests for positive, boundary, negative,
  regression, and privacy-safe failure behavior.
- Documented malformed, oversized, unsupported, dependency-failure, expired,
  and revoked outcomes where applicable.

## Trust Boundary / Privacy

- Secrets still cross the main-thread/worker boundary only as transferred
  `ArrayBuffer`s and are zeroed in the worker.
- Failure responses carry only stable machine codes and fixed messages. They
  never include media, credential/nullifier secrets, witness values, proof hex,
  public-input hex, or private keys.
- Browser ACIR is public but still bounded before JSON parsing when the fetch
  response exposes content length or a stream.

## Compatibility / Migration

- No Noir circuit source, public-input frame, verifier-input codec, contract
  ABI, deployment artifact, or stored-evidence format changes.
- Existing compatible callers continue to use `ProofWorkerClient.generate()`.
  The only new observable behavior is a stable terminal error code when a job
  exceeds pinned memory budgets.
- No data, contract, or evidence migration is required.

## Rollback

Revert the proof-worker memory module and worker error mapping. Existing stored
evidence and on-chain state require no repair. If a full browser-worker rollback
is needed, the evidence flow can return to direct `generateSilentWitnessProof`
calls as documented in `docs/proof-worker.md`.

### Public queries

```bash
cd frontend
npx vitest run src/proofWorkerMemory.test.ts src/workers/proofWorkerClient.test.ts

cd ..
python -m pytest zk/bench -q
```
