# Protocol proof regression suite

Pinned, synthetic regressions over Harpocrates' **public verifier-input boundary**.

## Trust boundary

- Inputs: conformance vectors under `zk/vectors/` (no real media, no production witnesses).
- Outputs: accept / stable reject codes only. Failures must not log secrets, seeds, or raw proofs.

## Compatibility

- Corpus format: `harpocrates.verifier-conformance` v1 (shared with
  `backend/test_conformance_vectors.py`, Rust `test_conformance.rs`, and the
  TypeScript conformance runner).
- Adding cases is additive; renumbering or changing accept→reject for an existing
  `id` is a breaking protocol change and needs a corpus version bump.

## Rollback

- Delete or revert this `zk/regression/` folder; the canonical corpus and existing
  layer runners remain the source of truth.

## Run conformance suite

```bash
pytest zk/regression/test_protocol_proof_suite.py -q
```

---

## On-chain Verifier E2E Test Harness (#799)

Proves end-to-end that UltraHonk proofs generated from the shipped browser circuit artifacts (`frontend/public/noir/*.json`) are accepted by the registry's `register_anonymous_verified` path when connected to a real on-chain verifier contract deployed in a local Soroban environment.

### Pinned Toolchain

- **Noir circuit compilation & witness generator**: `@noir-lang/noir_js` `1.0.0-beta.9`
- **Prover backend**: `@aztec/bb.js` `0.87.0` (UltraHonk with keccak transcript)
- **On-chain verifier**: [`NethermindEth/rs-soroban-ultrahonk`](https://github.com/NethermindEth/rs-soroban-ultrahonk) at pinned commit `9aae9581eab7bc4c69209c0322e54e119ed3180e`
- **Soroban SDK**: version `27`
- **Wasm target**: `wasm32v1-none`

### Acceptance Criteria & Assertions

1. **Valid proof registration**: A fresh UltraHonk proof generated from `frontend/public/noir/silent_witness.json` is submitted along with its 128-byte public input frame (`video_hash_hi`, `video_hash_lo`, `credential_root`, `nullifier`) to `register_anonymous_verified`. The transaction succeeds and records the proof record in the registry.
2. **Tampered input rejection**: Invoking `register_anonymous_verified` with a tampered public input or tampered proof fails closed with `InvalidProof` (`Error(Contract, #7)`).

### Running the Test Harness

#### 1. Generate proof fixture only

```bash
node zk/regression/generate_browser_proof_fixture.mjs --outDir tmp/fixtures
```

Outputs:
- `proof.bin` (valid UltraHonk proof, 14,592 bytes)
- `public_inputs.bin` (128-byte browser frame)
- `public_inputs_tampered.bin` (128 bytes with flipped nullifier byte)
- `proof_tampered.bin` (flipped proof byte)
- `vk_soroban.bin` (1,760-byte Soroban UltraHonk verification key)
- `video_hash.bin`, `metadata_hash.bin`, `proof_id.bin`, `credential_root.bin`, `memo.bin`
- `metadata.json` (hex strings and summary)

#### 2. Run full on-chain test harness (Linux / CI / WSL)

```bash
./zk/regression/test_onchain_verifier_e2e.sh
```

Environment options:
- `STELLAR_NETWORK`: `local` (default) or `testnet`
- `ADMIN_NAME`: identity name (default: `harpocrates-ci-admin`)
- `KEEP_TEMP`: set to `true` to preserve temporary build directories

#### 3. Run full on-chain test harness (PowerShell)

```powershell
.\zk\regression\test_onchain_verifier_e2e.ps1
```

#### 4. Scheduled and manual CI workflow

The test harness runs in `.github/workflows/zk-verifier-onchain-e2e.yml`:
- Nightly cron schedule (`0 4 * * *`)
- Manual trigger via `workflow_dispatch`
- Reports total wall-clock execution duration in the GitHub step summary.
