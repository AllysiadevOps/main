# Harpocrates Noir Circuits

This folder contains the real Noir path for Tier 1 Silent Witness,
including the bounded proof aggregation circuit.

## Circuits

### `silent_witness`

The base circuit proves:

- the prover knows a private `credential_secret`
- the public `credential_root` is derived from that secret
- the public `nullifier` is bound to `credential_secret`, `nullifier_secret`, `video_hash_hi`, and `video_hash_lo`

The creator can register evidence without revealing the credential secret.

### `redacted_ancestry`

Proves that a **redacted** derivative descends from a committed parent evidence
object without revealing the unredacted parent hash, the redaction mask
preimage, or the credential secrets. The operation is bound to the canonical
lineage `redact` identifier (the ASCII field element `0x726564616374`, matching
the registry `Symbol`), and the ancestry depth is bounded to `1..=4` to match
`backend/lineage.py`.

Public statement: `parent_commitment`, `derivative_digest`,
`parameters_digest`, `operation_type`, `ancestry_root`, `nullifier`, `depth`,
`domain_tag`. Private witness: parent hash halves, parent blinding, mask
commitment, redaction seed, and the credential / nullifier secrets.

Companion helper: `redacted_ancestry_helper` derives the public statement from
the private openings for the browser/native proving path.

Synthetic vectors: [`fixtures/redacted_ancestry_vectors.json`](fixtures/redacted_ancestry_vectors.json).  
Spec: [`docs/zk-redacted-ancestry-spec.md`](../../docs/zk-redacted-ancestry-spec.md).

```bash
cd zk/noir/redacted_ancestry && nargo test
cd zk/noir/redacted_ancestry_helper && nargo test
python -m pytest zk/tools -q
```

### `silent_witness_aggregator` (NEW)

Bounded aggregation circuit that bundles up to **8** individual Silent Witness
proofs into a single verifiable UltraHonk proof.  All video hashes in the
batch must be bound to the same credential identity.

Key properties:

- **MAX_AGGREGATION_SIZE = 8**: fixed upper bound enforced at circuit and
  contract level.
- **Same-identity binding**: all `credential_root` values in the batch must
  match the root derived from the private `credential_secret`.
- **Per-element nullifiers**: each video hash gets its own nullifier,
  preventing replay of individual elements from the batch.
- **Versioned domain separator**: the circuit is bound to a protocol version
  tag, preventing cross-version proof replay.

### `silent_witness_aggregator_helper` (NEW)

Helper circuit that derives batch public inputs (`credential_root` and
`nullifier` for each element) from private secrets and video hashes.


### `revocation_witness`

Non-membership circuit for the published revocation Merkle tree. Proves a
`credential_root` is **not** among the private leaves while binding the public
`revocation_root`, `nullifier`, and domain separator.

Key properties:

- **MAX_REVOCATION_WITNESS_DEPTH = 3**: fixed upper bound (`MAX_REVOCATION_LEAVES = 8`).
  Enforced at circuit structure and mirrored in the registry / verifier codec /
  `zk/tools/revocation_depth.py`. Depth changes require a new circuit version.
- **Private leaves**: the verifier learns only the root, not which credentials
  are revoked.
- **Domain binding**: `HARPOCRATES_REVOCATION_V1` prevents cross-version replay.

### `revocation_witness_helper`

Helper circuit that derives `credential_root` / `nullifier` and Merkle root
parameters for the depth-bounded revocation tree (same MAX constants).

### `selective_disclosure`

Attribute-selective circuit behind `frontend/src/selectiveDisclosure.ts`
(`/noir/selective_disclosure.json`) and the registry's
`verify_selective_disclosure`. Bounded at **MAX_ATTRIBUTES = 16** with predicate
types restricted to eq / set-membership / range, and bound to
`CURRENT_CIRCUIT_VERSION` so a proof from another circuit version cannot be
replayed against the registry.

## Constant-time comparisons

Field equality in these circuits compiles to fixed arithmetic constraints, so
no circuit branches on secret data, and set membership scans every slot. The
off-circuit codecs that consume the public inputs compare bindings in constant
time; see [docs/zk-conformance-vectors.md](../../docs/zk-conformance-vectors.md).

## Tooling

Noir's official installation path uses `noirup`/`nargo`. Barretenberg (`bb`) is the proving backend. On Windows, the official Noir docs recommend using WSL for the full toolchain.

Inside WSL:

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
source ~/.bashrc
noirup

curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
source ~/.bashrc
bbup
```

## Reproducible builds

Toolchain versions, the hermetic environment, artifact normalization rules, and
resource limits are pinned in [`zk/toolchain.lock.json`](../toolchain.lock.json).
The double-build reproducibility check is:

```bash
zk/noir/scripts/reproducible-build.sh          # build twice, compare, write manifest
zk/noir/scripts/reproducible-build.sh --verify # build once, compare to the committed manifest
zk/noir/scripts/reproducible-build.sh --check-coverage  # every circuit pinned? (no toolchain needed)
python zk/tools/artifact_manifest.py check-coverage     # same gate, tool only
python -m pytest zk/tools -q                   # tooling unit tests, no toolchain needed
```

`--check-coverage` fails when a package under `zk/noir/` is not declared in the
lock file, or when a declared circuit has no package. A circuit that is neither
built nor digested is an unpinned second truth at a public boundary — that is how
`selective_disclosure` reached the browser and the registry verifier while sitting
outside this pipeline. Adding a circuit means updating `zk/toolchain.lock.json`
*and* `CIRCUITS` in the build script; the gate fails until both agree.

See [docs/zk-reproducible-builds.md](../../docs/zk-reproducible-builds.md).

## Benchmarks

Cold/warm proof generation and verification baselines (browser, native, CI,
Soroban-adjacent) live under `zk/bench/`:

```bash
python -m pytest zk/bench -q
zk/bench/run.sh run --target ci --synthetic
```

See [docs/zk-benchmarks.md](../../docs/zk-benchmarks.md).

## Cross-layer conformance

The public-input codec shared by the backend, browser, and Soroban registry is
pinned by [`zk/vectors/verifier_conformance_v1.json`](../vectors/verifier_conformance_v1.json).
See [docs/zk-conformance-vectors.md](../../docs/zk-conformance-vectors.md) and
[docs/zk-fuzzing.md](../../docs/zk-fuzzing.md).

## Build

For the full local build with the checked-in prover file:

```bash
cd zk/noir/silent_witness
nargo check
nargo execute witness
bb prove --scheme ultra_honk --oracle_hash keccak --bytecode_path ./target/silent_witness.json --witness_path ./target/witness.gz --output_path ./target --output_format bytes_and_fields
bb write_vk --scheme ultra_honk --oracle_hash keccak --bytecode_path ./target/silent_witness.json --output_path ./target --output_format bytes_and_fields
bb verify --scheme ultra_honk --oracle_hash keccak --vk_path ./target/vk --proof_path ./target/proof --public_inputs_path ./target/public_inputs
```

Current local proof status:

```text
nargo version = 1.0.0-beta.9
bb version = 0.87.0
silent_witness proof verified successfully with UltraHonk
```

From PowerShell on Windows:

```powershell
.\zk\noir\scripts\build-silent-witness-wsl.ps1
```

Generate proof artifacts for a specific video hash:

```powershell
.\zk\noir\scripts\generate-silent-witness-wsl.ps1 `
  -VideoHash YOUR_32_BYTE_HEX `
  -CredentialSecret YOUR_FIELD_DECIMAL `
  -NullifierSecret YOUR_FIELD_DECIMAL
```

## Browser Prover

The React app serves the compiled circuit artifacts from:

```text
frontend/public/noir/silent_witness.json
frontend/public/noir/silent_witness_helper.json
```

The browser flow runs the helper circuit first to derive `credential_root` and
`nullifier`, then runs `silent_witness` and produces an UltraHonk proof with
`@aztec/bb.js` using Keccak challenges. Smoke-test the same path in Node:

```powershell
cd frontend
node scripts/test-noir-client-prover.mjs
```

Export proof artifacts as hex for Soroban tooling:

```powershell
.\zk\noir\scripts\prepare-soroban-verifier-artifacts.ps1
.\zk\noir\scripts\export-silent-witness-artifacts.ps1
```

## Soroban Integration

The Soroban registry now has two Tier 1 entrypoints:

- `register_anonymous`: development/demo boundary.
- `register_anonymous_verified`: production-facing path that calls an external `verify_proof(public_inputs, proof)` contract.

The expected public input order is:

```text
video_hash_hi
video_hash_lo
credential_root
nullifier
```

Stellar's official privacy docs currently highlight deployable Groth16 verifier examples, while Noir/UltraHonk-on-Soroban is an emerging path. Harpocrates keeps the UltraHonk verifier isolated behind a small contract interface so the registry API can stay stable.

See `contracts/VERIFIER_INTEGRATION.md` for the remaining on-chain verifier deployment step.

## Troubleshooting

Version skew between `nargo`, `bb`, and the frontend packages (`@noir-lang/noir_js`, `@aztec/bb.js`) or path/environment discrepancies across WSL and Windows can cause cryptic build and verification failures.

Always check installed versions against the single source of truth pinned in [`zk/toolchain.lock.json`](../toolchain.lock.json):

```bash
# In WSL or Linux: inspect pinned versions in the lock file
jq '.toolchain' zk/toolchain.lock.json

# Check currently installed CLI versions
nargo --version
bb --version

# Run the WSL toolchain validation script
bash zk/noir/scripts/check-toolchain-wsl.sh
```

To install or sync toolchain binaries to the versions declared in `zk/toolchain.lock.json`:

```bash
# Read and install the pinned versions directly from the lock file
noirup -v $(jq -r '.toolchain.nargo.version' zk/toolchain.lock.json)
bbup -v $(jq -r '.toolchain.barretenberg.version' zk/toolchain.lock.json)
```

In the frontend, verify that `frontend/package.json` dependencies match the pinned versions:
- `@noir-lang/noir_js` must match `.toolchain.nargo.version`
- `@aztec/bb.js` must match `.toolchain.barretenberg.version`

### Common Errors and Fixes

#### 1. Unsupported ACIR Version / Bytecode Serialization Error

- **Error message:**
  ```text
  Error: Unsupported ACIR version: expected <= 0.X.Y, got 0.A.B
  # or
  Failed to deserialize circuit: Opcode Not Supported / ACIR version mismatch
  ```
- **Cause:** The circuit bytecode was compiled using a version of `nargo` whose ACIR format is newer or incompatible with the version expected by `@aztec/bb.js`, `@noir-lang/noir_js`, or the installed `bb` binary.
- **Fix:**
  1. Inspect the pinned versions in [`zk/toolchain.lock.json`](../toolchain.lock.json) under `.toolchain.nargo.version` and `.toolchain.barretenberg.version`.
  2. Reinstall matching CLI versions:
     ```bash
     noirup -v $(jq -r '.toolchain.nargo.version' zk/toolchain.lock.json)
     bbup -v $(jq -r '.toolchain.barretenberg.version' zk/toolchain.lock.json)
     ```
  3. Ensure `frontend/package.json` pins `@noir-lang/noir_js` and `@aztec/bb.js` to the exact versions declared in the lock file, then recompile circuits and re-test:
     ```bash
     cd zk/noir/silent_witness && nargo compile
     cd ../../../frontend && npm install
     ```

#### 2. Verification Key or Proof Mismatch (`bb verify` failure)

- **Error message:**
  ```text
  Verification failed: proof does not match verification key
  # or
  Public inputs do not match proof transcript
  ```
- **Cause:** Circuit bytecode was recompiled without updating the corresponding verification key (`vk`), proof, or public inputs, or proof artifacts were generated with different scheme/oracle flags than verification expects.
- **Fix:**
  1. Verify flags match the configuration in `zk/toolchain.lock.json` (`--scheme ultra_honk --oracle_hash keccak`).
  2. Regenerate both the verification key and proof together against the latest bytecode:
     ```bash
     cd zk/noir/silent_witness
     nargo check
     nargo execute witness
     bb prove --scheme ultra_honk --oracle_hash keccak --bytecode_path ./target/silent_witness.json --witness_path ./target/witness.gz --output_path ./target --output_format bytes_and_fields
     bb write_vk --scheme ultra_honk --oracle_hash keccak --bytecode_path ./target/silent_witness.json --output_path ./target --output_format bytes_and_fields
     bb verify --scheme ultra_honk --oracle_hash keccak --vk_path ./target/vk --proof_path ./target/proof --public_inputs_path ./target/public_inputs
     ```

#### 3. Toolchain Version Drift Gate Failure (`reproducible-build.sh`)

- **Error message:**
  ```text
  {"event":"build.error","detail":"nargo version drift: expected 1.0.0-beta.9, found ..."}
  # or
  {"event":"build.error","detail":"bb version drift: expected 0.87.0, found ..."}
  ```
- **Cause:** `zk/noir/scripts/reproducible-build.sh` enforces strict version parity against `zk/toolchain.lock.json`. Your host environment is executing an unpinned `nargo` or `bb` version.
- **Fix:**
  1. Install the pinned version targets dynamically referenced from the lock file:
     ```bash
     noirup -v $(jq -r '.toolchain.nargo.version' zk/toolchain.lock.json)
     bbup -v $(jq -r '.toolchain.barretenberg.version' zk/toolchain.lock.json)
     ```
  2. Ensure your `PATH` points to the active installation directories (typically `~/.nargo/bin` and `~/.bb`).
  3. Re-run `bash zk/noir/scripts/check-toolchain-wsl.sh` to confirm the active versions before re-running the build.

#### 4. WSL Path Translation or Not Installed Error (Windows)

- **Error message:**
  ```powershell
  Expected a Windows absolute path, got ...
  # or
  wsl: The term 'wsl' is not recognized
  # or
  /bin/bash: line 1: /mnt/c/...: No such file or directory
  ```
- **Cause:**
  - Running PowerShell helper scripts (`build-silent-witness-wsl.ps1`, `generate-silent-witness-wsl.ps1`) outside a standard Windows drive mount (e.g. UNC path), or
  - WSL is not installed or the default distribution is missing, or
  - Windows CRLF line endings in shell scripts executed inside WSL.
- **Fix:**
  1. Ensure WSL is installed with a Linux distribution (e.g. `wsl --install -d Ubuntu`).
  2. Run PowerShell from a local drive path (e.g. `C:\...`).
  3. Ensure repository shell scripts use Linux LF line endings (`git config core.autocrlf input`).
  4. Ensure execution permissions inside WSL:
     ```bash
     chmod +x zk/noir/scripts/*.sh
     ```

