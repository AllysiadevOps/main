# Redacted Derivative Ancestry - Circuit Specification

**Status:** Prototype only (`redacted_ancestry/v1`; not enabled by default)
**Issue:** #356
**Compatibility:** Additive. Does not alter `silent_witness/v1`,
`revocation_witness/v1`, the lineage HTTP API, or the Soroban `register_lineage`
frame.

## 1. Summary

`redacted_ancestry` lets a prover demonstrate that a **redacted** derivative
descends from a committed parent evidence object without revealing the
unredacted parent content, the redaction mask preimage, or the credential
secrets that bind the prover to the evidence.

It reuses the canonical lineage operation identifier `redact` from
`backend/lineage.py` and `contracts/.../harpocrates-registry` (a Soroban
`Symbol`), bound in-circuit as its ASCII field element, and the bounded depth
`MAX_LINEAGE_DEPTH = 4` already enforced by the backend and the registry. It
does not introduce a second operation enum.

## 2. Public / Private Inputs

| Input | Visibility | Notes |
| --- | --- | --- |
| `parent_hash_hi` / `parent_hash_lo` | private | Unredacted parent media hash halves |
| `parent_blinding` | private | Binding factor for the parent commitment |
| `mask_commitment` | private | Commitment to the redaction mask |
| `redaction_seed` | private | Blinding / seed for the redaction parameters |
| `credential_secret` / `nullifier_secret` | private | Identity binders |
| `parent_commitment` | public | Pedersen commitment to the parent hash halves |
| `derivative_digest` | public | Digest of the redacted derivative, bound to the parent |
| `parameters_digest` | public | Digest of the redaction parameters |
| `operation_type` | public | Must equal the canonical `redact` field |
| `ancestry_root` | public | Protocol ancestry statement commitment |
| `nullifier` | public | One-use binder for this ancestry statement |
| `depth` | public | Ancestry depth in `[1, 4]` |
| `domain_tag` | public | Protocol / version / network separator |

## 3. Statement

```
parent_commitment = pedersen([DOMAIN_PARENT_COMMIT, hi, lo, blinding])
parameters_digest = pedersen([DOMAIN_REDACT_PARAMS, mask, seed])
derivative_digest = pedersen([DOMAIN_DERIVATIVE, hi, lo, parameters_digest, seed])
ancestry_root     = pedersen([DOMAIN_ANCESTRY, parent, derivative, params, OP_REDACT, depth, CIRCUIT_VERSION])
nullifier         = pedersen([DOMAIN_NULLIFIER, cred, null_secret, ancestry_root])
domain_tag        = pedersen([PROTOCOL, VERSION, NETWORK])
```

Additionally:

- `operation_type == OP_REDACT`, where `OP_REDACT` is the ASCII field element
  `0x726564616374` (`"redact"`);
- `depth` is one of `1`, `2`, `3`, `4`;
- no direct cycle: `parent_commitment != derivative_digest`;
- required statement and private opening fields are non-zero.

The `PROTOCOL` / `VERSION` / `NETWORK` fields are identical to the
`silent_witness` circuit, so a `redacted_ancestry` proof is bound to the same
protocol boundary.

## 4. Threat Model and Privacy

**Hidden:** parent hash halves, parent blinding, mask commitment opening,
redaction seed, credential secret, nullifier secret.

**Revealed:** parent commitment, derivative digest, parameters digest, operation
identifier, ancestry root, nullifier, depth, domain tag.

**Guarantees:**

- An adversary without the parent opening cannot forge a matching
  `parent_commitment`.
- Swapping hash halves, substituting a mask, forging a derivative digest,
  tampering with the ancestry root, or substituting a serialized statement from
  a different depth or domain fails closed.
- Nullifiers are one-use and bound to the whole statement, so a proof cannot be
  replayed across depths, domains, or credentials.

## 5. Failure Modes

Malformed, unsupported, oversized, cyclic, and zeroed inputs fail with stable
assert messages:

- `operation must be redact`
- `ancestry depth out of range`
- `parent commitment must be non-zero` / `derivative digest must be non-zero`
- `parameters digest must be non-zero` / `ancestry root must be non-zero`
- `nullifier must be non-zero`
- `credential secret must be non-zero` / `nullifier secret must be non-zero`
- `parent blinding must be non-zero` / `redaction seed must be non-zero`
- `ancestry cycle detected`
- `parent commitment mismatch` / `parameters digest mismatch`
- `derivative digest mismatch` / `ancestry root mismatch`
- `nullifier mismatch` / `domain tag mismatch`

No assert message echoes a witness value, media byte, or secret. The synthetic
vector corpus carries the same codes in `expect_fail_with`, and
`zk/tools/test_redacted_ancestry_vectors.py` fails if a declared code is not an
actual assert in the circuit.

### Prototype limits

The v1 circuit proves consistency of its Pedersen-derived statement only. It
does **not** constrain actual media bytes, visible pixel/frame regions, or an
ordered chunk/Merkle commitment, and it does not verify a parent proof inside
the circuit. Therefore v1 does not yet prove crop equivalence, reordered-chunk
resistance, altered-visible-region resistance, or that the committed parent
was registered. A caller must not interpret this proof as those guarantees.
Only the operation identifier `redact` is accepted; this is not an allowlist of
implemented media transformations. Those properties require a new circuit and
statement version with bounded source/derivative chunk commitments and explicit
parent-proof binding.

The cryptographic assumptions for this prototype are collision resistance of
the Noir Pedersen hash over the selected field and soundness of the pinned
UltraHonk proof system. These assumptions do not repair the missing media and
parent-proof relations above.

## 6. Compatibility, Migration, and Rollback

- **Compatibility:** additive circuit package under `zk/noir/redacted_ancestry`
  (plus `redacted_ancestry_helper`). Existing silent-witness, aggregation,
  revocation, and selective-disclosure artifacts and the on-chain lineage frame
  are unchanged. The backend and contract still use the `redact` `Symbol`; the
  circuit mirrors it rather than redefining it.
- **Migration:** none for existing callers. New callers may opt in by proving
  `redacted_ancestry` and registering the resulting statement.
- **Version:** `CIRCUIT_VERSION = 1` is folded into `ancestry_root`, so a future
  version produces a distinct root.
- **Browser adapter:** `frontend/src/redactedAncestry.ts` loads the versioned
  helper/main ACIRs, checks the helper-derived eight-field statement against
  the generated proof frame, and locally verifies before returning a proof.
  The adapter remains opt-in. Its ACIRs must be built with the pinned toolchain,
  published under `frontend/public/noir/`, and entered into both artifact
  manifests before the API can run. The current checkout does not publish
  these artifacts.
- **Soroban plan:** do not submit this frame through the existing
  `silent_witness` verifier codec. A future registry integration needs an
  additive schema identifier, fixed eight-field canonical codec in Python,
  TypeScript, and Rust, shared conformance vectors, verifier-version-window
  support, and an explicit lineage registration binding to an already verified
  parent proof. Until those changes and circuit limitations are addressed,
  Soroban registration is not supported.
- **Rollback:** remove the two packages from `zk/noir/`, drop their entries from
  `zk/toolchain.lock.json`, the `CIRCUITS` list in
  `zk/noir/scripts/reproducible-build.sh`, and regenerate
  `zk/circuit.provenance.json`. No stored evidence or manifest format migration
  is required.

## 7. Test Expectations

Focused positive, boundary, negative, and regression coverage lives in
`zk/noir/redacted_ancestry/src/main.nr` (`nargo test`), including depth `1` and
`4` boundaries, zeroed inputs, cycles, and forged/tampered statement fields.
Synthetic, versioned vectors are in
`zk/noir/fixtures/redacted_ancestry_vectors.json`. Python schema and
assert-code drift guards run via `python -m pytest zk/tools -q` without the Noir
toolchain.

```bash
cd zk/noir/redacted_ancestry && nargo test
cd zk/noir/redacted_ancestry_helper && nargo test
python -m pytest zk/tools -q
python zk/tools/artifact_manifest.py check-coverage
```

## 8. Threat Model References

- `THREAT_MODEL.md` - protocol threat model
- `LINEAGE_IMPLEMENTATION.md` - lineage graph constraints and operation set
- `backend/lineage.py` - `MAX_LINEAGE_DEPTH`, `SUPPORTED_OPERATIONS`
- `contracts/contracts/harpocrates-registry/src/lib.rs` - `register_lineage`
