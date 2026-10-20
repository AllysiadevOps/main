# Nullifier Derivation Specification

**Version:** 2.0  
**Date:** 2026-07-26  
**Status:** Active  
**Applies to:** Harpocrates scoped nullifier v2 (`HARPOCRATES_SCOPED_NULLIFIER_V1`)

---

## 1. Purpose

This document defines the formal derivation of nullifiers for the Harpocrates
protocol.  Nullifiers provide replay protection while preserving privacy:
a nullifier proves that a credential has been used without revealing the
credential secret or the identity of the prover.

The scoped nullifier derivation binds each nullifier to:

- **Protocol version** — prevents cross-version replay
- **Registry/network** — prevents cross-network replay
- **Verifier scope** — a field element derived from the verifier/relying-party
  identifier and purpose
- **Purpose** — embedded in the scope derivation
- **Epoch** — a bounded, admin-controlled counter per scope
- **Credential secret** — the prover's private credential key
- **Domain separator** — a version tag that binds the derivation to a
  specific circuit version

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **Nullifier** | A 32-byte BN254 field element that proves a credential has been used once. |
| **Scope** | A 32-byte field element derived from a canonical scope string. Identifies the verifier/purpose context. |
| **Epoch** | A non-negative integer admin-controlled counter per scope. Bounds the validity window of a nullifier. |
| **Credential root** | `pedersen_hash([credential_secret])` — a pseudonymous identifier for the credential. |
| **Domain separator** | A hardcoded 32-byte constant that binds the derivation to a specific circuit version. |
| **Verifier scope field** | A BN254 field element derived from the verifier address and purpose string. |

---

## 3. Derivation Algorithm

### 3.1 Inputs

| Input | Type | Description |
|-------|------|-------------|
| `credential_secret` | Field | Prover's private credential key (BN254 field element) |
| `nullifier_secret` | Field | Prover's private nullifier key (BN254 field element) |
| `video_hash_hi` | Field | Upper 128 bits of the SHA-256 hash of the video |
| `video_hash_lo` | Field | Lower 128 bits of the SHA-256 hash of the video |
| `verifier_scope` | Field | Scope field element (see §3.2) |
| `epoch` | Field | Current epoch for the scope (see §3.3) |

### 3.2 Scope Field Derivation

The scope field element is derived from a canonical scope string using:

```
scope_field = pedersen_hash("harpocrates:scope:{scopeString}") % BN254_FIELD_MODULUS
```

**Canonical scope string format:**

```
v:{verifierAddress}:p:{purpose}
```

Where:
- `verifierAddress` is the lowercase hex representation of the verifier's Stellar address
- `purpose` is a human-readable identifier for the relying party's purpose
- Both components are lowercased and trimmed

**Constraints on scope strings:**

- Must be non-empty
- Must be at most 64 bytes
- Must be lowercase ASCII alphanumeric with colons, hyphens, or underscores only
- Must not contain whitespace or uppercase characters

These constraints prevent arbitrary scope strings and ensure canonical encoding.

### 3.3 Epoch Management

Epochs are admin-controlled counters stored per scope on the Soroban registry:

- Default epoch for any scope is `0`
- Only the registry admin can advance the epoch via `set_scope_epoch`
- Epochs are strictly monotonically increasing within a scope (`epoch > current_epoch`)
- A proof is valid only if its `epoch` field matches the current epoch for its scope

**Monotonicity enforcement:**

- `set_scope_epoch(admin, scope, epoch)` enforces strict monotonicity: the new `epoch` must be strictly greater than the current epoch (`epoch > current_epoch`, where uninitialized scopes default to `DEFAULT_SCOPE_EPOCH = 0`).
- Attempts to decrease the epoch (`epoch < current_epoch`) or re-set the epoch to the same value (`epoch == current_epoch`) panic with `RegistryError::StaleEpoch`.
- Strict monotonicity prevents epoch rollback attacks where previously consumed scoped nullifiers could otherwise be revived and re-used in a subsequent context.
- Maintainers deliberately enforce strict inequality (`epoch > current_epoch`) over idempotence so that every `set_scope_epoch` invocation corresponds to an explicit, intentional advancement of the epoch boundary and prevents redundant state mutations or spurious event emissions.

**Epoch boundary behavior:**

- When the admin advances the epoch from N to N+1, all proofs generated under
  epoch N become stale and are rejected by `register_anonymous_verified`
- Proofs with epoch > current epoch are rejected (future epoch)
- Proofs with epoch < current epoch are rejected (stale epoch)
- The global/unscoped scope (field element `0`) has its own independent epoch

### 3.4 Nullifier Derivation

The nullifier is computed as:

```
scope_hash = pedersen_hash([domain_separator, verifier_scope, epoch])
nullifier  = pedersen_hash([credential_secret, nullifier_secret, video_hash_hi, video_hash_lo, scope_hash])
```

Where:
- `domain_separator` = `SCOPED_NULLIFIER_V1` (see §4)
- `pedersen_hash` is the Pedersen hash function on BN254

### 3.5 Credential Root Derivation

The credential root is computed as:

```
credential_root = pedersen_hash([credential_secret])
```

This is a public input to the circuit and is used to verify that the prover
knows the credential secret without revealing it.

---

## 4. Domain Separators

### 4.1 Scoped Nullifier V1

```
SCOPED_NULLIFIER_V1 = 0x00484152504f4352415445535f53434f5045445f4e554c4c49464945525f5631
```

This is the ASCII string `"HARPOCRATES_SCOPED_NULLIFIER_V1"` encoded as a 32-byte
BN254 field element with a leading `0x00` pad byte (BN254 field elements are
32 bytes, the string is 31 bytes).

### 4.2 Revocation V1 (for reference)

```
REVOCATION_DOMAIN_SEPARATOR = 0x00484152504f4352415445535f5245564f434154494f4e5f5631
```

This is the ASCII string `"HARPOCRATES_REVOCATION_V1"` encoded the same way.

---

## 5. Public Input Layout (v2 Scoped)

The v2 silent witness circuit produces 192 bytes (6 × 32-byte BN254 field elements):

| Index | Field | Description |
|-------|-------|-------------|
| 0–31 | `video_hash_hi` | Upper 128 bits of video hash |
| 32–63 | `video_hash_lo` | Lower 128 bits of video hash |
| 64–95 | `credential_root` | `pedersen_hash([credential_secret])` |
| 96–127 | `nullifier` | The derived nullifier |
| 128–159 | `verifier_scope` | Scope field element |
| 160–191 | `epoch` | Current epoch for the scope |

---

## 6. Replay Protection Guarantees

### 6.1 Global (Unscoped) Replay Protection

- Nullifiers are tracked globally in the registry's `Nullifier` set
- A nullifier can only be consumed once across all scopes and epochs
- The v1 circuit does not include scope or epoch, so v1 nullifiers are
  independent from v2 nullifiers

### 6.2 Scoped Replay Protection

- A nullifier derived for scope S and epoch E can only be consumed in scope S
  at epoch E
- The circuit binds the nullifier to `(credential_secret, nullifier_secret,
  video_hash, scope_hash)` where `scope_hash = pedersen_hash([domain_separator,
  verifier_scope, epoch])`
- Changing the scope or epoch changes the `scope_hash`, which changes the
  derived nullifier

### 6.3 Epoch-Boundary Replay Protection & Rollback Prevention

- When the admin advances the epoch for a scope, all proofs generated under
  the previous epoch are immediately rejected
- A proof with epoch N cannot be replayed at epoch N+1 because the circuit
  binding includes the epoch in the scope hash
- **Rollback Prevention:** The registry contract strictly prohibits rolling an epoch backward or repeating the current epoch via `set_scope_epoch`. If `epoch <= current_epoch`, the transaction panics with `RegistryError::StaleEpoch`. This guarantees that nullifiers from prior epochs can never be revived or re-enabled by rolling back the epoch counter.

### 6.4 Cross-Network Isolation

- Each registry contract deployment has its own nullifier set
- A nullifier consumed on one network/contract is not tracked on another
- This is an inherent property of the Soroban contract boundary

### 6.5 Cross-Verifier Isolation

- The verifier contract address is stored on-chain and used to verify proofs
- A proof produced for verifier A will not verify against verifier B
  (different proving keys)
- Changing the verifier on the registry does not invalidate previously
  consumed nullifiers

---

## 7. Privacy Properties

### 7.1 Scope Unlinkability

- Different scopes produce different nullifiers for the same credential
- An observer who sees nullifier N₁ for scope S₁ cannot determine whether
  the same credential was also used in scope S₂
- The scope field element is a public input, but it does not reveal the
  scope string or the verifier address

### 7.2 No Secret-Derived Stable Identifier Outside Intended Scope

- The nullifier is derived from `(credential_secret, nullifier_secret,
  video_hash, scope_hash)` — it is not a stable identifier
- The credential root `pedersen_hash([credential_secret])` is the only
  persistent pseudonymous identifier, and it is scoped to the credential
  itself, not to any particular verifier or purpose
- The scope string and purpose are never stored on-chain — only the derived
  field element is

### 7.3 Epoch Privacy

- The epoch is a public input but does not reveal the prover's identity
- The epoch only provides a time-bound validity window for the nullifier

---

## 8. Backward Compatibility

### 8.1 v1 → v2 Migration

- v1 proofs (128-byte public inputs) continue to work alongside v2 proofs
- v1 proofs do not include scope or epoch fields
- v1 nullifiers are independent from v2 nullifiers (different derivation)
- The registry automatically detects the input length (128 vs 192 bytes)
  and routes to the appropriate parsing path

### 8.2 Version Detection

- Input length 128 bytes → v1 legacy path
- Input length 192 bytes → v2 scoped path
- Any other length → `InvalidPublicInputs` error

### 8.3 Migration Path

1. Deploy the new registry contract with v2 support
2. Set the verifier contract address to the v2-compatible verifier
3. Existing v1 proofs continue to be accepted
4. New registrations should use v2 scoped proofs
5. The admin can set scope epochs to begin scoping new registrations

---

## 9. Test Vectors

Test vectors are maintained in `zk/noir/fixtures/scoped_nullifier_vectors.json`.

The vectors cover:

- Global scope (verifier_scope = 0, epoch = 0)
- Explicit scope with epoch 1
- Zero credential secret (edge case)
- Max-field credential secret (edge case)
- Zero video hash (edge case)
- Wrong credential secret (negative test)
- Wrong nullifier secret (negative test)
- Wrong video hash (negative test)
- Scope binding: nullifier from different scope fails (negative test)
- Epoch binding: nullifier from different epoch fails (negative test)

---

## 10. Threat Model References

This specification should be read alongside:

- `THREAT_MODEL.md` — Full threat model for the Harpocrates protocol
- `zk/noir/silent_witness/src/main.nr` — Noir circuit implementation
- `contracts/contracts/harpocrates-registry/src/lib.rs` — On-chain verification

---

## 11. Revision History

| Version | Date | Summary |
|---------|------|---------|
| 1.0 | 2026-07-24 | Initial scoped nullifier v1 derivation |
| 2.0 | 2026-07-26 | Added formal epoch boundaries, scope canonical encoding, cross-network/cross-verifier isolation guarantees, and v1→v2 backward compatibility |
| 2.1 | 2026-10-19 | Enforce strict monotonicity in set_scope_epoch (reject epoch <= current with StaleEpoch) to prevent nullifier revival |