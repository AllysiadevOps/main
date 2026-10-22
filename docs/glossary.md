# Glossary of Protocol Terms

Definitions for Harpocrates protocol vocabulary. Each term links to the
authoritative document or source file. Docs live at `docs/`; contracts live at
`contracts/`.

## Identity Tiers

### Silent Witness (Tier 1)
Anonymous identity tier built on a Noir zero-knowledge proof. A prover registers evidence against a credential identity without revealing the credential secret, using nullifier replay protection.

[README.md · Silent Witness](../README.md) — [contracts/README.md · Tier 1](../contracts/README.md) — [docs/zk-silent-witness-spec.md](zk-silent-witness-spec.md)

### Consistent Source (Tier 2)
Pseudonymous Stellar wallet source. A Stellar account attests as the source of evidence, with delegation support for pipelines acting on its behalf.

[README.md · Consistent Source](../README.md) — [contracts/README.md · Tier 2](../contracts/README.md) — [docs/contract-delegation.md](contract-delegation.md)

### Public Seal (Tier 3)
Verified institutional issuer. An approved institutional issuer seals evidence on behalf of an organization.

[README.md · Public Seal](../README.md) — [contracts/README.md · Tier 3](../contracts/README.md) — [contracts/DEPLOYMENT.md · Tier 3](../contracts/DEPLOYMENT.md)

## Nullifiers & Scopes

### Nullifier
A 32-byte BN254 field element that proves a credential has been used once, providing replay protection while preserving privacy.

[NULLIFIER_DERIVATION_SPEC.md §2 · Nullifier](../NULLIFIER_DERIVATION_SPEC.md)

### Scoped Nullifier (v2)
A nullifier bound to a scope (verifier + purpose), an epoch, a credential secret, a nullifier secret, and the video hash, preventing cross-scope and cross-epoch replay.

[NULLIFIER_DERIVATION_SPEC.md · Applies to scoped nullifier v2](../NULLIFIER_DERIVATION_SPEC.md)

### Scope
A 32-byte field element derived from a canonical scope string (`v:{verifierAddress}:p:{purpose}`) that identifies the verifier/purpose context of a proof.

[NULLIFIER_DERIVATION_SPEC.md §3.2 · Scope Field Derivation](../NULLIFIER_DERIVATION_SPEC.md)

### Scope Epoch
An admin-controlled, strictly monotonically increasing integer counter per scope that bounds the validity window of a nullifier. Advancing the epoch invalidates all proofs from prior epochs.

[NULLIFIER_DERIVATION_SPEC.md §3.3 · Epoch Management](../NULLIFIER_DERIVATION_SPEC.md)

### Nullifier Secret
The prover's private nullifier key (a BN254 field element) used together with the credential secret and video hash to derive the nullifier.

[NULLIFIER_DERIVATION_SPEC.md §3.1 · Inputs](../NULLIFIER_DERIVATION_SPEC.md)

### Domain Separator
A hardcoded 32-byte constant (e.g. `SCOPED_NULLIFIER_V1`) that binds the nullifier derivation to a specific circuit version, preventing cross-version replay.

[NULLIFIER_DERIVATION_SPEC.md §4 · Domain Separators](../NULLIFIER_DERIVATION_SPEC.md)

## Credential Roots & Revocation

### Credential Root
A pseudonymous identifier for a credential, computed as `pedersen_hash([credential_secret])`. It is a public circuit input used to verify knowledge of the credential secret without revealing it.

[NULLIFIER_DERIVATION_SPEC.md §3.5 · Credential Root Derivation](../NULLIFIER_DERIVATION_SPEC.md)

### Revocation Root
The on-chain value managed by `set_revocation_root` / `get_revocation_root` used to check non-revocation of a credential root (STATUS_REVOKED / STATUS_EXPIRED via the timelock).

[contracts/README.md · revocation root](../contracts/README.md) — [contracts/TIMELOCK.md · RevokeCredentialRoot](../contracts/TIMELOCK.md)

## Lineage & Metadata

### Lineage
Verifiable derivative media (crop, transcode, blur, redact, compose) chained to registered evidence, with bounded depth/fan-out, cycle detection, and actor binding.

[LINEAGE_IMPLEMENTATION.md](../LINEAGE_IMPLEMENTATION.md) — [contracts/LINEAGE.md](../contracts/LINEAGE.md)

### Metadata Envelope
An explicit envelope version (`METADATA_ENVELOPE_V1` or `V2`) recorded on-chain next to each proof's canonical `metadata_hash`, keeping raw envelope bytes, media, and private keys off-chain.

[contracts/METADATA_ENVELOPE.md](../contracts/METADATA_ENVELOPE.md)

## Time Assurance

### Timestamp Assurance
Independently verifiable timestamp anchoring distinguishing claimed time (device-provided), observed time (backend-recorded), and anchored time (Stellar ledger / RFC 3161 TSA).

[TIME_ATTESTATION_IMPLEMENTATION.md](../TIME_ATTESTATION_IMPLEMENTATION.md) — [backend/docs/time-attestation-protocol.md](../backend/docs/time-attestation-protocol.md)

## Roles & Delegation

### Guardian
A lower-trust, faster-response key that can pause registration for a bounded duration (up to 24 hours) but cannot unpause, set itself, or clear itself. Only the admin can lift a pause early.

[contracts/EMERGENCY_PAUSE.md · Guardian](../contracts/EMERGENCY_PAUSE.md)

### Delegation
A constrained, expiring capability granted by an issuer or source to a single delegate address for registration only, scoped by `DELEGATION_SCOPE_REGISTER_SOURCE` / `DELEGATION_SCOPE_REGISTER_SEAL`, never transferable and bounded by duration and per-grantor delegate caps.

[docs/contract-delegation.md](contract-delegation.md)

## Additional Terms

### Epoch
The current value of a scope's epoch counter; a proof is valid only if its `epoch` matches the current epoch for its scope. Defaults to `0` per scope.

[NULLIFIER_DERIVATION_SPEC.md §3.3 · Epoch Management](../NULLIFIER_DERIVATION_SPEC.md)

### Proof Event
A recorded registration or lineage event stored in NeonDB and indexed from Soroban contract events, queryable via the backend API (`GET /api/proofs`, `GET /api/proofs/by-video/:video_hash`).

[README.md · Backend API](../README.md)
