# Independent Timestamp Claims (#339)

**Version:** 1.0  
**Status:** Active  
**Scope:** `HarpocratesRegistry` (`contracts/contracts/harpocrates-registry`)

On-chain anchoring for off-chain time attestations (`harpocrates-time-attestation/v1`).
The contract stores **commitments and ledger metadata only** — never RFC 3161 token bytes, media, witness values, or private keys.

## Trust hierarchy

| Level | Constant | Meaning |
| --- | --- | --- |
| 0 | `TIMESTAMP_ASSURANCE_NONE` | No usable sources |
| 1 | `TIMESTAMP_ASSURANCE_CLAIMED` | Claimed time only (not used alone on-chain) |
| 2 | `TIMESTAMP_ASSURANCE_OBSERVED` | Reserved for observed-without-independent |
| 3 | `TIMESTAMP_ASSURANCE_INDEPENDENT` | Stellar ledger and/or RFC 3161 commitment |

Anchoring always sets `TIMESTAMP_SOURCE_STELLAR` from `env.ledger()`, so a successful `anchor_timestamp_claim` yields assurance level 3.

## Source bitflags

| Bit | Constant | Meaning |
| --- | --- | --- |
| `0x01` | `TIMESTAMP_SOURCE_CLAIMED` | Optional claimed capture time present |
| `0x02` | `TIMESTAMP_SOURCE_STELLAR` | Ledger timestamp + sequence recorded |
| `0x04` | `TIMESTAMP_SOURCE_RFC3161` | 32-byte RFC 3161 token commitment present |

## Public interface

```text
anchor_timestamp_claim(actor, proof_id, attestation_digest, claimed_time, rfc3161_commitment) -> TimestampClaim
get_timestamp_claim(proof_id) -> Option<TimestampClaim>
has_independent_timestamp_anchor(proof_id) -> bool
```

### Authorization

`actor` must authenticate and be the registry admin, the proof `source`, or the
proof `issuer`. Otherwise `UnauthorizedTimestampActor` (75).

### Validation

* Proof must exist → else `TimestampClaimNotFound` (73)
* `attestation_digest` must be non-zero → else `InvalidTimestampClaim` (72)
* If `claimed_time > 0`, it must be ≤ ledger time + `MAX_TIMESTAMP_FUTURE_DRIFT_SECS` (300) → else (72)
* Absence of claimed time (`0`) and absence of RFC 3161 commitment (`[0;32]`) are valid
* Re-anchor allowed only as an assurance upgrade or when newly adding RFC 3161 → else `TimestampClaimAlreadyAnchored` (74)

## Storage / migration

Additive `DataKey::TimestampClaim(proof_id)`. No schema version bump; missing
keys mean “no claim” and existing proofs remain valid. Rollback: ignore the
new key; readers treat absence as unanchored.

## Privacy

Events and storage expose proof id, attestation digest, source flags,
assurance, ledger time/sequence, and optional RFC 3161 commitment hash only.

## Frontend read wrappers

`HarpocratesRegistryClient` (`frontend/src/lib/harpocratesRegistry.ts`) exposes two
read-only wrappers that surface the on-chain timestamp claim to the frontend:

```ts
getTimestampClaim(proofId: string): Promise<TimestampClaim | null>
hasIndependentTimestampAnchor(proofId: string): Promise<boolean>

```

The `TimestampClaim` type mirrors the contract structure:

```ts
interface TimestampClaim {
  proofId: string;
  attestationDigest: string;
  sources: TimestampSources;
  assurance: TimestampAssurance;
  ledgerTime: number;
  ledgerSequence: number;
  claimedTime: number;
  rfc3161Commitment: string;
}

interface TimestampSources {
  stellar: boolean;
  claimed: boolean;
  rfc3161: boolean;
}
type TimestampAssurance = 0 | 1 | 2 | 3;
```

### Bit-flag decoding

The contract returns `sources` as a u32 bitmask. The wrapper decodes it into a
typed `TimestampSources` object using the following mapping:

| Mask | `stellar` | `claimed` | `rfc3161` |
| --- | --- | --- | --- |
| `0x00` | false | false | false |
| `0x01` | false | true | false |
| `0x02` | true | false | false |
| `@0x03` | true | true | false |
| `0x04` | false | false | true |
| `0x05` | false | true | true |
| `0x06` | true | false | true |
| `0x07` | true | true | true |

Any bits outside `0x07` are ignored by the decoder (forward-compatible with
future source flags). Decoding is covered by unit tests for all eight combinations.

### Result handling

* `getTimestampClaim` returns `null` when the simulation reports no claim (missing
storage key), and a fully decoded `TimestampClaim` otherwise.
* `hasIndependentTimestampAnchor` returns the contract boolean directly and is
safe to call for proofs with no claim (the contract returns `false`).
* Both wrappers are read-only: they simulate the contract call and never submit a
transaction.
