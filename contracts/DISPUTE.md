# Dispute And Supersession State Machine

**Version:** 1.0  
**Status:** Active  
**Scope:** `HarpocratesRegistry` (`contracts/contracts/harpocrates-registry`)

A dispute is a bounded, auditable record that challenges a proof's accuracy
**without deleting or revoking the original proof**. Disputes are a separate
axis from revocation: a disputed proof may still report `Valid` under
`get_proof_status`. Supersession is the terminal transition that links a
disputed proof to a corrected proof.

---

## 1. State Machine

```text
Open --respond(issuer/source/admin)--> Responded
Open --dismiss(admin)----------------> Dismissed
Open --supersede(admin, corrected)--> Superseded
Responded --resolve(admin)-----------> Resolved
Responded --dismiss(admin)-----------> Dismissed
Responded --supersede(admin)-> Superseded
```

`Resolved`, `Dismissed`, and `Superseded` are terminal. A terminal dispute can
never be re-opened or transitioned again; retries fail with a stable error and
emit no event.

| Constant | Value | Meaning |
| --- | --- | --- |
| `MAX_OPEN_DISPUTES_PER_PROOF` | `4` | Cap on simultaneous non-terminal disputes per proof. |
| `MAX_OPEN_DISPUTES_PER_REPORTER` | `5` | Cap on simultaneous non-terminal disputes opened by one reporter address across all proofs. |
| `REPORTER_COOLDOWN_SECS` | `86400` | Minimum interval between two disputes by the same `reporter_hash` on the same proof. |
| `RESPOND_DEADLINE_SECS` | `604800` | Window for the issuer/source to respond. |
| `RESOLVE_DEADLINE_SECS` | `1209600` | Window for the admin to resolve after a response. |

---

## 2. Public Interface

```text
open_dispute(reporter, reporter_hash, dispute_id, proof_id, reason, commitment_hash) -> DisputeRecord
respond_dispute(responder, dispute_id, response_commitment) -> DisputeRecord
resolve_dispute(admin, dispute_id) -> DisputeRecord
dismiss_dispute(admin, dispute_id) -> DisputeRecord
supersede_dispute(admin, dispute_id, superseding_proof_id) -> DisputeRecord
get_dispute(dispute_id) -> Option<DisputeRecord>
get_open_dispute_count(proof_id) -> u32
get_reporter_open_dispute_count(reporter) -> u32
```

* `open_dispute` requires the reporter's own authorization. `dispute_id` must
  be fresh, the proof must exist, the per-proof open-dispute cap must not be
  exceeded, the reporter must hold fewer than `MAX_OPEN_DISPUTES_PER_REPORTER`
  open disputes, and the reporter must not be on cooldown.
* `resolve_dispute`, `dismiss_dispute`, and `supersede_dispute` release one
  slot of both the per-proof and the per-reporter counters.
* `respond_dispute` is authorized for the proof's issuer (Tier 3) or source
  (Tier 2); for Tier 1 anonymous proofs only the admin may respond.
* `resolve_dispute`, `dismiss_dispute`, and `supersede_dispute` are admin-only.

### Failure codes (stable, append-only)

Existing dispute codes keep their values. New ones were appended:

| Code | Name | When |
| --- | --- | --- |
| `45` | `DisputeNotFound` | Unknown `dispute_id`, missing proof, or missing superseding proof. |
| `61` | `TooManyOpenDisputes` | `MAX_OPEN_DISPUTES_PER_PROOF` already reached. |
| `62` | `DisputeWindowExpired` | Respond/resolve deadline passed. |
| `63` | `DisputeAlreadyClosed` | Transition attempted on a terminal dispute. |
| `64` | `DisputeCyclicSupersession` | Self-cycle or direct 2-cycle in supersession. |
| `65` | `UnauthorizedResponder` | Caller is neither the proof's issuer/source nor admin. |
| `66` | `ReporterOnCooldown` | Same `reporter_hash` re-reporting within the cooldown. |
| `67` | `InvalidDisputeTransition` | State does not permit the requested transition. |
| `88` | `ReporterDisputesSaturated` | Reporter already holds `MAX_OPEN_DISPUTES_PER_REPORTER` open disputes. |

Duplicate `dispute_id` reuses the existing `DuplicateProof` (`4`) code.

---

## 3. Privacy Properties

* Callers supply a 32-byte `reporter_hash = H(reporter_address || proof_id)`
  commitment; the per-proof cooldown is keyed by that commitment and it is
  the only reporter identifier emitted in events.
* To enforce `MAX_OPEN_DISPUTES_PER_REPORTER`, the authenticated reporter
  address is stored on `DisputeRecord.reporter` and as the
  `ReporterOpenDisputeCount(reporter)` key, so a terminal transition can
  release the right slot. The address already appears in the transaction's
  authorization entries, so this does not reveal anything new on-chain.
* Dispute events carry only commitments, enums, IDs, and epoch-second
  timestamps. No media, proof bytes, witnesses, raw metadata, or private keys
  are written or emitted.
* `reporter_hash` is an opaque value from the contract's perspective: a caller
  could submit a different commitment to evade per-reporter cooldown, so the
  cooldown is a spam-throttle, not an identity guarantee. On-chain spike
  detection belongs in indexers, which observe `["dispute", "open", dispute_id]`.

---

## 4. Typed Events

```text
["dispute", "open", dispute_id]       => proof_id, reason, reporter_hash, commitment_hash, respond_deadline
["dispute", "respond", dispute_id]    => proof_id, response_commitment, resolve_deadline
["dispute", "resolve", dispute_id]    => proof_id, resolved_at
["dispute", "dismiss", dispute_id]    => proof_id, resolved_at
["dispute", "supersede", dispute_id]  => proof_id, superseded_by, resolved_at
```

Failed, rejected, and cancelled calls emit no event and do not mutate storage
(Soroban invocations are atomic).

---

## 5. Storage, Migration, And Rollback

Dispute state uses persistent storage for dispute records and open dispute counts,
and temporary storage for reporter cooldowns:

```text
Dispute(dispute_id)              -> DisputeRecord
ProofOpenDisputeCount(proof_id)  -> u32
ReporterOpenDisputeCount(reporter) -> u32
ReporterCooldown(reporter_hash)  -> u64
ProofDisputeSeq(proof_id)        -> u32
ProofDispute(proof_id, seq)      -> BytesN<32>
Lineage(output_digest)           -> LineageRecord   (restored lineage key)
```

### TTL Extension Policy

Dispute records and open dispute counters must remain available as long as the
proof they reference:

* **Write operations** (`open_dispute`, `respond_dispute`, `resolve_dispute`,
  `dismiss_dispute`, `supersede_dispute`) bump the persistent TTL of `DataKey::Dispute`
  and associated open dispute counters (`ProofOpenDisputeCount`, `ReporterOpenDisputeCount`)
  using the same thresholds as proof records:
  `BUMP_THRESHOLD_LEDGERS` (241,920 ledgers / ~14 days) and `BUMP_TARGET_LEDGERS`
  (518,400 ledgers / ~30 days).
* **Read operations** (`get_dispute`, `get_open_dispute_count`) also extend the
  persistent TTL using `BUMP_THRESHOLD_LEDGERS` and `BUMP_TARGET_LEDGERS` when entries
  are accessed.
* **Cooldown entries** (`ReporterCooldown`) are stored in **temporary storage**
  with a lifetime matching `REPORTER_COOLDOWN_SECS` (~17,280 ledgers). Because
  cooldown is only needed for the 24-hour rate limit window, temporary storage
  ensures cooldown entries do not consume persistent rent unnecessarily and are
  automatically reclaimed upon expiry.

Existing deployments have none of these keys populated, which reads as
"no disputes". Upgrading to this wasm is therefore backward compatible with no
migration step and no change to `ProofRecord`, `ProofVerifierStatus`, or any
pre-existing exported function signature.

Rollback to a pre-dispute wasm simply drops the dispute entry points; the
`Dispute*`/`ReporterCooldown` entries become inert and are ignored by the older
code. There is no forward dependency and no data to clean up.

The supersession cycle guard keeps a compact reverse index at
`DataKey::Dispute(SHA-256("harp_sup_rev" || superseding_proof_id))`. The 12-byte
prefix makes collision with a legitimate caller-chosen `dispute_id`
computationally implausible; a collision would at worst reject a supersession,
never authorize one.

---

## 6. Threat Notes

* **Spam / storage exhaustion.** Bounded by `MAX_OPEN_DISPUTES_PER_PROOF`,
  `REPORTER_COOLDOWN_SECS`, fixed-size records, and the admin-only terminal
  transitions.
* **Evidence destruction.** Disputes never modify or delete the disputed
  `ProofRecord`. `supersede_dispute` links a corrected proof and leaves the
  original in place; operators must call `revoke_proof` separately if
  revocation is also required.
* **Cycle abuse.** `supersede_dispute` rejects self-links and direct
  (length-2) cycles; only the admin can create supersession edges.
* **Privacy regression.** Only commitments are persisted or emitted. The
  dispute path is not gated by domain pause, so incident response
  (`revoke_proof`, `revoke_issuer`) stays available while a tier is paused.

---

## 7. Tests

`contracts/contracts/harpocrates-registry/src/test_dispute.rs` covers positive,
negative, boundary, and regression cases: happy-path open/respond/resolve,
duplicate `dispute_id`, unknown proof, open cap, reporter cooldown, unauthorized
responder, expired respond/resolve windows, resolve-before-response rejection,
non-admin authorization, dismiss from open/responded, dismissed terminal
retry, counter release on dismissal, supersession linking, unknown/self/reverse
cycle rejection, and proof-status invariance.
