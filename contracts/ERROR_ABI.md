# Contract Error ABI (`hpx-err/1`)

ABI version: 1

This document is the published, stable error ABI of the `HarpocratesRegistry`
Soroban contract (`contracts/harpocrates-registry`). It is the canonical
cross-layer mapping from `RegistryError` discriminants to the names, failure
classes, and retry hints that callers, indexers, SDKs, and the back end may rely on.

Failure on-chain is a reverting transaction carrying one `RegistryError` code.
The code is the ABI; the variant name is for humans and logs.

## Why This Exists

- **Interoperability.** Integrators can key retry, UX, and alerting decisions on
  the numeric code without pattern-matching SDK error strings.
- **Stability.** Existing codes are frozen. New failures are appended with the next
  unused number and never renumber an existing one, so stored evidence, emitted
  events, and deployed callers stay valid across upgrades.
- **Privacy.** A failure response is only ever `(code, name, class, retryable)`.
  Proof bytes, public inputs, witnesses, nullifiers, media, credentials, signatures,
  and private keys are never part of an error and never logged.

## Failure Classes

Every code below carries exactly one class. The six classes named in the issue
scope are `malformed`, `oversized`, `expired`, `revoked`, `unsupported`, and
`dependency`; the remaining four keep the taxonomy total.

| Class | Meaning |
|-------|---------|
| `malformed` | the input is syntactically or structurally invalid, or fails a range / domain-tag check |
| `oversized` | the input is well-formed but exceeds a documented bound (page, batch, depth, fan-out) |
| `expired` | a deadline, window, epoch, or cooldown has passed at the evaluated ledger time |
| `revoked` | a credential root, parent proof, or similar anchor has been withdrawn |
| `unsupported` | the referenced schema, issuer, credential root, or artifact version is not usable |
| `dependency` | a configured external dependency (the verifier contract) is missing or unusable |
| `auth` | the caller is authenticated but not authorized for this scope or operation |
| `conflict` | the request collides with existing evidence or would create a cycle / duplicate |
| `resource` | an internal per-key cap would be exceeded; the request is rejected without writes |
| `state` | the object exists but is not in the state the transition requires (or is already done) |

## Stable Codes

`Retryable` means the *same* call may succeed later with no code or input change,
once the external condition (unpause, timelock delay, activation ledger, cooldown,
issuer rotation grace window) has resolved. Every other code requires a different
input, a different actor, or new evidence before the call can succeed.

| Code | Variant | Class | Retryable | Meaning |
|------|---------|-------|-----------|---------|
| 1 | `AlreadyInitialized` | state | no | `init` was called on a registry that already has an admin. |
| 2 | `NotInitialized` | state | no | The operation requires an initialized registry. |
| 3 | `Unauthorized` | auth | no | The caller is not the admin or an authorized actor for this operation. |
| 4 | `DuplicateProof` | conflict | no | The `proof_id` is already registered. |
| 5 | `DuplicateVideo` | conflict | no | The `video_hash` is already bound to a registered proof. |
| 6 | `DuplicateNullifier` | conflict | no | The nullifier was already consumed by an earlier registration. |
| 7 | `InvalidProof` | malformed | no | The proof was rejected at the verifier boundary. |
| 8 | `UnknownIssuer` | unsupported | no | The issuer is not approved for Tier 3 registrations. |
| 9 | `VerifierNotSet` | dependency | no | No external verifier contract is configured. |
| 10 | `InvalidPublicInputs` | malformed | no | Public inputs are malformed, wrong length, or out of range. |
| 11 | `UnknownCredentialRoot` | unsupported | no | The credential root is not registered. |
| 12 | `RevokedCredentialRoot` | revoked | no | The credential root was revoked. |
| 13 | `HistorySaturated` | resource | no | The proof reached `MAX_HISTORY_ENTRIES_PER_PROOF`. |
| 14 | `InvalidHistoryAction` | malformed | no | The history action code is not defined. |
| 15 | `InvalidReasonCode` | malformed | no | The reason code is outside the bounded `0..=255` range. |
| 16 | `HistoryLimitExceeded` | oversized | no | The requested history page is above `MAX_HISTORY_LIMIT`. |
| 17 | `AlreadyExpired` | expired | no | The proof is already in expired status. |
| 18 | `NoCorrectionChange` | state | no | A correction supplied the same `metadata_hash`. |
| 19 | `HistoryCorruption` | state | no | Stored history bytes could not be decoded. |
| 20 | `NoPendingAdmin` | state | no | There is no pending admin transfer to accept or cancel. |
| 21 | `Paused` | state | yes | The target pause domain is active; retry after it is unpaused. |
| 22 | `InvalidPauseDomain` | malformed | no | The pause domain is zero or carries unknown bits. |
| 23 | `InvalidPauseDuration` | malformed | no | The pause duration is zero or above the role cap. |
| 24 | `InvalidDelegationScope` | malformed | no | The delegation scope is zero or carries unknown bits. |
| 25 | `InvalidDelegationDuration` | malformed | no | The delegation duration is zero or above `MAX_DELEGATION_DURATION_SECS`. |
| 26 | `DelegationNotFound` | state | no | No delegation exists from the named grantor to the caller. |
| 27 | `DelegationExpired` | expired | no | The delegation exists but its `expires_at` has passed. |
| 28 | `DelegationScopeExceeded` | auth | no | The live delegation does not carry the scope this operation needs. |
| 29 | `DelegationsSaturated` | resource | no | The grantor reached `MAX_DELEGATIONS_PER_GRANTOR`. |
| 30 | `SelfDelegation` | malformed | no | A grantor attempted to delegate to itself. |
| 31 | `ProposalNotFound` | state | no | The timelock proposal id does not exist. |
| 32 | `ProposalNotReady` | state | yes | The timelock delay has not elapsed; retry once it does. |
| 33 | `ProposalAlreadyExecuted` | state | no | The timelock proposal was already executed. |
| 34 | `ProposalCancelled` | state | no | The timelock proposal was cancelled. |
| 35 | `InvalidProposalAction` | malformed | no | The proposal action code is not supported. |
| 36 | `InvalidProposalPayload` | malformed | no | The proposal payload failed validation. |
| 37 | `ProposalsSaturated` | resource | no | The proposal queue is full. |
| 38 | `InvalidTimelockDelay` | malformed | no | The timelock delay is outside the allowed bounds. |
| 39 | `AlreadyCancelled` | state | no | The staged verifier rotation was already cancelled. |
| 40 | `RotationNotScheduled` | state | no | No staged verifier rotation is pending. |
| 41 | `RotationNotReady` | state | yes | The rotation activation ledger has not been reached yet. |
| 42 | `RotationWindowClosed` | expired | no | The rotation rollback window has closed. |
| 43 | `BatchTooLarge` | oversized | no | The batch exceeds the accepted element count. |
| 44 | `InvalidScopeEpoch` | malformed | no | The scope epoch value is out of range. |
| 45 | `DisputeNotFound` | state | no | The dispute id does not exist. |
| 46 | `DisputeAlreadyResolved` | state | no | The dispute was already resolved or dismissed. |
| 47 | `SupersessionCycleDetected` | conflict | no | Superseding the proof would create a cycle. |
| 48 | `SupersessionNotFound` | state | no | The referenced superseding proof does not exist. |
| 49 | `DomainTagMismatch` | malformed | no | The domain separation tag does not match the expected domain. |
| 50 | `UnknownSchema` | unsupported | no | The schema id is not registered. |
| 51 | `InactiveSchema` | unsupported | no | The schema was deprecated and cannot be used. |
| 52 | `SchemaVersionMismatch` | unsupported | no | The schema version is not the expected one. |
| 53 | `StaleEpoch` | expired | no | The scoped-nullifier proof was generated for a stale scope epoch, or `set_scope_epoch` attempted a non-increasing epoch. |
| 54 | `BatchSizeExceeded` | oversized | no | The batch is empty or above the element cap. |
| 55 | `BatchCredentialRootMismatch` | malformed | no | Batch elements do not share one credential root. |
| 56 | `BatchCountMismatch` | malformed | no | The batch size does not match the supplied video-hash list. |
| 57 | `InvalidLineage` | malformed | no | A lineage parent proof or lineage record was not found. |
| 58 | `LineageCycle` | conflict | no | The lineage edge would introduce a cycle. |
| 59 | `LineageTooDeep` | oversized | no | The requested lineage depth is above `MAX_LINEAGE_DEPTH`. |
| 60 | `LineageFanOutExceeded` | oversized | no | The requested lineage fan-out is above `MAX_LINEAGE_FANOUT`. |
| 61 | `TooManyOpenDisputes` | resource | no | The proof reached `MAX_OPEN_DISPUTES_PER_PROOF`. |
| 62 | `DisputeWindowExpired` | expired | no | The respond or resolve deadline for this transition has passed. |
| 63 | `DisputeAlreadyClosed` | state | no | The dispute is already in a terminal state. |
| 64 | `DisputeCyclicSupersession` | conflict | no | Dispute supersession would create a direct or depth-1 cycle. |
| 65 | `UnauthorizedResponder` | auth | no | The caller is not the proof issuer, source, or dispute admin. |
| 66 | `ReporterOnCooldown` | expired | yes | The reporter must wait out `REPORTER_COOLDOWN_SECS`; retry after it. |
| 67 | `InvalidDisputeTransition` | malformed | no | The dispute is not in the state this transition requires. |
| 68 | `UnsupportedMetadataEnvelopeVersion` | unsupported | no | The metadata envelope version is zero or above the accepted max. |
| 69 | `InvalidMetadataEnvelope` | malformed | no | The metadata envelope hash is zero or malformed. |
| 70 | `MetadataEnvelopeNotFound` | state | no | There is no metadata envelope or proof for the requested id. |
| 71 | `MetadataEnvelopeHashMismatch` | conflict | no | The bound envelope hash does not match the proof `metadata_hash`. |
| 72 | `InvalidTimestampClaim` | malformed | no | The timestamp claim is malformed, far-future, or missing a required digest. |
| 73 | `TimestampClaimNotFound` | state | no | No timestamp claim exists for the requested proof. |
| 74 | `TimestampClaimAlreadyAnchored` | state | no | The claim is already anchored and the update is not an allowed upgrade. |
| 75 | `UnauthorizedTimestampActor` | auth | no | The caller is neither admin nor the proof source or issuer. |
| 76 | `LineageEmptyParents` | malformed | no | Lineage registration supplied zero parents. |
| 77 | `LineageParentUnavailable` | revoked | no | A lineage parent proof is revoked or expired and cannot anchor a derivative. |
| 78 | `DuplicateLineage` | conflict | no | The lineage output digest is already registered. |
| 79 | `LineageChildrenLimitExceeded` | oversized | no | The `list_lineage_children` limit is zero or above the page cap. |
| 80 | `LineageChildrenSaturated` | resource | no | The parent reached `MAX_LINEAGE_CHILDREN_PER_PARENT`. |
| 81 | `UnsupportedCircuitVersion` | unsupported | no | The proof's circuit version is outside the active verifier's declared window. |
| 82 | `InvalidCircuitVersionRange` | malformed | no | The requested circuit-version window is empty or outside the wasm build's range. |
| 83 | `InvalidIssuerRotationGrace` | malformed | no | The requested rotation grace window is above `MAX_ISSUER_ROTATION_GRACE_SECS` or overflows ledger time. |
| 84 | `InvalidIssuerRotation` | malformed | no | A rotation named the same issuer key twice. |
| 85 | `IssuerRotationNotFound` | state | no | No issuer rotation grace record exists for the requested key. |
| 86 | `IssuerRotationGraceStillActive` | state | yes | The issuer rotation grace window has not lapsed; retry once it has. |
| 87 | `CircuitVersionMismatch` | unsupported | no | The scoped envelope commits a circuit version other than the expected one, or is the bare frame that commits none. |
| 88 | `ReporterDisputesSaturated` | resource | no | The reporter reached `MAX_OPEN_DISPUTES_PER_REPORTER`. |

## Privacy Rules

1. An error never echoes input material. Rejections are reported as a code, not as a
   dump of the offending bytes.
2. Host-side tooling and tests that print failures must print only the code, the
   variant name, and the class. The fuzz, budget, and conformance harnesses already
   follow this rule and this ABI makes it enforceable.
3. Failure is never signalled through a success event. Rejected calls emit no
   `proof/reg`, `proof/history`, or other lifecycle event, so an indexer can never
   mistake a rejected submission for accepted evidence.
4. `RegistryError` codes are safe to log and to surface to end users; they carry no
   witness values, private keys, or unhashed personal data.

## Compatibility And Migration

- **Additive only.** Codes `1..=86` are frozen at this ABI version. A future change
  that needs a new failure appends the next unused discriminant and adds a row here;
  it must not insert, reorder, or reuse a code.
- **No storage impact.** The ABI describes revert values. It does not add storage
  keys, change record layouts, or alter any existing entrypoint signature, so no
  migration is required to adopt it.
- **No contract version change.** `get_storage_schema_version` is unaffected; this
  document describes the behavior of the current interface, it does not change it.
- **Compatible callers.** A caller that already recovered from a code keeps working.
  A caller that only matched on message text should switch to the numeric code and
  the class column, which are the stable parts of this contract.
- **Downgrade.** Older readers ignore unknown codes and continue to treat any revert
  as a failure. Rolling back this documentation has no on-chain effect.

## Threat Model Notes

- Distinct codes for authorization (`Unauthorized`, `UnauthorizedResponder`,
  `UnauthorizedTimestampActor`, `DelegationScopeExceeded`) and for missing versus
  revoked anchors (`UnknownCredentialRoot` vs `RevokedCredentialRoot`) let operators
  alert on the difference between "not configured" and "withdrawn" without reading
  private material.
- `VerifierNotSet` is the only `dependency` failure: it means the registry was asked
  to verify against a verifier contract that was never configured, which is a
  fail-closed deployment fault rather than an input fault.
- The bounded resource classes (`oversized`, `resource`) make denial-of-service
  attempts observable as specific codes while the caps themselves keep the work
  bounded, so a hostile caller cannot turn the ABI into an unbounded work oracle.
- Failure classes are coarse by design. They must not be widened into oracles that
  leak, for example, whether a particular nullifier or video hash was seen before;
  `DuplicateProof`, `DuplicateVideo`, and `DuplicateNullifier` are deliberately
  distinct only at the code level, and callers should not expose them as a
  membership test on private evidence.

## Verification

`contracts/harpocrates-registry/src/test_error_abi.rs` parses this file and asserts
that the documented codes, names, and classes match the Rust enum exactly:

```bash
cd contracts
cargo test -p harpocrates-registry error_abi -- --nocapture
```

The suite fails if a variant is renamed, renumbered, dropped, duplicated, or if a
row uses a class outside the documented set, so this file cannot silently drift from
the contract.
