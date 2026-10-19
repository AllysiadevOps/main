# Scoped Emergency Pause Controls (#87)

Contains a compromised registration path (a bad issuer key, a broken
verifier, an abused Tier 2 signer, etc.) without freezing verification
reads or unaffected tiers.

## Threat Assumptions

- The admin key is the contract's root of trust. If it is compromised, pause
  controls cannot protect the contract on their own — the priority is
  detection and key rotation, not pause.
- A guardian key is a lower-trust, faster-response key (e.g. an on-call
  operational key or a monitoring bot) that can raise the alarm without
  holding admin authority. A compromised guardian key can only pause
  registration for up to 24 hours at a time (`MAX_GUARDIAN_PAUSE_DURATION_SECS`)
  and can never unpause — worst case it is a bounded denial of new
  registrations, not a way to bypass or weaken any check.
- Pausing must never be usable to hide, alter, or delete evidence. It only
  gates the four registration entry points; every read and every
  admin-remediation entry point (`revoke_proof`, `revoke_issuer`,
  `revoke_credential_root`, `set_verifier`) keeps working while paused.
- A stuck or lost admin/guardian key must not be able to brick registration
  forever. Every pause carries a bounded `expires_at` and lifts itself once
  the ledger clock passes it — no keeper transaction required.

## Pause Domains

One bit per identity tier's registration entry point, plus a convenience
alias that expands to all three:

| Domain constant                 | Value | Gates                                        |
|----------------------------------|-------|-----------------------------------------------|
| `PAUSE_DOMAIN_TIER1_REGISTRATION` | `1`   | `register_anonymous`, `register_anonymous_verified` |
| `PAUSE_DOMAIN_TIER2_REGISTRATION` | `2`   | `register_source`                             |
| `PAUSE_DOMAIN_TIER3_REGISTRATION` | `4`   | `register_seal`                               |
| `PAUSE_DOMAIN_ALL_REGISTRATION`   | `7`   | all three, in one call                        |

Never gated by any pause: `get_proof`, `get_proof_status`, `get_by_video`,
`has_nullifier`, `get_issuer`, `get_credential_root`, `get_verifier`,
`is_paused`, `get_pause_state`, and the admin-remediation entry points
listed above. Receipt-digest entry points are also deliberately ungated —
`add_receipt_signer`, `revoke_receipt_signer`, `commit_receipt_digest`, and
the receipt getters keep working while a registration pause is active, so
auditors can anchor and inspect receipts for already-registered proofs
during an incident (see `RECEIPT_COMMITMENT.md`).

## Roles And Authorization Matrix

| Actor            | `pause`                          | `unpause` | `set_guardian` | `clear_guardian` |
|-------------------|----------------------------------|-----------|-----------------|------------------|
| admin             | yes, up to `MAX_PAUSE_DURATION_SECS` (7 days) | yes | yes | yes |
| guardian          | yes, up to `MAX_GUARDIAN_PAUSE_DURATION_SECS` (24 hours) | no (`Unauthorized`, #3) | no (`Unauthorized`, #3) | no (`Unauthorized`, #3) |
| anyone else       | no (`Unauthorized`, #3)          | no (`Unauthorized`, #3) | no (`Unauthorized`, #3) | no (`Unauthorized`, #3) |

Only the admin can lift a pause early. A guardian can raise the alarm but
cannot stand it down before the bounded expiry — that asymmetry is
intentional so a compromised guardian key cannot re-open a path the admin
deliberately closed.

There is no guardian by default. `set_guardian` is additive and optional;
until the admin calls it (or after calling `clear_guardian`), only the admin can pause.

## State Machine

```text
unpaused --pause(caller, domain, duration)--> paused (expires_at = now + duration)
paused   --unpause(admin, domain)-----------> unpaused          (admin only, early)
paused   --ledger().timestamp() >= expires_at--> unpaused        (automatic, no transaction)
paused   --pause(caller, domain, duration)---> paused (expires_at overwritten/extended)
```

- **Idempotent pause**: re-pausing an already-paused domain overwrites its
  record with the new `paused_by`/`paused_at`/`expires_at` instead of
  erroring. Safe to retry.
- **Idempotent unpause**: unpausing a domain with no stored pause record is
  a no-op (no panic, no event).
- **Composite domains**: `PAUSE_DOMAIN_ALL_REGISTRATION` expands to the
  three single-bit domains inside one atomic call — either all three are
  updated or (on a panic, e.g. an invalid duration) none are, because
  Soroban invocations are all-or-nothing.
- **Bounded work**: exactly one storage read/write per domain bit touched
  (at most three); no loops over unbounded collections.

## Errors

| Code | Name                  | When                                                        |
|------|------------------------|--------------------------------------------------------------|
| 13   | `Paused`               | A registration call hit a domain with an unexpired pause.    |
| 14   | `InvalidPauseDomain`   | `domain` was `0` or contained bits outside the known set.    |
| 15   | `InvalidPauseDuration` | `duration_secs` was `0` or exceeded the caller's role cap.   |

## Event Schema

Privacy-safe by construction: payloads carry only a domain bitmask, actor
address, and epoch-second timestamps. No proof, witness, media, credential,
or signature material is ever included.

```text
["pause", "set", domain]      => paused_by, paused_at, expires_at
["pause", "clear", domain]    => unpaused_by, unpaused_at
["guardian", "set", guardian] => {}
["guardian", "clear"]         => {}
```

Natural (automatic) expiry does not itself emit an event, since no
transaction executes at the exact expiry moment — expiry is observable by
comparing `get_pause_state(domain).expires_at` against current ledger time,
or inferred from the absence of a `Paused` error on the next registration
attempt after the deadline.

## Migration And Compatibility

`Guardian` and `Pause(domain)` are new, additive persistent-storage keys.
Existing deployments have neither key populated, which reads as "no
guardian configured" / "nothing paused" — so upgrading a live contract to
this wasm is backward compatible with no migration step and no change in
behavior for existing callers. All 20 pre-#87 exported functions keep their
existing signatures and error codes.

### Rollback

Rolling back to a pre-#87 wasm build simply drops the `pause`/`unpause`/
`set_guardian`/`clear_guardian`/`is_paused`/`get_pause_state`/`get_guardian` entry points;
the `Guardian`/`Pause(domain)` storage entries become inert and are ignored
by the older contract code. There is no data to clean up and no forward
dependency — rollback is a plain wasm redeploy.

## Local Verification

```powershell
cd contracts
cargo test -p harpocrates-registry
stellar contract build
```

The `test_pause` module (`contracts/harpocrates-registry/src/test_pause.rs`)
covers: per-tier scoping, the full authorization matrix, bounded/oversized
durations for both roles, auto-expiry without a follow-up transaction,
idempotent pause/unpause, invalid-domain rejection, and that reads plus
admin-remediation entry points stay available under a full pause.

## Deployment Impact

No new deployment step is required. To use the feature after upgrading:

```powershell
.\scripts\set-guardian.ps1 -ContractId YOUR_REGISTRY_CONTRACT_ID -Admin harpocrates-admin -Guardian harpocrates-guardian
.\scripts\pause.ps1 -ContractId YOUR_REGISTRY_CONTRACT_ID -Caller harpocrates-admin -Domain Tier2 -DurationSecs 3600
.\scripts\unpause.ps1 -ContractId YOUR_REGISTRY_CONTRACT_ID -Admin harpocrates-admin -Domain Tier2
```

`-Domain` accepts `Tier1`, `Tier2`, `Tier3`, or `AllRegistration`.

## Troubleshooting

- **`Error(Contract, #13)` (`Paused`) on a register call**: expected —
  that tier's registration is currently paused. Call `is_paused` for the
  relevant domain, or `get_pause_state` for the exact `expires_at`, to see
  when it lifts (or have the admin `unpause` early).
- **`Error(Contract, #14)` (`InvalidPauseDomain`)**: the `domain` argument
  was `0` or included bits outside `PAUSE_DOMAIN_TIER1_REGISTRATION |
  PAUSE_DOMAIN_TIER2_REGISTRATION | PAUSE_DOMAIN_TIER3_REGISTRATION`.
  `get_pause_state` additionally requires a single bit, not a composite.
- **`Error(Contract, #15)` (`InvalidPauseDuration`)**: `duration_secs` was
  `0`, or exceeded `MAX_PAUSE_DURATION_SECS` (admin) /
  `MAX_GUARDIAN_PAUSE_DURATION_SECS` (guardian). Guardians who need a
  longer pause should escalate to the admin.
- **Guardian call to `unpause`, `set_guardian`, or `clear_guardian` fails with
  `Error(Contract, #3)` (`Unauthorized`)**: by design — only the admin can
  lift a pause or configure/clear the guardian.
- **Pause "isn't lifting"**: pauses lift automatically once
  `ledger().timestamp() >= expires_at`; `get_pause_state` may still return a
  stale record after that point until an explicit `unpause` clears it, but
  `is_paused` and the registration guards already treat it as unpaused.

## Limitations

- Pause is scoped to the four registration entry points only. It does not
  gate issuer/credential-root management, `revoke_proof`, or the receipt
  digest entry points (`add_receipt_signer`, `revoke_receipt_signer`,
  `commit_receipt_digest`), by design (those are the tools used to contain,
  clean up, and audit during an incident).
- There is a single guardian slot, not a list — rotate it with
  `set_guardian` rather than trying to run multiple guardians.
- Pause state is public (`is_paused`, `get_pause_state` take no auth), so it
  is observable by anyone, including an attacker deciding when to retry.
  This is an intentional tradeoff: pause status is operational metadata, not
  evidence, and hiding it would not meaningfully slow a determined attacker.
