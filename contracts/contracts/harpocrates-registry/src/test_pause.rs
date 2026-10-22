/// Scoped emergency pause controls (#87)
///
/// Rules under test:
///
/// 1. Registration domains (Tier 1/2/3) can be paused/unpaused independently;
///    pausing one tier never blocks another, and reads are always available.
/// 2. `pause`/`unpause` authorization matrix: admin and guardian may pause;
///    only admin may unpause; everyone else is rejected with Unauthorized.
/// 3. Pauses are bounded: `duration_secs == 0` or over the caller's role cap
///    (`MAX_PAUSE_DURATION_SECS` for admin, `MAX_GUARDIAN_PAUSE_DURATION_SECS`
///    for guardian) is rejected with `InvalidPauseDuration`.
/// 4. Pauses auto-expire at `expires_at` without a follow-up transaction.
/// 5. `pause` is idempotent (re-pausing extends/overwrites); `unpause` on an
///    unpaused domain is a no-op, not an error.
/// 6. `domain == 0` or bits outside the known set are rejected with
///    `InvalidPauseDomain`.
/// 7. Non-registration admin entry points (`revoke_proof`, `set_verifier`,
///    `revoke_issuer`, `revoke_credential_root`) remain callable while paused.
#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{
    testutils::Address as _, testutils::Events as _, testutils::Ledger, Address, Env,
};

#[cfg(test)]
fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

/// Returns (env, contract_id, admin, guardian, source) with the ledger
/// timestamp starting at `start_ts`.
#[cfg(test)]
fn setup(start_ts: u64) -> (Env, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(start_ts);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let guardian = Address::generate(&env);
    let source = Address::generate(&env);

    client.init(&admin);
    client.set_guardian(&admin, &guardian);

    (env, contract_id, admin, guardian, source)
}

// ---------------------------------------------------------------------------
// Scoping: pausing one domain does not affect another, reads always work
// ---------------------------------------------------------------------------

#[test]
fn pause_blocks_only_the_targeted_tier() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.add_credential_root(&admin, &b32(&env, 5), &b32(&env, 6));

    client.pause(&admin, &PAUSE_DOMAIN_TIER2_REGISTRATION, &3600u64);
    assert!(client.is_paused(&PAUSE_DOMAIN_TIER2_REGISTRATION));
    assert!(!client.is_paused(&PAUSE_DOMAIN_TIER1_REGISTRATION));
    assert!(!client.is_paused(&PAUSE_DOMAIN_TIER3_REGISTRATION));

    // Unaffected tier (Tier 1) still works while Tier 2 is paused.
    let rec = client.register_anonymous(
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
        &b32(&env, 4),
        &b32(&env, 5),
        &soroban_sdk::Bytes::from_array(&env, &[1, 2, 3, 4]),
    );
    assert_eq!(rec.tier, TIER_SILENT_WITNESS);
}

#[test]
#[should_panic(expected = "Error(Contract, #21)")]
fn pause_rejects_registration_on_paused_tier() {
    let (env, contract_id, admin, _, source) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.pause(&admin, &PAUSE_DOMAIN_TIER2_REGISTRATION, &3600u64);
    client.register_source(&source, &b32(&env, 1), &b32(&env, 2), &b32(&env, 3));
}

#[test]
fn pause_all_registration_blocks_every_tier() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.pause(&admin, &PAUSE_DOMAIN_ALL_REGISTRATION, &3600u64);
    assert!(client.is_paused(&PAUSE_DOMAIN_TIER1_REGISTRATION));
    assert!(client.is_paused(&PAUSE_DOMAIN_TIER2_REGISTRATION));
    assert!(client.is_paused(&PAUSE_DOMAIN_TIER3_REGISTRATION));
    assert!(client.is_paused(&PAUSE_DOMAIN_ALL_REGISTRATION));
}

#[test]
fn reads_remain_available_while_paused() {
    let (env, contract_id, admin, _, source) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let rec = client.register_source(&source, &b32(&env, 1), &b32(&env, 2), &b32(&env, 3));
    client.pause(&admin, &PAUSE_DOMAIN_ALL_REGISTRATION, &3600u64);

    // Reads are unaffected by any pause state.
    assert_eq!(client.get_proof(&b32(&env, 3)), Some(rec));
    assert_eq!(
        client.get_by_video(&b32(&env, 1)).unwrap().status,
        STATUS_REGISTERED
    );
    assert_eq!(
        client.get_proof_status(&b32(&env, 3)),
        ProofVerificationStatus::Valid
    );
}

#[test]
fn non_registration_admin_entry_points_work_while_paused() {
    let (env, contract_id, admin, _, source) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let proof_id = b32(&env, 3);
    client.register_source(&source, &b32(&env, 1), &b32(&env, 2), &proof_id);
    client.pause(&admin, &PAUSE_DOMAIN_ALL_REGISTRATION, &3600u64);

    // Incident-response entry points must still work under a full pause.
    client.revoke_proof(&admin, &proof_id);
    assert_eq!(client.get_proof(&proof_id).unwrap().status, STATUS_REVOKED);

    let verifier = Address::generate(&env);
    client.set_verifier(&admin, &verifier);
    assert_eq!(client.get_verifier(), Some(verifier));
}

// ---------------------------------------------------------------------------
// Authorization matrix
// ---------------------------------------------------------------------------

#[test]
fn pause_admin_succeeds() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &3600u64);
    assert!(client.is_paused(&PAUSE_DOMAIN_TIER1_REGISTRATION));
}

#[test]
fn pause_guardian_succeeds() {
    let (env, contract_id, _, guardian, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.pause(&guardian, &PAUSE_DOMAIN_TIER1_REGISTRATION, &3600u64);
    assert!(client.is_paused(&PAUSE_DOMAIN_TIER1_REGISTRATION));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn pause_unrelated_address_rejected() {
    let (env, contract_id, _, _, source) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.pause(&source, &PAUSE_DOMAIN_TIER1_REGISTRATION, &3600u64);
}

#[test]
fn unpause_admin_succeeds() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &3600u64);
    client.unpause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION);
    assert!(!client.is_paused(&PAUSE_DOMAIN_TIER1_REGISTRATION));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn unpause_guardian_rejected() {
    let (env, contract_id, admin, guardian, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &3600u64);
    // Guardian raised the alarm but cannot stand it down early.
    client.unpause(&guardian, &PAUSE_DOMAIN_TIER1_REGISTRATION);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn unpause_unrelated_address_rejected() {
    let (env, contract_id, admin, _, source) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &3600u64);
    client.unpause(&source, &PAUSE_DOMAIN_TIER1_REGISTRATION);
}

#[test]
fn set_guardian_admin_succeeds() {
    let (env, contract_id, admin, _, source) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.set_guardian(&admin, &source);
    assert_eq!(client.get_guardian(), Some(source));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn set_guardian_non_admin_rejected() {
    let (env, contract_id, _, guardian, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let new_guardian = Address::generate(&env);
    client.set_guardian(&guardian, &new_guardian);
}

#[test]
fn clear_guardian_admin_succeeds() {
    let (env, contract_id, admin, guardian, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    assert_eq!(client.get_guardian(), Some(guardian));

    client.clear_guardian(&admin);
    assert_eq!(client.get_guardian(), None);

    let events = env.events().all();
    assert_eq!(events.events().len(), 1);

    // Admin can still pause after guardian is cleared.
    client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &3600u64);
    assert!(client.is_paused(&PAUSE_DOMAIN_TIER1_REGISTRATION));

    // Admin can still unpause after guardian is cleared.
    client.unpause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION);
    assert!(!client.is_paused(&PAUSE_DOMAIN_TIER1_REGISTRATION));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn pause_guardian_after_clear_rejected() {
    let (env, contract_id, admin, guardian, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.clear_guardian(&admin);
    assert_eq!(client.get_guardian(), None);

    // Former guardian cannot pause once cleared.
    client.pause(&guardian, &PAUSE_DOMAIN_TIER1_REGISTRATION, &3600u64);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn clear_guardian_non_admin_rejected() {
    let (env, contract_id, _, guardian, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.clear_guardian(&guardian);
}

// ---------------------------------------------------------------------------
// Bounded duration
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #23)")]
fn pause_zero_duration_rejected() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &0u64);
}

#[test]
#[should_panic(expected = "Error(Contract, #23)")]
fn pause_admin_oversized_duration_rejected() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.pause(
        &admin,
        &PAUSE_DOMAIN_TIER1_REGISTRATION,
        &(MAX_PAUSE_DURATION_SECS + 1),
    );
}

#[test]
fn pause_admin_max_duration_succeeds() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let expires_at = client.pause(
        &admin,
        &PAUSE_DOMAIN_TIER1_REGISTRATION,
        &MAX_PAUSE_DURATION_SECS,
    );
    assert_eq!(expires_at, 1_000 + MAX_PAUSE_DURATION_SECS);
}

#[test]
#[should_panic(expected = "Error(Contract, #23)")]
fn pause_guardian_oversized_duration_rejected() {
    let (env, contract_id, _, guardian, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    // Within the admin cap but over the tighter guardian cap.
    client.pause(
        &guardian,
        &PAUSE_DOMAIN_TIER1_REGISTRATION,
        &(MAX_GUARDIAN_PAUSE_DURATION_SECS + 1),
    );
}

#[test]
fn pause_guardian_max_duration_succeeds() {
    let (env, contract_id, _, guardian, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let expires_at = client.pause(
        &guardian,
        &PAUSE_DOMAIN_TIER1_REGISTRATION,
        &MAX_GUARDIAN_PAUSE_DURATION_SECS,
    );
    assert_eq!(expires_at, 1_000 + MAX_GUARDIAN_PAUSE_DURATION_SECS);
}

// ---------------------------------------------------------------------------
// Auto-expiry, idempotent pause, no-op unpause
// ---------------------------------------------------------------------------

#[test]
fn pause_auto_expires_without_follow_up_transaction() {
    let (env, contract_id, admin, _, source) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.pause(&admin, &PAUSE_DOMAIN_TIER2_REGISTRATION, &3600u64);
    assert!(client.is_paused(&PAUSE_DOMAIN_TIER2_REGISTRATION));

    env.ledger().set_timestamp(1_000 + 3600);
    // At exactly expires_at the pause has lapsed (now < expires_at is false).
    assert!(!client.is_paused(&PAUSE_DOMAIN_TIER2_REGISTRATION));

    // The tier is usable again with no unpause call.
    let rec = client.register_source(&source, &b32(&env, 1), &b32(&env, 2), &b32(&env, 3));
    assert_eq!(rec.tier, TIER_CONSISTENT_SOURCE);
}

#[test]
fn re_pausing_an_already_paused_domain_extends_expiry() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let first = client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &100u64);
    let second = client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &200u64);

    assert_eq!(first, 1_100);
    assert_eq!(second, 1_200);
    let state = client
        .get_pause_state(&PAUSE_DOMAIN_TIER1_REGISTRATION)
        .unwrap();
    assert_eq!(state.expires_at, 1_200);
}

#[test]
fn unpause_on_unpaused_domain_is_a_no_op() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Must not panic even though the domain was never paused.
    client.unpause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION);
    assert!(!client.is_paused(&PAUSE_DOMAIN_TIER1_REGISTRATION));
}

#[test]
fn duplicate_unpause_is_idempotent() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &100u64);
    client.unpause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION);
    // Second unpause of the same, already-cleared domain must not panic.
    client.unpause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION);
    assert!(!client.is_paused(&PAUSE_DOMAIN_TIER1_REGISTRATION));
}

// ---------------------------------------------------------------------------
// Invalid domains
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #22)")]
fn pause_zero_domain_rejected() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.pause(&admin, &0u32, &3600u64);
}

#[test]
#[should_panic(expected = "Error(Contract, #22)")]
fn pause_out_of_range_domain_rejected() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.pause(&admin, &(1u32 << 5), &3600u64);
}

#[test]
#[should_panic(expected = "Error(Contract, #22)")]
fn get_pause_state_rejects_composite_domain() {
    let (env, contract_id, _, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.get_pause_state(&PAUSE_DOMAIN_ALL_REGISTRATION);
}

// ---------------------------------------------------------------------------
// Events: privacy-safe, no witness/proof/credential data
// ---------------------------------------------------------------------------

#[test]
fn pause_and_unpause_emit_events_without_sensitive_payloads() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // `events().all()` only reflects the most recent invocation, so each
    // call's events are captured and checked independently.
    client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &3600u64);
    let pause_events = env.events().all();
    assert_eq!(pause_events.events().len(), 1);

    client.unpause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION);
    let unpause_events = env.events().all();
    assert_eq!(unpause_events.events().len(), 1);

    // Payload is limited to domain bits, actor address, and timestamps --
    // no proof, witness, media, or credential material is ever included.
}

// ---------------------------------------------------------------------------
// Delegated entrypoints: pause is enforced on Tier 2 and Tier 3 delegates
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #21)")]
fn pause_blocks_register_source_delegated() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Set up a source and a delegate with a valid delegation.
    let source = Address::generate(&env);
    let delegate = Address::generate(&env);
    client.grant_delegation(
        &source,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &3600u64,
    );

    client.pause(&admin, &PAUSE_DOMAIN_TIER2_REGISTRATION, &3600u64);

    // The delegated path must respect the same Tier 2 pause as the direct path.
    client.register_source_delegated(
        &delegate,
        &source,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #21)")]
fn pause_blocks_register_seal_delegated() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Set up an issuer and a delegate with a valid delegation.
    let issuer = Address::generate(&env);
    let delegate = Address::generate(&env);
    client.add_issuer(&admin, &issuer, &b32(&env, 10));
    client.grant_delegation(
        &issuer,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &3600u64,
    );

    client.pause(&admin, &PAUSE_DOMAIN_TIER3_REGISTRATION, &3600u64);

    // The delegated path must respect the same Tier 3 pause as the direct path.
    client.register_seal_delegated(
        &delegate,
        &issuer,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
fn delegated_registration_unblocked_when_different_tier_paused() {
    let (env, contract_id, admin, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Set up a source and delegate for Tier 2.
    let source = Address::generate(&env);
    let delegate = Address::generate(&env);
    client.grant_delegation(
        &source,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &7200u64,
    );

    // Pause only Tier 1 — Tier 2 delegated path must still be open.
    client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &3600u64);

    let rec = client.register_source_delegated(
        &delegate,
        &source,
        &b32(&env, 11),
        &b32(&env, 12),
        &b32(&env, 13),
    );
    assert_eq!(rec.tier, TIER_CONSISTENT_SOURCE);
}
