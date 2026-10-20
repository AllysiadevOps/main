//! Dispute / correction state-machine tests (#dispute).
//!
//! Covers acceptance criteria:
//!   - Invalid state transitions, duplicate submissions, unauthorized resolution,
//!     expired windows, cyclic supersession, concurrent decisions
//!   - Disputed / superseded / valid / revoked / expired are distinct statuses
//!   - Resolution never deletes the original proof record
//!   - Open-dispute cap (MAX_OPEN_DISPUTES_PER_PROOF)
//!   - Per-reporter open-dispute cap (MAX_OPEN_DISPUTES_PER_REPORTER)
//!   - Reporter cooldown

#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

fn b32u(env: &Env, pos: usize, v: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[pos] = v;
    BytesN::from_array(env, &arr)
}

/// Create a fresh env + client, init registry, register a source proof and a
/// seal proof. Returns everything callers need.
fn make_env() -> (
    Env,
    Address,    // contract_id
    Address,    // admin
    Address,    // source
    Address,    // issuer
    BytesN<32>, // source_proof_id
    BytesN<32>, // seal_proof_id
) {
    let env = Env::default();
    env.mock_all_auths();
    // Start at a non-epoch-zero timestamp so `resolved_at` and the reporter
    // cooldown (which stores/compares raw timestamps) are observable.
    env.ledger().set_timestamp(1_000_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);

    client.init(&admin);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAA));

    let source_proof_id = b32(&env, 0x01);
    client.register_source(
        &source,
        &b32(&env, 0x02),
        &b32(&env, 0x03),
        &source_proof_id,
    );

    let seal_proof_id = b32(&env, 0x11);
    client.register_seal(&issuer, &b32(&env, 0x12), &b32(&env, 0x13), &seal_proof_id);

    (
        env,
        contract_id,
        admin,
        source,
        issuer,
        source_proof_id,
        seal_proof_id,
    )
}

// ---------------------------------------------------------------------------
// open_dispute: happy path stores record
// ---------------------------------------------------------------------------

#[test]
fn open_dispute_stores_record() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0xD1);
    let rep_hash = b32(&env, 0xE1);
    let commitment = b32(&env, 0xC1);

    let rec = client.open_dispute(
        &reporter,
        &rep_hash,
        &dispute_id,
        &spid,
        &DisputeReason::ContentError,
        &commitment,
    );

    assert_eq!(rec.status, DisputeStatus::Open);
    assert_eq!(rec.dispute_id, dispute_id);
    assert_eq!(rec.proof_id, spid);
    assert_eq!(rec.reason, DisputeReason::ContentError);
    assert_eq!(rec.reporter_hash, rep_hash);
    assert_eq!(rec.commitment_hash, commitment);
    assert_eq!(rec.response_commitment, None);
    assert_eq!(rec.superseded_by, None);
    assert_eq!(rec.resolved_at, 0);

    let fetched = client.get_dispute(&dispute_id).expect("dispute not found");
    assert_eq!(fetched.status, DisputeStatus::Open);
    assert_eq!(client.get_open_dispute_count(&spid), 1);
}

// ---------------------------------------------------------------------------
// open_dispute: duplicate dispute_id rejected
// ---------------------------------------------------------------------------

#[test]
fn duplicate_dispute_id_rejected() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0xD2);

    client.open_dispute(
        &reporter,
        &b32(&env, 0xE2),
        &dispute_id,
        &spid,
        &DisputeReason::MetadataError,
        &b32(&env, 0xC2),
    );

    let result = client.try_open_dispute(
        &reporter,
        &b32(&env, 0xE2),
        &dispute_id,
        &spid,
        &DisputeReason::MetadataError,
        &b32(&env, 0xC2),
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// open_dispute: non-existent proof rejected
// ---------------------------------------------------------------------------

#[test]
fn dispute_nonexistent_proof_rejected() {
    let (env, cid, _admin, _source, _issuer, _, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    let reporter = Address::generate(&env);
    let result = client.try_open_dispute(
        &reporter,
        &b32(&env, 0xE3),
        &b32(&env, 0xD3),
        &b32(&env, 0xFF),
        &DisputeReason::Other,
        &b32(&env, 0xC3),
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// open_dispute: open-cap enforced
// ---------------------------------------------------------------------------

#[test]
fn open_dispute_cap_enforced() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    for i in 0..MAX_OPEN_DISPUTES_PER_PROOF {
        let reporter = Address::generate(&env);
        client.open_dispute(
            &reporter,
            &b32u(&env, 0, (0xE0 + i) as u8),
            &b32u(&env, 1, (0xD0 + i) as u8),
            &spid,
            &DisputeReason::Other,
            &b32u(&env, 2, (0xC0 + i) as u8),
        );
    }
    assert_eq!(
        client.get_open_dispute_count(&spid),
        MAX_OPEN_DISPUTES_PER_PROOF
    );

    let reporter = Address::generate(&env);
    let result = client.try_open_dispute(
        &reporter,
        &b32(&env, 0xEF),
        &b32(&env, 0xDF),
        &spid,
        &DisputeReason::Other,
        &b32(&env, 0xCF),
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// open_dispute: reporter cooldown
// ---------------------------------------------------------------------------

#[test]
fn reporter_cooldown_enforced() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let rep_hash = b32(&env, 0xE5);

    client.open_dispute(
        &reporter,
        &rep_hash,
        &b32(&env, 0xD5),
        &spid,
        &DisputeReason::TierMismatch,
        &b32(&env, 0xC5),
    );

    // Still on cooldown after 1 second
    let ts = env.ledger().timestamp();
    env.ledger().set_timestamp(ts + 1);

    let result = client.try_open_dispute(
        &reporter,
        &rep_hash,
        &b32(&env, 0xD6),
        &spid,
        &DisputeReason::TierMismatch,
        &b32(&env, 0xC6),
    );
    assert!(result.is_err());

    // Past cooldown succeeds
    env.ledger().set_timestamp(ts + REPORTER_COOLDOWN_SECS + 1);
    client.open_dispute(
        &reporter,
        &rep_hash,
        &b32(&env, 0xD7),
        &spid,
        &DisputeReason::TierMismatch,
        &b32(&env, 0xC7),
    );
}

// ---------------------------------------------------------------------------
// respond_dispute: happy path
// ---------------------------------------------------------------------------

#[test]
fn respond_dispute_happy_path() {
    let (env, cid, _admin, source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0xAA);

    client.open_dispute(
        &reporter,
        &b32(&env, 0xEA),
        &dispute_id,
        &spid,
        &DisputeReason::ContentError,
        &b32(&env, 0xCA),
    );

    let rec = client.respond_dispute(&source, &dispute_id, &b32(&env, 0xBA));
    assert_eq!(rec.status, DisputeStatus::Responded);
    assert_eq!(rec.response_commitment, Some(b32(&env, 0xBA)));
    assert!(rec.resolve_deadline > 0);
}

// ---------------------------------------------------------------------------
// respond_dispute: unauthorized responder rejected
// ---------------------------------------------------------------------------

#[test]
fn unauthorized_responder_rejected() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let stranger = Address::generate(&env);
    let dispute_id = b32(&env, 0xCC);

    client.open_dispute(
        &reporter,
        &b32(&env, 0xEC),
        &dispute_id,
        &spid,
        &DisputeReason::ContentError,
        &b32(&env, 0xCC),
    );

    let result = client.try_respond_dispute(&stranger, &dispute_id, &b32(&env, 0xDC));
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// respond_dispute: deadline expired
// ---------------------------------------------------------------------------

#[test]
fn respond_after_deadline_rejected() {
    let (env, cid, _admin, source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0xF1);

    client.open_dispute(
        &reporter,
        &b32(&env, 0xE1),
        &dispute_id,
        &spid,
        &DisputeReason::ContentError,
        &b32(&env, 0xC1),
    );

    let ts = env.ledger().timestamp();
    env.ledger().set_timestamp(ts + RESPOND_DEADLINE_SECS + 1);

    let result = client.try_respond_dispute(&source, &dispute_id, &b32(&env, 0xD1));
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// resolve_dispute: happy path open→respond→resolve
// ---------------------------------------------------------------------------

#[test]
fn resolve_dispute_happy_path() {
    let (env, cid, admin, source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0xBB);

    client.open_dispute(
        &reporter,
        &b32(&env, 0xEB),
        &dispute_id,
        &spid,
        &DisputeReason::PrivacyViolation,
        &b32(&env, 0xCB),
    );
    client.respond_dispute(&source, &dispute_id, &b32(&env, 0xDB));

    let rec = client.resolve_dispute(&admin, &dispute_id);
    assert_eq!(rec.status, DisputeStatus::Resolved);
    assert!(rec.resolved_at > 0);
    assert_eq!(client.get_open_dispute_count(&spid), 0);

    // Proof unchanged
    let proof = client.get_proof(&spid).expect("proof deleted");
    assert_eq!(proof.status, STATUS_REGISTERED);
}

// ---------------------------------------------------------------------------
// resolve_dispute: resolve-deadline expired
// ---------------------------------------------------------------------------

#[test]
fn resolve_after_deadline_rejected() {
    let (env, cid, admin, source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0xF2);

    client.open_dispute(
        &reporter,
        &b32(&env, 0xE2),
        &dispute_id,
        &spid,
        &DisputeReason::ContentError,
        &b32(&env, 0xC2),
    );
    client.respond_dispute(&source, &dispute_id, &b32(&env, 0xD2));

    let ts = env.ledger().timestamp();
    env.ledger().set_timestamp(ts + RESOLVE_DEADLINE_SECS + 1);

    let result = client.try_resolve_dispute(&admin, &dispute_id);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// resolve_dispute: cannot resolve Open (must be Responded first)
// ---------------------------------------------------------------------------

#[test]
fn cannot_resolve_open_dispute() {
    let (env, cid, admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0xF4);

    client.open_dispute(
        &reporter,
        &b32(&env, 0xE4),
        &dispute_id,
        &spid,
        &DisputeReason::ContentError,
        &b32(&env, 0xC4),
    );

    let result = client.try_resolve_dispute(&admin, &dispute_id);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// resolve_dispute: non-admin rejected
// ---------------------------------------------------------------------------

#[test]
fn non_admin_cannot_resolve() {
    let (env, cid, _admin, source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let stranger = Address::generate(&env);
    let dispute_id = b32(&env, 0xDD);

    client.open_dispute(
        &reporter,
        &b32(&env, 0xED),
        &dispute_id,
        &spid,
        &DisputeReason::ContentError,
        &b32(&env, 0xCD),
    );
    client.respond_dispute(&source, &dispute_id, &b32(&env, 0xDE));

    let result = client.try_resolve_dispute(&stranger, &dispute_id);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// dismiss_dispute: open -> dismissed releases the open counter
// ---------------------------------------------------------------------------

#[test]
fn dismiss_open_dispute_releases_counter() {
    let (env, cid, admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0x71);

    client.open_dispute(
        &reporter,
        &b32(&env, 0x72),
        &dispute_id,
        &spid,
        &DisputeReason::Other,
        &b32(&env, 0x73),
    );
    assert_eq!(client.get_open_dispute_count(&spid), 1);

    let rec = client.dismiss_dispute(&admin, &dispute_id);
    assert_eq!(rec.status, DisputeStatus::Dismissed);
    assert!(rec.resolved_at > 0);
    assert_eq!(client.get_open_dispute_count(&spid), 0);

    // Dismissal never deletes or mutates the original proof.
    let proof = client.get_proof(&spid).expect("proof deleted");
    assert_eq!(proof.status, STATUS_REGISTERED);
}

// ---------------------------------------------------------------------------
// dismiss_dispute: responded -> dismissed is also valid
// ---------------------------------------------------------------------------

#[test]
fn dismiss_responded_dispute_succeeds() {
    let (env, cid, admin, source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0x74);

    client.open_dispute(
        &reporter,
        &b32(&env, 0x75),
        &dispute_id,
        &spid,
        &DisputeReason::Other,
        &b32(&env, 0x76),
    );
    client.respond_dispute(&source, &dispute_id, &b32(&env, 0x77));

    let rec = client.dismiss_dispute(&admin, &dispute_id);
    assert_eq!(rec.status, DisputeStatus::Dismissed);
    assert_eq!(client.get_open_dispute_count(&spid), 0);
}

// ---------------------------------------------------------------------------
// dismiss_dispute: terminal disputes cannot be dismissed again (regression)
// ---------------------------------------------------------------------------

#[test]
fn dismiss_closed_dispute_rejected() {
    let (env, cid, admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0x78);

    client.open_dispute(
        &reporter,
        &b32(&env, 0x79),
        &dispute_id,
        &spid,
        &DisputeReason::Other,
        &b32(&env, 0x7A),
    );
    client.dismiss_dispute(&admin, &dispute_id);

    let result = client.try_dismiss_dispute(&admin, &dispute_id);
    assert!(result.is_err());
    // Counter must not go negative / wrap on the rejected retry.
    assert_eq!(client.get_open_dispute_count(&spid), 0);
}

#[test]
fn non_admin_cannot_dismiss() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let stranger = Address::generate(&env);
    let dispute_id = b32(&env, 0x7B);

    client.open_dispute(
        &reporter,
        &b32(&env, 0x7C),
        &dispute_id,
        &spid,
        &DisputeReason::Other,
        &b32(&env, 0x7D),
    );
    let result = client.try_dismiss_dispute(&stranger, &dispute_id);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// supersede_dispute: links a correcting proof and records the direction
// ---------------------------------------------------------------------------

#[test]
fn supersede_links_correcting_proof() {
    let (env, cid, admin, _source, _issuer, spid, sealid) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0x81);

    client.open_dispute(
        &reporter,
        &b32(&env, 0x82),
        &dispute_id,
        &spid,
        &DisputeReason::ContentError,
        &b32(&env, 0x83),
    );
    assert_eq!(client.get_open_dispute_count(&spid), 1);

    let rec = client.supersede_dispute(&admin, &dispute_id, &sealid);
    assert_eq!(rec.status, DisputeStatus::Superseded);
    assert_eq!(rec.superseded_by, Some(sealid.clone()));
    assert!(rec.resolved_at > 0);
    assert_eq!(client.get_open_dispute_count(&spid), 0);

    // The superseding proof and the disputed proof both survive unchanged.
    assert!(client.get_proof(&spid).is_some());
    assert_eq!(client.get_proof(&spid).unwrap().status, STATUS_REGISTERED,);
    assert!(client.get_proof(&sealid).is_some());
}

#[test]
fn supersede_unknown_proof_rejected() {
    let (env, cid, admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0x84);

    client.open_dispute(
        &reporter,
        &b32(&env, 0x85),
        &dispute_id,
        &spid,
        &DisputeReason::Other,
        &b32(&env, 0x86),
    );

    let result = client.try_supersede_dispute(&admin, &dispute_id, &b32(&env, 0xFF));
    assert!(result.is_err());
}

#[test]
fn supersede_self_cycle_rejected() {
    let (env, cid, admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0x87);

    client.open_dispute(
        &reporter,
        &b32(&env, 0x88),
        &dispute_id,
        &spid,
        &DisputeReason::Other,
        &b32(&env, 0x89),
    );

    let result = client.try_supersede_dispute(&admin, &dispute_id, &spid);
    assert!(result.is_err());
}

// Regression: a supersession cannot be reversed into a 2-cycle.
#[test]
fn supersede_reverse_cycle_rejected() {
    let (env, cid, admin, _source, _issuer, spid, sealid) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    // Dispute on spid, corrected by sealid  =>  sealid supersedes spid.
    let d1 = b32(&env, 0x8A);
    client.open_dispute(
        &Address::generate(&env),
        &b32(&env, 0x8B),
        &d1,
        &spid,
        &DisputeReason::ContentError,
        &b32(&env, 0x8C),
    );
    client.supersede_dispute(&admin, &d1, &sealid);

    // Attempting the reverse (spid supersedes sealid) must be rejected.
    let d2 = b32(&env, 0x8D);
    client.open_dispute(
        &Address::generate(&env),
        &b32(&env, 0x8E),
        &d2,
        &sealid,
        &DisputeReason::ContentError,
        &b32(&env, 0x8F),
    );
    let result = client.try_supersede_dispute(&admin, &d2, &spid);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Disputes are separate from revocation: status is unaffected
// ---------------------------------------------------------------------------

#[test]
fn dispute_does_not_change_proof_status() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);
    let dispute_id = b32(&env, 0x91);

    client.open_dispute(
        &reporter,
        &b32(&env, 0x92),
        &dispute_id,
        &spid,
        &DisputeReason::MetadataError,
        &b32(&env, 0x93),
    );

    assert_eq!(
        client.get_proof_status(&spid),
        ProofVerificationStatus::Valid,
    );
}

// Boundary: exactly MAX_OPEN_DISPUTES_PER_PROOF open disputes then a dismissal
// frees a slot for a new dispute.
#[test]
fn dismiss_frees_open_dispute_slot() {
    let (env, cid, admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let mut first = b32(&env, 0xA0);

    for i in 0..MAX_OPEN_DISPUTES_PER_PROOF {
        let reporter = Address::generate(&env);
        let dispute_id = b32u(&env, 1, (0xA0 + i) as u8);
        if i == 0 {
            first = dispute_id.clone();
        }
        client.open_dispute(
            &reporter,
            &b32u(&env, 0, (0xB0 + i) as u8),
            &dispute_id,
            &spid,
            &DisputeReason::Other,
            &b32u(&env, 2, (0xC0 + i) as u8),
        );
    }
    assert_eq!(
        client.get_open_dispute_count(&spid),
        MAX_OPEN_DISPUTES_PER_PROOF
    );

    client.dismiss_dispute(&admin, &first);
    assert_eq!(
        client.get_open_dispute_count(&spid),
        MAX_OPEN_DISPUTES_PER_PROOF - 1
    );

    client.open_dispute(
        &Address::generate(&env),
        &b32(&env, 0xBF),
        &b32(&env, 0xAF),
        &spid,
        &DisputeReason::Other,
        &b32(&env, 0xCF),
    );
    assert_eq!(
        client.get_open_dispute_count(&spid),
        MAX_OPEN_DISPUTES_PER_PROOF
    );
}

// Boundary: omitted (`None`) reason codes / unknown dispute ids are safe reads.
#[test]
fn get_dispute_unknown_id_is_none() {
    let (env, cid, _admin, _source, _issuer, _spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    assert!(client.get_dispute(&b32(&env, 0xFE)).is_none());
}

// ---------------------------------------------------------------------------
// Per-reporter open-dispute cap (MAX_OPEN_DISPUTES_PER_REPORTER)
// ---------------------------------------------------------------------------

/// Register `n` additional source proofs with unique ids / hashes so a single
/// reporter can dispute distinct proofs without touching the per-proof cap.
fn register_extra_proofs(
    env: &Env,
    client: &HarpocratesRegistryClient,
    source: &Address,
    n: u32,
) -> std::vec::Vec<BytesN<32>> {
    let mut ids = std::vec::Vec::new();
    for i in 0..n {
        let tag = (0x40 + i) as u8;
        let pid = b32u(env, 3, tag);
        client.register_source(source, &b32u(env, 4, tag), &b32u(env, 5, tag), &pid);
        ids.push(pid);
    }
    ids
}

/// Open a dispute by `reporter` on `proof_id`, using `tag` to derive a fresh
/// dispute id, reporter_hash, and commitment.
fn open_tagged(
    env: &Env,
    client: &HarpocratesRegistryClient,
    reporter: &Address,
    proof_id: &BytesN<32>,
    tag: u8,
) -> BytesN<32> {
    let dispute_id = b32u(env, 6, tag);
    client.open_dispute(
        reporter,
        &b32u(env, 7, tag),
        &dispute_id,
        proof_id,
        &DisputeReason::Other,
        &b32u(env, 8, tag),
    );
    dispute_id
}

fn reporter_saturated_err() -> Result<soroban_sdk::Error, soroban_sdk::InvokeError> {
    Ok(soroban_sdk::Error::from_contract_error(
        RegistryError::ReporterDisputesSaturated as u32,
    ))
}

#[test]
fn reporter_cap_reached_then_dismiss_releases_slot_and_reopen_succeeds() {
    let (env, cid, admin, source, _issuer, _spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);

    let proofs = register_extra_proofs(&env, &client, &source, MAX_OPEN_DISPUTES_PER_REPORTER + 1);

    let mut disputes = std::vec::Vec::new();
    for i in 0..MAX_OPEN_DISPUTES_PER_REPORTER {
        disputes.push(open_tagged(&env, &client, &reporter, &proofs[i as usize], i as u8));
    }
    assert_eq!(
        client.get_reporter_open_dispute_count(&reporter),
        MAX_OPEN_DISPUTES_PER_REPORTER
    );

    // One more dispute on a fresh proof is rejected by the reporter cap.
    let extra = &proofs[MAX_OPEN_DISPUTES_PER_REPORTER as usize];
    let res = client.try_open_dispute(
        &reporter,
        &b32u(&env, 7, 0x60),
        &b32u(&env, 6, 0x60),
        extra,
        &DisputeReason::Other,
        &b32u(&env, 8, 0x60),
    );
    assert_eq!(res, Err(reporter_saturated_err()));
    // Rejection is atomic: no counters moved.
    assert_eq!(client.get_open_dispute_count(extra), 0);
    assert!(client.get_dispute(&b32u(&env, 6, 0x60)).is_none());

    // A different reporter is unaffected.
    let other = Address::generate(&env);
    open_tagged(&env, &client, &other, extra, 0x61);
    assert_eq!(client.get_reporter_open_dispute_count(&other), 1);

    // Dismissing one dispute releases a slot.
    client.dismiss_dispute(&admin, &disputes[0]);
    assert_eq!(
        client.get_reporter_open_dispute_count(&reporter),
        MAX_OPEN_DISPUTES_PER_REPORTER - 1
    );

    // Reopen succeeds and the cap is reached again.
    open_tagged(&env, &client, &reporter, extra, 0x62);
    assert_eq!(
        client.get_reporter_open_dispute_count(&reporter),
        MAX_OPEN_DISPUTES_PER_REPORTER
    );
}

#[test]
fn reporter_cap_released_on_resolve_and_supersede() {
    let (env, cid, admin, source, _issuer, _spid, sealid) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let reporter = Address::generate(&env);

    let proofs = register_extra_proofs(&env, &client, &source, MAX_OPEN_DISPUTES_PER_REPORTER + 2);

    let mut disputes = std::vec::Vec::new();
    for i in 0..MAX_OPEN_DISPUTES_PER_REPORTER {
        disputes.push(open_tagged(&env, &client, &reporter, &proofs[i as usize], i as u8));
    }

    // Resolve path: respond then resolve.
    client.respond_dispute(&source, &disputes[0], &b32(&env, 0x91));
    // A responded (still open) dispute keeps holding its slot.
    assert_eq!(
        client.get_reporter_open_dispute_count(&reporter),
        MAX_OPEN_DISPUTES_PER_REPORTER
    );
    client.resolve_dispute(&admin, &disputes[0]);
    assert_eq!(
        client.get_reporter_open_dispute_count(&reporter),
        MAX_OPEN_DISPUTES_PER_REPORTER - 1
    );

    let p_a = &proofs[MAX_OPEN_DISPUTES_PER_REPORTER as usize];
    open_tagged(&env, &client, &reporter, p_a, 0x70);
    assert_eq!(
        client.try_open_dispute(
            &reporter,
            &b32u(&env, 7, 0x71),
            &b32u(&env, 6, 0x71),
            &proofs[MAX_OPEN_DISPUTES_PER_REPORTER as usize + 1],
            &DisputeReason::Other,
            &b32u(&env, 8, 0x71),
        ),
        Err(reporter_saturated_err())
    );

    // Supersede path releases a slot too.
    client.supersede_dispute(&admin, &disputes[1], &sealid);
    assert_eq!(
        client.get_reporter_open_dispute_count(&reporter),
        MAX_OPEN_DISPUTES_PER_REPORTER - 1
    );
    open_tagged(
        &env,
        &client,
        &reporter,
        &proofs[MAX_OPEN_DISPUTES_PER_REPORTER as usize + 1],
        0x72,
    );
    assert_eq!(
        client.get_reporter_open_dispute_count(&reporter),
        MAX_OPEN_DISPUTES_PER_REPORTER
    );

    // Retrying a terminal transition must not double-release the slot.
    assert!(client.try_dismiss_dispute(&admin, &disputes[0]).is_err());
    assert_eq!(
        client.get_reporter_open_dispute_count(&reporter),
        MAX_OPEN_DISPUTES_PER_REPORTER
    );
}

#[test]
fn reporter_cap_does_not_change_per_proof_cap() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    // Distinct reporters each open one dispute on the same proof: the
    // per-proof cap still trips at MAX_OPEN_DISPUTES_PER_PROOF.
    for i in 0..MAX_OPEN_DISPUTES_PER_PROOF {
        let r = Address::generate(&env);
        open_tagged(&env, &client, &r, &spid, (0x80 + i) as u8);
        assert_eq!(client.get_reporter_open_dispute_count(&r), 1);
    }
    let r = Address::generate(&env);
    let res = client.try_open_dispute(
        &r,
        &b32u(&env, 7, 0x8F),
        &b32u(&env, 6, 0x8F),
        &spid,
        &DisputeReason::Other,
        &b32u(&env, 8, 0x8F),
    );
    assert_eq!(
        res,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::TooManyOpenDisputes as u32
        )))
    );
    assert_eq!(client.get_reporter_open_dispute_count(&r), 0);
}

// ---------------------------------------------------------------------------
// list_proof_disputes: empty, multiple, pagination, all statuses, supersession
// ---------------------------------------------------------------------------

#[test]
fn test_list_proof_disputes_empty() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    assert_eq!(client.get_proof_dispute_count(&spid), 0);
    let disputes = client.list_proof_disputes(&spid, &0, &10);
    assert_eq!(disputes.len(), 0);

    let unknown_proof = b32(&env, 0xEE);
    assert_eq!(client.get_proof_dispute_count(&unknown_proof), 0);
    let unknown_disputes = client.list_proof_disputes(&unknown_proof, &0, &10);
    assert_eq!(unknown_disputes.len(), 0);
}

#[test]
fn test_list_proof_disputes_multiple_and_pagination() {
    let (env, cid, _admin, _source, _issuer, spid, _) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    let mut expected_ids = std::vec::Vec::new();
    for i in 0..MAX_OPEN_DISPUTES_PER_PROOF {
        let reporter = Address::generate(&env);
        let d_id = open_tagged(&env, &client, &reporter, &spid, (0x90 + i) as u8);
        expected_ids.push(d_id);
    }

    assert_eq!(
        client.get_proof_dispute_count(&spid),
        MAX_OPEN_DISPUTES_PER_PROOF
    );

    // Page 1: limit 2 from cursor 0
    let page1 = client.list_proof_disputes(&spid, &0, &2);
    assert_eq!(page1.len(), 2);
    assert_eq!(page1.get(0).unwrap(), expected_ids[0]);
    assert_eq!(page1.get(1).unwrap(), expected_ids[1]);

    // Page 2: limit 2 from cursor 2
    let page2 = client.list_proof_disputes(&spid, &2, &2);
    assert_eq!(page2.len(), 2);
    assert_eq!(page2.get(0).unwrap(), expected_ids[2]);
    assert_eq!(page2.get(1).unwrap(), expected_ids[3]);

    // Page 3: limit 2 from cursor 4 (past last item)
    let page3 = client.list_proof_disputes(&spid, &4, &2);
    assert_eq!(page3.len(), 0);

    // Cursor far past end
    let page_past = client.list_proof_disputes(&spid, &10, &2);
    assert_eq!(page_past.len(), 0);

    // Limit 0 returns empty
    let page_zero = client.list_proof_disputes(&spid, &0, &0);
    assert_eq!(page_zero.len(), 0);

    // Limit exceeding cap is clamped without error
    let page_capped = client.list_proof_disputes(&spid, &0, &(MAX_PROOF_DISPUTES_PAGE + 10));
    assert_eq!(page_capped.len(), 4);
    for i in 0..4 {
        assert_eq!(page_capped.get(i as u32).unwrap(), expected_ids[i]);
    }
}

#[test]
fn test_list_proof_disputes_all_statuses_and_supersession() {
    let (env, cid, admin, source, _issuer, spid, sealid) = make_env();
    let client = HarpocratesRegistryClient::new(&env, &cid);

    let r0 = Address::generate(&env);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);
    let r3 = Address::generate(&env);

    let d0 = open_tagged(&env, &client, &r0, &spid, 0xA0);
    let d1 = open_tagged(&env, &client, &r1, &spid, 0xA1);
    let d2 = open_tagged(&env, &client, &r2, &spid, 0xA2);
    let d3 = open_tagged(&env, &client, &r3, &spid, 0xA3);

    // d0 stays Open.
    // d1 transitions to Responded.
    client.respond_dispute(&source, &d1, &b32(&env, 0xB1));
    // d2 transitions to Responded, then Resolved.
    client.respond_dispute(&source, &d2, &b32(&env, 0xB2));
    client.resolve_dispute(&admin, &d2);
    // d3 transitions to Dismissed.
    client.dismiss_dispute(&admin, &d3);

    // Resolving d2 and dismissing d3 freed 2 open dispute slots.
    // Open d4 and supersede it with sealid.
    let r4 = Address::generate(&env);
    let d4 = open_tagged(&env, &client, &r4, &spid, 0xA4);
    client.supersede_dispute(&admin, &d4, &sealid);

    // Total disputes indexed for spid is 5.
    assert_eq!(client.get_proof_dispute_count(&spid), 5);

    // List all disputes for spid: creation order [d0, d1, d2, d3, d4]
    let all_disputes = client.list_proof_disputes(&spid, &0, &10);
    assert_eq!(all_disputes.len(), 5);
    assert_eq!(all_disputes.get(0).unwrap(), d0);
    assert_eq!(all_disputes.get(1).unwrap(), d1);
    assert_eq!(all_disputes.get(2).unwrap(), d2);
    assert_eq!(all_disputes.get(3).unwrap(), d3);
    assert_eq!(all_disputes.get(4).unwrap(), d4);

    // Verify all dispute states are preserved and queryable via get_dispute
    let rec0 = client.get_dispute(&d0).unwrap();
    assert_eq!(rec0.status, DisputeStatus::Open);

    let rec1 = client.get_dispute(&d1).unwrap();
    assert_eq!(rec1.status, DisputeStatus::Responded);

    let rec2 = client.get_dispute(&d2).unwrap();
    assert_eq!(rec2.status, DisputeStatus::Resolved);

    let rec3 = client.get_dispute(&d3).unwrap();
    assert_eq!(rec3.status, DisputeStatus::Dismissed);

    let rec4 = client.get_dispute(&d4).unwrap();
    assert_eq!(rec4.status, DisputeStatus::Superseded);
    assert_eq!(rec4.superseded_by, Some(sealid.clone()));

    // Verify superseding proof has no disputes indexed under it
    assert_eq!(client.get_proof_dispute_count(&sealid), 0);
    let seal_disputes = client.list_proof_disputes(&sealid, &0, &10);
    assert_eq!(seal_disputes.len(), 0);

    // Verify pagination across the 5 items
    let p1 = client.list_proof_disputes(&spid, &0, &2);
    assert_eq!(p1.len(), 2);
    assert_eq!(p1.get(0).unwrap(), d0);
    assert_eq!(p1.get(1).unwrap(), d1);

    let p2 = client.list_proof_disputes(&spid, &2, &2);
    assert_eq!(p2.len(), 2);
    assert_eq!(p2.get(0).unwrap(), d2);
    assert_eq!(p2.get(1).unwrap(), d3);

    let p3 = client.list_proof_disputes(&spid, &4, &2);
    assert_eq!(p3.len(), 1);
    assert_eq!(p3.get(0).unwrap(), d4);

    let p4 = client.list_proof_disputes(&spid, &5, &2);
    assert_eq!(p4.len(), 0);
}
