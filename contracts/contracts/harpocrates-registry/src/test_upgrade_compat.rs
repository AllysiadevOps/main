//! Upgrade compatibility harness (#347)
//!
//! Focused positive, negative, boundary, and regression coverage for the
//! registry storage-schema upgrade path so Harpocrates stays safe at its
//! public boundaries across wasm replacements.
//!
//! Coverage:
//!   - `init` stamps `SchemaVersion::V1` and `get_storage_schema_version` reads it.
//!   - `upgrade_storage` is admin-only (Unauthorized for outsiders).
//!   - Idempotent no-op at V1: no `SchemaUpgraded` event, version unchanged.
//!   - Legacy registries missing `SchemaVersion` are stamped to V1 without an
//!     upgrade event (privacy-safe; no proof payload logged).
//!   - Existing Tier-2 source proofs remain readable and status-stable across
//!     an upgrade call (compatible callers / stored evidence preserved).
//!   - Verifier pointer survives an upgrade call (integration boundary).
//!
//! Threat / migration notes (see also contracts/README.md):
//!   - Trust boundary: only admin may mutate schema version.
//!   - Privacy: harness asserts schema topics only; never prints proof bytes,
//!     public inputs, witnesses, media, or keys.
//!   - Rollback: stamping V1 is additive; prior wasm ignoring the key is fine.
//!
//! Run: `cargo test -p harpocrates-registry upgrade_compat -- --nocapture`

#![cfg(test)]

use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger},
    Address, Bytes, BytesN, Env,
};

#[contract]
struct MockVerifierUpgrade;

#[contractimpl]
impl MockVerifierUpgrade {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        if !matches!(public_inputs.len(), 128 | 160 | 224 | 256) || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

fn schema_upgrade_event_count(env: &Env, _contract_id: &Address) -> u32 {
    // These tests invoke only the registry, so no contract filter is needed.
    // `events().all()` reflects the most recent invocation only.
    event_test_utils::count_events(env, &["schema", "upgrade"])
}

fn init_registry() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, contract_id, admin)
}

#[test]
fn upgrade_compat_init_stamps_v1() {
    let (env, contract_id, _admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V2 as u32
    );

    let present = env.as_contract(&contract_id, || {
        env.storage().persistent().has(&DataKey::SchemaVersion)
    });
    assert!(present, "init must persist SchemaVersion");
}

#[test]
fn upgrade_compat_idempotent_noop_at_v2() {
    let (env, contract_id, admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let before = schema_upgrade_event_count(&env, &contract_id);
    client.upgrade_storage(&admin);
    client.upgrade_storage(&admin);
    let after = schema_upgrade_event_count(&env, &contract_id);

    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V2 as u32
    );
    assert_eq!(
        after, before,
        "idempotent V2 upgrade must not emit SchemaUpgraded"
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn upgrade_compat_rejects_non_admin() {
    let (env, contract_id, _admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let outsider = Address::generate(&env);
    client.upgrade_storage(&outsider);
}

#[test]
fn upgrade_compat_stamps_legacy_missing_schema_version() {
    let (env, contract_id, admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Simulate a pre-#85 deployment: admin present, SchemaVersion absent.
    env.as_contract(&contract_id, || {
        env.storage().persistent().remove(&DataKey::SchemaVersion);
    });
    assert!(
        !env.as_contract(&contract_id, || {
            env.storage().persistent().has(&DataKey::SchemaVersion)
        }),
        "fixture must clear SchemaVersion"
    );
    // Getter remains compatible (treats missing as V1).
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V2 as u32
    );

    let before = schema_upgrade_event_count(&env, &contract_id);
    client.upgrade_storage(&admin);
    let after = schema_upgrade_event_count(&env, &contract_id);

    assert!(
        env.as_contract(&contract_id, || {
            env.storage().persistent().has(&DataKey::SchemaVersion)
        }),
        "upgrade_storage must stamp SchemaVersion on legacy registries"
    );
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V2 as u32
    );
    assert_eq!(
        after,
        before + 1,
        "legacy stamp must emit SchemaUpgraded due to V2 migration"
    );
}

#[test]
fn upgrade_compat_preserves_registered_source_proof() {
    let (env, contract_id, admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);

    let video = b32(&env, 0x11);
    let meta = b32(&env, 0x22);
    let proof_id = b32(&env, 0x33);
    let record = client.register_source(&source, &video, &meta, &proof_id);
    assert_eq!(record.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(record.status, STATUS_REGISTERED);

    client.upgrade_storage(&admin);

    let after = client
        .get_proof(&proof_id)
        .expect("proof must survive upgrade");
    assert_eq!(after.video_hash, video);
    assert_eq!(after.metadata_hash, meta);
    assert_eq!(after.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(after.status, STATUS_REGISTERED);
    let by_video = client
        .get_by_video(&video)
        .expect("video index must survive upgrade");
    assert_eq!(by_video.video_hash, video);
    assert_eq!(by_video.metadata_hash, meta);
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V2 as u32
    );
}

#[test]
fn upgrade_compat_preserves_verifier_boundary() {
    let (env, contract_id, admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let verifier_id = env.register(MockVerifierUpgrade, ());
    client.set_verifier(&admin, &verifier_id);

    client.upgrade_storage(&admin);

    assert_eq!(
        client.get_verifier(),
        Some(verifier_id),
        "verifier integration pointer must survive upgrade_storage"
    );
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V2 as u32
    );
}

#[test]
fn upgrade_compat_repeated_legacy_stamp_stays_idempotent() {
    let (env, contract_id, admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    env.as_contract(&contract_id, || {
        env.storage().persistent().remove(&DataKey::SchemaVersion);
    });

    client.upgrade_storage(&admin);
    let mid = schema_upgrade_event_count(&env, &contract_id);
    client.upgrade_storage(&admin);
    let end = schema_upgrade_event_count(&env, &contract_id);

    assert_eq!(end, mid);
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V2 as u32
    );
}

const SECOND_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7e,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x08, 0x01, 0x04, 0x63, 0x61, 0x6c, 0x6c, 0x00, 0x00,
    0x0a, 0x08, 0x01, 0x06, 0x00, 0x42, 0x8e, 0xdc, 0x2d, 0x0b,
    0x00, 0x1e, 0x11, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x65,
    0x6e, 0x76, 0x6d, 0x65, 0x74, 0x61, 0x76, 0x30, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
];

fn advance_time(env: &Env, secs: u64) {
    env.ledger().set_timestamp(env.ledger().timestamp() + secs);
}

#[test]
fn upgrade_compat_wasm_upgrade_preserves_state() {
    let (env, contract_id, admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let verifier_id = env.register(MockVerifierUpgrade, ());
    client.set_verifier(&admin, &verifier_id);

    // Register a source proof prior to upgrade
    let source = Address::generate(&env);
    let video = b32(&env, 0x11);
    let meta = b32(&env, 0x22);
    let proof_id = b32(&env, 0x33);
    let record = client.register_source(&source, &video, &meta, &proof_id);
    assert_eq!(record.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(record.status, STATUS_REGISTERED);

    // Upload a second Wasm in the test env
    let new_wasm_hash = env.deployer().upload_contract_wasm(SECOND_WASM);

    // Propose Wasm upgrade
    let dummy_target = Address::generate(&env);
    let proposal_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::UpgradeWasm as u32),
        &dummy_target,
        &new_wasm_hash,
    );
    assert_eq!(proposal_id, 1);

    // Acceptance criterion: Upgrade cannot happen before the timelock delay
    let outsider = Address::generate(&env);
    let premature_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.execute_timelocked_proposal(&outsider, &proposal_id);
    }));
    assert!(premature_result.is_err(), "cannot execute upgrade before timelock delay");

    // Acceptance criterion: Disallow emergency_execute_timelock for upgrades
    let emergency_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.emergency_execute_timelock(&admin, &proposal_id);
    }));
    assert!(emergency_result.is_err(), "emergency execution of UpgradeWasm must panic");

    // Advance time past minimum delay
    advance_time(&env, DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);

    // Execute proposal after timelock delay
    client.execute_timelocked_proposal(&outsider, &proposal_id);

    let proposal = client.get_timelock_proposal(&proposal_id).expect("proposal must exist");
    assert!(proposal.executed);

    // Verify upgrade event emitted
    assert!(
        event_test_utils::has_event(&env, &["contract", "upgrade"]),
        "ContractUpgraded event must be emitted"
    );

    // Verify current wasm hash stored
    assert_eq!(client.get_current_wasm_hash(), Some(new_wasm_hash));

    // Acceptance criterion: Storage survives the upgrade in test_upgrade_compat.rs
    let after_proof = client
        .get_proof(&proof_id)
        .expect("proof must survive wasm upgrade");
    assert_eq!(after_proof.video_hash, video);
    assert_eq!(after_proof.metadata_hash, meta);
    assert_eq!(after_proof.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(after_proof.status, STATUS_REGISTERED);

    assert_eq!(
        client.get_verifier(),
        Some(verifier_id),
        "verifier pointer must survive wasm upgrade"
    );
    assert_eq!(
        client.get_storage_schema_version(),
        SchemaVersion::V2 as u32,
        "schema version must survive wasm upgrade"
    );
    assert!(client.is_admin(&admin), "admin must survive wasm upgrade");
}

#[test]
fn upgrade_compat_wasm_upgrade_rejects_non_admin_proposal() {
    let (env, contract_id, _admin) = init_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let outsider = Address::generate(&env);
    let new_wasm_hash = env.deployer().upload_contract_wasm(SECOND_WASM);

    // Non-admin proposals rejected
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.propose_timelocked_action(
            &outsider,
            &(ProposalAction::UpgradeWasm as u32),
            &contract_id,
            &new_wasm_hash,
        );
    }));
    assert!(result.is_err(), "non-admin proposal must be rejected");
}
