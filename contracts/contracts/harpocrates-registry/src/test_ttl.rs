#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Events, vec, Env, IntoVal};

#[test]
fn test_extend_instance_ttl() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, HarpocratesRegistry);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.extend_instance_ttl();

    let events = env.events().all();
    assert!(events.len() > 0);
    
    let last_event = events.last().unwrap();
    assert_eq!(last_event.0, contract_id);
    
    let topics: SorobanVec<Val> = last_event.1;
    assert_eq!(topics.len(), 2);
    
    let topic_0: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
    let topic_1: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
    
    assert_eq!(topic_0, Symbol::new(&env, "ttl"));
    assert_eq!(topic_1, Symbol::new(&env, "instance"));
}

#[test]
fn test_extend_persistent_ttls() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, HarpocratesRegistry);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.init(&admin);

    // Provide a list of keys to extend
    let keys = vec![
        &env,
        DataKey::Admin,
        DataKey::ProofTtl,
    ];

    client.extend_persistent_ttls(&keys);

    let events = env.events().all();
    
    let maintain_events: std::vec::Vec<_> = events.into_iter().filter(|e| {
        if e.0 != contract_id {
            return false;
        }
        let topics: SorobanVec<Val> = e.1.clone();
        if topics.len() != 2 {
            return false;
        }
        let topic_0: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
        let topic_1: Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
        topic_0 == Symbol::new(&env, "ttl") && topic_1 == Symbol::new(&env, "maintain")
    }).collect();

    assert_eq!(maintain_events.len(), 1);
    
    let event_data: TTLMaintained = maintain_events[0].2.clone().try_into_val(&env).unwrap();
    assert_eq!(event_data.count, 2);
}

#[test]
#[should_panic(expected = "HostError")]
fn test_extend_persistent_ttls_empty() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HarpocratesRegistry);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.extend_persistent_ttls(&vec![&env]);
}

#[test]
#[should_panic(expected = "HostError")]
fn test_extend_persistent_ttls_too_many() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HarpocratesRegistry);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let mut keys = vec![&env];
    for _ in 0..51 {
        keys.push_back(DataKey::ProofTtl);
    }

    client.extend_persistent_ttls(&keys);
}

#[test]
fn test_lineage_and_timestamp_claim_ttl_extension_and_ledger_advancement() {
    use soroban_sdk::testutils::{Address as _, Ledger};

    let env = Env::default();
    env.mock_all_auths();

    // Start at an initial timestamp and ledger sequence
    let start_ts: u64 = 1_700_000_000;
    env.ledger().set_timestamp(start_ts);
    env.ledger().set_sequence_number(100);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);

    client.init(&admin);

    // Register a source proof
    let parent_proof_id = BytesN::from_array(&env, &[0x11; 32]);
    let video_hash = BytesN::from_array(&env, &[0x12; 32]);
    let metadata_hash = BytesN::from_array(&env, &[0x13; 32]);
    client.register_source(&actor, &video_hash, &metadata_hash, &parent_proof_id);

    // Register lineage derivative
    let child_digest = BytesN::from_array(&env, &[0x21; 32]);
    let manifest_digest = BytesN::from_array(&env, &[0x22; 32]);
    let mut parent_ids = SorobanVec::new(&env);
    parent_ids.push_back(parent_proof_id.clone());

    let lineage_rec = client.register_lineage(
        &actor,
        &parent_ids,
        &manifest_digest,
        &Symbol::new(&env, "crop"),
        &child_digest,
        &1,
    );
    assert_eq!(lineage_rec.depth, 1);

    // Anchor an independent timestamp claim
    let attestation_digest = BytesN::from_array(&env, &[0x31; 32]);
    let zero_rfc = BytesN::from_array(&env, &[0u8; 32]);
    let claim = client.anchor_timestamp_claim(
        &actor,
        &parent_proof_id,
        &attestation_digest,
        &0u64,
        &zero_rfc,
    );
    assert_eq!(claim.proof_id, parent_proof_id);

    // Verify initial readability
    let initial_lineage = client.get_lineage(&child_digest);
    assert!(initial_lineage.is_some());
    assert_eq!(initial_lineage.unwrap().output_digest, child_digest);

    let initial_children = client.list_lineage_children(&parent_proof_id, &0, &10);
    assert_eq!(initial_children.total, 1);
    assert_eq!(initial_children.children.len(), 1);
    assert_eq!(initial_children.children.get(0).unwrap(), child_digest);

    let initial_claim = client.get_timestamp_claim(&parent_proof_id);
    assert!(initial_claim.is_some());
    assert_eq!(initial_claim.unwrap().attestation_digest, attestation_digest);

    // Collect the exact persistent DataKeys written by lineage and timestamp claim registration
    let keys = vec![
        &env,
        DataKey::Lineage(child_digest.clone()),
        DataKey::LineageChildSeq(parent_proof_id.clone()),
        DataKey::LineageChild(parent_proof_id.clone(), 1),
        DataKey::TimestampClaim(parent_proof_id.clone()),
    ];

    // Maintain/extend TTL on these persistent entries
    client.extend_persistent_ttls(&keys);

    // Advance the ledger sequence and timestamp well beyond typical thresholds (e.g. 500_000 ledgers / ~30 days)
    // with reads in between
    for step in 1..=5 {
        let advanced_ts = start_ts + (step as u64) * 100_000;
        let advanced_seq = 100 + step * 100_000;
        env.ledger().set_timestamp(advanced_ts);
        env.ledger().set_sequence_number(advanced_seq);

        // Assert all keys remain readable during ledger progression
        let lin = client.get_lineage(&child_digest);
        assert!(lin.is_some(), "Lineage must remain readable at step {}", step);
        assert_eq!(lin.unwrap().manifest_digest, manifest_digest);

        let kids = client.list_lineage_children(&parent_proof_id, &0, &10);
        assert_eq!(kids.total, 1, "Children total must be 1 at step {}", step);
        assert_eq!(kids.children.get(0).unwrap(), child_digest);

        let tc = client.get_timestamp_claim(&parent_proof_id);
        assert!(tc.is_some(), "Timestamp claim must remain readable at step {}", step);
        assert_eq!(tc.unwrap().attestation_digest, attestation_digest);
    }

    // Final assertion beyond default TTL / threshold:
    // get_lineage, list_lineage_children, and get_timestamp_claim
    let final_lineage = client.get_lineage(&child_digest).expect("lineage record exists");
    assert_eq!(final_lineage.output_digest, child_digest);

    let final_children = client.list_lineage_children(&parent_proof_id, &0, &10);
    assert_eq!(final_children.total, 1);
    assert_eq!(final_children.children.get(0).unwrap(), child_digest);

    let final_claim = client.get_timestamp_claim(&parent_proof_id).expect("timestamp claim exists");
    assert_eq!(final_claim.proof_id, parent_proof_id);
    assert_eq!(final_claim.attestation_digest, attestation_digest);
}

#[test]
fn test_dispute_ttl_extension_and_ledger_advancement() {
    use soroban_sdk::testutils::{Address as _, Ledger};

    let env = Env::default();
    env.mock_all_auths();

    // Start at an initial timestamp and ledger sequence
    let start_ts: u64 = 1_700_000_000;
    env.ledger().set_timestamp(start_ts);
    env.ledger().set_sequence_number(100);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let reporter = Address::generate(&env);

    client.init(&admin);

    // Register a source proof
    let proof_id = BytesN::from_array(&env, &[0x41; 32]);
    let video_hash = BytesN::from_array(&env, &[0x42; 32]);
    let metadata_hash = BytesN::from_array(&env, &[0x43; 32]);
    client.register_source(&actor, &video_hash, &metadata_hash, &proof_id);

    // Open a dispute
    let dispute_id = BytesN::from_array(&env, &[0x51; 32]);
    let rep_hash = BytesN::from_array(&env, &[0x52; 32]);
    let commitment = BytesN::from_array(&env, &[0x53; 32]);

    let dispute_rec = client.open_dispute(
        &reporter,
        &rep_hash,
        &dispute_id,
        &proof_id,
        &DisputeReason::ContentError,
        &commitment,
    );
    assert_eq!(dispute_rec.status, DisputeStatus::Open);
    assert_eq!(dispute_rec.dispute_id, dispute_id);
    assert_eq!(dispute_rec.proof_id, proof_id);

    // Verify initial readability
    let initial_dispute = client.get_dispute(&dispute_id);
    assert!(initial_dispute.is_some());
    assert_eq!(initial_dispute.unwrap().dispute_id, dispute_id);
    assert_eq!(client.get_open_dispute_count(&proof_id), 1);
    assert_eq!(client.get_reporter_open_dispute_count(&reporter), 1);

    // Assert that ReporterCooldown uses temporary storage and does NOT consume persistent rent
    assert!(
        env.storage().temporary().has(&DataKey::ReporterCooldown(rep_hash.clone())),
        "ReporterCooldown must be stored in temporary storage"
    );
    assert!(
        !env.storage().persistent().has(&DataKey::ReporterCooldown(rep_hash.clone())),
        "ReporterCooldown must not consume persistent storage rent"
    );

    // Maintain/extend TTL on persistent keys including proof and dispute entries
    let keys = vec![
        &env,
        DataKey::Proof(proof_id.clone()),
        DataKey::Dispute(dispute_id.clone()),
        DataKey::ProofOpenDisputeCount(proof_id.clone()),
    ];
    client.extend_persistent_ttls(&keys);

    // Advance the ledger sequence and timestamp through multiple steps
    // (500_000 ledgers / ~30 days) with reads in between
    for step in 1..=5 {
        let advanced_ts = start_ts + (step as u64) * 100_000;
        let advanced_seq = 100 + step * 100_000;
        env.ledger().set_timestamp(advanced_ts);
        env.ledger().set_sequence_number(advanced_seq);

        // Assert dispute and open count remain readable during ledger progression
        let disp = client.get_dispute(&dispute_id);
        assert!(disp.is_some(), "Dispute must remain readable at step {}", step);
        assert_eq!(disp.unwrap().dispute_id, dispute_id);

        let count = client.get_open_dispute_count(&proof_id);
        assert_eq!(count, 1, "Dispute count must remain 1 at step {}", step);
    }

    // Verify proof and dispute records survived as long as their proof
    let final_proof = client.get_proof(&proof_id);
    assert!(final_proof.is_some(), "Proof must survive ledger advancement");

    let final_dispute = client.get_dispute(&dispute_id);
    assert!(final_dispute.is_some(), "Dispute must survive as long as its proof");
    assert_eq!(client.get_open_dispute_count(&proof_id), 1);

    // After advancing well past the 24h cooldown window (500_000s > 86_400s),
    // temporary cooldown entry has expired, allowing a second dispute from the same reporter
    let dispute_id_2 = BytesN::from_array(&env, &[0x61; 32]);
    let commitment_2 = BytesN::from_array(&env, &[0x62; 32]);
    let dispute_rec_2 = client.open_dispute(
        &reporter,
        &rep_hash,
        &dispute_id_2,
        &proof_id,
        &DisputeReason::MetadataError,
        &commitment_2,
    );
    assert_eq!(dispute_rec_2.status, DisputeStatus::Open);
    assert_eq!(client.get_open_dispute_count(&proof_id), 2);

    // Respond to dispute_id_2 to test respond_dispute write path
    let response_commitment = BytesN::from_array(&env, &[0x64; 32]);
    let responded = client.respond_dispute(&actor, &dispute_id_2, &response_commitment);
    assert_eq!(responded.status, DisputeStatus::Responded);

    // Advance ledgers again and assert both disputes and proof remain alive
    let advanced_ts_2 = start_ts + 700_000;
    let advanced_seq_2 = 100 + 700_000;
    env.ledger().set_timestamp(advanced_ts_2);
    env.ledger().set_sequence_number(advanced_seq_2);

    let disp_1 = client.get_dispute(&dispute_id).expect("dispute 1 exists");
    assert_eq!(disp_1.status, DisputeStatus::Open);

    let disp_2 = client.get_dispute(&dispute_id_2).expect("dispute 2 exists");
    assert_eq!(disp_2.status, DisputeStatus::Responded);

    assert_eq!(client.get_open_dispute_count(&proof_id), 2);
    assert!(client.get_proof(&proof_id).is_some());
}
