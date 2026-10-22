//! Tier 2 Source Batch Merkle inclusion tests.
//!
//! Verifies batch root anchoring, inclusion proofs, domain-separated leaf/node
//! hashing, second-preimage attack resistance by construction, bounds, and
//! cross-checks conformance vectors against `zk/vectors/source_batch_inclusion_v1.json`.

#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::Address as _,
    Address, Bytes, BytesN, Env, Vec as SVec,
};
use sha2::{Digest, Sha256};
use std::format;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

const CORPUS: &str = include_str!("../../../../../zk/vectors/source_batch_inclusion_v1.json");

// ---------------------------------------------------------------------------
// Reference Merkle Tree Implementation
// ---------------------------------------------------------------------------

pub struct ReferenceMerkleTree {
    pub leaves: Vec<[u8; 32]>,
    pub levels: Vec<Vec<[u8; 32]>>,
}

impl ReferenceMerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        assert!(!leaves.is_empty(), "Merkle tree must have at least one leaf");

        // Level 0: leaf hashes domain-separated with 0x00
        let mut current_level: Vec<[u8; 32]> = leaves
            .iter()
            .map(|leaf| {
                let mut hasher = Sha256::new();
                hasher.update([SOURCE_BATCH_LEAF_DOMAIN]);
                hasher.update(leaf);
                let result = hasher.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&result);
                out
            })
            .collect();

        let mut levels = vec![current_level.clone()];

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks_exact(2) {
                let mut hasher = Sha256::new();
                hasher.update([SOURCE_BATCH_NODE_DOMAIN]);
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
                let result = hasher.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&result);
                next_level.push(out);
            }
            current_level = next_level;
            levels.push(current_level.clone());
        }

        Self { leaves, levels }
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels.last().unwrap()[0]
    }

    pub fn proof(&self, index: usize) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_idx = idx ^ 1;
            proof.push(level[sibling_idx]);
            idx /= 2;
        }
        proof
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn b32(env: &Env, val: u8) -> BytesN<32> {
    BytesN::from_array(env, &[val; 32])
}

fn make_leaf(val: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"harpocrates:batch-leaf:v1");
    let mut buf = [0u8; 32];
    buf[28..32].copy_from_slice(&val.to_be_bytes());
    hasher.update(&buf);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn decode_hex_32(hex_str: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte_str = &hex_str[i * 2..i * 2 + 2];
        out[i] = u8::from_str_radix(byte_str, 16).expect("valid hex byte");
    }
    out
}

fn field_value(line: &str, key: &str) -> Option<String> {
    let trimmed = line.trim();
    let prefix = format!("\"{}\":", key);
    let rest = trimmed.strip_prefix(prefix.as_str())?;
    let rest = rest.trim().trim_end_matches(',').trim();
    if rest == "null" {
        return Some("null".to_string());
    }
    Some(rest.trim_matches('"').to_string())
}

struct ParsedVector {
    id: String,
    root: [u8; 32],
    leaf: [u8; 32],
    proof: Vec<[u8; 32]>,
    index: u32,
    valid: bool,
}

fn parse_vectors() -> Vec<ParsedVector> {
    let mut cases = Vec::new();
    let mut cur_id: Option<String> = None;
    let mut cur_root: Option<[u8; 32]> = None;
    let mut cur_leaf: Option<[u8; 32]> = None;
    let mut cur_proof: Vec<[u8; 32]> = Vec::new();
    let mut in_proof = false;
    let mut cur_index: Option<u32> = None;
    let mut cur_valid: Option<bool> = None;

    for line in CORPUS.lines() {
        let trimmed = line.trim();

        if let Some(id) = field_value(line, "id") {
            cur_id = Some(id);
            cur_root = None;
            cur_leaf = None;
            cur_proof.clear();
            in_proof = false;
            cur_index = None;
            cur_valid = None;
            continue;
        }

        if let Some(root_hex) = field_value(line, "root") {
            cur_root = Some(decode_hex_32(&root_hex));
            continue;
        }

        if let Some(leaf_hex) = field_value(line, "leaf") {
            cur_leaf = Some(decode_hex_32(&leaf_hex));
            continue;
        }

        if trimmed.starts_with("\"proof\": [") {
            in_proof = true;
            if trimmed.contains(']') {
                in_proof = false;
            }
            continue;
        }

        if in_proof {
            if trimmed.starts_with(']') {
                in_proof = false;
            } else {
                let clean = trimmed.trim_matches('"').trim_end_matches(',').trim_matches('"');
                if clean.len() == 64 {
                    cur_proof.push(decode_hex_32(clean));
                }
            }
            continue;
        }

        if let Some(idx_str) = field_value(line, "index") {
            cur_index = Some(idx_str.parse::<u32>().expect("valid index number"));
            continue;
        }

        if let Some(valid_str) = field_value(line, "valid") {
            cur_valid = Some(valid_str == "true");
            continue;
        }

        if let Some(_err) = field_value(line, "error") {
            if let (Some(id), Some(root), Some(leaf), Some(index), Some(valid)) = (
                cur_id.take(),
                cur_root.take(),
                cur_leaf.take(),
                cur_index.take(),
                cur_valid.take(),
            ) {
                cases.push(ParsedVector {
                    id,
                    root,
                    leaf,
                    proof: cur_proof.clone(),
                    index,
                    valid,
                });
                cur_proof.clear();
            }
        }
    }

    cases
}

// ---------------------------------------------------------------------------
// Unit and Acceptance Tests
// ---------------------------------------------------------------------------

#[test]
fn test_register_source_batch_root_lifecycle() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    let root = b32(&env, 0x11);
    let metadata_hash = b32(&env, 0x22);
    let count = 1000u32;

    let record = client.register_source_batch_root(&source, &root, &count, &metadata_hash);
    assert_eq!(record.root, root);
    assert_eq!(record.source, source);
    assert_eq!(record.count, count);
    assert_eq!(record.metadata_hash, metadata_hash);

    let fetched = client.get_source_batch(&root).expect("batch record exists");
    assert_eq!(fetched, record);

    // Query non-existent batch
    assert!(client.get_source_batch(&b32(&env, 0x99)).is_none());
}

#[test]
fn test_register_source_batch_pause_domain() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    // Pausing Tier 1 does NOT pause Tier 2 batch registration
    client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &3600);
    let record = client.register_source_batch_root(
        &source,
        &b32(&env, 0x01),
        &10,
        &b32(&env, 0x02),
    );
    assert_eq!(record.count, 10);

    // Pausing Tier 2 registration blocks register_source_batch_root
    client.pause(&admin, &PAUSE_DOMAIN_TIER2_REGISTRATION, &3600);
    let err = client.try_register_source_batch_root(
        &source,
        &b32(&env, 0x03),
        &10,
        &b32(&env, 0x04),
    );
    assert_eq!(
        err,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::Paused as u32
        )))
    );

    // Unpausing restores registration
    client.unpause(&admin, &PAUSE_DOMAIN_TIER2_REGISTRATION);
    let ok = client.register_source_batch_root(
        &source,
        &b32(&env, 0x03),
        &10,
        &b32(&env, 0x04),
    );
    assert_eq!(ok.count, 10);
}

#[test]
fn test_register_source_batch_bounds() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    // count = 0 rejected
    let err_zero = client.try_register_source_batch_root(
        &source,
        &b32(&env, 0x01),
        &0,
        &b32(&env, 0x02),
    );
    assert_eq!(
        err_zero,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::BatchSizeExceeded as u32
        )))
    );

    // count > MAX_SOURCE_BATCH_COUNT rejected
    let err_max = client.try_register_source_batch_root(
        &source,
        &b32(&env, 0x01),
        &(MAX_SOURCE_BATCH_COUNT + 1),
        &b32(&env, 0x02),
    );
    assert_eq!(
        err_max,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::BatchSizeExceeded as u32
        )))
    );
}

#[test]
fn test_register_source_batch_duplicate_root() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    let root = b32(&env, 0x55);
    client.register_source_batch_root(&source, &root, &100, &b32(&env, 0x00));

    // Duplicate root rejected
    let err = client.try_register_source_batch_root(&source, &root, &100, &b32(&env, 0x00));
    assert_eq!(
        err,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::DuplicateProof as u32
        )))
    );
}

#[test]
fn test_inclusion_verifies_for_every_leaf_of_reference_trees() {
    let env = Env::default();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Test trees of size 1, 2, 4, 8, 16
    for size in [1, 2, 4, 8, 16] {
        let raw_leaves: Vec<[u8; 32]> = (0..size).map(|i| make_leaf(i as u32)).collect();
        let tree = ReferenceMerkleTree::new(raw_leaves.clone());
        let root = BytesN::from_array(&env, &tree.root());

        for i in 0..size {
            let leaf = BytesN::from_array(&env, &raw_leaves[i]);
            let proof_elements = tree.proof(i);
            let mut proof = SVec::new(&env);
            for p in proof_elements {
                proof.push_back(BytesN::from_array(&env, &p));
            }

            let valid = client.verify_source_batch_inclusion(&root, &leaf, &proof, &(i as u32));
            assert!(valid, "Leaf {i} of size {size} must verify");
        }
    }
}

#[test]
fn test_second_preimage_resistance_by_construction() {
    let env = Env::default();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // 4-leaf tree
    let raw_leaves: Vec<[u8; 32]> = (0..4).map(|i| make_leaf(i as u32)).collect();
    let tree = ReferenceMerkleTree::new(raw_leaves);
    let root = BytesN::from_array(&env, &tree.root());

    // In a 4-leaf tree without domain separation, internal node 01 could be attacked as a leaf
    // with sibling node 23.
    // With domain separation:
    // Leaf hashing prefixes 0x00, node hashing prefixes 0x01.
    // Passing the internal node digest as leaf must fail.
    let left_node = BytesN::from_array(&env, &tree.levels[1][0]);
    let right_node = BytesN::from_array(&env, &tree.levels[1][1]);
    let mut fake_proof = SVec::new(&env);
    fake_proof.push_back(right_node);

    let err = client.try_verify_source_batch_inclusion(&root, &left_node, &fake_proof, &0);
    assert_eq!(
        err,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidInclusionProof as u32
        ))),
        "Second-preimage attack (treating internal node as leaf) must fail"
    );
}

#[test]
fn test_inclusion_tampering_rejections() {
    let env = Env::default();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let raw_leaves: Vec<[u8; 32]> = (0..4).map(|i| make_leaf(i as u32)).collect();
    let tree = ReferenceMerkleTree::new(raw_leaves.clone());
    let root = BytesN::from_array(&env, &tree.root());
    let leaf0 = BytesN::from_array(&env, &raw_leaves[0]);
    let proof0_elements = tree.proof(0);
    let mut proof0 = SVec::new(&env);
    for p in proof0_elements {
        proof0.push_back(BytesN::from_array(&env, &p));
    }

    // 1. Tampered leaf
    let tampered_leaf = b32(&env, 0xEE);
    let err_leaf = client.try_verify_source_batch_inclusion(&root, &tampered_leaf, &proof0, &0);
    assert_eq!(
        err_leaf,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidInclusionProof as u32
        )))
    );

    // 2. Tampered root
    let tampered_root = b32(&env, 0xFF);
    let err_root = client.try_verify_source_batch_inclusion(&tampered_root, &leaf0, &proof0, &0);
    assert_eq!(
        err_root,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidInclusionProof as u32
        )))
    );

    // 3. Wrong index
    let err_idx = client.try_verify_source_batch_inclusion(&root, &leaf0, &proof0, &1);
    assert_eq!(
        err_idx,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidInclusionProof as u32
        )))
    );

    // 4. Index out of range for depth (index >= 2^depth)
    let err_oor = client.try_verify_source_batch_inclusion(&root, &leaf0, &proof0, &4);
    assert_eq!(
        err_oor,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidInclusionProof as u32
        )))
    );

    // 5. Proof too long (> 32)
    let mut too_long_proof = SVec::new(&env);
    for _ in 0..33 {
        too_long_proof.push_back(b32(&env, 0x11));
    }
    let err_long = client.try_verify_source_batch_inclusion(&root, &leaf0, &too_long_proof, &0);
    assert_eq!(
        err_long,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidInclusionProof as u32
        )))
    );
}

#[test]
fn test_cross_check_vectors_json() {
    let env = Env::default();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let cases = parse_vectors();
    assert!(!cases.is_empty(), "Must parse test cases from vector corpus");

    for case in cases {
        let root = BytesN::from_array(&env, &case.root);
        let leaf = BytesN::from_array(&env, &case.leaf);

        let mut proof = SVec::new(&env);
        for p in case.proof {
            proof.push_back(BytesN::from_array(&env, &p));
        }

        let res = client.try_verify_source_batch_inclusion(&root, &leaf, &proof, &case.index);

        if case.valid {
            assert!(
                matches!(res, Ok(Ok(true))),
                "Case {} was expected to succeed but got {:?}",
                case.id,
                res
            );
        } else {
            assert_eq!(
                res,
                Err(Ok(soroban_sdk::Error::from_contract_error(
                    RegistryError::InvalidInclusionProof as u32
                ))),
                "Case {} was expected to fail with InvalidInclusionProof",
                case.id
            );
        }
    }
}
