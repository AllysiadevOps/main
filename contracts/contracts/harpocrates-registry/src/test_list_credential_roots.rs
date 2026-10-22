//! Tests for paginated credential root enumeration (#731).
//!
//! Validates:
//! - Empty enumeration returns empty page and next_cursor == None.
//! - Accurate pagination across multiple pages with next_cursor tracking.
//! - Transitions from Registered -> Revoked and Registered -> Expired are reflected.
//! - Limit clamping to MAX_CREDENTIAL_ROOTS_PAGE when limit == 0 or exceeds cap.
//! - Out-of-range cursors return empty pages gracefully.
//! - Idempotent index appending.

#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

fn setup_registry() -> (Env, HarpocratesRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, client, admin)
}

#[test]
fn test_list_credential_roots_empty() {
    let (_env, client, _admin) = setup_registry();

    assert_eq!(client.get_credential_root_count(), 0);

    let page = client.list_credential_roots(&0, &10);
    assert_eq!(page.roots.len(), 0);
    assert_eq!(page.next_cursor, None);

    let page_offset = client.list_credential_roots(&1, &10);
    assert_eq!(page_offset.roots.len(), 0);
    assert_eq!(page_offset.next_cursor, None);

    let page_past = client.list_credential_roots(&99, &10);
    assert_eq!(page_past.roots.len(), 0);
    assert_eq!(page_past.next_cursor, None);
}

#[test]
fn test_list_credential_roots_add_transitions() {
    let (env, client, admin) = setup_registry();

    let root1 = b32(&env, 0x11);
    let meta1 = b32(&env, 0xAA);
    let root2 = b32(&env, 0x22);
    let meta2 = b32(&env, 0xBB);

    client.add_credential_root(&admin, &root1, &meta1);
    assert_eq!(client.get_credential_root_count(), 1);

    client.add_credential_root(&admin, &root2, &meta2);
    assert_eq!(client.get_credential_root_count(), 2);

    let page = client.list_credential_roots(&0, &10);
    assert_eq!(page.roots.len(), 2);
    assert_eq!(page.next_cursor, None);

    let r1 = page.roots.get(0).unwrap();
    assert_eq!(r1.root_hash, root1);
    assert_eq!(r1.status, STATUS_REGISTERED);

    let r2 = page.roots.get(1).unwrap();
    assert_eq!(r2.root_hash, root2);
    assert_eq!(r2.status, STATUS_REGISTERED);
}

#[test]
fn test_list_credential_roots_reflects_revoke_transition() {
    let (env, client, admin) = setup_registry();

    let root = b32(&env, 0x33);
    let meta = b32(&env, 0xCC);

    client.add_credential_root(&admin, &root, &meta);

    // Initial state: registered
    let page = client.list_credential_roots(&0, &10);
    assert_eq!(page.roots.len(), 1);
    assert_eq!(page.roots.get(0).unwrap().status, STATUS_REGISTERED);

    // Revoke
    client.revoke_credential_root(&admin, &root);

    // Reflects revoked status
    let page_revoked = client.list_credential_roots(&0, &10);
    assert_eq!(page_revoked.roots.len(), 1);
    assert_eq!(page_revoked.roots.get(0).unwrap().root_hash, root);
    assert_eq!(page_revoked.roots.get(0).unwrap().status, STATUS_REVOKED);
}

#[test]
fn test_list_credential_roots_reflects_expire_transition() {
    let (env, client, admin) = setup_registry();

    let root = b32(&env, 0x44);
    let meta = b32(&env, 0xDD);

    client.add_credential_root(&admin, &root, &meta);

    // Initial state: registered
    let page = client.list_credential_roots(&0, &10);
    assert_eq!(page.roots.len(), 1);
    assert_eq!(page.roots.get(0).unwrap().status, STATUS_REGISTERED);

    // Expire explicitly
    client.expire_credential_root(&admin, &root);

    // Reflects expired status
    let page_expired = client.list_credential_roots(&0, &10);
    assert_eq!(page_expired.roots.len(), 1);
    assert_eq!(page_expired.roots.get(0).unwrap().root_hash, root);
    assert_eq!(page_expired.roots.get(0).unwrap().status, STATUS_EXPIRED);
}

#[test]
fn test_list_credential_roots_pagination_and_cursors() {
    let (env, client, admin) = setup_registry();

    let mut roots = soroban_sdk::Vec::new(&env);
    for i in 1..=5 {
        let root = b32(&env, i as u8);
        client.add_credential_root(&admin, &root, &b32(&env, 0xEE));
        roots.push_back(root);
    }

    assert_eq!(client.get_credential_root_count(), 5);

    // Page 1: limit 2
    let page1 = client.list_credential_roots(&0, &2);
    assert_eq!(page1.roots.len(), 2);
    assert_eq!(page1.roots.get(0).unwrap().root_hash, roots.get(0).unwrap());
    assert_eq!(page1.roots.get(1).unwrap().root_hash, roots.get(1).unwrap());
    assert_eq!(page1.next_cursor, Some(3));

    // Page 2: limit 2 from cursor 3
    let page2 = client.list_credential_roots(&page1.next_cursor.unwrap(), &2);
    assert_eq!(page2.roots.len(), 2);
    assert_eq!(page2.roots.get(0).unwrap().root_hash, roots.get(2).unwrap());
    assert_eq!(page2.roots.get(1).unwrap().root_hash, roots.get(3).unwrap());
    assert_eq!(page2.next_cursor, Some(5));

    // Page 3: limit 2 from cursor 5 (last element)
    let page3 = client.list_credential_roots(&page2.next_cursor.unwrap(), &2);
    assert_eq!(page3.roots.len(), 1);
    assert_eq!(page3.roots.get(0).unwrap().root_hash, roots.get(4).unwrap());
    assert_eq!(page3.next_cursor, None);

    // Past end cursor returns empty page
    let page_past = client.list_credential_roots(&6, &2);
    assert_eq!(page_past.roots.len(), 0);
    assert_eq!(page_past.next_cursor, None);
}

#[test]
fn test_list_credential_roots_limit_clamping() {
    let (env, client, admin) = setup_registry();

    let root = b32(&env, 0x55);
    client.add_credential_root(&admin, &root, &b32(&env, 0x11));

    // limit = 0 clamped to MAX_CREDENTIAL_ROOTS_PAGE
    let page_zero = client.list_credential_roots(&0, &0);
    assert_eq!(page_zero.roots.len(), 1);

    // limit > MAX clamped to MAX_CREDENTIAL_ROOTS_PAGE
    let page_large = client.list_credential_roots(&0, &100);
    assert_eq!(page_large.roots.len(), 1);
}

#[test]
fn test_list_credential_roots_idempotent_indexing() {
    let (env, client, admin) = setup_registry();

    let root = b32(&env, 0x66);
    let meta = b32(&env, 0x22);

    client.add_credential_root(&admin, &root, &meta);
    assert_eq!(client.get_credential_root_count(), 1);

    // Adding the exact same root again should not increment the sequence count
    client.add_credential_root(&admin, &root, &meta);
    assert_eq!(client.get_credential_root_count(), 1);

    let page = client.list_credential_roots(&0, &10);
    assert_eq!(page.roots.len(), 1);
}
