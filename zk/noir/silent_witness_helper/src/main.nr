use harpocrates_common::{
    DIGEST_ALGORITHM_SHA256,
    DOMAIN_NETWORK_FIELD,
    DOMAIN_PROTOCOL_FIELD,
    DOMAIN_VERSION_FIELD,
    SCOPED_NULLIFIER_V1,
};

fn main(
    credential_secret: Field,
    nullifier_secret: Field,
    video_hash_hi: Field,
    video_hash_lo: Field,
    verifier_scope: Field,
    epoch: Field,
) -> pub (Field, Field, Field) {
    let scope_hash = std::hash::pedersen_hash([
        SCOPED_NULLIFIER_V1,
        verifier_scope,
        epoch,
    ]);

    // Commit to the complete canonical evidence digest with algorithm binding.
    // This must match the derivation in the main silent_witness circuit so that
    // the off-chain helper produces the same credential_root and nullifier that
    // the main circuit expects.
    let evidence_digest = std::hash::pedersen_hash([
        DIGEST_ALGORITHM_SHA256,
        video_hash_hi,
        video_hash_lo,
        scope_hash,
    ]);

    let credential_root = std::hash::pedersen_hash([credential_secret]);
    let nullifier = std::hash::pedersen_hash([
        credential_secret,
        nullifier_secret,
        evidence_digest,
    ]);
    let domain_tag = std::hash::pedersen_hash([
        DOMAIN_PROTOCOL_FIELD,
        DOMAIN_VERSION_FIELD,
        DOMAIN_NETWORK_FIELD,
    ]);

    (credential_root, nullifier, domain_tag)
}

// =============================================================================
// Test helpers: compute Merkle tree nodes and domain separator for the
// revocation witness non-membership circuit.
//
// Run `nargo test --show-output` to extract field values for Prover.toml
// and shared conformance vectors.
// =============================================================================

/// Compute the test domain separator.
/// Must match the value in the Soroban contract test vectors.
fn test_domain_separator() -> Field {
    // pedersen(["HARPOCRATES_REVOCATION_V1", 0, 0])
    std::hash::pedersen_hash([0x484152504f4352415445535f5245564f434154494f4e5f5631, 0, 0])
}

/// Compute the Merkle root for 8 leaves (depth 3, Pedersen).
fn compute_merkle_root(
    l0: Field, l1: Field, l2: Field, l3: Field,
    l4: Field, l5: Field, l6: Field, l7: Field,
) -> Field {
    let n01 = std::hash::pedersen_hash([l0, l1]);
    let n23 = std::hash::pedersen_hash([l2, l3]);
    let n45 = std::hash::pedersen_hash([l4, l5]);
    let n67 = std::hash::pedersen_hash([l6, l7]);
    let n0123 = std::hash::pedersen_hash([n01, n23]);
    let n4567 = std::hash::pedersen_hash([n45, n67]);
    std::hash::pedersen_hash([n0123, n4567])
}

/// Compute all parameters for the base test fixture and print them.
/// Credential: cs=12345, ns=67890
/// Revoked leaves: 0, root(33333), root(44444), ..., root(99999)
#[test]
fn test_compute_revocation_tree_params() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let (credential_root, nullifier, domain_tag) = main(cs, ns, 0, 0, 0, 0);

    let l0: Field = 0;
    let l1 = std::hash::pedersen_hash([33333]);
    let l2 = std::hash::pedersen_hash([44444]);
    let l3 = std::hash::pedersen_hash([55555]);
    let l4 = std::hash::pedersen_hash([66666]);
    let l5 = std::hash::pedersen_hash([77777]);
    let l6 = std::hash::pedersen_hash([88888]);
    let l7 = std::hash::pedersen_hash([99999]);

    let tree_root = compute_merkle_root(l0, l1, l2, l3, l4, l5, l6, l7);
    let ds = test_domain_separator();

    // Verify all computed values are non-zero (proof of work).
    assert(credential_root != 0);
    assert(nullifier != 0);
    assert(domain_tag != 0);
    assert(tree_root != 0);
    assert(ds != 0);
    assert(l1 != 0);
    assert(l7 != 0);

    // Bind the values so the compiler doesn't optimize them away.
    let _ = (credential_root, nullifier, domain_tag, tree_root, ds, l0, l1, l2, l3, l4, l5, l6, l7);
}
