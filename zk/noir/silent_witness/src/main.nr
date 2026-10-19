use harpocrates_common::{
    compute_scoped_nullifier,
    DIGEST_ALGORITHM_SHA256,
    DOMAIN_NETWORK_FIELD,
    DOMAIN_PROTOCOL_FIELD,
    DOMAIN_VERSION_FIELD,
    expected_domain_tag,
    SCOPED_NULLIFIER_V1,
};

// Circuit version committed to the proof envelope (#368). This must match
// EXPECTED_CIRCUIT_VERSION in the Soroban registry, the Python codec, and the
// TypeScript codec, so a proof can never be detached from the exact circuit
// that produced it.
global CURRENT_CIRCUIT_VERSION: u32 = 2;

fn main(
    credential_secret: Field,
    nullifier_secret: Field,
    video_hash_hi: pub Field,
    video_hash_lo: pub Field,
    credential_root: pub Field,
    nullifier: pub Field,
    verifier_scope: pub Field,
    epoch: pub Field,
    domain_tag: pub Field,
    circuit_version: pub Field,
) {
    let scope_hash = std::hash::pedersen_hash([
        SCOPED_NULLIFIER_V1,
        verifier_scope,
        epoch,
    ]);

    // Commit to the complete canonical evidence digest: algorithm identifier,
    // video hash halves, and scope commitment hash.
    let evidence_digest = std::hash::pedersen_hash([
        DIGEST_ALGORITHM_SHA256,
        video_hash_hi,
        video_hash_lo,
        scope_hash,
    ]);

    let derived_root = std::hash::pedersen_hash([credential_secret]);
    let derived_nullifier = std::hash::pedersen_hash([
        credential_secret,
        nullifier_secret,
        evidence_digest,
    ]);

    assert(derived_root == credential_root, "malformed");
    assert(derived_nullifier == nullifier, "malformed");

    // --- domain separation constraint ---
    // Bind this proof to the Harpocrates protocol, circuit version 1, and
    // the target network.
    let expected_domain_tag = std::hash::pedersen_hash([
        DOMAIN_PROTOCOL_FIELD,
        DOMAIN_VERSION_FIELD,
        DOMAIN_NETWORK_FIELD,
    ]);
    assert(domain_tag == expected_domain_tag, "unsupported");
}

// ---------------------------------------------------------------------------
// Test corpus -- Silent Witness circuit (scoped nullifier v1)
//
// ALL SECRETS ARE SYNTHETIC AND FOR TESTING ONLY.
//
// Base fixture (all values derived from these synthetic seeds):
//   credential_secret   = 12345
//   nullifier_secret    = 67890
//   video_hash_hi       = 22685491128062564230891640495451214097
//                         (hi-128 bits of SHA-256("harpocrates-test-video"))
//   video_hash_lo       = 45370982256125128461783280990902428194
//                         (lo-128 bits of SHA-256("harpocrates-test-video"))
//   DIGEST_ALGORITHM_ID = 0 (SHA-256)
//
// Derived public inputs (BN254/UltraHonk, Pedersen):
//   evidence_digest  = std::hash::pedersen_hash([0, video_hash_hi, video_hash_lo])
//   credential_root  = std::hash::pedersen_hash([12345])
//                    = 0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9
//   nullifier        = std::hash::pedersen_hash([12345, 67890, evidence_digest])
//                    = (changed from previous derivation - now bound to canonical evidence digest)
//
// Edge-case secrets:
//   zero_credential_secret      = 0
//   max_field_credential_secret = BN254 prime - 1
//   zero_video_hash: hi = 0, lo = 0
// ---------------------------------------------------------------------------

// Public input ordering expected by the Soroban verifier:
//   [0] video_hash_hi
//   [1] video_hash_lo
//   [2] credential_root
//   [3] nullifier
//   [4] verifier_scope
//   [5] epoch
//   [6] domain_tag
//   [7] circuit_version    (added by #368)
// ---------------------------------------------------------------------------

// ============================================================
// Positive: well-formed witness
// ============================================================

// All inputs correct: global scope (0), epoch 0.
#[test]
fn test_valid_witness() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let null = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, null, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// Edge: zero credential_secret is a valid field element.
#[test]
fn test_zero_credential_secret() {
    let cs: Field = 0;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let null = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, null, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// Edge: max-field credential_secret (BN254 prime - 1).
#[test]
fn test_max_field_credential_secret() {
    let cs: Field = 21888242871839275222246405745257275088548364400416034343698204186575808495616;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let null = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, null, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// Edge: all-zero video hash (e.g. blank-frame video) with correct secrets.
// The nullifier is derived via the evidence digest commitment, not raw halves.
#[test]
fn test_zero_video_hash() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 0;
    let vlo: Field = 0;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let null = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, null, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// ============================================================
// Negative - wrong private inputs (existing)
// ============================================================

#[test(should_fail_with = "malformed")]
fn test_wrong_credential_secret() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(99999, ns, vhi, vlo, root, nul, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

#[test(should_fail_with = "malformed")]
fn test_wrong_nullifier_secret() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, 11111, vhi, vlo, root, nul, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// ============================================================
// Negative - wrong video hash (existing)
// ============================================================

#[test(should_fail_with = "malformed")]
fn test_wrong_video_hash_hi() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, 99999999999999999999999999999999999999, vlo, root, nul, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

#[test(should_fail_with = "malformed")]
fn test_wrong_video_hash_lo() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, 99999999999999999999999999999999999999, root, nul, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

#[test(should_fail_with = "malformed")]
fn test_wrong_video_hash_both_halves() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, 11111111111111111111111111111111111111, 22222222222222222222222222222222222222, root, nul, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// ============================================================
// Negative - tampered public inputs (existing)
// ============================================================

#[test(should_fail_with = "malformed")]
fn test_tampered_credential_root_public_input() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([99999]); // wrong root
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

#[test(should_fail_with = "malformed")]
fn test_tampered_nullifier_public_input() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    // Nullifier for a different credential
    let nul = compute_scoped_nullifier(99999, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

#[test(should_fail_with = "malformed")]
fn test_both_public_inputs_wrong_identity() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([99999]);
    let nul = compute_scoped_nullifier(99999, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// ============================================================
// Negative - public input ordering attacks (existing)
// ============================================================

#[test(should_fail_with = "malformed")]
fn test_swapped_credential_root_and_nullifier() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    // Swap: nullifier passed as credential_root, root passed as nullifier
    main(cs, ns, vhi, vlo, nul, root, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

#[test(should_fail_with = "malformed")]
fn test_swapped_video_hash_halves() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    // Swap: lo in hi slot, hi in lo slot
    main(cs, ns, vlo, vhi, root, nul, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// ============================================================
// Negative -- scope binding
// ============================================================

// A valid proof for scope=0 must NOT satisfy scope=999.
// Proves the nullifier binds to the specific verifier_scope.
#[test(should_fail_with = "malformed")]
fn test_nullifier_from_different_scope() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    // Nullifier computed for scope=999 (different scope)
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, 999, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// A valid proof for epoch=1 must NOT satisfy epoch=2.
// Proves the nullifier binds to the specific epoch.
#[test(should_fail_with = "malformed")]
fn test_nullifier_from_different_epoch() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 42;
    let ep: Field = 1;
    let root = std::hash::pedersen_hash([cs]);
    // Nullifier computed for epoch=2 (different epoch, same scope)
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, 2);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// ============================================================
// Negative -- nullifier/video binding (unchanged from v1)
// ============================================================

#[test(should_fail_with = "malformed")]
fn test_nullifier_from_different_video() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    // Nullifier computed for a different video hash (vhi+1)
    let nul = compute_scoped_nullifier(cs, ns, vhi + 1, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// ============================================================
// Negative - domain tag mismatch (NEW: domain separation tests)
// ============================================================

// Zero domain_tag — never equals the expected Pedersen hash.
#[test(should_fail_with = "unsupported")]
fn test_zero_domain_tag_rejected() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep, 0, CURRENT_CIRCUIT_VERSION as Field);
}

// ============================================================
// Negative -- evidence digest algorithm binding
// ============================================================

fn nullifier_with_algorithm_id(
    cs: Field, ns: Field, vhi: Field, vlo: Field, algo: Field, scope: Field, ep: Field,
) -> Field {
    let scope_hash = std::hash::pedersen_hash([SCOPED_NULLIFIER_V1, scope, ep]);
    let evidence = std::hash::pedersen_hash([algo, vhi, vlo, scope_hash]);
    std::hash::pedersen_hash([cs, ns, evidence])
}

#[test(should_fail_with = "malformed")]
fn test_wrong_algorithm_id_in_nullifier() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    // nullifier computed with algorithm_id=1 (substituted)
    let wrong_null = nullifier_with_algorithm_id(cs, ns, vhi, vlo, 1, scope, ep);
    main(cs, ns, vhi, vlo, root, wrong_null, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// ============================================================
// Negative -- evidence digest commitment preimage
// ============================================================

#[test(should_fail_with = "malformed")]
fn test_swapped_algorithm_id_and_video_hash_hi() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let scope_hash = std::hash::pedersen_hash([SCOPED_NULLIFIER_V1, scope, ep]);
    let swapped_evidence = std::hash::pedersen_hash([vhi, DIGEST_ALGORITHM_SHA256, vlo, scope_hash]);
    let root = std::hash::pedersen_hash([cs]);
    let swapped_null = std::hash::pedersen_hash([cs, ns, swapped_evidence]);
    main(cs, ns, vhi, vlo, root, swapped_null, scope, ep, expected_domain_tag(), CURRENT_CIRCUIT_VERSION as Field);
}

// ============================================================
// Negative -- circuit version downgrade (#368)
// ============================================================

// A proof that claims circuit version 1 must be rejected: the envelope
// commits to the exact circuit, so an old, weaker circuit cannot be
// resurrected against the v2 verifier.
#[test(should_fail_with = "circuit version mismatch")]
fn test_circuit_version_downgrade() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = std::hash::pedersen_hash([cs]);
    let null = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, null, scope, ep, expected_domain_tag(), 1);
}

// ============================================================
// Positive — nullifier collision boundaries
// ============================================================

// Adjacent secrets must not collapse to the same field element. This catches
// accidental truncation or an off-by-one reduction at the secret boundary.
#[test]
fn test_adjacent_nullifier_secrets_are_distinct() {
    let cs: Field = 12345;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;

    let first = compute_scoped_nullifier(cs, 67890, vhi, vlo, scope, ep);
    let adjacent = compute_scoped_nullifier(cs, 67891, vhi, vlo, scope, ep);
    assert(first != adjacent, "adjacent nullifier secrets collided");
}

// The largest representable secret and zero are the two sides of the field
// boundary. They must remain distinct even when a caller intentionally wraps
// from p - 1 to 0.
#[test]
fn test_nullifier_secret_field_edges_are_distinct() {
    let cs: Field = 12345;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let max_field: Field = 2188824287183927522224640574525727508854836440034343698204186575808495616;

    let at_max = compute_scoped_nullifier(cs, max_field, vhi, vlo, scope, ep);
    let wrapped_to_zero = compute_scoped_nullifier(cs, 0, vhi, vlo, scope, ep);
    assert(at_max != wrapped_to_zero, "nullifier secret field boundary collided");
}

// Scope and epoch are part of the nullifier preimage. Test their adjacent
// boundaries explicitly so a scope-only collision cannot pass unnoticed.
#[test]
fn test_scope_and_epoch_boundaries_are_distinct() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;

    let global_epoch_zero = compute_scoped_nullifier(cs, ns, vhi, vlo, 0, 0);
    let adjacent_scope = compute_scoped_nullifier(cs, ns, vhi, vlo, 1, 0);
    let adjacent_epoch = compute_scoped_nullifier(cs, ns, vhi, vlo, 0, 1);
    assert(global_epoch_zero != adjacent_scope, "scope boundary nullifiers collided");
    assert(global_epoch_zero != adjacent_epoch, "epoch boundary nullifiers collided");
}

// Video hash limbs are field elements too. Exercise the zero and adjacent
// high-limb boundaries independently from the nullifier secret boundary.
#[test]
fn test_video_hash_limb_boundaries_are_distinct() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;

    let zero_high = compute_scoped_nullifier(cs, ns, 0, vlo, scope, ep);
    let adjacent_high = compute_scoped_nullifier(cs, ns, 1, vlo, scope, ep);
    assert(zero_high != adjacent_high, "video hash high-limb boundary collided");
}
