// =============================================================================
// Redacted Derivative Ancestry - Harpocrates ZK circuit
//
// Proves that a *redacted* derivative descends from a committed parent evidence
// object without revealing the unredacted parent media hash, the redaction mask
// preimage, or the credential secrets that bind the prover to the evidence.
//
// The statement reuses the canonical lineage operation identifier from the
// backend / Soroban registry, "redact" (bound here as the ASCII field element
// 0x726564616374), and the bounded lineage depth from backend/lineage.py
// (MAX_LINEAGE_DEPTH = 4). It does not introduce a second operation enum.
//
// Public statement:
//   parent_commitment  - Pedersen commitment to the parent media hash halves
//   derivative_digest  - digest of the redacted derivative, bound to the parent
//   parameters_digest  - digest of the redaction parameters (mask + seed)
//   operation_type     - must equal the canonical "redact" identifier
//   ancestry_root      - protocol ancestry statement commitment
//   nullifier          - one-use binder for this ancestry statement
//   depth              - ancestry depth in [1, MAX_ANCESTRY_DEPTH]
//   domain_tag         - protocol / version / network domain separator
//
// Private witness:
//   parent_hash_hi, parent_hash_lo, parent_blinding, mask_commitment,
//   redaction_seed, credential_secret, nullifier_secret
//
// Failure responses are stable assert codes. No witness value, media byte, or
// secret is ever emitted by the circuit or its test corpus.
// =============================================================================

use harpocrates_common::expected_domain_tag;
use std::hash::pedersen_hash;

// Canonical lineage operation identifier. This is the ASCII encoding of the
// registry Symbol "redact" and MUST NOT be renumbered: the numeric code table
// is deliberately not replicated here so the registry symbol stays the single
// operation truth.
global OPERATION_REDACT: Field = 0x726564616374;

// Lineage graph bound, mirrored from backend/lineage.py (MAX_LINEAGE_DEPTH).
global MIN_ANCESTRY_DEPTH: Field = 1;
global MAX_ANCESTRY_DEPTH: Field = 4;
global CIRCUIT_VERSION: Field = 1;

// Domain separators. Each is 0x00-prefixed ASCII so the value is comfortably
// below the BN254 scalar field modulus and the separator is auditable.
global DOMAIN_PARENT_COMMIT: Field = 0x0048505f5245444143545f504152454e545f5631; // "HP_REDACT_PARENT_V1"
global DOMAIN_REDACT_PARAMS: Field = 0x0048505f5245444143545f504152414d535f5631; // "HP_REDACT_PARAMS_V1"
global DOMAIN_DERIVATIVE: Field = 0x0048505f5245444143545f44455249565f5631; // "HP_REDACT_DERIV_V1"
global DOMAIN_ANCESTRY: Field = 0x0048505f5245444143545f414e4345535452595f5631; // "HP_REDACT_ANCESTRY_V1"
global DOMAIN_NULLIFIER: Field = 0x0048505f5245444143545f4e554c4c49464945525f5631; // "HP_REDACT_NULLIFIER_V1"

fn derive_parent_commitment(parent_hash_hi: Field, parent_hash_lo: Field, parent_blinding: Field) -> Field {
    pedersen_hash([DOMAIN_PARENT_COMMIT, parent_hash_hi, parent_hash_lo, parent_blinding])
}

fn derive_parameters_digest(mask_commitment: Field, redaction_seed: Field) -> Field {
    pedersen_hash([DOMAIN_REDACT_PARAMS, mask_commitment, redaction_seed])
}

fn derive_derivative_digest(
    parent_hash_hi: Field,
    parent_hash_lo: Field,
    parameters_digest: Field,
    redaction_seed: Field,
) -> Field {
    pedersen_hash([
        DOMAIN_DERIVATIVE,
        parent_hash_hi,
        parent_hash_lo,
        parameters_digest,
        redaction_seed,
    ])
}

fn derive_ancestry_root(
    parent_commitment: Field,
    derivative_digest: Field,
    parameters_digest: Field,
    depth: Field,
) -> Field {
    pedersen_hash([
        DOMAIN_ANCESTRY,
        parent_commitment,
        derivative_digest,
        parameters_digest,
        OPERATION_REDACT,
        depth,
        CIRCUIT_VERSION,
    ])
}

fn derive_nullifier(credential_secret: Field, nullifier_secret: Field, ancestry_root: Field) -> Field {
    pedersen_hash([DOMAIN_NULLIFIER, credential_secret, nullifier_secret, ancestry_root])
}

fn assert_valid_depth(depth: Field) {
    let ok = (depth == MIN_ANCESTRY_DEPTH)
        | (depth == 2)
        | (depth == 3)
        | (depth == MAX_ANCESTRY_DEPTH);
    assert(ok, "ancestry depth out of range");
}

fn main(
    // --- private witness ---
    parent_hash_hi: Field,
    parent_hash_lo: Field,
    parent_blinding: Field,
    mask_commitment: Field,
    redaction_seed: Field,
    credential_secret: Field,
    nullifier_secret: Field,
    // --- public statement ---
    parent_commitment: pub Field,
    derivative_digest: pub Field,
    parameters_digest: pub Field,
    operation_type: pub Field,
    ancestry_root: pub Field,
    nullifier: pub Field,
    depth: pub Field,
    domain_tag: pub Field,
) {
    // This circuit only attests the canonical "redact" operation.
    assert(operation_type == OPERATION_REDACT, "operation must be redact");

    // Bound the ancestry depth to the lineage graph limit (1..=4).
    assert_valid_depth(depth);

    // Reject zeroed statement fields with stable, privacy-safe failures.
    assert(parent_commitment != 0, "parent commitment must be non-zero");
    assert(derivative_digest != 0, "derivative digest must be non-zero");
    assert(parameters_digest != 0, "parameters digest must be non-zero");
    assert(ancestry_root != 0, "ancestry root must be non-zero");
    assert(nullifier != 0, "nullifier must be non-zero");

    // Reject degenerate private openings so a commitment cannot be satisfied
    // with a trivial preimage.
    assert(credential_secret != 0, "credential secret must be non-zero");
    assert(nullifier_secret != 0, "nullifier secret must be non-zero");
    assert(parent_blinding != 0, "parent blinding must be non-zero");
    assert(redaction_seed != 0, "redaction seed must be non-zero");

    // A derivative cannot commit to itself as its parent.
    assert(parent_commitment != derivative_digest, "ancestry cycle detected");

    let derived_parent = derive_parent_commitment(parent_hash_hi, parent_hash_lo, parent_blinding);
    assert(derived_parent == parent_commitment, "parent commitment mismatch");

    let derived_params = derive_parameters_digest(mask_commitment, redaction_seed);
    assert(derived_params == parameters_digest, "parameters digest mismatch");

    let derived_derivative = derive_derivative_digest(
        parent_hash_hi,
        parent_hash_lo,
        derived_params,
        redaction_seed,
    );
    assert(derived_derivative == derivative_digest, "derivative digest mismatch");

    let derived_root = derive_ancestry_root(derived_parent, derived_derivative, derived_params, depth);
    assert(derived_root == ancestry_root, "ancestry root mismatch");

    let derived_nullifier = derive_nullifier(credential_secret, nullifier_secret, derived_root);
    assert(derived_nullifier == nullifier, "nullifier mismatch");

    assert(domain_tag == expected_domain_tag(), "domain tag mismatch");
}

// ---------------------------------------------------------------------------
// Synthetic test corpus -- ALL SECRETS AND OPENINGS ARE FOR TESTING ONLY.
//
// Base fixture:
//   parent_hash_hi    = 11111
//   parent_hash_lo    = 22222
//   parent_blinding   = 33333
//   mask_commitment   = 44444
//   redaction_seed    = 55555
//   credential_secret = 12345
//   nullifier_secret  = 67890
//   depth             = 1
// ---------------------------------------------------------------------------

global TEST_PHI: Field = 11111;
global TEST_PLO: Field = 22222;
global TEST_BLIND: Field = 33333;
global TEST_MASK: Field = 44444;
global TEST_SEED: Field = 55555;
global TEST_CS: Field = 12345;
global TEST_NS: Field = 67890;
global TEST_DEPTH: Field = 1;

fn fixture_statement() -> (Field, Field, Field, Field, Field, Field) {
    let parent = derive_parent_commitment(TEST_PHI, TEST_PLO, TEST_BLIND);
    let params = derive_parameters_digest(TEST_MASK, TEST_SEED);
    let deriv = derive_derivative_digest(TEST_PHI, TEST_PLO, params, TEST_SEED);
    let root = derive_ancestry_root(parent, deriv, params, TEST_DEPTH);
    let nullifier = derive_nullifier(TEST_CS, TEST_NS, root);
    let domain = expected_domain_tag();
    (parent, deriv, params, root, nullifier, domain)
}

fn run_valid(
    parent_hash_hi: Field,
    parent_hash_lo: Field,
    depth: Field,
) {
    let parent = derive_parent_commitment(parent_hash_hi, parent_hash_lo, TEST_BLIND);
    let params = derive_parameters_digest(TEST_MASK, TEST_SEED);
    let deriv = derive_derivative_digest(parent_hash_hi, parent_hash_lo, params, TEST_SEED);
    let root = derive_ancestry_root(parent, deriv, params, depth);
    let nullifier = derive_nullifier(TEST_CS, TEST_NS, root);
    main(
        parent_hash_hi,
        parent_hash_lo,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        depth,
        expected_domain_tag(),
    );
}

// ============================================================
// Positive and boundary: well-formed witnesses
// ============================================================

#[test]
fn test_valid_redacted_ancestry() {
    let (parent, deriv, params, root, nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

#[test]
fn test_valid_min_depth() {
    run_valid(TEST_PHI, TEST_PLO, MIN_ANCESTRY_DEPTH);
}

#[test]
fn test_valid_depth_two() {
    run_valid(TEST_PHI, TEST_PLO, 2);
}

#[test]
fn test_valid_depth_three() {
    run_valid(TEST_PHI, TEST_PLO, 3);
}

#[test]
fn test_valid_max_depth() {
    run_valid(TEST_PHI, TEST_PLO, MAX_ANCESTRY_DEPTH);
}

// A fully redacted / blank parent still commits to a non-zero value because the
// domain separator and blinding are bound into the commitment.
#[test]
fn test_valid_zero_parent_hash() {
    run_valid(0, 0, TEST_DEPTH);
}

// ============================================================
// Negative: unsupported operation, malformed and oversized depth
// ============================================================

#[test(should_fail_with = "operation must be redact")]
fn test_rejects_non_redact_operation() {
    let (parent, deriv, params, root, nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        0, // "crop" numeric code is not the canonical identifier
        root,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

#[test(should_fail_with = "ancestry depth out of range")]
fn test_rejects_zero_depth() {
    run_valid(TEST_PHI, TEST_PLO, 0);
}

#[test(should_fail_with = "ancestry depth out of range")]
fn test_rejects_oversized_depth() {
    run_valid(TEST_PHI, TEST_PLO, 5);
}

#[test(should_fail_with = "ancestry depth out of range")]
fn test_rejects_negative_like_depth() {
    run_valid(TEST_PHI, TEST_PLO, 999);
}

// ============================================================
// Negative: forged / tampered statement fields
// ============================================================

#[test(should_fail_with = "parent commitment mismatch")]
fn test_rejects_wrong_parent_opening() {
    let (parent, deriv, params, root, nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        99999,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

#[test(should_fail_with = "parent commitment mismatch")]
fn test_rejects_swapped_parent_hash_halves() {
    let (parent, deriv, params, root, nullifier, domain) = fixture_statement();
    main(
        TEST_PLO,
        TEST_PHI,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

#[test(should_fail_with = "parameters digest mismatch")]
fn test_rejects_wrong_redaction_params() {
    let (parent, deriv, params, root, nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        99999,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

#[test(should_fail_with = "derivative digest mismatch")]
fn test_rejects_forged_derivative_digest() {
    let (parent, _deriv, params, root, nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        0xbeef,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

#[test(should_fail_with = "ancestry root mismatch")]
fn test_rejects_tampered_ancestry_root() {
    let (parent, deriv, params, _root, nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        0xcafe,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_rejects_forged_nullifier() {
    let (parent, deriv, params, root, _nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        0xdead,
        TEST_DEPTH,
        domain,
    );
}

#[test(should_fail_with = "domain tag mismatch")]
fn test_rejects_wrong_domain_tag() {
    let (parent, deriv, params, root, nullifier, _domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        0xbad,
    );
}

// ============================================================
// Negative: cycles and zeroed inputs
// ============================================================

#[test(should_fail_with = "ancestry cycle detected")]
fn test_rejects_direct_cycle() {
    let params = derive_parameters_digest(TEST_MASK, TEST_SEED);
    let deriv = derive_derivative_digest(TEST_PHI, TEST_PLO, params, TEST_SEED);
    // Parent commitment is forged to equal the derivative, creating a self-cycle.
    let root = derive_ancestry_root(deriv, deriv, params, TEST_DEPTH);
    let nullifier = derive_nullifier(TEST_CS, TEST_NS, root);
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        deriv,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        expected_domain_tag(),
    );
}

#[test(should_fail_with = "credential secret must be non-zero")]
fn test_rejects_zero_credential_secret() {
    let (parent, deriv, params, root, nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        0,
        TEST_NS,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

#[test(should_fail_with = "nullifier secret must be non-zero")]
fn test_rejects_zero_nullifier_secret() {
    let (parent, deriv, params, root, nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        0,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

#[test(should_fail_with = "parent blinding must be non-zero")]
fn test_rejects_zero_parent_blinding() {
    let (parent, deriv, params, root, nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        0,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

#[test(should_fail_with = "redaction seed must be non-zero")]
fn test_rejects_zero_redaction_seed() {
    let (parent, deriv, params, root, nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        0,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

#[test(should_fail_with = "parent commitment must be non-zero")]
fn test_rejects_zero_parent_commitment() {
    let (_parent, deriv, params, root, nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        0,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

#[test(should_fail_with = "derivative digest must be non-zero")]
fn test_rejects_zero_derivative_digest() {
    let (parent, _deriv, params, root, nullifier, domain) = fixture_statement();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        0,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        domain,
    );
}

// A statement built for one depth must not verify at another depth: the
// ancestry root binds the depth.
#[test(should_fail_with = "ancestry root mismatch")]
fn test_rejects_depth_substitution() {
    let parent = derive_parent_commitment(TEST_PHI, TEST_PLO, TEST_BLIND);
    let params = derive_parameters_digest(TEST_MASK, TEST_SEED);
    let deriv = derive_derivative_digest(TEST_PHI, TEST_PLO, params, TEST_SEED);
    // Root is built at depth 1 but the public statement claims depth 2.
    let root = derive_ancestry_root(parent, deriv, params, 1);
    let nullifier = derive_nullifier(TEST_CS, TEST_NS, root);
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OPERATION_REDACT,
        root,
        nullifier,
        2,
        expected_domain_tag(),
    );
}
