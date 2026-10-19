// =============================================================================
// Redacted Derivative Ancestry Helper
//
// Derives the public statement for the `redacted_ancestry` circuit from the
// private openings. This is the browser/native proving path used to fill the
// main circuit's Prover.toml and to construct on-chain public inputs.
//
// The derivations MUST stay byte-for-byte compatible with `redacted_ancestry`.
// The helper is unconstrained input glue only; it proves nothing and accepts no
// secrets at the trust boundary.
// =============================================================================

use harpocrates_common::{
    DOMAIN_NETWORK_FIELD,
    DOMAIN_PROTOCOL_FIELD,
    DOMAIN_VERSION_FIELD,
};
use std::hash::pedersen_hash;

global OPERATION_REDACT: Field = 0x726564616374; // ASCII "redact"

global DOMAIN_PARENT_COMMIT: Field = 0x0048505f5245444143545f504152454e545f5631; // "HP_REDACT_PARENT_V1"
global DOMAIN_REDACT_PARAMS: Field = 0x0048505f5245444143545f504152414d535f5631; // "HP_REDACT_PARAMS_V1"
global DOMAIN_DERIVATIVE: Field = 0x0048505f5245444143545f44455249565f5631; // "HP_REDACT_DERIV_V1"
global DOMAIN_ANCESTRY: Field = 0x0048505f5245444143545f414e4345535452595f5631; // "HP_REDACT_ANCESTRY_V1"
global DOMAIN_NULLIFIER: Field = 0x0048505f5245444143545f4e554c4c49464945525f5631; // "HP_REDACT_NULLIFIER_V1"

global CIRCUIT_VERSION: Field = 1;

fn main(
    parent_hash_hi: Field,
    parent_hash_lo: Field,
    parent_blinding: Field,
    mask_commitment: Field,
    redaction_seed: Field,
    credential_secret: Field,
    nullifier_secret: Field,
    depth: Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field) {
    let parent_commitment = pedersen_hash([
        DOMAIN_PARENT_COMMIT,
        parent_hash_hi,
        parent_hash_lo,
        parent_blinding,
    ]);
    let parameters_digest = pedersen_hash([
        DOMAIN_REDACT_PARAMS,
        mask_commitment,
        redaction_seed,
    ]);
    let derivative_digest = pedersen_hash([
        DOMAIN_DERIVATIVE,
        parent_hash_hi,
        parent_hash_lo,
        parameters_digest,
        redaction_seed,
    ]);
    let ancestry_root = pedersen_hash([
        DOMAIN_ANCESTRY,
        parent_commitment,
        derivative_digest,
        parameters_digest,
        OPERATION_REDACT,
        depth,
        CIRCUIT_VERSION,
    ]);
    let nullifier = pedersen_hash([
        DOMAIN_NULLIFIER,
        credential_secret,
        nullifier_secret,
        ancestry_root,
    ]);
    let domain_tag = pedersen_hash([
        DOMAIN_PROTOCOL_FIELD,
        DOMAIN_VERSION_FIELD,
        DOMAIN_NETWORK_FIELD,
    ]);
    (
        parent_commitment,
        derivative_digest,
        parameters_digest,
        ancestry_root,
        nullifier,
        depth,
        domain_tag,
    )
}

#[test]
fn test_helper_produces_nonzero_publics() {
    let (parent, derivative, params, root, nullifier, depth, domain) = main(
        11111,
        22222,
        33333,
        44444,
        55555,
        12345,
        67890,
        1,
    );
    assert(parent != 0);
    assert(derivative != 0);
    assert(params != 0);
    assert(root != 0);
    assert(nullifier != 0);
    assert(depth == 1);
    assert(domain != 0);
}

// The helper's parent commitment derivation must agree with the main circuit.
#[test]
fn test_helper_binds_parent_and_depth() {
    let (parent_a, _, _, root_a, _, _, _) = main(11111, 22222, 33333, 44444, 55555, 12345, 67890, 1);
    let (parent_b, _, _, root_b, _, _, _) = main(11111, 22222, 33333, 44444, 55555, 12345, 67890, 2);
    // Same parent opening, different depth -> same parent, different root.
    assert(parent_a == parent_b);
    assert(root_a != root_b);
}
