// =============================================================================
// Harpocrates Common Noir Library
//
// Shared cryptographic domain constants, evidence digest identifiers, and
// derivation helpers consumed across Harpocrates Noir circuits and helpers.
// =============================================================================

pub global DIGEST_ALGORITHM_SHA256: Field = 0;
pub global SCOPED_NULLIFIER_V1: Field = 0x00484152504f4352415445535f53434f5045445f4e554c4c49464945525f5631;

pub global DOMAIN_PROTOCOL_FIELD: Field = 0x261e9f6e39e3c1ae6aca9f29e84c10d59c82d5f4b40c21c1b7e3c01ad571c201;
pub global DOMAIN_VERSION_FIELD: Field = 0x0c89eff4ec8e39a01e9f19547a0cc9dd7fd2a97d79ba4d94fd32e97a1f5ac623;
pub global DOMAIN_NETWORK_FIELD: Field = 0x2a2c3f48ce2e3c2f1e6c89b18d64b5f5c1f88a59a0d9bc82cb61a1e8cb77a50f;

pub fn expected_domain_tag() -> Field {
    std::hash::pedersen_hash([
        DOMAIN_PROTOCOL_FIELD,
        DOMAIN_VERSION_FIELD,
        DOMAIN_NETWORK_FIELD,
    ])
}

pub fn compute_scoped_nullifier(
    cs: Field,
    ns: Field,
    vhi: Field,
    vlo: Field,
    scope: Field,
    ep: Field,
) -> Field {
    let scope_hash = std::hash::pedersen_hash([SCOPED_NULLIFIER_V1, scope, ep]);
    let evidence = std::hash::pedersen_hash([DIGEST_ALGORITHM_SHA256, vhi, vlo, scope_hash]);
    std::hash::pedersen_hash([cs, ns, evidence])
}
